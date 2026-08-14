//! NAT traversal, candidate gathering, and seamless direct/relay routing.

use core::fmt;
pub use latencydesk_protocol::WireIpAddr;
use latencydesk_protocol::{
    compute_candidate_priority, compute_pair_priority, CandidateType, IceCandidate, RelayProvider,
    TransportProtocol,
};

/// Errors encountered during NAT traversal or routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatError {
    CandidateLimitReached,
    InvalidCandidate,
    NoCandidatesAvailable,
    NoValidPath,
    PathTimeout,
    DirectProbeFailed,
}

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for NatError {}

/// Maximum number of candidates retained per peer.
pub const MAX_CANDIDATES: usize = 32;

/// Gathers and prioritizes local ICE candidates (Host, STUN Srflx, TURN/DERP Relay).
#[derive(Debug, Clone)]
pub struct CandidateGatherer {
    candidates: Vec<IceCandidate>,
    foundation_counter: u64,
}

impl Default for CandidateGatherer {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidateGatherer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            candidates: Vec::new(),
            foundation_counter: 1,
        }
    }

    fn next_foundation(&mut self) -> [u8; 8] {
        let val = self.foundation_counter;
        self.foundation_counter = self.foundation_counter.wrapping_add(1);
        val.to_be_bytes()
    }

    /// Adds a direct local network interface (Host) candidate.
    pub fn add_host_candidate(
        &mut self,
        ip: WireIpAddr,
        port: u16,
        component: u8,
        local_preference: u16,
    ) -> Result<IceCandidate, NatError> {
        if self.candidates.len() >= MAX_CANDIDATES {
            return Err(NatError::CandidateLimitReached);
        }
        let priority = compute_candidate_priority(CandidateType::Host, local_preference, component);
        let candidate = IceCandidate {
            foundation: self.next_foundation(),
            component,
            transport: TransportProtocol::Udp,
            priority,
            candidate_type: CandidateType::Host,
            relay_provider: RelayProvider::None,
            ip,
            port,
            related_address: None,
        };
        candidate
            .validate()
            .map_err(|_| NatError::InvalidCandidate)?;
        self.candidates.push(candidate);
        Ok(candidate)
    }

    /// Adds a server-reflexive (srflx via STUN) candidate.
    pub fn add_srflx_candidate(
        &mut self,
        srflx_ip: WireIpAddr,
        srflx_port: u16,
        base_ip: WireIpAddr,
        base_port: u16,
        component: u8,
        local_preference: u16,
    ) -> Result<IceCandidate, NatError> {
        if self.candidates.len() >= MAX_CANDIDATES {
            return Err(NatError::CandidateLimitReached);
        }
        let priority =
            compute_candidate_priority(CandidateType::ServerReflexive, local_preference, component);
        let candidate = IceCandidate {
            foundation: self.next_foundation(),
            component,
            transport: TransportProtocol::Udp,
            priority,
            candidate_type: CandidateType::ServerReflexive,
            relay_provider: RelayProvider::None,
            ip: srflx_ip,
            port: srflx_port,
            related_address: Some((base_ip, base_port)),
        };
        candidate
            .validate()
            .map_err(|_| NatError::InvalidCandidate)?;
        self.candidates.push(candidate);
        Ok(candidate)
    }

    /// Adds an allocated relay candidate (TURN / DERP).
    pub fn add_relay_candidate(
        &mut self,
        relay_ip: WireIpAddr,
        relay_port: u16,
        provider: RelayProvider,
        component: u8,
        local_preference: u16,
    ) -> Result<IceCandidate, NatError> {
        if self.candidates.len() >= MAX_CANDIDATES {
            return Err(NatError::CandidateLimitReached);
        }
        let priority =
            compute_candidate_priority(CandidateType::Relayed, local_preference, component);
        let candidate = IceCandidate {
            foundation: self.next_foundation(),
            component,
            transport: TransportProtocol::Udp,
            priority,
            candidate_type: CandidateType::Relayed,
            relay_provider: provider,
            ip: relay_ip,
            port: relay_port,
            related_address: None,
        };
        candidate
            .validate()
            .map_err(|_| NatError::InvalidCandidate)?;
        self.candidates.push(candidate);
        Ok(candidate)
    }

    #[must_use]
    pub fn candidates(&self) -> &[IceCandidate] {
        &self.candidates
    }

    /// Returns all gathered candidates sorted by priority descending.
    #[must_use]
    pub fn finish_gathering(&mut self) -> Vec<IceCandidate> {
        self.candidates
            .sort_by_key(|b| std::cmp::Reverse(b.priority));
        self.candidates.clone()
    }
}

/// State of an individual candidate pair connectivity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePairState {
    Frozen,
    Waiting,
    InProgress,
    Succeeded,
    Failed,
}

/// A local and remote candidate pair for connectivity evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidatePair {
    pub local: IceCandidate,
    pub remote: IceCandidate,
    pub pair_priority: u64,
    pub state: CandidatePairState,
    pub rtt_ns: Option<u64>,
}

impl CandidatePair {
    #[must_use]
    pub fn new(local: IceCandidate, remote: IceCandidate, is_controlling: bool) -> Self {
        let pair_priority = compute_pair_priority(local.priority, remote.priority, is_controlling);
        Self {
            local,
            remote,
            pair_priority,
            state: CandidatePairState::Waiting,
            rtt_ns: None,
        }
    }

    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.local.candidate_type != CandidateType::Relayed
            && self.remote.candidate_type != CandidateType::Relayed
    }
}

/// Currently active network transmission path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPath {
    Direct {
        local_ip: WireIpAddr,
        local_port: u16,
        remote_ip: WireIpAddr,
        remote_port: u16,
        pair_priority: u64,
    },
    Relay {
        relay_session_id: u64,
        provider: RelayProvider,
        remote_peer_id: [u8; 16],
    },
}

/// Observable routing and fallback counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouterStats {
    pub direct_attempts: u32,
    pub direct_successes: u32,
    pub relay_fallbacks: u32,
    pub direct_upgrades: u32,
    pub relay_downgrades: u32,
    pub probes_sent: u32,
}

/// Manages direct connection priority, seamless relay fallback, and background direct path probing.
#[derive(Debug, Clone)]
pub struct ConnectionRouter {
    is_controlling: bool,
    direct_check_timeout_ns: u64,
    probe_interval_ns: u64,
    last_probe_ns: u64,
    local_candidates: Vec<IceCandidate>,
    remote_candidates: Vec<IceCandidate>,
    pairs: Vec<CandidatePair>,
    active_path: Option<ConnectionPath>,
    fallback_relay_path: Option<ConnectionPath>,
    stats: RouterStats,
}

impl ConnectionRouter {
    #[must_use]
    pub const fn new(is_controlling: bool, direct_check_timeout_ns: u64) -> Self {
        Self {
            is_controlling,
            direct_check_timeout_ns,
            probe_interval_ns: 500_000_000, // 500ms
            last_probe_ns: 0,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            pairs: Vec::new(),
            active_path: None,
            fallback_relay_path: None,
            stats: RouterStats {
                direct_attempts: 0,
                direct_successes: 0,
                relay_fallbacks: 0,
                direct_upgrades: 0,
                relay_downgrades: 0,
                probes_sent: 0,
            },
        }
    }

    pub fn set_candidates(
        &mut self,
        local: Vec<IceCandidate>,
        remote: Vec<IceCandidate>,
        relay_session_id: u64,
        remote_peer_id: [u8; 16],
    ) {
        self.local_candidates = local;
        self.remote_candidates = remote;

        let mut pairs = Vec::new();
        for loc in &self.local_candidates {
            for rem in &self.remote_candidates {
                if loc.transport == rem.transport && loc.component == rem.component {
                    pairs.push(CandidatePair::new(*loc, *rem, self.is_controlling));
                }
            }
        }
        // Direct pairs with higher priority appear first; relay pairs appear last
        pairs.sort_by_key(|b| std::cmp::Reverse(b.pair_priority));
        self.pairs = pairs;

        // Establish default fallback relay path
        let relay_provider = self
            .local_candidates
            .iter()
            .find(|c| c.candidate_type == CandidateType::Relayed)
            .map(|c| c.relay_provider)
            .unwrap_or(RelayProvider::Turn);

        self.fallback_relay_path = Some(ConnectionPath::Relay {
            relay_session_id,
            provider: relay_provider,
            remote_peer_id,
        });
    }

    #[must_use]
    pub fn pairs(&self) -> &[CandidatePair] {
        &self.pairs
    }

    #[must_use]
    pub fn active_path(&self) -> Option<ConnectionPath> {
        self.active_path
    }

    #[must_use]
    pub fn is_using_relay(&self) -> bool {
        matches!(self.active_path, Some(ConnectionPath::Relay { .. }))
    }

    #[must_use]
    pub fn stats(&self) -> RouterStats {
        self.stats
    }

    /// Selects an initial transport path: prefers direct candidates, but falls back to relay
    /// if direct checks have timed out or failed.
    pub fn select_initial_path(&mut self, now_ns: u64) -> Result<ConnectionPath, NatError> {
        // If an active path is already chosen, return it
        if let Some(path) = self.active_path {
            return Ok(path);
        }

        // 1. Check if any direct pair has succeeded
        if let Some(succeeded_direct) = self
            .pairs
            .iter()
            .find(|p| p.is_direct() && p.state == CandidatePairState::Succeeded)
        {
            let path = ConnectionPath::Direct {
                local_ip: succeeded_direct.local.ip,
                local_port: succeeded_direct.local.port,
                remote_ip: succeeded_direct.remote.ip,
                remote_port: succeeded_direct.remote.port,
                pair_priority: succeeded_direct.pair_priority,
            };
            self.active_path = Some(path);
            self.stats.direct_successes += 1;
            return Ok(path);
        }

        // 2. If direct checks are still within initial check window, attempt top direct pair
        let has_pending_direct = self
            .pairs
            .iter()
            .any(|p| p.is_direct() && p.state != CandidatePairState::Failed);

        if has_pending_direct && now_ns < self.direct_check_timeout_ns {
            self.stats.direct_attempts += 1;
            if let Some(pair) = self
                .pairs
                .iter_mut()
                .find(|p| p.is_direct() && p.state == CandidatePairState::Waiting)
            {
                pair.state = CandidatePairState::InProgress;
            }
            // Return transient direct target for probing
            if let Some(pair) = self.pairs.iter().find(|p| p.is_direct()) {
                let path = ConnectionPath::Direct {
                    local_ip: pair.local.ip,
                    local_port: pair.local.port,
                    remote_ip: pair.remote.ip,
                    remote_port: pair.remote.port,
                    pair_priority: pair.pair_priority,
                };
                return Ok(path);
            }
        }

        // 3. Direct checks timed out or unavailable -> Seamless fallback to encrypted Relay
        if let Some(relay_path) = self.fallback_relay_path {
            self.active_path = Some(relay_path);
            self.stats.relay_fallbacks += 1;
            return Ok(relay_path);
        }

        Err(NatError::NoValidPath)
    }

    /// Records connectivity check outcome for a pair. Performs seamless upgrade or downgrade.
    pub fn record_check_result(
        &mut self,
        pair_idx: usize,
        success: bool,
        rtt_ns: u64,
        _now_ns: u64,
    ) -> Option<ConnectionPath> {
        if pair_idx >= self.pairs.len() {
            return None;
        }

        let is_direct = self.pairs[pair_idx].is_direct();
        if success {
            self.pairs[pair_idx].state = CandidatePairState::Succeeded;
            self.pairs[pair_idx].rtt_ns = Some(rtt_ns);

            // If currently on Relay fallback and a direct path succeeds -> SEAMLESS DIRECT UPGRADE!
            if is_direct && self.is_using_relay() {
                let upgraded = ConnectionPath::Direct {
                    local_ip: self.pairs[pair_idx].local.ip,
                    local_port: self.pairs[pair_idx].local.port,
                    remote_ip: self.pairs[pair_idx].remote.ip,
                    remote_port: self.pairs[pair_idx].remote.port,
                    pair_priority: self.pairs[pair_idx].pair_priority,
                };
                self.active_path = Some(upgraded);
                self.stats.direct_upgrades += 1;
                return Some(upgraded);
            }
        } else {
            self.pairs[pair_idx].state = CandidatePairState::Failed;

            // If currently active direct path failed -> SEAMLESS RELAY DOWNGRADE!
            if let Some(ConnectionPath::Direct { pair_priority, .. }) = self.active_path {
                if self.pairs[pair_idx].pair_priority == pair_priority {
                    if let Some(relay) = self.fallback_relay_path {
                        self.active_path = Some(relay);
                        self.stats.relay_downgrades += 1;
                        return Some(relay);
                    }
                }
            }
        }

        self.active_path
    }

    /// While operating over relay fallback, periodically probes unverified direct candidate pairs.
    pub fn tick_background_probing(&mut self, now_ns: u64) -> Option<CandidatePair> {
        if !self.is_using_relay() {
            return None;
        }
        if now_ns.saturating_sub(self.last_probe_ns) < self.probe_interval_ns {
            return None;
        }

        // Find top unverified direct pair to probe
        if let Some(pair) = self
            .pairs
            .iter_mut()
            .find(|p| p.is_direct() && p.state != CandidatePairState::Succeeded)
        {
            pair.state = CandidatePairState::InProgress;
            self.last_probe_ns = now_ns;
            self.stats.probes_sent += 1;
            return Some(*pair);
        }

        None
    }
}
