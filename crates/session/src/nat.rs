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
    initial_check_started_ns: Option<u64>,
    probe_interval_ns: u64,
    last_probe_ns: u64,
    next_probe_cursor: usize,
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
            initial_check_started_ns: None,
            probe_interval_ns: 500_000_000, // 500ms
            last_probe_ns: 0,
            next_probe_cursor: 0,
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
    ) -> Result<(), NatError> {
        if local.is_empty() || remote.is_empty() {
            return Err(NatError::NoCandidatesAvailable);
        }
        if local.len() > MAX_CANDIDATES || remote.len() > MAX_CANDIDATES {
            return Err(NatError::CandidateLimitReached);
        }
        if local
            .iter()
            .chain(remote.iter())
            .any(|candidate| candidate.validate().is_err())
        {
            return Err(NatError::InvalidCandidate);
        }

        self.local_candidates = local;
        self.remote_candidates = remote;
        self.initial_check_started_ns = None;
        self.last_probe_ns = 0;
        self.next_probe_cursor = 0;
        self.active_path = None;

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

        // A relay path exists only after the caller supplies a real allocated
        // relay candidate and nonzero session/peer identities. Never invent a
        // TURN route from direct-only candidates.
        self.fallback_relay_path = self
            .local_candidates
            .iter()
            .find(|candidate| {
                candidate.candidate_type == CandidateType::Relayed
                    && candidate.validate().is_ok()
                    && relay_session_id != 0
                    && remote_peer_id != [0; 16]
            })
            .map(|candidate| ConnectionPath::Relay {
                relay_session_id,
                provider: candidate.relay_provider,
                remote_peer_id,
            });
        Ok(())
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

        // The timeout is a duration, not an absolute monotonic timestamp. It
        // begins when this candidate generation is first evaluated.
        let started_ns = *self.initial_check_started_ns.get_or_insert(now_ns);
        let elapsed_ns = now_ns.saturating_sub(started_ns);

        // 2. Within the direct-check window, start the highest-priority waiting
        // pair. If a check is already in progress, return that exact pair rather
        // than accidentally resurrecting a failed higher-priority pair.
        if elapsed_ns < self.direct_check_timeout_ns {
            if let Some(pair) = self
                .pairs
                .iter_mut()
                .find(|pair| pair.is_direct() && pair.state == CandidatePairState::Waiting)
            {
                pair.state = CandidatePairState::InProgress;
                self.stats.direct_attempts = self.stats.direct_attempts.saturating_add(1);
                return Ok(direct_path(*pair));
            }
            if let Some(pair) = self
                .pairs
                .iter()
                .find(|pair| pair.is_direct() && pair.state == CandidatePairState::InProgress)
            {
                return Ok(direct_path(*pair));
            }
        }

        // 3. Direct checks timed out or unavailable -> Seamless fallback to encrypted Relay
        for pair in &mut self.pairs {
            if pair.is_direct() && pair.state == CandidatePairState::InProgress {
                pair.state = CandidatePairState::Failed;
            }
        }
        if let Some(relay_path) = self.fallback_relay_path {
            self.active_path = Some(relay_path);
            self.stats.relay_fallbacks = self.stats.relay_fallbacks.saturating_add(1);
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

        // Rotate through eligible direct pairs so one failed high-priority path
        // cannot starve every other interface/address family forever.
        let pair_count = self.pairs.len();
        for offset in 0..pair_count {
            let index = (self.next_probe_cursor + offset) % pair_count;
            let pair = &mut self.pairs[index];
            if pair.is_direct()
                && !matches!(
                    pair.state,
                    CandidatePairState::Succeeded | CandidatePairState::InProgress
                )
            {
                pair.state = CandidatePairState::InProgress;
                self.next_probe_cursor = (index + 1) % pair_count;
                self.last_probe_ns = now_ns;
                self.stats.probes_sent = self.stats.probes_sent.saturating_add(1);
                return Some(*pair);
            }
        }

        None
    }
}

fn direct_path(pair: CandidatePair) -> ConnectionPath {
    ConnectionPath::Direct {
        local_ip: pair.local.ip,
        local_port: pair.local.port,
        remote_ip: pair.remote.ip,
        remote_port: pair.remote.port,
        pair_priority: pair.pair_priority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(
        host_octets: &[[u8; 4]],
        relay: bool,
        preference_start: u16,
    ) -> Vec<IceCandidate> {
        let mut gatherer = CandidateGatherer::new();
        for (index, octets) in host_octets.iter().copied().enumerate() {
            gatherer
                .add_host_candidate(
                    WireIpAddr::V4(octets),
                    5_000 + index as u16,
                    1,
                    preference_start.saturating_sub(index as u16),
                )
                .expect("host candidate");
        }
        if relay {
            gatherer
                .add_relay_candidate(
                    WireIpAddr::V4([198, 51, 100, 10]),
                    7_000,
                    RelayProvider::Turn,
                    1,
                    1,
                )
                .expect("relay candidate");
        }
        gatherer.finish_gathering()
    }

    #[test]
    fn direct_timeout_is_relative_to_the_first_selection() {
        let mut router = ConnectionRouter::new(true, 1_000_000_000);
        router
            .set_candidates(
                candidates(&[[10, 0, 0, 1]], true, 100),
                candidates(&[[10, 0, 0, 2]], true, 100),
                7,
                [9; 16],
            )
            .expect("valid candidates");

        assert!(matches!(
            router.select_initial_path(10_000_000_000),
            Ok(ConnectionPath::Direct { .. })
        ));
        assert!(matches!(
            router.select_initial_path(11_000_000_001),
            Ok(ConnectionPath::Relay { .. })
        ));
    }

    #[test]
    fn router_never_invents_a_relay_without_an_allocated_candidate() {
        let mut router = ConnectionRouter::new(true, 100);
        router
            .set_candidates(
                candidates(&[[10, 0, 0, 1]], false, 100),
                candidates(&[[10, 0, 0, 2]], false, 100),
                7,
                [9; 16],
            )
            .expect("valid candidates");

        let first = router.select_initial_path(1_000).expect("direct probe");
        let pair_priority = match first {
            ConnectionPath::Direct { pair_priority, .. } => pair_priority,
            ConnectionPath::Relay { .. } => panic!("relay was not allocated"),
        };
        let pair_index = router
            .pairs()
            .iter()
            .position(|pair| pair.pair_priority == pair_priority)
            .expect("selected pair");
        router.record_check_result(pair_index, false, 0, 1_001);

        assert_eq!(
            router.select_initial_path(1_101),
            Err(NatError::NoValidPath)
        );
    }

    #[test]
    fn failed_high_priority_pair_advances_to_the_next_waiting_pair() {
        let mut router = ConnectionRouter::new(true, 1_000_000_000);
        router
            .set_candidates(
                candidates(&[[10, 0, 0, 1], [10, 0, 1, 1]], true, 100),
                candidates(&[[10, 0, 0, 2]], true, 100),
                7,
                [9; 16],
            )
            .expect("valid candidates");

        let first = router.select_initial_path(10).expect("first direct pair");
        let first_priority = match first {
            ConnectionPath::Direct { pair_priority, .. } => pair_priority,
            ConnectionPath::Relay { .. } => panic!("expected direct pair"),
        };
        let first_index = router
            .pairs()
            .iter()
            .position(|pair| pair.pair_priority == first_priority)
            .expect("first pair index");
        router.record_check_result(first_index, false, 0, 20);

        let second = router.select_initial_path(30).expect("second direct pair");
        assert!(matches!(
            second,
            ConnectionPath::Direct { pair_priority, .. } if pair_priority != first_priority
        ));
    }

    #[test]
    fn background_probing_rotates_after_a_failed_pair() {
        let mut router = ConnectionRouter::new(true, 0);
        router
            .set_candidates(
                candidates(&[[10, 0, 0, 1], [10, 0, 1, 1]], true, 100),
                candidates(&[[10, 0, 0, 2]], true, 100),
                7,
                [9; 16],
            )
            .expect("valid candidates");
        assert!(matches!(
            router.select_initial_path(1),
            Ok(ConnectionPath::Relay { .. })
        ));

        let first = router
            .tick_background_probing(500_000_001)
            .expect("first background pair");
        let first_index = router
            .pairs()
            .iter()
            .position(|pair| pair.pair_priority == first.pair_priority)
            .expect("first pair index");
        router.record_check_result(first_index, false, 0, 500_000_002);

        let second = router
            .tick_background_probing(1_000_000_002)
            .expect("second background pair");
        assert_ne!(second.pair_priority, first.pair_priority);
    }

    #[test]
    fn router_rejects_invalid_or_unbounded_candidate_batches_before_mutation() {
        let valid_remote = candidates(&[[10, 0, 0, 2]], false, 100);
        let mut invalid_local = candidates(&[[10, 0, 0, 1]], false, 100);
        invalid_local[0].relay_provider = RelayProvider::Turn;
        let mut router = ConnectionRouter::new(true, 100);

        assert_eq!(
            router.set_candidates(invalid_local, valid_remote.clone(), 0, [0; 16]),
            Err(NatError::InvalidCandidate)
        );
        assert!(router.pairs().is_empty());

        let valid = valid_remote[0];
        assert_eq!(
            router.set_candidates(vec![valid; MAX_CANDIDATES + 1], valid_remote, 0, [0; 16]),
            Err(NatError::CandidateLimitReached)
        );
        assert!(router.pairs().is_empty());
    }
}
