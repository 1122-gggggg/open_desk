//! Bounded Sans-I/O RFC 8445 connectivity-check adapter.
//!
//! The adapter intentionally owns no socket. Callers feed received STUN
//! datagrams into [`Ice::handle_datagram`] and send [`IceTransmit`] values on
//! the exact socket represented by `source`. This permits sequential ownership:
//! run ICE first, stop raw reads, then hand the nominated socket to Quinn.
//! It does not multiplex ICE with a socket already owned by Quinn.
//!
//! ICE uses HMAC-SHA1 for the standardized STUN `MESSAGE-INTEGRITY` attribute.
//! SHA-1 is not used here as a password hash or signature algorithm.
//! The upstream state machine's transaction IDs are correlation values, not
//! authentication nonces; authenticity comes from wrapper-generated CSPRNG
//! short-term credentials and STUN HMAC validation.

use ice_core::{Candidate, IceAgent, IceAgentEvent, IceConnectionState, IceCreds};
use std::error::Error;
use std::fmt;
use std::net::UdpSocket;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub const MAX_ICE_CANDIDATES: usize = 8;
pub const MAX_ICE_PAIRS: usize = MAX_ICE_CANDIDATES * MAX_ICE_CANDIDATES;
pub const MAX_ICE_DATAGRAM_BYTES: usize = 2_048;
pub const MAX_ICE_IGNORED_DATAGRAMS: usize = 32;
const MAX_ICE_OUTBOUND_DATAGRAMS: usize = 512;
const MAX_ICE_INBOUND_DATAGRAMS: usize = 1024;
const MAX_ICE_INBOUND_BYTES: usize = 2 * 1024 * 1024;
const MAX_ICE_DRAIN_DATAGRAMS: usize = 128;
const ICE_TARGET_MTU: usize = 1_200;
const ICE_WARN_MTU: usize = 1_500;
const ICE_UFRAG_LEN: usize = 16;
const ICE_PASSWORD_LEN: usize = 32;
const ICE_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceRole {
    Controlling,
    Controlled,
}

impl IceRole {
    #[must_use]
    pub const fn from_signaling(role: latencydesk_protocol::IceCredentialRole) -> Self {
        match role {
            latencydesk_protocol::IceCredentialRole::Controlling => Self::Controlling,
            latencydesk_protocol::IceCredentialRole::Controlled => Self::Controlled,
        }
    }

    #[must_use]
    pub const fn to_signaling(self) -> latencydesk_protocol::IceCredentialRole {
        match self {
            Self::Controlling => latencydesk_protocol::IceCredentialRole::Controlling,
            Self::Controlled => latencydesk_protocol::IceCredentialRole::Controlled,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IceCandidateKind {
    Host,
    ServerReflexive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IceCandidate {
    pub address: SocketAddr,
    pub base: SocketAddr,
    pub kind: IceCandidateKind,
}

impl IceCandidate {
    #[must_use]
    pub const fn host(address: SocketAddr) -> Self {
        Self {
            address,
            base: address,
            kind: IceCandidateKind::Host,
        }
    }

    #[must_use]
    pub const fn server_reflexive(address: SocketAddr, base: SocketAddr) -> Self {
        Self {
            address,
            base,
            kind: IceCandidateKind::ServerReflexive,
        }
    }

    pub fn from_protocol(candidate: latencydesk_protocol::IceCandidate) -> Result<Self, IceError> {
        use latencydesk_protocol::{CandidateType, TransportProtocol, WireIpAddr};
        candidate
            .validate()
            .map_err(|_| IceError::UnsupportedCandidate)?;
        if candidate.transport != TransportProtocol::Udp || candidate.component != 1 {
            return Err(IceError::UnsupportedCandidate);
        }
        let address = match candidate.ip {
            WireIpAddr::V4(bytes) => SocketAddr::from((bytes, candidate.port)),
            WireIpAddr::V6(bytes) => SocketAddr::from((bytes, candidate.port)),
        };
        let (kind, base) = match candidate.candidate_type {
            CandidateType::Host if candidate.related_address.is_none() => {
                (IceCandidateKind::Host, address)
            }
            CandidateType::ServerReflexive => {
                let Some((related, port)) = candidate.related_address else {
                    return Err(IceError::UnsupportedCandidate);
                };
                let base = match related {
                    WireIpAddr::V4(bytes) => SocketAddr::from((bytes, port)),
                    WireIpAddr::V6(bytes) => SocketAddr::from((bytes, port)),
                };
                (IceCandidateKind::ServerReflexive, base)
            }
            _ => return Err(IceError::UnsupportedCandidate),
        };
        let converted = Self {
            address,
            base,
            kind,
        };
        validate_candidate(converted)?;
        Ok(converted)
    }

    /// First application-probe profile: exactly one UDP component-1 Host
    /// candidate. Server-reflexive support remains in the generic adapter but
    /// is deliberately unavailable until a real NAT/STUN matrix is gated.
    pub fn from_probe_protocol(
        candidate: latencydesk_protocol::IceCandidate,
    ) -> Result<Self, IceError> {
        let converted = Self::from_protocol(candidate)?;
        if converted.kind != IceCandidateKind::Host || !converted.address.is_ipv4() {
            return Err(IceError::UnsupportedCandidate);
        }
        Ok(converted)
    }

    /// Validates the first probe profile's entire remote set: one IPv4 Host
    /// candidate on the already-authenticated peer IP, but a fresh UDP port.
    pub fn probe_remote_from_exchange(
        exchange: &latencydesk_protocol::CandidateExchange,
        active_peer: SocketAddr,
    ) -> Result<Self, IceError> {
        if exchange.candidates.len() != 1 || !active_peer.is_ipv4() {
            return Err(IceError::InvalidProbeCandidateSet);
        }
        let candidate = Self::from_probe_protocol(exchange.candidates[0])?;
        if candidate.address.ip() != active_peer.ip() || candidate.address == active_peer {
            return Err(IceError::InvalidProbeCandidateSet);
        }
        Ok(candidate)
    }
}

/// Short-term ICE credentials. Debug output always redacts both fields.
#[derive(Clone, PartialEq, Eq)]
pub struct IceCredentials {
    ufrag: String,
    password: String,
}

impl IceCredentials {
    /// Convert credentials for authenticated, secret-safe protocol signaling.
    pub fn to_signaling(
        &self,
        exchange_id: u64,
        generation: u32,
        role: IceRole,
    ) -> Result<latencydesk_protocol::IceCredentialExchange, IceError> {
        latencydesk_protocol::IceCredentialExchange::new(
            latencydesk_protocol::IceCredentialExchange::VERSION,
            exchange_id,
            generation,
            role.to_signaling(),
            self.ufrag.clone(),
            self.password.clone(),
        )
        .map_err(|_| IceError::InvalidCredentials)
    }
}

impl IceCredentials {
    pub fn generate() -> Result<Self, IceError> {
        let mut ufrag_entropy = [0_u8; ICE_UFRAG_LEN];
        let mut password_entropy = [0_u8; ICE_PASSWORD_LEN];
        getrandom::getrandom(&mut ufrag_entropy).map_err(|_| IceError::EntropyUnavailable)?;
        getrandom::getrandom(&mut password_entropy).map_err(|_| IceError::EntropyUnavailable)?;
        let ufrag = encode_ice_entropy(&ufrag_entropy);
        let password = encode_ice_entropy(&password_entropy);
        ufrag_entropy.zeroize();
        password_entropy.zeroize();
        Self::from_parts(ufrag, password)
    }

    pub fn from_parts(mut ufrag: String, mut password: String) -> Result<Self, IceError> {
        if !(4..=256).contains(&ufrag.len())
            || !(22..=256).contains(&password.len())
            || !ufrag.bytes().all(is_ice_char)
            || !password.bytes().all(is_ice_char)
        {
            ufrag.zeroize();
            password.zeroize();
            return Err(IceError::InvalidCredentials);
        }
        Ok(Self { ufrag, password })
    }

    pub fn from_signaling(
        exchange: &latencydesk_protocol::IceCredentialExchange,
    ) -> Result<Self, IceError> {
        exchange.with_password(|password| {
            Self::from_parts(exchange.ufrag().to_owned(), password.to_owned())
        })
    }

    #[must_use]
    pub fn ufrag(&self) -> &str {
        &self.ufrag
    }

    #[must_use]
    pub fn password_len(&self) -> usize {
        self.password.len()
    }

    fn to_core(&self) -> IceCreds {
        IceCreds {
            ufrag: self.ufrag.clone(),
            pass: self.password.clone(),
        }
    }
}

impl fmt::Debug for IceCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IceCredentials")
            .field("ufrag", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Drop for IceCredentials {
    fn drop(&mut self) {
        self.ufrag.zeroize();
        self.password.zeroize();
    }
}

fn encode_ice_entropy(entropy: &[u8]) -> String {
    entropy
        .iter()
        .map(|byte| ICE_CHARS[usize::from(*byte & 0x3f)] as char)
        .collect()
}

const fn is_ice_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

#[derive(Clone, Debug)]
pub struct IceConfig {
    pub timing_advance: Duration,
    pub initial_rto: Duration,
    pub max_rto: Duration,
    pub max_retransmits: usize,
    pub establishment_deadline: Duration,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            timing_advance: Duration::from_millis(50),
            initial_rto: Duration::from_millis(250),
            max_rto: Duration::from_secs(3),
            max_retransmits: 7,
            establishment_deadline: Duration::from_secs(20),
        }
    }
}

impl IceConfig {
    pub fn validate(&self) -> Result<(), IceError> {
        if !(Duration::from_millis(10)..=Duration::from_secs(1)).contains(&self.timing_advance)
            || !(Duration::from_millis(10)..=Duration::from_secs(1)).contains(&self.initial_rto)
            || self.max_rto < self.initial_rto
            || self.max_rto > Duration::from_secs(3)
            || !(1..=9).contains(&self.max_retransmits)
            || self.establishment_deadline < self.initial_rto
            || self.establishment_deadline > Duration::from_secs(40)
        {
            return Err(IceError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum IceError {
    InvalidConfig,
    InvalidCredentials,
    EntropyUnavailable,
    CandidateLimit,
    DuplicateCandidate,
    MixedAddressFamily,
    UnsupportedCandidate,
    RemoteCredentialsChanged,
    InvalidDatagram,
    UnexpectedDatagramDestination,
    OversizedTransmit(usize),
    AgentInvariant,
    EstablishmentDeadlineExceeded,
    Cancelled,
    Io(std::io::Error),
    IgnoredDatagramLimit,
    TrafficLimit,
    InvalidProbeCandidateSet,
    WorkerFailed,
    WorkerTimeout,
    Agent(ice_core::IceError),
}

impl fmt::Display for IceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for IceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Agent(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ice_core::IceError> for IceError {
    fn from(error: ice_core::IceError) -> Self {
        Self::Agent(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceTransmit {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub contents: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceState {
    New,
    Checking,
    Connected,
    Completed,
    Disconnected,
}

impl IceState {
    #[must_use]
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected | Self::Completed)
    }
}

impl From<IceConnectionState> for IceState {
    fn from(state: IceConnectionState) -> Self {
        match state {
            IceConnectionState::New => Self::New,
            IceConnectionState::Checking => Self::Checking,
            IceConnectionState::Connected => Self::Connected,
            IceConnectionState::Completed => Self::Completed,
            IceConnectionState::Disconnected => Self::Disconnected,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IceStats {
    pub binding_requests_sent: u64,
    pub binding_successes_received: u64,
    pub binding_requests_received: u64,
    pub discovered_remote_addresses: u64,
    pub nominations_sent: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceEvent {
    Restart,
    State(IceState),
    Discovered {
        source: SocketAddr,
    },
    Nominated {
        source: SocketAddr,
        destination: SocketAddr,
    },
}

pub struct Ice {
    agent: IceAgent,
    configured_role: IceRole,
    local_candidates: Vec<IceCandidate>,
    remote_candidates: Vec<IceCandidate>,
    remote_credentials: Option<IceCredentials>,
    family_is_ipv4: Option<bool>,
    started_at: Instant,
    establishment_deadline: Duration,
    ever_connected: bool,
}

impl fmt::Debug for Ice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ice")
            .field("configured_role", &self.configured_role)
            .field("effective_role", &self.effective_role())
            .field("local_candidates", &self.local_candidates.len())
            .field("remote_candidates", &self.remote_candidates.len())
            .field("state", &self.state())
            .finish()
    }
}

impl Ice {
    pub fn new(role: IceRole, config: IceConfig) -> Result<(Self, IceCredentials), IceError> {
        Self::new_at(role, config, Instant::now())
    }

    pub fn new_at(
        role: IceRole,
        config: IceConfig,
        started_at: Instant,
    ) -> Result<(Self, IceCredentials), IceError> {
        let credentials = IceCredentials::generate()?;
        let agent = Self::build_agent(role, &config, &credentials)?;
        Ok((
            Self {
                agent,
                configured_role: role,
                local_candidates: Vec::new(),
                remote_candidates: Vec::new(),
                remote_credentials: None,
                family_is_ipv4: None,
                started_at,
                establishment_deadline: config.establishment_deadline,
                ever_connected: false,
            },
            credentials,
        ))
    }

    #[cfg(test)]
    fn with_credentials_at(
        role: IceRole,
        config: IceConfig,
        started_at: Instant,
        credentials: &IceCredentials,
    ) -> Result<Self, IceError> {
        let agent = Self::build_agent(role, &config, credentials)?;
        Ok(Self {
            agent,
            configured_role: role,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            remote_credentials: None,
            family_is_ipv4: None,
            started_at,
            establishment_deadline: config.establishment_deadline,
            ever_connected: false,
        })
    }

    fn build_agent(
        role: IceRole,
        config: &IceConfig,
        credentials: &IceCredentials,
    ) -> Result<IceAgent, IceError> {
        config.validate()?;
        let mut agent = IceAgent::new(credentials.to_core());
        agent.set_controlling(matches!(role, IceRole::Controlling));
        agent.set_control_tie_breaker(random_nonzero_u64()?);
        agent.set_max_candidate_pairs(MAX_ICE_PAIRS);
        agent.set_timing_advance(config.timing_advance);
        agent.set_initial_stun_rto(config.initial_rto);
        agent.set_max_stun_rto(config.max_rto);
        agent.set_max_stun_retransmits(config.max_retransmits);
        agent.set_mtu(ICE_TARGET_MTU..=ICE_WARN_MTU);
        Ok(agent)
    }

    pub fn set_remote_credentials(&mut self, credentials: &IceCredentials) -> Result<(), IceError> {
        if let Some(current) = &self.remote_credentials {
            if current != credentials {
                return Err(IceError::RemoteCredentialsChanged);
            }
            return Ok(());
        }
        self.agent.set_remote_credentials(credentials.to_core());
        self.remote_credentials = Some(credentials.clone());
        Ok(())
    }

    pub fn add_local_candidate(&mut self, candidate: IceCandidate) -> Result<(), IceError> {
        self.add_candidate(candidate, true)
    }

    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) -> Result<(), IceError> {
        self.add_candidate(candidate, false)
    }

    fn add_candidate(&mut self, candidate: IceCandidate, local: bool) -> Result<(), IceError> {
        validate_candidate(candidate)?;
        let family_is_ipv4 = candidate.address.is_ipv4();
        if self
            .family_is_ipv4
            .is_some_and(|existing| existing != family_is_ipv4)
        {
            return Err(IceError::MixedAddressFamily);
        }
        let candidates = if local {
            &mut self.local_candidates
        } else {
            &mut self.remote_candidates
        };
        if candidates.len() >= MAX_ICE_CANDIDATES {
            return Err(IceError::CandidateLimit);
        }
        if candidates.contains(&candidate) {
            return Err(IceError::DuplicateCandidate);
        }
        let core = match candidate.kind {
            IceCandidateKind::Host => Candidate::host(candidate.address, "udp"),
            IceCandidateKind::ServerReflexive => {
                Candidate::server_reflexive(candidate.address, candidate.base, "udp")
            }
        }
        .map_err(|_| IceError::UnsupportedCandidate)?;
        if local {
            if self.agent.add_local_candidate(core).is_none() {
                return Err(IceError::UnsupportedCandidate);
            }
        } else {
            self.agent.add_remote_candidate(core);
        }
        candidates.push(candidate);
        self.family_is_ipv4 = Some(family_is_ipv4);
        Ok(())
    }

    #[must_use]
    pub fn candidate_counts(&self) -> (usize, usize) {
        (self.local_candidates.len(), self.remote_candidates.len())
    }

    #[must_use]
    pub fn candidate_pair_upper_bound(&self) -> usize {
        self.local_candidates
            .len()
            .saturating_mul(self.remote_candidates.len())
    }

    pub fn advance(&mut self, now: Instant) -> Result<(), IceError> {
        if self.expired(now) {
            return Err(IceError::EstablishmentDeadlineExceeded);
        }
        self.agent.handle_timeout(now);
        self.update_connected_state();
        Ok(())
    }

    pub fn handle_datagram(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        bytes: &[u8],
    ) -> Result<bool, IceError> {
        if self.expired(now) {
            return Err(IceError::EstablishmentDeadlineExceeded);
        }
        if bytes.is_empty()
            || bytes.len() > MAX_ICE_DATAGRAM_BYTES
            || !is_usable_address(source)
            || source.is_ipv4() != destination.is_ipv4()
        {
            return Err(IceError::InvalidDatagram);
        }
        if !self
            .local_candidates
            .iter()
            .any(|candidate| candidate.base == destination)
        {
            return Err(IceError::UnexpectedDatagramDestination);
        }
        latencydesk_protocol::stun::validate_message_fingerprint(bytes)
            .map_err(|_| IceError::InvalidDatagram)?;
        let message =
            ice_core::stun::StunMessage::parse(bytes).map_err(|_| IceError::InvalidDatagram)?;
        let packet = ice_core::stun::StunPacket {
            proto: ice_core::Protocol::Udp,
            source,
            destination,
            message,
        };
        let accepted = self.agent.handle_packet(now, packet);
        self.update_connected_state();
        Ok(accepted)
    }

    pub fn poll_transmit(&mut self) -> Result<Option<IceTransmit>, IceError> {
        let Some(transmit) = self.agent.poll_transmit() else {
            return Ok(None);
        };
        let contents: Vec<u8> = transmit.contents.into();
        if contents.len() > MAX_ICE_DATAGRAM_BYTES {
            return Err(IceError::OversizedTransmit(contents.len()));
        }
        if !self
            .local_candidates
            .iter()
            .any(|candidate| candidate.base == transmit.source)
        {
            return Err(IceError::AgentInvariant);
        }
        if !is_usable_address(transmit.destination)
            || transmit.source.is_ipv4() != transmit.destination.is_ipv4()
        {
            return Err(IceError::AgentInvariant);
        }
        Ok(Some(IceTransmit {
            source: transmit.source,
            destination: transmit.destination,
            contents,
        }))
    }

    pub fn poll_event(&mut self) -> Option<IceEvent> {
        self.agent.poll_event().map(|event| match event {
            IceAgentEvent::IceRestart(_) => IceEvent::Restart,
            IceAgentEvent::IceConnectionStateChange(state) => IceEvent::State(state.into()),
            IceAgentEvent::DiscoveredRecv { source, .. } => IceEvent::Discovered { source },
            IceAgentEvent::NominatedSend {
                source,
                destination,
                ..
            } => IceEvent::Nominated {
                source,
                destination,
            },
        })
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.agent.poll_timeout()
    }

    #[must_use]
    pub fn state(&self) -> IceState {
        self.agent.state().into()
    }

    #[must_use]
    pub fn configured_role(&self) -> IceRole {
        self.configured_role
    }

    #[must_use]
    pub fn effective_role(&self) -> IceRole {
        if self.agent.controlling() {
            IceRole::Controlling
        } else {
            IceRole::Controlled
        }
    }

    #[cfg(test)]
    fn set_tie_breaker_for_test(&mut self, tie_breaker: u64) {
        assert_ne!(tie_breaker, 0);
        self.agent.set_control_tie_breaker(tie_breaker);
    }

    #[must_use]
    pub fn stats(&self) -> IceStats {
        let stats = self.agent.stats();
        IceStats {
            binding_requests_sent: stats.bind_request_sent,
            binding_successes_received: stats.bind_success_recv,
            binding_requests_received: stats.bind_request_recv,
            discovered_remote_addresses: stats.discovered_recv_count,
            nominations_sent: stats.nomination_send_count,
        }
    }

    #[must_use]
    pub fn liveness_timeout(&self) -> Duration {
        self.agent.ice_timeout()
    }

    #[must_use]
    pub fn expired(&self, now: Instant) -> bool {
        !self.ever_connected
            && now
                .checked_duration_since(self.started_at)
                .is_some_and(|elapsed| elapsed >= self.establishment_deadline)
    }

    fn update_connected_state(&mut self) {
        self.ever_connected |= self.agent.state().is_connected();
    }
}

#[derive(Clone, Debug)]
pub struct IceRunControl {
    cancelled: Arc<AtomicBool>,
    nominated: Arc<AtomicBool>,
    handoff: Arc<AtomicBool>,
}

impl Default for IceRunControl {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            nominated: Arc::new(AtomicBool::new(false)),
            handoff: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl IceRunControl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    pub fn request_handoff(&self) {
        self.handoff.store(true, Ordering::Release);
    }
    pub fn handoff_requested(&self) -> bool {
        self.handoff.load(Ordering::Acquire)
    }
    pub fn is_nominated(&self) -> bool {
        self.nominated.load(Ordering::Acquire)
    }
}
pub type IceCancellation = IceRunControl;

/// Joinable owner for the one blocking raw-UDP ICE loop. Dropping the handle
/// requests cancellation; successful socket handoff always joins the worker.
#[derive(Debug)]
pub struct IceSocketWorker {
    control: IceRunControl,
    task: Option<tokio::task::JoinHandle<Result<IceSocketHandoff, IceError>>>,
}

impl IceSocketWorker {
    pub fn spawn(socket: UdpSocket, ice: Ice) -> Self {
        let control = IceRunControl::new();
        let worker_control = control.clone();
        let task =
            tokio::task::spawn_blocking(move || run_ice_on_socket(socket, ice, &worker_control));
        Self {
            control,
            task: Some(task),
        }
    }

    #[must_use]
    pub fn control(&self) -> IceRunControl {
        self.control.clone()
    }

    pub async fn wait_nominated(&mut self, timeout: Duration) -> Result<(), IceError> {
        if timeout.is_zero() {
            return Err(IceError::WorkerTimeout);
        }
        let wait = async {
            loop {
                if self.control.is_nominated() {
                    return Ok(());
                }
                if self.task.as_ref().is_some_and(|task| task.is_finished()) {
                    let task = self.task.take().ok_or(IceError::WorkerFailed)?;
                    return match task.await {
                        Ok(Err(error)) => Err(error),
                        Ok(Ok(_)) | Err(_) => Err(IceError::WorkerFailed),
                    };
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| IceError::WorkerTimeout)?
    }

    pub async fn handoff(mut self, timeout: Duration) -> Result<IceSocketHandoff, IceError> {
        self.control.request_handoff();
        let mut task = self.task.take().ok_or(IceError::WorkerFailed)?;
        let result = tokio::time::timeout(timeout, &mut task).await;
        match result {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(IceError::WorkerFailed),
            Err(_) => {
                self.control.cancel();
                let _ = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
                Err(IceError::WorkerTimeout)
            }
        }
    }

    pub async fn cancel(mut self, timeout: Duration) -> Result<(), IceError> {
        self.control.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match tokio::time::timeout(timeout, &mut task).await {
            Ok(Ok(Err(IceError::Cancelled))) => Ok(()),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Ok(Ok(_))) | Ok(Err(_)) => Err(IceError::WorkerFailed),
            Err(_) => Err(IceError::WorkerTimeout),
        }
    }
}

impl Drop for IceSocketWorker {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

pub struct IceSocketHandoff {
    pub socket: UdpSocket,
    pub local_candidates: Vec<IceCandidate>,
    pub remote_candidates: Vec<IceCandidate>,
    pub nominated: (SocketAddr, SocketAddr),
    pub effective_role: IceRole,
    pub stats: IceStats,
    pub elapsed: Duration,
}

impl fmt::Debug for IceSocketHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceSocketHandoff")
            .field("local_candidates", &self.local_candidates.len())
            .field("remote_candidates", &self.remote_candidates.len())
            .field("nominated", &self.nominated)
            .field("effective_role", &self.effective_role)
            .field("stats", &self.stats)
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

/// Run the bounded ICE state machine on one exclusively-owned UDP socket.
/// The socket is returned unchanged only after nomination; every other exit
/// drops it, preventing accidental reuse after cancellation or timeout.
pub fn run_ice_on_socket(
    socket: UdpSocket,
    mut ice: Ice,
    cancellation: &IceRunControl,
) -> Result<IceSocketHandoff, IceError> {
    socket.set_nonblocking(true).map_err(IceError::Io)?;
    let local = socket.local_addr().map_err(IceError::Io)?;
    if ice.local_candidates.is_empty() {
        return Err(IceError::AgentInvariant);
    }
    if !ice
        .local_candidates
        .iter()
        .all(|candidate| candidate.base == local)
    {
        return Err(IceError::AgentInvariant);
    }
    let started = Instant::now();
    let mut nominated = None;
    let mut buffer = [0_u8; MAX_ICE_DATAGRAM_BYTES];
    let mut ignored = 0_usize;
    let mut outbound = 0_usize;
    let mut inbound = 0_usize;
    let mut inbound_bytes = 0_usize;
    loop {
        let now = Instant::now();
        if cancellation.is_cancelled() {
            return Err(IceError::Cancelled);
        }
        ice.advance(now)?;
        while let Some(transmit) = ice.poll_transmit()? {
            if transmit.source != local {
                return Err(IceError::AgentInvariant);
            }
            let mut sent = false;
            for _ in 0..4 {
                match socket.send_to(&transmit.contents, transmit.destination) {
                    Ok(sent_bytes) if sent_bytes == transmit.contents.len() => {
                        sent = true;
                        break;
                    }
                    Ok(_) => return Err(IceError::AgentInvariant),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now()
                    }
                    Err(error) => return Err(IceError::Io(error)),
                }
            }
            if !sent {
                return Err(IceError::Io(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                )));
            }
            outbound += 1;
            if outbound > MAX_ICE_OUTBOUND_DATAGRAMS {
                return Err(IceError::TrafficLimit);
            }
        }
        let mut received_this_round = 0_usize;
        loop {
            if received_this_round >= MAX_ICE_INBOUND_DATAGRAMS {
                return Err(IceError::TrafficLimit);
            }
            match socket.recv_from(&mut buffer) {
                Ok((length, source)) => {
                    received_this_round += 1;
                    inbound += 1;
                    inbound_bytes = inbound_bytes.saturating_add(length);
                    if inbound > MAX_ICE_INBOUND_DATAGRAMS || inbound_bytes > MAX_ICE_INBOUND_BYTES
                    {
                        return Err(IceError::TrafficLimit);
                    }
                    match ice.handle_datagram(now, source, local, &buffer[..length]) {
                        Ok(true) => {}
                        Ok(false)
                        | Err(IceError::InvalidDatagram)
                        | Err(IceError::UnexpectedDatagramDestination) => {
                            ignored += 1;
                            if ignored > MAX_ICE_IGNORED_DATAGRAMS {
                                return Err(IceError::IgnoredDatagramLimit);
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(IceError::Io(error)),
            }
        }
        while let Some(event) = ice.poll_event() {
            if let IceEvent::Nominated {
                source,
                destination,
            } = event
            {
                if source != local || !is_usable_address(destination) {
                    return Err(IceError::AgentInvariant);
                }
                nominated = Some((source, destination));
                cancellation.nominated.store(true, Ordering::Release);
            }
        }
        if cancellation.handoff_requested() && ice.state().is_connected() {
            if let Some(nominated) = nominated {
                if nominated.0 != local || !is_usable_address(nominated.1) {
                    return Err(IceError::AgentInvariant);
                }
                // Consume already queued ICE datagrams before transferring ownership.
                let mut drained = false;
                for _ in 0..MAX_ICE_DRAIN_DATAGRAMS {
                    match socket.recv_from(&mut buffer) {
                        Ok(_) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            drained = true;
                            break;
                        }
                        Err(error) => return Err(IceError::Io(error)),
                    }
                }
                if !drained {
                    return Err(IceError::TrafficLimit);
                }
                let effective_role = ice.effective_role();
                if effective_role != ice.configured_role() {
                    return Err(IceError::AgentInvariant);
                }
                let stats = ice.stats();
                return Ok(IceSocketHandoff {
                    socket,
                    local_candidates: ice.local_candidates,
                    remote_candidates: ice.remote_candidates,
                    nominated,
                    effective_role,
                    stats,
                    elapsed: started.elapsed(),
                });
            }
        }
        if ice.expired(now) {
            return Err(IceError::EstablishmentDeadlineExceeded);
        }
        let sleep_for = ice
            .poll_timeout()
            .map_or(Duration::from_millis(5), |deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5))
            });
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }
    }
}

fn validate_candidate(candidate: IceCandidate) -> Result<(), IceError> {
    if !is_usable_address(candidate.address)
        || !is_usable_address(candidate.base)
        || candidate.address.is_ipv4() != candidate.base.is_ipv4()
        || (candidate.kind == IceCandidateKind::Host && candidate.address != candidate.base)
        || (candidate.kind == IceCandidateKind::ServerReflexive
            && candidate.address == candidate.base)
    {
        return Err(IceError::UnsupportedCandidate);
    }
    Ok(())
}

fn is_usable_address(address: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() && !ip.is_link_local()
        }
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

fn random_nonzero_u64() -> Result<u64, IceError> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 8];
        getrandom::getrandom(&mut bytes).map_err(|_| IceError::EntropyUnavailable)?;
        let value = u64::from_be_bytes(bytes);
        bytes.zeroize();
        if value != 0 {
            return Ok(value);
        }
    }
    Err(IceError::EntropyUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{bind_client_on_socket, bind_server_on_socket, QuicConnection};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::{Ipv4Addr, UdpSocket};
    use std::sync::Arc;
    use std::thread;

    const STEP: Duration = Duration::from_millis(50);

    fn credentials(label: char) -> IceCredentials {
        IceCredentials::from_parts(
            format!("{label}ufrag012345678"),
            std::iter::repeat_n(label, ICE_PASSWORD_LEN).collect(),
        )
        .expect("fixed credentials")
    }

    fn fast_config() -> IceConfig {
        IceConfig {
            timing_advance: Duration::from_millis(10),
            initial_rto: Duration::from_millis(20),
            max_rto: Duration::from_millis(100),
            max_retransmits: 4,
            establishment_deadline: Duration::from_secs(5),
        }
    }

    fn configured_pair(both_controlling: bool, wrong_credentials: bool) -> (Ice, Ice, Instant) {
        let start = Instant::now();
        let credentials_a = credentials('a');
        let credentials_b = credentials('b');
        let wrong_b = credentials('x');
        let address_a = SocketAddr::from((Ipv4Addr::LOCALHOST, 5_001));
        let address_b = SocketAddr::from((Ipv4Addr::LOCALHOST, 5_002));
        let mut a =
            Ice::with_credentials_at(IceRole::Controlling, fast_config(), start, &credentials_a)
                .expect("agent a");
        let mut b = Ice::with_credentials_at(
            if both_controlling {
                IceRole::Controlling
            } else {
                IceRole::Controlled
            },
            fast_config(),
            start,
            &credentials_b,
        )
        .expect("agent b");
        a.set_tie_breaker_for_test(10);
        b.set_tie_breaker_for_test(20);
        a.set_remote_credentials(if wrong_credentials {
            &wrong_b
        } else {
            &credentials_b
        })
        .expect("remote credentials a");
        b.set_remote_credentials(&credentials_a)
            .expect("remote credentials b");
        a.add_local_candidate(IceCandidate::host(address_a))
            .expect("local a");
        a.add_remote_candidate(IceCandidate::host(address_b))
            .expect("remote b");
        b.add_local_candidate(IceCandidate::host(address_b))
            .expect("local b");
        b.add_remote_candidate(IceCandidate::host(address_a))
            .expect("remote a");
        (a, b, start)
    }

    #[derive(Clone, Copy)]
    enum Delivery {
        Normal,
        Corrupt,
        Drop,
    }

    #[derive(Default)]
    struct DriveReport {
        accepted: usize,
        rejected: usize,
        max_datagram: usize,
        nominations_a: Vec<(SocketAddr, SocketAddr)>,
        nominations_b: Vec<(SocketAddr, SocketAddr)>,
    }

    fn drain_events(agent: &mut Ice, nominations: &mut Vec<(SocketAddr, SocketAddr)>) {
        while let Some(event) = agent.poll_event() {
            if let IceEvent::Nominated {
                source,
                destination,
            } = event
            {
                nominations.push((source, destination));
            }
        }
    }

    fn drive_step(
        a: &mut Ice,
        b: &mut Ice,
        now: Instant,
        delivery: Delivery,
        report: &mut DriveReport,
    ) {
        a.advance(now).expect("advance a");
        b.advance(now).expect("advance b");
        for _ in 0..16 {
            let mut progress = false;
            for from_a in [true, false] {
                loop {
                    let transmit = if from_a {
                        a.poll_transmit().expect("transmit a")
                    } else {
                        b.poll_transmit().expect("transmit b")
                    };
                    let Some(mut transmit) = transmit else {
                        break;
                    };
                    progress = true;
                    report.max_datagram = report.max_datagram.max(transmit.contents.len());
                    if matches!(delivery, Delivery::Drop) {
                        continue;
                    }
                    if matches!(delivery, Delivery::Corrupt) {
                        let last = transmit.contents.len() - 1;
                        transmit.contents[last] ^= 1;
                    }
                    let result = if from_a {
                        b.handle_datagram(
                            now,
                            transmit.source,
                            transmit.destination,
                            &transmit.contents,
                        )
                    } else {
                        a.handle_datagram(
                            now,
                            transmit.source,
                            transmit.destination,
                            &transmit.contents,
                        )
                    };
                    match result {
                        Ok(true) => report.accepted += 1,
                        Ok(false) | Err(_) => report.rejected += 1,
                    }
                }
            }
            if !progress {
                break;
            }
        }
        drain_events(a, &mut report.nominations_a);
        drain_events(b, &mut report.nominations_b);
    }

    fn drive_until_connected(a: &mut Ice, b: &mut Ice, start: Instant) -> DriveReport {
        let mut report = DriveReport::default();
        for step in 0..200_u32 {
            drive_step(a, b, start + STEP * step, Delivery::Normal, &mut report);
            if a.state().is_connected()
                && b.state().is_connected()
                && !report.nominations_a.is_empty()
                && !report.nominations_b.is_empty()
            {
                return report;
            }
        }
        panic!(
            "ICE pair did not connect: a={:?} b={:?}",
            a.state(),
            b.state()
        );
    }

    #[test]
    fn credentials_are_os_random_bounded_and_redacted() {
        let first = IceCredentials::generate().expect("credentials");
        let second = IceCredentials::generate().expect("credentials");
        assert_ne!(first, second);
        assert_eq!(first.ufrag().len(), ICE_UFRAG_LEN);
        assert_eq!(first.password_len(), ICE_PASSWORD_LEN);
        let fixed = credentials('s');
        let rendered = format!("{fixed:?}");
        assert!(!rendered.contains(fixed.ufrag()));
        assert!(!rendered.contains(&"s".repeat(ICE_PASSWORD_LEN)));
        assert!(IceCredentials::from_parts("bad!".into(), "x".repeat(22)).is_err());

        let signaled = latencydesk_protocol::IceCredentialExchange::new(
            1,
            7,
            1,
            latencydesk_protocol::IceCredentialRole::Controlled,
            "peerUfrag".into(),
            "P".repeat(22),
        )
        .unwrap();
        let converted = IceCredentials::from_signaling(&signaled).unwrap();
        assert_eq!(converted.ufrag(), "peerUfrag");
        assert_eq!(converted.password_len(), 22);
        assert_eq!(IceRole::from_signaling(signaled.role), IceRole::Controlled);
        assert_eq!(
            IceRole::Controlling.to_signaling(),
            latencydesk_protocol::IceCredentialRole::Controlling
        );
    }

    #[test]
    fn protocol_candidates_convert_only_supported_udp_shapes() {
        use latencydesk_protocol::{CandidateType, RelayProvider, TransportProtocol, WireIpAddr};
        let host = latencydesk_protocol::IceCandidate {
            foundation: [0; 8],
            component: 1,
            transport: TransportProtocol::Udp,
            priority: 1,
            candidate_type: CandidateType::Host,
            relay_provider: RelayProvider::None,
            ip: WireIpAddr::V4([127, 0, 0, 1]),
            port: 5000,
            related_address: None,
        };
        assert_eq!(
            IceCandidate::from_protocol(host).unwrap(),
            IceCandidate::host("127.0.0.1:5000".parse().unwrap())
        );
        let mut tcp = host;
        tcp.transport = TransportProtocol::Tcp;
        assert!(matches!(
            IceCandidate::from_protocol(tcp),
            Err(IceError::UnsupportedCandidate)
        ));
        let mut srflx = host;
        srflx.candidate_type = CandidateType::ServerReflexive;
        assert!(matches!(
            IceCandidate::from_protocol(srflx),
            Err(IceError::UnsupportedCandidate)
        ));

        let mut srflx = host;
        srflx.candidate_type = CandidateType::ServerReflexive;
        srflx.ip = WireIpAddr::V4([127, 0, 0, 2]);
        srflx.related_address = Some((WireIpAddr::V4([127, 0, 0, 1]), 5000));
        assert!(IceCandidate::from_protocol(srflx).is_ok());
        assert!(matches!(
            IceCandidate::from_probe_protocol(srflx),
            Err(IceError::UnsupportedCandidate)
        ));

        let exchange = latencydesk_protocol::CandidateExchange {
            version: latencydesk_protocol::CandidateExchange::VERSION,
            exchange_id: 7,
            generation: 1,
            candidates: vec![host],
        };
        assert!(IceCandidate::probe_remote_from_exchange(
            &exchange,
            "127.0.0.1:4000".parse().unwrap()
        )
        .is_ok());
        assert!(matches!(
            IceCandidate::probe_remote_from_exchange(&exchange, "127.0.0.1:5000".parse().unwrap()),
            Err(IceError::InvalidProbeCandidateSet)
        ));
        assert!(matches!(
            IceCandidate::probe_remote_from_exchange(&exchange, "127.0.0.2:4000".parse().unwrap()),
            Err(IceError::InvalidProbeCandidateSet)
        ));
        let multiple = latencydesk_protocol::CandidateExchange {
            candidates: vec![host, host],
            ..exchange.clone()
        };
        assert!(matches!(
            IceCandidate::probe_remote_from_exchange(&multiple, "127.0.0.1:4000".parse().unwrap()),
            Err(IceError::InvalidProbeCandidateSet)
        ));
        let ipv6 = latencydesk_protocol::CandidateExchange {
            candidates: vec![latencydesk_protocol::IceCandidate {
                ip: WireIpAddr::V6(std::net::Ipv6Addr::LOCALHOST.octets()),
                port: 5000,
                ..host
            }],
            ..exchange
        };
        assert!(matches!(
            IceCandidate::probe_remote_from_exchange(&ipv6, "[::1]:4000".parse().unwrap()),
            Err(IceError::InvalidProbeCandidateSet)
        ));
    }

    #[test]
    fn candidate_and_policy_bounds_fail_closed() {
        let start = Instant::now();
        let credentials = credentials('a');
        let mut ice =
            Ice::with_credentials_at(IceRole::Controlled, fast_config(), start, &credentials)
                .expect("agent");
        for index in 0..MAX_ICE_CANDIDATES {
            ice.add_local_candidate(IceCandidate::host(SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                10_000 + index as u16,
            ))))
            .expect("bounded local candidate");
        }
        assert!(matches!(
            ice.add_local_candidate(IceCandidate::host(SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                20_000,
            )))),
            Err(IceError::CandidateLimit)
        ));
        let first_remote = IceCandidate::host(SocketAddr::from((Ipv4Addr::LOCALHOST, 30_000)));
        assert!(ice.add_remote_candidate(first_remote).is_ok());
        assert!(matches!(
            ice.add_remote_candidate(first_remote),
            Err(IceError::DuplicateCandidate)
        ));
        assert!(matches!(
            ice.add_remote_candidate(IceCandidate::host("[::1]:10001".parse().unwrap())),
            Err(IceError::MixedAddressFamily)
        ));
        for index in 1..MAX_ICE_CANDIDATES {
            ice.add_remote_candidate(IceCandidate::host(SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                30_000 + index as u16,
            ))))
            .expect("bounded remote candidate");
        }
        assert_eq!(ice.candidate_counts(), (8, 8));
        assert_eq!(ice.candidate_pair_upper_bound(), MAX_ICE_PAIRS);
        assert!(IceConfig {
            establishment_deadline: Duration::ZERO,
            ..fast_config()
        }
        .validate()
        .is_err());

        let (mut expiring, _) = Ice::new_at(IceRole::Controlled, fast_config(), start).unwrap();
        assert!(matches!(
            expiring.advance(start + Duration::from_secs(5)),
            Err(IceError::EstablishmentDeadlineExceeded)
        ));
    }

    #[test]
    fn two_agents_authenticate_checks_and_nominate() {
        let (mut a, mut b, start) = configured_pair(false, false);
        let report = drive_until_connected(&mut a, &mut b, start);
        assert!(report.accepted > 0);
        assert_eq!(report.rejected, 0);
        assert!(report.max_datagram <= MAX_ICE_DATAGRAM_BYTES);
        assert_eq!(a.effective_role(), IceRole::Controlling);
        assert_eq!(b.effective_role(), IceRole::Controlled);
        assert!(a.stats().binding_successes_received > 0);
        assert!(b.stats().binding_requests_received > 0);
    }

    #[test]
    fn wrong_credentials_and_mutation_never_nominate() {
        let (mut wrong_a, mut wrong_b, start) = configured_pair(false, true);
        let mut wrong_report = DriveReport::default();
        for step in 0..80_u32 {
            drive_step(
                &mut wrong_a,
                &mut wrong_b,
                start + STEP * step,
                Delivery::Normal,
                &mut wrong_report,
            );
        }
        assert!(!wrong_a.state().is_connected());
        assert!(!wrong_b.state().is_connected());
        assert!(wrong_report.rejected > 0);
        assert!(wrong_report.nominations_a.is_empty());
        assert!(wrong_report.nominations_b.is_empty());

        let (mut corrupt_a, mut corrupt_b, start) = configured_pair(false, false);
        let mut corrupt_report = DriveReport::default();
        for step in 0..80_u32 {
            drive_step(
                &mut corrupt_a,
                &mut corrupt_b,
                start + STEP * step,
                Delivery::Corrupt,
                &mut corrupt_report,
            );
        }
        assert!(!corrupt_a.state().is_connected());
        assert!(!corrupt_b.state().is_connected());
        assert!(corrupt_report.rejected > 0);
    }

    #[test]
    fn role_conflict_resolves_to_one_controlling_agent() {
        let (mut a, mut b, start) = configured_pair(true, false);
        drive_until_connected(&mut a, &mut b, start);
        assert_ne!(a.effective_role(), b.effective_role());
        assert_eq!(a.effective_role(), IceRole::Controlled);
        assert_eq!(b.effective_role(), IceRole::Controlling);
    }

    #[test]
    fn established_pair_expires_when_all_liveness_checks_are_dropped() {
        let (mut a, mut b, start) = configured_pair(false, false);
        drive_until_connected(&mut a, &mut b, start);
        let mut report = DriveReport::default();
        let disconnect_start = start + Duration::from_secs(10);
        for step in 0..400_u32 {
            drive_step(
                &mut a,
                &mut b,
                disconnect_start + STEP * step,
                Delivery::Drop,
                &mut report,
            );
            if a.state() == IceState::Disconnected && b.state() == IceState::Disconnected {
                return;
            }
        }
        panic!(
            "ICE liveness did not expire: a={:?} b={:?}",
            a.state(),
            b.state()
        );
    }

    struct TestIdentity {
        certificate: CertificateDer<'static>,
        private_key: PrivateKeyDer<'static>,
    }

    fn test_identity(name: &str) -> TestIdentity {
        let certified = generate_simple_self_signed(vec![name.into()]).expect("certificate");
        TestIdentity {
            certificate: certified.cert.der().clone(),
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )),
        }
    }

    fn test_tls_configs() -> (quinn::ServerConfig, quinn::ClientConfig, Vec<u8>, Vec<u8>) {
        let server_identity = test_identity("localhost");
        let client_identity = test_identity("latencydesk-ice-client");
        let server_certificate = server_identity.certificate.as_ref().to_vec();
        let client_certificate = client_identity.certificate.as_ref().to_vec();

        let mut client_roots = rustls::RootCertStore::empty();
        client_roots
            .add(server_identity.certificate.clone())
            .expect("server root");
        let client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(client_roots)
        .with_client_auth_cert(
            vec![client_identity.certificate],
            client_identity.private_key,
        )
        .expect("client identity");

        let mut server_roots = rustls::RootCertStore::empty();
        server_roots
            .add(client_certificate.clone().into())
            .expect("client root");
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(server_roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("client verifier");
        let server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_identity.certificate],
            server_identity.private_key,
        )
        .expect("server identity");

        let server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_crypto))
                .expect("server QUIC crypto"),
        ));
        let client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_crypto))
                .expect("client QUIC crypto"),
        ));
        (server, client, server_certificate, client_certificate)
    }

    fn real_udp_runner_handoffs() -> (IceSocketHandoff, IceSocketHandoff) {
        let socket_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("socket a");
        let socket_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("socket b");
        let address_a = socket_a.local_addr().unwrap();
        let address_b = socket_b.local_addr().unwrap();
        let start = Instant::now();
        let credentials_a = credentials('a');
        let credentials_b = credentials('b');
        let mut a =
            Ice::with_credentials_at(IceRole::Controlling, fast_config(), start, &credentials_a)
                .unwrap();
        let mut b =
            Ice::with_credentials_at(IceRole::Controlled, fast_config(), start, &credentials_b)
                .unwrap();
        a.set_tie_breaker_for_test(10);
        b.set_tie_breaker_for_test(20);
        a.set_remote_credentials(&credentials_b).unwrap();
        b.set_remote_credentials(&credentials_a).unwrap();
        a.add_local_candidate(IceCandidate::host(address_a))
            .unwrap();
        a.add_remote_candidate(IceCandidate::host(address_b))
            .unwrap();
        b.add_local_candidate(IceCandidate::host(address_b))
            .unwrap();
        b.add_remote_candidate(IceCandidate::host(address_a))
            .unwrap();

        let control_a = IceRunControl::new();
        let control_b = IceRunControl::new();
        let worker_control_a = control_a.clone();
        let worker_control_b = control_b.clone();
        let worker_a = thread::spawn(move || run_ice_on_socket(socket_a, a, &worker_control_a));
        let worker_b = thread::spawn(move || run_ice_on_socket(socket_b, b, &worker_control_b));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !(control_a.is_nominated() && control_b.is_nominated()) {
            assert!(Instant::now() < deadline, "both ICE runners must nominate");
            thread::sleep(Duration::from_millis(1));
        }
        control_a.request_handoff();
        control_b.request_handoff();
        let handoff_a = worker_a.join().unwrap().unwrap();
        let handoff_b = worker_b.join().unwrap().unwrap();
        assert_eq!(handoff_a.nominated, (address_a, address_b));
        assert_eq!(handoff_b.nominated, (address_b, address_a));
        assert_eq!(handoff_a.effective_role, IceRole::Controlling);
        assert_eq!(handoff_b.effective_role, IceRole::Controlled);
        assert!(handoff_a.stats.binding_requests_sent > 0);
        assert!(handoff_b.stats.binding_requests_received > 0);
        (handoff_a, handoff_b)
    }

    #[test]
    fn real_socket_runners_require_two_phase_handoff_and_preserve_ports() {
        let (handoff_a, handoff_b) = real_udp_runner_handoffs();
        assert_eq!(
            handoff_a.socket.local_addr().unwrap(),
            handoff_a.nominated.0
        );
        assert_eq!(
            handoff_b.socket.local_addr().unwrap(),
            handoff_b.nominated.0
        );
    }

    #[test]
    fn socket_runner_cancellation_wrong_base_and_noise_fail_boundedly() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = socket.local_addr().unwrap();
        let remote_port = if local.port() == u16::MAX {
            u16::MAX - 1
        } else {
            local.port() + 1
        };
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, remote_port));
        let credentials_local = credentials('a');
        let credentials_remote = credentials('b');
        let mut cancelled = Ice::with_credentials_at(
            IceRole::Controlling,
            fast_config(),
            Instant::now(),
            &credentials_local,
        )
        .unwrap();
        cancelled
            .set_remote_credentials(&credentials_remote)
            .unwrap();
        cancelled
            .add_local_candidate(IceCandidate::host(local))
            .unwrap();
        cancelled
            .add_remote_candidate(IceCandidate::host(remote))
            .unwrap();
        let control = IceRunControl::new();
        control.cancel();
        assert!(matches!(
            run_ice_on_socket(socket, cancelled, &control),
            Err(IceError::Cancelled)
        ));

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let actual = socket.local_addr().unwrap();
        let wrong_port = if actual.port() == u16::MAX {
            u16::MAX - 1
        } else {
            actual.port() + 1
        };
        let wrong = SocketAddr::new(actual.ip(), wrong_port);
        let mut wrong_base = Ice::with_credentials_at(
            IceRole::Controlling,
            fast_config(),
            Instant::now(),
            &credentials_local,
        )
        .unwrap();
        wrong_base
            .set_remote_credentials(&credentials_remote)
            .unwrap();
        wrong_base
            .add_local_candidate(IceCandidate::host(wrong))
            .unwrap();
        wrong_base
            .add_remote_candidate(IceCandidate::host(remote))
            .unwrap();
        assert!(matches!(
            run_ice_on_socket(socket, wrong_base, &IceRunControl::new()),
            Err(IceError::AgentInvariant)
        ));

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = socket.local_addr().unwrap();
        let mut noisy = Ice::with_credentials_at(
            IceRole::Controlling,
            fast_config(),
            Instant::now(),
            &credentials_local,
        )
        .unwrap();
        noisy.set_remote_credentials(&credentials_remote).unwrap();
        noisy
            .add_local_candidate(IceCandidate::host(local))
            .unwrap();
        noisy
            .add_remote_candidate(IceCandidate::host(remote))
            .unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        for _ in 0..=MAX_ICE_IGNORED_DATAGRAMS {
            sender.send_to(&[1, 2, 3], local).unwrap();
        }
        assert!(matches!(
            run_ice_on_socket(socket, noisy, &IceRunControl::new()),
            Err(IceError::IgnoredDatagramLimit)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_worker_error_can_be_cleaned_without_polling_join_twice() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let actual = socket.local_addr().unwrap();
        let wrong_port = if actual.port() == u16::MAX {
            u16::MAX - 1
        } else {
            actual.port() + 1
        };
        let mut ice = Ice::with_credentials_at(
            IceRole::Controlling,
            fast_config(),
            Instant::now(),
            &credentials('a'),
        )
        .unwrap();
        ice.set_remote_credentials(&credentials('b')).unwrap();
        ice.add_local_candidate(IceCandidate::host(SocketAddr::new(actual.ip(), wrong_port)))
            .unwrap();
        ice.add_remote_candidate(IceCandidate::host(SocketAddr::new(
            actual.ip(),
            actual.port(),
        )))
        .unwrap();
        let mut worker = IceSocketWorker::spawn(socket, ice);
        assert!(matches!(
            worker.wait_nominated(Duration::from_secs(1)).await,
            Err(IceError::AgentInvariant)
        ));
        worker.cancel(Duration::from_secs(1)).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_ice_nominated_sockets_hand_off_to_exact_mtls_quinn() {
        let (handoff_a, handoff_b) = real_udp_runner_handoffs();
        let address_a = handoff_a.nominated.0;
        let address_b = handoff_b.nominated.0;

        let (server_config, client_config, server_certificate, client_certificate) =
            test_tls_configs();
        let server_endpoint = bind_server_on_socket(server_config, handoff_b.socket).unwrap();
        let client_endpoint = bind_client_on_socket(client_config, handoff_a.socket).unwrap();
        assert_eq!(server_endpoint.local_addr().unwrap(), address_b);
        assert_eq!(client_endpoint.local_addr().unwrap(), address_a);
        let (server, client) = tokio::join!(
            QuicConnection::accept(&server_endpoint),
            QuicConnection::connect(&client_endpoint, address_b, "localhost"),
        );
        let server = server.expect("server mTLS");
        let client = client.expect("client mTLS");
        assert_eq!(client.remote_address(), address_b);
        assert_eq!(server.remote_address(), address_a);
        assert_eq!(
            client.peer_certificate_chain().unwrap()[0],
            server_certificate
        );
        assert_eq!(
            server.peer_certificate_chain().unwrap()[0],
            client_certificate
        );
        client.close(0, b"ICE handoff complete");
        let _ = server.closed().await;
        server_endpoint.close(0_u32.into(), b"test complete");
        client_endpoint.close(0_u32.into(), b"test complete");
        server_endpoint.wait_idle().await;
        client_endpoint.wait_idle().await;
    }
}
