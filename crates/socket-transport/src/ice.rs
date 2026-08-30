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
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub const MAX_ICE_CANDIDATES: usize = 8;
pub const MAX_ICE_PAIRS: usize = MAX_ICE_CANDIDATES * MAX_ICE_CANDIDATES;
pub const MAX_ICE_DATAGRAM_BYTES: usize = 2_048;
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
}

/// Short-term ICE credentials. Debug output always redacts both fields.
#[derive(Clone, PartialEq, Eq)]
pub struct IceCredentials {
    ufrag: String,
    password: String,
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
    use std::io;
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

    fn drive_udp_pair(socket_a: &UdpSocket, socket_b: &UdpSocket, a: &mut Ice, b: &mut Ice) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut nominated_a = false;
        let mut nominated_b = false;
        let mut buffer = [0_u8; MAX_ICE_DATAGRAM_BYTES];
        while Instant::now() < deadline {
            let now = Instant::now();
            a.advance(now).expect("advance udp a");
            b.advance(now).expect("advance udp b");
            while let Some(transmit) = a.poll_transmit().expect("udp transmit a") {
                assert_eq!(transmit.source, socket_a.local_addr().unwrap());
                socket_a
                    .send_to(&transmit.contents, transmit.destination)
                    .expect("send ICE a");
            }
            while let Some(transmit) = b.poll_transmit().expect("udp transmit b") {
                assert_eq!(transmit.source, socket_b.local_addr().unwrap());
                socket_b
                    .send_to(&transmit.contents, transmit.destination)
                    .expect("send ICE b");
            }
            for (socket, agent) in [(socket_a, &mut *a), (socket_b, &mut *b)] {
                loop {
                    match socket.recv_from(&mut buffer) {
                        Ok((length, source)) => {
                            assert!(agent
                                .handle_datagram(
                                    now,
                                    source,
                                    socket.local_addr().unwrap(),
                                    &buffer[..length],
                                )
                                .expect("receive ICE"));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("receive ICE failed: {error}"),
                    }
                }
            }
            while let Some(event) = a.poll_event() {
                if let IceEvent::Nominated {
                    source,
                    destination,
                } = event
                {
                    assert_eq!(source, socket_a.local_addr().unwrap());
                    assert_eq!(destination, socket_b.local_addr().unwrap());
                    nominated_a = true;
                }
            }
            while let Some(event) = b.poll_event() {
                if let IceEvent::Nominated {
                    source,
                    destination,
                } = event
                {
                    assert_eq!(source, socket_b.local_addr().unwrap());
                    assert_eq!(destination, socket_a.local_addr().unwrap());
                    nominated_b = true;
                }
            }
            if a.state().is_connected() && b.state().is_connected() && nominated_a && nominated_b {
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("real UDP ICE did not nominate");
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

    fn drain_socket(socket: &UdpSocket) {
        let mut buffer = [0_u8; MAX_ICE_DATAGRAM_BYTES];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("drain ICE socket failed: {error}"),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_ice_nominated_sockets_hand_off_to_exact_mtls_quinn() {
        let socket_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("socket a");
        let socket_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("socket b");
        socket_a.set_nonblocking(true).unwrap();
        socket_b.set_nonblocking(true).unwrap();
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
        drive_udp_pair(&socket_a, &socket_b, &mut a, &mut b);
        drain_socket(&socket_a);
        drain_socket(&socket_b);

        let (server_config, client_config, server_certificate, client_certificate) =
            test_tls_configs();
        let server_endpoint = bind_server_on_socket(server_config, socket_b).unwrap();
        let client_endpoint = bind_client_on_socket(client_config, socket_a).unwrap();
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
