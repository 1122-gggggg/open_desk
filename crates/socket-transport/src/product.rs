//! Application-neutral production session semantics over authenticated QUIC.
//!
//! Identity enrollment, certificate creation, and certificate verification are
//! deliberately outside this module. A [`QuicConnection`] supplied here has
//! already completed the caller-configured mutual-TLS handshake.

use crate::quic::{MediaSendOutcome, QuicConnection, QuicInboundStream, QuicTransportError};
use bytes::Bytes;
use latencydesk_protocol::quic::{
    MediaDatagram, SessionStamp, StreamKind, StreamRecord, QUIC_MEDIA_HEADER_LEN,
};
use latencydesk_protocol::{
    CandidateExchange, ControlHeader, ControlKind, ControlPacket, HandshakeCompletedMessage,
    IceCredentialExchange, IceCredentialRole, ProtocolError, RouteTransitionMessage,
    RouteTransitionStage, VideoCodecCapabilities, VideoStreamConfig, MEDIA_HEADER_LEN,
};
use latencydesk_transport::{
    frame_fragments_with_packet_budget, FragmentSpec, IngestOutcome, ReassembledFrame, Reassembler,
    ReassemblyConfig, TransportError, MAX_DATAGRAM_MTU,
};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const ACTIVE_GENERATION: u64 = 1;
const ACTIVE_EPOCH: u32 = 1;
const DEFAULT_PRODUCT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PRODUCT_HANDSHAKE_TIMEOUT_CODE: u32 = 0x102;
const PRODUCT_HANDSHAKE_TIMEOUT_REASON: &[u8] = b"product handshake timed out";
#[cfg(not(test))]
const ROUTE_TRANSITION_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(test)]
const ROUTE_TRANSITION_TIMEOUT: Duration = Duration::from_millis(100);
// The legacy handshake message reserves a nonce field. TLS already provides
// freshness for this adapter, so one canonical value avoids inventing a second
// unauthenticated challenge protocol.
const POST_MTLS_NONCE: [u8; 16] = [0; 16];

/// A peer-authenticated session whose reliable and unreliable records are all
/// bound to one exact active [`SessionStamp`].
#[derive(Debug, Clone)]
pub struct ProductSession {
    connection: QuicConnection,
    stamp: SessionStamp,
    route_epoch: Arc<AtomicU64>,
    route_sequence: Arc<AtomicU64>,
    route_authorized: Arc<AtomicBool>,
    reassembler: Arc<Mutex<Reassembler>>,
    reassembly_config: ReassemblyConfig,
    reassembly_route_epoch: Arc<AtomicU64>,
    last_delivered_frame_id: Arc<Mutex<Option<u64>>>,
    clock_origin: Instant,
    inbound_control: Arc<Mutex<Option<QuicInboundStream>>>,
    candidate_exchange: Arc<Mutex<CandidateExchangeTracker>>,
    ice_generation: Arc<Mutex<IceGenerationTracker>>,
    ice_roles: Arc<Mutex<Option<IceSignalingRoles>>>,
    ice_role_assignment: IceSignalingRoles,
    control_send: Arc<Mutex<()>>,
    route_transition: Arc<Mutex<RouteWireState>>,
    #[cfg(test)]
    ice_send_cancellation_hook: Option<Arc<IceSendCancellationHook>>,
    #[cfg(test)]
    route_send_cancellation_hook: Option<Arc<IceSendCancellationHook>>,
}

/// A fully exact-mTLS-authenticated candidate with no application-lane
/// authority until consumed by [`ProductRouteSet`].
#[derive(Debug)]
pub struct UnauthorizedCandidateSession {
    session: ProductSession,
}

impl UnauthorizedCandidateSession {
    fn new(session: ProductSession) -> Self {
        session.set_route_authorized(false);
        Self { session }
    }

    /// Binds a higher-layer verified route digest to this exact TLS session.
    /// The transcript half is derived internally from the TLS exporter.
    pub fn bind_authenticated_route(
        &self,
        route_digest: [u8; 32],
    ) -> Result<VerifiedRouteBinding, ProductSessionError> {
        route_binding_for_session(&self.session, route_digest)
    }
}

/// Receiver for the dedicated ordered input lane.
#[derive(Debug)]
pub struct InputReceiver {
    connection: QuicConnection,
    stream: QuicInboundStream,
    expected_stamp: SessionStamp,
    route_epoch: Arc<AtomicU64>,
    route_authorized: Arc<AtomicBool>,
}

/// Receiver for the peer's persistent ordered control lane.
#[derive(Debug)]
pub struct ControlReceiver {
    connection: QuicConnection,
    stream: QuicInboundStream,
    expected_stamp: SessionStamp,
    route_epoch: Arc<AtomicU64>,
    route_sequence: Arc<AtomicU64>,
    route_authorized: Arc<AtomicBool>,
    candidate_exchange: CandidateExchangeTracker,
    ice_generation: IceGenerationTracker,
    ice_roles: Arc<Mutex<Option<IceSignalingRoles>>>,
    route_transition: Arc<Mutex<RouteWireState>>,
    #[cfg(test)]
    route_receive_cancellation_hook: Option<Arc<IceSendCancellationHook>>,
}

/// Two exact-mTLS product connections for one lifecycle stamp. Only one index
/// has application authority; the other remains available for bounded rollback.
#[derive(Debug)]
pub struct ProductRouteSet {
    routes: [ProductSession; 2],
    bindings: [VerifiedRouteBinding; 2],
    active: usize,
    transition_timer: Arc<AtomicU64>,
    activation: RouteActivationState,
    transition_route: Option<usize>,
}

/// Route metadata cryptographically bound to one exact-mTLS connection.
/// The higher layer remains responsible for deriving `route_digest` from
/// verified nomination/consent evidence; the transcript digest is derived
/// internally from the TLS exporter and cannot be caller supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRouteBinding {
    route_digest: [u8; 32],
    transcript_digest: [u8; 32],
    connection_id: usize,
    peer_fingerprint: [u8; 32],
}

impl VerifiedRouteBinding {
    /// Returns the public material required to authenticate a route transition.
    /// The exporter secret itself is never exposed.
    #[must_use]
    pub fn transition_material(&self) -> ([u8; 32], [u8; 32]) {
        (self.route_digest, self.transcript_digest)
    }
}

#[derive(Debug)]
pub struct ActiveRouteControlReceiver {
    route_index: usize,
    receiver: ControlReceiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteActivationState {
    Idle,
    AwaitingActivated {
        previous: usize,
        commit: RouteTransitionMessage,
    },
    AwaitingConfirmed {
        commit: RouteTransitionMessage,
    },
}

struct FailClosedRouteSetOperation {
    routes: [ProductSession; 2],
    armed: bool,
}

impl FailClosedRouteSetOperation {
    fn new(routes: &[ProductSession; 2]) -> Self {
        Self {
            routes: [routes[0].clone(), routes[1].clone()],
            armed: true,
        }
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for FailClosedRouteSetOperation {
    fn drop(&mut self) {
        if self.armed {
            for route in &self.routes {
                route.set_route_authorized(false);
                route.close(0x103, b"route-set operation cancelled or failed");
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteWireState {
    Idle,
    PrepareSent(RouteTransitionMessage),
    PrepareReceived(RouteTransitionMessage),
    PreparedSent(RouteTransitionMessage),
    PreparedReceived(RouteTransitionMessage),
}

fn same_route_transition(first: RouteTransitionMessage, second: RouteTransitionMessage) -> bool {
    first.sequence == second.sequence
        && first.base_route_epoch == second.base_route_epoch
        && first.next_route_epoch == second.next_route_epoch
        && first.expires_at_ns == second.expires_at_ns
        && first.route_digest == second.route_digest
        && first.transcript_digest == second.transcript_digest
}

impl RouteWireState {
    fn sent(self, message: RouteTransitionMessage) -> Result<Self, RouteTransitionViolation> {
        match (self, message.stage) {
            (Self::Idle, RouteTransitionStage::Prepare) => Ok(Self::PrepareSent(message)),
            (Self::PrepareReceived(prepare), RouteTransitionStage::Prepared)
                if same_route_transition(prepare, message) =>
            {
                Ok(Self::PreparedSent(message))
            }
            (Self::PreparedReceived(prepared), RouteTransitionStage::Commit)
                if same_route_transition(prepared, message) =>
            {
                Ok(Self::Idle)
            }
            _ => Err(RouteTransitionViolation::InvalidState),
        }
    }

    fn received(self, message: RouteTransitionMessage) -> Result<Self, RouteTransitionViolation> {
        match (self, message.stage) {
            (Self::Idle, RouteTransitionStage::Prepare) => Ok(Self::PrepareReceived(message)),
            (Self::PrepareSent(prepare), RouteTransitionStage::Prepared)
                if same_route_transition(prepare, message) =>
            {
                Ok(Self::PreparedReceived(message))
            }
            (Self::PreparedSent(prepared), RouteTransitionStage::Commit)
                if same_route_transition(prepared, message) =>
            {
                Ok(Self::Idle)
            }
            _ => Err(RouteTransitionViolation::InvalidState),
        }
    }
}

/// Enforces the ordered, per-peer candidate advertisement sequence.
#[derive(Debug, Clone, Default)]
pub struct CandidateExchangeTracker {
    exchange_id: Option<u64>,
    generation: u32,
}

/// Couples credentials and candidates into one authenticated, ordered update.
#[derive(Debug, Clone, Default)]
pub struct IceGenerationTracker {
    exchange_id: Option<u64>,
    generation: u32,
    pending: Option<u32>,
    mode: Option<IceSignalingMode>,
    poisoned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IceSignalingMode {
    AdvertisementOnly,
    CredentialGenerations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IceSignalingRoles {
    local: IceCredentialRole,
    remote: IceCredentialRole,
}

impl IceGenerationTracker {
    fn ensure_mode(&self, requested: IceSignalingMode) -> Result<(), IceGenerationViolation> {
        if self.poisoned {
            return Err(IceGenerationViolation::Poisoned);
        }
        if self.mode.is_some_and(|current| current != requested) {
            return Err(IceGenerationViolation::ModeConflict);
        }
        Ok(())
    }

    fn advertisement(&self) -> Result<Self, IceGenerationViolation> {
        self.ensure_mode(IceSignalingMode::AdvertisementOnly)?;
        let mut next = self.clone();
        next.mode = Some(IceSignalingMode::AdvertisementOnly);
        Ok(next)
    }

    fn begin(
        &self,
        credentials: &IceCredentialExchange,
        session_id: u64,
    ) -> Result<Self, IceGenerationViolation> {
        self.ensure_mode(IceSignalingMode::CredentialGenerations)?;
        if credentials.exchange_id != session_id {
            return Err(IceGenerationViolation::ExchangeId {
                expected: session_id,
                actual: credentials.exchange_id,
            });
        }
        let expected = self
            .generation
            .checked_add(1)
            .ok_or(IceGenerationViolation::GenerationExhausted)?;
        if credentials.generation != expected {
            return Err(IceGenerationViolation::Generation {
                expected,
                actual: credentials.generation,
            });
        }
        if self.pending.is_some() {
            return Err(IceGenerationViolation::Pending);
        }
        let mut next = self.clone();
        next.mode = Some(IceSignalingMode::CredentialGenerations);
        next.exchange_id = Some(session_id);
        next.pending = Some(credentials.generation);
        Ok(next)
    }
    fn finish(mut self, candidates: &CandidateExchange) -> Result<Self, IceGenerationViolation> {
        let generation = self
            .pending
            .ok_or(IceGenerationViolation::CandidateBeforeCredentials)?;
        if candidates.exchange_id != self.exchange_id.unwrap_or_default() {
            return Err(IceGenerationViolation::ExchangeId {
                expected: self.exchange_id.unwrap_or_default(),
                actual: candidates.exchange_id,
            });
        }
        if candidates.generation != generation {
            return Err(IceGenerationViolation::Generation {
                expected: generation,
                actual: candidates.generation,
            });
        }
        self.generation = generation;
        self.pending = None;
        Ok(self)
    }

    fn poison(&mut self) {
        self.poisoned = true;
        self.pending = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IceGenerationViolation {
    Malformed(ProtocolError),
    ExchangeId {
        expected: u64,
        actual: u64,
    },
    Generation {
        expected: u32,
        actual: u32,
    },
    GenerationExhausted,
    Pending,
    CandidateBeforeCredentials,
    IceControlRequiresTypedApi,
    IceCapabilityNotNegotiated,
    IceSignalingNotNegotiated,
    ModeConflict,
    Poisoned,
    RoleMismatch {
        expected: IceCredentialRole,
        actual: IceCredentialRole,
    },
}

impl CandidateExchangeTracker {
    /// Validates a candidate exchange and advances the tracker atomically.
    pub fn accept(
        &mut self,
        exchange: &CandidateExchange,
    ) -> Result<(), CandidateExchangeViolation> {
        if let Err(error) = exchange.encode() {
            return Err(CandidateExchangeViolation::Malformed(error));
        }
        self.accept_validated(exchange)
    }

    fn accept_validated(
        &mut self,
        exchange: &CandidateExchange,
    ) -> Result<(), CandidateExchangeViolation> {
        if let Some(exchange_id) = self.exchange_id {
            if exchange.exchange_id != exchange_id {
                return Err(CandidateExchangeViolation::ExchangeId {
                    expected: exchange_id,
                    actual: exchange.exchange_id,
                });
            }
            let expected = self
                .generation
                .checked_add(1)
                .ok_or(CandidateExchangeViolation::GenerationExhausted)?;
            if exchange.generation != expected {
                return Err(CandidateExchangeViolation::Generation {
                    expected,
                    actual: exchange.generation,
                });
            }
        } else if exchange.generation != 1 {
            return Err(CandidateExchangeViolation::Generation {
                expected: 1,
                actual: exchange.generation,
            });
        }
        self.exchange_id = Some(exchange.exchange_id);
        self.generation = exchange.generation;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateExchangeViolation {
    Malformed(ProtocolError),
    ExchangeId { expected: u64, actual: u64 },
    Generation { expected: u32, actual: u32 },
    GenerationExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTransitionViolation {
    Malformed(ProtocolError),
    ControlRequiresTypedApi,
    UnexpectedKind(ControlKind),
    StageKindMismatch {
        stage: RouteTransitionStage,
        kind: ControlKind,
    },
    RouteEpoch {
        expected: u64,
        actual: u64,
    },
    Sequence {
        expected: u64,
        actual: u64,
    },
    InvalidState,
    SessionMismatch,
    PeerIdentityMismatch,
    DuplicateConnection,
    WrongActiveRoute,
    InactiveRoute,
    InvalidBinding,
    BindingMismatch,
}

/// Validated product control message with an owned payload.
#[derive(Clone, PartialEq, Eq)]
pub struct ProductControlMessage {
    pub kind: ControlKind,
    pub payload: Bytes,
}

impl fmt::Debug for ProductControlMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductControlMessage")
            .field("kind", &self.kind)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

struct PrivateControlMessage {
    kind: ControlKind,
    payload: Zeroizing<Vec<u8>>,
}

struct FailClosedIceWrite<'a> {
    tracker: &'a mut IceGenerationTracker,
    connection: QuicConnection,
    armed: bool,
}

impl<'a> FailClosedIceWrite<'a> {
    fn new(tracker: &'a mut IceGenerationTracker, connection: QuicConnection) -> Self {
        Self {
            tracker,
            connection,
            armed: true,
        }
    }

    fn commit(mut self, next: IceGenerationTracker) {
        *self.tracker = next;
        self.armed = false;
    }
}

impl Drop for FailClosedIceWrite<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.tracker.poison();
            self.connection.close_for_protocol_violation();
        }
    }
}

struct FailClosedControlRead {
    connection: QuicConnection,
    armed: bool,
}

impl FailClosedControlRead {
    fn new(connection: QuicConnection) -> Self {
        Self {
            connection,
            armed: true,
        }
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for FailClosedControlRead {
    fn drop(&mut self) {
        if self.armed {
            self.connection.close_for_protocol_violation();
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct IceSendCancellationHook {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductNetworkStats {
    pub rtt: Duration,
    pub sent_packets: u64,
    pub lost_packets: u64,
    pub congestion_events: u64,
    pub congestion_window_bytes: u64,
    pub current_mtu: u16,
}

/// Successful whole-frame submission details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaFrameSendReport {
    /// Number of QUIC DATAGRAMs accepted by Quinn.
    pub fragments_sent: usize,
    /// Largest complete `MediaDatagram` submitted for this frame.
    pub largest_datagram_bytes: usize,
    /// Path limit observed before packetization.
    pub path_max_datagram_bytes: usize,
    /// Sender-local deadline encoded in every fragment.
    pub expires_at_ns: u64,
}

/// Peer behaviors that violate the product session protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductProtocolViolation {
    /// A reliable stream was opened for a lane that is not valid at this point.
    UnexpectedLane {
        expected: StreamKind,
        actual: StreamKind,
    },
    /// A record carried a different session identity or lifecycle epoch.
    StampMismatch {
        expected: SessionStamp,
        actual: SessionStamp,
    },
    /// The initial control record did not carry the canonical active-v2 stamp.
    InvalidHandshakeStamp(SessionStamp),
    /// The initial control payload was not a handshake-completion record.
    UnexpectedHandshakeKind(ControlKind),
    /// The nested control header was not bound to the outer session stamp.
    ControlSessionMismatch {
        expected: u64,
        actual: u64,
    },
    /// The reliable control record did not contain a valid bounded packet.
    MalformedControl(ProtocolError),
    /// The handshake body was not bound to the outer session stamp.
    HandshakeSessionMismatch {
        expected: u64,
        actual: u64,
    },
    /// The handshake body carried another authorization epoch.
    HandshakeAuthorizationMismatch {
        expected: u32,
        actual: u32,
    },
    /// The post-mTLS handshake used a non-canonical legacy nonce value.
    HandshakeNonceMismatch,
    /// A control record was not a candidate advertisement.
    UnexpectedCandidateKind {
        actual: ControlKind,
    },
    UnexpectedCredentialsKind {
        actual: ControlKind,
    },
    /// Candidate advertisement bytes or ordering were invalid.
    CandidateExchange(CandidateExchangeViolation),
    IceGeneration(IceGenerationViolation),
    RouteTransition(RouteTransitionViolation),
    /// A replacement connection reused its session identity or did not advance
    /// every lifecycle epoch beyond the prior authenticated session.
    NonMonotonicSuccessor {
        previous: SessionStamp,
        actual: SessionStamp,
    },
}

/// Product-session construction, framing, and bounded-media failures.
#[derive(Debug)]
pub enum ProductSessionError {
    Quic(QuicTransportError),
    Protocol(ProtocolError),
    Transport(TransportError),
    PeerProtocol(ProductProtocolViolation),
    CandidateExchange(CandidateExchangeViolation),
    IceGeneration(IceGenerationViolation),
    RouteTransition(RouteTransitionViolation),
    /// A route commit must advance exactly once from the currently active epoch.
    RouteEpochTransition {
        expected_current: u64,
        actual_current: u64,
        requested_next: u64,
    },
    /// QUIC DATAGRAM support was not negotiated.
    DatagramsUnsupported,
    /// The path cannot fit an outer QUIC-media header, one inner media header,
    /// and at least one payload byte.
    DatagramBudgetTooSmall {
        path_max_datagram_bytes: usize,
        outer_header_bytes: usize,
        minimum_inner_datagram_bytes: usize,
    },
    /// A nonzero finite media lifetime is required.
    InvalidMediaMaxAge,
    /// Sender-local deadline arithmetic exceeded the wire clock range.
    MediaDeadlineOverflow,
    /// A fragment was not accepted; remaining fragments of the AU were not sent.
    MediaSendAborted {
        /// QUIC/media outcome that stopped the access unit.
        outcome: MediaSendOutcome,
        /// Fragments accepted as [`MediaSendOutcome::Sent`] before abort.
        fragments_sent: usize,
        /// Fragments that belonged to the aborted access unit.
        fragments_total: usize,
    },
    /// The complete post-mTLS product handshake exceeded its local bound.
    HandshakeTimedOut {
        /// Local bound applied to the handshake.
        timeout: Duration,
    },
}

impl fmt::Display for ProductSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic(error) => write!(formatter, "QUIC session operation failed: {error}"),
            Self::Protocol(error) => write!(formatter, "session record is invalid: {error}"),
            Self::Transport(error) => write!(formatter, "media transport failed: {error}"),
            Self::PeerProtocol(error) => {
                write!(
                    formatter,
                    "peer violated the product session protocol: {error:?}"
                )
            }
            Self::CandidateExchange(error) => {
                write!(formatter, "local candidate exchange is invalid: {error:?}")
            }
            Self::IceGeneration(error) => write!(formatter, "local ICE generation is invalid: {error:?}"),
            Self::RouteTransition(error) => {
                write!(formatter, "local route transition is invalid: {error:?}")
            }
            Self::RouteEpochTransition {
                expected_current,
                actual_current,
                requested_next,
            } => write!(
                formatter,
                "route epoch transition expected {expected_current}, found {actual_current}, requested {requested_next}"
            ),
            Self::DatagramsUnsupported => {
                formatter.write_str("QUIC DATAGRAM support was not negotiated")
            }
            Self::DatagramBudgetTooSmall {
                path_max_datagram_bytes,
                outer_header_bytes,
                minimum_inner_datagram_bytes,
            } => write!(
                formatter,
                "QUIC DATAGRAM limit {path_max_datagram_bytes} cannot reserve \
                 {outer_header_bytes} bytes and fit the minimum \
                 {minimum_inner_datagram_bytes}-byte media packet"
            ),
            Self::InvalidMediaMaxAge => {
                formatter.write_str("media max age must be nonzero and fit in u64 nanoseconds")
            }
            Self::MediaDeadlineOverflow => {
                formatter.write_str("sender-local media deadline overflowed")
            }
            Self::MediaSendAborted {
                outcome,
                fragments_sent,
                fragments_total,
            } => write!(
                formatter,
                "media access unit aborted after {fragments_sent}/{fragments_total} fragments: {outcome:?}"
            ),
            Self::HandshakeTimedOut { timeout } => {
                write!(formatter, "product handshake timed out after {timeout:?}")
            }
        }
    }
}

impl Error for ProductSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Quic(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::PeerProtocol(_)
            | Self::CandidateExchange(_)
            | Self::IceGeneration(_)
            | Self::RouteTransition(_)
            | Self::RouteEpochTransition { .. }
            | Self::DatagramsUnsupported
            | Self::DatagramBudgetTooSmall { .. }
            | Self::InvalidMediaMaxAge
            | Self::MediaDeadlineOverflow
            | Self::MediaSendAborted { .. }
            | Self::HandshakeTimedOut { .. } => None,
        }
    }
}

impl From<QuicTransportError> for ProductSessionError {
    fn from(error: QuicTransportError) -> Self {
        Self::Quic(error)
    }
}

impl From<ProtocolError> for ProductSessionError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<TransportError> for ProductSessionError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl ProductSessionError {
    /// True only when an already-authenticated QUIC path timed out or was
    /// reset by its peer. Authentication, protocol, codec, framing, and local
    /// resource failures are deliberately terminal.
    #[must_use]
    pub fn is_retryable_connection_loss(&self) -> bool {
        matches!(
            self,
            Self::Quic(error) if error.is_retryable_connection_loss()
        )
    }
}

impl ProductSession {
    /// Activates the host side of an already mutually-authenticated connection
    /// and publishes the caller-assigned nonzero session ID on the reliable
    /// control lane.
    pub async fn host(
        connection: QuicConnection,
        session_id: NonZeroU64,
    ) -> Result<Self, ProductSessionError> {
        Self::host_with_reassembly(connection, session_id, ReassemblyConfig::default()).await
    }

    /// Activates a Host session with a caller-allocated lifecycle stamp.
    /// Reconnect authorities use this path so successor generations are not
    /// collapsed back to the compatibility `1/1/1/1` epochs.
    pub async fn host_with_stamp(
        connection: QuicConnection,
        stamp: SessionStamp,
    ) -> Result<Self, ProductSessionError> {
        Self::host_with_stamp_reassembly_timeout(
            connection,
            stamp,
            ReassemblyConfig::default(),
            DEFAULT_PRODUCT_HANDSHAKE_TIMEOUT,
        )
        .await
    }

    /// Host constructor with caller-selected bounded reassembly limits.
    pub async fn host_with_reassembly(
        connection: QuicConnection,
        session_id: NonZeroU64,
        reassembly: ReassemblyConfig,
    ) -> Result<Self, ProductSessionError> {
        Self::host_with_reassembly_timeout(
            connection,
            session_id,
            reassembly,
            DEFAULT_PRODUCT_HANDSHAKE_TIMEOUT,
        )
        .await
    }

    /// Waits for and strictly validates the host's first reliable control
    /// record before exposing an active client session.
    pub async fn client(connection: QuicConnection) -> Result<Self, ProductSessionError> {
        Self::client_with_reassembly(connection, ReassemblyConfig::default()).await
    }

    /// Activates a second exact-mTLS route only when its Host publishes the
    /// same lifecycle identity as the already-authorized product session.
    pub async fn client_route_candidate(
        connection: QuicConnection,
        expected: SessionStamp,
    ) -> Result<UnauthorizedCandidateSession, ProductSessionError> {
        validate_active_product_stamp(expected)?;
        let session = Self::client(connection).await?;
        let actual = session.stamp();
        if actual != expected {
            session.connection.close_for_protocol_violation();
            return Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::StampMismatch { expected, actual },
            ));
        }
        Ok(UnauthorizedCandidateSession::new(session))
    }

    /// Host half of a parallel candidate. It publishes the exact existing
    /// lifecycle stamp but remains unable to send application traffic.
    pub async fn host_route_candidate(
        connection: QuicConnection,
        stamp: SessionStamp,
    ) -> Result<UnauthorizedCandidateSession, ProductSessionError> {
        let session = Self::host_with_stamp(connection, stamp).await?;
        Ok(UnauthorizedCandidateSession::new(session))
    }

    /// Activates a replacement Client session only when the Host supplies a
    /// fresh session identity and advances every lifecycle epoch.
    pub async fn client_successor(
        connection: QuicConnection,
        previous: SessionStamp,
    ) -> Result<Self, ProductSessionError> {
        validate_active_product_stamp(previous)?;
        Self::client_with_reassembly_timeout_after(
            connection,
            ReassemblyConfig::default(),
            DEFAULT_PRODUCT_HANDSHAKE_TIMEOUT,
            Some(previous),
        )
        .await
    }

    /// Client constructor with caller-selected bounded reassembly limits.
    pub async fn client_with_reassembly(
        connection: QuicConnection,
        reassembly: ReassemblyConfig,
    ) -> Result<Self, ProductSessionError> {
        Self::client_with_reassembly_timeout(
            connection,
            reassembly,
            DEFAULT_PRODUCT_HANDSHAKE_TIMEOUT,
        )
        .await
    }

    async fn host_with_reassembly_timeout(
        connection: QuicConnection,
        session_id: NonZeroU64,
        reassembly: ReassemblyConfig,
        timeout: Duration,
    ) -> Result<Self, ProductSessionError> {
        Self::host_with_stamp_reassembly_timeout(
            connection,
            active_stamp(session_id),
            reassembly,
            timeout,
        )
        .await
    }

    async fn host_with_stamp_reassembly_timeout(
        connection: QuicConnection,
        stamp: SessionStamp,
        reassembly: ReassemblyConfig,
        timeout: Duration,
    ) -> Result<Self, ProductSessionError> {
        validate_active_product_stamp(stamp)?;
        let timeout_connection = connection.clone();
        let operation = async move {
            let session = Self::new(connection, stamp, reassembly)?;
            let record = encode_handshake_completed(session.stamp)?;
            session.connection.send_control(&record).await?;
            Ok(session)
        };
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result,
            Err(_) => {
                timeout_connection.close(
                    PRODUCT_HANDSHAKE_TIMEOUT_CODE,
                    PRODUCT_HANDSHAKE_TIMEOUT_REASON,
                );
                Err(ProductSessionError::HandshakeTimedOut { timeout })
            }
        }
    }

    async fn client_with_reassembly_timeout(
        connection: QuicConnection,
        reassembly: ReassemblyConfig,
        timeout: Duration,
    ) -> Result<Self, ProductSessionError> {
        Self::client_with_reassembly_timeout_after(connection, reassembly, timeout, None).await
    }

    async fn client_with_reassembly_timeout_after(
        connection: QuicConnection,
        reassembly: ReassemblyConfig,
        timeout: Duration,
        previous: Option<SessionStamp>,
    ) -> Result<Self, ProductSessionError> {
        // Validate local resource policy before waiting on peer-controlled I/O.
        let reassembler = Reassembler::new(reassembly)?;
        let timeout_connection = connection.clone();
        let operation = async move {
            let mut stream = connection
                .accept_inbound_stream()
                .await
                .map_err(|error| inbound_error(&connection, error))?;
            if stream.kind() != StreamKind::Control {
                return fail_peer_protocol(
                    &connection,
                    ProductProtocolViolation::UnexpectedLane {
                        expected: StreamKind::Control,
                        actual: stream.kind(),
                    },
                );
            }
            let record = stream
                .next_record()
                .await
                .map_err(|error| inbound_error(&connection, error))?;
            let stamp = match validate_handshake_completed(&record) {
                Ok(stamp) => stamp,
                Err(error) => {
                    connection.close_for_protocol_violation();
                    return Err(error);
                }
            };
            if let Some(previous) = previous {
                if stamp.session_id == previous.session_id
                    || stamp.generation <= previous.generation
                    || stamp.authorization_epoch <= previous.authorization_epoch
                    || stamp.display_epoch <= previous.display_epoch
                    || stamp.codec_epoch <= previous.codec_epoch
                {
                    return fail_peer_protocol(
                        &connection,
                        ProductProtocolViolation::NonMonotonicSuccessor {
                            previous,
                            actual: stamp,
                        },
                    );
                }
            }
            Ok(Self {
                connection,
                stamp,
                route_epoch: Arc::new(AtomicU64::new(stamp.route_epoch)),
                route_sequence: Arc::new(AtomicU64::new(0)),
                route_authorized: Arc::new(AtomicBool::new(true)),
                reassembler: Arc::new(Mutex::new(reassembler)),
                reassembly_config: reassembly,
                reassembly_route_epoch: Arc::new(AtomicU64::new(stamp.route_epoch)),
                last_delivered_frame_id: Arc::new(Mutex::new(None)),
                clock_origin: Instant::now(),
                inbound_control: Arc::new(Mutex::new(Some(stream))),
                candidate_exchange: Arc::new(Mutex::new(CandidateExchangeTracker::default())),
                ice_generation: Arc::new(Mutex::new(IceGenerationTracker::default())),
                ice_roles: Arc::new(Mutex::new(None)),
                ice_role_assignment: IceSignalingRoles {
                    local: IceCredentialRole::Controlling,
                    remote: IceCredentialRole::Controlled,
                },
                control_send: Arc::new(Mutex::new(())),
                route_transition: Arc::new(Mutex::new(RouteWireState::Idle)),
                #[cfg(test)]
                ice_send_cancellation_hook: None,
                #[cfg(test)]
                route_send_cancellation_hook: None,
            })
        };
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result,
            Err(_) => {
                timeout_connection.close(
                    PRODUCT_HANDSHAKE_TIMEOUT_CODE,
                    PRODUCT_HANDSHAKE_TIMEOUT_REASON,
                );
                Err(ProductSessionError::HandshakeTimedOut { timeout })
            }
        }
    }

    /// Exact active stamp attached to every record in this session.
    #[must_use]
    pub fn stamp(&self) -> SessionStamp {
        stamp_at_route_epoch(self.stamp, self.route_epoch.load(Ordering::Acquire))
    }

    /// Applies a validated typed commit to every cloned product-lane gate.
    fn advance_route_epoch(
        &self,
        expected_current: u64,
        requested_next: u64,
    ) -> Result<SessionStamp, ProductSessionError> {
        let valid_next = expected_current
            .checked_add(1)
            .is_some_and(|next| next == requested_next);
        if !valid_next {
            return Err(ProductSessionError::RouteEpochTransition {
                expected_current,
                actual_current: self.route_epoch.load(Ordering::Acquire),
                requested_next,
            });
        }
        match self.route_epoch.compare_exchange(
            expected_current,
            requested_next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(self.stamp()),
            Err(actual_current) => Err(ProductSessionError::RouteEpochTransition {
                expected_current,
                actual_current,
                requested_next,
            }),
        }
    }

    /// Closes only this product connection. The owning endpoint remains usable
    /// for a strictly newer successor session.
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.connection.close(error_code, reason);
    }

    /// Snapshot of Quinn's current path telemetry for adaptation feedback.
    #[must_use]
    pub fn network_stats(&self) -> ProductNetworkStats {
        let stats = self.connection.path_stats();
        ProductNetworkStats {
            rtt: stats.rtt,
            sent_packets: stats.sent_packets,
            lost_packets: stats.lost_packets,
            congestion_events: stats.congestion_events,
            congestion_window_bytes: stats.cwnd_bytes,
            current_mtu: stats.current_mtu,
        }
    }

    /// UDP peer address Quinn currently reports for this authenticated path.
    /// Candidate advertisements cannot modify it.
    #[must_use]
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
    }

    /// Binds a higher-layer verified route digest to this exact TLS session.
    /// The transcript half is derived internally from the TLS exporter.
    pub fn bind_authenticated_route(
        &self,
        route_digest: [u8; 32],
    ) -> Result<VerifiedRouteBinding, ProductSessionError> {
        route_binding_for_session(self, route_digest)
    }

    /// Enables authenticated ICE signaling only when both the validated offer
    /// and the selected stream configuration negotiated it. The connection
    /// initiator is always controlling and the Host is always controlled, so
    /// callers cannot create a same-role pair.
    pub async fn enable_authenticated_ice_signaling(
        &self,
        offered: VideoCodecCapabilities,
        selected: VideoStreamConfig,
    ) -> Result<(), ProductSessionError> {
        offered.encode()?;
        selected.encode()?;
        if !offered.supports_authenticated_ice_credentials()
            || !selected.supports_authenticated_ice_credentials()
        {
            return Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::IceCapabilityNotNegotiated,
            ));
        }
        let mut roles = self.ice_roles.lock().await;
        if roles.is_none() {
            *roles = Some(self.ice_role_assignment);
        }
        Ok(())
    }

    /// Writes one typed product message on the persistent reliable control lane.
    pub async fn send_control(
        &self,
        kind: ControlKind,
        payload: &[u8],
    ) -> Result<(), ProductSessionError> {
        self.ensure_route_authorized()?;
        if matches!(
            kind,
            ControlKind::IceCredentials | ControlKind::IceCandidate
        ) {
            return Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::IceControlRequiresTypedApi,
            ));
        }
        if is_route_control(kind) {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::ControlRequiresTypedApi,
            ));
        }
        let _send_guard = self.control_send.lock().await;
        self.send_control_unlocked(kind, payload).await
    }

    /// Sends one authenticated prepare/prepared/commit record. Only a matching
    /// commit advances the shared epoch used by every product lane.
    async fn send_route_transition(
        &self,
        message: RouteTransitionMessage,
    ) -> Result<(), ProductSessionError> {
        message
            .validate()
            .map_err(RouteTransitionViolation::Malformed)
            .map_err(ProductSessionError::RouteTransition)?;
        let current = self.route_epoch.load(Ordering::Acquire);
        if message.base_route_epoch != current {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::RouteEpoch {
                    expected: current,
                    actual: message.base_route_epoch,
                },
            ));
        }
        if message.stage == RouteTransitionStage::Prepare {
            let last = self.route_sequence.load(Ordering::Acquire);
            let expected = last.checked_add(1).unwrap_or(0);
            if message.sequence != expected {
                return Err(ProductSessionError::RouteTransition(
                    RouteTransitionViolation::Sequence {
                        expected,
                        actual: message.sequence,
                    },
                ));
            }
        }
        let mut state = self.route_transition.lock().await;
        let next = state
            .sent(message)
            .map_err(ProductSessionError::RouteTransition)?;
        let payload = message
            .encode()
            .map_err(RouteTransitionViolation::Malformed)
            .map_err(ProductSessionError::RouteTransition)?;
        let _send_guard = self.control_send.lock().await;
        self.send_control_unlocked(message.stage.control_kind(), &payload)
            .await?;
        #[cfg(test)]
        if let Some(hook) = &self.route_send_cancellation_hook {
            hook.reached.notify_one();
            hook.release.notified().await;
        }
        if message.stage == RouteTransitionStage::Commit {
            if let Err(error) =
                self.advance_route_epoch(message.base_route_epoch, message.next_route_epoch)
            {
                self.connection.close_for_protocol_violation();
                return Err(error);
            }
            self.route_sequence
                .store(message.sequence, Ordering::Release);
        }
        *state = next;
        Ok(())
    }

    async fn send_route_activation(
        &self,
        message: RouteTransitionMessage,
    ) -> Result<(), ProductSessionError> {
        if !matches!(
            message.stage,
            RouteTransitionStage::Activated | RouteTransitionStage::Confirmed
        ) {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidState,
            ));
        }
        let payload = message
            .encode()
            .map_err(RouteTransitionViolation::Malformed)
            .map_err(ProductSessionError::RouteTransition)?;
        let _send_guard = self.control_send.lock().await;
        self.send_control_unlocked(message.stage.control_kind(), &payload)
            .await
    }

    /// Sends one credentials/candidates generation as an indivisible ordered pair.
    pub async fn send_ice_generation(
        &self,
        credentials: IceCredentialExchange,
        candidates: CandidateExchange,
    ) -> Result<(), ProductSessionError> {
        let roles = (*self.ice_roles.lock().await).ok_or(ProductSessionError::IceGeneration(
            IceGenerationViolation::IceSignalingNotNegotiated,
        ))?;
        if credentials.role != roles.local {
            return Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::RoleMismatch {
                    expected: roles.local,
                    actual: credentials.role,
                },
            ));
        }
        let payload = credentials
            .encode()
            .map_err(IceGenerationViolation::Malformed)
            .map_err(ProductSessionError::IceGeneration)?;
        let candidate_payload = candidates.encode()?;
        let mut tracker = self.ice_generation.lock().await;
        let next = tracker
            .begin(&credentials, self.stamp.session_id)
            .map_err(ProductSessionError::IceGeneration)?;
        let next = next
            .finish(&candidates)
            .map_err(ProductSessionError::IceGeneration)?;
        let _send_guard = self.control_send.lock().await;
        let transaction = FailClosedIceWrite::new(&mut tracker, self.connection.clone());
        self.send_control_unlocked(ControlKind::IceCredentials, &payload)
            .await?;
        #[cfg(test)]
        self.pause_after_ice_write_for_cancellation_test().await;
        self.send_control_unlocked(ControlKind::IceCandidate, &candidate_payload)
            .await?;
        transaction.commit(next);
        Ok(())
    }

    async fn send_control_unlocked(
        &self,
        kind: ControlKind,
        payload: &[u8],
    ) -> Result<(), ProductSessionError> {
        let stamp = self.stamp();
        let control = Zeroizing::new(ControlPacket::encode(
            ControlHeader {
                kind,
                flags: 0,
                session_id: stamp.session_id,
                payload_len: u32::try_from(payload.len())
                    .map_err(|_| ProtocolError::ControlLength(u32::MAX))?,
            },
            payload,
        )?);
        let record = Zeroizing::new(StreamRecord::encode(StreamKind::Control, stamp, &control)?);
        self.connection.send_control(&record).await?;
        Ok(())
    }

    #[cfg(test)]
    async fn pause_after_ice_write_for_cancellation_test(&self) {
        if let Some(hook) = &self.ice_send_cancellation_hook {
            hook.reached.notify_one();
            hook.release.notified().await;
        }
    }

    /// Sends one validated, sequential ICE candidate advertisement.
    pub async fn send_candidate_exchange(
        &self,
        exchange: CandidateExchange,
    ) -> Result<(), ProductSessionError> {
        let payload = exchange.encode()?;
        if exchange.exchange_id != self.stamp.session_id {
            return Err(ProductSessionError::CandidateExchange(
                CandidateExchangeViolation::ExchangeId {
                    expected: self.stamp.session_id,
                    actual: exchange.exchange_id,
                },
            ));
        }
        let mut mode_tracker = self.ice_generation.lock().await;
        let next_mode = mode_tracker
            .advertisement()
            .map_err(ProductSessionError::IceGeneration)?;
        let mut candidate_tracker = self.candidate_exchange.lock().await;
        let mut next_candidate = candidate_tracker.clone();
        next_candidate
            .accept_validated(&exchange)
            .map_err(ProductSessionError::CandidateExchange)?;
        let _send_guard = self.control_send.lock().await;
        let transaction = FailClosedIceWrite::new(&mut mode_tracker, self.connection.clone());
        self.send_control_unlocked(ControlKind::IceCandidate, &payload)
            .await?;
        #[cfg(test)]
        self.pause_after_ice_write_for_cancellation_test().await;
        *candidate_tracker = next_candidate;
        transaction.commit(next_mode);
        Ok(())
    }

    /// Takes the peer's one persistent reliable control lane. On the client,
    /// this continues the lane whose first record completed the product
    /// handshake rather than opening or accepting a second lane.
    pub async fn accept_control_receiver(&self) -> Result<ControlReceiver, ProductSessionError> {
        let retained = self.inbound_control.lock().await.take();
        let stream = match retained {
            Some(stream) => stream,
            None => self
                .connection
                .accept_inbound_stream()
                .await
                .map_err(|error| inbound_error(&self.connection, error))?,
        };
        if stream.kind() != StreamKind::Control {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::UnexpectedLane {
                    expected: StreamKind::Control,
                    actual: stream.kind(),
                },
            );
        }
        Ok(ControlReceiver {
            connection: self.connection.clone(),
            stream,
            expected_stamp: self.stamp,
            route_epoch: Arc::clone(&self.route_epoch),
            route_sequence: Arc::clone(&self.route_sequence),
            route_authorized: Arc::clone(&self.route_authorized),
            candidate_exchange: CandidateExchangeTracker::default(),
            ice_generation: IceGenerationTracker::default(),
            ice_roles: Arc::clone(&self.ice_roles),
            route_transition: Arc::clone(&self.route_transition),
            #[cfg(test)]
            route_receive_cancellation_hook: None,
        })
    }

    /// Encodes and writes one bounded payload on the independent reliable input
    /// lane.
    pub async fn send_input(&self, payload: &[u8]) -> Result<(), ProductSessionError> {
        self.ensure_route_authorized()?;
        let record = StreamRecord::encode(StreamKind::Input, self.stamp(), payload)?;
        self.connection.send_input(&record).await?;
        Ok(())
    }

    /// Encodes and writes one input payload with a caller-selected local
    /// bound. The QUIC layer closes fail-closed if cancellation might have
    /// interrupted a record write.
    pub async fn send_input_with_timeout(
        &self,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<(), ProductSessionError> {
        self.ensure_route_authorized()?;
        let record = StreamRecord::encode(StreamKind::Input, self.stamp(), payload)?;
        self.connection
            .send_input_with_timeout(&record, timeout)
            .await?;
        Ok(())
    }

    /// Accepts the peer's one persistent reliable input lane.
    pub async fn accept_input_receiver(&self) -> Result<InputReceiver, ProductSessionError> {
        let stream = self
            .connection
            .accept_inbound_stream()
            .await
            .map_err(|error| inbound_error(&self.connection, error))?;
        if stream.kind() != StreamKind::Input {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::UnexpectedLane {
                    expected: StreamKind::Input,
                    actual: stream.kind(),
                },
            );
        }
        Ok(InputReceiver {
            connection: self.connection.clone(),
            stream,
            expected_stamp: self.stamp,
            route_epoch: Arc::clone(&self.route_epoch),
            route_authorized: Arc::clone(&self.route_authorized),
        })
    }

    /// Fragments one bounded frame using the current QUIC DATAGRAM limit,
    /// wraps every inner packet with the exact session stamp, and submits every
    /// fragment with one sender-local deadline.
    pub fn send_media_frame(
        &self,
        spec: FragmentSpec,
        frame: &[u8],
        max_age: Duration,
    ) -> Result<MediaFrameSendReport, ProductSessionError> {
        let now_ns = self.local_now_ns();
        self.send_media_frame_at(spec, frame, max_age, now_ns, |_| now_ns)
    }

    fn send_media_frame_at(
        &self,
        spec: FragmentSpec,
        frame: &[u8],
        max_age: Duration,
        now_ns: u64,
        mut send_now_ns: impl FnMut(usize) -> u64,
    ) -> Result<MediaFrameSendReport, ProductSessionError> {
        self.ensure_route_authorized()?;
        let max_age_ns = u64::try_from(max_age.as_nanos())
            .ok()
            .filter(|age| *age != 0)
            .ok_or(ProductSessionError::InvalidMediaMaxAge)?;
        let path_max_datagram_bytes = self
            .connection
            .max_datagram_size()
            .ok_or(ProductSessionError::DatagramsUnsupported)?;
        let inner_datagram_bytes = media_packet_budget(path_max_datagram_bytes)?;
        let fragments = frame_fragments_with_packet_budget(spec, frame, inner_datagram_bytes)?;

        // Preflight every final length before sending the first fragment. This
        // prevents a static MTU mistake from producing a partial frame.
        let largest_datagram_bytes = fragments
            .clone()
            .map(|fragment| {
                QUIC_MEDIA_HEADER_LEN
                    .saturating_add(MEDIA_HEADER_LEN)
                    .saturating_add(fragment.payload.len())
            })
            .max()
            .unwrap_or(0);
        if largest_datagram_bytes > path_max_datagram_bytes {
            return Err(ProductSessionError::DatagramBudgetTooSmall {
                path_max_datagram_bytes,
                outer_header_bytes: QUIC_MEDIA_HEADER_LEN,
                minimum_inner_datagram_bytes: largest_datagram_bytes
                    .saturating_sub(QUIC_MEDIA_HEADER_LEN),
            });
        }

        let expires_at_ns = now_ns
            .checked_add(max_age_ns)
            .ok_or(ProductSessionError::MediaDeadlineOverflow)?;
        let fragments_total = fragments.len();
        let mut fragments_sent = 0;
        for (index, fragment) in fragments.enumerate() {
            let datagram = MediaDatagram::encode(
                self.stamp(),
                expires_at_ns,
                fragment.header,
                fragment.payload,
            )?;
            debug_assert!(datagram.len() <= path_max_datagram_bytes);
            match self.connection.send_media(
                Bytes::from(datagram),
                send_now_ns(index),
                expires_at_ns,
            )? {
                MediaSendOutcome::Sent => fragments_sent += 1,
                outcome => {
                    return Err(ProductSessionError::MediaSendAborted {
                        outcome,
                        fragments_sent,
                        fragments_total,
                    });
                }
            }
        }

        Ok(MediaFrameSendReport {
            fragments_sent,
            largest_datagram_bytes,
            path_max_datagram_bytes,
            expires_at_ns,
        })
    }

    /// Receives media until one frame completes. The peer's absolute expiry is
    /// intentionally not compared with this machine's clock; only local
    /// arrival times drive bounded reassembly age.
    pub async fn receive_media_frame(&self) -> Result<ReassembledFrame, ProductSessionError> {
        loop {
            self.ensure_route_authorized()?;
            {
                let mut reassembler = self.reassembler.lock().await;
                reassembler.expire_due(self.local_now_ns());
            }
            let bytes = self.connection.receive_media().await?;
            self.ensure_route_authorized()?;
            let datagram = match MediaDatagram::decode(&bytes) {
                Ok(datagram) => datagram,
                Err(error) => {
                    self.connection.close_for_protocol_violation();
                    return Err(ProductSessionError::Protocol(error));
                }
            };
            let expected_stamp = self.stamp();
            if datagram.stamp != expected_stamp {
                return fail_peer_protocol(
                    &self.connection,
                    ProductProtocolViolation::StampMismatch {
                        expected: expected_stamp,
                        actual: datagram.stamp,
                    },
                );
            }

            // Do not use `datagram.expires_at_ns` here: it belongs to the
            // sender's monotonic clock domain. Reassembler age is local-only.
            let now_ns = self.local_now_ns();
            let outcome = {
                let mut reassembler = self.reassembler.lock().await;
                if self.reassembly_route_epoch.load(Ordering::Acquire) != expected_stamp.route_epoch
                {
                    *reassembler = Reassembler::new(self.reassembly_config)?;
                    self.reassembly_route_epoch
                        .store(expected_stamp.route_epoch, Ordering::Release);
                }
                reassembler.expire_due(now_ns);
                reassembler.ingest(&bytes[QUIC_MEDIA_HEADER_LEN..], now_ns)
            };
            if self.stamp() != expected_stamp {
                continue;
            }
            match outcome {
                Ok(IngestOutcome::Complete(frame)) => {
                    let frame_id = frame.header.frame_id;
                    let is_stale = {
                        let mut last_delivered = self.last_delivered_frame_id.lock().await;
                        match *last_delivered {
                            Some(previous) if frame_id <= previous => true,
                            _ => {
                                *last_delivered = Some(frame_id);
                                false
                            }
                        }
                    };
                    // QUIC DATAGRAMs are intentionally unordered. A valid old
                    // frame can finish after a newer frame has already been
                    // delivered, and replayed fragments can also complete an
                    // already-seen frame. Both are stale media, not a reason to
                    // tear down the authenticated control/input session.
                    if is_stale {
                        continue;
                    }
                    return Ok(frame);
                }
                Ok(IngestOutcome::Pending { .. } | IngestOutcome::Duplicate { .. }) => {}
                Err(error) if is_skippable_ingest_error(&error) => {}
                Err(error) => {
                    self.connection.close_for_protocol_violation();
                    return Err(ProductSessionError::Transport(error));
                }
            }
        }
    }

    fn new(
        connection: QuicConnection,
        stamp: SessionStamp,
        reassembly: ReassemblyConfig,
    ) -> Result<Self, ProductSessionError> {
        validate_active_product_stamp(stamp)?;
        Ok(Self {
            connection,
            stamp,
            route_epoch: Arc::new(AtomicU64::new(stamp.route_epoch)),
            route_sequence: Arc::new(AtomicU64::new(0)),
            route_authorized: Arc::new(AtomicBool::new(true)),
            reassembler: Arc::new(Mutex::new(Reassembler::new(reassembly)?)),
            reassembly_config: reassembly,
            reassembly_route_epoch: Arc::new(AtomicU64::new(stamp.route_epoch)),
            last_delivered_frame_id: Arc::new(Mutex::new(None)),
            clock_origin: Instant::now(),
            inbound_control: Arc::new(Mutex::new(None)),
            candidate_exchange: Arc::new(Mutex::new(CandidateExchangeTracker::default())),
            ice_generation: Arc::new(Mutex::new(IceGenerationTracker::default())),
            ice_roles: Arc::new(Mutex::new(None)),
            ice_role_assignment: IceSignalingRoles {
                local: IceCredentialRole::Controlled,
                remote: IceCredentialRole::Controlling,
            },
            control_send: Arc::new(Mutex::new(())),
            route_transition: Arc::new(Mutex::new(RouteWireState::Idle)),
            #[cfg(test)]
            ice_send_cancellation_hook: None,
            #[cfg(test)]
            route_send_cancellation_hook: None,
        })
    }

    fn local_now_ns(&self) -> u64 {
        u64::try_from(self.clock_origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn ensure_route_authorized(&self) -> Result<(), ProductSessionError> {
        if self.route_authorized.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute,
            ))
        }
    }

    fn set_route_authorized(&self, authorized: bool) {
        self.route_authorized.store(authorized, Ordering::Release);
    }
}

impl ProductRouteSet {
    pub fn new(
        active: ProductSession,
        active_binding: VerifiedRouteBinding,
        rollback_candidate: UnauthorizedCandidateSession,
        candidate_binding: VerifiedRouteBinding,
    ) -> Result<Self, ProductSessionError> {
        if active_binding.route_digest == [0; 32]
            || active_binding.transcript_digest == [0; 32]
            || candidate_binding.route_digest == [0; 32]
            || candidate_binding.transcript_digest == [0; 32]
            || active_binding.route_digest == candidate_binding.route_digest
            || active_binding.transcript_digest == candidate_binding.transcript_digest
            || active_binding.connection_id != active.connection.stable_id()
            || candidate_binding.connection_id != rollback_candidate.session.connection.stable_id()
        {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidBinding,
            ));
        }
        let rollback_candidate = rollback_candidate.session;
        if active.connection.stable_id() == rollback_candidate.connection.stable_id() {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::DuplicateConnection,
            ));
        }
        if active.stamp() != rollback_candidate.stamp() {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::SessionMismatch,
            ));
        }
        if active.connection.peer_certificate_chain()?
            != rollback_candidate.connection.peer_certificate_chain()?
        {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::PeerIdentityMismatch,
            ));
        }
        if active_binding.peer_fingerprint != candidate_binding.peer_fingerprint {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidBinding,
            ));
        }
        active.set_route_authorized(true);
        rollback_candidate.set_route_authorized(false);
        Ok(Self {
            routes: [active, rollback_candidate],
            bindings: [active_binding, candidate_binding],
            active: 0,
            transition_timer: Arc::new(AtomicU64::new(0)),
            activation: RouteActivationState::Idle,
            transition_route: None,
        })
    }

    #[must_use]
    pub const fn active_index(&self) -> usize {
        self.active
    }

    #[must_use]
    pub fn stamp(&self) -> SessionStamp {
        self.routes[self.active].stamp()
    }

    #[must_use]
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.routes[self.active].remote_address()
    }

    pub async fn accept_control_receiver(
        &self,
    ) -> Result<ActiveRouteControlReceiver, ProductSessionError> {
        Ok(ActiveRouteControlReceiver {
            route_index: self.active,
            receiver: self.routes[self.active].accept_control_receiver().await?,
        })
    }

    pub async fn accept_standby_control_receiver(
        &self,
    ) -> Result<ActiveRouteControlReceiver, ProductSessionError> {
        let standby = 1 - self.active;
        Ok(ActiveRouteControlReceiver {
            route_index: standby,
            receiver: self.routes[standby].accept_control_receiver().await?,
        })
    }

    pub async fn send_route_transition(
        &mut self,
        message: RouteTransitionMessage,
    ) -> Result<(), ProductSessionError> {
        self.validate_transition_binding(message)?;
        let control_route = match message.stage {
            RouteTransitionStage::Prepare if self.transition_route.is_none() => self.active,
            RouteTransitionStage::Prepared | RouteTransitionStage::Commit => self
                .transition_route
                .ok_or(ProductSessionError::RouteTransition(
                    RouteTransitionViolation::InvalidState,
                ))?,
            _ => {
                return Err(ProductSessionError::RouteTransition(
                    RouteTransitionViolation::InvalidState,
                ))
            }
        };
        let mut operation = FailClosedRouteSetOperation::new(&self.routes);
        let current = self.active;
        self.routes[control_route]
            .send_route_transition(message)
            .await?;
        if message.stage == RouteTransitionStage::Commit {
            self.synchronize_route_epochs(message)?;
            self.activation = RouteActivationState::AwaitingActivated {
                previous: current,
                commit: message,
            };
            self.transition_route = None;
        } else if message.stage == RouteTransitionStage::Prepare {
            self.transition_route = Some(control_route);
            self.arm_transition_timeout();
        }
        operation.commit();
        Ok(())
    }

    /// Starts rollback over the retained path when the active candidate can no
    /// longer carry the prepare exchange. Application authority remains
    /// revoked/current until the same candidate activation barrier completes.
    pub async fn send_rollback_via_retained(
        &mut self,
        message: RouteTransitionMessage,
    ) -> Result<(), ProductSessionError> {
        if message.stage != RouteTransitionStage::Prepare
            || self.transition_route.is_some()
            || self.activation != RouteActivationState::Idle
            || self.routes[self.active]
                .route_authorized
                .load(Ordering::Acquire)
        {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidState,
            ));
        }
        self.validate_transition_binding(message)?;
        let retained = 1 - self.active;
        let mut operation = FailClosedRouteSetOperation::new(&self.routes);
        self.routes[retained].send_route_transition(message).await?;
        self.transition_route = Some(retained);
        self.arm_transition_timeout();
        operation.commit();
        Ok(())
    }

    pub async fn next_route_transition(
        &mut self,
        receiver: &mut ActiveRouteControlReceiver,
    ) -> Result<RouteTransitionMessage, ProductSessionError> {
        if self
            .transition_route
            .is_some_and(|route| receiver.route_index != route)
        {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::WrongActiveRoute,
            ));
        }
        let mut operation = FailClosedRouteSetOperation::new(&self.routes);
        let current = self.active;
        let target_binding = self.bindings[1 - self.active];
        let message = receiver
            .receiver
            .next_route_transition_bound(target_binding, receiver.route_index != self.active)
            .await?;
        if message.stage == RouteTransitionStage::Prepare {
            if self.transition_route.is_some() {
                return Err(ProductSessionError::RouteTransition(
                    RouteTransitionViolation::InvalidState,
                ));
            }
            self.transition_route = Some(receiver.route_index);
            if receiver.route_index != self.active {
                self.routes[self.active].set_route_authorized(false);
            }
        } else if self.transition_route != Some(receiver.route_index) {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::WrongActiveRoute,
            ));
        }
        if message.stage == RouteTransitionStage::Commit {
            self.synchronize_route_epochs(message)?;
            let next = 1 - current;
            self.routes[next]
                .send_route_activation(RouteTransitionMessage {
                    stage: RouteTransitionStage::Activated,
                    ..message
                })
                .await?;
            self.activate_prepared_route(current);
            self.activation = RouteActivationState::AwaitingConfirmed { commit: message };
            self.transition_route = None;
        } else if message.stage == RouteTransitionStage::Prepare {
            self.arm_transition_timeout();
        }
        operation.commit();
        Ok(message)
    }

    pub async fn next_route_activation(
        &mut self,
        receiver: &mut ActiveRouteControlReceiver,
    ) -> Result<RouteTransitionMessage, ProductSessionError> {
        let RouteActivationState::AwaitingActivated { previous, commit } = self.activation else {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidState,
            ));
        };
        let next = 1 - previous;
        if self.active != previous || receiver.route_index != next {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::WrongActiveRoute,
            ));
        }
        let mut operation = FailClosedRouteSetOperation::new(&self.routes);
        let activated = receiver
            .receiver
            .next_route_activation(self.bindings[next], commit, RouteTransitionStage::Activated)
            .await?;
        self.routes[next]
            .send_route_activation(RouteTransitionMessage {
                stage: RouteTransitionStage::Confirmed,
                ..commit
            })
            .await?;
        self.activate_prepared_route(previous);
        self.activation = RouteActivationState::Idle;
        self.disarm_transition_timeout();
        operation.commit();
        Ok(activated)
    }

    pub async fn next_route_confirmation(
        &mut self,
        receiver: &mut ActiveRouteControlReceiver,
    ) -> Result<RouteTransitionMessage, ProductSessionError> {
        let RouteActivationState::AwaitingConfirmed { commit } = self.activation else {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidState,
            ));
        };
        if receiver.route_index != self.active {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::WrongActiveRoute,
            ));
        }
        let mut operation = FailClosedRouteSetOperation::new(&self.routes);
        let confirmed = receiver
            .receiver
            .next_route_activation(
                self.bindings[self.active],
                commit,
                RouteTransitionStage::Confirmed,
            )
            .await?;
        self.activation = RouteActivationState::Idle;
        self.disarm_transition_timeout();
        operation.commit();
        Ok(confirmed)
    }

    fn synchronize_route_epochs(
        &self,
        message: RouteTransitionMessage,
    ) -> Result<(), ProductSessionError> {
        for route in &self.routes {
            let epoch = route.stamp().route_epoch;
            let synchronized = if epoch == message.base_route_epoch {
                route
                    .advance_route_epoch(message.base_route_epoch, message.next_route_epoch)
                    .map(|_| ())
            } else if epoch == message.next_route_epoch {
                Ok(())
            } else {
                Err(ProductSessionError::RouteEpochTransition {
                    expected_current: message.base_route_epoch,
                    actual_current: epoch,
                    requested_next: message.next_route_epoch,
                })
            };
            if let Err(error) = synchronized {
                for failed in &self.routes {
                    failed.close(0x103, b"route-set epoch synchronization failed");
                }
                return Err(error);
            }
            route
                .route_sequence
                .store(message.sequence, Ordering::Release);
        }
        Ok(())
    }

    fn activate_prepared_route(&mut self, previous: usize) {
        let next = 1 - previous;
        self.routes[previous].set_route_authorized(false);
        self.routes[next].set_route_authorized(true);
        self.active = next;
    }

    fn validate_transition_binding(
        &self,
        message: RouteTransitionMessage,
    ) -> Result<(), ProductSessionError> {
        let target = self.bindings[1 - self.active];
        if message.route_digest != target.route_digest
            || message.transcript_digest != target.transcript_digest
        {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::BindingMismatch,
            ));
        }
        Ok(())
    }

    fn arm_transition_timeout(&self) {
        let ticket = self
            .transition_timer
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let timer = Arc::clone(&self.transition_timer);
        let routes = [self.routes[0].clone(), self.routes[1].clone()];
        tokio::spawn(async move {
            tokio::time::sleep(ROUTE_TRANSITION_TIMEOUT).await;
            if timer.load(Ordering::Acquire) == ticket {
                for route in &routes {
                    route.set_route_authorized(false);
                    route.close(0x103, b"route transition expired");
                }
            }
        });
    }

    fn disarm_transition_timeout(&self) {
        self.transition_timer.fetch_add(1, Ordering::AcqRel);
    }

    pub async fn send_control(
        &self,
        kind: ControlKind,
        payload: &[u8],
    ) -> Result<(), ProductSessionError> {
        self.routes[self.active].send_control(kind, payload).await
    }

    pub async fn next_control(
        &self,
        receiver: &mut ActiveRouteControlReceiver,
    ) -> Result<ProductControlMessage, ProductSessionError> {
        if receiver.route_index != self.active {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::WrongActiveRoute,
            ));
        }
        receiver.receiver.next_control().await
    }

    pub async fn send_input(&self, payload: &[u8]) -> Result<(), ProductSessionError> {
        self.routes[self.active].send_input(payload).await
    }

    pub async fn accept_input_receiver(&self) -> Result<InputReceiver, ProductSessionError> {
        self.routes[self.active].accept_input_receiver().await
    }

    pub fn send_media_frame(
        &self,
        spec: FragmentSpec,
        frame: &[u8],
        max_age: Duration,
    ) -> Result<MediaFrameSendReport, ProductSessionError> {
        self.routes[self.active].send_media_frame(spec, frame, max_age)
    }

    pub async fn receive_media_frame(&self) -> Result<ReassembledFrame, ProductSessionError> {
        self.routes[self.active].receive_media_frame().await
    }

    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.disarm_transition_timeout();
        for route in &self.routes {
            route.set_route_authorized(false);
            route.close(error_code, reason);
        }
    }

    /// Revokes and closes only the active transport so rollback control can
    /// proceed over the retained exact-mTLS connection.
    pub fn fail_active_route(&self, error_code: u32, reason: &[u8]) {
        self.routes[self.active].set_route_authorized(false);
        self.routes[self.active].close(error_code, reason);
    }
}

impl InputReceiver {
    /// Reads the next input payload and rejects any stamp drift before handing
    /// bytes to the application-specific input decoder.
    pub async fn next_input(&mut self) -> Result<Bytes, ProductSessionError> {
        if !self.route_authorized.load(Ordering::Acquire) {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute,
            ));
        }
        let record = self
            .stream
            .next_record()
            .await
            .map_err(|error| inbound_error(&self.connection, error))?;
        if !self.route_authorized.load(Ordering::Acquire) {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute,
            ));
        }
        let expected_stamp = stamp_at_route_epoch(
            self.expected_stamp,
            self.route_epoch.load(Ordering::Acquire),
        );
        if record.stamp != expected_stamp {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::StampMismatch {
                    expected: expected_stamp,
                    actual: record.stamp,
                },
            );
        }
        Ok(record.payload)
    }
}

impl ControlReceiver {
    /// Receives one credentials/candidates pair, requiring the complementary role.
    pub async fn next_ice_generation(
        &mut self,
    ) -> Result<(IceCredentialExchange, CandidateExchange), ProductSessionError> {
        let roles = (*self.ice_roles.lock().await).ok_or(ProductSessionError::IceGeneration(
            IceGenerationViolation::IceSignalingNotNegotiated,
        ))?;
        self.ice_generation
            .ensure_mode(IceSignalingMode::CredentialGenerations)
            .map_err(ProductSessionError::IceGeneration)?;
        let mut operation = FailClosedControlRead::new(self.connection.clone());
        let credentials_message = self.next_control_private().await?;
        if credentials_message.kind != ControlKind::IceCredentials {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::UnexpectedCredentialsKind {
                    actual: credentials_message.kind,
                },
            );
        }
        let credentials =
            IceCredentialExchange::decode(&credentials_message.payload).map_err(|error| {
                self.connection.close_for_protocol_violation();
                ProductSessionError::PeerProtocol(ProductProtocolViolation::IceGeneration(
                    IceGenerationViolation::Malformed(error),
                ))
            })?;
        if credentials.exchange_id != self.expected_stamp.session_id {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::IceGeneration(IceGenerationViolation::ExchangeId {
                    expected: self.expected_stamp.session_id,
                    actual: credentials.exchange_id,
                }),
            );
        }
        if credentials.role != roles.remote {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::IceGeneration(IceGenerationViolation::RoleMismatch {
                    expected: roles.remote,
                    actual: credentials.role,
                }),
            );
        }
        let next = self
            .ice_generation
            .begin(&credentials, self.expected_stamp.session_id)
            .map_err(|v| {
                self.connection.close_for_protocol_violation();
                ProductSessionError::PeerProtocol(ProductProtocolViolation::IceGeneration(v))
            })?;
        // Persist the half-generation before the second network await. If the
        // future is externally cancelled, the mode cannot fall back to legacy
        // advertisement and the armed operation guard closes the connection.
        self.ice_generation = next;
        let candidate_message = self.next_control_private().await?;
        if candidate_message.kind != ControlKind::IceCandidate {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::UnexpectedCandidateKind {
                    actual: candidate_message.kind,
                },
            );
        }
        let candidates =
            CandidateExchange::decode(&candidate_message.payload).map_err(|error| {
                self.connection.close_for_protocol_violation();
                ProductSessionError::PeerProtocol(ProductProtocolViolation::CandidateExchange(
                    CandidateExchangeViolation::Malformed(error),
                ))
            })?;
        let committed = self
            .ice_generation
            .clone()
            .finish(&candidates)
            .map_err(|v| {
                self.connection.close_for_protocol_violation();
                ProductSessionError::PeerProtocol(ProductProtocolViolation::IceGeneration(v))
            })?;
        self.ice_generation = committed;
        operation.commit();
        Ok((credentials, candidates))
    }

    /// Reads one non-ICE control message. ICE credentials and candidates must
    /// use their typed APIs so capability, role, generation, and mode state
    /// cannot be bypassed.
    pub async fn next_control(&mut self) -> Result<ProductControlMessage, ProductSessionError> {
        let mut operation = FailClosedControlRead::new(self.connection.clone());
        let message = self.next_control_private().await?;
        if matches!(
            message.kind,
            ControlKind::IceCredentials | ControlKind::IceCandidate
        ) {
            return Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::IceControlRequiresTypedApi,
            ));
        }
        if is_route_control(message.kind) {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::ControlRequiresTypedApi,
            ));
        }
        let result = ProductControlMessage {
            kind: message.kind,
            payload: Bytes::copy_from_slice(&message.payload),
        };
        operation.commit();
        Ok(result)
    }

    /// Receives one authenticated route transition stage and enforces the
    /// prepare -> prepared -> commit state machine across both directions.
    #[cfg(test)]
    async fn next_route_transition(
        &mut self,
    ) -> Result<RouteTransitionMessage, ProductSessionError> {
        self.next_route_transition_inner(None, false).await
    }

    async fn next_route_transition_bound(
        &mut self,
        binding: VerifiedRouteBinding,
        allow_inactive: bool,
    ) -> Result<RouteTransitionMessage, ProductSessionError> {
        self.next_route_transition_inner(Some(binding), allow_inactive)
            .await
    }

    async fn next_route_activation(
        &mut self,
        binding: VerifiedRouteBinding,
        commit: RouteTransitionMessage,
        expected_stage: RouteTransitionStage,
    ) -> Result<RouteTransitionMessage, ProductSessionError> {
        let mut operation = FailClosedControlRead::new(self.connection.clone());
        let record = self
            .stream
            .next_record()
            .await
            .map_err(|error| inbound_error(&self.connection, error))?;
        let expected_stamp = stamp_at_route_epoch(
            self.expected_stamp,
            self.route_epoch.load(Ordering::Acquire),
        );
        if record.stamp != expected_stamp {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::StampMismatch {
                    expected: expected_stamp,
                    actual: record.stamp,
                },
            );
        }
        let packet = ControlPacket::decode(&record.payload).map_err(|error| {
            self.connection.close_for_protocol_violation();
            ProductSessionError::PeerProtocol(ProductProtocolViolation::MalformedControl(error))
        })?;
        let message = RouteTransitionMessage::decode(packet.payload).map_err(|error| {
            self.connection.close_for_protocol_violation();
            ProductSessionError::PeerProtocol(ProductProtocolViolation::RouteTransition(
                RouteTransitionViolation::Malformed(error),
            ))
        })?;
        if packet.header.session_id != expected_stamp.session_id
            || packet.header.kind != expected_stage.control_kind()
            || message.stage != expected_stage
            || !same_route_transition(message, commit)
            || message.route_digest != binding.route_digest
            || message.transcript_digest != binding.transcript_digest
        {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::RouteTransition(
                    RouteTransitionViolation::BindingMismatch,
                ),
            );
        }
        operation.commit();
        Ok(message)
    }

    async fn next_route_transition_inner(
        &mut self,
        binding: Option<VerifiedRouteBinding>,
        allow_inactive: bool,
    ) -> Result<RouteTransitionMessage, ProductSessionError> {
        let mut operation = FailClosedControlRead::new(self.connection.clone());
        let private = self.next_control_private_inner(allow_inactive).await?;
        if !is_route_control(private.kind) {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::RouteTransition(
                    RouteTransitionViolation::UnexpectedKind(private.kind),
                ),
            );
        }
        let message = match RouteTransitionMessage::decode(&private.payload) {
            Ok(message) => message,
            Err(error) => {
                return fail_peer_protocol(
                    &self.connection,
                    ProductProtocolViolation::RouteTransition(RouteTransitionViolation::Malformed(
                        error,
                    )),
                )
            }
        };
        if message.stage.control_kind() != private.kind {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::RouteTransition(
                    RouteTransitionViolation::StageKindMismatch {
                        stage: message.stage,
                        kind: private.kind,
                    },
                ),
            );
        }
        if binding.is_some_and(|expected| {
            message.route_digest != expected.route_digest
                || message.transcript_digest != expected.transcript_digest
        }) {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::RouteTransition(
                    RouteTransitionViolation::BindingMismatch,
                ),
            );
        }
        let current = self.route_epoch.load(Ordering::Acquire);
        if message.base_route_epoch != current {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::RouteTransition(RouteTransitionViolation::RouteEpoch {
                    expected: current,
                    actual: message.base_route_epoch,
                }),
            );
        }
        if message.stage == RouteTransitionStage::Prepare {
            let last = self.route_sequence.load(Ordering::Acquire);
            let expected = last.checked_add(1).unwrap_or(0);
            if message.sequence != expected {
                return fail_peer_protocol(
                    &self.connection,
                    ProductProtocolViolation::RouteTransition(RouteTransitionViolation::Sequence {
                        expected,
                        actual: message.sequence,
                    }),
                );
            }
        }
        let mut state = self.route_transition.lock().await;
        let next = match state.received(message) {
            Ok(next) => next,
            Err(violation) => {
                return fail_peer_protocol(
                    &self.connection,
                    ProductProtocolViolation::RouteTransition(violation),
                )
            }
        };
        if message.stage == RouteTransitionStage::Commit
            && self
                .route_epoch
                .compare_exchange(
                    message.base_route_epoch,
                    message.next_route_epoch,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::RouteTransition(RouteTransitionViolation::InvalidState),
            );
        }
        if message.stage == RouteTransitionStage::Commit {
            self.route_sequence
                .store(message.sequence, Ordering::Release);
        }
        #[cfg(test)]
        if let Some(hook) = &self.route_receive_cancellation_hook {
            hook.reached.notify_one();
            hook.release.notified().await;
        }
        *state = next;
        operation.commit();
        Ok(message)
    }

    async fn next_control_private(&mut self) -> Result<PrivateControlMessage, ProductSessionError> {
        self.next_control_private_inner(false).await
    }

    async fn next_control_private_inner(
        &mut self,
        allow_inactive: bool,
    ) -> Result<PrivateControlMessage, ProductSessionError> {
        if !allow_inactive && !self.route_authorized.load(Ordering::Acquire) {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute,
            ));
        }
        let record = self
            .stream
            .next_record()
            .await
            .map_err(|error| inbound_error(&self.connection, error))?;
        if !allow_inactive && !self.route_authorized.load(Ordering::Acquire) {
            return Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute,
            ));
        }
        let expected_stamp = stamp_at_route_epoch(
            self.expected_stamp,
            self.route_epoch.load(Ordering::Acquire),
        );
        if record.stamp != expected_stamp {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::StampMismatch {
                    expected: expected_stamp,
                    actual: record.stamp,
                },
            );
        }
        let packet = match ControlPacket::decode(&record.payload) {
            Ok(packet) => packet,
            Err(error) => {
                return fail_peer_protocol(
                    &self.connection,
                    ProductProtocolViolation::MalformedControl(error),
                )
            }
        };
        if packet.header.session_id != self.expected_stamp.session_id {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::ControlSessionMismatch {
                    expected: self.expected_stamp.session_id,
                    actual: packet.header.session_id,
                },
            );
        }
        Ok(PrivateControlMessage {
            kind: packet.header.kind,
            payload: Zeroizing::new(packet.payload.to_vec()),
        })
    }

    /// Reads the next candidate advertisement and enforces its per-connection
    /// exchange identity and strictly consecutive generation.
    pub async fn next_candidate_exchange(
        &mut self,
    ) -> Result<CandidateExchange, ProductSessionError> {
        let next_mode = self
            .ice_generation
            .advertisement()
            .map_err(ProductSessionError::IceGeneration)?;
        let mut operation = FailClosedControlRead::new(self.connection.clone());
        let message = self.next_control_private().await?;
        if message.kind != ControlKind::IceCandidate {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::UnexpectedCandidateKind {
                    actual: message.kind,
                },
            );
        }
        let exchange = match CandidateExchange::decode(&message.payload) {
            Ok(exchange) => exchange,
            Err(error) => {
                return fail_peer_protocol(
                    &self.connection,
                    ProductProtocolViolation::CandidateExchange(
                        CandidateExchangeViolation::Malformed(error),
                    ),
                )
            }
        };
        if exchange.exchange_id != self.expected_stamp.session_id {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::CandidateExchange(
                    CandidateExchangeViolation::ExchangeId {
                        expected: self.expected_stamp.session_id,
                        actual: exchange.exchange_id,
                    },
                ),
            );
        }
        let mut next_candidate = self.candidate_exchange.clone();
        if let Err(violation) = next_candidate.accept_validated(&exchange) {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::CandidateExchange(violation),
            );
        }
        self.candidate_exchange = next_candidate;
        self.ice_generation = next_mode;
        operation.commit();
        Ok(exchange)
    }
}

fn validate_active_product_stamp(stamp: SessionStamp) -> Result<(), ProductSessionError> {
    stamp.validate_pending()?;
    if stamp.authorization_epoch == 0 || stamp.display_epoch == 0 || stamp.codec_epoch == 0 {
        return Err(ProductSessionError::Protocol(
            ProtocolError::InvalidSessionStamp,
        ));
    }
    Ok(())
}

fn stamp_at_route_epoch(mut stamp: SessionStamp, route_epoch: u64) -> SessionStamp {
    stamp.route_epoch = route_epoch;
    stamp
}

fn route_binding_for_session(
    session: &ProductSession,
    route_digest: [u8; 32],
) -> Result<VerifiedRouteBinding, ProductSessionError> {
    if route_digest == [0; 32] {
        return Err(ProductSessionError::RouteTransition(
            RouteTransitionViolation::InvalidBinding,
        ));
    }
    let peer_chain = session.connection.peer_certificate_chain()?;
    let peer_leaf = peer_chain
        .first()
        .ok_or(ProductSessionError::RouteTransition(
            RouteTransitionViolation::PeerIdentityMismatch,
        ))?;
    let context = route_exporter_context(session.stamp, route_digest);
    let exporter = session.connection.route_exporter(&context)?;
    let mut transcript = Sha256::new();
    transcript.update(b"latencydesk/product-route-transcript/v1");
    transcript.update(&exporter[..]);
    transcript.update(context);
    let transcript_digest = transcript.finalize().into();
    Ok(VerifiedRouteBinding {
        route_digest,
        transcript_digest,
        connection_id: session.connection.stable_id(),
        peer_fingerprint: Sha256::digest(peer_leaf).into(),
    })
}

fn route_exporter_context(stamp: SessionStamp, route_digest: [u8; 32]) -> [u8; 68] {
    let mut context = [0_u8; 68];
    context[0..8].copy_from_slice(&stamp.session_id.to_be_bytes());
    context[8..16].copy_from_slice(&stamp.generation.to_be_bytes());
    context[16..20].copy_from_slice(&stamp.authorization_epoch.to_be_bytes());
    context[20..24].copy_from_slice(&stamp.display_epoch.to_be_bytes());
    context[24..28].copy_from_slice(&stamp.codec_epoch.to_be_bytes());
    context[28..36].copy_from_slice(&stamp.route_epoch.to_be_bytes());
    context[36..68].copy_from_slice(&route_digest);
    context
}

fn is_route_control(kind: ControlKind) -> bool {
    matches!(
        kind,
        ControlKind::RoutePrepare
            | ControlKind::RoutePrepared
            | ControlKind::RouteCommit
            | ControlKind::RouteActivated
            | ControlKind::RouteConfirmed
    )
}

fn active_stamp(session_id: NonZeroU64) -> SessionStamp {
    SessionStamp {
        session_id: session_id.get(),
        generation: ACTIVE_GENERATION,
        authorization_epoch: ACTIVE_EPOCH,
        display_epoch: ACTIVE_EPOCH,
        codec_epoch: ACTIVE_EPOCH,
        route_epoch: 1,
    }
}

fn media_packet_budget(path_max_datagram_bytes: usize) -> Result<usize, ProductSessionError> {
    let minimum_inner_datagram_bytes = MEDIA_HEADER_LEN + 1;
    let available_inner_bytes = path_max_datagram_bytes
        .checked_sub(QUIC_MEDIA_HEADER_LEN)
        .filter(|available| *available >= minimum_inner_datagram_bytes)
        .ok_or(ProductSessionError::DatagramBudgetTooSmall {
            path_max_datagram_bytes,
            outer_header_bytes: QUIC_MEDIA_HEADER_LEN,
            minimum_inner_datagram_bytes,
        })?;
    Ok(available_inner_bytes.min(MAX_DATAGRAM_MTU))
}

fn encode_handshake_completed(stamp: SessionStamp) -> Result<Vec<u8>, ProductSessionError> {
    let completed = HandshakeCompletedMessage {
        session_id: stamp.session_id,
        authorization_epoch: stamp.authorization_epoch,
        server_nonce: POST_MTLS_NONCE,
    };
    let completed = completed.encode();
    let control = ControlPacket::encode(
        ControlHeader {
            kind: ControlKind::HandshakeCompleted,
            flags: 0,
            session_id: stamp.session_id,
            payload_len: completed.len() as u32,
        },
        &completed,
    )?;
    Ok(StreamRecord::encode(StreamKind::Control, stamp, &control)?)
}

fn validate_handshake_completed(
    record: &crate::quic::ReceivedStreamRecord,
) -> Result<SessionStamp, ProductSessionError> {
    let stamp = record.stamp;
    if validate_active_product_stamp(stamp).is_err() {
        return Err(ProductSessionError::PeerProtocol(
            ProductProtocolViolation::InvalidHandshakeStamp(stamp),
        ));
    }

    let control = ControlPacket::decode(&record.payload)?;
    if control.header.kind != ControlKind::HandshakeCompleted {
        return Err(ProductSessionError::PeerProtocol(
            ProductProtocolViolation::UnexpectedHandshakeKind(control.header.kind),
        ));
    }
    if control.header.session_id != stamp.session_id {
        return Err(ProductSessionError::PeerProtocol(
            ProductProtocolViolation::ControlSessionMismatch {
                expected: stamp.session_id,
                actual: control.header.session_id,
            },
        ));
    }
    let completed = HandshakeCompletedMessage::decode(control.payload)?;
    if completed.session_id != stamp.session_id {
        return Err(ProductSessionError::PeerProtocol(
            ProductProtocolViolation::HandshakeSessionMismatch {
                expected: stamp.session_id,
                actual: completed.session_id,
            },
        ));
    }
    if completed.authorization_epoch != stamp.authorization_epoch {
        return Err(ProductSessionError::PeerProtocol(
            ProductProtocolViolation::HandshakeAuthorizationMismatch {
                expected: stamp.authorization_epoch,
                actual: completed.authorization_epoch,
            },
        ));
    }
    if completed.server_nonce != POST_MTLS_NONCE {
        return Err(ProductSessionError::PeerProtocol(
            ProductProtocolViolation::HandshakeNonceMismatch,
        ));
    }
    Ok(stamp)
}

fn fail_peer_protocol<T>(
    connection: &QuicConnection,
    violation: ProductProtocolViolation,
) -> Result<T, ProductSessionError> {
    connection.close_for_protocol_violation();
    Err(ProductSessionError::PeerProtocol(violation))
}

fn inbound_error(connection: &QuicConnection, error: QuicTransportError) -> ProductSessionError {
    if matches!(
        &error,
        QuicTransportError::Read(quinn::ReadExactError::FinishedEarly(_))
    ) {
        connection.close_for_protocol_violation();
    }
    ProductSessionError::Quic(error)
}

fn is_skippable_ingest_error(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::StaleCodecEpoch { .. }
            | TransportError::MetadataConflict(_)
            | TransportError::FragmentConflict
            | TransportError::FragmentOverlap
            | TransportError::ReplayDetected(_)
            | TransportError::FragmentEntryLimit
            | TransportError::ReassemblyCapacity
            | TransportError::FrameExceedsReassemblyBudget { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{bind_client, bind_server};
    use latencydesk_protocol::{
        media_flags, video_capability_flags, video_stream_flags, CandidateType, IceCandidate,
        MediaKind, MediaPacket, RelayProvider, TransportProtocol, VideoCodec,
        VideoCodecCapabilities, VideoProfile, VideoStreamConfig, WireIpAddr,
        VIDEO_CODEC_CONTRACT_VERSION,
    };
    use latencydesk_transport::{fragment_frame_with_packet_budget, FrameKey};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn only_quic_path_timeout_or_reset_is_a_retryable_product_failure() {
        let timeout = ProductSessionError::Quic(QuicTransportError::Connection(
            quinn::ConnectionError::TimedOut,
        ));
        let reset = ProductSessionError::Quic(QuicTransportError::Write(
            quinn::WriteError::ConnectionLost(quinn::ConnectionError::Reset),
        ));
        let protocol = ProductSessionError::Protocol(ProtocolError::InvalidSessionStamp);

        assert!(timeout.is_retryable_connection_loss());
        assert!(reset.is_retryable_connection_loss());
        assert!(!protocol.is_retryable_connection_loss());
    }

    fn candidate_exchange(generation: u32, exchange_id: u64) -> CandidateExchange {
        CandidateExchange {
            version: CandidateExchange::VERSION,
            exchange_id,
            generation,
            candidates: vec![IceCandidate {
                foundation: *b"testcand",
                component: 1,
                transport: TransportProtocol::Udp,
                priority: 1,
                candidate_type: CandidateType::Host,
                relay_provider: RelayProvider::None,
                ip: WireIpAddr::V4([127, 0, 0, 1]),
                port: 5000,
                related_address: None,
            }],
        }
    }

    fn credentials(
        generation: u32,
        exchange_id: u64,
        role: IceCredentialRole,
    ) -> IceCredentialExchange {
        IceCredentialExchange::new(
            1,
            exchange_id,
            generation,
            role,
            "ufrag".into(),
            "abcdefghijklmnopqrstuv".into(),
        )
        .unwrap()
    }

    fn authenticated_ice_offer() -> VideoCodecCapabilities {
        VideoCodecCapabilities {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            flags: video_capability_flags::RAW_NV12
                | video_capability_flags::AUTHENTICATED_ICE_CREDENTIALS,
            max_width: 2,
            max_height: 2,
            max_fps: 1,
        }
    }

    fn authenticated_ice_selection() -> VideoStreamConfig {
        VideoStreamConfig {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            codec: VideoCodec::RawNv12,
            profile: VideoProfile::RawNv12,
            pixel_format: u32::from_le_bytes(*b"NV12"),
            stream_id: 1,
            codec_epoch: 1,
            width: 2,
            height: 2,
            fps: 1,
            target_bitrate_bps: 1,
            flags: video_stream_flags::AUTHENTICATED_ICE_CREDENTIALS,
        }
    }

    #[test]
    fn ice_generation_tracker_accepts_two_complete_generations() {
        let mut tracker = IceGenerationTracker::default();
        tracker = tracker
            .begin(&credentials(1, 42, IceCredentialRole::Controlling), 42)
            .unwrap();
        tracker = tracker.finish(&candidate_exchange(1, 42)).unwrap();
        tracker = tracker
            .begin(&credentials(2, 42, IceCredentialRole::Controlling), 42)
            .unwrap();
        assert_eq!(
            tracker
                .finish(&candidate_exchange(2, 42))
                .unwrap()
                .generation,
            2
        );
    }

    #[test]
    fn ice_generation_tracker_rejects_candidate_before_credentials() {
        assert!(matches!(
            IceGenerationTracker::default().finish(&candidate_exchange(1, 42)),
            Err(IceGenerationViolation::CandidateBeforeCredentials)
        ));
    }

    #[test]
    fn ice_generation_tracker_rejects_id_generation_replay_gap_and_overflow() {
        let mut tracker = IceGenerationTracker::default();
        assert!(matches!(
            tracker.begin(&credentials(1, 9, IceCredentialRole::Controlled), 42),
            Err(IceGenerationViolation::ExchangeId { .. })
        ));
        tracker = tracker
            .begin(&credentials(1, 42, IceCredentialRole::Controlled), 42)
            .unwrap();
        assert!(matches!(
            tracker.begin(&credentials(1, 42, IceCredentialRole::Controlled), 42),
            Err(IceGenerationViolation::Pending)
        ));
        tracker = tracker.finish(&candidate_exchange(1, 42)).unwrap();
        assert!(matches!(
            tracker.begin(&credentials(3, 42, IceCredentialRole::Controlled), 42),
            Err(IceGenerationViolation::Generation { .. })
        ));
        let exhausted = IceGenerationTracker {
            exchange_id: Some(42),
            generation: u32::MAX,
            pending: None,
            mode: Some(IceSignalingMode::CredentialGenerations),
            poisoned: false,
        };
        assert!(matches!(
            exhausted.begin(&credentials(1, 42, IceCredentialRole::Controlled), 42),
            Err(IceGenerationViolation::GenerationExhausted)
        ));
    }

    #[test]
    fn ice_generation_tracker_rejects_candidate_id_or_generation_mismatch() {
        let tracker = IceGenerationTracker::default()
            .begin(&credentials(1, 42, IceCredentialRole::Controlling), 42)
            .unwrap();
        assert!(matches!(
            tracker.clone().finish(&candidate_exchange(1, 43)),
            Err(IceGenerationViolation::ExchangeId { .. })
        ));
        assert!(matches!(
            tracker.finish(&candidate_exchange(2, 42)),
            Err(IceGenerationViolation::Generation { .. })
        ));
    }

    #[test]
    fn ice_credentials_debug_redacts_secret_and_role_is_explicit() {
        let value = credentials(1, 42, IceCredentialRole::Controlled);
        let debug = format!("{value:?}");
        assert!(!debug.contains("abcdefghijklmnopqrstuv"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn candidate_tracker_accepts_round_trip_and_sequential_updates() {
        let first = candidate_exchange(1, 42);
        let decoded = CandidateExchange::decode(&first.encode().unwrap()).unwrap();
        let mut tracker = CandidateExchangeTracker::default();
        assert_eq!(tracker.accept(&decoded), Ok(()));
        assert_eq!(tracker.accept(&candidate_exchange(2, 42)), Ok(()));
    }

    #[test]
    fn candidate_tracker_rejects_replay_gap_id_change_and_exhaustion() {
        let mut tracker = CandidateExchangeTracker::default();
        assert!(tracker.accept(&candidate_exchange(1, 42)).is_ok());
        for generation in [1, 3] {
            assert!(matches!(
                tracker.accept(&candidate_exchange(generation, 42)),
                Err(CandidateExchangeViolation::Generation { .. })
            ));
        }
        assert!(matches!(
            tracker.accept(&candidate_exchange(2, 43)),
            Err(CandidateExchangeViolation::ExchangeId { .. })
        ));
        let mut exhausted = CandidateExchangeTracker {
            exchange_id: Some(42),
            generation: u32::MAX,
        };
        assert_eq!(
            exhausted.accept(&candidate_exchange(u32::MAX, 42)),
            Err(CandidateExchangeViolation::GenerationExhausted)
        );
    }

    #[test]
    fn candidate_tracker_rejects_malformed_payload() {
        let malformed = CandidateExchange::decode(&[1, 2, 3]);
        assert!(malformed.is_err());
        let mut tracker = CandidateExchangeTracker::default();
        let invalid = CandidateExchange {
            version: 1,
            exchange_id: 1,
            generation: 1,
            candidates: vec![],
        };
        assert!(matches!(
            tracker.accept(&invalid),
            Err(CandidateExchangeViolation::Malformed(_))
        ));
    }

    struct TestIdentity {
        certificate: CertificateDer<'static>,
        private_key: PrivateKeyDer<'static>,
    }

    struct ConnectedPair {
        client: QuicConnection,
        server: QuicConnection,
        _client_endpoint: quinn::Endpoint,
        _server_endpoint: quinn::Endpoint,
    }

    struct ConnectedRoutePairs {
        first_client: QuicConnection,
        first_server: QuicConnection,
        second_client: QuicConnection,
        second_server: QuicConnection,
        _client_endpoint: quinn::Endpoint,
        _server_endpoint: quinn::Endpoint,
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

    fn test_configs(path_mtu: u16) -> (quinn::ServerConfig, quinn::ClientConfig) {
        test_configs_with_client_uni_stream_credit(path_mtu, None)
    }

    fn test_configs_with_client_uni_stream_credit(
        path_mtu: u16,
        client_uni_stream_credit: Option<u32>,
    ) -> (quinn::ServerConfig, quinn::ClientConfig) {
        let server_identity = test_identity("localhost");
        let client_identity = test_identity("latencydesk-product-client");

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
            vec![client_identity.certificate.clone()],
            client_identity.private_key,
        )
        .expect("client identity");

        let mut server_roots = rustls::RootCertStore::empty();
        server_roots
            .add(client_identity.certificate)
            .expect("client root");
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
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
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(
            vec![server_identity.certificate],
            server_identity.private_key,
        )
        .expect("server identity");

        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_crypto))
                .expect("QUIC server crypto"),
        ));
        server.transport = Arc::new(test_transport_config(path_mtu));
        let mut client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_crypto))
                .expect("QUIC client crypto"),
        ));
        let mut client_transport = test_transport_config(path_mtu);
        if let Some(credit) = client_uni_stream_credit {
            client_transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(credit));
        }
        client.transport_config(Arc::new(client_transport));
        (server, client)
    }

    fn test_transport_config(path_mtu: u16) -> quinn::TransportConfig {
        let mut config = quinn::TransportConfig::default();
        config
            .initial_mtu(path_mtu)
            .min_mtu(path_mtu)
            .mtu_discovery_config(None)
            .datagram_receive_buffer_size(Some(256 * 1024))
            .datagram_send_buffer_size(256 * 1024);
        config
    }

    async fn connected_pair(path_mtu: u16) -> ConnectedPair {
        connected_pair_with_configs(test_configs(path_mtu)).await
    }

    async fn connected_pair_with_configs(
        configs: (quinn::ServerConfig, quinn::ClientConfig),
    ) -> ConnectedPair {
        let (server_config, client_config) = configs;
        let server_endpoint =
            bind_server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("server endpoint");
        let client_endpoint =
            bind_client(client_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("client endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");
        let (server, client) = tokio::join!(
            QuicConnection::accept(&server_endpoint),
            QuicConnection::connect(&client_endpoint, server_address, "localhost"),
        );
        ConnectedPair {
            client: client.expect("client connection"),
            server: server.expect("server connection"),
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
        }
    }

    async fn product_pair(path_mtu: u16) -> (ProductSession, ProductSession) {
        let pair = connected_pair(path_mtu).await;
        let (host, client) = tokio::join!(
            ProductSession::host(pair.server, NonZeroU64::new(41).expect("nonzero")),
            ProductSession::client(pair.client),
        );
        (host.expect("host session"), client.expect("client session"))
    }

    async fn product_route_sets(path_mtu: u16) -> (ProductRouteSet, ProductRouteSet) {
        let (server_config, client_config) = test_configs(path_mtu);
        let server_endpoint =
            bind_server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let client_endpoint =
            bind_client(client_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_address = server_endpoint.local_addr().unwrap();
        let (first_server, first_client) = tokio::join!(
            QuicConnection::accept(&server_endpoint),
            QuicConnection::connect(&client_endpoint, server_address, "localhost"),
        );
        let (second_server, second_client) = tokio::join!(
            QuicConnection::accept(&server_endpoint),
            QuicConnection::connect(&client_endpoint, server_address, "localhost"),
        );
        let pairs = ConnectedRoutePairs {
            first_client: first_client.unwrap(),
            first_server: first_server.unwrap(),
            second_client: second_client.unwrap(),
            second_server: second_server.unwrap(),
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
        };
        let stamp = active_stamp(NonZeroU64::new(41).unwrap());
        let (first_host, first_client) = tokio::join!(
            ProductSession::host_with_stamp(pairs.first_server, stamp),
            ProductSession::client(pairs.first_client),
        );
        let first_host = first_host.unwrap();
        let first_client = first_client.unwrap();
        let (second_host, second_client) = tokio::join!(
            ProductSession::host_route_candidate(pairs.second_server, stamp),
            ProductSession::client_route_candidate(pairs.second_client, stamp),
        );
        let second_host = second_host.unwrap();
        let second_client = second_client.unwrap();
        let host_active_binding = route_binding(&first_host, 0x21);
        let host_candidate_binding = candidate_route_binding(&second_host, 0x31);
        let client_active_binding = route_binding(&first_client, 0x21);
        let client_candidate_binding = candidate_route_binding(&second_client, 0x31);
        (
            ProductRouteSet::new(
                first_host,
                host_active_binding,
                second_host,
                host_candidate_binding,
            )
            .unwrap(),
            ProductRouteSet::new(
                first_client,
                client_active_binding,
                second_client,
                client_candidate_binding,
            )
            .unwrap(),
        )
    }

    async fn configure_ice_pair(host: &ProductSession, client: &ProductSession) {
        let offered = authenticated_ice_offer();
        let selected = authenticated_ice_selection();
        let (host_result, client_result) = tokio::join!(
            host.enable_authenticated_ice_signaling(offered, selected),
            client.enable_authenticated_ice_signaling(offered, selected),
        );
        host_result.unwrap();
        client_result.unwrap();
    }

    async fn send_raw_product_control(session: &ProductSession, kind: ControlKind, payload: &[u8]) {
        let stamp = session.stamp();
        let control = ControlPacket::encode(
            ControlHeader {
                kind,
                flags: 0,
                session_id: stamp.session_id,
                payload_len: u32::try_from(payload.len()).unwrap(),
            },
            payload,
        )
        .unwrap();
        let record = StreamRecord::encode(StreamKind::Control, stamp, &control).unwrap();
        session.connection.send_control(&record).await.unwrap();
    }

    async fn send_raw_ice_generation(
        session: &ProductSession,
        credentials: &IceCredentialExchange,
        candidates: &CandidateExchange,
    ) {
        let credential_payload = credentials.encode().unwrap();
        send_raw_product_control(session, ControlKind::IceCredentials, &credential_payload).await;
        send_raw_product_control(
            session,
            ControlKind::IceCandidate,
            &candidates.encode().unwrap(),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_generation_product_round_trip_is_ordered_and_role_bound() {
        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        client
            .send_ice_generation(
                credentials(1, 41, IceCredentialRole::Controlling),
                candidate_exchange(1, 41),
            )
            .await
            .unwrap();
        let mut receiver = host.accept_control_receiver().await.unwrap();
        for generation in 1..=2 {
            if generation > 1 {
                client
                    .send_ice_generation(
                        credentials(generation, 41, IceCredentialRole::Controlling),
                        candidate_exchange(generation, 41),
                    )
                    .await
                    .unwrap();
            }
            let (received_credentials, received_candidates) =
                receiver.next_ice_generation().await.unwrap();
            assert_eq!(received_credentials.exchange_id, 41);
            assert_eq!(received_credentials.generation, generation);
            assert_eq!(received_credentials.role, IceCredentialRole::Controlling);
            assert_eq!(received_credentials.password_len(), 22);
            assert_eq!(received_candidates.generation, generation);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_generation_requires_negotiated_session_roles_and_typed_control() {
        let (_host, client) = product_pair(1_450).await;
        assert!(matches!(
            client
                .send_ice_generation(
                    credentials(1, 41, IceCredentialRole::Controlling),
                    candidate_exchange(1, 41),
                )
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::IceSignalingNotNegotiated
            ))
        ));
        let mut receiver = client.accept_control_receiver().await.unwrap();
        assert!(matches!(
            receiver.next_ice_generation().await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::IceSignalingNotNegotiated
            ))
        ));
        let offered = authenticated_ice_offer();
        let selected = authenticated_ice_selection();
        assert!(matches!(
            client
                .enable_authenticated_ice_signaling(
                    VideoCodecCapabilities {
                        flags: video_capability_flags::RAW_NV12,
                        ..offered
                    },
                    selected,
                )
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::IceCapabilityNotNegotiated
            ))
        ));
        assert!(matches!(
            client
                .enable_authenticated_ice_signaling(
                    offered,
                    VideoStreamConfig {
                        flags: 0,
                        ..selected
                    },
                )
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::IceCapabilityNotNegotiated
            ))
        ));
        client
            .enable_authenticated_ice_signaling(offered, selected)
            .await
            .unwrap();
        client
            .enable_authenticated_ice_signaling(offered, selected)
            .await
            .unwrap();
        for kind in [ControlKind::IceCredentials, ControlKind::IceCandidate] {
            assert!(matches!(
                client.send_control(kind, &[1, 2, 3]).await,
                Err(ProductSessionError::IceGeneration(
                    IceGenerationViolation::IceControlRequiresTypedApi
                ))
            ));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn candidate_advertisement_and_credential_generations_are_mutually_exclusive() {
        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        let advertised = candidate_exchange(1, 41);
        client
            .send_candidate_exchange(advertised.clone())
            .await
            .unwrap();
        assert!(matches!(
            client
                .send_ice_generation(
                    credentials(1, 41, IceCredentialRole::Controlling),
                    candidate_exchange(1, 41),
                )
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::ModeConflict
            ))
        ));
        let mut receiver = host.accept_control_receiver().await.unwrap();
        assert_eq!(
            receiver.next_candidate_exchange().await.unwrap(),
            advertised
        );
        assert!(matches!(
            receiver.next_ice_generation().await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::ModeConflict
            ))
        ));

        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        client
            .send_ice_generation(
                credentials(1, 41, IceCredentialRole::Controlling),
                candidate_exchange(1, 41),
            )
            .await
            .unwrap();
        assert!(matches!(
            client
                .send_candidate_exchange(candidate_exchange(1, 41))
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::ModeConflict
            ))
        ));
        let mut receiver = host.accept_control_receiver().await.unwrap();
        receiver.next_ice_generation().await.unwrap();
        assert!(matches!(
            receiver.next_candidate_exchange().await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::ModeConflict
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_mixed_ice_apis_select_exactly_one_wire_mode() {
        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        let advertisement_sender = client.clone();
        let generation_sender = client.clone();
        let advertisement = candidate_exchange(1, 41);
        let (advertisement_result, generation_result) = tokio::join!(
            advertisement_sender.send_candidate_exchange(advertisement.clone()),
            generation_sender.send_ice_generation(
                credentials(1, 41, IceCredentialRole::Controlling),
                candidate_exchange(1, 41),
            ),
        );
        assert_ne!(advertisement_result.is_ok(), generation_result.is_ok());
        let mut receiver = host.accept_control_receiver().await.unwrap();
        if advertisement_result.is_ok() {
            assert!(matches!(
                generation_result,
                Err(ProductSessionError::IceGeneration(
                    IceGenerationViolation::ModeConflict
                ))
            ));
            assert_eq!(
                receiver.next_candidate_exchange().await.unwrap(),
                advertisement
            );
        } else {
            assert!(matches!(
                advertisement_result,
                Err(ProductSessionError::IceGeneration(
                    IceGenerationViolation::ModeConflict
                ))
            ));
            let (received_credentials, received_candidates) =
                receiver.next_ice_generation().await.unwrap();
            assert_eq!(received_credentials.generation, 1);
            assert_eq!(received_candidates.generation, 1);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_ice_senders_poison_mode_and_close_the_connection() {
        let (host, mut client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        let hook = Arc::new(IceSendCancellationHook::default());
        client.ice_send_cancellation_hook = Some(Arc::clone(&hook));
        let sender = client.clone();
        let task = tokio::spawn(async move {
            sender
                .send_ice_generation(
                    credentials(1, 41, IceCredentialRole::Controlling),
                    candidate_exchange(1, 41),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), hook.reached.notified())
            .await
            .expect("credentials reached the wire before cancellation");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(client.ice_generation.lock().await.poisoned);
        tokio::time::timeout(Duration::from_secs(1), host.connection.closed())
            .await
            .expect("credential cancellation closed the peer connection");

        let (host, mut client) = product_pair(1_450).await;
        let hook = Arc::new(IceSendCancellationHook::default());
        client.ice_send_cancellation_hook = Some(Arc::clone(&hook));
        let sender = client.clone();
        let task = tokio::spawn(async move {
            sender
                .send_candidate_exchange(candidate_exchange(1, 41))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), hook.reached.notified())
            .await
            .expect("candidate reached the wire before cancellation");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(client.ice_generation.lock().await.poisoned);
        tokio::time::timeout(Duration::from_secs(1), host.connection.closed())
            .await
            .expect("candidate cancellation closed the peer connection");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_ice_receive_persists_pending_mode_and_closes() {
        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        let credential_payload = credentials(1, 41, IceCredentialRole::Controlling)
            .encode()
            .unwrap();
        send_raw_product_control(&client, ControlKind::IceCredentials, &credential_payload).await;
        let mut receiver = host.accept_control_receiver().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), receiver.next_ice_generation())
                .await
                .is_err()
        );
        assert_eq!(receiver.ice_generation.pending, Some(1));
        assert_eq!(
            receiver.ice_generation.mode,
            Some(IceSignalingMode::CredentialGenerations)
        );
        assert!(matches!(
            receiver.next_candidate_exchange().await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::ModeConflict
            ))
        ));
        tokio::time::timeout(Duration::from_secs(1), client.connection.closed())
            .await
            .expect("peer observed cancellation close");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn generic_control_receive_rejects_ice_and_debug_never_renders_payload() {
        let message = ProductControlMessage {
            kind: ControlKind::IceCredentials,
            payload: Bytes::from_static(b"do-not-render-this-secret"),
        };
        let rendered = format!("{message:?}");
        assert!(!rendered.contains("do-not-render-this-secret"));
        assert!(rendered.contains("<redacted>"));

        for kind in [ControlKind::IceCredentials, ControlKind::IceCandidate] {
            let (host, client) = product_pair(1_450).await;
            send_raw_product_control(&client, kind, &[1, 2, 3]).await;
            let mut receiver = host.accept_control_receiver().await.unwrap();
            assert!(matches!(
                receiver.next_control().await,
                Err(ProductSessionError::IceGeneration(
                    IceGenerationViolation::IceControlRequiresTypedApi
                ))
            ));
            tokio::time::timeout(Duration::from_secs(1), client.connection.closed())
                .await
                .expect("generic ICE receive closed the peer connection");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_duplicate_ice_generation_has_exactly_one_sender_winner() {
        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        let first = client.clone();
        let second = client.clone();
        let (first_result, second_result) = tokio::join!(
            first.send_ice_generation(
                credentials(1, 41, IceCredentialRole::Controlling),
                candidate_exchange(1, 41),
            ),
            second.send_ice_generation(
                credentials(1, 41, IceCredentialRole::Controlling),
                candidate_exchange(1, 41),
            ),
        );
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        let error = if let Err(error) = first_result {
            error
        } else {
            second_result.unwrap_err()
        };
        assert!(matches!(
            error,
            ProductSessionError::IceGeneration(IceGenerationViolation::Generation {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_generation_rejects_local_and_remote_role_mismatch() {
        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        assert!(matches!(
            client
                .send_ice_generation(
                    credentials(1, 41, IceCredentialRole::Controlled),
                    candidate_exchange(1, 41),
                )
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::RoleMismatch { .. }
            ))
        ));
        send_raw_ice_generation(
            &client,
            &credentials(1, 41, IceCredentialRole::Controlled),
            &candidate_exchange(1, 41),
        )
        .await;
        let mut receiver = host.accept_control_receiver().await.unwrap();
        assert!(matches!(
            receiver.next_ice_generation().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::IceGeneration(
                    IceGenerationViolation::RoleMismatch { .. }
                )
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn candidate_before_credentials_and_malformed_credentials_fail_closed() {
        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        send_raw_product_control(
            &client,
            ControlKind::IceCandidate,
            &candidate_exchange(1, 41).encode().unwrap(),
        )
        .await;
        let mut receiver = host.accept_control_receiver().await.unwrap();
        assert!(matches!(
            receiver.next_ice_generation().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::UnexpectedCredentialsKind {
                    actual: ControlKind::IceCandidate
                }
            ))
        ));

        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        assert!(matches!(
            client
                .send_control(ControlKind::IceCredentials, &[1, 2, 3])
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::IceControlRequiresTypedApi
            ))
        ));
        send_raw_product_control(&client, ControlKind::IceCredentials, &[1, 2, 3]).await;
        let mut receiver = host.accept_control_receiver().await.unwrap();
        let error = receiver.next_ice_generation().await.unwrap_err();
        assert!(matches!(
            error,
            ProductSessionError::PeerProtocol(ProductProtocolViolation::IceGeneration(
                IceGenerationViolation::Malformed(_)
            ))
        ));
        assert!(!format!("{error}").contains("abcdefghijklmnopqrstuv"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_typed_ice_write_poisoned_the_session_mode() {
        let (host, client) = product_pair(1_450).await;
        configure_ice_pair(&host, &client).await;
        host.close(0x123, b"test peer shutdown");
        tokio::time::timeout(Duration::from_secs(1), client.connection.closed())
            .await
            .expect("client observed peer shutdown");

        assert!(matches!(
            client
                .send_ice_generation(
                    credentials(1, 41, IceCredentialRole::Controlling),
                    candidate_exchange(1, 41),
                )
                .await,
            Err(ProductSessionError::Quic(_))
        ));
        assert!(matches!(
            client
                .send_ice_generation(
                    credentials(1, 41, IceCredentialRole::Controlling),
                    candidate_exchange(1, 41),
                )
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::Poisoned
            ))
        ));
        assert!(matches!(
            client
                .send_candidate_exchange(candidate_exchange(1, 41))
                .await,
            Err(ProductSessionError::IceGeneration(
                IceGenerationViolation::Poisoned
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_control_packet_closes_the_authenticated_connection() {
        let (host, client) = product_pair(1_450).await;
        let record = StreamRecord::encode(StreamKind::Control, client.stamp, &[1, 2, 3])
            .expect("bounded malformed control record");
        client.connection.send_control(&record).await.unwrap();
        let mut receiver = host.accept_control_receiver().await.unwrap();
        assert!(matches!(
            receiver.next_control().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::MalformedControl(_)
            ))
        ));
        tokio::time::timeout(Duration::from_secs(1), client.connection.closed())
            .await
            .expect("peer observed protocol close");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_pre_handshake_ice_credentials_are_rejected() {
        let pair = connected_pair(1_450).await;
        let stamp = active_stamp(NonZeroU64::new(41).unwrap());
        let credentials = credentials(1, 41, IceCredentialRole::Controlling);
        let payload = credentials.encode().unwrap();
        let packet = ControlPacket::encode(
            ControlHeader {
                kind: ControlKind::IceCredentials,
                flags: 0,
                session_id: 41,
                payload_len: u32::try_from(payload.len()).unwrap(),
            },
            &payload,
        )
        .unwrap();
        pair.server
            .send_control(&StreamRecord::encode(StreamKind::Control, stamp, &packet).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            ProductSession::client(pair.client).await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::UnexpectedHandshakeKind(ControlKind::IceCredentials)
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn candidate_exchange_product_round_trip_and_sequence() {
        let (host, client) = product_pair(1_450).await;
        let first = candidate_exchange(1, 41);
        let second = candidate_exchange(2, 41);
        client.send_candidate_exchange(first.clone()).await.unwrap();
        client
            .send_candidate_exchange(second.clone())
            .await
            .unwrap();
        let mut receiver = host.accept_control_receiver().await.unwrap();
        assert_eq!(receiver.next_candidate_exchange().await.unwrap(), first);
        assert_eq!(receiver.next_candidate_exchange().await.unwrap(), second);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn candidate_exchange_id_must_match_the_active_product_session() {
        let (host, client) = product_pair(1_450).await;
        let wrong_session = candidate_exchange(1, 42);
        assert!(matches!(
            client.send_candidate_exchange(wrong_session.clone()).await,
            Err(ProductSessionError::CandidateExchange(
                CandidateExchangeViolation::ExchangeId {
                    expected: 41,
                    actual: 42
                }
            ))
        ));

        send_raw_product_control(
            &client,
            ControlKind::IceCandidate,
            &wrong_session.encode().expect("valid candidate payload"),
        )
        .await;
        let mut receiver = host.accept_control_receiver().await.expect("control lane");
        assert!(matches!(
            receiver.next_candidate_exchange().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::CandidateExchange(
                    CandidateExchangeViolation::ExchangeId {
                        expected: 41,
                        actual: 42
                    }
                )
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_pre_handshake_candidate_is_rejected() {
        let pair = connected_pair(1_450).await;
        let stamp = active_stamp(NonZeroU64::new(41).unwrap());
        let packet = ControlPacket::encode(
            ControlHeader {
                kind: ControlKind::IceCandidate,
                flags: 0,
                session_id: 41,
                payload_len: 0,
            },
            &[],
        )
        .unwrap();
        pair.server
            .send_control(&StreamRecord::encode(StreamKind::Control, stamp, &packet).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            ProductSession::client(pair.client).await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::UnexpectedHandshakeKind(ControlKind::IceCandidate)
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_candidate_closes_active_connection() {
        let (host, client) = product_pair(1_450).await;
        send_raw_product_control(&client, ControlKind::IceCandidate, &[1, 2, 3]).await;
        let mut receiver = host.accept_control_receiver().await.unwrap();
        assert!(matches!(
            receiver.next_candidate_exchange().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::CandidateExchange(CandidateExchangeViolation::Malformed(
                    _
                ))
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_candidate_kind_closes_active_connection() {
        let (host, client) = product_pair(1_450).await;
        client
            .send_control(ControlKind::Capabilities, &[])
            .await
            .unwrap();
        let mut receiver = host.accept_control_receiver().await.unwrap();
        assert!(matches!(
            receiver.next_candidate_exchange().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::UnexpectedCandidateKind {
                    actual: ControlKind::Capabilities
                }
            ))
        ));
    }

    fn video_spec(frame_id: u64) -> FragmentSpec {
        FragmentSpec {
            kind: MediaKind::Video,
            flags: media_flags::KEYFRAME,
            stream_id: 1,
            codec_epoch: ACTIVE_EPOCH,
            frame_id,
            dependency_frame_id: None,
        }
    }

    fn route_message(
        stage: RouteTransitionStage,
        sequence: u64,
        base_route_epoch: u64,
        route_digest: [u8; 32],
    ) -> RouteTransitionMessage {
        RouteTransitionMessage {
            version: latencydesk_protocol::WIRE_VERSION,
            stage,
            sequence,
            base_route_epoch,
            next_route_epoch: base_route_epoch + 1,
            expires_at_ns: 1_000_000,
            route_digest,
            transcript_digest: [route_digest[0].wrapping_add(0x70); 32],
        }
    }

    fn bound_route_message(
        routes: &ProductRouteSet,
        target_index: usize,
        stage: RouteTransitionStage,
        sequence: u64,
        base_route_epoch: u64,
    ) -> RouteTransitionMessage {
        let (route_digest, transcript_digest) = routes.bindings[target_index].transition_material();
        RouteTransitionMessage {
            version: latencydesk_protocol::WIRE_VERSION,
            stage,
            sequence,
            base_route_epoch,
            next_route_epoch: base_route_epoch + 1,
            expires_at_ns: 1_000_000,
            route_digest,
            transcript_digest,
        }
    }

    fn route_binding(session: &ProductSession, byte: u8) -> VerifiedRouteBinding {
        session.bind_authenticated_route([byte; 32]).unwrap()
    }

    fn candidate_route_binding(
        session: &UnauthorizedCandidateSession,
        byte: u8,
    ) -> VerifiedRouteBinding {
        session.bind_authenticated_route([byte; 32]).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_mtls_handshake_activates_the_exact_v2_stamp() {
        let (host, client) = product_pair(1_450).await;
        let expected = SessionStamp {
            session_id: 41,
            generation: 1,
            authorization_epoch: 1,
            display_epoch: 1,
            codec_epoch: 1,
            route_epoch: 1,
        };
        assert_eq!(host.stamp(), expected);
        assert_eq!(client.stamp(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_supplied_lifecycle_stamp_survives_the_product_handshake() {
        let pair = connected_pair(1_450).await;
        let stamp = SessionStamp {
            session_id: 81,
            generation: 7,
            authorization_epoch: 8,
            display_epoch: 9,
            codec_epoch: 10,
            route_epoch: 1,
        };
        let (host, client) = tokio::join!(
            ProductSession::host_with_stamp(pair.server, stamp),
            ProductSession::client(pair.client),
        );

        assert_eq!(host.expect("host session").stamp(), stamp);
        assert_eq!(client.expect("client session").stamp(), stamp);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn route_binding_transcript_is_tls_exporter_and_context_bound() {
        let route_digest = [0x41; 32];
        let (host, client) = product_pair(1_450).await;
        let host_material = host
            .bind_authenticated_route(route_digest)
            .unwrap()
            .transition_material();
        let client_material = client
            .bind_authenticated_route(route_digest)
            .unwrap()
            .transition_material();
        assert_eq!(host_material, client_material);
        assert_eq!(host_material.0, route_digest);
        assert_ne!(host_material.1, [0; 32]);

        let different_route = host
            .bind_authenticated_route([0x42; 32])
            .unwrap()
            .transition_material();
        assert_ne!(different_route.1, host_material.1);
        assert!(matches!(
            host.bind_authenticated_route([0; 32]),
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidBinding
            ))
        ));

        let (other_host, _other_client) = product_pair(1_450).await;
        let other_connection = other_host
            .bind_authenticated_route(route_digest)
            .unwrap()
            .transition_material();
        assert_ne!(other_connection.1, host_material.1);

        let mut later_stamp = host.stamp();
        later_stamp.generation += 1;
        let current_context = route_exporter_context(host.stamp(), route_digest);
        let later_context = route_exporter_context(later_stamp, route_digest);
        assert_ne!(current_context, later_context);
        let current_exporter = host.connection.route_exporter(&current_context).unwrap();
        let later_exporter = host.connection.route_exporter(&later_context).unwrap();
        assert_ne!(&current_exporter[..], &later_exporter[..]);
    }

    #[test]
    fn route_exporter_context_has_a_fixed_big_endian_layout() {
        let stamp = SessionStamp {
            session_id: 0x0102_0304_0506_0708,
            generation: 0x1112_1314_1516_1718,
            authorization_epoch: 0x2122_2324,
            display_epoch: 0x3132_3334,
            codec_epoch: 0x4142_4344,
            route_epoch: 0x5152_5354_5556_5758,
        };
        let context = route_exporter_context(stamp, [0x61; 32]);
        assert_eq!(
            &context[..36],
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44,
                0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            ]
        );
        assert_eq!(&context[36..], &[0x61; 32]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successor_client_rejects_a_non_monotonic_generation() {
        let pair = connected_pair(1_450).await;
        let previous = SessionStamp {
            session_id: 80,
            generation: 7,
            authorization_epoch: 8,
            display_epoch: 9,
            codec_epoch: 10,
            route_epoch: 1,
        };
        let replayed = SessionStamp {
            session_id: 81,
            generation: 7,
            authorization_epoch: 9,
            display_epoch: 9,
            codec_epoch: 10,
            route_epoch: 1,
        };
        let (host, client) = tokio::join!(
            ProductSession::host_with_stamp(pair.server, replayed),
            ProductSession::client_successor(pair.client, previous),
        );
        host.expect("host publishes its stamp");
        assert!(matches!(
            client,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::NonMonotonicSuccessor { .. }
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successor_client_accepts_fresh_identity_and_strictly_new_lifecycle_epochs() {
        let pair = connected_pair(1_450).await;
        let previous = SessionStamp {
            session_id: 80,
            generation: 7,
            authorization_epoch: 8,
            display_epoch: 9,
            codec_epoch: 10,
            route_epoch: 1,
        };
        let successor = SessionStamp {
            session_id: 81,
            generation: 8,
            authorization_epoch: 9,
            display_epoch: 10,
            codec_epoch: 11,
            route_epoch: 1,
        };
        let (host, client) = tokio::join!(
            ProductSession::host_with_stamp(pair.server, successor),
            ProductSession::client_successor(pair.client, previous),
        );
        assert_eq!(host.expect("host successor").stamp(), successor);
        assert_eq!(client.expect("client successor").stamp(), successor);
        assert_eq!(successor.route_epoch, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successor_client_rejects_reused_identity_or_non_monotonic_stream_epochs() {
        let previous = SessionStamp {
            session_id: 80,
            generation: 7,
            authorization_epoch: 8,
            display_epoch: 9,
            codec_epoch: 10,
            route_epoch: 1,
        };
        for invalid in [
            SessionStamp {
                session_id: 80,
                generation: 8,
                authorization_epoch: 9,
                display_epoch: 10,
                codec_epoch: 11,
                route_epoch: 1,
            },
            SessionStamp {
                session_id: 81,
                generation: 8,
                authorization_epoch: 9,
                display_epoch: 9,
                codec_epoch: 11,
                route_epoch: 1,
            },
            SessionStamp {
                session_id: 81,
                generation: 8,
                authorization_epoch: 9,
                display_epoch: 10,
                codec_epoch: 10,
                route_epoch: 1,
            },
        ] {
            let pair = connected_pair(1_450).await;
            let (host, client) = tokio::join!(
                ProductSession::host_with_stamp(pair.server, invalid),
                ProductSession::client_successor(pair.client, previous),
            );
            host.expect("host publishes its invalid successor stamp");
            assert!(matches!(
                client,
                Err(ProductSessionError::PeerProtocol(
                    ProductProtocolViolation::NonMonotonicSuccessor { .. }
                ))
            ));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_endpoint_accepts_a_fresh_product_session_after_clean_close() {
        let pair = connected_pair(1_450).await;
        let server_endpoint = pair._server_endpoint;
        let client_endpoint = pair._client_endpoint;
        let server_address = server_endpoint.local_addr().expect("server address");
        let first_stamp = SessionStamp {
            session_id: 91,
            generation: 1,
            authorization_epoch: 1,
            display_epoch: 1,
            codec_epoch: 1,
            route_epoch: 1,
        };
        let (first_host, first_client) = tokio::join!(
            ProductSession::host_with_stamp(pair.server, first_stamp),
            ProductSession::client(pair.client),
        );
        let first_host = first_host.expect("first host session");
        let first_client = first_client.expect("first client session");
        first_client.close(0, b"first session complete");
        drop(first_client);
        drop(first_host);

        let (server_connection, client_connection) = tokio::join!(
            QuicConnection::accept(&server_endpoint),
            QuicConnection::connect(&client_endpoint, server_address, "localhost"),
        );
        let successor_stamp = SessionStamp {
            session_id: 92,
            generation: 2,
            authorization_epoch: 2,
            display_epoch: 2,
            codec_epoch: 2,
            route_epoch: 1,
        };
        let (successor_host, successor_client) = tokio::join!(
            ProductSession::host_with_stamp(
                server_connection.expect("successor server connection"),
                successor_stamp,
            ),
            ProductSession::client_successor(
                client_connection.expect("successor client connection"),
                first_stamp,
            ),
        );
        assert_eq!(
            successor_host.expect("successor host").stamp(),
            successor_stamp
        );
        assert_eq!(
            successor_client.expect("successor client").stamp(),
            successor_stamp
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn host_handshake_times_out_when_peer_advertises_zero_stream_credit() {
        let pair =
            connected_pair_with_configs(test_configs_with_client_uni_stream_credit(1_450, Some(0)))
                .await;
        let timeout = Duration::from_millis(50);

        assert!(matches!(
            ProductSession::host_with_reassembly_timeout(
                pair.server,
                NonZeroU64::new(42).expect("nonzero"),
                ReassemblyConfig::default(),
                timeout,
            )
            .await,
            Err(ProductSessionError::HandshakeTimedOut { timeout: actual }) if actual == timeout
        ));
        assert!(matches!(
            pair.client.closed().await,
            quinn::ConnectionError::ApplicationClosed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn silent_host_cannot_hold_client_handshake_forever() {
        let pair = connected_pair(1_450).await;
        let timeout = Duration::from_millis(50);

        assert!(matches!(
            ProductSession::client_with_reassembly_timeout(
                pair.client,
                ReassemblyConfig::default(),
                timeout,
            )
            .await,
            Err(ProductSessionError::HandshakeTimedOut { timeout: actual }) if actual == timeout
        ));
        assert!(matches!(
            pair.server.closed().await,
            quinn::ConnectionError::ApplicationClosed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_rejects_noncanonical_handshake_stamp_and_closes() {
        let pair = connected_pair(1_450).await;
        let wrong_stamp = SessionStamp {
            session_id: 41,
            generation: 2,
            authorization_epoch: 1,
            display_epoch: 1,
            codec_epoch: 0,
            route_epoch: 1,
        };
        let record = encode_handshake_completed(wrong_stamp).expect("handshake record");
        pair.server
            .send_control(&record)
            .await
            .expect("send malformed handshake");

        assert!(matches!(
            ProductSession::client(pair.client).await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::InvalidHandshakeStamp(_)
            ))
        ));
        assert!(matches!(
            pair.server.closed().await,
            quinn::ConnectionError::ApplicationClosed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn input_round_trip_uses_its_own_reliable_lane() {
        let (host, client) = product_pair(1_450).await;
        client.send_input(b"pointer delta").await.expect("input");
        let mut receiver = host.accept_input_receiver().await.expect("input receiver");
        assert_eq!(
            receiver.next_input().await.expect("input record").as_ref(),
            b"pointer delta"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_round_trip_continues_the_handshake_lane() {
        let (host, client) = product_pair(1_450).await;

        client
            .send_control(ControlKind::Capabilities, b"h264-high-420")
            .await
            .expect("client capabilities");
        let mut host_control = host
            .accept_control_receiver()
            .await
            .expect("host control receiver");
        let offered = host_control.next_control().await.expect("capabilities");
        assert_eq!(offered.kind, ControlKind::Capabilities);
        assert_eq!(offered.payload.as_ref(), b"h264-high-420");

        host.send_control(ControlKind::ConfigureStream, b"h264-selected")
            .await
            .expect("host configuration");
        let mut client_control = client
            .accept_control_receiver()
            .await
            .expect("client retained control receiver");
        let selected = client_control.next_control().await.expect("configuration");
        assert_eq!(selected.kind, ControlKind::ConfigureStream);
        assert_eq!(selected.payload.as_ref(), b"h264-selected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn explicit_raw_nv12_negotiation_precedes_other_lanes() {
        let (host, client) = product_pair(1_450).await;
        let capabilities = VideoCodecCapabilities {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            flags: video_capability_flags::RAW_NV12,
            max_width: 1_280,
            max_height: 720,
            max_fps: 60,
        };
        client
            .send_control(
                ControlKind::Capabilities,
                &capabilities.encode().expect("capabilities"),
            )
            .await
            .expect("send capabilities first");
        let mut host_control = host
            .accept_control_receiver()
            .await
            .expect("host control receiver");
        let offered = host_control.next_control().await.expect("capabilities");
        let offered = VideoCodecCapabilities::decode(&offered.payload).expect("typed offer");
        assert_eq!(offered.flags, video_capability_flags::RAW_NV12);

        let config = VideoStreamConfig {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            codec: VideoCodec::RawNv12,
            profile: VideoProfile::RawNv12,
            pixel_format: u32::from_le_bytes(*b"NV12"),
            stream_id: 1,
            codec_epoch: host.stamp().codec_epoch,
            width: 1_280,
            height: 720,
            fps: 60,
            target_bitrate_bps: 663_552_000,
            flags: 0,
        };
        host.send_control(
            ControlKind::ConfigureStream,
            &config.encode().expect("configuration"),
        )
        .await
        .expect("send explicit raw configuration");
        let mut client_control = client
            .accept_control_receiver()
            .await
            .expect("retained handshake lane");
        let selected = client_control.next_control().await.expect("configuration");
        assert_eq!(VideoStreamConfig::decode(&selected.payload), Ok(config));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_fragment_media_round_trip_reassembles_exact_frame() {
        let (host, client) = product_pair(1_450).await;
        let frame: Vec<u8> = (0..8_000).map(|index| (index % 251) as u8).collect();
        let report = host
            .send_media_frame(video_spec(7), &frame, Duration::from_millis(250))
            .expect("send frame");
        assert!(report.fragments_sent > 1);
        let received = tokio::time::timeout(Duration::from_secs(2), client.receive_media_frame())
            .await
            .expect("frame arrival")
            .expect("reassemble frame");
        assert_eq!(received.bytes, frame);
        assert_eq!(received.header.frame_id, 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_frame_replay_and_rollback_are_dropped_without_disconnect() {
        for stale_frame_id in [10_u64, 9_u64] {
            let (host, client) = product_pair(1_450).await;
            host.send_media_frame(video_spec(10), &[0xA5; 128], Duration::from_millis(250))
                .expect("initial frame send");
            let initial = client
                .receive_media_frame()
                .await
                .expect("initial frame delivery");
            assert_eq!(initial.header.frame_id, 10);

            host.send_media_frame(
                video_spec(stale_frame_id),
                &[0x5A; 128],
                Duration::from_millis(250),
            )
            .expect("adversarial frame send");
            host.send_media_frame(video_spec(11), &[0x3C; 128], Duration::from_millis(250))
                .expect("new frame send");
            let next = tokio::time::timeout(Duration::from_secs(2), client.receive_media_frame())
                .await
                .expect("receiver must skip stale media")
                .expect("new frame remains deliverable");
            assert_eq!(next.header.frame_id, 11);
            assert!(
                tokio::time::timeout(Duration::from_millis(50), host.connection.closed())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_completion_from_datagram_reordering_is_skipped() {
        let pair = connected_pair(1_450).await;
        let raw_host = pair.server.clone();
        let (host, client) = tokio::join!(
            ProductSession::host(pair.server, NonZeroU64::new(52).expect("nonzero")),
            ProductSession::client(pair.client),
        );
        let host = host.expect("host session");
        let client = client.expect("client session");

        let old_packets = fragment_frame_with_packet_budget(
            video_spec(10),
            &[0xA5; 1_024],
            MEDIA_HEADER_LEN + 256,
        )
        .expect("fragment old frame");
        assert!(old_packets.len() > 1);

        let send_raw = |encoded: &[u8]| {
            let packet = MediaPacket::decode(encoded).expect("inner packet");
            MediaDatagram::encode(host.stamp(), 1, packet.header, packet.payload)
                .expect("outer datagram")
        };
        raw_host
            .send_media(Bytes::from(send_raw(&old_packets[0])), 0, 1)
            .expect("first old fragment");

        host.send_media_frame(video_spec(11), &[0x5A; 128], Duration::from_millis(250))
            .expect("newer complete frame");
        let newer = client
            .receive_media_frame()
            .await
            .expect("newer frame delivery");
        assert_eq!(newer.header.frame_id, 11);

        for packet in &old_packets[1..] {
            raw_host
                .send_media(Bytes::from(send_raw(packet)), 0, 1)
                .expect("late old fragment");
        }
        host.send_media_frame(video_spec(12), &[0xC3; 128], Duration::from_millis(250))
            .expect("latest frame");
        let latest = tokio::time::timeout(Duration::from_secs(2), client.receive_media_frame())
            .await
            .expect("receiver must not stall on late completion")
            .expect("latest frame remains deliverable");
        assert_eq!(latest.header.frame_id, 12);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receiver_does_not_compare_the_senders_absolute_expiry() {
        let pair = connected_pair(1_450).await;
        let raw_host = pair.server.clone();
        let (host, client) = tokio::join!(
            ProductSession::host(pair.server, NonZeroU64::new(51).expect("nonzero")),
            ProductSession::client(pair.client),
        );
        let host = host.expect("host session");
        let client = client.expect("client session");
        let packet =
            fragment_frame_with_packet_budget(video_spec(8), &[0x3C; 128], MEDIA_HEADER_LEN + 128)
                .expect("one inner packet")
                .remove(0);
        let packet = MediaPacket::decode(&packet).expect("inner packet");
        let sender_absolute_expiry = 1;
        let wire = MediaDatagram::encode(
            host.stamp(),
            sender_absolute_expiry,
            packet.header,
            packet.payload,
        )
        .expect("outer datagram");
        assert_eq!(
            raw_host
                .send_media(Bytes::from(wire), 0, sender_absolute_expiry)
                .expect("send media"),
            MediaSendOutcome::Sent
        );

        let received = client
            .receive_media_frame()
            .await
            .expect("receiver-local reassembly");
        assert_eq!(received.bytes, vec![0x3C; 128]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn input_stamp_mismatch_fails_closed() {
        let pair = connected_pair(1_450).await;
        let raw_client = pair.client.clone();
        let (host, client) = tokio::join!(
            ProductSession::host(pair.server, NonZeroU64::new(9).expect("nonzero")),
            ProductSession::client(pair.client),
        );
        let host = host.expect("host session");
        let client = client.expect("client session");
        let wrong_stamp = SessionStamp {
            generation: 2,
            ..client.stamp()
        };
        let record = StreamRecord::encode(StreamKind::Input, wrong_stamp, b"stale")
            .expect("wrong-stamp record");
        raw_client.send_input(&record).await.expect("raw input");

        let mut receiver = host.accept_input_receiver().await.expect("input receiver");
        assert!(matches!(
            receiver.next_input().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::StampMismatch { .. }
            ))
        ));
        assert!(matches!(
            client.connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_route_prepare_prepared_commit_promotes_and_rolls_back() {
        let (host, client) = product_pair(1_450).await;
        let mut client_control = client.accept_control_receiver().await.unwrap();

        let prepare = route_message(RouteTransitionStage::Prepare, 1, 1, [0x11; 32]);
        host.send_route_transition(prepare).await.unwrap();
        assert_eq!(host.stamp().route_epoch, 1);
        assert_eq!(
            client_control.next_route_transition().await.unwrap(),
            prepare
        );
        assert_eq!(client.stamp().route_epoch, 1);

        let prepared = RouteTransitionMessage {
            stage: RouteTransitionStage::Prepared,
            ..prepare
        };
        client.send_route_transition(prepared).await.unwrap();
        let mut host_control = host.accept_control_receiver().await.unwrap();
        assert_eq!(
            host_control.next_route_transition().await.unwrap(),
            prepared
        );
        assert_eq!(host.stamp().route_epoch, 1);

        let commit = RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..prepare
        };
        host.send_route_transition(commit).await.unwrap();
        assert_eq!(host.stamp().route_epoch, 2);
        assert_eq!(
            client_control.next_route_transition().await.unwrap(),
            commit
        );
        assert_eq!(client.stamp().route_epoch, 2);

        // Rollback is another authenticated transition and advances to N+2;
        // the prior route never regains its stale epoch value.
        let rollback_prepare = route_message(RouteTransitionStage::Prepare, 2, 2, [0x22; 32]);
        host.send_route_transition(rollback_prepare).await.unwrap();
        client_control.next_route_transition().await.unwrap();
        let rollback_prepared = RouteTransitionMessage {
            stage: RouteTransitionStage::Prepared,
            ..rollback_prepare
        };
        client
            .send_route_transition(rollback_prepared)
            .await
            .unwrap();
        host_control.next_route_transition().await.unwrap();
        let rollback_commit = RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..rollback_prepare
        };
        host.send_route_transition(rollback_commit).await.unwrap();
        client_control.next_route_transition().await.unwrap();
        assert_eq!(host.stamp().route_epoch, 3);
        assert_eq!(client.stamp().route_epoch, 3);
        let replay = route_message(RouteTransitionStage::Prepare, 2, 3, [0x23; 32]);
        assert!(matches!(
            host.send_route_transition(replay).await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::Sequence {
                    expected: 3,
                    actual: 2
                }
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_exact_mtls_route_set_switches_authority_and_retains_rollback() {
        let (mut host, mut client) = product_route_sets(1_450).await;
        assert_eq!(host.active_index(), 0);
        assert_eq!(client.active_index(), 0);
        let mut client_control = client.accept_control_receiver().await.unwrap();

        let unbound = route_message(RouteTransitionStage::Prepare, 1, 1, [0x32; 32]);
        assert!(matches!(
            host.send_route_transition(unbound).await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::BindingMismatch
            ))
        ));
        assert_eq!(host.active_index(), 0);

        let prepare = bound_route_message(&host, 1, RouteTransitionStage::Prepare, 1, 1);
        host.send_route_transition(prepare).await.unwrap();
        client
            .next_route_transition(&mut client_control)
            .await
            .unwrap();
        let prepared = RouteTransitionMessage {
            stage: RouteTransitionStage::Prepared,
            ..prepare
        };
        client.send_route_transition(prepared).await.unwrap();
        let mut host_control = host.accept_control_receiver().await.unwrap();
        host.next_route_transition(&mut host_control).await.unwrap();
        let commit = RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..prepare
        };
        host.send_route_transition(commit).await.unwrap();
        assert_eq!(host.active_index(), 0);
        client
            .next_route_transition(&mut client_control)
            .await
            .unwrap();
        assert_eq!(client.active_index(), 1);
        let mut host_candidate_control = host.accept_standby_control_receiver().await.unwrap();
        host.next_route_activation(&mut host_candidate_control)
            .await
            .unwrap();
        let mut client_candidate_control = client.accept_control_receiver().await.unwrap();
        client
            .next_route_confirmation(&mut client_candidate_control)
            .await
            .unwrap();
        assert_eq!(host.active_index(), 1);
        assert_eq!(client.active_index(), 1);
        assert_eq!(host.stamp().route_epoch, 2);
        assert_eq!(client.stamp().route_epoch, 2);
        assert!(matches!(
            host.routes[0].send_input(b"old-route").await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute
            ))
        ));

        client.send_input(b"candidate-route").await.unwrap();
        let mut input = host.accept_input_receiver().await.unwrap();
        assert_eq!(input.next_input().await.unwrap(), b"candidate-route"[..]);
        host.send_media_frame(
            video_spec(30),
            b"candidate-media",
            Duration::from_millis(250),
        )
        .unwrap();
        assert_eq!(
            client.receive_media_frame().await.unwrap().bytes,
            b"candidate-media"
        );

        // Roll back over the current route, advancing to epoch 3 and restoring
        // authority exclusively to the retained connection at index 0.
        let rollback = bound_route_message(&host, 0, RouteTransitionStage::Prepare, 2, 2);
        host.send_route_transition(rollback).await.unwrap();
        client
            .next_route_transition(&mut client_candidate_control)
            .await
            .unwrap();
        client
            .send_route_transition(RouteTransitionMessage {
                stage: RouteTransitionStage::Prepared,
                ..rollback
            })
            .await
            .unwrap();
        host.next_route_transition(&mut host_candidate_control)
            .await
            .unwrap();
        host.send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..rollback
        })
        .await
        .unwrap();
        assert_eq!(host.active_index(), 1);
        client
            .next_route_transition(&mut client_candidate_control)
            .await
            .unwrap();
        assert_eq!(client.active_index(), 0);
        host.next_route_activation(&mut host_control).await.unwrap();
        client
            .next_route_confirmation(&mut client_control)
            .await
            .unwrap();
        assert_eq!(host.active_index(), 0);
        assert_eq!(client.active_index(), 0);
        assert_eq!(host.stamp().route_epoch, 3);
        assert_eq!(client.stamp().route_epoch, 3);
        assert!(matches!(
            client.routes[1].send_input(b"stale-candidate").await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_active_candidate_rolls_back_over_the_retained_path() {
        let (mut host, mut client) = product_route_sets(1_450).await;
        let mut client_retained = client.accept_control_receiver().await.unwrap();
        let prepare = bound_route_message(&host, 1, RouteTransitionStage::Prepare, 1, 1);
        host.send_route_transition(prepare).await.unwrap();
        client
            .next_route_transition(&mut client_retained)
            .await
            .unwrap();
        client
            .send_route_transition(RouteTransitionMessage {
                stage: RouteTransitionStage::Prepared,
                ..prepare
            })
            .await
            .unwrap();
        let mut host_retained = host.accept_control_receiver().await.unwrap();
        host.next_route_transition(&mut host_retained)
            .await
            .unwrap();
        host.send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..prepare
        })
        .await
        .unwrap();
        client
            .next_route_transition(&mut client_retained)
            .await
            .unwrap();
        let mut host_candidate = host.accept_standby_control_receiver().await.unwrap();
        host.next_route_activation(&mut host_candidate)
            .await
            .unwrap();
        let mut client_candidate = client.accept_control_receiver().await.unwrap();
        client
            .next_route_confirmation(&mut client_candidate)
            .await
            .unwrap();
        assert_eq!((host.active_index(), client.active_index()), (1, 1));

        let rollback = bound_route_message(&host, 0, RouteTransitionStage::Prepare, 2, 2);
        assert!(matches!(
            host.send_rollback_via_retained(rollback).await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidState
            ))
        ));
        host.routes[1].set_route_authorized(false);
        client.routes[1].set_route_authorized(false);
        host.send_rollback_via_retained(rollback).await.unwrap();
        client
            .next_route_transition(&mut client_retained)
            .await
            .unwrap();
        client
            .send_route_transition(RouteTransitionMessage {
                stage: RouteTransitionStage::Prepared,
                ..rollback
            })
            .await
            .unwrap();
        host.next_route_transition(&mut host_retained)
            .await
            .unwrap();
        host.send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..rollback
        })
        .await
        .unwrap();
        client
            .next_route_transition(&mut client_retained)
            .await
            .unwrap();
        host.next_route_activation(&mut host_retained)
            .await
            .unwrap();
        client
            .next_route_confirmation(&mut client_retained)
            .await
            .unwrap();
        assert_eq!((host.active_index(), client.active_index()), (0, 0));
        assert_eq!(
            (host.stamp().route_epoch, client.stamp().route_epoch),
            (3, 3)
        );
        client.send_input(b"retained-after-failure").await.unwrap();
        let mut input = host.accept_input_receiver().await.unwrap();
        assert_eq!(
            input.next_input().await.unwrap(),
            b"retained-after-failure"[..]
        );
        assert_eq!(
            (
                host.routes[0].stamp().route_epoch,
                host.routes[1].stamp().route_epoch,
            ),
            (3, 3)
        );

        let repromote = bound_route_message(&host, 1, RouteTransitionStage::Prepare, 3, 3);
        host.send_route_transition(repromote).await.unwrap();
        client
            .next_route_transition(&mut client_retained)
            .await
            .unwrap();
        client
            .send_route_transition(RouteTransitionMessage {
                stage: RouteTransitionStage::Prepared,
                ..repromote
            })
            .await
            .unwrap();
        host.next_route_transition(&mut host_retained)
            .await
            .unwrap();
        host.send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..repromote
        })
        .await
        .unwrap();
        client
            .next_route_transition(&mut client_retained)
            .await
            .unwrap();
        host.next_route_activation(&mut host_candidate)
            .await
            .unwrap();
        client
            .next_route_confirmation(&mut client_candidate)
            .await
            .unwrap();
        assert_eq!((host.active_index(), client.active_index()), (1, 1));
        assert_eq!(
            (host.stamp().route_epoch, client.stamp().route_epoch),
            (4, 4)
        );

        host.fail_active_route(0x104, b"injected active path failure");
        client.fail_active_route(0x104, b"injected active path failure");
        let closed_rollback = bound_route_message(&host, 0, RouteTransitionStage::Prepare, 4, 4);
        host.send_rollback_via_retained(closed_rollback)
            .await
            .unwrap();
        client
            .next_route_transition(&mut client_retained)
            .await
            .unwrap();
        client
            .send_route_transition(RouteTransitionMessage {
                stage: RouteTransitionStage::Prepared,
                ..closed_rollback
            })
            .await
            .unwrap();
        host.next_route_transition(&mut host_retained)
            .await
            .unwrap();
        host.send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..closed_rollback
        })
        .await
        .unwrap();
        client
            .next_route_transition(&mut client_retained)
            .await
            .unwrap();
        host.next_route_activation(&mut host_retained)
            .await
            .unwrap();
        client
            .next_route_confirmation(&mut client_retained)
            .await
            .unwrap();
        assert_eq!((host.active_index(), client.active_index()), (0, 0));
        assert_eq!(
            (host.stamp().route_epoch, client.stamp().route_epoch),
            (5, 5)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn route_set_rejects_a_second_connection_to_another_exact_peer() {
        let (same_host, _same_client) = product_pair(1_450).await;
        let same_candidate = UnauthorizedCandidateSession::new(same_host.clone());
        let same_active_binding = route_binding(&same_host, 0x21);
        let same_candidate_binding = candidate_route_binding(&same_candidate, 0x31);
        assert!(matches!(
            ProductRouteSet::new(
                same_host,
                same_active_binding,
                same_candidate,
                same_candidate_binding
            ),
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::DuplicateConnection
            ))
        ));
        let (first_host, _first_client) = product_pair(1_450).await;
        let (second_host, _second_client) = product_pair(1_450).await;
        let foreign_candidate = UnauthorizedCandidateSession::new(second_host);
        let first_binding = route_binding(&first_host, 0x21);
        let foreign_binding = candidate_route_binding(&foreign_candidate, 0x31);
        assert!(matches!(
            ProductRouteSet::new(
                first_host,
                first_binding,
                foreign_candidate,
                foreign_binding
            ),
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::PeerIdentityMismatch
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn route_set_prepare_timeout_revokes_both_connections() {
        let (mut host, _client) = product_route_sets(1_450).await;
        let prepare = bound_route_message(&host, 1, RouteTransitionStage::Prepare, 1, 1);
        host.send_route_transition(prepare).await.unwrap();
        tokio::time::sleep(ROUTE_TRANSITION_TIMEOUT + Duration::from_millis(50)).await;
        assert!(matches!(
            host.send_input(b"after-expiry").await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute
            ))
        ));
        assert!(!host.routes[0].route_authorized.load(Ordering::Acquire));
        assert!(!host.routes[1].route_authorized.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelling_commit_after_wire_write_revokes_the_whole_route_set() {
        let (mut host, mut client) = product_route_sets(1_450).await;
        let mut client_control = client.accept_control_receiver().await.unwrap();
        let prepare = bound_route_message(&host, 1, RouteTransitionStage::Prepare, 1, 1);
        host.send_route_transition(prepare).await.unwrap();
        client
            .next_route_transition(&mut client_control)
            .await
            .unwrap();
        client
            .send_route_transition(RouteTransitionMessage {
                stage: RouteTransitionStage::Prepared,
                ..prepare
            })
            .await
            .unwrap();
        let mut host_control = host.accept_control_receiver().await.unwrap();
        host.next_route_transition(&mut host_control).await.unwrap();

        let hook = Arc::new(IceSendCancellationHook::default());
        host.routes[0].route_send_cancellation_hook = Some(Arc::clone(&hook));
        let retained = [host.routes[0].clone(), host.routes[1].clone()];
        let commit = RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..prepare
        };
        let task = tokio::spawn(async move { host.send_route_transition(commit).await });
        hook.reached.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!retained[0].route_authorized.load(Ordering::Acquire));
        assert!(!retained[1].route_authorized.load(Ordering::Acquire));
        assert!(matches!(
            retained[1].send_input(b"must-not-send").await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InactiveRoute
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelling_commit_receive_after_epoch_update_revokes_both_routes() {
        let (mut host, mut client) = product_route_sets(1_450).await;
        let mut client_control = client.accept_control_receiver().await.unwrap();
        let prepare = bound_route_message(&host, 1, RouteTransitionStage::Prepare, 1, 1);
        host.send_route_transition(prepare).await.unwrap();
        client
            .next_route_transition(&mut client_control)
            .await
            .unwrap();
        client
            .send_route_transition(RouteTransitionMessage {
                stage: RouteTransitionStage::Prepared,
                ..prepare
            })
            .await
            .unwrap();
        let mut host_control = host.accept_control_receiver().await.unwrap();
        host.next_route_transition(&mut host_control).await.unwrap();

        let hook = Arc::new(IceSendCancellationHook::default());
        client_control.receiver.route_receive_cancellation_hook = Some(Arc::clone(&hook));
        let retained = [client.routes[0].clone(), client.routes[1].clone()];
        let receive =
            tokio::spawn(async move { client.next_route_transition(&mut client_control).await });
        host.send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..prepare
        })
        .await
        .unwrap();
        hook.reached.notified().await;
        receive.abort();
        assert!(receive.await.unwrap_err().is_cancelled());
        assert!(!retained[0].route_authorized.load(Ordering::Acquire));
        assert!(!retained[1].route_authorized.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn route_commit_without_prepare_and_generic_route_control_fail_closed() {
        let (host, _client) = product_pair(1_450).await;
        let commit = route_message(RouteTransitionStage::Commit, 1, 1, [0x11; 32]);
        assert!(matches!(
            host.send_route_transition(commit).await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::InvalidState
            ))
        ));
        assert!(matches!(
            host.send_control(ControlKind::RoutePrepare, &commit.encode().unwrap())
                .await,
            Err(ProductSessionError::RouteTransition(
                RouteTransitionViolation::ControlRequiresTypedApi
            ))
        ));
        assert_eq!(host.stamp().route_epoch, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn route_epoch_promotion_and_rollback_update_all_live_product_lanes() {
        let (host, client) = product_pair(1_450).await;
        let mut client_control = client
            .accept_control_receiver()
            .await
            .expect("retained control receiver");

        assert_eq!(host.advance_route_epoch(1, 2).unwrap().route_epoch, 2);
        assert_eq!(client.advance_route_epoch(1, 2).unwrap().route_epoch, 2);
        assert!(matches!(
            host.advance_route_epoch(1, 2),
            Err(ProductSessionError::RouteEpochTransition {
                actual_current: 2,
                ..
            })
        ));

        host.send_control(ControlKind::ConfigureStream, b"epoch-2")
            .await
            .expect("epoch-2 control");
        assert_eq!(
            client_control
                .next_control()
                .await
                .expect("epoch-2 control receive")
                .payload,
            Bytes::from_static(b"epoch-2")
        );
        client.send_input(b"epoch-2-input").await.unwrap();
        let mut host_input = host.accept_input_receiver().await.unwrap();
        assert_eq!(
            host_input.next_input().await.unwrap(),
            Bytes::from_static(b"epoch-2-input")
        );
        host.send_media_frame(video_spec(21), b"epoch-2-media", Duration::from_millis(250))
            .unwrap();
        assert_eq!(
            client.receive_media_frame().await.unwrap().bytes,
            b"epoch-2-media"
        );

        // A failed candidate rolls back by advancing again; epoch values never
        // return to the prior route's number.
        assert_eq!(host.advance_route_epoch(2, 3).unwrap().route_epoch, 3);
        assert_eq!(client.advance_route_epoch(2, 3).unwrap().route_epoch, 3);
        host.send_control(ControlKind::ConfigureStream, b"epoch-3")
            .await
            .expect("epoch-3 control");
        assert_eq!(
            client_control
                .next_control()
                .await
                .expect("epoch-3 control receive")
                .payload,
            Bytes::from_static(b"epoch-3")
        );
        client.send_input(b"epoch-3-input").await.unwrap();
        assert_eq!(
            host_input.next_input().await.unwrap(),
            Bytes::from_static(b"epoch-3-input")
        );
        host.send_media_frame(video_spec(22), b"epoch-3-media", Duration::from_millis(250))
            .unwrap();
        assert_eq!(
            client.receive_media_frame().await.unwrap().bytes,
            b"epoch-3-media"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_route_epoch_is_rejected_before_control_input_or_media_dispatch() {
        // Reliable control.
        let (host, client) = product_pair(1_450).await;
        let old_stamp = host.stamp();
        let mut receiver = client.accept_control_receiver().await.unwrap();
        host.advance_route_epoch(1, 2).unwrap();
        client.advance_route_epoch(1, 2).unwrap();
        let control = ControlPacket::encode(
            ControlHeader {
                kind: ControlKind::ConfigureStream,
                flags: 0,
                session_id: old_stamp.session_id,
                payload_len: 5,
            },
            b"stale",
        )
        .unwrap();
        let record = StreamRecord::encode(StreamKind::Control, old_stamp, &control).unwrap();
        host.connection.send_control(&record).await.unwrap();
        assert!(matches!(
            receiver.next_control().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::StampMismatch { .. }
            ))
        ));

        // Ordered input.
        let (host, client) = product_pair(1_450).await;
        let old_stamp = client.stamp();
        host.advance_route_epoch(1, 2).unwrap();
        client.advance_route_epoch(1, 2).unwrap();
        let record = StreamRecord::encode(StreamKind::Input, old_stamp, b"stale").unwrap();
        client.connection.send_input(&record).await.unwrap();
        let mut receiver = host.accept_input_receiver().await.unwrap();
        assert!(matches!(
            receiver.next_input().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::StampMismatch { .. }
            ))
        ));

        // Media before reassembly.
        let (host, client) = product_pair(1_450).await;
        let old_stamp = host.stamp();
        host.advance_route_epoch(1, 2).unwrap();
        client.advance_route_epoch(1, 2).unwrap();
        let inner =
            fragment_frame_with_packet_budget(video_spec(1), b"stale-media", MEDIA_HEADER_LEN + 64)
                .unwrap()
                .remove(0);
        let inner = MediaPacket::decode(&inner).unwrap();
        let wire =
            MediaDatagram::encode(old_stamp, 1_000_000, inner.header, inner.payload).unwrap();
        host.connection
            .send_media(Bytes::from(wire), 0, 1_000_000)
            .unwrap();
        assert!(matches!(
            client.receive_media_frame().await,
            Err(ProductSessionError::PeerProtocol(
                ProductProtocolViolation::StampMismatch { .. }
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_wire_media_datagram_stays_within_the_observed_path_limit() {
        let pair = connected_pair(1_450).await;
        let raw_client = pair.client.clone();
        let (host, client) = tokio::join!(
            ProductSession::host(pair.server, NonZeroU64::new(71).expect("nonzero")),
            ProductSession::client(pair.client),
        );
        let host = host.expect("host session");
        let _client = client.expect("client session");
        let frame = vec![0xA5; 12_000];
        let report = host
            .send_media_frame(video_spec(11), &frame, Duration::from_millis(250))
            .expect("send frame");

        let mut inner_packets = Vec::new();
        for _ in 0..report.fragments_sent {
            let wire = tokio::time::timeout(Duration::from_secs(1), raw_client.receive_media())
                .await
                .expect("datagram arrival")
                .expect("valid media datagram");
            assert!(wire.len() <= report.path_max_datagram_bytes);
            let outer = MediaDatagram::decode(&wire).expect("outer datagram");
            inner_packets.push(
                MediaPacket::encode(outer.packet.header, outer.packet.payload)
                    .expect("inner packet"),
            );
        }
        assert_eq!(
            inner_packets.iter().map(Vec::len).max().expect("packets") + QUIC_MEDIA_HEADER_LEN,
            report.largest_datagram_bytes
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn minimum_quic_path_mtu_round_trips_a_fragmented_frame() {
        let (host, client) = product_pair(1_200).await;
        let frame = vec![7; 4_000];
        let report = host
            .send_media_frame(video_spec(13), &frame, Duration::from_millis(250))
            .expect("minimum-path frame send");
        assert!(report.fragments_sent > 1);
        let received = tokio::time::timeout(Duration::from_secs(2), client.receive_media_frame())
            .await
            .expect("frame arrival")
            .expect("minimum-path frame reassembly");
        assert_eq!(received.bytes, frame);
    }

    #[test]
    fn path_budget_below_both_headers_and_one_payload_byte_fails() {
        let too_small = QUIC_MEDIA_HEADER_LEN + MEDIA_HEADER_LEN;
        let error = media_packet_budget(too_small).expect_err("one payload byte is required");
        assert!(matches!(
            error,
            ProductSessionError::DatagramBudgetTooSmall { .. }
        ));
        assert_eq!(
            media_packet_budget(too_small + 1).expect("minimum complete datagram"),
            MEDIA_HEADER_LEN + 1
        );
    }

    #[test]
    fn stale_and_conflict_ingest_errors_are_skippable() {
        assert!(is_skippable_ingest_error(
            &TransportError::StaleCodecEpoch {
                packet_epoch: 1,
                current_epoch: 2,
            }
        ));
        assert!(is_skippable_ingest_error(
            &TransportError::MetadataConflict(FrameKey {
                stream_id: 1,
                codec_epoch: 1,
                frame_id: 7,
                kind: MediaKind::Video as u8,
            })
        ));
        assert!(!is_skippable_ingest_error(
            &TransportError::UnsupportedParity
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_fragment_aborts_the_access_unit() {
        let (host, client) = product_pair(1_450).await;
        let frame = vec![0xA5; 8_000];
        let now_ns = host.local_now_ns();
        let error = host
            .send_media_frame_at(
                video_spec(99),
                &frame,
                Duration::from_millis(250),
                now_ns,
                |index| {
                    if index == 0 {
                        now_ns
                    } else {
                        u64::MAX
                    }
                },
            )
            .expect_err("dropped fragment must not report AU success");
        assert!(matches!(
            error,
            ProductSessionError::MediaSendAborted {
                outcome: MediaSendOutcome::DroppedExpired,
                fragments_sent: 1,
                fragments_total,
            } if fragments_total > 1
        ));

        host.send_media_frame(video_spec(100), &[0x11; 64], Duration::from_millis(250))
            .expect("session still sends after abort");
        let received = tokio::time::timeout(Duration::from_secs(2), client.receive_media_frame())
            .await
            .expect("later frame arrival")
            .expect("later frame remains deliverable");
        assert_eq!(received.header.frame_id, 100);
        assert_eq!(received.bytes, vec![0x11; 64]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_and_conflict_ingest_does_not_close_session() {
        let pair = connected_pair(1_450).await;
        let raw_host = pair.server.clone();
        let (host, client) = tokio::join!(
            ProductSession::host(pair.server, NonZeroU64::new(61).expect("nonzero")),
            ProductSession::client(pair.client),
        );
        let host = host.expect("host session");
        let client = client.expect("client session");

        let send_raw = |encoded: &[u8]| {
            let packet = MediaPacket::decode(encoded).expect("inner packet");
            MediaDatagram::encode(host.stamp(), 1_000_000_000, packet.header, packet.payload)
                .expect("outer datagram")
        };

        let conflict_packets = fragment_frame_with_packet_budget(
            video_spec(20),
            &[0x22; 2_048],
            MEDIA_HEADER_LEN + 256,
        )
        .expect("conflict fragments");
        assert!(conflict_packets.len() > 1);
        assert_eq!(
            raw_host
                .send_media(
                    Bytes::from(send_raw(&conflict_packets[0])),
                    0,
                    1_000_000_000
                )
                .expect("partial"),
            MediaSendOutcome::Sent
        );
        let first = MediaPacket::decode(&conflict_packets[0]).expect("decode first");
        let mut conflicting_header = first.header;
        conflicting_header.frame_len = first.header.frame_len.saturating_add(64);
        let conflicting =
            MediaPacket::encode(conflicting_header, first.payload).expect("conflict packet");
        assert_eq!(
            raw_host
                .send_media(Bytes::from(send_raw(&conflicting)), 0, 1_000_000_000)
                .expect("conflict send"),
            MediaSendOutcome::Sent
        );

        host.send_media_frame(video_spec(21), &[0x33; 128], Duration::from_millis(250))
            .expect("valid frame after conflict");
        let received = tokio::time::timeout(Duration::from_secs(2), client.receive_media_frame())
            .await
            .expect("receiver must skip conflict")
            .expect("valid frame remains deliverable");
        assert_eq!(received.header.frame_id, 21);
        assert_eq!(received.bytes, vec![0x33; 128]);

        {
            let mut bumped = video_spec(50);
            bumped.codec_epoch = 2;
            let epoch2 =
                fragment_frame_with_packet_budget(bumped, &[0xAA; 128], MEDIA_HEADER_LEN + 128)
                    .expect("epoch bump packet")
                    .remove(0);
            let mut reassembler = client.reassembler.lock().await;
            assert!(matches!(
                reassembler.ingest(&epoch2, client.local_now_ns()),
                Ok(IngestOutcome::Complete(_))
            ));
            assert_eq!(reassembler.active_codec_epoch(), 2);
        }
        host.send_media_frame(video_spec(22), &[0x44; 64], Duration::from_millis(250))
            .expect("stale-epoch product frame");
        let receive = client.receive_media_frame();
        tokio::pin!(receive);
        let mut stale_seen = false;
        for _ in 0..20 {
            match tokio::time::timeout(Duration::from_millis(25), &mut receive).await {
                Ok(Ok(_)) => panic!("stale codec epoch must not complete a frame"),
                Ok(Err(error)) => panic!("stale codec epoch must not fail the session: {error}"),
                Err(_) => {}
            }
            if client
                .reassembler
                .lock()
                .await
                .stats()
                .stale_epoch_datagrams
                > 0
            {
                stale_seen = true;
                break;
            }
        }
        assert!(
            stale_seen,
            "receive loop must ingest the stale-epoch datagram"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut receive)
                .await
                .is_err(),
            "stale codec epoch must be skipped, not delivered or fatal"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), host.connection.closed())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), client.connection.closed())
                .await
                .is_err()
        );
    }
}
