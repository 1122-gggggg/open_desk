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
    ControlHeader, ControlKind, ControlPacket, HandshakeCompletedMessage, ProtocolError,
    MEDIA_HEADER_LEN,
};
use latencydesk_transport::{
    frame_fragments_with_packet_budget, FragmentSpec, IngestOutcome, ReassembledFrame, Reassembler,
    ReassemblyConfig, TransportError, MAX_DATAGRAM_MTU,
};
use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const ACTIVE_GENERATION: u64 = 1;
const ACTIVE_EPOCH: u32 = 1;
const DEFAULT_PRODUCT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PRODUCT_HANDSHAKE_TIMEOUT_CODE: u32 = 0x102;
const PRODUCT_HANDSHAKE_TIMEOUT_REASON: &[u8] = b"product handshake timed out";
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
    reassembler: Arc<Mutex<Reassembler>>,
    last_delivered_frame_id: Arc<Mutex<Option<u64>>>,
    clock_origin: Instant,
    inbound_control: Arc<Mutex<Option<QuicInboundStream>>>,
}

/// Receiver for the dedicated ordered input lane.
#[derive(Debug)]
pub struct InputReceiver {
    connection: QuicConnection,
    stream: QuicInboundStream,
    expected_stamp: SessionStamp,
}

/// Receiver for the peer's persistent ordered control lane.
#[derive(Debug)]
pub struct ControlReceiver {
    connection: QuicConnection,
    stream: QuicInboundStream,
    expected_stamp: SessionStamp,
}

/// Validated product control message with an owned payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductControlMessage {
    pub kind: ControlKind,
    pub payload: Bytes,
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
    /// The initial control record did not carry the canonical active-v1 stamp.
    InvalidHandshakeStamp(SessionStamp),
    /// The initial control payload was not a handshake-completion record.
    UnexpectedHandshakeKind(ControlKind),
    /// The nested control header was not bound to the outer session stamp.
    ControlSessionMismatch { expected: u64, actual: u64 },
    /// The handshake body was not bound to the outer session stamp.
    HandshakeSessionMismatch { expected: u64, actual: u64 },
    /// The handshake body carried another authorization epoch.
    HandshakeAuthorizationMismatch { expected: u32, actual: u32 },
    /// The post-mTLS handshake used a non-canonical legacy nonce value.
    HandshakeNonceMismatch,
}

/// Product-session construction, framing, and bounded-media failures.
#[derive(Debug)]
pub enum ProductSessionError {
    Quic(QuicTransportError),
    Protocol(ProtocolError),
    Transport(TransportError),
    PeerProtocol(ProductProtocolViolation),
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
        let timeout_connection = connection.clone();
        let operation = async move {
            let session = Self::new(connection, active_stamp(session_id), reassembly)?;
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
            Ok(Self {
                connection,
                stamp,
                reassembler: Arc::new(Mutex::new(reassembler)),
                last_delivered_frame_id: Arc::new(Mutex::new(None)),
                clock_origin: Instant::now(),
                inbound_control: Arc::new(Mutex::new(Some(stream))),
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
    pub const fn stamp(&self) -> SessionStamp {
        self.stamp
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

    /// Writes one typed product message on the persistent reliable control lane.
    pub async fn send_control(
        &self,
        kind: ControlKind,
        payload: &[u8],
    ) -> Result<(), ProductSessionError> {
        let control = ControlPacket::encode(
            ControlHeader {
                kind,
                flags: 0,
                session_id: self.stamp.session_id,
                payload_len: u32::try_from(payload.len())
                    .map_err(|_| ProtocolError::ControlLength(u32::MAX))?,
            },
            payload,
        )?;
        let record = StreamRecord::encode(StreamKind::Control, self.stamp, &control)?;
        self.connection.send_control(&record).await?;
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
        })
    }

    /// Encodes and writes one bounded payload on the independent reliable input
    /// lane.
    pub async fn send_input(&self, payload: &[u8]) -> Result<(), ProductSessionError> {
        let record = StreamRecord::encode(StreamKind::Input, self.stamp, payload)?;
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
        let record = StreamRecord::encode(StreamKind::Input, self.stamp, payload)?;
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
                self.stamp,
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
            {
                let mut reassembler = self.reassembler.lock().await;
                reassembler.expire_due(self.local_now_ns());
            }
            let bytes = self.connection.receive_media().await?;
            let datagram = match MediaDatagram::decode(&bytes) {
                Ok(datagram) => datagram,
                Err(error) => {
                    self.connection.close_for_protocol_violation();
                    return Err(ProductSessionError::Protocol(error));
                }
            };
            if datagram.stamp != self.stamp {
                return fail_peer_protocol(
                    &self.connection,
                    ProductProtocolViolation::StampMismatch {
                        expected: self.stamp,
                        actual: datagram.stamp,
                    },
                );
            }

            // Do not use `datagram.expires_at_ns` here: it belongs to the
            // sender's monotonic clock domain. Reassembler age is local-only.
            let now_ns = self.local_now_ns();
            let outcome = {
                let mut reassembler = self.reassembler.lock().await;
                reassembler.expire_due(now_ns);
                reassembler.ingest(&bytes[QUIC_MEDIA_HEADER_LEN..], now_ns)
            };
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
        Ok(Self {
            connection,
            stamp,
            reassembler: Arc::new(Mutex::new(Reassembler::new(reassembly)?)),
            last_delivered_frame_id: Arc::new(Mutex::new(None)),
            clock_origin: Instant::now(),
            inbound_control: Arc::new(Mutex::new(None)),
        })
    }

    fn local_now_ns(&self) -> u64 {
        u64::try_from(self.clock_origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

impl InputReceiver {
    /// Reads the next input payload and rejects any stamp drift before handing
    /// bytes to the application-specific input decoder.
    pub async fn next_input(&mut self) -> Result<Bytes, ProductSessionError> {
        let record = self
            .stream
            .next_record()
            .await
            .map_err(|error| inbound_error(&self.connection, error))?;
        if record.stamp != self.expected_stamp {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::StampMismatch {
                    expected: self.expected_stamp,
                    actual: record.stamp,
                },
            );
        }
        Ok(record.payload)
    }
}

impl ControlReceiver {
    /// Reads and validates the next typed control message.
    pub async fn next_control(&mut self) -> Result<ProductControlMessage, ProductSessionError> {
        let record = self
            .stream
            .next_record()
            .await
            .map_err(|error| inbound_error(&self.connection, error))?;
        if record.stamp != self.expected_stamp {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::StampMismatch {
                    expected: self.expected_stamp,
                    actual: record.stamp,
                },
            );
        }
        let packet = ControlPacket::decode(&record.payload)?;
        if packet.header.session_id != self.expected_stamp.session_id {
            return fail_peer_protocol(
                &self.connection,
                ProductProtocolViolation::ControlSessionMismatch {
                    expected: self.expected_stamp.session_id,
                    actual: packet.header.session_id,
                },
            );
        }
        Ok(ProductControlMessage {
            kind: packet.header.kind,
            payload: Bytes::copy_from_slice(packet.payload),
        })
    }
}

fn active_stamp(session_id: NonZeroU64) -> SessionStamp {
    SessionStamp {
        session_id: session_id.get(),
        generation: ACTIVE_GENERATION,
        authorization_epoch: ACTIVE_EPOCH,
        display_epoch: ACTIVE_EPOCH,
        codec_epoch: ACTIVE_EPOCH,
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
    let canonical = stamp.session_id != 0
        && stamp.generation == ACTIVE_GENERATION
        && stamp.authorization_epoch == ACTIVE_EPOCH
        && stamp.display_epoch == ACTIVE_EPOCH
        && stamp.codec_epoch == ACTIVE_EPOCH;
    if !canonical {
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
        media_flags, video_capability_flags, MediaKind, MediaPacket, VideoCodec,
        VideoCodecCapabilities, VideoProfile, VideoStreamConfig, VIDEO_CODEC_CONTRACT_VERSION,
    };
    use latencydesk_transport::{fragment_frame_with_packet_budget, FrameKey};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::{Ipv4Addr, SocketAddr};

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_mtls_handshake_activates_the_exact_v1_stamp() {
        let (host, client) = product_pair(1_450).await;
        let expected = SessionStamp {
            session_id: 41,
            generation: 1,
            authorization_epoch: 1,
            display_epoch: 1,
            codec_epoch: 1,
        };
        assert_eq!(host.stamp(), expected);
        assert_eq!(client.stamp(), expected);
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
            codec_epoch: 1,
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
