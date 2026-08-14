//! Quinn-backed authenticated application lanes.
//!
//! QUIC owns encryption, authentication, loss recovery, congestion control,
//! stream ordering, and DATAGRAM path limits. The protocol crate owns the
//! bounded application framing carried by those lanes.

use bytes::Bytes;
use latencydesk_protocol::quic::{
    MediaDatagram, SessionStamp, StreamKind, StreamRecord, StreamRecordHeader,
    STREAM_RECORD_HEADER_LEN,
};
use latencydesk_protocol::ProtocolError;
use rustls::pki_types::CertificateDer;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

const PROTOCOL_VIOLATION_CODE: quinn::VarInt = quinn::VarInt::from_u32(0x100);
const PROTOCOL_VIOLATION_REASON: &[u8] = b"invalid application record";

/// Outcome of an unreliable media submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaSendOutcome {
    /// Quinn accepted the DATAGRAM for transmission.
    Sent,
    /// The deadline elapsed locally, so no network work was performed.
    DroppedExpired,
    /// The current QUIC path cannot carry the complete DATAGRAM.
    DroppedTooLarge,
    /// The negotiated peer or local endpoint does not support DATAGRAMs.
    Unsupported,
}

/// One complete validated record read from a reliable application lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedStreamRecord {
    /// The lane that carried the record.
    pub kind: StreamKind,
    /// Session identity and lifecycle values attached to the record.
    pub stamp: SessionStamp,
    /// The exact bounded application payload.
    pub payload: Bytes,
}

/// Failures surfaced by the QUIC lane adapter.
#[derive(Debug)]
pub enum QuicTransportError {
    /// The endpoint socket could not be created.
    Io(std::io::Error),
    /// A client connection could not be started.
    Connect(quinn::ConnectError),
    /// The QUIC connection or endpoint closed.
    Connection(quinn::ConnectionError),
    /// A reliable stream ended before its declared record body.
    Read(quinn::ReadExactError),
    /// Quinn rejected a reliable stream write.
    Write(quinn::WriteError),
    /// The scheduler deadline disagreed with the authenticated wire record.
    ExpiryMismatch {
        /// Deadline supplied by the caller.
        expected: u64,
        /// Deadline encoded in the media DATAGRAM.
        actual: u64,
    },
    /// A bounded application record was malformed or inconsistent.
    Protocol(ProtocolError),
    /// The endpoint stopped before an incoming connection was accepted.
    EndpointClosed,
    /// Quinn did not expose a TLS peer identity.
    MissingPeerIdentity,
    /// Quinn exposed an identity type other than rustls certificates.
    UnexpectedPeerIdentity,
    /// The peer attempted to open a second instance of an application lane.
    DuplicateInboundLane(StreamKind),
    /// A later record changed the kind assigned to its stream.
    StreamKindChanged {
        /// Kind established by the first record.
        expected: StreamKind,
        /// Kind carried by the invalid later record.
        actual: StreamKind,
    },
}

impl fmt::Display for QuicTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "QUIC endpoint I/O failed: {error}"),
            Self::Connect(error) => write!(formatter, "QUIC connection start failed: {error}"),
            Self::Connection(error) => write!(formatter, "QUIC connection failed: {error}"),
            Self::Read(error) => write!(formatter, "QUIC stream read failed: {error}"),
            Self::Write(error) => write!(formatter, "QUIC stream write failed: {error}"),
            Self::ExpiryMismatch { expected, actual } => {
                write!(
                    formatter,
                    "media expiry mismatch: expected {expected}, record carries {actual}"
                )
            }
            Self::Protocol(error) => write!(formatter, "invalid QUIC application record: {error}"),
            Self::EndpointClosed => formatter.write_str("QUIC endpoint closed before accept"),
            Self::MissingPeerIdentity => formatter.write_str("QUIC peer did not authenticate"),
            Self::UnexpectedPeerIdentity => {
                formatter.write_str("QUIC peer identity was not rustls certificates")
            }
            Self::DuplicateInboundLane(kind) => {
                write!(formatter, "duplicate inbound {kind:?} application lane")
            }
            Self::StreamKindChanged { expected, actual } => {
                write!(
                    formatter,
                    "stream kind changed from {expected:?} to {actual:?}"
                )
            }
        }
    }
}

impl Error for QuicTransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Connect(error) => Some(error),
            Self::Connection(error) => Some(error),
            Self::Read(error) => Some(error),
            Self::Write(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::ExpiryMismatch { .. }
            | Self::EndpointClosed
            | Self::MissingPeerIdentity
            | Self::UnexpectedPeerIdentity
            | Self::DuplicateInboundLane(_)
            | Self::StreamKindChanged { .. } => None,
        }
    }
}

/// A mutually authenticated QUIC connection with one persistent reliable
/// stream per ordered application lane and QUIC DATAGRAM media delivery.
#[derive(Debug, Clone)]
pub struct QuicConnection {
    connection: quinn::Connection,
    outbound: Arc<OutboundLanes>,
    inbound: Arc<InboundLanes>,
}

#[derive(Debug, Default)]
struct OutboundLanes {
    control: Mutex<Option<quinn::SendStream>>,
    input: Mutex<Option<quinn::SendStream>>,
}

#[derive(Debug, Default)]
struct InboundLanes {
    control: Mutex<bool>,
    input: Mutex<bool>,
}

/// A persistent incoming reliable lane.
#[derive(Debug)]
pub struct QuicInboundStream {
    connection: quinn::Connection,
    stream: quinn::RecvStream,
    kind: StreamKind,
    first_record: Option<ReceivedStreamRecord>,
}

impl QuicInboundStream {
    /// The kind established by the first record on this stream.
    pub const fn kind(&self) -> StreamKind {
        self.kind
    }

    /// Reads the next record without allocating until its bounded header has
    /// passed protocol validation.
    pub async fn next_record(&mut self) -> Result<ReceivedStreamRecord, QuicTransportError> {
        if let Some(record) = self.first_record.take() {
            return Ok(record);
        }

        match read_stream_record(&mut self.stream).await {
            Ok(record) if record.kind == self.kind => Ok(record),
            Ok(record) => {
                self.close_for_protocol_violation();
                Err(QuicTransportError::StreamKindChanged {
                    expected: self.kind,
                    actual: record.kind,
                })
            }
            Err(error @ QuicTransportError::Protocol(_)) => {
                self.close_for_protocol_violation();
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn close_for_protocol_violation(&self) {
        self.connection
            .close(PROTOCOL_VIOLATION_CODE, PROTOCOL_VIOLATION_REASON);
    }
}

impl QuicConnection {
    /// Waits for a full TLS 1.3 connection. It deliberately does not expose
    /// Quinn's 0-RTT API, so application records cannot enter early data.
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<Self, QuicTransportError> {
        let connecting = endpoint
            .connect(remote, server_name)
            .map_err(QuicTransportError::Connect)?;
        let connection = connecting.await.map_err(QuicTransportError::Connection)?;
        Ok(Self::from_connection(connection))
    }

    /// Accepts and fully authenticates the next incoming QUIC connection.
    pub async fn accept(endpoint: &quinn::Endpoint) -> Result<Self, QuicTransportError> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or(QuicTransportError::EndpointClosed)?;
        let connecting = incoming.accept().map_err(QuicTransportError::Connection)?;
        let connection = connecting.await.map_err(QuicTransportError::Connection)?;
        Ok(Self::from_connection(connection))
    }

    /// Closes the connection with a caller-selected application error code.
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.connection
            .close(quinn::VarInt::from_u32(error_code), reason);
    }

    /// Waits until Quinn reports the terminal connection condition.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.connection.closed().await
    }

    /// Returns the verified certificate chain Quinn obtained during the TLS
    /// handshake. Server callers receive the client chain only when mutual TLS
    /// is configured by the endpoint.
    pub fn peer_certificate_chain(&self) -> Result<Vec<Vec<u8>>, QuicTransportError> {
        let identity = self
            .connection
            .peer_identity()
            .ok_or(QuicTransportError::MissingPeerIdentity)?;
        let certificates = identity
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| QuicTransportError::UnexpectedPeerIdentity)?;
        Ok(certificates
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect())
    }

    /// Writes a complete control record onto the one persistent ordered control
    /// stream.
    pub async fn send_control(&self, record: &[u8]) -> Result<(), QuicTransportError> {
        self.send_reliable(StreamKind::Control, record).await
    }

    /// Writes a complete input record onto the one persistent ordered input
    /// stream, independent from control head-of-line blocking.
    pub async fn send_input(&self, record: &[u8]) -> Result<(), QuicTransportError> {
        self.send_reliable(StreamKind::Input, record).await
    }

    /// Accepts the next persistent ordered lane. A peer can establish at most
    /// one control lane and one input lane for this connection.
    pub async fn accept_inbound_stream(&self) -> Result<QuicInboundStream, QuicTransportError> {
        let mut stream = self
            .connection
            .accept_uni()
            .await
            .map_err(QuicTransportError::Connection)?;
        let first_record = match read_stream_record(&mut stream).await {
            Ok(record) => record,
            Err(error @ QuicTransportError::Protocol(_)) => {
                self.close_for_protocol_violation();
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        let already_accepted = match first_record.kind {
            StreamKind::Control => {
                let mut admitted = self.inbound.control.lock().await;
                let duplicate = *admitted;
                *admitted = true;
                duplicate
            }
            StreamKind::Input => {
                let mut admitted = self.inbound.input.lock().await;
                let duplicate = *admitted;
                *admitted = true;
                duplicate
            }
        };
        if already_accepted {
            let _ = stream.stop(PROTOCOL_VIOLATION_CODE);
            self.close_for_protocol_violation();
            return Err(QuicTransportError::DuplicateInboundLane(first_record.kind));
        }

        Ok(QuicInboundStream {
            connection: self.connection.clone(),
            stream,
            kind: first_record.kind,
            first_record: Some(first_record),
        })
    }

    /// Validates a complete media DATAGRAM before Quinn accepts it. The
    /// caller's deadline is authoritative for local scheduling, while the
    /// embedded deadline remains part of the authenticated protocol record.
    /// Expired and over-path-MTU media are intentional lossy outcomes;
    /// connection failures remain errors.
    pub fn send_media(
        &self,
        datagram: Bytes,
        now_ns: u64,
        expires_at_ns: u64,
    ) -> Result<MediaSendOutcome, QuicTransportError> {
        let parsed = MediaDatagram::decode(&datagram).map_err(QuicTransportError::Protocol)?;
        if parsed.expires_at_ns != expires_at_ns {
            return Err(QuicTransportError::ExpiryMismatch {
                expected: expires_at_ns,
                actual: parsed.expires_at_ns,
            });
        }
        if expires_at_ns <= now_ns {
            return Ok(MediaSendOutcome::DroppedExpired);
        }

        let Some(max_datagram_size) = self.connection.max_datagram_size() else {
            return Ok(MediaSendOutcome::Unsupported);
        };
        if datagram.len() > max_datagram_size {
            return Ok(MediaSendOutcome::DroppedTooLarge);
        }

        match self.connection.send_datagram(datagram) {
            Ok(()) => Ok(MediaSendOutcome::Sent),
            Err(
                quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled,
            ) => Ok(MediaSendOutcome::Unsupported),
            Err(quinn::SendDatagramError::TooLarge) => Ok(MediaSendOutcome::DroppedTooLarge),
            Err(quinn::SendDatagramError::ConnectionLost(error)) => {
                Err(QuicTransportError::Connection(error))
            }
        }
    }

    /// Receives one complete bounded media DATAGRAM after validating its
    /// protocol framing. Deadline policy belongs to the session scheduler,
    /// whose clock domain owns the supplied expiry value.
    pub async fn receive_media(&self) -> Result<Bytes, QuicTransportError> {
        let datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(QuicTransportError::Connection)?;
        match MediaDatagram::decode(&datagram) {
            Ok(_) => Ok(datagram),
            Err(error) => {
                self.close_for_protocol_violation();
                Err(QuicTransportError::Protocol(error))
            }
        }
    }

    fn from_connection(connection: quinn::Connection) -> Self {
        Self {
            connection,
            outbound: Arc::new(OutboundLanes::default()),
            inbound: Arc::new(InboundLanes::default()),
        }
    }

    async fn send_reliable(
        &self,
        kind: StreamKind,
        record: &[u8],
    ) -> Result<(), QuicTransportError> {
        StreamRecord::decode_for(kind, record).map_err(QuicTransportError::Protocol)?;

        let lane = match kind {
            StreamKind::Control => &self.outbound.control,
            StreamKind::Input => &self.outbound.input,
        };
        let mut stream = lane.lock().await;
        if stream.is_none() {
            *stream = Some(
                self.connection
                    .open_uni()
                    .await
                    .map_err(QuicTransportError::Connection)?,
            );
        }
        stream
            .as_mut()
            .expect("stream assigned before use")
            .write_all(record)
            .await
            .map_err(QuicTransportError::Write)
    }

    fn close_for_protocol_violation(&self) {
        self.connection
            .close(PROTOCOL_VIOLATION_CODE, PROTOCOL_VIOLATION_REASON);
    }
}

/// Binds a server endpoint with the caller's TLS 1.3/mutual-authentication
/// configuration.
pub fn bind_server(
    configuration: quinn::ServerConfig,
    address: SocketAddr,
) -> Result<quinn::Endpoint, QuicTransportError> {
    quinn::Endpoint::server(configuration, address).map_err(QuicTransportError::Io)
}

/// Binds a client endpoint and installs the caller's TLS 1.3 client
/// configuration before any connection attempt.
pub fn bind_client(
    configuration: quinn::ClientConfig,
    address: SocketAddr,
) -> Result<quinn::Endpoint, QuicTransportError> {
    let mut endpoint = quinn::Endpoint::client(address).map_err(QuicTransportError::Io)?;
    endpoint.set_default_client_config(configuration);
    Ok(endpoint)
}

async fn read_stream_record(
    stream: &mut quinn::RecvStream,
) -> Result<ReceivedStreamRecord, QuicTransportError> {
    let mut encoded_header = [0_u8; STREAM_RECORD_HEADER_LEN];
    stream
        .read_exact(&mut encoded_header)
        .await
        .map_err(QuicTransportError::Read)?;
    let header =
        StreamRecordHeader::decode(&encoded_header).map_err(QuicTransportError::Protocol)?;
    let mut payload = vec![0_u8; header.payload_len as usize];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(QuicTransportError::Read)?;
    Ok(ReceivedStreamRecord {
        kind: header.kind,
        stamp: header.stamp,
        payload: Bytes::from(payload),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use latencydesk_protocol::quic::{MediaDatagram, SessionStamp, StreamKind, StreamRecord};
    use latencydesk_protocol::{
        media_flags, MediaHeader, MediaKind, MediaPacket, ProtocolError, NO_DEPENDENCY,
    };
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    struct TestIdentity {
        certificate: CertificateDer<'static>,
        private_key: PrivateKeyDer<'static>,
    }

    struct ConnectedPair {
        client: QuicConnection,
        server: QuicConnection,
        _client_endpoint: quinn::Endpoint,
        _server_endpoint: quinn::Endpoint,
        server_certificate: Vec<u8>,
        client_certificate: Vec<u8>,
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

    fn test_configs() -> (quinn::ServerConfig, quinn::ClientConfig, Vec<u8>, Vec<u8>) {
        let server_identity = test_identity("localhost");
        let client_identity = test_identity("latencydesk-client");
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
        server.transport = Arc::new(test_transport_config());
        let mut client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_crypto))
                .expect("QUIC client crypto"),
        ));
        client.transport_config(Arc::new(test_transport_config()));
        (server, client, server_certificate, client_certificate)
    }

    fn test_transport_config() -> quinn::TransportConfig {
        let mut config = quinn::TransportConfig::default();
        config
            .initial_mtu(1_200)
            .min_mtu(1_200)
            .mtu_discovery_config(None)
            .datagram_receive_buffer_size(Some(64 * 1024))
            .datagram_send_buffer_size(64 * 1024);
        config
    }

    async fn connected_pair() -> ConnectedPair {
        let (server_config, client_config, server_certificate, client_certificate) = test_configs();
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
            server_certificate,
            client_certificate,
        }
    }

    fn active_stamp() -> SessionStamp {
        SessionStamp {
            session_id: 9,
            generation: 2,
            authorization_epoch: 3,
            display_epoch: 4,
            codec_epoch: 5,
        }
    }

    fn media_datagram(payload_len: usize, expires_at_ns: u64) -> Bytes {
        let payload = vec![7_u8; payload_len];
        let header = MediaHeader {
            kind: MediaKind::Video,
            flags: media_flags::KEYFRAME,
            stream_id: 1,
            codec_epoch: active_stamp().codec_epoch,
            frame_id: 1,
            dependency_frame_id: NO_DEPENDENCY,
            frame_len: payload_len as u32,
            fragment_offset: 0,
            fragment_len: payload_len as u16,
        };
        Bytes::from(
            MediaDatagram::encode(active_stamp(), expires_at_ns, header, &payload)
                .expect("media datagram"),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mutual_tls_exposes_authenticated_peer_certificates() {
        let pair = connected_pair().await;

        assert_eq!(
            pair.client
                .peer_certificate_chain()
                .expect("server identity")[0],
            pair.server_certificate
        );
        assert_eq!(
            pair.server
                .peer_certificate_chain()
                .expect("client identity")[0],
            pair.client_certificate
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_tls_authentication_never_returns_an_application_connection() {
        let (server_config, client_config, _, _) = test_configs();
        let server_endpoint =
            bind_server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("server endpoint");
        let client_endpoint =
            bind_client(client_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("client endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");

        let (server, client) = tokio::join!(
            QuicConnection::accept(&server_endpoint),
            QuicConnection::connect(&client_endpoint, server_address, "untrusted.local"),
        );

        assert!(matches!(client, Err(QuicTransportError::Connection(_))));
        assert!(matches!(server, Err(QuicTransportError::Connection(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_application_close_is_observable_without_a_transport_retry() {
        let pair = connected_pair().await;
        pair.server.close(42, b"test close");

        assert!(matches!(
            pair.client.closed().await,
            quinn::ConnectionError::ApplicationClosed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_and_input_keep_independent_ordered_streams() {
        let pair = connected_pair().await;
        let control_first = StreamRecord::encode(StreamKind::Control, active_stamp(), b"control-1")
            .expect("first control record");
        let control_second =
            StreamRecord::encode(StreamKind::Control, active_stamp(), b"control-2")
                .expect("second control record");
        let input_first = StreamRecord::encode(StreamKind::Input, active_stamp(), b"input-1")
            .expect("first input record");
        let input_second = StreamRecord::encode(StreamKind::Input, active_stamp(), b"input-2")
            .expect("second input record");

        pair.client
            .send_control(&control_first)
            .await
            .expect("send first control");
        pair.client
            .send_input(&input_first)
            .await
            .expect("send first input");
        pair.client
            .send_control(&control_second)
            .await
            .expect("send second control");
        pair.client
            .send_input(&input_second)
            .await
            .expect("send second input");

        let first = pair
            .server
            .accept_inbound_stream()
            .await
            .expect("first lane");
        let second = pair
            .server
            .accept_inbound_stream()
            .await
            .expect("second lane");
        let (mut control, mut input) = match (first.kind(), second.kind()) {
            (StreamKind::Control, StreamKind::Input) => (first, second),
            (StreamKind::Input, StreamKind::Control) => (second, first),
            kinds => panic!("expected one control and one input lane, got {kinds:?}"),
        };

        assert_eq!(
            control
                .next_record()
                .await
                .expect("first control")
                .payload
                .as_ref(),
            b"control-1"
        );
        assert_eq!(
            input
                .next_record()
                .await
                .expect("first input")
                .payload
                .as_ref(),
            b"input-1"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), control.next_record())
                .await
                .expect("second control arrived")
                .expect("second control")
                .payload
                .as_ref(),
            b"control-2"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), input.next_record())
                .await
                .expect("second input arrived")
                .expect("second input")
                .payload
                .as_ref(),
            b"input-2"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_media_is_dropped_without_blocking_control() {
        let pair = connected_pair().await;
        assert_eq!(
            pair.client
                .send_media(media_datagram(4, 100), 100, 100)
                .expect("drop expired media"),
            MediaSendOutcome::DroppedExpired
        );

        assert!(matches!(
            pair.client.send_media(media_datagram(4, 100), 1, 101),
            Err(QuicTransportError::ExpiryMismatch {
                expected: 101,
                actual: 100,
            })
        ));

        let control = StreamRecord::encode(StreamKind::Control, active_stamp(), b"still-live")
            .expect("control record");
        pair.client
            .send_control(&control)
            .await
            .expect("send control");
        let mut inbound = pair
            .server
            .accept_inbound_stream()
            .await
            .expect("control lane");
        assert_eq!(
            inbound
                .next_record()
                .await
                .expect("control record")
                .payload
                .as_ref(),
            b"still-live"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn valid_media_datagram_reaches_the_media_lane() {
        let pair = connected_pair().await;
        let datagram = media_datagram(4, 1_000);

        assert_eq!(
            pair.client
                .send_media(datagram.clone(), 1, 1_000)
                .expect("send media"),
            MediaSendOutcome::Sent
        );
        assert_eq!(
            pair.server.receive_media().await.expect("receive media"),
            datagram
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_authenticated_media_closes_the_connection() {
        let pair = connected_pair().await;
        pair.client
            .connection
            .send_datagram(Bytes::from_static(b"malformed"))
            .expect("send authenticated datagram");

        assert!(matches!(
            pair.server.receive_media().await,
            Err(QuicTransportError::Protocol(
                ProtocolError::Truncated { .. }
            ))
        ));
        assert!(matches!(
            pair.client.closed().await,
            quinn::ConnectionError::ApplicationClosed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversize_media_is_dropped_before_quinn_buffers_it() {
        let pair = connected_pair().await;
        assert_eq!(
            pair.client
                .send_media(media_datagram(16_000, 10_000), 1, 10_000)
                .expect("oversize media outcome"),
            MediaSendOutcome::DroppedTooLarge
        );
    }

    #[test]
    fn media_builder_preserves_inner_protocol_validation() {
        let bad = MediaHeader {
            kind: MediaKind::Video,
            flags: 0,
            stream_id: 1,
            codec_epoch: active_stamp().codec_epoch,
            frame_id: 2,
            dependency_frame_id: 2,
            frame_len: 1,
            fragment_offset: 0,
            fragment_len: 1,
        };
        assert!(matches!(
            MediaDatagram::encode(active_stamp(), 10, bad, b"x"),
            Err(ProtocolError::InvalidDependency { .. })
        ));
        assert_eq!(
            MediaPacket::decode(&[]),
            Err(ProtocolError::Truncated {
                expected: latencydesk_protocol::MEDIA_HEADER_LEN,
                actual: 0,
            })
        );
    }
}
