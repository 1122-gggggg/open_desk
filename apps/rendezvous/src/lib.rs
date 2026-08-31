//! Bounded mTLS rendezvous service and client exchange.
//!
//! TLS supplies the caller's exact certificate fingerprint. Registration
//! payloads never name their sender, and the service transports only bounded
//! ICE metadata—not desktop, input, media, or relay payloads.

use latencydesk_protocol::quic::{SessionStamp, StreamKind, StreamRecord};
use latencydesk_protocol::{ProtocolError, RendezvousRegistration, RendezvousRole};
use latencydesk_rendezvous::{
    DeviceId, RegisterOutcome, RendezvousBroker, RendezvousDelivery, RendezvousError,
    RendezvousLimits,
};
use latencydesk_socket_transport::identity::{
    accept_allowed_exact_peer_with_timeout, IdentityError,
};
use latencydesk_socket_transport::quic::{QuicConnection, QuicTransportError};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const MAX_FRAME: usize = 4 * 1024;
pub const MAX_REJECTIONS: usize = 16;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(3);
const RENDEZVOUS_ERROR_CODE: u32 = 0x130;
const RESPONSE_HEADER_LEN: usize = 48;
const RESPONSE_WAITING: u8 = 1;
const RESPONSE_DELIVERY: u8 = 2;

pub const RENDEZVOUS_STAMP: SessionStamp = SessionStamp {
    session_id: 1,
    generation: 1,
    authorization_epoch: 1,
    display_epoch: 1,
    codec_epoch: 1,
};

#[derive(Debug)]
pub enum WireError {
    Oversize,
    Truncated,
    InvalidResponse,
    Protocol(ProtocolError),
    Broker(RendezvousError),
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for WireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Broker(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ProtocolError> for WireError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<RendezvousError> for WireError {
    fn from(error: RendezvousError) -> Self {
        Self::Broker(error)
    }
}

#[derive(Debug)]
pub enum ServiceError {
    InvalidConfig,
    Timeout,
    RejectionLimit,
    Unmatched,
    Identity(IdentityError),
    Quic(QuicTransportError),
    Wire(WireError),
    Broker(RendezvousError),
    Protocol(ProtocolError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::Quic(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Broker(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<IdentityError> for ServiceError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<QuicTransportError> for ServiceError {
    fn from(error: QuicTransportError) -> Self {
        Self::Quic(error)
    }
}

impl From<WireError> for ServiceError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<RendezvousError> for ServiceError {
    fn from(error: RendezvousError) -> Self {
        Self::Broker(error)
    }
}

impl From<ProtocolError> for ServiceError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

pub enum RendezvousResponse {
    Waiting { ttl_seconds: u64 },
    Delivery(RendezvousDelivery),
}

impl fmt::Debug for RendezvousResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Waiting { ttl_seconds } => formatter
                .debug_struct("Waiting")
                .field("ttl_seconds", ttl_seconds)
                .finish(),
            Self::Delivery(delivery) => formatter
                .debug_struct("Delivery")
                .field("peer", &delivery.peer)
                .field("registration", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerReport {
    pub registrations: usize,
    pub matched: usize,
    pub rejected: usize,
}

fn record_rejection(report: &mut ServerReport) -> Result<(), ServiceError> {
    report.rejected = report
        .rejected
        .checked_add(1)
        .ok_or(ServiceError::RejectionLimit)?;
    if report.rejected >= MAX_REJECTIONS {
        return Err(ServiceError::RejectionLimit);
    }
    Ok(())
}

struct FailClosedConnection<'a> {
    connection: &'a QuicConnection,
    armed: bool,
}

impl<'a> FailClosedConnection<'a> {
    fn new(connection: &'a QuicConnection) -> Self {
        Self {
            connection,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FailClosedConnection<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.connection.close(
                RENDEZVOUS_ERROR_CODE,
                b"rendezvous exchange cancelled or failed",
            );
        }
    }
}

/// One length-prefixed secret-bearing registration request.
pub fn encode_request(
    registration: &RendezvousRegistration,
) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let payload = registration.encode()?;
    if payload.len() > MAX_FRAME {
        return Err(WireError::Oversize);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_request(frame: &[u8]) -> Result<RendezvousRegistration, WireError> {
    if frame.len() < 4 {
        return Err(WireError::Truncated);
    }
    let len = u32::from_be_bytes(frame[..4].try_into().expect("four-byte prefix")) as usize;
    if len > MAX_FRAME {
        return Err(WireError::Oversize);
    }
    if frame.len() != 4 + len {
        return Err(WireError::Truncated);
    }
    Ok(RendezvousRegistration::decode(&frame[4..])?)
}

pub fn encode_response(response: &RendezvousResponse) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let mut out = Zeroizing::new(Vec::with_capacity(RESPONSE_HEADER_LEN + MAX_FRAME));
    match response {
        RendezvousResponse::Waiting { ttl_seconds } => {
            out.push(RESPONSE_WAITING);
            out.extend_from_slice(&[0; 3]);
            out.extend_from_slice(&ttl_seconds.to_be_bytes());
            out.extend_from_slice(&[0; 32]);
            out.extend_from_slice(&0_u32.to_be_bytes());
        }
        RendezvousResponse::Delivery(delivery) => {
            let registration = delivery.registration.encode()?;
            if registration.len() > MAX_FRAME {
                return Err(WireError::Oversize);
            }
            out.push(RESPONSE_DELIVERY);
            out.extend_from_slice(&[0; 3]);
            out.extend_from_slice(&0_u64.to_be_bytes());
            out.extend_from_slice(&delivery.peer.into_bytes());
            out.extend_from_slice(&(registration.len() as u32).to_be_bytes());
            out.extend_from_slice(&registration);
        }
    }
    Ok(out)
}

pub fn decode_response(bytes: &[u8]) -> Result<RendezvousResponse, WireError> {
    if bytes.len() < RESPONSE_HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if bytes[1..4] != [0; 3] {
        return Err(WireError::InvalidResponse);
    }
    let value = u64::from_be_bytes(bytes[4..12].try_into().expect("eight-byte value"));
    let mut peer = [0_u8; 32];
    peer.copy_from_slice(&bytes[12..44]);
    let registration_len =
        u32::from_be_bytes(bytes[44..48].try_into().expect("four-byte length")) as usize;
    let expected = RESPONSE_HEADER_LEN
        .checked_add(registration_len)
        .ok_or(WireError::Oversize)?;
    if registration_len > MAX_FRAME || bytes.len() != expected {
        return Err(WireError::Oversize);
    }
    match bytes[0] {
        RESPONSE_WAITING if value > 0 && peer == [0; 32] && registration_len == 0 => {
            Ok(RendezvousResponse::Waiting { ttl_seconds: value })
        }
        RESPONSE_DELIVERY if value == 0 && peer != [0; 32] && registration_len > 0 => {
            Ok(RendezvousResponse::Delivery(RendezvousDelivery {
                peer: DeviceId::new(peer)?,
                registration: RendezvousRegistration::decode(&bytes[RESPONSE_HEADER_LEN..])?,
            }))
        }
        _ => Err(WireError::InvalidResponse),
    }
}

/// Dispatches one request on one authenticated connection.
pub fn dispatch_once(
    broker: &mut RendezvousBroker,
    authenticated_device: DeviceId,
    frame: &[u8],
    now: u64,
) -> Result<RegisterOutcome, WireError> {
    let registration = decode_request(frame)?;
    Ok(broker.register(authenticated_device, registration, now)?)
}

/// Runs one bounded service lifecycle until one reciprocal pair receives
/// one-shot deliveries. Invalid or unauthenticated attempts are rejected
/// without terminating the listener before the fixed rejection cap.
pub async fn serve_one_match(
    endpoint: &quinn::Endpoint,
    allowed_client_certificates: &[Vec<u8>],
    total_timeout: Duration,
) -> Result<ServerReport, ServiceError> {
    if total_timeout.is_zero() {
        return Err(ServiceError::InvalidConfig);
    }
    let deadline = tokio::time::Instant::now() + total_timeout;
    let started = Instant::now();
    let mut broker = RendezvousBroker::new(RendezvousLimits::default())?;
    let mut waiting_connections: HashMap<(DeviceId, [u8; 16]), QuicConnection> = HashMap::new();
    let mut report = ServerReport {
        registrations: 0,
        matched: 0,
        rejected: 0,
    };

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ServiceError::Timeout);
        }
        let accepted = tokio::time::timeout(
            remaining,
            accept_allowed_exact_peer_with_timeout(
                endpoint,
                allowed_client_certificates,
                HANDSHAKE_TIMEOUT.min(remaining),
            ),
        )
        .await;
        let peer = match accepted {
            Ok(Ok(peer)) => peer,
            Ok(Err(_)) => {
                record_rejection(&mut report)?;
                continue;
            }
            Err(_) => return Err(ServiceError::Timeout),
        };
        let device = DeviceId::new(peer.peer_fingerprint)?;
        let operation_deadline = (tokio::time::Instant::now() + OPERATION_TIMEOUT).min(deadline);
        if operation_deadline <= tokio::time::Instant::now() {
            return Err(ServiceError::Timeout);
        }
        let request = receive_request(&peer.connection, operation_deadline).await;
        let registration = match request {
            Ok(registration) => registration,
            Err(_) => {
                peer.connection
                    .close(RENDEZVOUS_ERROR_CODE, b"invalid rendezvous request");
                record_rejection(&mut report)?;
                continue;
            }
        };
        let match_id = registration.match_id;
        let now = started.elapsed().as_secs();
        match broker.register(device, registration, now) {
            Ok(RegisterOutcome::Waiting { expires_at }) => {
                send_response(
                    &peer.connection,
                    &RendezvousResponse::Waiting {
                        ttl_seconds: expires_at.saturating_sub(now).max(1),
                    },
                    operation_deadline,
                )
                .await?;
                waiting_connections.insert((device, match_id), peer.connection);
                report.registrations += 1;
                if report.registrations >= 2 {
                    return Err(ServiceError::Unmatched);
                }
            }
            Ok(RegisterOutcome::Matched(caller_delivery)) => {
                let waiting_device = caller_delivery.peer;
                let waiting_delivery = broker.take_delivery(waiting_device, match_id, now)?;
                let waiting_connection = waiting_connections
                    .remove(&(waiting_device, match_id))
                    .ok_or(ServiceError::Unmatched)?;
                send_response(
                    &peer.connection,
                    &RendezvousResponse::Delivery(caller_delivery),
                    operation_deadline,
                )
                .await?;
                send_response(
                    &waiting_connection,
                    &RendezvousResponse::Delivery(waiting_delivery),
                    operation_deadline,
                )
                .await?;
                report.registrations += 1;
                report.matched = 1;
                wait_for_client_close(&peer.connection, deadline).await;
                wait_for_client_close(&waiting_connection, deadline).await;
                return Ok(report);
            }
            Err(_) => {
                peer.connection
                    .close(RENDEZVOUS_ERROR_CODE, b"rendezvous registration rejected");
                record_rejection(&mut report)?;
            }
        }
    }
}

async fn receive_request(
    connection: &QuicConnection,
    deadline: tokio::time::Instant,
) -> Result<RendezvousRegistration, ServiceError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut lane = tokio::time::timeout(remaining, connection.accept_inbound_stream())
        .await
        .map_err(|_| ServiceError::Timeout)??;
    if lane.kind() != StreamKind::Control {
        return Err(ServiceError::Wire(WireError::InvalidResponse));
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let record = tokio::time::timeout(remaining, lane.next_record())
        .await
        .map_err(|_| ServiceError::Timeout)??;
    if record.stamp != RENDEZVOUS_STAMP {
        return Err(ServiceError::Wire(WireError::InvalidResponse));
    }
    Ok(decode_request(&record.payload)?)
}

async fn send_response(
    connection: &QuicConnection,
    response: &RendezvousResponse,
    deadline: tokio::time::Instant,
) -> Result<(), ServiceError> {
    let payload = encode_response(response)?;
    let record = Zeroizing::new(StreamRecord::encode(
        StreamKind::Control,
        RENDEZVOUS_STAMP,
        &payload,
    )?);
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(ServiceError::Timeout);
    }
    tokio::time::timeout(remaining, connection.send_control(&record))
        .await
        .map_err(|_| ServiceError::Timeout)??;
    Ok(())
}

async fn wait_for_client_close(connection: &QuicConnection, deadline: tokio::time::Instant) {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if tokio::time::timeout(remaining.min(Duration::from_secs(1)), connection.closed())
        .await
        .is_err()
    {
        connection.close(0, b"rendezvous delivery complete");
    }
}

/// Sends one registration and waits for the reciprocal peer's one-shot
/// delivery. The connection is closed after the delivery is validated.
pub async fn exchange_registration(
    connection: QuicConnection,
    self_device: DeviceId,
    registration: RendezvousRegistration,
    total_timeout: Duration,
) -> Result<RendezvousDelivery, ServiceError> {
    let mut fail_closed = FailClosedConnection::new(&connection);
    if total_timeout.is_zero() {
        return Err(ServiceError::InvalidConfig);
    }
    let deadline = tokio::time::Instant::now() + total_timeout;
    let expected_peer = registration.expected_peer_fingerprint;
    let expected_role = registration.role;
    let expected_match = registration.match_id;
    let expected_generation = registration.generation;
    let expected_exchange = registration.credentials.exchange_id;
    let request = encode_request(&registration)?;
    let record = Zeroizing::new(StreamRecord::encode(
        StreamKind::Control,
        RENDEZVOUS_STAMP,
        &request,
    )?);
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    tokio::time::timeout(remaining, connection.send_control(&record))
        .await
        .map_err(|_| ServiceError::Timeout)??;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut lane = tokio::time::timeout(remaining, connection.accept_inbound_stream())
        .await
        .map_err(|_| ServiceError::Timeout)??;
    if lane.kind() != StreamKind::Control {
        connection.close(RENDEZVOUS_ERROR_CODE, b"wrong rendezvous response lane");
        return Err(ServiceError::Wire(WireError::InvalidResponse));
    }
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            connection.close(RENDEZVOUS_ERROR_CODE, b"rendezvous response timeout");
            return Err(ServiceError::Timeout);
        }
        let record = tokio::time::timeout(remaining, lane.next_record())
            .await
            .map_err(|_| ServiceError::Timeout)??;
        if record.stamp != RENDEZVOUS_STAMP {
            connection.close(RENDEZVOUS_ERROR_CODE, b"rendezvous stamp mismatch");
            return Err(ServiceError::Wire(WireError::InvalidResponse));
        }
        match decode_response(&record.payload)? {
            RendezvousResponse::Waiting { .. } => continue,
            RendezvousResponse::Delivery(delivery) => {
                let peer = &delivery.registration;
                let roles_complementary = matches!(
                    (expected_role, peer.role),
                    (RendezvousRole::Initiator, RendezvousRole::Responder)
                        | (RendezvousRole::Responder, RendezvousRole::Initiator)
                );
                if delivery.peer.into_bytes() != expected_peer
                    || peer.expected_peer_fingerprint != self_device.into_bytes()
                    || peer.match_id != expected_match
                    || peer.generation != expected_generation
                    || peer.credentials.exchange_id != expected_exchange
                    || !roles_complementary
                {
                    connection.close(RENDEZVOUS_ERROR_CODE, b"rendezvous delivery mismatch");
                    return Err(ServiceError::Wire(WireError::InvalidResponse));
                }
                connection.close(0, b"rendezvous delivery accepted");
                fail_closed.disarm();
                return Ok(delivery);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_protocol::{
        CandidateExchange, CandidateType, IceCandidate, IceCredentialExchange, IceCredentialRole,
        RelayProvider, TransportProtocol, WireIpAddr,
    };
    use latencydesk_socket_transport::identity::{
        certificate_fingerprint, mtls_client_config, mtls_server_config_for_exact_clients,
        TlsIdentity,
    };
    use latencydesk_socket_transport::quic::{bind_client, bind_server};
    use std::net::{Ipv4Addr, SocketAddr};

    fn registration(role: RendezvousRole, expected: DeviceId, port: u16) -> RendezvousRegistration {
        RendezvousRegistration {
            version: RendezvousRegistration::VERSION,
            role,
            generation: 1,
            ttl_seconds: 30,
            match_id: [9; 16],
            expected_peer_fingerprint: expected.into_bytes(),
            credentials: IceCredentialExchange::new(
                1,
                7,
                1,
                if role == RendezvousRole::Initiator {
                    IceCredentialRole::Controlling
                } else {
                    IceCredentialRole::Controlled
                },
                format!("rendezvous{port}"),
                "R".repeat(32),
            )
            .unwrap(),
            candidates: CandidateExchange {
                version: CandidateExchange::VERSION,
                exchange_id: 7,
                generation: 1,
                candidates: vec![IceCandidate {
                    foundation: [1; 8],
                    component: 1,
                    transport: TransportProtocol::Udp,
                    priority: 1,
                    candidate_type: CandidateType::Host,
                    relay_provider: RelayProvider::None,
                    ip: WireIpAddr::V4([127, 0, 0, 1]),
                    port,
                    related_address: None,
                }],
            },
        }
    }

    #[test]
    fn framing_rejects_oversize_trailing_and_invalid_response() {
        assert!(matches!(
            decode_request(&[0, 0, 0, 1]),
            Err(WireError::Truncated)
        ));
        let mut frame = vec![0, 0, 0x10, 0x01];
        frame.resize(4 + 0x1001, 0);
        assert!(matches!(decode_request(&frame), Err(WireError::Oversize)));
        assert!(matches!(
            decode_response(&[0; RESPONSE_HEADER_LEN]),
            Err(WireError::InvalidResponse)
        ));
    }

    #[test]
    fn rejection_attempt_cap_is_exact() {
        let mut report = ServerReport {
            registrations: 0,
            matched: 0,
            rejected: 0,
        };
        for expected in 1..MAX_REJECTIONS {
            record_rejection(&mut report).unwrap();
            assert_eq!(report.rejected, expected);
        }
        assert!(matches!(
            record_rejection(&mut report),
            Err(ServiceError::RejectionLimit)
        ));
        assert_eq!(report.rejected, MAX_REJECTIONS);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_exact_clients_receive_reciprocal_registrations() {
        let server_identity = TlsIdentity::generate("Rendezvous Server").unwrap();
        let client_a = TlsIdentity::generate("Rendezvous Client A").unwrap();
        let client_b = TlsIdentity::generate("Rendezvous Client B").unwrap();
        let allowed = vec![
            client_a.certificate_der().to_vec(),
            client_b.certificate_der().to_vec(),
        ];
        let server_endpoint = bind_server(
            mtls_server_config_for_exact_clients(&server_identity, &allowed).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let address = server_endpoint.local_addr().unwrap();
        let endpoint_a = bind_client(
            mtls_client_config(&client_a, server_identity.certificate_der()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let endpoint_b = bind_client(
            mtls_client_config(&client_b, server_identity.certificate_der()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let device_a = DeviceId::new(certificate_fingerprint(client_a.certificate_der())).unwrap();
        let device_b = DeviceId::new(certificate_fingerprint(client_b.certificate_der())).unwrap();

        let (server, clients) = tokio::join!(
            serve_one_match(&server_endpoint, &allowed, Duration::from_secs(5)),
            async {
                tokio::join!(
                    async {
                        let connection =
                            latencydesk_socket_transport::identity::connect_exact_peer(
                                &endpoint_a,
                                address,
                                server_identity.certificate_der(),
                            )
                            .await
                            .unwrap();
                        exchange_registration(
                            connection,
                            device_a,
                            registration(RendezvousRole::Initiator, device_b, 5001),
                            Duration::from_secs(5),
                        )
                        .await
                    },
                    async {
                        let connection =
                            latencydesk_socket_transport::identity::connect_exact_peer(
                                &endpoint_b,
                                address,
                                server_identity.certificate_der(),
                            )
                            .await
                            .unwrap();
                        exchange_registration(
                            connection,
                            device_b,
                            registration(RendezvousRole::Responder, device_a, 5002),
                            Duration::from_secs(5),
                        )
                        .await
                    },
                )
            },
        );
        let report = server.unwrap();
        let (delivery_a, delivery_b) = clients;
        assert_eq!(report.registrations, 2);
        assert_eq!(report.matched, 1);
        assert_eq!(delivery_a.unwrap().peer, device_b);
        assert_eq!(delivery_b.unwrap().peer, device_a);
        server_endpoint.close(0_u32.into(), b"test complete");
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        server_endpoint.wait_idle().await;
        endpoint_a.wait_idle().await;
        endpoint_b.wait_idle().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stranger_and_malformed_allowed_client_do_not_terminate_listener() {
        let server_identity = TlsIdentity::generate("Rendezvous Server").unwrap();
        let client_a = TlsIdentity::generate("Rendezvous Client A").unwrap();
        let client_b = TlsIdentity::generate("Rendezvous Client B").unwrap();
        let stranger = TlsIdentity::generate("Rendezvous Stranger").unwrap();
        let allowed = vec![
            client_a.certificate_der().to_vec(),
            client_b.certificate_der().to_vec(),
        ];
        let server_endpoint = bind_server(
            mtls_server_config_for_exact_clients(&server_identity, &allowed).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let address = server_endpoint.local_addr().unwrap();
        let endpoint_a = bind_client(
            mtls_client_config(&client_a, server_identity.certificate_der()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let endpoint_b = bind_client(
            mtls_client_config(&client_b, server_identity.certificate_der()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let stranger_endpoint = bind_client(
            mtls_client_config(&stranger, server_identity.certificate_der()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let device_a = DeviceId::new(certificate_fingerprint(client_a.certificate_der())).unwrap();
        let device_b = DeviceId::new(certificate_fingerprint(client_b.certificate_der())).unwrap();

        let (server, clients) = tokio::join!(
            serve_one_match(&server_endpoint, &allowed, Duration::from_secs(8)),
            async {
                if let Ok(connection) = latencydesk_socket_transport::identity::connect_exact_peer(
                    &stranger_endpoint,
                    address,
                    server_identity.certificate_der(),
                )
                .await
                {
                    let _ = tokio::time::timeout(Duration::from_secs(2), connection.closed()).await;
                }

                let malformed = latencydesk_socket_transport::identity::connect_exact_peer(
                    &endpoint_a,
                    address,
                    server_identity.certificate_der(),
                )
                .await
                .unwrap();
                let malformed_record = StreamRecord::encode(
                    StreamKind::Control,
                    RENDEZVOUS_STAMP,
                    &[0, 0, 0x10, 0x01],
                )
                .unwrap();
                malformed.send_control(&malformed_record).await.unwrap();
                tokio::time::timeout(Duration::from_secs(2), malformed.closed())
                    .await
                    .unwrap();

                tokio::join!(
                    async {
                        let connection =
                            latencydesk_socket_transport::identity::connect_exact_peer(
                                &endpoint_a,
                                address,
                                server_identity.certificate_der(),
                            )
                            .await
                            .unwrap();
                        exchange_registration(
                            connection,
                            device_a,
                            registration(RendezvousRole::Initiator, device_b, 5001),
                            Duration::from_secs(5),
                        )
                        .await
                    },
                    async {
                        let connection =
                            latencydesk_socket_transport::identity::connect_exact_peer(
                                &endpoint_b,
                                address,
                                server_identity.certificate_der(),
                            )
                            .await
                            .unwrap();
                        exchange_registration(
                            connection,
                            device_b,
                            registration(RendezvousRole::Responder, device_a, 5002),
                            Duration::from_secs(5),
                        )
                        .await
                    },
                )
            },
        );
        let report = server.unwrap();
        let (delivery_a, delivery_b) = clients;
        assert!(report.rejected >= 2);
        assert!(delivery_a.is_ok());
        assert!(delivery_b.is_ok());
        server_endpoint.close(0_u32.into(), b"test complete");
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        stranger_endpoint.close(0_u32.into(), b"test complete");
        server_endpoint.wait_idle().await;
        endpoint_a.wait_idle().await;
        endpoint_b.wait_idle().await;
        stranger_endpoint.wait_idle().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exchange_timeout_closes_the_authenticated_connection() {
        let server_identity = TlsIdentity::generate("Rendezvous Server").unwrap();
        let client_identity = TlsIdentity::generate("Rendezvous Client").unwrap();
        let expected_peer = TlsIdentity::generate("Expected Peer").unwrap();
        let allowed = vec![client_identity.certificate_der().to_vec()];
        let server_endpoint = bind_server(
            mtls_server_config_for_exact_clients(&server_identity, &allowed).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let client_endpoint = bind_client(
            mtls_client_config(&client_identity, server_identity.certificate_der()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let address = server_endpoint.local_addr().unwrap();
        let (server, client) = tokio::join!(
            latencydesk_socket_transport::identity::accept_allowed_exact_peer_with_timeout(
                &server_endpoint,
                &allowed,
                Duration::from_secs(1),
            ),
            latencydesk_socket_transport::identity::connect_exact_peer(
                &client_endpoint,
                address,
                server_identity.certificate_der(),
            ),
        );
        let server = server.unwrap();
        let client = client.unwrap();
        let self_device =
            DeviceId::new(certificate_fingerprint(client_identity.certificate_der())).unwrap();
        let peer_device =
            DeviceId::new(certificate_fingerprint(expected_peer.certificate_der())).unwrap();
        let exchange = tokio::spawn(exchange_registration(
            client,
            self_device,
            registration(RendezvousRole::Initiator, peer_device, 5001),
            Duration::from_millis(50),
        ));
        let mut request_lane = server.connection.accept_inbound_stream().await.unwrap();
        request_lane.next_record().await.unwrap();
        assert!(matches!(
            exchange.await.unwrap(),
            Err(ServiceError::Timeout)
        ));
        let closed = tokio::time::timeout(Duration::from_secs(1), server.connection.closed())
            .await
            .expect("timed-out exchange left the authenticated connection open");
        assert!(matches!(
            closed,
            quinn::ConnectionError::ApplicationClosed(ref close)
                if close.error_code.into_inner() == u64::from(RENDEZVOUS_ERROR_CODE)
        ));

        server_endpoint.close(0_u32.into(), b"test complete");
        client_endpoint.close(0_u32.into(), b"test complete");
        server_endpoint.wait_idle().await;
        client_endpoint.wait_idle().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_exchange_closes_the_authenticated_connection() {
        let server_identity = TlsIdentity::generate("Rendezvous Server").unwrap();
        let client_identity = TlsIdentity::generate("Rendezvous Client").unwrap();
        let expected_peer = TlsIdentity::generate("Expected Peer").unwrap();
        let allowed = vec![client_identity.certificate_der().to_vec()];
        let server_endpoint = bind_server(
            mtls_server_config_for_exact_clients(&server_identity, &allowed).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let client_endpoint = bind_client(
            mtls_client_config(&client_identity, server_identity.certificate_der()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let address = server_endpoint.local_addr().unwrap();
        let (server, client) = tokio::join!(
            latencydesk_socket_transport::identity::accept_allowed_exact_peer_with_timeout(
                &server_endpoint,
                &allowed,
                Duration::from_secs(1),
            ),
            latencydesk_socket_transport::identity::connect_exact_peer(
                &client_endpoint,
                address,
                server_identity.certificate_der(),
            ),
        );
        let server = server.unwrap();
        let client = client.unwrap();
        let self_device =
            DeviceId::new(certificate_fingerprint(client_identity.certificate_der())).unwrap();
        let peer_device =
            DeviceId::new(certificate_fingerprint(expected_peer.certificate_der())).unwrap();
        let exchange = tokio::spawn(exchange_registration(
            client,
            self_device,
            registration(RendezvousRole::Initiator, peer_device, 5001),
            Duration::from_secs(5),
        ));
        let mut request_lane = server.connection.accept_inbound_stream().await.unwrap();
        request_lane.next_record().await.unwrap();
        exchange.abort();
        assert!(exchange.await.unwrap_err().is_cancelled());
        let closed = tokio::time::timeout(Duration::from_secs(1), server.connection.closed())
            .await
            .expect("cancelled exchange left the authenticated connection open");
        assert!(matches!(
            closed,
            quinn::ConnectionError::ApplicationClosed(ref close)
                if close.error_code.into_inner() == u64::from(RENDEZVOUS_ERROR_CODE)
        ));

        server_endpoint.close(0_u32.into(), b"test complete");
        client_endpoint.close(0_u32.into(), b"test complete");
        server_endpoint.wait_idle().await;
        client_endpoint.wait_idle().await;
    }
}
