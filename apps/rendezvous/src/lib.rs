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
use latencydesk_socket_transport::quic::{QuicConnection, QuicInboundStream, QuicTransportError};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

pub const MAX_FRAME: usize = 4 * 1024;
pub const MAX_REJECTIONS: usize = 16;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_CONCURRENT_ADMISSIONS: usize = 8;
const RENDEZVOUS_ERROR_CODE: u32 = 0x130;
const RESPONSE_HEADER_LEN: usize = 48;
const RESPONSE_WAITING: u8 = 1;
const RESPONSE_DELIVERY: u8 = 2;
const RESPONSE_COMMIT: u8 = 3;
const RESPONSE_COMPLETE: u8 = 4;
const DELIVERY_ACK_TAG: &[u8] = b"latencydesk/rendezvous/delivery-ack/v1";
const COMMIT_ACK_TAG: &[u8] = b"latencydesk/rendezvous/commit-ack/v1";

struct Admission {
    device: DeviceId,
    registration: RendezvousRegistration,
    connection: QuicConnection,
    inbound: QuicInboundStream,
}

struct WaitingConnection {
    connection: QuicConnection,
    inbound: QuicInboundStream,
    expires_at: u64,
}

pub const RENDEZVOUS_STAMP: SessionStamp = SessionStamp {
    session_id: 1,
    generation: 1,
    authorization_epoch: 1,
    display_epoch: 1,
    codec_epoch: 1,
    route_epoch: 1,
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
    Commit,
    Complete,
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
            Self::Commit => formatter.write_str("Commit"),
            Self::Complete => formatter.write_str("Complete"),
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
        RendezvousResponse::Commit => {
            out.push(RESPONSE_COMMIT);
            out.extend_from_slice(&[0; 3]);
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&[0; 32]);
            out.extend_from_slice(&0_u32.to_be_bytes());
        }
        RendezvousResponse::Complete => {
            out.push(RESPONSE_COMPLETE);
            out.extend_from_slice(&[0; 3]);
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&[0; 32]);
            out.extend_from_slice(&0_u32.to_be_bytes());
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
        RESPONSE_COMMIT if value == 0 && peer == [0; 32] && registration_len == 0 => {
            Ok(RendezvousResponse::Commit)
        }
        RESPONSE_COMPLETE if value == 0 && peer == [0; 32] && registration_len == 0 => {
            Ok(RendezvousResponse::Complete)
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

fn spawn_admission(
    tasks: &mut JoinSet<Result<Admission, ServiceError>>,
    endpoint: quinn::Endpoint,
    allowed: Arc<Vec<Vec<u8>>>,
    service_deadline: tokio::time::Instant,
) {
    tasks.spawn(async move {
        let remaining = service_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ServiceError::Timeout);
        }
        let peer = accept_allowed_exact_peer_with_timeout(
            &endpoint,
            &allowed,
            HANDSHAKE_TIMEOUT.min(remaining),
        )
        .await?;
        let device = DeviceId::new(peer.peer_fingerprint)?;
        let operation_deadline =
            (tokio::time::Instant::now() + OPERATION_TIMEOUT).min(service_deadline);
        let (registration, inbound) =
            match receive_request(&peer.connection, operation_deadline).await {
                Ok(registration) => registration,
                Err(error) => {
                    peer.connection
                        .close(RENDEZVOUS_ERROR_CODE, b"invalid rendezvous request");
                    return Err(error);
                }
            };
        Ok(Admission {
            device,
            registration,
            connection: peer.connection,
            inbound,
        })
    });
}

fn close_expired_waiters(
    waiting: &mut HashMap<(DeviceId, [u8; 16]), WaitingConnection>,
    now: u64,
) -> Vec<(DeviceId, [u8; 16])> {
    let mut expired = Vec::new();
    waiting.retain(|key, entry| {
        if entry.expires_at > now {
            true
        } else {
            entry
                .connection
                .close(RENDEZVOUS_ERROR_CODE, b"rendezvous registration expired");
            expired.push(*key);
            false
        }
    });
    expired
}

/// Runs one bounded service lifecycle until one reciprocal pair receives
/// one-shot deliveries. Invalid or unauthenticated attempts are rejected
/// without terminating the listener before the fixed rejection cap.
pub async fn serve_one_match(
    endpoint: &quinn::Endpoint,
    allowed_client_certificates: &[Vec<u8>],
    total_timeout: Duration,
) -> Result<ServerReport, ServiceError> {
    serve_matches(endpoint, allowed_client_certificates, total_timeout, 2, 1).await
}

/// Serves a bounded number of independent reciprocal exchanges.  Each
/// successful registration consumes one slot and each match is one-shot.
pub async fn serve_matches(
    endpoint: &quinn::Endpoint,
    allowed_client_certificates: &[Vec<u8>],
    total_timeout: Duration,
    max_successful_registrations: usize,
    max_matches: usize,
) -> Result<ServerReport, ServiceError> {
    if total_timeout.is_zero() {
        return Err(ServiceError::InvalidConfig);
    }
    if !(2..=64).contains(&max_successful_registrations)
        || !(1..=32).contains(&max_matches)
        || max_successful_registrations < max_matches.saturating_mul(2)
        || allowed_client_certificates.len() < 2
        || allowed_client_certificates.len() > 32
    {
        return Err(ServiceError::InvalidConfig);
    }
    let started = tokio::time::Instant::now();
    let deadline = started + total_timeout;
    let mut broker = RendezvousBroker::new(RendezvousLimits {
        max_pending_per_device: 16,
        max_successful_registrations,
        max_matches,
        ..RendezvousLimits::default()
    })?;
    let mut waiting_connections: HashMap<(DeviceId, [u8; 16]), WaitingConnection> = HashMap::new();
    let allowed = Arc::new(allowed_client_certificates.to_vec());
    let mut admissions = JoinSet::new();
    for _ in 0..MAX_CONCURRENT_ADMISSIONS.min(max_successful_registrations) {
        spawn_admission(
            &mut admissions,
            endpoint.clone(),
            Arc::clone(&allowed),
            deadline,
        );
    }
    let mut closing = JoinSet::new();
    let mut disconnected = JoinSet::new();
    let mut report = ServerReport {
        registrations: 0,
        matched: 0,
        rejected: 0,
    };

    loop {
        let waiter_deadline = waiting_connections
            .values()
            .map(|waiting| started + Duration::from_secs(waiting.expires_at))
            .min()
            .unwrap_or(deadline)
            .min(deadline);
        let joined = tokio::select! {
            admission = admissions.join_next() => Some(admission),
            disconnected = disconnected.join_next(), if !disconnected.is_empty() => {
                if let Some(Ok((device, match_id))) = disconnected {
                    let now = started.elapsed().as_secs();
                    let released = broker.cancel_waiting(device, match_id, now);
                    report.registrations = report.registrations.saturating_sub(released);
                    waiting_connections.remove(&(device, match_id));
                }
                continue;
            }
            _ = tokio::time::sleep_until(waiter_deadline) => None,
        };
        let mut admission = match joined {
            Some(Some(Ok(Ok(admission)))) => admission,
            Some(Some(Ok(Err(_))) | Some(Err(_))) => {
                record_rejection(&mut report)?;
                spawn_admission(
                    &mut admissions,
                    endpoint.clone(),
                    Arc::clone(&allowed),
                    deadline,
                );
                continue;
            }
            None if waiter_deadline < deadline => {
                let now = started.elapsed().as_secs();
                let released = broker.cleanup(now);
                report.registrations = report.registrations.saturating_sub(released);
                for (device, match_id) in close_expired_waiters(&mut waiting_connections, now) {
                    let released = broker.cancel_waiting(device, match_id, now);
                    report.registrations = report.registrations.saturating_sub(released);
                }
                continue;
            }
            Some(None) | None => return Err(ServiceError::Timeout),
        };
        spawn_admission(
            &mut admissions,
            endpoint.clone(),
            Arc::clone(&allowed),
            deadline,
        );
        let operation_deadline = (tokio::time::Instant::now() + OPERATION_TIMEOUT).min(deadline);
        if operation_deadline <= tokio::time::Instant::now() {
            return Err(ServiceError::Timeout);
        }
        let device = admission.device;
        let registration = admission.registration;
        let match_id = registration.match_id;
        let now = started.elapsed().as_secs();
        let released = broker.cleanup(now);
        report.registrations = report.registrations.saturating_sub(released);
        for (device, match_id) in close_expired_waiters(&mut waiting_connections, now) {
            let released = broker.cancel_waiting(device, match_id, now);
            report.registrations = report.registrations.saturating_sub(released);
        }
        // The disconnect watcher normally removes this entry first.  This
        // immediate check closes the admission race where the responder and
        // the watch notification become ready in the same scheduler turn.
        if let Ok(expected_waiter) = DeviceId::new(registration.expected_peer_fingerprint) {
            let key = (expected_waiter, match_id);
            let closed = if let Some(waiting) = waiting_connections.get(&key) {
                connection_closed_now(&waiting.connection).await
            } else {
                false
            };
            if closed {
                waiting_connections.remove(&key);
                let released = broker.cancel_waiting(expected_waiter, match_id, now);
                report.registrations = report.registrations.saturating_sub(released);
                admission
                    .connection
                    .close(RENDEZVOUS_ERROR_CODE, b"rendezvous waiter disconnected");
                record_rejection(&mut report)?;
                continue;
            }
        }
        match broker.register(device, registration, now) {
            Ok(RegisterOutcome::Waiting { expires_at }) => {
                let waiting_sent = send_response(
                    &admission.connection,
                    &RendezvousResponse::Waiting {
                        ttl_seconds: expires_at.saturating_sub(now).max(1),
                    },
                    operation_deadline,
                )
                .await;
                if waiting_sent.is_err() {
                    broker.cancel_waiting(device, match_id, now);
                    admission
                        .connection
                        .close(RENDEZVOUS_ERROR_CODE, b"rendezvous waiting response failed");
                    record_rejection(&mut report)?;
                    continue;
                }
                waiting_connections.insert(
                    (device, match_id),
                    WaitingConnection {
                        connection: admission.connection,
                        inbound: admission.inbound,
                        expires_at,
                    },
                );
                let watch_connection = waiting_connections
                    .get(&(device, match_id))
                    .expect("waiting connection inserted")
                    .connection
                    .clone();
                disconnected.spawn(async move {
                    let _ = watch_connection.closed().await;
                    (device, match_id)
                });
                report.registrations += 1;
                if report.registrations >= max_successful_registrations {
                    return Err(ServiceError::Unmatched);
                }
            }
            Ok(RegisterOutcome::Matched(caller_delivery)) => {
                report.registrations += 1;
                let waiting_device = caller_delivery.peer;
                let waiting_delivery = match broker.take_delivery(waiting_device, match_id, now) {
                    Ok(delivery) => delivery,
                    Err(error) => {
                        let released = broker.abort_match(match_id, now);
                        report.registrations = report.registrations.saturating_sub(released);
                        admission
                            .connection
                            .close(RENDEZVOUS_ERROR_CODE, b"rendezvous delivery unavailable");
                        return Err(ServiceError::Broker(error));
                    }
                };
                let mut waiting_connection =
                    match waiting_connections.remove(&(waiting_device, match_id)) {
                        Some(connection) => connection,
                        None => {
                            let released = broker.abort_match(match_id, now);
                            report.registrations = report.registrations.saturating_sub(released);
                            admission
                                .connection
                                .close(RENDEZVOUS_ERROR_CODE, b"rendezvous waiter disconnected");
                            record_rejection(&mut report)?;
                            continue;
                        }
                    };
                // The reciprocal registration consumes the second
                // registration slot immediately, but it remains refundable
                // until both protocol phases complete.
                let delivery_result = async {
                    send_response(
                        &admission.connection,
                        &RendezvousResponse::Delivery(caller_delivery),
                        operation_deadline,
                    )
                    .await?;
                    send_response(
                        &waiting_connection.connection,
                        &RendezvousResponse::Delivery(waiting_delivery),
                        operation_deadline,
                    )
                    .await?;
                    await_delivery_ack(
                        &mut admission.inbound,
                        DELIVERY_ACK_TAG,
                        match_id,
                        operation_deadline,
                    )
                    .await?;
                    await_delivery_ack(
                        &mut waiting_connection.inbound,
                        DELIVERY_ACK_TAG,
                        match_id,
                        operation_deadline,
                    )
                    .await?;
                    send_response(
                        &admission.connection,
                        &RendezvousResponse::Commit,
                        operation_deadline,
                    )
                    .await?;
                    send_response(
                        &waiting_connection.connection,
                        &RendezvousResponse::Commit,
                        operation_deadline,
                    )
                    .await?;
                    await_delivery_ack(
                        &mut admission.inbound,
                        COMMIT_ACK_TAG,
                        match_id,
                        operation_deadline,
                    )
                    .await?;
                    await_delivery_ack(
                        &mut waiting_connection.inbound,
                        COMMIT_ACK_TAG,
                        match_id,
                        operation_deadline,
                    )
                    .await?;
                    // A second CommitAck is a replay, not a harmless extra
                    // record.  Drain only the already-authenticated phase
                    // boundary before committing; later records are handled
                    // after Complete by connection shutdown.
                    reject_replayed_ack(&mut admission.inbound).await?;
                    reject_replayed_ack(&mut waiting_connection.inbound).await?;
                    // From this point onward the broker state is committed.
                    // Complete is a final client-visible signal; failure to
                    // send it must not roll back a two-sided commit.
                    broker.confirm_match(match_id, started.elapsed().as_secs())?;
                    let _ = send_response(
                        &admission.connection,
                        &RendezvousResponse::Complete,
                        operation_deadline,
                    )
                    .await;
                    let _ = send_response(
                        &waiting_connection.connection,
                        &RendezvousResponse::Complete,
                        operation_deadline,
                    )
                    .await;
                    Ok::<(), ServiceError>(())
                }
                .await;
                if delivery_result.is_err() {
                    let released = broker.abort_match(match_id, started.elapsed().as_secs());
                    report.registrations = report.registrations.saturating_sub(released);
                    admission.connection.close(
                        RENDEZVOUS_ERROR_CODE,
                        b"rendezvous delivery not acknowledged",
                    );
                    waiting_connection.connection.close(
                        RENDEZVOUS_ERROR_CODE,
                        b"rendezvous delivery not acknowledged",
                    );
                    record_rejection(&mut report)?;
                    continue;
                }
                report.matched += 1;
                closing.spawn(wait_for_client_close(admission.connection, deadline));
                closing.spawn(wait_for_client_close(
                    waiting_connection.connection,
                    deadline,
                ));
                if report.matched >= max_matches {
                    admissions.abort_all();
                    for (_, waiting) in waiting_connections.drain() {
                        waiting
                            .connection
                            .close(RENDEZVOUS_ERROR_CODE, b"rendezvous service complete");
                    }
                    let cleanup = async { while closing.join_next().await.is_some() {} };
                    let _ = tokio::time::timeout(Duration::from_secs(1), cleanup).await;
                    return Ok(report);
                }
            }
            Err(_) => {
                admission
                    .connection
                    .close(RENDEZVOUS_ERROR_CODE, b"rendezvous registration rejected");
                record_rejection(&mut report)?;
            }
        }
    }
}

async fn receive_request(
    connection: &QuicConnection,
    deadline: tokio::time::Instant,
) -> Result<(RendezvousRegistration, QuicInboundStream), ServiceError> {
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
    Ok((decode_request(&record.payload)?, lane))
}

fn encode_phase_ack(tag: &[u8], match_id: [u8; 16]) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(tag.len() + 16));
    payload.extend_from_slice(tag);
    payload.extend_from_slice(&match_id);
    payload
}

async fn await_delivery_ack(
    lane: &mut QuicInboundStream,
    tag: &[u8],
    match_id: [u8; 16],
    deadline: tokio::time::Instant,
) -> Result<(), ServiceError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let record = tokio::time::timeout(remaining, lane.next_record())
        .await
        .map_err(|_| ServiceError::Timeout)??;
    if record.kind != StreamKind::Control
        || record.stamp != RENDEZVOUS_STAMP
        || record.payload.as_ref() != encode_phase_ack(tag, match_id).as_slice()
    {
        return Err(ServiceError::Wire(WireError::InvalidResponse));
    }
    Ok(())
}

async fn reject_replayed_ack(lane: &mut QuicInboundStream) -> Result<(), ServiceError> {
    match tokio::time::timeout(Duration::from_millis(2), lane.next_record()).await {
        Err(_) => Ok(()),
        Ok(Ok(_)) => Err(ServiceError::Wire(WireError::InvalidResponse)),
        Ok(Err(error)) => Err(ServiceError::Quic(error)),
    }
}

async fn connection_closed_now(connection: &QuicConnection) -> bool {
    tokio::select! {
        biased;
        _ = connection.closed() => true,
        _ = tokio::task::yield_now() => false,
    }
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

async fn send_delivery_ack(
    connection: &QuicConnection,
    tag: &[u8],
    match_id: [u8; 16],
    deadline: tokio::time::Instant,
) -> Result<(), ServiceError> {
    let payload = encode_phase_ack(tag, match_id);
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

async fn wait_for_client_close(connection: QuicConnection, deadline: tokio::time::Instant) {
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
    let mut delivered = None;
    let mut committed = false;
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
            RendezvousResponse::Waiting { .. } => {
                if delivered.is_some() || committed {
                    connection.close(RENDEZVOUS_ERROR_CODE, b"waiting after rendezvous delivery");
                    return Err(ServiceError::Wire(WireError::InvalidResponse));
                }
                continue;
            }
            RendezvousResponse::Delivery(delivery) => {
                if delivered.is_some() || committed {
                    connection.close(RENDEZVOUS_ERROR_CODE, b"duplicate rendezvous delivery");
                    return Err(ServiceError::Wire(WireError::InvalidResponse));
                }
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
                send_delivery_ack(&connection, DELIVERY_ACK_TAG, expected_match, deadline).await?;
                delivered = Some(delivery);
            }
            RendezvousResponse::Commit => {
                if committed {
                    connection.close(RENDEZVOUS_ERROR_CODE, b"duplicate rendezvous commit");
                    return Err(ServiceError::Wire(WireError::InvalidResponse));
                }
                if delivered.is_none() {
                    connection.close(RENDEZVOUS_ERROR_CODE, b"rendezvous commit before delivery");
                    return Err(ServiceError::Wire(WireError::InvalidResponse));
                }
                send_delivery_ack(&connection, COMMIT_ACK_TAG, expected_match, deadline).await?;
                committed = true;
            }
            RendezvousResponse::Complete => {
                let Some(delivery) = delivered.take() else {
                    connection.close(
                        RENDEZVOUS_ERROR_CODE,
                        b"rendezvous complete before delivery",
                    );
                    return Err(ServiceError::Wire(WireError::InvalidResponse));
                };
                if !committed {
                    connection.close(RENDEZVOUS_ERROR_CODE, b"rendezvous complete before commit");
                    return Err(ServiceError::Wire(WireError::InvalidResponse));
                }
                connection.close(0, b"rendezvous delivery complete");
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

    fn registration_for_match(
        role: RendezvousRole,
        expected: DeviceId,
        port: u16,
        match_id: [u8; 16],
    ) -> RendezvousRegistration {
        RendezvousRegistration {
            version: RendezvousRegistration::VERSION,
            role,
            generation: 1,
            ttl_seconds: 30,
            match_id,
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

    fn registration(role: RendezvousRole, expected: DeviceId, port: u16) -> RendezvousRegistration {
        registration_for_match(role, expected, port, [9; 16])
    }

    async fn connect_and_exchange(
        endpoint: &quinn::Endpoint,
        address: SocketAddr,
        server_certificate: &[u8],
        self_device: DeviceId,
        registration: RendezvousRegistration,
    ) -> Result<RendezvousDelivery, ServiceError> {
        let connection = latencydesk_socket_transport::identity::connect_exact_peer(
            endpoint,
            address,
            server_certificate,
        )
        .await?;
        exchange_registration(
            connection,
            self_device,
            registration,
            Duration::from_secs(5),
        )
        .await
    }

    async fn send_registration_and_open_response_lane(
        connection: &QuicConnection,
        registration: RendezvousRegistration,
    ) -> Result<QuicInboundStream, ServiceError> {
        let request = encode_request(&registration)?;
        let record = Zeroizing::new(StreamRecord::encode(
            StreamKind::Control,
            RENDEZVOUS_STAMP,
            &request,
        )?);
        connection.send_control(&record).await?;
        let lane = connection.accept_inbound_stream().await?;
        if lane.kind() != StreamKind::Control {
            return Err(ServiceError::Wire(WireError::InvalidResponse));
        }
        Ok(lane)
    }

    async fn send_registration_only(
        connection: &QuicConnection,
        registration: RendezvousRegistration,
    ) -> Result<(), ServiceError> {
        let request = encode_request(&registration)?;
        let record = Zeroizing::new(StreamRecord::encode(
            StreamKind::Control,
            RENDEZVOUS_STAMP,
            &request,
        )?);
        connection.send_control(&record).await?;
        Ok(())
    }

    async fn read_until_delivery(
        lane: &mut QuicInboundStream,
    ) -> Result<RendezvousResponse, ServiceError> {
        loop {
            let record = lane.next_record().await?;
            match decode_response(&record.payload)? {
                RendezvousResponse::Waiting { .. } => continue,
                response @ RendezvousResponse::Delivery(_) => return Ok(response),
                RendezvousResponse::Commit | RendezvousResponse::Complete => {
                    return Err(ServiceError::Wire(WireError::InvalidResponse));
                }
            }
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
        let commit = encode_response(&RendezvousResponse::Commit).unwrap();
        assert!(matches!(
            decode_response(&commit),
            Ok(RendezvousResponse::Commit)
        ));
        let mut malformed_commit = commit.to_vec();
        malformed_commit[12] = 1;
        assert!(matches!(
            decode_response(&malformed_commit),
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
    async fn first_commit_ack_cannot_complete_when_second_peer_fails() {
        let server_identity = TlsIdentity::generate("Commit Server").unwrap();
        let client_a = TlsIdentity::generate("Commit Client A").unwrap();
        let client_b = TlsIdentity::generate("Commit Client B").unwrap();
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
        let server_endpoint_for_task = server_endpoint.clone();
        let allowed_for_task = allowed.clone();
        let server = tokio::spawn(async move {
            serve_one_match(
                &server_endpoint_for_task,
                &allowed_for_task,
                Duration::from_secs(3),
            )
            .await
        });
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
        let connection_a = latencydesk_socket_transport::identity::connect_exact_peer(
            &endpoint_a,
            address,
            server_identity.certificate_der(),
        )
        .await
        .unwrap();
        let connection_b = latencydesk_socket_transport::identity::connect_exact_peer(
            &endpoint_b,
            address,
            server_identity.certificate_der(),
        )
        .await
        .unwrap();
        let device_a = DeviceId::new(certificate_fingerprint(client_a.certificate_der())).unwrap();
        let device_b = DeviceId::new(certificate_fingerprint(client_b.certificate_der())).unwrap();
        let (lane_a, lane_b) = tokio::join!(
            send_registration_and_open_response_lane(
                &connection_a,
                registration(RendezvousRole::Initiator, device_b, 5301),
            ),
            send_registration_and_open_response_lane(
                &connection_b,
                registration(RendezvousRole::Responder, device_a, 5302),
            ),
        );
        let mut lane_a = lane_a.unwrap();
        let mut lane_b = lane_b.unwrap();
        let (delivery_a, delivery_b) = tokio::join!(
            read_until_delivery(&mut lane_a),
            read_until_delivery(&mut lane_b)
        );
        assert!(matches!(
            delivery_a.unwrap(),
            RendezvousResponse::Delivery(_)
        ));
        assert!(matches!(
            delivery_b.unwrap(),
            RendezvousResponse::Delivery(_)
        ));
        let ack_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let (delivery_ack_a, delivery_ack_b) = tokio::join!(
            send_delivery_ack(&connection_a, DELIVERY_ACK_TAG, [9; 16], ack_deadline),
            send_delivery_ack(&connection_b, DELIVERY_ACK_TAG, [9; 16], ack_deadline),
        );
        delivery_ack_a.unwrap();
        delivery_ack_b.unwrap();
        let (commit_a, commit_b) = tokio::join!(lane_a.next_record(), lane_b.next_record());
        assert!(matches!(
            decode_response(&commit_a.unwrap().payload),
            Ok(RendezvousResponse::Commit)
        ));
        assert!(matches!(
            decode_response(&commit_b.unwrap().payload),
            Ok(RendezvousResponse::Commit)
        ));
        send_delivery_ack(
            &connection_a,
            COMMIT_ACK_TAG,
            [9; 16],
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        // This is intentionally a first-side CommitAck sent before the
        // second side can acknowledge.  The server must not emit Complete.
        connection_b.close(RENDEZVOUS_ERROR_CODE, b"second commit phase failed");
        let first_side = tokio::time::timeout(Duration::from_secs(1), lane_a.next_record()).await;
        assert!(first_side.is_err() || first_side.unwrap().is_err());
        assert!(server.await.unwrap().is_err());
        server_endpoint.close(0_u32.into(), b"test complete");
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        server_endpoint.wait_idle().await;
        endpoint_a.wait_idle().await;
        endpoint_b.wait_idle().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn closed_waiting_response_does_not_terminate_a_later_valid_pair() {
        let server_identity = TlsIdentity::generate("Waiting Failure Server").unwrap();
        let client_a = TlsIdentity::generate("Waiting Failure Client A").unwrap();
        let client_b = TlsIdentity::generate("Waiting Failure Client B").unwrap();
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
        let server_endpoint_for_task = server_endpoint.clone();
        let allowed_for_task = allowed.clone();
        let server = tokio::spawn(async move {
            serve_one_match(
                &server_endpoint_for_task,
                &allowed_for_task,
                Duration::from_secs(5),
            )
            .await
        });

        let abandoned = latencydesk_socket_transport::identity::connect_exact_peer(
            &endpoint_a,
            address,
            server_identity.certificate_der(),
        )
        .await
        .unwrap();
        send_registration_only(
            &abandoned,
            registration_for_match(RendezvousRole::Initiator, device_b, 5401, [0xC1; 16]),
        )
        .await
        .unwrap();
        abandoned.close(RENDEZVOUS_ERROR_CODE, b"client closed before Waiting");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (valid_a, valid_b) = tokio::join!(
            connect_and_exchange(
                &endpoint_a,
                address,
                server_identity.certificate_der(),
                device_a,
                registration_for_match(RendezvousRole::Initiator, device_b, 5402, [0xC2; 16],),
            ),
            connect_and_exchange(
                &endpoint_b,
                address,
                server_identity.certificate_der(),
                device_b,
                registration_for_match(RendezvousRole::Responder, device_a, 5403, [0xC2; 16],),
            ),
        );
        assert_eq!(valid_a.unwrap().peer, device_b);
        assert_eq!(valid_b.unwrap().peer, device_a);
        let report = server.await.unwrap().unwrap();
        assert_eq!(report.registrations, 2);
        assert_eq!(report.matched, 1);

        server_endpoint.close(0_u32.into(), b"test complete");
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        server_endpoint.wait_idle().await;
        endpoint_a.wait_idle().await;
        endpoint_b.wait_idle().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_matches_complete_concurrently_despite_a_slow_allowed_client() {
        let server_identity = TlsIdentity::generate("Rendezvous Multi Server").unwrap();
        let clients = (0..5)
            .map(|index| TlsIdentity::generate(&format!("Rendezvous Client {index}")).unwrap())
            .collect::<Vec<_>>();
        let allowed = clients
            .iter()
            .map(|identity| identity.certificate_der().to_vec())
            .collect::<Vec<_>>();
        let server_endpoint = bind_server(
            mtls_server_config_for_exact_clients(&server_identity, &allowed).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let address = server_endpoint.local_addr().unwrap();
        let endpoints = clients
            .iter()
            .map(|identity| {
                bind_client(
                    mtls_client_config(identity, server_identity.certificate_der()).unwrap(),
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let devices = clients
            .iter()
            .map(|identity| {
                DeviceId::new(certificate_fingerprint(identity.certificate_der())).unwrap()
            })
            .collect::<Vec<_>>();

        let run = async {
            let (server, slow_and_clients) = tokio::join!(
                serve_matches(&server_endpoint, &allowed, Duration::from_secs(5), 4, 2),
                async {
                    let slow = latencydesk_socket_transport::identity::connect_exact_peer(
                        &endpoints[4],
                        address,
                        server_identity.certificate_der(),
                    )
                    .await
                    .unwrap();
                    let clients = tokio::join!(
                        connect_and_exchange(
                            &endpoints[0],
                            address,
                            server_identity.certificate_der(),
                            devices[0],
                            registration_for_match(
                                RendezvousRole::Initiator,
                                devices[1],
                                5101,
                                [0xA1; 16],
                            ),
                        ),
                        connect_and_exchange(
                            &endpoints[1],
                            address,
                            server_identity.certificate_der(),
                            devices[1],
                            registration_for_match(
                                RendezvousRole::Responder,
                                devices[0],
                                5102,
                                [0xA1; 16],
                            ),
                        ),
                        connect_and_exchange(
                            &endpoints[2],
                            address,
                            server_identity.certificate_der(),
                            devices[2],
                            registration_for_match(
                                RendezvousRole::Initiator,
                                devices[3],
                                5201,
                                [0xB2; 16],
                            ),
                        ),
                        connect_and_exchange(
                            &endpoints[3],
                            address,
                            server_identity.certificate_der(),
                            devices[3],
                            registration_for_match(
                                RendezvousRole::Responder,
                                devices[2],
                                5202,
                                [0xB2; 16],
                            ),
                        ),
                    );
                    (slow, clients)
                },
            );
            (server, slow_and_clients)
        };
        let (server, (slow, deliveries)) = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("slow client caused rendezvous head-of-line blocking");
        let report = server.unwrap();
        assert_eq!(report.registrations, 4);
        assert_eq!(report.matched, 2);
        let (a, b, c, d) = deliveries;
        assert_eq!(a.unwrap().peer, devices[1]);
        assert_eq!(b.unwrap().peer, devices[0]);
        assert_eq!(c.unwrap().peer, devices[3]);
        assert_eq!(d.unwrap().peer, devices[2]);
        slow.close(0, b"test complete");
        server_endpoint.close(0_u32.into(), b"test complete");
        for endpoint in endpoints {
            endpoint.close(0_u32.into(), b"test complete");
            endpoint.wait_idle().await;
        }
        server_endpoint.wait_idle().await;
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
