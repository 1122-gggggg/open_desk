//! A short-lived, isolated QUIC probe for validating an ICE nominated path.
//!
//! The probe owns a fresh handed-off UDP socket and never touches the product
//! control session.  Its transcript is carried as ordinary authenticated
//! control records, which keeps all validation behind the existing exact-leaf
//! mTLS boundary.

use crate::ice::{IceRole, IceSocketHandoff};
use crate::identity::{accept_exact_peer, connect_exact_peer, IdentityError, TlsIdentity};
use crate::quic::{
    bind_client_on_socket, bind_server_on_socket, QuicConnection, QuicTransportError,
};
use latencydesk_protocol::quic::{SessionStamp, StreamKind, StreamRecord};
use latencydesk_protocol::{
    ControlHeader, ControlKind, ControlPacket, IceProbeMessage, IceProbeStage,
};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_PROBE_PAYLOAD: usize = 256;
const PROBE_ERROR: u32 = 0x120;
type DecodedProbe = (IceProbeMessage, [u8; 16], [u8; 16], [u8; 32]);

/// Generates a fresh nonce for the authenticated control-session barrier.
pub fn generate_control_nonce() -> Result<[u8; 16], IceProbeError> {
    for _ in 0..3 {
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| IceProbeError::Entropy)?;
        if nonce != [0; 16] {
            return Ok(nonce);
        }
    }
    Err(IceProbeError::Entropy)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceProbeReport {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub elapsed: Duration,
}

#[derive(Debug)]
pub enum IceProbeError {
    InvalidRemote {
        expected: SocketAddr,
        actual: SocketAddr,
    },
    Timeout,
    Identity(IdentityError),
    Quic(QuicTransportError),
    Protocol(latencydesk_protocol::ProtocolError),
    Transcript(&'static str),
    Entropy,
    CleanupTimeout,
}

impl fmt::Display for IceProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRemote { expected, actual } => {
                write!(f, "probe remote {actual} is not nominated {expected}")
            }
            Self::Timeout => f.write_str("ICE probe timed out"),
            Self::Identity(e) => write!(f, "probe identity failed: {e}"),
            Self::Quic(e) => write!(f, "probe QUIC failed: {e}"),
            Self::Protocol(e) => write!(f, "probe protocol failed: {e}"),
            Self::Transcript(e) => write!(f, "probe transcript failed: {e}"),
            Self::Entropy => f.write_str("probe nonce generation failed"),
            Self::CleanupTimeout => f.write_str("probe endpoint cleanup timed out"),
        }
    }
}
impl std::error::Error for IceProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::Quic(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
impl From<IdentityError> for IceProbeError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}
impl From<QuicTransportError> for IceProbeError {
    fn from(e: QuicTransportError) -> Self {
        Self::Quic(e)
    }
}
impl From<latencydesk_protocol::ProtocolError> for IceProbeError {
    fn from(e: latencydesk_protocol::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// A server endpoint prepared on the exact nominated UDP socket.
pub struct PreparedIceProbeServer {
    endpoint: quinn::Endpoint,
    local: SocketAddr,
    timeout: Duration,
    nominated_remote: SocketAddr,
}

impl PreparedIceProbeServer {
    pub fn prepare(
        handoff: IceSocketHandoff,
        identity: &TlsIdentity,
        exact_client: &[u8],
        timeout: Duration,
    ) -> Result<Self, IceProbeError> {
        if timeout.is_zero() {
            return Err(IceProbeError::Timeout);
        }
        if handoff.effective_role != IceRole::Controlled {
            return Err(IceProbeError::Transcript(
                "server ICE role is not controlled",
            ));
        }
        let local = handoff
            .socket
            .local_addr()
            .map_err(|_| IceProbeError::Transcript("invalid handed-off socket"))?;
        if handoff.nominated.0 != local {
            return Err(IceProbeError::InvalidRemote {
                expected: local,
                actual: handoff.nominated.0,
            });
        }
        let nominated_remote = handoff.nominated.1;
        let config = crate::identity::mtls_server_config(identity, exact_client)?;
        let endpoint =
            bind_server_on_socket(config, handoff.socket).map_err(IceProbeError::Quic)?;
        Ok(Self {
            endpoint,
            local,
            timeout,
            nominated_remote,
        })
    }

    pub async fn accept_echo(
        self,
        expected: SessionStamp,
        ice_generation: u32,
        exact_client: &[u8],
        client_nonce: [u8; 16],
        host_nonce: [u8; 16],
    ) -> Result<IceProbeReport, IceProbeError> {
        let result = tokio::time::timeout(
            self.timeout,
            self.accept_echo_inner(
                expected,
                ice_generation,
                exact_client,
                client_nonce,
                host_nonce,
            ),
        )
        .await;
        self.endpoint
            .close(quinn::VarInt::from_u32(PROBE_ERROR), b"probe complete");
        if tokio::time::timeout(Duration::from_secs(2), self.endpoint.wait_idle())
            .await
            .is_err()
        {
            return Err(IceProbeError::CleanupTimeout);
        }
        match result {
            Ok(r) => r,
            Err(_) => Err(IceProbeError::Timeout),
        }
    }

    async fn accept_echo_inner(
        &self,
        expected: SessionStamp,
        generation: u32,
        exact_client: &[u8],
        client_nonce: [u8; 16],
        host_nonce: [u8; 16],
    ) -> Result<IceProbeReport, IceProbeError> {
        let started = Instant::now();
        let connection = accept_exact_peer(&self.endpoint, exact_client).await?;
        let remote = connection.remote_address();
        if remote != self.nominated_remote {
            connection.close(PROBE_ERROR, b"wrong nominated peer");
            return Err(IceProbeError::InvalidRemote {
                expected: self.nominated_remote,
                actual: remote,
            });
        }
        let mut lane = connection.accept_inbound_stream().await?;
        let first = lane.next_record().await?;
        let (request, request_client_nonce, request_host_nonce, challenge) = decode_probe(&first)?;
        if request.stage != IceProbeStage::EchoRequest
            || request.stamp != expected
            || request.ice_generation != generation
        {
            connection.close(PROBE_ERROR, b"invalid probe request");
            return Err(IceProbeError::Transcript("request binding"));
        }
        if client_nonce == [0; 16]
            || host_nonce == [0; 16]
            || request_client_nonce != client_nonce
            || request_host_nonce != host_nonce
        {
            connection.close(PROBE_ERROR, b"invalid nonce");
            return Err(IceProbeError::Transcript("nonce binding"));
        }
        send_probe(
            &connection,
            expected,
            generation,
            IceProbeStage::EchoResponse,
            client_nonce,
            host_nonce,
            challenge,
        )
        .await?;
        let complete = lane.next_record().await?;
        let (message, _, _, complete_challenge) = decode_probe(&complete)?;
        if message.stage != IceProbeStage::Complete
            || message.stamp != expected
            || message.ice_generation != generation
            || message.client_nonce != client_nonce
            || message.host_nonce != host_nonce
            || complete_challenge != challenge
        {
            connection.close(PROBE_ERROR, b"invalid completion");
            return Err(IceProbeError::Transcript("completion binding"));
        }
        send_probe(
            &connection,
            expected,
            generation,
            IceProbeStage::Complete,
            client_nonce,
            host_nonce,
            challenge,
        )
        .await?;
        let _ = connection.closed().await;
        Ok(IceProbeReport {
            local: self.local,
            remote,
            elapsed: started.elapsed(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn connect_echo(
    handoff: IceSocketHandoff,
    identity: &TlsIdentity,
    exact_server: &[u8],
    expected_remote: SocketAddr,
    stamp: SessionStamp,
    ice_generation: u32,
    client_nonce: [u8; 16],
    host_nonce: [u8; 16],
    timeout: Duration,
) -> Result<IceProbeReport, IceProbeError> {
    if timeout.is_zero() {
        return Err(IceProbeError::Timeout);
    }
    if handoff.effective_role != IceRole::Controlling {
        return Err(IceProbeError::Transcript(
            "client ICE role is not controlling",
        ));
    }
    if client_nonce == [0; 16] || host_nonce == [0; 16] {
        return Err(IceProbeError::Transcript("nonces must be nonzero"));
    }
    let local = handoff
        .socket
        .local_addr()
        .map_err(|_| IceProbeError::Transcript("invalid handed-off socket"))?;
    if handoff.nominated.0 != local {
        return Err(IceProbeError::InvalidRemote {
            expected: local,
            actual: handoff.nominated.0,
        });
    }
    if handoff.nominated.1 != expected_remote {
        return Err(IceProbeError::InvalidRemote {
            expected: expected_remote,
            actual: handoff.nominated.1,
        });
    }
    let config = crate::identity::mtls_client_config(identity, exact_server)?;
    let endpoint = bind_client_on_socket(config, handoff.socket).map_err(IceProbeError::Quic)?;
    let started = Instant::now();
    let result = tokio::time::timeout(timeout, async {
        let connection = connect_exact_peer(&endpoint, expected_remote, exact_server).await?;
        let challenge = generate_challenge()?;
        send_probe(
            &connection,
            stamp,
            ice_generation,
            IceProbeStage::EchoRequest,
            client_nonce,
            host_nonce,
            challenge,
        )
        .await?;
        let mut lane = connection.accept_inbound_stream().await?;
        let response = lane.next_record().await?;
        let (message, response_client_nonce, response_host_nonce, response_challenge) =
            decode_probe(&response)?;
        if message.stage != IceProbeStage::EchoResponse
            || message.stamp != stamp
            || message.ice_generation != ice_generation
            || response_client_nonce != client_nonce
            || response_host_nonce != host_nonce
            || response_challenge != challenge
        {
            return Err(IceProbeError::Transcript("response binding"));
        }
        send_probe(
            &connection,
            stamp,
            ice_generation,
            IceProbeStage::Complete,
            client_nonce,
            host_nonce,
            challenge,
        )
        .await?;
        let final_record = lane.next_record().await?;
        let (final_message, final_client_nonce, final_host_nonce, final_challenge) =
            decode_probe(&final_record)?;
        if final_message.stage != IceProbeStage::Complete
            || final_message.stamp != stamp
            || final_message.ice_generation != ice_generation
            || final_client_nonce != client_nonce
            || final_host_nonce != host_nonce
            || final_challenge != challenge
        {
            return Err(IceProbeError::Transcript("final completion binding"));
        }
        connection.close(0, b"probe complete");
        Ok(IceProbeReport {
            local,
            remote: expected_remote,
            elapsed: started.elapsed(),
        })
    })
    .await;
    endpoint.close(quinn::VarInt::from_u32(PROBE_ERROR), b"probe complete");
    if tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
        .await
        .is_err()
    {
        return Err(IceProbeError::CleanupTimeout);
    }
    match result {
        Ok(r) => r,
        Err(_) => Err(IceProbeError::Timeout),
    }
}

async fn send_probe(
    connection: &QuicConnection,
    stamp: SessionStamp,
    generation: u32,
    stage: IceProbeStage,
    client_nonce: [u8; 16],
    host_nonce: [u8; 16],
    challenge: [u8; 32],
) -> Result<(), IceProbeError> {
    let payload = IceProbeMessage {
        version: IceProbeMessage::VERSION,
        stage,
        ice_generation: generation,
        stamp,
        client_nonce,
        host_nonce,
        challenge,
    }
    .encode()?;
    let control = ControlPacket::encode(
        ControlHeader {
            kind: ControlKind::IceProbe,
            flags: 0,
            session_id: stamp.session_id,
            payload_len: payload.len() as u32,
        },
        &payload,
    )?;
    if control.len() > MAX_PROBE_PAYLOAD {
        return Err(IceProbeError::Transcript("probe payload exceeds bound"));
    }
    let record = StreamRecord::encode(StreamKind::Control, stamp, &control)?;
    connection.send_control(&record).await?;
    Ok(())
}

fn decode_probe(record: &crate::quic::ReceivedStreamRecord) -> Result<DecodedProbe, IceProbeError> {
    if record.kind != StreamKind::Control {
        return Err(IceProbeError::Transcript("wrong lane"));
    }
    let packet = ControlPacket::decode(&record.payload)?;
    if packet.header.kind != ControlKind::IceProbe
        || packet.header.session_id != record.stamp.session_id
    {
        return Err(IceProbeError::Transcript("wrong control binding"));
    }
    let message = IceProbeMessage::decode(packet.payload)?;
    if record.stamp != message.stamp {
        return Err(IceProbeError::Transcript("outer stamp binding"));
    }
    Ok((
        message,
        message.client_nonce,
        message.host_nonce,
        message.challenge,
    ))
}

fn generate_challenge() -> Result<[u8; 32], IceProbeError> {
    for _ in 0..3 {
        let mut challenge = [0_u8; 32];
        getrandom::getrandom(&mut challenge).map_err(|_| IceProbeError::Entropy)?;
        if challenge != [0; 32] {
            return Ok(challenge);
        }
    }
    Err(IceProbeError::Entropy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ice::{IceCandidate, IceRole, IceStats};
    use std::net::{Ipv4Addr, UdpSocket};

    fn stamp(session_id: u64) -> SessionStamp {
        SessionStamp {
            session_id,
            generation: 2,
            authorization_epoch: 3,
            display_epoch: 4,
            codec_epoch: 5,
        }
    }

    fn handoff(socket: UdpSocket, remote: SocketAddr, role: IceRole) -> IceSocketHandoff {
        let local = socket.local_addr().unwrap();
        IceSocketHandoff {
            socket,
            local_candidates: vec![IceCandidate::host(local)],
            remote_candidates: vec![IceCandidate::host(remote)],
            nominated: (local, remote),
            effective_role: role,
            stats: IceStats::default(),
            elapsed: Duration::from_millis(1),
        }
    }

    #[test]
    fn control_nonce_is_fresh_and_nonzero() {
        let nonce = generate_control_nonce().expect("OS entropy");
        assert_ne!(nonce, [0; 16]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exact_mtls_probe_echo_preserves_handed_off_ports() {
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let client_address = client_socket.local_addr().unwrap();
        let server_identity = TlsIdentity::generate("probe-server").unwrap();
        let client_identity = TlsIdentity::generate("probe-client").unwrap();
        let client_nonce = generate_control_nonce().unwrap();
        let host_nonce = generate_control_nonce().unwrap();
        let server = PreparedIceProbeServer::prepare(
            handoff(server_socket, client_address, IceRole::Controlled),
            &server_identity,
            client_identity.certificate_der(),
            DEFAULT_PROBE_TIMEOUT,
        )
        .unwrap();
        let (server_result, client_result) = tokio::join!(
            server.accept_echo(
                stamp(7),
                1,
                client_identity.certificate_der(),
                client_nonce,
                host_nonce,
            ),
            connect_echo(
                handoff(client_socket, server_address, IceRole::Controlling),
                &client_identity,
                server_identity.certificate_der(),
                server_address,
                stamp(7),
                1,
                client_nonce,
                host_nonce,
                DEFAULT_PROBE_TIMEOUT,
            ),
        );
        let server_report = server_result.unwrap();
        let client_report = client_result.unwrap();
        assert_eq!(server_report.local, server_address);
        assert_eq!(server_report.remote, client_address);
        assert_eq!(client_report.local, client_address);
        assert_eq!(client_report.remote, server_address);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_certificate_and_transcript_binding_never_pass_probe() {
        let server_identity = TlsIdentity::generate("probe-server").unwrap();
        let expected_client = TlsIdentity::generate("expected-client").unwrap();
        let intruder = TlsIdentity::generate("intruder-client").unwrap();
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let client_address = client_socket.local_addr().unwrap();
        let client_nonce = generate_control_nonce().unwrap();
        let host_nonce = generate_control_nonce().unwrap();
        let server = PreparedIceProbeServer::prepare(
            handoff(server_socket, client_address, IceRole::Controlled),
            &server_identity,
            expected_client.certificate_der(),
            Duration::from_millis(500),
        )
        .unwrap();
        let (server_result, client_result) = tokio::join!(
            server.accept_echo(
                stamp(7),
                1,
                expected_client.certificate_der(),
                client_nonce,
                host_nonce,
            ),
            connect_echo(
                handoff(client_socket, server_address, IceRole::Controlling),
                &intruder,
                server_identity.certificate_der(),
                server_address,
                stamp(7),
                1,
                client_nonce,
                host_nonce,
                Duration::from_millis(500),
            ),
        );
        assert!(server_result.is_err());
        assert!(client_result.is_err());

        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let client_address = client_socket.local_addr().unwrap();
        let server = PreparedIceProbeServer::prepare(
            handoff(server_socket, client_address, IceRole::Controlled),
            &server_identity,
            expected_client.certificate_der(),
            Duration::from_millis(500),
        )
        .unwrap();
        let wrong_nonce = generate_control_nonce().unwrap();
        let (server_result, client_result) = tokio::join!(
            server.accept_echo(
                stamp(7),
                1,
                expected_client.certificate_der(),
                client_nonce,
                host_nonce,
            ),
            connect_echo(
                handoff(client_socket, server_address, IceRole::Controlling),
                &expected_client,
                server_identity.certificate_der(),
                server_address,
                stamp(8),
                2,
                wrong_nonce,
                host_nonce,
                Duration::from_millis(500),
            ),
        );
        assert!(server_result.is_err());
        assert!(client_result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_nomination_and_silent_peer_timeout_are_bounded() {
        let server_identity = TlsIdentity::generate("probe-server").unwrap();
        let client_identity = TlsIdentity::generate("probe-client").unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = socket.local_addr().unwrap();
        let wrong_local = SocketAddr::new(
            local.ip(),
            if local.port() == u16::MAX {
                u16::MAX - 1
            } else {
                local.port() + 1
            },
        );
        let invalid = IceSocketHandoff {
            nominated: (wrong_local, local),
            ..handoff(socket, local, IceRole::Controlled)
        };
        assert!(matches!(
            PreparedIceProbeServer::prepare(
                invalid,
                &server_identity,
                client_identity.certificate_der(),
                Duration::from_millis(50),
            ),
            Err(IceProbeError::InvalidRemote { .. })
        ));

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = socket.local_addr().unwrap();
        let remote = SocketAddr::new(local.ip(), local.port().wrapping_add(1).max(1));
        let server = PreparedIceProbeServer::prepare(
            handoff(socket, remote, IceRole::Controlled),
            &server_identity,
            client_identity.certificate_der(),
            Duration::from_millis(50),
        )
        .unwrap();
        let started = Instant::now();
        assert!(matches!(
            server
                .accept_echo(
                    stamp(7),
                    1,
                    client_identity.certificate_der(),
                    generate_control_nonce().unwrap(),
                    generate_control_nonce().unwrap(),
                )
                .await,
            Err(IceProbeError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
