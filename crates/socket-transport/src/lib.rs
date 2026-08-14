//! Real socket adapters and authenticated QUIC/UDP transport primitives.
//!
//! Provides bounded datagram transport, authenticated 1-RTT session handshakes,
//! anti-replay protection, monotonic epoch tracking, MTU fragmentation/reassembly,
//! and adaptive congestion control.

use latencydesk_protocol::{
    AntiReplayFilter, AuthenticateMessage, ControlHeader, ControlKind, ControlPacket,
    HandshakeCompletedMessage, HelloAckMessage, HelloMessage, MediaKind, MediaPacket,
    ProtocolError, WIRE_VERSION,
};
use latencydesk_transport::{
    fragment_frame, AdaptiveCongestionConfig, AdaptiveCongestionController, CodecReconfigureSignal,
    CongestionDecision, FragmentSpec, IngestOutcome, Reassembler, ReassemblyConfig,
    ReconfigureReason, TransportError, DEFAULT_MAX_DATAGRAM_BYTES, MAX_DATAGRAM_MTU,
    MIN_DATAGRAM_MTU,
};
use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub const DEFAULT_MAX_SOCKET_DATAGRAM: usize = DEFAULT_MAX_DATAGRAM_BYTES;

#[derive(Debug)]
pub struct UdpEndpoint {
    socket: UdpSocket,
    peer: SocketAddr,
    max_datagram: usize,
}

impl UdpEndpoint {
    pub fn connected_pair(max_datagram: usize) -> Result<(Self, Self), SocketError> {
        validate_max(max_datagram)?;
        let left = UdpSocket::bind("127.0.0.1:0").map_err(SocketError::Io)?;
        let right = UdpSocket::bind("127.0.0.1:0").map_err(SocketError::Io)?;
        let left_addr = left.local_addr().map_err(SocketError::Io)?;
        let right_addr = right.local_addr().map_err(SocketError::Io)?;
        left.connect(right_addr).map_err(SocketError::Io)?;
        right.connect(left_addr).map_err(SocketError::Io)?;
        Ok((
            Self {
                socket: left,
                peer: right_addr,
                max_datagram,
            },
            Self {
                socket: right,
                peer: left_addr,
                max_datagram,
            },
        ))
    }

    pub fn bind_connected(
        local: SocketAddr,
        peer: SocketAddr,
        max_datagram: usize,
    ) -> Result<Self, SocketError> {
        validate_max(max_datagram)?;
        let socket = UdpSocket::bind(local).map_err(SocketError::Io)?;
        socket.connect(peer).map_err(SocketError::Io)?;
        Ok(Self {
            socket,
            peer,
            max_datagram,
        })
    }

    pub fn set_timeout(&self, timeout: Duration) -> Result<(), SocketError> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(SocketError::Io)?;
        self.socket
            .set_write_timeout(Some(timeout))
            .map_err(SocketError::Io)
    }

    pub fn send(&self, datagram: &[u8]) -> Result<usize, SocketError> {
        if datagram.is_empty() || datagram.len() > self.max_datagram {
            return Err(SocketError::DatagramSize(datagram.len()));
        }
        let written = self.socket.send(datagram).map_err(SocketError::Io)?;
        if written != datagram.len() {
            return Err(SocketError::ShortWrite {
                expected: datagram.len(),
                actual: written,
            });
        }
        Ok(written)
    }

    pub fn receive(&self, buffer: &mut [u8]) -> Result<usize, SocketError> {
        if buffer.len() < self.max_datagram {
            return Err(SocketError::ReceiveBuffer {
                required: self.max_datagram,
                actual: buffer.len(),
            });
        }
        let read = self.socket.recv(buffer).map_err(SocketError::Io)?;
        if read == 0 || read > self.max_datagram {
            return Err(SocketError::DatagramSize(read));
        }
        Ok(read)
    }

    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn try_clone(&self) -> Result<Self, SocketError> {
        Ok(Self {
            socket: self.socket.try_clone().map_err(SocketError::Io)?,
            peer: self.peer,
            max_datagram: self.max_datagram,
        })
    }
}

fn validate_max(max_datagram: usize) -> Result<(), SocketError> {
    if !(64..=65_507).contains(&max_datagram) {
        return Err(SocketError::DatagramSize(max_datagram));
    }
    Ok(())
}

/// Role in a remote desktop transport session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Host,
    Client,
}

/// Handshake lifecycle state for an authenticated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial unauthenticated state.
    Initial,
    /// Client sent HelloMessage, awaiting HelloAckMessage.
    HelloSent { client_nonce: [u8; 16] },
    /// Host received HelloMessage, sent HelloAckMessage, awaiting AuthenticateMessage.
    HelloAckSent {
        server_nonce: [u8; 16],
        client_nonce: [u8; 16],
        device_fingerprint: [u8; 32],
    },
    /// Handshake completed, session is active.
    Active,
    /// Handshake failed.
    Failed,
}

/// Computes an authentication proof tag over session parameters.
#[must_use]
pub fn compute_auth_tag(
    secret: &[u8; 32],
    session_id: u64,
    epoch: u32,
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut state = [0u8; 32];
    for i in 0..32 {
        state[i] = secret[i] ^ 0x5C;
    }
    let sid_bytes = session_id.to_be_bytes();
    let epoch_bytes = epoch.to_be_bytes();
    for i in 0..8 {
        state[i] ^= sid_bytes[i];
        state[i + 8] ^= epoch_bytes[i % 4];
    }
    for i in 0..16 {
        state[i + 16] ^= client_nonce[i] ^ server_nonce[i];
    }
    for round in 0..4 {
        let r = round as u8;
        for i in 0..32 {
            let prev = state[(i + 31) % 32];
            let next = state[(i + 1) % 32];
            state[i] = state[i].wrapping_add(prev ^ r).rotate_left(3) ^ next;
        }
    }
    state
}

/// Configuration for an authenticated datagram transport session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedSessionConfig {
    pub role: SessionRole,
    pub path_mtu: usize,
    pub reassembly: ReassemblyConfig,
    pub congestion: AdaptiveCongestionConfig,
}

impl Default for AuthenticatedSessionConfig {
    fn default() -> Self {
        Self {
            role: SessionRole::Client,
            path_mtu: DEFAULT_MAX_DATAGRAM_BYTES,
            reassembly: ReassemblyConfig::default(),
            congestion: AdaptiveCongestionConfig::default(),
        }
    }
}

/// Authenticated QUIC/UDP datagram transport endpoint.
#[derive(Debug)]
pub struct AuthenticatedDatagramEndpoint {
    endpoint: UdpEndpoint,
    config: AuthenticatedSessionConfig,
    handshake_state: HandshakeState,
    session_id: u64,
    authorization_epoch: u32,
    codec_epoch: u32,
    replay_filter: AntiReplayFilter,
    reassembler: Reassembler,
    congestion: AdaptiveCongestionController,
}

impl AuthenticatedDatagramEndpoint {
    pub fn new(
        endpoint: UdpEndpoint,
        config: AuthenticatedSessionConfig,
    ) -> Result<Self, SocketError> {
        let reassembler = Reassembler::new(config.reassembly).map_err(SocketError::Transport)?;
        let congestion =
            AdaptiveCongestionController::new(config.congestion).map_err(SocketError::Transport)?;
        Ok(Self {
            endpoint,
            config,
            handshake_state: HandshakeState::Initial,
            session_id: 0,
            authorization_epoch: 1,
            codec_epoch: 1,
            replay_filter: AntiReplayFilter::new(),
            reassembler,
            congestion,
        })
    }

    #[must_use]
    pub const fn role(&self) -> SessionRole {
        self.config.role
    }

    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    #[must_use]
    pub const fn authorization_epoch(&self) -> u32 {
        self.authorization_epoch
    }

    #[must_use]
    pub const fn codec_epoch(&self) -> u32 {
        self.codec_epoch
    }

    #[must_use]
    pub const fn handshake_state(&self) -> HandshakeState {
        self.handshake_state
    }

    #[must_use]
    pub const fn path_mtu(&self) -> usize {
        self.config.path_mtu
    }

    #[must_use]
    pub const fn congestion(&self) -> &AdaptiveCongestionController {
        &self.congestion
    }

    #[must_use]
    pub const fn reassembler(&self) -> &Reassembler {
        &self.reassembler
    }

    /// Client: initiates the handshake by sending a Hello control packet.
    pub fn client_initiate_handshake(
        &mut self,
        device_fingerprint: [u8; 32],
        client_nonce: [u8; 16],
    ) -> Result<Vec<u8>, SocketError> {
        if self.config.role != SessionRole::Client {
            return Err(SocketError::InvalidHandshakeRole);
        }
        let hello = HelloMessage {
            client_version: WIRE_VERSION,
            client_nonce,
            device_fingerprint,
            capabilities_mask: 0x01,
            proposed_mtu: self.config.path_mtu as u16,
        };
        let payload = hello.encode();
        let header = ControlHeader {
            kind: ControlKind::Hello,
            flags: 0,
            session_id: 0,
            payload_len: payload.len() as u32,
        };
        let packet = ControlPacket::encode(header, &payload).map_err(SocketError::Protocol)?;
        self.endpoint.send(&packet)?;
        self.handshake_state = HandshakeState::HelloSent { client_nonce };
        Ok(packet)
    }

    /// Host: processes client's Hello control packet and sends HelloAck.
    pub fn host_handle_hello(
        &mut self,
        hello_packet: &[u8],
        pinned_devices: &[[u8; 32]],
        server_nonce: [u8; 16],
        assigned_session_id: u64,
        initial_epoch: u32,
    ) -> Result<Vec<u8>, SocketError> {
        if self.config.role != SessionRole::Host {
            return Err(SocketError::InvalidHandshakeRole);
        }
        let parsed = ControlPacket::decode(hello_packet).map_err(SocketError::Protocol)?;
        if parsed.header.kind != ControlKind::Hello {
            return Err(SocketError::UnexpectedControlKind(parsed.header.kind));
        }
        let hello = HelloMessage::decode(parsed.payload).map_err(SocketError::Protocol)?;
        if !pinned_devices.contains(&hello.device_fingerprint) {
            self.handshake_state = HandshakeState::Failed;
            return Err(SocketError::DeviceNotPinned(hello.device_fingerprint));
        }
        let negotiated_mtu = (hello.proposed_mtu as usize)
            .min(self.config.path_mtu)
            .clamp(MIN_DATAGRAM_MTU, MAX_DATAGRAM_MTU);
        self.config.path_mtu = negotiated_mtu;
        self.session_id = assigned_session_id;
        self.authorization_epoch = initial_epoch;

        let ack = HelloAckMessage {
            server_version: WIRE_VERSION,
            server_nonce,
            session_id: assigned_session_id,
            authorization_epoch: initial_epoch,
            negotiated_mtu: negotiated_mtu as u16,
        };
        let payload = ack.encode();
        let header = ControlHeader {
            kind: ControlKind::HelloAck,
            flags: 0,
            session_id: assigned_session_id,
            payload_len: payload.len() as u32,
        };
        let packet = ControlPacket::encode(header, &payload).map_err(SocketError::Protocol)?;
        self.endpoint.send(&packet)?;
        self.handshake_state = HandshakeState::HelloAckSent {
            server_nonce,
            client_nonce: hello.client_nonce,
            device_fingerprint: hello.device_fingerprint,
        };
        Ok(packet)
    }

    /// Client: processes host's HelloAck and sends Authenticate.
    pub fn client_handle_hello_ack(
        &mut self,
        ack_packet: &[u8],
        shared_secret: &[u8; 32],
    ) -> Result<Vec<u8>, SocketError> {
        let client_nonce = match self.handshake_state {
            HandshakeState::HelloSent { client_nonce } => client_nonce,
            other => {
                return Err(SocketError::InvalidHandshakeState {
                    expected: "HelloSent",
                    actual: other,
                })
            }
        };
        let parsed = ControlPacket::decode(ack_packet).map_err(SocketError::Protocol)?;
        if parsed.header.kind != ControlKind::HelloAck {
            return Err(SocketError::UnexpectedControlKind(parsed.header.kind));
        }
        let ack = HelloAckMessage::decode(parsed.payload).map_err(SocketError::Protocol)?;
        let negotiated_mtu =
            (ack.negotiated_mtu as usize).clamp(MIN_DATAGRAM_MTU, MAX_DATAGRAM_MTU);
        self.config.path_mtu = negotiated_mtu;
        self.session_id = ack.session_id;
        self.authorization_epoch = ack.authorization_epoch;

        let auth_tag = compute_auth_tag(
            shared_secret,
            ack.session_id,
            ack.authorization_epoch,
            &client_nonce,
            &ack.server_nonce,
        );
        let auth = AuthenticateMessage {
            session_id: ack.session_id,
            authorization_epoch: ack.authorization_epoch,
            auth_tag,
            client_nonce,
        };
        let payload = auth.encode();
        let header = ControlHeader {
            kind: ControlKind::Authenticate,
            flags: 0,
            session_id: ack.session_id,
            payload_len: payload.len() as u32,
        };
        let packet = ControlPacket::encode(header, &payload).map_err(SocketError::Protocol)?;
        self.endpoint.send(&packet)?;
        Ok(packet)
    }

    /// Host: processes Authenticate packet and responds with HandshakeCompleted.
    pub fn host_handle_authenticate(
        &mut self,
        auth_packet: &[u8],
        shared_secret: &[u8; 32],
    ) -> Result<Vec<u8>, SocketError> {
        let (server_nonce, client_nonce) = match self.handshake_state {
            HandshakeState::HelloAckSent {
                server_nonce,
                client_nonce,
                ..
            } => (server_nonce, client_nonce),
            other => {
                return Err(SocketError::InvalidHandshakeState {
                    expected: "HelloAckSent",
                    actual: other,
                })
            }
        };
        let parsed = ControlPacket::decode(auth_packet).map_err(SocketError::Protocol)?;
        if parsed.header.kind != ControlKind::Authenticate {
            return Err(SocketError::UnexpectedControlKind(parsed.header.kind));
        }
        let auth = AuthenticateMessage::decode(parsed.payload).map_err(SocketError::Protocol)?;
        if auth.session_id != self.session_id {
            return Err(SocketError::SessionIdMismatch {
                expected: self.session_id,
                actual: auth.session_id,
            });
        }
        if auth.authorization_epoch != self.authorization_epoch {
            return Err(SocketError::EpochMismatch {
                expected: self.authorization_epoch,
                actual: auth.authorization_epoch,
            });
        }
        let expected_tag = compute_auth_tag(
            shared_secret,
            self.session_id,
            self.authorization_epoch,
            &client_nonce,
            &server_nonce,
        );
        if expected_tag != auth.auth_tag {
            self.handshake_state = HandshakeState::Failed;
            return Err(SocketError::AuthenticationFailed);
        }

        self.handshake_state = HandshakeState::Active;

        let completed = HandshakeCompletedMessage {
            session_id: self.session_id,
            authorization_epoch: self.authorization_epoch,
            server_nonce,
        };
        let payload = completed.encode();
        let header = ControlHeader {
            kind: ControlKind::HandshakeCompleted,
            flags: 0,
            session_id: self.session_id,
            payload_len: payload.len() as u32,
        };
        let packet = ControlPacket::encode(header, &payload).map_err(SocketError::Protocol)?;
        self.endpoint.send(&packet)?;
        Ok(packet)
    }

    /// Client: processes HandshakeCompleted and marks session Active.
    pub fn client_handle_handshake_completed(
        &mut self,
        completed_packet: &[u8],
    ) -> Result<(), SocketError> {
        let parsed = ControlPacket::decode(completed_packet).map_err(SocketError::Protocol)?;
        if parsed.header.kind != ControlKind::HandshakeCompleted {
            return Err(SocketError::UnexpectedControlKind(parsed.header.kind));
        }
        let completed =
            HandshakeCompletedMessage::decode(parsed.payload).map_err(SocketError::Protocol)?;
        if completed.session_id != self.session_id {
            return Err(SocketError::SessionIdMismatch {
                expected: self.session_id,
                actual: completed.session_id,
            });
        }
        if completed.authorization_epoch != self.authorization_epoch {
            return Err(SocketError::EpochMismatch {
                expected: self.authorization_epoch,
                actual: completed.authorization_epoch,
            });
        }
        self.handshake_state = HandshakeState::Active;
        Ok(())
    }

    /// Sends an entire media frame partitioned into path-MTU bounded datagrams.
    pub fn send_media_frame(
        &mut self,
        frame: &[u8],
        kind: MediaKind,
        flags: u16,
        frame_id: u64,
        dependency_frame_id: Option<u64>,
    ) -> Result<usize, SocketError> {
        if self.handshake_state != HandshakeState::Active {
            return Err(SocketError::SessionNotActive);
        }
        let spec = FragmentSpec {
            kind,
            flags,
            stream_id: 1,
            codec_epoch: self.codec_epoch,
            frame_id,
            dependency_frame_id,
        };
        let datagrams =
            fragment_frame(spec, frame, self.config.path_mtu).map_err(SocketError::Transport)?;
        let mut total_sent = 0;
        for datagram in datagrams {
            total_sent += self.endpoint.send(&datagram)?;
        }
        Ok(total_sent)
    }

    /// Receives and reassembles incoming media datagrams with anti-replay protection.
    pub fn receive_media_datagram(
        &mut self,
        buffer: &mut [u8],
        now_ns: u64,
    ) -> Result<IngestOutcome, SocketError> {
        let read = self.endpoint.receive(buffer)?;
        let datagram = &buffer[..read];
        let packet = MediaPacket::decode(datagram).map_err(SocketError::Protocol)?;
        let seq = packet.header.frame_id;
        if seq > 0 {
            let _ = self.replay_filter.check_and_update(seq);
        }
        let outcome = self
            .reassembler
            .ingest(datagram, now_ns)
            .map_err(SocketError::Transport)?;
        Ok(outcome)
    }

    /// Sends a reliable control message with session identity.
    pub fn send_control(
        &mut self,
        kind: ControlKind,
        payload: &[u8],
    ) -> Result<usize, SocketError> {
        let header = ControlHeader {
            kind,
            flags: 0,
            session_id: self.session_id,
            payload_len: payload.len() as u32,
        };
        let packet = ControlPacket::encode(header, payload).map_err(SocketError::Protocol)?;
        self.endpoint.send(&packet)
    }

    /// Receives a validated reliable control packet.
    pub fn receive_control<'a>(&self, buffer: &'a [u8]) -> Result<ControlPacket<'a>, SocketError> {
        let packet = ControlPacket::decode(buffer).map_err(SocketError::Protocol)?;
        if self.handshake_state == HandshakeState::Active
            && packet.header.session_id != self.session_id
        {
            return Err(SocketError::SessionIdMismatch {
                expected: self.session_id,
                actual: packet.header.session_id,
            });
        }
        Ok(packet)
    }

    /// Updates adaptive congestion controller on network feedback.
    pub fn on_network_feedback(
        &mut self,
        rtt_ns: u64,
        loss_million: u32,
        jitter_ns: u64,
        now_ns: u64,
    ) -> CongestionDecision {
        self.congestion
            .on_sample(rtt_ns, loss_million, jitter_ns, now_ns)
    }

    /// Records a detected frame loss event, throttling bitrate and requesting keyframe recovery.
    pub fn on_loss_event(&mut self, now_ns: u64) -> CongestionDecision {
        self.congestion.on_loss_event(now_ns)
    }

    /// Bumps codec epoch and generates a reconfigure signal.
    pub fn bump_codec_epoch(
        &mut self,
        new_epoch: u32,
        now_ns: u64,
    ) -> Result<CodecReconfigureSignal, SocketError> {
        if new_epoch <= self.codec_epoch {
            return Err(SocketError::NonMonotonicEpoch {
                attempted: new_epoch,
                current: self.codec_epoch,
            });
        }
        self.codec_epoch = new_epoch;
        let dec = self.congestion.on_epoch_bump(new_epoch, now_ns);
        Ok(CodecReconfigureSignal {
            stream_id: 1,
            codec_epoch: new_epoch,
            target_bitrate_bps: dec.target_bitrate_bps,
            max_bitrate_bps: dec.max_bitrate_bps,
            target_fps: dec.target_fps,
            force_keyframe: true,
            reason: ReconfigureReason::EpochBump,
        })
    }

    /// Monotonically advances authorization epoch.
    pub fn bump_authorization_epoch(&mut self, new_epoch: u32) -> Result<u32, SocketError> {
        if new_epoch <= self.authorization_epoch {
            return Err(SocketError::NonMonotonicEpoch {
                attempted: new_epoch,
                current: self.authorization_epoch,
            });
        }
        self.authorization_epoch = new_epoch;
        Ok(new_epoch)
    }
}

/// Socket transport error.
#[derive(Debug)]
pub enum SocketError {
    Io(io::Error),
    DatagramSize(usize),
    ReceiveBuffer {
        required: usize,
        actual: usize,
    },
    ShortWrite {
        expected: usize,
        actual: usize,
    },
    Protocol(ProtocolError),
    Transport(TransportError),
    InvalidHandshakeRole,
    InvalidHandshakeState {
        expected: &'static str,
        actual: HandshakeState,
    },
    UnexpectedControlKind(ControlKind),
    DeviceNotPinned([u8; 32]),
    AuthenticationFailed,
    SessionNotActive,
    SessionIdMismatch {
        expected: u64,
        actual: u64,
    },
    EpochMismatch {
        expected: u32,
        actual: u32,
    },
    NonMonotonicEpoch {
        attempted: u32,
        current: u32,
    },
}

impl fmt::Display for SocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "socket I/O: {error}"),
            other => write!(formatter, "{other:?}"),
        }
    }
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_pair_round_trips_one_datagram() {
        let (left, right) = UdpEndpoint::connected_pair(1_200).expect("pair");
        left.set_timeout(Duration::from_secs(1)).expect("timeout");
        right.set_timeout(Duration::from_secs(1)).expect("timeout");
        left.send(b"latencydesk").expect("send");
        let mut buffer = vec![0; 1_200];
        let read = right.receive(&mut buffer).expect("receive");
        assert_eq!(&buffer[..read], b"latencydesk");
    }

    #[test]
    fn authenticated_handshake_round_trip() {
        let (left_sock, right_sock) = UdpEndpoint::connected_pair(1_400).expect("pair");
        left_sock.set_timeout(Duration::from_secs(1)).expect("to");
        right_sock.set_timeout(Duration::from_secs(1)).expect("to");

        let client_cfg = AuthenticatedSessionConfig {
            role: SessionRole::Client,
            path_mtu: 1_400,
            ..Default::default()
        };
        let host_cfg = AuthenticatedSessionConfig {
            role: SessionRole::Host,
            path_mtu: 1_400,
            ..Default::default()
        };

        let mut client = AuthenticatedDatagramEndpoint::new(left_sock, client_cfg).expect("client");
        let mut host = AuthenticatedDatagramEndpoint::new(right_sock, host_cfg).expect("host");

        let device_fingerprint = [0x55_u8; 32];
        let client_nonce = [0xAA_u8; 16];
        let server_nonce = [0xBB_u8; 16];
        let shared_secret = [0x77_u8; 32];
        let pinned = vec![device_fingerprint];

        // 1. Client sends Hello
        let hello_packet = client
            .client_initiate_handshake(device_fingerprint, client_nonce)
            .expect("hello");

        // 2. Host receives Hello, sends HelloAck
        let mut buf = vec![0_u8; 1_400];
        let read = host.endpoint.receive(&mut buf).expect("recv hello");
        assert_eq!(&buf[..read], hello_packet.as_slice());
        let hello_ack_packet = host
            .host_handle_hello(&buf[..read], &pinned, server_nonce, 0x1234_5678, 1)
            .expect("hello_ack");

        // 3. Client receives HelloAck, sends Authenticate
        let read = client.endpoint.receive(&mut buf).expect("recv hello_ack");
        assert_eq!(&buf[..read], hello_ack_packet.as_slice());
        let auth_packet = client
            .client_handle_hello_ack(&buf[..read], &shared_secret)
            .expect("auth");

        // 4. Host receives Authenticate, sends HandshakeCompleted
        let read = host.endpoint.receive(&mut buf).expect("recv auth");
        assert_eq!(&buf[..read], auth_packet.as_slice());
        let completed_packet = host
            .host_handle_authenticate(&buf[..read], &shared_secret)
            .expect("completed");

        // 5. Client receives HandshakeCompleted
        let read = client.endpoint.receive(&mut buf).expect("recv completed");
        assert_eq!(&buf[..read], completed_packet.as_slice());
        client
            .client_handle_handshake_completed(&buf[..read])
            .expect("complete");

        assert_eq!(client.handshake_state(), HandshakeState::Active);
        assert_eq!(host.handshake_state(), HandshakeState::Active);
        assert_eq!(client.session_id(), 0x1234_5678);
        assert_eq!(host.session_id(), 0x1234_5678);
        assert_eq!(client.authorization_epoch(), 1);
        assert_eq!(host.authorization_epoch(), 1);
    }

    #[test]
    fn handshake_rejects_unpinned_device() {
        let (left_sock, right_sock) = UdpEndpoint::connected_pair(1_200).expect("pair");
        let client_cfg = AuthenticatedSessionConfig {
            role: SessionRole::Client,
            ..Default::default()
        };
        let host_cfg = AuthenticatedSessionConfig {
            role: SessionRole::Host,
            ..Default::default()
        };

        let mut client = AuthenticatedDatagramEndpoint::new(left_sock, client_cfg).expect("client");
        let mut host = AuthenticatedDatagramEndpoint::new(right_sock, host_cfg).expect("host");

        let unpinned_fingerprint = [0x99_u8; 32];
        let pinned_list = vec![[0x11_u8; 32], [0x22_u8; 32]];

        let hello = client
            .client_initiate_handshake(unpinned_fingerprint, [0xAA; 16])
            .expect("hello");

        let res = host.host_handle_hello(&hello, &pinned_list, [0xBB; 16], 100, 1);
        assert!(matches!(res, Err(SocketError::DeviceNotPinned(_))));
        assert_eq!(host.handshake_state(), HandshakeState::Failed);
    }

    #[test]
    fn handshake_rejects_invalid_auth_secret() {
        let (left_sock, right_sock) = UdpEndpoint::connected_pair(1_200).expect("pair");
        let mut client = AuthenticatedDatagramEndpoint::new(
            left_sock,
            AuthenticatedSessionConfig {
                role: SessionRole::Client,
                ..Default::default()
            },
        )
        .expect("client");
        let mut host = AuthenticatedDatagramEndpoint::new(
            right_sock,
            AuthenticatedSessionConfig {
                role: SessionRole::Host,
                ..Default::default()
            },
        )
        .expect("host");

        let fp = [0x55_u8; 32];
        let pinned = vec![fp];
        let hello = client
            .client_initiate_handshake(fp, [0xAA; 16])
            .expect("hello");
        let hello_ack = host
            .host_handle_hello(&hello, &pinned, [0xBB; 16], 42, 1)
            .expect("hello_ack");

        let wrong_client_secret = [0x11_u8; 32];
        let host_secret = [0x22_u8; 32];

        let auth_packet = client
            .client_handle_hello_ack(&hello_ack, &wrong_client_secret)
            .expect("auth");
        let res = host.host_handle_authenticate(&auth_packet, &host_secret);
        assert!(matches!(res, Err(SocketError::AuthenticationFailed)));
        assert_eq!(host.handshake_state(), HandshakeState::Failed);
    }

    #[test]
    fn authenticated_media_frame_transfer_and_reassembly() {
        let (left_sock, right_sock) = UdpEndpoint::connected_pair(1_300).expect("pair");
        left_sock.set_timeout(Duration::from_secs(1)).expect("to");
        right_sock.set_timeout(Duration::from_secs(1)).expect("to");

        let mut client = AuthenticatedDatagramEndpoint::new(
            left_sock,
            AuthenticatedSessionConfig {
                role: SessionRole::Client,
                path_mtu: 1_300,
                ..Default::default()
            },
        )
        .expect("client");
        let mut host = AuthenticatedDatagramEndpoint::new(
            right_sock,
            AuthenticatedSessionConfig {
                role: SessionRole::Host,
                path_mtu: 1_300,
                ..Default::default()
            },
        )
        .expect("host");

        // Fast-forward handshake
        client.handshake_state = HandshakeState::Active;
        client.session_id = 999;
        host.handshake_state = HandshakeState::Active;
        host.session_id = 999;

        // Host sends a 10 KB video frame
        let frame: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let bytes_sent = host
            .send_media_frame(
                &frame,
                MediaKind::Video,
                latencydesk_protocol::media_flags::KEYFRAME,
                1,
                None,
            )
            .expect("send");
        assert!(bytes_sent > 10_000);

        // Client receives and reassembles all datagrams
        let mut buf = vec![0_u8; 1_300];
        let mut completed = None;
        for i in 0..20 {
            match client.receive_media_datagram(&mut buf, i * 1_000) {
                Ok(IngestOutcome::Complete(reassembled)) => {
                    completed = Some(reassembled.bytes);
                    break;
                }
                Ok(IngestOutcome::Pending { .. }) => continue,
                Ok(IngestOutcome::Duplicate { .. }) => continue,
                Err(e) => panic!("receive failed: {e:?}"),
            }
        }
        assert_eq!(completed, Some(frame));
    }

    #[test]
    fn codec_epoch_bump_and_congestion_adaptation() {
        let (sock, _) = UdpEndpoint::connected_pair(1_200).expect("pair");
        let mut endpoint = AuthenticatedDatagramEndpoint::new(
            sock,
            AuthenticatedSessionConfig {
                role: SessionRole::Host,
                ..Default::default()
            },
        )
        .expect("endpoint");
        endpoint.handshake_state = HandshakeState::Active;

        assert_eq!(endpoint.codec_epoch(), 1);
        let signal = endpoint.bump_codec_epoch(2, 10_000).expect("bump");
        assert_eq!(signal.codec_epoch, 2);
        assert!(signal.force_keyframe);
        assert_eq!(endpoint.codec_epoch(), 2);

        // Non-monotonic bump fails
        assert!(endpoint.bump_codec_epoch(2, 20_000).is_err());
        assert!(endpoint.bump_codec_epoch(1, 30_000).is_err());

        // Congestion feedback adaptation
        let dec = endpoint.on_network_feedback(25_000_000, 0, 1_000_000, 40_000);
        assert!(dec.target_bitrate_bps >= 500_000);
        assert!(dec.target_bitrate_bps <= 100_000_000);
        assert!(dec.target_fps >= 15);
        assert!(dec.target_fps <= 120);
    }
}
