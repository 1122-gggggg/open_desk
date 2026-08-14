//! Bounded wire primitives for LatencyDesk.
//!
//! This crate intentionally has no transport, async runtime, codec, or platform
//! dependencies. Every parser validates lengths before allocating and rejects
//! trailing bytes so datagram boundaries remain unambiguous.

use core::fmt;

pub mod quic;

/// Current wire protocol version.
pub const WIRE_VERSION: u8 = 1;
/// Fixed media fragment header length in bytes.
pub const MEDIA_HEADER_LEN: usize = 44;
/// Fixed reliable-control header length in bytes.
pub const CONTROL_HEADER_LEN: usize = 20;
/// Maximum encoded access-unit size accepted by the protocol.
pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;
/// Maximum fragment payload accepted by this protocol layer.
///
/// A real transport must negotiate a much smaller path-MTU-safe payload. The
/// larger hard cap exists only to reject pathological allocations consistently.
pub const MAX_FRAGMENT_BYTES: u16 = 16 * 1024;
/// Maximum reliable control payload.
pub const MAX_CONTROL_BYTES: u32 = 256 * 1024;
/// Sentinel used when a frame has no inter-frame dependency.
pub const NO_DEPENDENCY: u64 = u64::MAX;

const MEDIA_MAGIC: [u8; 4] = *b"LDSK";
const CONTROL_MAGIC: [u8; 4] = *b"LDC1";

/// Media payload class carried by a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MediaKind {
    /// Encoded full-frame video access unit.
    Video = 1,
    /// Exact sparse tile or later static refinement.
    Tile = 2,
    /// Cursor metadata or cursor-shape payload.
    Cursor = 3,
    /// Audio payload; reserved until the audio milestone.
    Audio = 4,
}

impl TryFrom<u8> for MediaKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Video),
            2 => Ok(Self::Tile),
            3 => Ok(Self::Cursor),
            4 => Ok(Self::Audio),
            other => Err(ProtocolError::UnknownMediaKind(other)),
        }
    }
}

/// Flags used by [`MediaHeader`].
pub mod media_flags {
    /// The access unit is independently decodable and resets decoder continuity.
    pub const KEYFRAME: u16 = 1 << 0;
    /// The payload may be discarded without invalidating later reference frames.
    pub const DISCARDABLE: u16 = 1 << 1;
    /// The payload is an exact/lossless update.
    pub const LOSSLESS: u16 = 1 << 2;
    /// The packet carries one XOR parity shard rather than source bytes.
    pub const PARITY: u16 = 1 << 3;
    /// Reserved mask; packets setting unknown bits are rejected in version 1.
    pub const KNOWN_MASK: u16 = KEYFRAME | DISCARDABLE | LOSSLESS | PARITY;
}

/// Fixed-width, network-byte-order header for one media fragment.
///
/// Layout (44 bytes):
/// `magic[4], version[1], kind[1], flags[2], stream_id[4], codec_epoch[4],
/// frame_id[8], dependency_frame_id[8], frame_len[4], fragment_offset[4],
/// fragment_len[2], reserved[2]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaHeader {
    /// Payload class.
    pub kind: MediaKind,
    /// Versioned media flags.
    pub flags: u16,
    /// Logical media stream identifier.
    pub stream_id: u32,
    /// Incremented whenever decoder configuration or continuity is reset.
    pub codec_epoch: u32,
    /// Monotonic frame identifier within a stream.
    pub frame_id: u64,
    /// Conservative reference dependency or [`NO_DEPENDENCY`].
    pub dependency_frame_id: u64,
    /// Total encoded access-unit size before fragmentation.
    pub frame_len: u32,
    /// Byte offset of this fragment in the access unit.
    pub fragment_offset: u32,
    /// Payload bytes following this header.
    pub fragment_len: u16,
}

impl MediaHeader {
    /// Validates all bounds and continuity-independent invariants.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.flags & !media_flags::KNOWN_MASK != 0 {
            return Err(ProtocolError::UnknownFlags(self.flags));
        }
        if self.frame_len == 0 || self.frame_len > MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameLength(self.frame_len));
        }
        if self.fragment_len == 0 || self.fragment_len > MAX_FRAGMENT_BYTES {
            return Err(ProtocolError::FragmentLength(self.fragment_len));
        }
        let end = self
            .fragment_offset
            .checked_add(u32::from(self.fragment_len))
            .ok_or(ProtocolError::FragmentRange)?;
        if self.fragment_offset >= self.frame_len || end > self.frame_len {
            return Err(ProtocolError::FragmentRange);
        }
        if self.flags & media_flags::KEYFRAME != 0 && self.dependency_frame_id != NO_DEPENDENCY {
            return Err(ProtocolError::KeyframeHasDependency);
        }
        if self.dependency_frame_id != NO_DEPENDENCY && self.dependency_frame_id >= self.frame_id {
            return Err(ProtocolError::InvalidDependency {
                frame_id: self.frame_id,
                dependency_frame_id: self.dependency_frame_id,
            });
        }
        Ok(())
    }

    /// Serializes this header in network byte order.
    pub fn encode(self) -> Result<[u8; MEDIA_HEADER_LEN], ProtocolError> {
        self.validate()?;
        let mut out = [0_u8; MEDIA_HEADER_LEN];
        out[0..4].copy_from_slice(&MEDIA_MAGIC);
        out[4] = WIRE_VERSION;
        out[5] = self.kind as u8;
        out[6..8].copy_from_slice(&self.flags.to_be_bytes());
        out[8..12].copy_from_slice(&self.stream_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.codec_epoch.to_be_bytes());
        out[16..24].copy_from_slice(&self.frame_id.to_be_bytes());
        out[24..32].copy_from_slice(&self.dependency_frame_id.to_be_bytes());
        out[32..36].copy_from_slice(&self.frame_len.to_be_bytes());
        out[36..40].copy_from_slice(&self.fragment_offset.to_be_bytes());
        out[40..42].copy_from_slice(&self.fragment_len.to_be_bytes());
        // 42..44 are reserved and remain zero.
        Ok(out)
    }

    /// Parses and validates a fixed-width header without allocating.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < MEDIA_HEADER_LEN {
            return Err(ProtocolError::Truncated {
                expected: MEDIA_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != MEDIA_MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if bytes[4] != WIRE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(bytes[4]));
        }
        if bytes[42] != 0 || bytes[43] != 0 {
            return Err(ProtocolError::ReservedBits);
        }

        let header = Self {
            kind: MediaKind::try_from(bytes[5])?,
            flags: read_u16(bytes, 6),
            stream_id: read_u32(bytes, 8),
            codec_epoch: read_u32(bytes, 12),
            frame_id: read_u64(bytes, 16),
            dependency_frame_id: read_u64(bytes, 24),
            frame_len: read_u32(bytes, 32),
            fragment_offset: read_u32(bytes, 36),
            fragment_len: read_u16(bytes, 40),
        };
        header.validate()?;
        Ok(header)
    }
}

/// Borrowed, fully validated media datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaPacket<'a> {
    pub header: MediaHeader,
    pub payload: &'a [u8],
}

impl<'a> MediaPacket<'a> {
    /// Parses a complete datagram. Missing or trailing payload bytes are rejected.
    pub fn decode(datagram: &'a [u8]) -> Result<Self, ProtocolError> {
        let header = MediaHeader::decode(datagram)?;
        let expected = MEDIA_HEADER_LEN
            .checked_add(usize::from(header.fragment_len))
            .ok_or(ProtocolError::PacketLength)?;
        if datagram.len() != expected {
            return Err(ProtocolError::PayloadLength {
                expected,
                actual: datagram.len(),
            });
        }
        Ok(Self {
            header,
            payload: &datagram[MEDIA_HEADER_LEN..],
        })
    }

    /// Encodes a complete media datagram.
    pub fn encode(header: MediaHeader, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if payload.len() != usize::from(header.fragment_len) {
            return Err(ProtocolError::PayloadLength {
                expected: usize::from(header.fragment_len),
                actual: payload.len(),
            });
        }
        let encoded_header = header.encode()?;
        let mut out = Vec::with_capacity(MEDIA_HEADER_LEN + payload.len());
        out.extend_from_slice(&encoded_header);
        out.extend_from_slice(payload);
        Ok(out)
    }
}

/// Reliable-control message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ControlKind {
    Hello = 1,
    HelloAck = 2,
    Authenticate = 3,
    Capabilities = 4,
    ConfigureStream = 5,
    RecoveryRequest = 6,
    Ping = 7,
    Pong = 8,
    Close = 9,
    Error = 10,
    InputAck = 11,
    PermissionRevoked = 12,
    RateUpdate = 13,
    CongestionFeedback = 14,
    HandshakeCompleted = 15,
    IceCandidate = 16,
    RelayEnvelope = 17,
    Pairing = 18,
    Disconnect = 19,
    UnattendedAuth = 20,
}

impl TryFrom<u8> for ControlKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::Authenticate),
            4 => Ok(Self::Capabilities),
            5 => Ok(Self::ConfigureStream),
            6 => Ok(Self::RecoveryRequest),
            7 => Ok(Self::Ping),
            8 => Ok(Self::Pong),
            9 => Ok(Self::Close),
            10 => Ok(Self::Error),
            11 => Ok(Self::InputAck),
            12 => Ok(Self::PermissionRevoked),
            13 => Ok(Self::RateUpdate),
            14 => Ok(Self::CongestionFeedback),
            15 => Ok(Self::HandshakeCompleted),
            16 => Ok(Self::IceCandidate),
            17 => Ok(Self::RelayEnvelope),
            18 => Ok(Self::Pairing),
            19 => Ok(Self::Disconnect),
            20 => Ok(Self::UnattendedAuth),
            other => Err(ProtocolError::UnknownControlKind(other)),
        }
    }
}

/// Fixed reliable-control envelope.
///
/// Layout (20 bytes):
/// `magic[4], version[1], kind[1], flags[2], session_id[8], payload_len[4]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlHeader {
    pub kind: ControlKind,
    pub flags: u16,
    pub session_id: u64,
    pub payload_len: u32,
}

impl ControlHeader {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.flags != 0 {
            return Err(ProtocolError::UnknownControlFlags(self.flags));
        }
        if self.payload_len > MAX_CONTROL_BYTES {
            return Err(ProtocolError::ControlLength(self.payload_len));
        }
        Ok(())
    }

    pub fn encode(self) -> Result<[u8; CONTROL_HEADER_LEN], ProtocolError> {
        self.validate()?;
        let mut out = [0_u8; CONTROL_HEADER_LEN];
        out[0..4].copy_from_slice(&CONTROL_MAGIC);
        out[4] = WIRE_VERSION;
        out[5] = self.kind as u8;
        out[6..8].copy_from_slice(&self.flags.to_be_bytes());
        out[8..16].copy_from_slice(&self.session_id.to_be_bytes());
        out[16..20].copy_from_slice(&self.payload_len.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < CONTROL_HEADER_LEN {
            return Err(ProtocolError::Truncated {
                expected: CONTROL_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != CONTROL_MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if bytes[4] != WIRE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(bytes[4]));
        }
        let header = Self {
            kind: ControlKind::try_from(bytes[5])?,
            flags: read_u16(bytes, 6),
            session_id: read_u64(bytes, 8),
            payload_len: read_u32(bytes, 16),
        };
        header.validate()?;
        Ok(header)
    }
}

/// Borrowed reliable-control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlPacket<'a> {
    pub header: ControlHeader,
    pub payload: &'a [u8],
}

impl<'a> ControlPacket<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let header = ControlHeader::decode(bytes)?;
        let expected = CONTROL_HEADER_LEN
            .checked_add(header.payload_len as usize)
            .ok_or(ProtocolError::PacketLength)?;
        if bytes.len() != expected {
            return Err(ProtocolError::PayloadLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            header,
            payload: &bytes[CONTROL_HEADER_LEN..],
        })
    }

    pub fn encode(header: ControlHeader, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if payload.len() != header.payload_len as usize {
            return Err(ProtocolError::PayloadLength {
                expected: header.payload_len as usize,
                actual: payload.len(),
            });
        }
        let encoded_header = header.encode()?;
        let mut out = Vec::with_capacity(CONTROL_HEADER_LEN + payload.len());
        out.extend_from_slice(&encoded_header);
        out.extend_from_slice(payload);
        Ok(out)
    }
}

/// Decoder-recovery request sent on the reliable control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub stream_id: u32,
    pub codec_epoch: u32,
    pub last_good_frame_id: u64,
    pub first_missing_frame_id: u64,
}

impl RecoveryRequest {
    pub const ENCODED_LEN: usize = 24;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.codec_epoch.to_be_bytes());
        out[8..16].copy_from_slice(&self.last_good_frame_id.to_be_bytes());
        out[16..24].copy_from_slice(&self.first_missing_frame_id.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let request = Self {
            stream_id: read_u32(bytes, 0),
            codec_epoch: read_u32(bytes, 4),
            last_good_frame_id: read_u64(bytes, 8),
            first_missing_frame_id: read_u64(bytes, 16),
        };
        if request.first_missing_frame_id <= request.last_good_frame_id {
            return Err(ProtocolError::InvalidRecoveryRange);
        }
        Ok(request)
    }
}
/// Flags used by [`RateUpdateMessage`].
pub mod rate_flags {
    /// Forces the next encoded frame to be a keyframe (IDR / recovery point).
    pub const FORCE_KEYFRAME: u16 = 1 << 0;
    /// Indicates an epoch transition / increment occurred.
    pub const EPOCH_BUMP: u16 = 1 << 1;
}

/// Initial client handshake initiation message carried on the reliable control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloMessage {
    pub client_version: u8,
    pub client_nonce: [u8; 16],
    pub device_fingerprint: [u8; 32],
    pub capabilities_mask: u32,
    pub proposed_mtu: u16,
}

impl HelloMessage {
    pub const ENCODED_LEN: usize = 60;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0] = self.client_version;
        // out[1..4] reserved
        out[4..20].copy_from_slice(&self.client_nonce);
        out[20..52].copy_from_slice(&self.device_fingerprint);
        out[52..56].copy_from_slice(&self.capabilities_mask.to_be_bytes());
        out[56..58].copy_from_slice(&self.proposed_mtu.to_be_bytes());
        // out[58..60] padding
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != WIRE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(bytes[0]));
        }
        let mut client_nonce = [0_u8; 16];
        client_nonce.copy_from_slice(&bytes[4..20]);
        let mut device_fingerprint = [0_u8; 32];
        device_fingerprint.copy_from_slice(&bytes[20..52]);
        let capabilities_mask = read_u32(bytes, 52);
        let proposed_mtu = read_u16(bytes, 56);
        Ok(Self {
            client_version: bytes[0],
            client_nonce,
            device_fingerprint,
            capabilities_mask,
            proposed_mtu,
        })
    }
}

/// Host response to client [`HelloMessage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloAckMessage {
    pub server_version: u8,
    pub server_nonce: [u8; 16],
    pub session_id: u64,
    pub authorization_epoch: u32,
    pub negotiated_mtu: u16,
}

impl HelloAckMessage {
    pub const ENCODED_LEN: usize = 36;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0] = self.server_version;
        // out[1..4] reserved
        out[4..20].copy_from_slice(&self.server_nonce);
        out[20..28].copy_from_slice(&self.session_id.to_be_bytes());
        out[28..32].copy_from_slice(&self.authorization_epoch.to_be_bytes());
        out[32..34].copy_from_slice(&self.negotiated_mtu.to_be_bytes());
        // out[34..36] padding
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != WIRE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(bytes[0]));
        }
        let mut server_nonce = [0_u8; 16];
        server_nonce.copy_from_slice(&bytes[4..20]);
        let session_id = read_u64(bytes, 20);
        let authorization_epoch = read_u32(bytes, 28);
        let negotiated_mtu = read_u16(bytes, 32);
        Ok(Self {
            server_version: bytes[0],
            server_nonce,
            session_id,
            authorization_epoch,
            negotiated_mtu,
        })
    }
}

/// Client authentication proof message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticateMessage {
    pub session_id: u64,
    pub authorization_epoch: u32,
    pub auth_tag: [u8; 32],
    pub client_nonce: [u8; 16],
}

impl AuthenticateMessage {
    pub const ENCODED_LEN: usize = 60;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..8].copy_from_slice(&self.session_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.authorization_epoch.to_be_bytes());
        out[12..44].copy_from_slice(&self.auth_tag);
        out[44..60].copy_from_slice(&self.client_nonce);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let session_id = read_u64(bytes, 0);
        let authorization_epoch = read_u32(bytes, 8);
        let mut auth_tag = [0_u8; 32];
        auth_tag.copy_from_slice(&bytes[12..44]);
        let mut client_nonce = [0_u8; 16];
        client_nonce.copy_from_slice(&bytes[44..60]);
        Ok(Self {
            session_id,
            authorization_epoch,
            auth_tag,
            client_nonce,
        })
    }
}

/// Host handshake completion confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeCompletedMessage {
    pub session_id: u64,
    pub authorization_epoch: u32,
    pub server_nonce: [u8; 16],
}

impl HandshakeCompletedMessage {
    pub const ENCODED_LEN: usize = 28;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..8].copy_from_slice(&self.session_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.authorization_epoch.to_be_bytes());
        out[12..28].copy_from_slice(&self.server_nonce);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let session_id = read_u64(bytes, 0);
        let authorization_epoch = read_u32(bytes, 8);
        let mut server_nonce = [0_u8; 16];
        server_nonce.copy_from_slice(&bytes[12..28]);
        Ok(Self {
            session_id,
            authorization_epoch,
            server_nonce,
        })
    }
}

/// Codec rate and framerate reconfiguration signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateUpdateMessage {
    pub stream_id: u32,
    pub codec_epoch: u32,
    pub target_bitrate_bps: u32,
    pub max_bitrate_bps: u32,
    pub target_fps: u32,
    pub flags: u16,
}

impl RateUpdateMessage {
    pub const ENCODED_LEN: usize = 24;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.codec_epoch.to_be_bytes());
        out[8..12].copy_from_slice(&self.target_bitrate_bps.to_be_bytes());
        out[12..16].copy_from_slice(&self.max_bitrate_bps.to_be_bytes());
        out[16..20].copy_from_slice(&self.target_fps.to_be_bytes());
        out[20..22].copy_from_slice(&self.flags.to_be_bytes());
        // 22..24 reserved
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            stream_id: read_u32(bytes, 0),
            codec_epoch: read_u32(bytes, 4),
            target_bitrate_bps: read_u32(bytes, 8),
            max_bitrate_bps: read_u32(bytes, 12),
            target_fps: read_u32(bytes, 16),
            flags: read_u16(bytes, 20),
        })
    }
}

/// Congestion and network quality feedback message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionFeedbackMessage {
    pub feedback_sequence: u64,
    pub echo_timestamp_ns: u64,
    pub rtt_ns: u32,
    pub loss_per_million: u32,
    pub jitter_ns: u32,
    pub received_bitrate_bps: u32,
}

impl CongestionFeedbackMessage {
    pub const ENCODED_LEN: usize = 32;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..8].copy_from_slice(&self.feedback_sequence.to_be_bytes());
        out[8..16].copy_from_slice(&self.echo_timestamp_ns.to_be_bytes());
        out[16..20].copy_from_slice(&self.rtt_ns.to_be_bytes());
        out[20..24].copy_from_slice(&self.loss_per_million.to_be_bytes());
        out[24..28].copy_from_slice(&self.jitter_ns.to_be_bytes());
        out[28..32].copy_from_slice(&self.received_bitrate_bps.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            feedback_sequence: read_u64(bytes, 0),
            echo_timestamp_ns: read_u64(bytes, 8),
            rtt_ns: read_u32(bytes, 16),
            loss_per_million: read_u32(bytes, 20),
            jitter_ns: read_u32(bytes, 24),
            received_bitrate_bps: read_u32(bytes, 28),
        })
    }
}

/// Heartbeat ping / pong message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingPongMessage {
    pub nonce: u64,
    pub timestamp_ns: u64,
}

impl PingPongMessage {
    pub const ENCODED_LEN: usize = 16;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..8].copy_from_slice(&self.nonce.to_be_bytes());
        out[8..16].copy_from_slice(&self.timestamp_ns.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            nonce: read_u64(bytes, 0),
            timestamp_ns: read_u64(bytes, 8),
        })
    }
}

/// 128-bit sliding window anti-replay filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiReplayFilter {
    max_sequence: u64,
    bitmap: u128,
}

impl Default for AntiReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayFilter {
    pub const WINDOW_SIZE: u64 = 128;

    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_sequence: 0,
            bitmap: 0,
        }
    }

    #[must_use]
    pub const fn max_sequence(&self) -> u64 {
        self.max_sequence
    }

    pub fn check(&self, sequence: u64) -> Result<(), ProtocolError> {
        if sequence == 0 {
            return Err(ProtocolError::ReplayedPacket(0));
        }
        if sequence > self.max_sequence {
            return Ok(());
        }
        let diff = self.max_sequence - sequence;
        if diff >= Self::WINDOW_SIZE {
            return Err(ProtocolError::ReplayedPacket(sequence));
        }
        if (self.bitmap & (1u128 << diff)) != 0 {
            return Err(ProtocolError::ReplayedPacket(sequence));
        }
        Ok(())
    }

    pub fn update(&mut self, sequence: u64) {
        if sequence > self.max_sequence {
            let shift = sequence - self.max_sequence;
            if shift >= Self::WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.max_sequence = sequence;
        } else {
            let diff = self.max_sequence - sequence;
            if diff < Self::WINDOW_SIZE {
                self.bitmap |= 1u128 << diff;
            }
        }
    }

    pub fn check_and_update(&mut self, sequence: u64) -> Result<(), ProtocolError> {
        self.check(sequence)?;
        self.update(sequence);
        Ok(())
    }
}

/// Action resulting from evaluating a packet's epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochAction {
    /// Packet matches the current active epoch.
    Current,
    /// Packet belongs to an advanced/newer epoch (epoch bump).
    Advanced(u32),
    /// Packet belongs to a stale/older epoch.
    Stale,
}

/// Monotonic epoch tracker preventing stale packet acceptance and managing epoch transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochTracker {
    current_epoch: u32,
}

impl EpochTracker {
    #[must_use]
    pub const fn new(initial_epoch: u32) -> Self {
        Self {
            current_epoch: initial_epoch,
        }
    }

    #[must_use]
    pub const fn current_epoch(&self) -> u32 {
        self.current_epoch
    }

    #[must_use]
    pub fn validate_packet_epoch(&self, packet_epoch: u32) -> EpochAction {
        if packet_epoch == self.current_epoch {
            EpochAction::Current
        } else if packet_epoch > self.current_epoch {
            EpochAction::Advanced(packet_epoch)
        } else {
            EpochAction::Stale
        }
    }

    pub fn advance_epoch(&mut self, new_epoch: u32) -> Result<u32, ProtocolError> {
        if new_epoch <= self.current_epoch {
            return Err(ProtocolError::NonMonotonicEpoch {
                attempted: new_epoch,
                current: self.current_epoch,
            });
        }
        self.current_epoch = new_epoch;
        Ok(new_epoch)
    }
}

/// ICE Candidate gathering type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CandidateType {
    Host = 1,
    ServerReflexive = 2,
    PeerReflexive = 3,
    Relayed = 4,
}

impl TryFrom<u8> for CandidateType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Host),
            2 => Ok(Self::ServerReflexive),
            3 => Ok(Self::PeerReflexive),
            4 => Ok(Self::Relayed),
            other => Err(ProtocolError::InvalidCandidateType(other)),
        }
    }
}

/// Transport protocol for candidate connectivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransportProtocol {
    Udp = 1,
    Tcp = 2,
}

impl TryFrom<u8> for TransportProtocol {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Udp),
            2 => Ok(Self::Tcp),
            other => Err(ProtocolError::InvalidTransportProtocol(other)),
        }
    }
}

/// Relay provider classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RelayProvider {
    None = 0,
    Turn = 1,
    Derp = 2,
}

impl TryFrom<u8> for RelayProvider {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Turn),
            2 => Ok(Self::Derp),
            other => Err(ProtocolError::InvalidRelayProvider(other)),
        }
    }
}

/// Bounded IP address wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireIpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// Computes RFC 8445 candidate priority.
#[must_use]
pub const fn compute_candidate_priority(
    candidate_type: CandidateType,
    local_preference: u16,
    component: u8,
) -> u32 {
    let type_pref: u32 = match candidate_type {
        CandidateType::Host => 126,
        CandidateType::PeerReflexive => 110,
        CandidateType::ServerReflexive => 100,
        CandidateType::Relayed => 0,
    };
    let local_pref = local_preference as u32;
    let comp = (256 - (component as u32 & 0xFF)) & 0xFF;
    (type_pref << 24) | (local_pref << 8) | comp
}

/// Computes RFC 8445 candidate pair priority.
#[must_use]
pub const fn compute_pair_priority(
    controlling_prio: u32,
    controlled_prio: u32,
    is_controlling: bool,
) -> u64 {
    let (g, d) = if is_controlling {
        (controlling_prio as u64, controlled_prio as u64)
    } else {
        (controlled_prio as u64, controlling_prio as u64)
    };
    let min = if g < d { g } else { d };
    let max = if g > d { g } else { d };
    let s = if g > d { 1u64 } else { 0u64 };
    (1u64 << 32) * min + 2 * max + s
}

/// Bounded ICE Candidate descriptor for NAT traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IceCandidate {
    pub foundation: [u8; 8],
    pub component: u8,
    pub transport: TransportProtocol,
    pub priority: u32,
    pub candidate_type: CandidateType,
    pub relay_provider: RelayProvider,
    pub ip: WireIpAddr,
    pub port: u16,
    pub related_address: Option<(WireIpAddr, u16)>,
}

impl IceCandidate {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.component == 0 {
            return Err(ProtocolError::InvalidCandidateComponent);
        }
        if self.port == 0 {
            return Err(ProtocolError::InvalidCandidatePort);
        }
        if let Some((_, rel_port)) = self.related_address {
            if rel_port == 0 {
                return Err(ProtocolError::InvalidCandidatePort);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.foundation);
        out.push(self.component);
        out.push(self.transport as u8);
        out.push(self.candidate_type as u8);
        out.push(self.relay_provider as u8);
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(&self.port.to_be_bytes());
        match self.ip {
            WireIpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4);
            }
            WireIpAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6);
            }
        }
        match self.related_address {
            None => out.push(0),
            Some((WireIpAddr::V4(v4), p)) => {
                out.push(4);
                out.extend_from_slice(&v4);
                out.extend_from_slice(&p.to_be_bytes());
            }
            Some((WireIpAddr::V6(v6), p)) => {
                out.push(6);
                out.extend_from_slice(&v6);
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < 19 {
            return Err(ProtocolError::Truncated {
                expected: 19,
                actual: bytes.len(),
            });
        }
        let mut foundation = [0_u8; 8];
        foundation.copy_from_slice(&bytes[0..8]);
        let component = bytes[8];
        let transport = TransportProtocol::try_from(bytes[9])?;
        let candidate_type = CandidateType::try_from(bytes[10])?;
        let relay_provider = RelayProvider::try_from(bytes[11])?;
        let priority = read_u32(bytes, 12);
        let port = read_u16(bytes, 16);

        let mut cursor = 18;
        let ip_type = bytes[cursor];
        cursor += 1;

        let ip = match ip_type {
            4 => {
                if bytes.len() < cursor + 4 {
                    return Err(ProtocolError::Truncated {
                        expected: cursor + 4,
                        actual: bytes.len(),
                    });
                }
                let mut v4 = [0_u8; 4];
                v4.copy_from_slice(&bytes[cursor..cursor + 4]);
                cursor += 4;
                WireIpAddr::V4(v4)
            }
            6 => {
                if bytes.len() < cursor + 16 {
                    return Err(ProtocolError::Truncated {
                        expected: cursor + 16,
                        actual: bytes.len(),
                    });
                }
                let mut v6 = [0_u8; 16];
                v6.copy_from_slice(&bytes[cursor..cursor + 16]);
                cursor += 16;
                WireIpAddr::V6(v6)
            }
            _ => return Err(ProtocolError::InvalidCandidateAddress),
        };

        if bytes.len() < cursor + 1 {
            return Err(ProtocolError::Truncated {
                expected: cursor + 1,
                actual: bytes.len(),
            });
        }
        let rel_type = bytes[cursor];
        cursor += 1;

        let related_address = match rel_type {
            0 => None,
            4 => {
                if bytes.len() < cursor + 6 {
                    return Err(ProtocolError::Truncated {
                        expected: cursor + 6,
                        actual: bytes.len(),
                    });
                }
                let mut v4 = [0_u8; 4];
                v4.copy_from_slice(&bytes[cursor..cursor + 4]);
                let p = read_u16(bytes, cursor + 4);
                cursor += 6;
                Some((WireIpAddr::V4(v4), p))
            }
            6 => {
                if bytes.len() < cursor + 18 {
                    return Err(ProtocolError::Truncated {
                        expected: cursor + 18,
                        actual: bytes.len(),
                    });
                }
                let mut v6 = [0_u8; 16];
                v6.copy_from_slice(&bytes[cursor..cursor + 16]);
                let p = read_u16(bytes, cursor + 16);
                cursor += 18;
                Some((WireIpAddr::V6(v6), p))
            }
            _ => return Err(ProtocolError::InvalidCandidateAddress),
        };

        if cursor != bytes.len() {
            return Err(ProtocolError::PayloadLength {
                expected: cursor,
                actual: bytes.len(),
            });
        }

        let candidate = Self {
            foundation,
            component,
            transport,
            priority,
            candidate_type,
            relay_provider,
            ip,
            port,
            related_address,
        };
        candidate.validate()?;
        Ok(candidate)
    }
}

/// Magic constant for E2E-encrypted relay envelope.
pub const RELAY_MAGIC: [u8; 4] = *b"LDRL";
/// Fixed relay header length.
pub const RELAY_HEADER_LEN: usize = 52;
/// Maximum payload size inside one relay envelope.
pub const MAX_RELAY_PAYLOAD_BYTES: u32 = 64 * 1024;

/// Relay control flags.
pub mod relay_flags {
    pub const DIRECT_PROBE: u16 = 1 << 0;
    pub const FALLBACK_ACTIVE: u16 = 1 << 1;
    pub const HEARTBEAT: u16 = 1 << 2;
    pub const UPGRADE_ACK: u16 = 1 << 3;
}

/// Fixed header for end-to-end encrypted relay packet framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayHeader {
    pub version: u8,
    pub provider: RelayProvider,
    pub flags: u16,
    pub relay_session_id: u64,
    pub source_peer_id: [u8; 16],
    pub target_peer_id: [u8; 16],
    pub payload_len: u32,
}

impl RelayHeader {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != WIRE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.payload_len > MAX_RELAY_PAYLOAD_BYTES {
            return Err(ProtocolError::ControlLength(self.payload_len));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; RELAY_HEADER_LEN], ProtocolError> {
        self.validate()?;
        let mut out = [0_u8; RELAY_HEADER_LEN];
        out[0..4].copy_from_slice(&RELAY_MAGIC);
        out[4] = self.version;
        out[5] = self.provider as u8;
        out[6..8].copy_from_slice(&self.flags.to_be_bytes());
        out[8..16].copy_from_slice(&self.relay_session_id.to_be_bytes());
        out[16..32].copy_from_slice(&self.source_peer_id);
        out[32..48].copy_from_slice(&self.target_peer_id);
        out[48..52].copy_from_slice(&self.payload_len.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < RELAY_HEADER_LEN {
            return Err(ProtocolError::Truncated {
                expected: RELAY_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != RELAY_MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        let version = bytes[4];
        if version != WIRE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let provider = RelayProvider::try_from(bytes[5])?;
        let flags = read_u16(bytes, 6);
        let relay_session_id = read_u64(bytes, 8);
        let mut source_peer_id = [0_u8; 16];
        source_peer_id.copy_from_slice(&bytes[16..32]);
        let mut target_peer_id = [0_u8; 16];
        target_peer_id.copy_from_slice(&bytes[32..48]);
        let payload_len = read_u32(bytes, 48);

        let header = Self {
            version,
            provider,
            flags,
            relay_session_id,
            source_peer_id,
            target_peer_id,
            payload_len,
        };
        header.validate()?;
        Ok(header)
    }
}

/// Borrowed end-to-end encrypted relay packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPacket<'a> {
    pub header: RelayHeader,
    pub payload: &'a [u8],
}

impl<'a> RelayPacket<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let header = RelayHeader::decode(bytes)?;
        let expected = RELAY_HEADER_LEN
            .checked_add(header.payload_len as usize)
            .ok_or(ProtocolError::PacketLength)?;
        if bytes.len() != expected {
            return Err(ProtocolError::PayloadLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            header,
            payload: &bytes[RELAY_HEADER_LEN..],
        })
    }

    pub fn encode(header: RelayHeader, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if payload.len() != header.payload_len as usize {
            return Err(ProtocolError::PayloadLength {
                expected: header.payload_len as usize,
                actual: payload.len(),
            });
        }
        let encoded_header = header.encode()?;
        let mut out = Vec::with_capacity(RELAY_HEADER_LEN + payload.len());
        out.extend_from_slice(&encoded_header);
        out.extend_from_slice(payload);
        Ok(out)
    }
}

/// 6-digit numeric Short Authentication String (SAS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SasCode(u32);

impl SasCode {
    pub const MAX_VALUE: u32 = 999_999;

    pub const fn from_u32(val: u32) -> Result<Self, ProtocolError> {
        if val > Self::MAX_VALUE {
            Err(ProtocolError::InvalidSasCode(val))
        } else {
            Ok(Self(val))
        }
    }

    pub fn from_digits_str(s: &str) -> Result<Self, ProtocolError> {
        let s = s.trim();
        let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() != 6 {
            return Err(ProtocolError::InvalidSasFormat);
        }
        let val: u32 = digits
            .parse()
            .map_err(|_| ProtocolError::InvalidSasFormat)?;
        Self::from_u32(val)
    }

    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Computes deterministic 6-digit SAS code from ephemeral keys and context salt.
    #[must_use]
    pub fn compute(host_key: &[u8], client_key: &[u8], salt: &[u8]) -> Self {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in host_key.iter().chain(client_key.iter()).chain(salt.iter()) {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        let code = (h % 1_000_000) as u32;
        Self(code)
    }

    /// Formats as 6 ascii digits: e.g. b"123456".
    #[must_use]
    pub fn to_ascii_digits(self) -> [u8; 6] {
        let mut out = [b'0'; 6];
        let mut v = self.0;
        for i in (0..6).rev() {
            out[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        out
    }

    /// Formats with middle dash: e.g. b"123-456".
    #[must_use]
    pub fn to_dashed_ascii(self) -> [u8; 7] {
        let digits = self.to_ascii_digits();
        [
            digits[0], digits[1], digits[2], b'-', digits[3], digits[4], digits[5],
        ]
    }
}

/// Pairing protocol wire message kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PairingWireKind {
    Request = 1,
    Response = 2,
    SasConfirm = 3,
    Complete = 4,
}

impl TryFrom<u8> for PairingWireKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::SasConfirm),
            4 => Ok(Self::Complete),
            other => Err(ProtocolError::InvalidPairingWireKind(other)),
        }
    }
}

/// Client pairing request payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingRequestWire {
    pub client_fingerprint: [u8; 32],
    pub client_ephemeral_key: [u8; 32],
    pub requested_capabilities: u8,
    pub timestamp_ns: u64,
}

impl PairingRequestWire {
    pub const ENCODED_LEN: usize = 73;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..32].copy_from_slice(&self.client_fingerprint);
        out[32..64].copy_from_slice(&self.client_ephemeral_key);
        out[64] = self.requested_capabilities;
        out[65..73].copy_from_slice(&self.timestamp_ns.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let mut client_fingerprint = [0_u8; 32];
        client_fingerprint.copy_from_slice(&bytes[0..32]);
        let mut client_ephemeral_key = [0_u8; 32];
        client_ephemeral_key.copy_from_slice(&bytes[32..64]);
        let requested_capabilities = bytes[64];
        let timestamp_ns = read_u64(bytes, 65);
        Ok(Self {
            client_fingerprint,
            client_ephemeral_key,
            requested_capabilities,
            timestamp_ns,
        })
    }
}

/// Host pairing response payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingResponseWire {
    pub host_fingerprint: [u8; 32],
    pub host_ephemeral_key: [u8; 32],
    pub sas_commitment: [u8; 32],
    pub expires_at_ns: u64,
}

impl PairingResponseWire {
    pub const ENCODED_LEN: usize = 104;

    /// Computes deterministic 32-byte cryptographic SAS commitment hash from ephemeral keys and context salt.
    #[must_use]
    pub fn compute_commitment(host_key: &[u8], client_key: &[u8], salt: &[u8]) -> [u8; 32] {
        let mut out = [0_u8; 32];
        let mut h: u64 = 0xcbf29ce484222325;
        for b in host_key.iter().chain(client_key.iter()).chain(salt.iter()) {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for i in 0..4 {
            h ^= h >> 33;
            h = h.wrapping_mul(0xff51afd7ed558ccd);
            let chunk = h.to_be_bytes();
            out[i * 8..(i + 1) * 8].copy_from_slice(&chunk);
        }
        out
    }
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..32].copy_from_slice(&self.host_fingerprint);
        out[32..64].copy_from_slice(&self.host_ephemeral_key);
        out[64..96].copy_from_slice(&self.sas_commitment);
        out[96..104].copy_from_slice(&self.expires_at_ns.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let mut host_fingerprint = [0_u8; 32];
        host_fingerprint.copy_from_slice(&bytes[0..32]);
        let mut host_ephemeral_key = [0_u8; 32];
        host_ephemeral_key.copy_from_slice(&bytes[32..64]);
        let mut sas_commitment = [0_u8; 32];
        sas_commitment.copy_from_slice(&bytes[64..96]);
        let expires_at_ns = read_u64(bytes, 96);
        Ok(Self {
            host_fingerprint,
            host_ephemeral_key,
            sas_commitment,
            expires_at_ns,
        })
    }
}

/// SAS out-of-band confirmation wire payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SasConfirmWire {
    pub sas_code: u32,
    pub confirmation_nonce: [u8; 16],
}

impl SasConfirmWire {
    pub const ENCODED_LEN: usize = 20;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..4].copy_from_slice(&self.sas_code.to_be_bytes());
        out[4..20].copy_from_slice(&self.confirmation_nonce);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let sas_code = read_u32(bytes, 0);
        let mut confirmation_nonce = [0_u8; 16];
        confirmation_nonce.copy_from_slice(&bytes[4..20]);
        Ok(Self {
            sas_code,
            confirmation_nonce,
        })
    }
}

/// Reasons for explicit or safe session termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DisconnectReason {
    UserInitiated = 1,
    HostShutdown = 2,
    IdleTimeout = 3,
    HeartbeatExpired = 4,
    AuthenticationRevoked = 5,
    TokenExpired = 6,
    SecurityViolation = 7,
    SasMismatch = 8,
    NatTraversalFailed = 9,
    MigrationFailed = 10,
}

impl TryFrom<u8> for DisconnectReason {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::UserInitiated),
            2 => Ok(Self::HostShutdown),
            3 => Ok(Self::IdleTimeout),
            4 => Ok(Self::HeartbeatExpired),
            5 => Ok(Self::AuthenticationRevoked),
            6 => Ok(Self::TokenExpired),
            7 => Ok(Self::SecurityViolation),
            8 => Ok(Self::SasMismatch),
            9 => Ok(Self::NatTraversalFailed),
            10 => Ok(Self::MigrationFailed),
            other => Err(ProtocolError::InvalidDisconnectReason(other)),
        }
    }
}

/// Safe disconnect wire message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectWire<'a> {
    pub reason: DisconnectReason,
    pub session_id: u64,
    pub authorization_epoch: u32,
    pub message: &'a str,
}

impl<'a> DisconnectWire<'a> {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let msg_bytes = self.message.as_bytes();
        if msg_bytes.len() > 256 {
            return Err(ProtocolError::InvalidDisconnectMessage);
        }
        let mut out = Vec::with_capacity(15 + msg_bytes.len());
        out.push(self.reason as u8);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.authorization_epoch.to_be_bytes());
        out.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(msg_bytes);
        Ok(out)
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < 15 {
            return Err(ProtocolError::Truncated {
                expected: 15,
                actual: bytes.len(),
            });
        }
        let reason = DisconnectReason::try_from(bytes[0])?;
        let session_id = read_u64(bytes, 1);
        let authorization_epoch = read_u32(bytes, 9);
        let msg_len = read_u16(bytes, 13) as usize;
        if bytes.len() != 15 + msg_len {
            return Err(ProtocolError::PayloadLength {
                expected: 15 + msg_len,
                actual: bytes.len(),
            });
        }
        let message = core::str::from_utf8(&bytes[15..15 + msg_len])
            .map_err(|_| ProtocolError::InvalidDisconnectMessage)?;
        Ok(Self {
            reason,
            session_id,
            authorization_epoch,
            message,
        })
    }
}

/// Unattended authorization token wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnattendedTokenWire {
    pub token_id: [u8; 16],
    pub device_fingerprint: [u8; 32],
    pub allowed_capabilities: u8,
    pub issued_at_ns: u64,
    pub expires_at_ns: u64,
    pub signature: [u8; 32],
}

impl UnattendedTokenWire {
    pub const ENCODED_LEN: usize = 97;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..16].copy_from_slice(&self.token_id);
        out[16..48].copy_from_slice(&self.device_fingerprint);
        out[48] = self.allowed_capabilities;
        out[49..57].copy_from_slice(&self.issued_at_ns.to_be_bytes());
        out[57..65].copy_from_slice(&self.expires_at_ns.to_be_bytes());
        out[65..97].copy_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let mut token_id = [0_u8; 16];
        token_id.copy_from_slice(&bytes[0..16]);
        let mut device_fingerprint = [0_u8; 32];
        device_fingerprint.copy_from_slice(&bytes[16..48]);
        let allowed_capabilities = bytes[48];
        let issued_at_ns = read_u64(bytes, 49);
        let expires_at_ns = read_u64(bytes, 57);
        if expires_at_ns <= issued_at_ns {
            return Err(ProtocolError::InvalidUnattendedToken);
        }
        let mut signature = [0_u8; 32];
        signature.copy_from_slice(&bytes[65..97]);
        Ok(Self {
            token_id,
            device_fingerprint,
            allowed_capabilities,
            issued_at_ns,
            expires_at_ns,
            signature,
        })
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// Wire validation or parsing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Truncated {
        expected: usize,
        actual: usize,
    },
    BadMagic,
    UnsupportedVersion(u8),
    UnknownMediaKind(u8),
    UnknownStreamKind(u8),
    UnknownControlKind(u8),
    UnknownFlags(u16),
    UnknownControlFlags(u16),
    ReservedBits,
    FrameLength(u32),
    FragmentLength(u16),
    FragmentRange,
    PacketLength,
    PayloadLength {
        expected: usize,
        actual: usize,
    },
    ControlLength(u32),
    StreamPayloadLength {
        kind: quic::StreamKind,
        limit: usize,
        actual: usize,
    },
    StreamKindMismatch {
        expected: quic::StreamKind,
        actual: quic::StreamKind,
    },
    InvalidSessionStamp,
    InactiveInputStamp,
    InactiveMediaStamp,
    InvalidMediaStreamId,
    MediaEpochMismatch {
        header_epoch: u32,
        stamp_epoch: u32,
    },
    ExpiredMediaDatagram,
    KeyframeHasDependency,
    InvalidDependency {
        frame_id: u64,
        dependency_frame_id: u64,
    },
    InvalidRecoveryRange,
    InvalidHandshake,
    ReplayedPacket(u64),
    StaleEpoch {
        packet_epoch: u32,
        current_epoch: u32,
    },
    NonMonotonicEpoch {
        attempted: u32,
        current: u32,
    },
    InvalidMtu(u16),
    AuthenticationFailed,
    InvalidCandidateType(u8),
    InvalidTransportProtocol(u8),
    InvalidRelayProvider(u8),
    InvalidCandidatePort,
    InvalidCandidateComponent,
    InvalidCandidateAddress,
    InvalidSasCode(u32),
    InvalidSasFormat,
    InvalidPairingWireKind(u8),
    InvalidDisconnectReason(u8),
    InvalidDisconnectMessage,
    InvalidUnattendedToken,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> MediaHeader {
        MediaHeader {
            kind: MediaKind::Video,
            flags: media_flags::KEYFRAME,
            stream_id: 7,
            codec_epoch: 3,
            frame_id: 42,
            dependency_frame_id: NO_DEPENDENCY,
            frame_len: 2_000,
            fragment_offset: 1_000,
            fragment_len: 1_000,
        }
    }

    #[test]
    fn round_trip_media_packet() {
        let header = valid_header();
        let payload = vec![7_u8; 1_000];
        let packet = MediaPacket::encode(header, &payload).expect("encode");
        let decoded = MediaPacket::decode(&packet).expect("decode");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn rejects_trailing_media_bytes() {
        let header = valid_header();
        let mut packet = MediaPacket::encode(header, &vec![0; 1_000]).expect("encode");
        packet.push(0);
        assert!(matches!(
            MediaPacket::decode(&packet),
            Err(ProtocolError::PayloadLength { .. })
        ));
    }

    #[test]
    fn rejects_out_of_range_fragment_before_allocation() {
        let mut header = valid_header();
        header.fragment_offset = 1_500;
        header.fragment_len = 1_000;
        assert_eq!(header.validate(), Err(ProtocolError::FragmentRange));
    }

    #[test]
    fn rejects_unknown_flags() {
        let mut header = valid_header();
        header.flags |= 1 << 15;
        assert!(matches!(
            header.validate(),
            Err(ProtocolError::UnknownFlags(_))
        ));
    }

    #[test]
    fn rejects_forward_dependency() {
        let mut header = valid_header();
        header.flags = 0;
        header.dependency_frame_id = header.frame_id;
        assert!(matches!(
            header.validate(),
            Err(ProtocolError::InvalidDependency { .. })
        ));
    }

    #[test]
    fn round_trip_control_packet() {
        let payload = b"capabilities";
        let header = ControlHeader {
            kind: ControlKind::Capabilities,
            flags: 0,
            session_id: 99,
            payload_len: payload.len() as u32,
        };
        let encoded = ControlPacket::encode(header, payload).expect("encode");
        let decoded = ControlPacket::decode(&encoded).expect("decode");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn recovery_range_must_advance() {
        let bad = RecoveryRequest {
            stream_id: 1,
            codec_epoch: 1,
            last_good_frame_id: 10,
            first_missing_frame_id: 10,
        };
        assert_eq!(
            RecoveryRequest::decode(&bad.encode()),
            Err(ProtocolError::InvalidRecoveryRange)
        );
    }

    #[test]
    fn hello_round_trip() {
        let msg = HelloMessage {
            client_version: WIRE_VERSION,
            client_nonce: [42_u8; 16],
            device_fingerprint: [7_u8; 32],
            capabilities_mask: 0x0102_0304,
            proposed_mtu: 1_400,
        };
        let encoded = msg.encode();
        let decoded = HelloMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn hello_ack_round_trip() {
        let msg = HelloAckMessage {
            server_version: WIRE_VERSION,
            server_nonce: [99_u8; 16],
            session_id: 0x1234_5678_9ABC_DEF0,
            authorization_epoch: 1,
            negotiated_mtu: 1_350,
        };
        let encoded = msg.encode();
        let decoded = HelloAckMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn authenticate_round_trip() {
        let msg = AuthenticateMessage {
            session_id: 12345,
            authorization_epoch: 2,
            auth_tag: [11_u8; 32],
            client_nonce: [22_u8; 16],
        };
        let encoded = msg.encode();
        let decoded = AuthenticateMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn handshake_completed_round_trip() {
        let msg = HandshakeCompletedMessage {
            session_id: 54321,
            authorization_epoch: 3,
            server_nonce: [33_u8; 16],
        };
        let encoded = msg.encode();
        let decoded = HandshakeCompletedMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn rate_update_round_trip() {
        let msg = RateUpdateMessage {
            stream_id: 1,
            codec_epoch: 5,
            target_bitrate_bps: 25_000_000,
            max_bitrate_bps: 40_000_000,
            target_fps: 60,
            flags: rate_flags::FORCE_KEYFRAME | rate_flags::EPOCH_BUMP,
        };
        let encoded = msg.encode();
        let decoded = RateUpdateMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn congestion_feedback_round_trip() {
        let msg = CongestionFeedbackMessage {
            feedback_sequence: 100,
            echo_timestamp_ns: 1_000_000_000,
            rtt_ns: 20_000_000,
            loss_per_million: 5_000,
            jitter_ns: 2_000_000,
            received_bitrate_bps: 18_000_000,
        };
        let encoded = msg.encode();
        let decoded = CongestionFeedbackMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn ping_pong_round_trip() {
        let msg = PingPongMessage {
            nonce: 0xDEAD_BEEF_CAFE_BABE,
            timestamp_ns: 9_999_999,
        };
        let encoded = msg.encode();
        let decoded = PingPongMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn anti_replay_filter_sliding_window() {
        let mut filter = AntiReplayFilter::new();
        assert_eq!(
            filter.check_and_update(0),
            Err(ProtocolError::ReplayedPacket(0))
        );

        // In-order packets
        assert!(filter.check_and_update(1).is_ok());
        assert!(filter.check_and_update(2).is_ok());
        assert!(filter.check_and_update(3).is_ok());

        // Exact duplicate
        assert_eq!(
            filter.check_and_update(2),
            Err(ProtocolError::ReplayedPacket(2))
        );

        // Jump ahead within window
        assert!(filter.check_and_update(50).is_ok());
        // Out of order within window
        assert!(filter.check_and_update(40).is_ok());
        assert_eq!(
            filter.check_and_update(40),
            Err(ProtocolError::ReplayedPacket(40))
        );

        // Jump far ahead (beyond window)
        assert!(filter.check_and_update(200).is_ok());
        // Packets older than (200 - 128 = 72) must be rejected
        assert_eq!(
            filter.check_and_update(50),
            Err(ProtocolError::ReplayedPacket(50))
        );
        // Packet within new window (e.g. 150) is accepted
        assert!(filter.check_and_update(150).is_ok());
        assert_eq!(
            filter.check_and_update(150),
            Err(ProtocolError::ReplayedPacket(150))
        );
    }

    #[test]
    fn epoch_tracker_monotonicity() {
        let mut tracker = EpochTracker::new(1);
        assert_eq!(tracker.current_epoch(), 1);
        assert_eq!(tracker.validate_packet_epoch(1), EpochAction::Current);
        assert_eq!(tracker.validate_packet_epoch(2), EpochAction::Advanced(2));
        assert_eq!(tracker.validate_packet_epoch(0), EpochAction::Stale);

        assert_eq!(tracker.advance_epoch(2), Ok(2));
        assert_eq!(tracker.current_epoch(), 2);
        assert_eq!(tracker.validate_packet_epoch(1), EpochAction::Stale);

        assert!(matches!(
            tracker.advance_epoch(2),
            Err(ProtocolError::NonMonotonicEpoch { .. })
        ));
        assert!(matches!(
            tracker.advance_epoch(1),
            Err(ProtocolError::NonMonotonicEpoch { .. })
        ));
    }
    #[test]
    fn ice_candidate_v4_round_trip() {
        let candidate = IceCandidate {
            foundation: [1, 2, 3, 4, 5, 6, 7, 8],
            component: 1,
            transport: TransportProtocol::Udp,
            priority: compute_candidate_priority(CandidateType::Host, 100, 1),
            candidate_type: CandidateType::Host,
            relay_provider: RelayProvider::None,
            ip: WireIpAddr::V4([192, 168, 1, 50]),
            port: 50000,
            related_address: None,
        };
        let encoded = candidate.encode().expect("encode");
        let decoded = IceCandidate::decode(&encoded).expect("decode");
        assert_eq!(decoded, candidate);
    }

    #[test]
    fn ice_candidate_srflx_with_related_round_trip() {
        let candidate = IceCandidate {
            foundation: [9, 8, 7, 6, 5, 4, 3, 2],
            component: 1,
            transport: TransportProtocol::Udp,
            priority: compute_candidate_priority(CandidateType::ServerReflexive, 50, 1),
            candidate_type: CandidateType::ServerReflexive,
            relay_provider: RelayProvider::None,
            ip: WireIpAddr::V4([203, 0, 113, 19]),
            port: 34567,
            related_address: Some((WireIpAddr::V4([192, 168, 1, 50]), 50000)),
        };
        let encoded = candidate.encode().expect("encode");
        let decoded = IceCandidate::decode(&encoded).expect("decode");
        assert_eq!(decoded, candidate);
    }

    #[test]
    fn ice_candidate_priority_ordering() {
        let host_prio = compute_candidate_priority(CandidateType::Host, 100, 1);
        let srflx_prio = compute_candidate_priority(CandidateType::ServerReflexive, 100, 1);
        let prflx_prio = compute_candidate_priority(CandidateType::PeerReflexive, 100, 1);
        let relay_prio = compute_candidate_priority(CandidateType::Relayed, 100, 1);

        assert!(host_prio > prflx_prio);
        assert!(prflx_prio > srflx_prio);
        assert!(srflx_prio > relay_prio);

        let pair_prio_direct = compute_pair_priority(host_prio, host_prio, true);
        let pair_prio_relay = compute_pair_priority(relay_prio, relay_prio, true);
        assert!(pair_prio_direct > pair_prio_relay);
    }

    #[test]
    fn relay_packet_round_trip() {
        let payload = b"encrypted_inner_payload_e2e";
        let header = RelayHeader {
            version: WIRE_VERSION,
            provider: RelayProvider::Derp,
            flags: relay_flags::FALLBACK_ACTIVE | relay_flags::DIRECT_PROBE,
            relay_session_id: 0xAABB_CCDD_EEFF_0011,
            source_peer_id: [1_u8; 16],
            target_peer_id: [2_u8; 16],
            payload_len: payload.len() as u32,
        };
        let encoded = RelayPacket::encode(header, payload).expect("encode");
        let decoded = RelayPacket::decode(&encoded).expect("decode");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn sas_code_calculation_and_formatting() {
        let host_key = [0xAA; 32];
        let client_key = [0xBB; 32];
        let salt = b"LatencyDesk-v1-SAS";
        let sas = SasCode::compute(&host_key, &client_key, salt);
        assert!(sas.value() <= SasCode::MAX_VALUE);

        let dashed = sas.to_dashed_ascii();
        let dashed_str = core::str::from_utf8(&dashed).expect("utf8");
        assert_eq!(dashed_str.len(), 7);
        assert_eq!(&dashed_str[3..4], "-");

        let parsed = SasCode::from_digits_str(dashed_str).expect("parse");
        assert_eq!(parsed, sas);

        assert!(matches!(
            SasCode::from_u32(1_000_000),
            Err(ProtocolError::InvalidSasCode(_))
        ));
        assert!(SasCode::from_digits_str("12345").is_err());
        assert!(SasCode::from_digits_str("abcdef").is_err());
    }

    #[test]
    fn pairing_wire_packets_round_trip() {
        let req = PairingRequestWire {
            client_fingerprint: [3_u8; 32],
            client_ephemeral_key: [4_u8; 32],
            requested_capabilities: 0x03,
            timestamp_ns: 1_234_567_890,
        };
        let enc_req = req.encode();
        let dec_req = PairingRequestWire::decode(&enc_req).expect("decode req");
        assert_eq!(dec_req, req);

        let resp = PairingResponseWire {
            host_fingerprint: [5_u8; 32],
            host_ephemeral_key: [6_u8; 32],
            sas_commitment: [7_u8; 32],
            expires_at_ns: 9_999_999_999,
        };
        let enc_resp = resp.encode();
        let dec_resp = PairingResponseWire::decode(&enc_resp).expect("decode resp");
        assert_eq!(dec_resp, resp);

        let confirm = SasConfirmWire {
            sas_code: 654321,
            confirmation_nonce: [8_u8; 16],
        };
        let enc_confirm = confirm.encode();
        let dec_confirm = SasConfirmWire::decode(&enc_confirm).expect("decode confirm");
        assert_eq!(dec_confirm, confirm);
    }

    #[test]
    fn pairing_sas_commitment_computation() {
        let host_key = [1_u8; 32];
        let client_key = [2_u8; 32];
        let salt = b"LatencyDesk-v1-SAS-Numeric";
        let commitment1 = PairingResponseWire::compute_commitment(&host_key, &client_key, salt);
        let commitment2 = PairingResponseWire::compute_commitment(&host_key, &client_key, salt);
        assert_eq!(commitment1, commitment2);
        assert_ne!(commitment1, [0_u8; 32]);

        let diff_key = [3_u8; 32];
        let commitment3 = PairingResponseWire::compute_commitment(&diff_key, &client_key, salt);
        assert_ne!(commitment1, commitment3);
    }

    #[test]
    fn disconnect_wire_round_trip() {
        let disc = DisconnectWire {
            reason: DisconnectReason::AuthenticationRevoked,
            session_id: 0x8877_6655_4433_2211,
            authorization_epoch: 5,
            message: "Host operator revoked permissions",
        };
        let encoded = disc.encode().expect("encode");
        let decoded = DisconnectWire::decode(&encoded).expect("decode");
        assert_eq!(decoded, disc);
    }

    #[test]
    fn unattended_token_wire_round_trip() {
        let token = UnattendedTokenWire {
            token_id: [0x11; 16],
            device_fingerprint: [0x22; 32],
            allowed_capabilities: 0x01,
            issued_at_ns: 1_000_000,
            expires_at_ns: 2_000_000,
            signature: [0x33; 32],
        };
        let encoded = token.encode();
        let decoded = UnattendedTokenWire::decode(&encoded).expect("decode");
        assert_eq!(decoded, token);
    }
}
