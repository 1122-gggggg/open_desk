//! Bounded wire primitives for LatencyDesk.
//!
//! This crate intentionally has no transport, async runtime, codec, or platform
//! dependencies. Every parser validates lengths before allocating and rejects
//! trailing bytes so datagram boundaries remain unambiguous.

use core::fmt;
use zeroize::{Zeroize, Zeroizing};

pub mod quic;
pub mod stun;

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
    IceCredentials = 21,
    IceProbe = 22,
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
            21 => Ok(Self::IceCredentials),
            22 => Ok(Self::IceProbe),
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
/// Version of the explicit video-codec negotiation contract carried on the
/// reliable control lane. Media DATAGRAM payloads never identify their codec.
pub const VIDEO_CODEC_CONTRACT_VERSION: u16 = 1;

/// Capabilities declared by a secure video receiver.
pub mod video_capability_flags {
    /// H.264 High profile with 8-bit 4:2:0 output.
    pub const H264_HIGH_420: u16 = 1 << 0;
    /// Packed raw NV12 compatibility. Product peers must never infer this bit.
    pub const RAW_NV12: u16 = 1 << 1;
    /// The Client understands and may request full-stamp input application
    /// acknowledgments. A Host must intersect this with its platform support.
    pub const INPUT_APPLIED_ACK: u16 = 1 << 2;
    /// Client accepts authenticated candidate advertisements only; this does
    /// not select routes or claim ICE completion.
    pub const AUTHENTICATED_CANDIDATE_EXCHANGE: u16 = 1 << 3;
    /// Authenticated ICE credentials for signaling only; no connectivity claim.
    pub const AUTHENTICATED_ICE_CREDENTIALS: u16 = 1 << 4;
    /// Opt-in isolated connectivity probe; requires authenticated credentials.
    pub const ICE_CONNECTIVITY_PROBE: u16 = 1 << 5;
}

/// Host capabilities attached to the selected secure stream configuration.
/// Unknown bits are protocol errors so a Client never infers support.
pub mod video_stream_flags {
    /// The Host can emit a full-stamp [`super::InputAppliedAck`] after platform
    /// input application. Linux X11 advertises this only when that path exists.
    pub const INPUT_APPLIED_ACK: u32 = 1 << 0;
    /// Host may emit authenticated candidate advertisements only; this does
    /// not select routes or claim ICE completion.
    pub const AUTHENTICATED_CANDIDATE_EXCHANGE: u32 = 1 << 1;
    /// Authenticated ICE credentials for signaling only; no connectivity claim.
    pub const AUTHENTICATED_ICE_CREDENTIALS: u32 = 1 << 2;
    /// Opt-in isolated connectivity probe; requires authenticated credentials.
    pub const ICE_CONNECTIVITY_PROBE: u32 = 1 << 3;

    pub(crate) const KNOWN: u32 = INPUT_APPLIED_ACK
        | AUTHENTICATED_CANDIDATE_EXCHANGE
        | AUTHENTICATED_ICE_CREDENTIALS
        | ICE_CONNECTIVITY_PROBE;
}

/// Fixed-size receiver codec offer carried by [`ControlKind::Capabilities`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoCodecCapabilities {
    pub contract_version: u16,
    pub flags: u16,
    pub max_width: u32,
    pub max_height: u32,
    pub max_fps: u32,
}

impl VideoCodecCapabilities {
    pub const ENCODED_LEN: usize = 16;

    pub fn encode(self) -> Result<[u8; Self::ENCODED_LEN], ProtocolError> {
        self.validate()?;
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..2].copy_from_slice(&self.contract_version.to_be_bytes());
        out[2..4].copy_from_slice(&self.flags.to_be_bytes());
        out[4..8].copy_from_slice(&self.max_width.to_be_bytes());
        out[8..12].copy_from_slice(&self.max_height.to_be_bytes());
        out[12..16].copy_from_slice(&self.max_fps.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let capabilities = Self {
            contract_version: read_u16(bytes, 0),
            flags: read_u16(bytes, 2),
            max_width: read_u32(bytes, 4),
            max_height: read_u32(bytes, 8),
            max_fps: read_u32(bytes, 12),
        };
        capabilities.validate()?;
        Ok(capabilities)
    }

    fn validate(self) -> Result<(), ProtocolError> {
        let known = video_capability_flags::H264_HIGH_420
            | video_capability_flags::RAW_NV12
            | video_capability_flags::INPUT_APPLIED_ACK
            | video_capability_flags::AUTHENTICATED_CANDIDATE_EXCHANGE
            | video_capability_flags::AUTHENTICATED_ICE_CREDENTIALS
            | video_capability_flags::ICE_CONNECTIVITY_PROBE;
        if self.contract_version != VIDEO_CODEC_CONTRACT_VERSION {
            return Err(ProtocolError::UnsupportedCodecContract(
                self.contract_version,
            ));
        }
        if self.flags == 0 || self.flags & !known != 0 {
            return Err(ProtocolError::InvalidCodecCapabilities(self.flags));
        }
        if self.supports_ice_connectivity_probe() && !self.supports_authenticated_ice_credentials()
        {
            return Err(ProtocolError::IceProbeRequiresCredentials);
        }
        if self.max_width == 0
            || self.max_height == 0
            || self.max_width % 2 != 0
            || self.max_height % 2 != 0
            || self.max_fps == 0
        {
            return Err(ProtocolError::InvalidVideoGeometry);
        }
        Ok(())
    }

    #[must_use]
    pub const fn offers_h264(self) -> bool {
        self.flags & video_capability_flags::H264_HIGH_420 != 0
    }

    #[must_use]
    pub const fn offers_nv12(self) -> bool {
        self.flags & video_capability_flags::RAW_NV12 != 0
    }

    #[must_use]
    pub const fn supports_input_applied_ack(self) -> bool {
        self.flags & video_capability_flags::INPUT_APPLIED_ACK != 0
    }

    #[must_use]
    pub const fn supports_authenticated_candidate_exchange(self) -> bool {
        self.flags & video_capability_flags::AUTHENTICATED_CANDIDATE_EXCHANGE != 0
    }

    #[must_use]
    pub const fn supports_authenticated_ice_credentials(self) -> bool {
        self.flags & video_capability_flags::AUTHENTICATED_ICE_CREDENTIALS != 0
    }

    #[must_use]
    pub const fn supports_ice_connectivity_probe(self) -> bool {
        self.flags & video_capability_flags::ICE_CONNECTIVITY_PROBE != 0
    }
}

/// Picks the lowest-latency codec both peers can actually implement.
/// H.264 4:2:0 wins over raw NV12 because uncompressed frames saturate a LAN
/// and add milliseconds of queueing.
pub fn select_host_codec(
    client: VideoCodecCapabilities,
    host_can_h264: bool,
    host_can_nv12: bool,
) -> Result<(VideoCodec, VideoProfile), ProtocolError> {
    if host_can_h264 && client.offers_h264() {
        Ok((VideoCodec::H264, VideoProfile::H264High420))
    } else if host_can_nv12 && client.offers_nv12() {
        Ok((VideoCodec::RawNv12, VideoProfile::RawNv12))
    } else {
        Err(ProtocolError::InvalidCodecCapabilities(client.flags))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VideoCodec {
    H264 = 1,
    RawNv12 = 2,
}

impl TryFrom<u8> for VideoCodec {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::H264),
            2 => Ok(Self::RawNv12),
            other => Err(ProtocolError::UnknownVideoCodec(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VideoProfile {
    H264High420 = 1,
    RawNv12 = 2,
}

impl TryFrom<u8> for VideoProfile {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::H264High420),
            2 => Ok(Self::RawNv12),
            other => Err(ProtocolError::UnknownVideoProfile(other)),
        }
    }
}

/// Host-selected stream format carried by [`ControlKind::ConfigureStream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoStreamConfig {
    pub contract_version: u16,
    pub codec: VideoCodec,
    pub profile: VideoProfile,
    pub pixel_format: u32,
    pub stream_id: u32,
    pub codec_epoch: u32,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub target_bitrate_bps: u32,
    pub flags: u32,
}

impl VideoStreamConfig {
    pub const ENCODED_LEN: usize = 36;

    pub fn encode(self) -> Result<[u8; Self::ENCODED_LEN], ProtocolError> {
        self.validate()?;
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0..2].copy_from_slice(&self.contract_version.to_be_bytes());
        out[2] = self.codec as u8;
        out[3] = self.profile as u8;
        out[4..8].copy_from_slice(&self.pixel_format.to_be_bytes());
        out[8..12].copy_from_slice(&self.stream_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.codec_epoch.to_be_bytes());
        out[16..20].copy_from_slice(&self.width.to_be_bytes());
        out[20..24].copy_from_slice(&self.height.to_be_bytes());
        out[24..28].copy_from_slice(&self.fps.to_be_bytes());
        out[28..32].copy_from_slice(&self.target_bitrate_bps.to_be_bytes());
        out[32..36].copy_from_slice(&self.flags.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let config = Self {
            contract_version: read_u16(bytes, 0),
            codec: VideoCodec::try_from(bytes[2])?,
            profile: VideoProfile::try_from(bytes[3])?,
            pixel_format: read_u32(bytes, 4),
            stream_id: read_u32(bytes, 8),
            codec_epoch: read_u32(bytes, 12),
            width: read_u32(bytes, 16),
            height: read_u32(bytes, 20),
            fps: read_u32(bytes, 24),
            target_bitrate_bps: read_u32(bytes, 28),
            flags: read_u32(bytes, 32),
        };
        config.validate()?;
        Ok(config)
    }

    #[must_use]
    pub const fn supports_authenticated_candidate_exchange(self) -> bool {
        self.flags & video_stream_flags::AUTHENTICATED_CANDIDATE_EXCHANGE != 0
    }

    #[must_use]
    pub const fn supports_authenticated_ice_credentials(self) -> bool {
        self.flags & video_stream_flags::AUTHENTICATED_ICE_CREDENTIALS != 0
    }

    #[must_use]
    pub const fn supports_ice_connectivity_probe(self) -> bool {
        self.flags & video_stream_flags::ICE_CONNECTIVITY_PROBE != 0
    }

    fn validate(self) -> Result<(), ProtocolError> {
        if self.contract_version != VIDEO_CODEC_CONTRACT_VERSION {
            return Err(ProtocolError::UnsupportedCodecContract(
                self.contract_version,
            ));
        }
        let valid_pair = matches!(
            (self.codec, self.profile),
            (VideoCodec::H264, VideoProfile::H264High420)
                | (VideoCodec::RawNv12, VideoProfile::RawNv12)
        );
        if !valid_pair || self.pixel_format != u32::from_le_bytes(*b"NV12") {
            return Err(ProtocolError::InvalidVideoProfile);
        }
        let unknown_flags = self.flags & !video_stream_flags::KNOWN;
        if unknown_flags != 0 {
            return Err(ProtocolError::UnknownVideoStreamFlags(unknown_flags));
        }
        if self.supports_authenticated_candidate_exchange()
            && self.supports_authenticated_ice_credentials()
        {
            return Err(ProtocolError::ConflictingIceSignalingModes);
        }
        if self.supports_ice_connectivity_probe() && !self.supports_authenticated_ice_credentials()
        {
            return Err(ProtocolError::IceProbeRequiresCredentials);
        }
        if self.stream_id == 0
            || self.codec_epoch == 0
            || self.width == 0
            || self.height == 0
            || self.width % 2 != 0
            || self.height % 2 != 0
            || self.fps == 0
            || self.target_bitrate_bps == 0
        {
            return Err(ProtocolError::InvalidVideoGeometry);
        }
        Ok(())
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

/// Result of one ACK-requested input after reconciliation/platform injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InputAckStatus {
    Applied = 1,
    IgnoredStaleSequence = 2,
    IgnoredStaleEpoch = 3,
    ApplyFailed = 4,
}

impl TryFrom<u8> for InputAckStatus {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Applied),
            2 => Ok(Self::IgnoredStaleSequence),
            3 => Ok(Self::IgnoredStaleEpoch),
            4 => Ok(Self::ApplyFailed),
            other => Err(ProtocolError::UnknownInputAckStatus(other)),
        }
    }
}

/// Host report emitted only after an ACK-requested input has been reconciled
/// and any resulting platform injections have returned. It intentionally
/// contains no key codes, text, button identities, or state snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputAppliedAck {
    pub stamp: quic::SessionStamp,
    pub input_epoch: u32,
    pub input_sequence: u64,
    pub ack_sequence: u64,
    pub status: InputAckStatus,
    pub applied_action_count: u16,
}

impl InputAppliedAck {
    pub const ENCODED_LEN: usize = 56;

    pub fn encode(self) -> Result<[u8; Self::ENCODED_LEN], ProtocolError> {
        self.validate()?;
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0] = WIRE_VERSION;
        out[1] = self.status as u8;
        // 2..4 reserved
        out[4..12].copy_from_slice(&self.stamp.session_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.stamp.generation.to_be_bytes());
        out[20..24].copy_from_slice(&self.stamp.authorization_epoch.to_be_bytes());
        out[24..28].copy_from_slice(&self.stamp.display_epoch.to_be_bytes());
        out[28..32].copy_from_slice(&self.stamp.codec_epoch.to_be_bytes());
        out[32..36].copy_from_slice(&self.input_epoch.to_be_bytes());
        out[36..44].copy_from_slice(&self.input_sequence.to_be_bytes());
        out[44..52].copy_from_slice(&self.ack_sequence.to_be_bytes());
        out[52..54].copy_from_slice(&self.applied_action_count.to_be_bytes());
        // 54..56 reserved
        Ok(out)
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
        if bytes[2..4] != [0, 0] || bytes[54..56] != [0, 0] {
            return Err(ProtocolError::ReservedBits);
        }
        let ack = Self {
            stamp: quic::SessionStamp {
                session_id: read_u64(bytes, 4),
                generation: read_u64(bytes, 12),
                authorization_epoch: read_u32(bytes, 20),
                display_epoch: read_u32(bytes, 24),
                codec_epoch: read_u32(bytes, 28),
            },
            input_epoch: read_u32(bytes, 32),
            input_sequence: read_u64(bytes, 36),
            ack_sequence: read_u64(bytes, 44),
            status: InputAckStatus::try_from(bytes[1])?,
            applied_action_count: read_u16(bytes, 52),
        };
        ack.validate()?;
        Ok(ack)
    }

    fn validate(self) -> Result<(), ProtocolError> {
        self.stamp.validate_pending()?;
        if self.stamp.authorization_epoch == 0
            || self.stamp.display_epoch == 0
            || self.stamp.codec_epoch == 0
            || self.input_epoch != self.stamp.authorization_epoch
            || self.input_sequence == 0
            || self.ack_sequence == 0
            || (self.status != InputAckStatus::Applied && self.applied_action_count != 0)
        {
            return Err(ProtocolError::InvalidInputAck);
        }
        Ok(())
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

/// Ordered stage in the isolated ICE connectivity-probe transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IceProbeStage {
    ClientNominated = 1,
    HostNominated = 2,
    ClientReady = 3,
    HostReady = 4,
    ReadyAck = 5,
    EchoRequest = 6,
    EchoResponse = 7,
    Complete = 8,
}

impl TryFrom<u8> for IceProbeStage {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientNominated),
            2 => Ok(Self::HostNominated),
            3 => Ok(Self::ClientReady),
            4 => Ok(Self::HostReady),
            5 => Ok(Self::ReadyAck),
            6 => Ok(Self::EchoRequest),
            7 => Ok(Self::EchoResponse),
            8 => Ok(Self::Complete),
            other => Err(ProtocolError::InvalidIceProbeStage(other)),
        }
    }
}

/// Fixed-size transcript record shared by the authenticated readiness barrier
/// and the isolated probe connection. It binds every stage to the full active
/// session stamp, one ICE generation, and fresh nonces contributed by both
/// peers. Nonces are correlation values; exact mTLS supplies authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IceProbeMessage {
    pub version: u8,
    pub stage: IceProbeStage,
    pub ice_generation: u32,
    pub stamp: quic::SessionStamp,
    pub client_nonce: [u8; 16],
    pub host_nonce: [u8; 16],
    pub challenge: [u8; 32],
}

impl IceProbeMessage {
    pub const VERSION: u8 = 1;
    pub const ENCODED_LEN: usize = 100;

    pub fn encode(self) -> Result<[u8; Self::ENCODED_LEN], ProtocolError> {
        self.validate()?;
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0] = self.version;
        out[1] = self.stage as u8;
        out[4..8].copy_from_slice(&self.ice_generation.to_be_bytes());
        out[8..16].copy_from_slice(&self.stamp.session_id.to_be_bytes());
        out[16..24].copy_from_slice(&self.stamp.generation.to_be_bytes());
        out[24..28].copy_from_slice(&self.stamp.authorization_epoch.to_be_bytes());
        out[28..32].copy_from_slice(&self.stamp.display_epoch.to_be_bytes());
        out[32..36].copy_from_slice(&self.stamp.codec_epoch.to_be_bytes());
        out[36..52].copy_from_slice(&self.client_nonce);
        out[52..68].copy_from_slice(&self.host_nonce);
        out[68..100].copy_from_slice(&self.challenge);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::PayloadLength {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[2..4] != [0, 0] {
            return Err(ProtocolError::ReservedBits);
        }
        let mut client_nonce = [0_u8; 16];
        client_nonce.copy_from_slice(&bytes[36..52]);
        let mut host_nonce = [0_u8; 16];
        host_nonce.copy_from_slice(&bytes[52..68]);
        let mut challenge = [0_u8; 32];
        challenge.copy_from_slice(&bytes[68..100]);
        let message = Self {
            version: bytes[0],
            stage: IceProbeStage::try_from(bytes[1])?,
            ice_generation: read_u32(bytes, 4),
            stamp: quic::SessionStamp {
                session_id: read_u64(bytes, 8),
                generation: read_u64(bytes, 16),
                authorization_epoch: read_u32(bytes, 24),
                display_epoch: read_u32(bytes, 28),
                codec_epoch: read_u32(bytes, 32),
            },
            client_nonce,
            host_nonce,
            challenge,
        };
        message.validate()?;
        Ok(message)
    }

    fn validate(self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.ice_generation == 0
            || self.stamp.validate_pending().is_err()
            || self.stamp.authorization_epoch == 0
            || self.stamp.display_epoch == 0
            || self.stamp.codec_epoch == 0
            || self.client_nonce == [0; 16]
            || (self.stage == IceProbeStage::ClientNominated && self.host_nonce != [0; 16])
            || (self.stage != IceProbeStage::ClientNominated && self.host_nonce == [0; 16])
            || (matches!(
                self.stage,
                IceProbeStage::EchoRequest | IceProbeStage::EchoResponse | IceProbeStage::Complete
            ) && self.challenge == [0; 32])
            || (!matches!(
                self.stage,
                IceProbeStage::EchoRequest | IceProbeStage::EchoResponse | IceProbeStage::Complete
            ) && self.challenge != [0; 32])
        {
            return Err(ProtocolError::InvalidIceProbeMessage);
        }
        Ok(())
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
        if !is_usable_candidate_address(self.ip) {
            return Err(ProtocolError::InvalidCandidateAddress);
        }
        if let Some((related, rel_port)) = self.related_address {
            if rel_port == 0 {
                return Err(ProtocolError::InvalidCandidatePort);
            }
            if !is_usable_candidate_address(related) {
                return Err(ProtocolError::InvalidCandidateAddress);
            }
        }
        let is_relayed = self.candidate_type == CandidateType::Relayed;
        let has_relay_provider = self.relay_provider != RelayProvider::None;
        if is_relayed != has_relay_provider {
            return Err(ProtocolError::InvalidCandidateRelayProvider);
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

/// Version 1 candidate advertisement payload carried by `ControlKind::IceCandidate`.
///
/// The payload is deliberately an advertisement only: TCP and relayed candidates
/// are rejected until a later version defines their connectivity semantics. A
/// Duplicate detection uses a conservative endpoint key (component, transport,
/// primary address, and port). This is stricter than full RFC 8445 redundancy
/// until this descriptor grows an explicit base address, so changing foundation,
/// priority, or type cannot bypass deduplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateExchange {
    pub version: u8,
    pub exchange_id: u64,
    pub generation: u32,
    pub candidates: Vec<IceCandidate>,
}

/// Role used by the authenticated ICE credential signaling exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IceCredentialRole {
    Controlling = 1,
    Controlled = 2,
}

impl TryFrom<u8> for IceCredentialRole {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Controlling),
            2 => Ok(Self::Controlled),
            other => Err(ProtocolError::InvalidIceCredentialRole(other)),
        }
    }
}

/// Version-one ICE credentials. This is signaling only: it does not claim
/// candidate pair checks, NAT traversal, relay use, or connectivity.
pub struct IceCredentialExchange {
    pub version: u8,
    pub exchange_id: u64,
    pub generation: u32,
    pub role: IceCredentialRole,
    ufrag: String,
    password: String,
}

impl fmt::Debug for IceCredentialExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceCredentialExchange")
            .field("version", &self.version)
            .field("exchange_id", &self.exchange_id)
            .field("generation", &self.generation)
            .field("role", &self.role)
            .field("ufrag", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

impl PartialEq for IceCredentialExchange {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.exchange_id == other.exchange_id
            && self.generation == other.generation
            && self.role == other.role
            && self.ufrag == other.ufrag
            && self.password == other.password
    }
}
impl Eq for IceCredentialExchange {}

impl Drop for IceCredentialExchange {
    fn drop(&mut self) {
        self.ufrag.zeroize();
        self.password.zeroize();
    }
}

impl IceCredentialExchange {
    pub const VERSION: u8 = 1;
    const HEADER_LEN: usize = 18;
    pub const MIN_UFRAG_LEN: usize = 4;
    pub const MAX_UFRAG_LEN: usize = 64;
    pub const MIN_PASSWORD_LEN: usize = 22;
    pub const MAX_PASSWORD_LEN: usize = 128;

    pub fn new(
        version: u8,
        exchange_id: u64,
        generation: u32,
        role: IceCredentialRole,
        ufrag: String,
        password: String,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            version,
            exchange_id,
            generation,
            role,
            ufrag,
            password,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn ufrag(&self) -> &str {
        &self.ufrag
    }
    pub const fn password_len(&self) -> usize {
        self.password.len()
    }
    pub fn with_password<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        f(&self.password)
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(
            Self::HEADER_LEN + self.ufrag.len() + self.password.len(),
        ));
        out.push(self.version);
        out.extend_from_slice(&self.exchange_id.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(self.role as u8);
        out.extend_from_slice(&(self.ufrag.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.password.len() as u16).to_be_bytes());
        out.extend_from_slice(self.ufrag.as_bytes());
        out.extend_from_slice(self.password.as_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_CONTROL_BYTES as usize {
            return Err(ProtocolError::ControlLength(
                u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            ));
        }
        if bytes.len() < Self::HEADER_LEN {
            return Err(ProtocolError::Truncated {
                expected: Self::HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let ulen = read_u16(bytes, 14) as usize;
        let plen = read_u16(bytes, 16) as usize;
        if !(Self::MIN_UFRAG_LEN..=Self::MAX_UFRAG_LEN).contains(&ulen) {
            return Err(ProtocolError::InvalidIceCredentialUfrag);
        }
        if !(Self::MIN_PASSWORD_LEN..=Self::MAX_PASSWORD_LEN).contains(&plen) {
            return Err(ProtocolError::InvalidIceCredentialPassword);
        }
        let expected = Self::HEADER_LEN
            .checked_add(ulen)
            .and_then(|n| n.checked_add(plen))
            .ok_or(ProtocolError::PacketLength)?;
        if bytes.len() != expected {
            return Err(ProtocolError::PayloadLength {
                expected,
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let exchange_id = read_u64(bytes, 1);
        if exchange_id == 0 {
            return Err(ProtocolError::InvalidIceCredentialExchangeId);
        }
        let generation = read_u32(bytes, 9);
        if generation == 0 {
            return Err(ProtocolError::InvalidIceCredentialGeneration);
        }
        let role = IceCredentialRole::try_from(bytes[13])?;
        let split = Self::HEADER_LEN + ulen;
        if !ice_bytes_charset(&bytes[Self::HEADER_LEN..split]) {
            return Err(ProtocolError::InvalidIceCredentialUfrag);
        }
        if !ice_bytes_charset(&bytes[split..]) {
            return Err(ProtocolError::InvalidIceCredentialPassword);
        }
        let mut ufrag = secret_string_from_bytes(&bytes[Self::HEADER_LEN..split])?;
        let password = match secret_string_from_bytes(&bytes[split..]) {
            Ok(password) => password,
            Err(error) => {
                ufrag.zeroize();
                return Err(error);
            }
        };
        Self::new(version, exchange_id, generation, role, ufrag, password)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.exchange_id == 0 {
            return Err(ProtocolError::InvalidIceCredentialExchangeId);
        }
        if self.generation == 0 {
            return Err(ProtocolError::InvalidIceCredentialGeneration);
        }
        if !(Self::MIN_UFRAG_LEN..=Self::MAX_UFRAG_LEN).contains(&self.ufrag.len())
            || !ice_charset(&self.ufrag)
        {
            return Err(ProtocolError::InvalidIceCredentialUfrag);
        }
        if !(Self::MIN_PASSWORD_LEN..=Self::MAX_PASSWORD_LEN).contains(&self.password.len())
            || !ice_charset(&self.password)
        {
            return Err(ProtocolError::InvalidIceCredentialPassword);
        }
        Ok(())
    }
}

/// Authenticated peer's role in one rendezvous match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RendezvousRole {
    Initiator = 1,
    Responder = 2,
}

impl TryFrom<u8> for RendezvousRole {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Initiator),
            2 => Ok(Self::Responder),
            other => Err(ProtocolError::InvalidRendezvousRole(other)),
        }
    }
}

/// One bounded rendezvous registration carried only after the service has
/// authenticated the connection's client certificate. The payload can carry
/// connectivity metadata and short-term ICE credentials, never desktop data.
#[derive(Debug, PartialEq, Eq)]
pub struct RendezvousRegistration {
    pub version: u8,
    pub role: RendezvousRole,
    pub generation: u32,
    pub ttl_seconds: u16,
    pub match_id: [u8; 16],
    pub expected_peer_fingerprint: [u8; 32],
    pub credentials: IceCredentialExchange,
    pub candidates: CandidateExchange,
}

impl RendezvousRegistration {
    pub const VERSION: u8 = 1;
    pub const HEADER_LEN: usize = 68;
    pub const MIN_TTL_SECONDS: u16 = 5;
    pub const MAX_TTL_SECONDS: u16 = 120;
    pub const MAX_ENCODED_LEN: usize = 4 * 1024;

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        self.validate()?;
        let credentials = self.credentials.encode()?;
        let candidates = self.candidates.encode()?;
        let total = Self::HEADER_LEN
            .checked_add(credentials.len())
            .and_then(|value| value.checked_add(candidates.len()))
            .ok_or(ProtocolError::PacketLength)?;
        if total > Self::MAX_ENCODED_LEN {
            return Err(ProtocolError::RendezvousLength(total));
        }
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        out.push(self.version);
        out.push(self.role as u8);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.ttl_seconds.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.match_id);
        out.extend_from_slice(&self.expected_peer_fingerprint);
        out.extend_from_slice(&(credentials.len() as u32).to_be_bytes());
        out.extend_from_slice(&(candidates.len() as u32).to_be_bytes());
        out.extend_from_slice(&credentials);
        out.extend_from_slice(&candidates);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > Self::MAX_ENCODED_LEN {
            return Err(ProtocolError::RendezvousLength(bytes.len()));
        }
        if bytes.len() < Self::HEADER_LEN {
            return Err(ProtocolError::Truncated {
                expected: Self::HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[2..4] != [0, 0] || bytes[10..12] != [0, 0] {
            return Err(ProtocolError::ReservedBits);
        }
        let credentials_len = read_u32(bytes, 60) as usize;
        let candidates_len = read_u32(bytes, 64) as usize;
        let expected = Self::HEADER_LEN
            .checked_add(credentials_len)
            .and_then(|value| value.checked_add(candidates_len))
            .ok_or(ProtocolError::PacketLength)?;
        if expected != bytes.len() {
            return Err(ProtocolError::PayloadLength {
                expected,
                actual: bytes.len(),
            });
        }
        let credentials_end = Self::HEADER_LEN + credentials_len;
        let mut match_id = [0_u8; 16];
        match_id.copy_from_slice(&bytes[12..28]);
        let mut expected_peer_fingerprint = [0_u8; 32];
        expected_peer_fingerprint.copy_from_slice(&bytes[28..60]);
        let registration = Self {
            version: bytes[0],
            role: RendezvousRole::try_from(bytes[1])?,
            generation: read_u32(bytes, 4),
            ttl_seconds: read_u16(bytes, 8),
            match_id,
            expected_peer_fingerprint,
            credentials: IceCredentialExchange::decode(&bytes[Self::HEADER_LEN..credentials_end])?,
            candidates: CandidateExchange::decode(&bytes[credentials_end..])?,
        };
        registration.validate()?;
        Ok(registration)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.generation == 0
            || !(Self::MIN_TTL_SECONDS..=Self::MAX_TTL_SECONDS).contains(&self.ttl_seconds)
            || self.match_id == [0; 16]
            || self.expected_peer_fingerprint == [0; 32]
            || self.credentials.generation != self.generation
            || self.candidates.generation != self.generation
            || self.credentials.exchange_id != self.candidates.exchange_id
            || !matches!(
                (self.role, self.credentials.role),
                (RendezvousRole::Initiator, IceCredentialRole::Controlling)
                    | (RendezvousRole::Responder, IceCredentialRole::Controlled)
            )
        {
            return Err(ProtocolError::InvalidRendezvousRegistration);
        }
        self.credentials.validate()?;
        self.candidates.encode()?;
        Ok(())
    }
}

fn secret_string_from_bytes(bytes: &[u8]) -> Result<String, ProtocolError> {
    match String::from_utf8(bytes.to_vec()) {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut rejected = error.into_bytes();
            rejected.zeroize();
            Err(ProtocolError::InvalidIceCredentialCharset)
        }
    }
}

fn ice_charset(value: &str) -> bool {
    ice_bytes_charset(value.as_bytes())
}

fn ice_bytes_charset(value: &[u8]) -> bool {
    value
        .iter()
        .copied()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
}

impl CandidateExchange {
    pub const VERSION: u8 = 1;
    pub const MAX_CANDIDATES: usize = 8;
    const HEADER_LEN: usize = 14;

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.candidates.len() * 40);
        out.push(self.version);
        out.extend_from_slice(&self.exchange_id.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(self.candidates.len() as u8);
        for candidate in &self.candidates {
            let encoded = candidate.encode()?;
            out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
            out.extend_from_slice(&encoded);
        }
        if out.len() > MAX_CONTROL_BYTES as usize {
            return Err(ProtocolError::CandidateExchangeLength(out.len()));
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(ProtocolError::Truncated {
                expected: Self::HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes.len() > MAX_CONTROL_BYTES as usize {
            return Err(ProtocolError::CandidateExchangeLength(bytes.len()));
        }
        let version = bytes[0];
        if version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let exchange_id = read_u64(bytes, 1);
        let generation = read_u32(bytes, 9);
        let count = bytes[13] as usize;
        if count == 0 || count > Self::MAX_CANDIDATES {
            return Err(ProtocolError::CandidateExchangeCount(count));
        }
        let mut cursor = Self::HEADER_LEN;
        let mut candidates = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < cursor + 2 {
                return Err(ProtocolError::Truncated {
                    expected: cursor + 2,
                    actual: bytes.len(),
                });
            }
            let len = read_u16(bytes, cursor) as usize;
            cursor += 2;
            let end = cursor.checked_add(len).ok_or(ProtocolError::PacketLength)?;
            if end > bytes.len() {
                return Err(ProtocolError::Truncated {
                    expected: end,
                    actual: bytes.len(),
                });
            }
            candidates.push(IceCandidate::decode(&bytes[cursor..end])?);
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(ProtocolError::PayloadLength {
                expected: cursor,
                actual: bytes.len(),
            });
        }
        let exchange = Self {
            version,
            exchange_id,
            generation,
            candidates,
        };
        exchange.validate()?;
        Ok(exchange)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.exchange_id == 0 {
            return Err(ProtocolError::InvalidCandidateExchangeId);
        }
        if self.generation == 0 {
            return Err(ProtocolError::InvalidCandidateGeneration);
        }
        if self.candidates.is_empty() || self.candidates.len() > Self::MAX_CANDIDATES {
            return Err(ProtocolError::CandidateExchangeCount(self.candidates.len()));
        }
        let family = |ip: WireIpAddr| matches!(ip, WireIpAddr::V4(_));
        let first_family = family(self.candidates[0].ip);
        for (index, candidate) in self.candidates.iter().enumerate() {
            candidate.validate()?;
            if candidate.transport == TransportProtocol::Tcp {
                return Err(ProtocolError::UnsupportedCandidateTransport);
            }
            if candidate.candidate_type == CandidateType::Relayed {
                return Err(ProtocolError::UnsupportedCandidateType);
            }
            if family(candidate.ip) != first_family {
                return Err(ProtocolError::MixedCandidateAddressFamily);
            }
            if let Some((related, _)) = candidate.related_address {
                if family(related) != first_family {
                    return Err(ProtocolError::RelatedCandidateAddressFamily);
                }
            }
            for prior in &self.candidates[..index] {
                if prior.component == candidate.component
                    && prior.transport == candidate.transport
                    && prior.ip == candidate.ip
                    && prior.port == candidate.port
                {
                    return Err(ProtocolError::DuplicateCandidate);
                }
            }
        }
        Ok(())
    }
}

fn is_usable_candidate_address(address: WireIpAddr) -> bool {
    match address {
        WireIpAddr::V4(octets) => {
            octets != [0; 4] && octets != [255; 4] && octets[0] & 0xf0 != 0xe0
        }
        WireIpAddr::V6(octets) => octets != [0; 16] && octets[0] != 0xff,
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
    UnknownInputAckStatus(u8),
    UnknownVideoStreamFlags(u32),
    ConflictingIceSignalingModes,
    IceProbeRequiresCredentials,
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
    UnsupportedCodecContract(u16),
    InvalidCodecCapabilities(u16),
    UnknownVideoCodec(u8),
    UnknownVideoProfile(u8),
    InvalidVideoProfile,
    InvalidVideoGeometry,
    InvalidHandshake,
    InvalidInputAck,
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
    InvalidCandidateRelayProvider,
    InvalidCandidatePort,
    InvalidCandidateComponent,
    InvalidCandidateAddress,
    InvalidCandidateExchangeId,
    InvalidCandidateGeneration,
    InvalidIceCredentialExchangeId,
    InvalidIceCredentialGeneration,
    InvalidIceCredentialRole(u8),
    InvalidIceCredentialUfrag,
    InvalidIceCredentialPassword,
    InvalidIceCredentialCharset,
    InvalidIceProbeStage(u8),
    InvalidIceProbeMessage,
    InvalidRendezvousRole(u8),
    InvalidRendezvousRegistration,
    RendezvousLength(usize),
    CandidateExchangeCount(usize),
    CandidateExchangeLength(usize),
    DuplicateCandidate,
    MixedCandidateAddressFamily,
    UnsupportedCandidateTransport,
    UnsupportedCandidateType,
    RelatedCandidateAddressFamily,
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

    #[test]
    fn input_applied_ack_round_trip_and_fail_closed_fields() {
        let stamp = quic::SessionStamp {
            session_id: 41,
            generation: 2,
            authorization_epoch: 3,
            display_epoch: 4,
            codec_epoch: 5,
        };
        let ack = InputAppliedAck {
            stamp,
            input_epoch: 3,
            input_sequence: 9,
            ack_sequence: 1,
            status: InputAckStatus::Applied,
            applied_action_count: 1,
        };
        let encoded = ack.encode().expect("ack encode");
        assert_eq!(InputAppliedAck::decode(&encoded).expect("ack decode"), ack);

        let mut malformed = encoded;
        malformed[1] = 0xff;
        assert_eq!(
            InputAppliedAck::decode(&malformed),
            Err(ProtocolError::UnknownInputAckStatus(0xff))
        );
        malformed = encoded;
        malformed[2] = 1;
        assert_eq!(
            InputAppliedAck::decode(&malformed),
            Err(ProtocolError::ReservedBits)
        );

        let invalid = InputAppliedAck {
            input_epoch: 4,
            ..ack
        };
        assert_eq!(invalid.encode(), Err(ProtocolError::InvalidInputAck));
        let invalid = InputAppliedAck {
            status: InputAckStatus::IgnoredStaleSequence,
            applied_action_count: 1,
            ..ack
        };
        assert_eq!(invalid.encode(), Err(ProtocolError::InvalidInputAck));
    }

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
    fn video_codec_contract_round_trip_is_explicit() {
        let capabilities = VideoCodecCapabilities {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            flags: video_capability_flags::H264_HIGH_420
                | video_capability_flags::INPUT_APPLIED_ACK
                | video_capability_flags::AUTHENTICATED_CANDIDATE_EXCHANGE,
            max_width: 3_840,
            max_height: 2_160,
            max_fps: 120,
        };
        assert_eq!(
            VideoCodecCapabilities::decode(&capabilities.encode().expect("capabilities")),
            Ok(capabilities)
        );
        assert!(capabilities.supports_input_applied_ack());
        assert!(capabilities.supports_authenticated_candidate_exchange());

        let config = VideoStreamConfig {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            codec: VideoCodec::H264,
            profile: VideoProfile::H264High420,
            pixel_format: u32::from_le_bytes(*b"NV12"),
            stream_id: 1,
            codec_epoch: 7,
            width: 1_920,
            height: 1_080,
            fps: 60,
            target_bitrate_bps: 30_000_000,
            flags: 0,
        };
        assert_eq!(
            VideoStreamConfig::decode(&config.encode().expect("config")),
            Ok(config)
        );

        let input_ack_capable = VideoStreamConfig {
            flags: video_stream_flags::INPUT_APPLIED_ACK
                | video_stream_flags::AUTHENTICATED_CANDIDATE_EXCHANGE,
            ..config
        };
        assert_eq!(
            VideoStreamConfig::decode(
                &input_ack_capable
                    .encode()
                    .expect("input ACK capability config")
            ),
            Ok(input_ack_capable)
        );
        assert!(input_ack_capable.supports_authenticated_candidate_exchange());
        let unknown = VideoStreamConfig {
            flags: 1 << 31,
            ..config
        };
        assert_eq!(
            unknown.encode(),
            Err(ProtocolError::UnknownVideoStreamFlags(1 << 31))
        );
    }

    #[test]
    fn raw_nv12_requires_an_explicit_codec_profile_pair() {
        let mismatched = VideoStreamConfig {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            codec: VideoCodec::RawNv12,
            profile: VideoProfile::H264High420,
            pixel_format: u32::from_le_bytes(*b"NV12"),
            stream_id: 1,
            codec_epoch: 1,
            width: 1_280,
            height: 720,
            fps: 60,
            target_bitrate_bps: 30_000_000,
            flags: 0,
        };
        assert_eq!(mismatched.encode(), Err(ProtocolError::InvalidVideoProfile));
    }

    #[test]
    fn host_prefers_h264_when_both_peers_offer_it() {
        let client = VideoCodecCapabilities {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            flags: video_capability_flags::H264_HIGH_420 | video_capability_flags::RAW_NV12,
            max_width: 1_280,
            max_height: 720,
            max_fps: 60,
        };
        assert_eq!(
            select_host_codec(client, true, true),
            Ok((VideoCodec::H264, VideoProfile::H264High420))
        );
        assert_eq!(
            select_host_codec(client, false, true),
            Ok((VideoCodec::RawNv12, VideoProfile::RawNv12))
        );
        assert!(select_host_codec(client, false, false).is_err());
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
    fn ice_candidate_rejects_inconsistent_relay_provider() {
        let mut candidate = IceCandidate {
            foundation: [1; 8],
            component: 1,
            transport: TransportProtocol::Udp,
            priority: compute_candidate_priority(CandidateType::Host, 100, 1),
            candidate_type: CandidateType::Host,
            relay_provider: RelayProvider::Turn,
            ip: WireIpAddr::V4([192, 0, 2, 10]),
            port: 50_000,
            related_address: None,
        };
        assert!(candidate.validate().is_err());

        candidate.candidate_type = CandidateType::Relayed;
        candidate.relay_provider = RelayProvider::None;
        candidate.priority = compute_candidate_priority(CandidateType::Relayed, 100, 1);
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn ice_candidate_rejects_unspecified_and_multicast_addresses() {
        let mut candidate = IceCandidate {
            foundation: [1; 8],
            component: 1,
            transport: TransportProtocol::Udp,
            priority: compute_candidate_priority(CandidateType::Host, 100, 1),
            candidate_type: CandidateType::Host,
            relay_provider: RelayProvider::None,
            ip: WireIpAddr::V4([0, 0, 0, 0]),
            port: 50_000,
            related_address: None,
        };
        assert!(candidate.validate().is_err());

        candidate.ip = WireIpAddr::V4([224, 0, 0, 1]);
        assert!(candidate.validate().is_err());

        candidate.ip = WireIpAddr::V6([0; 16]);
        assert!(candidate.validate().is_err());

        let mut multicast_v6 = [0; 16];
        multicast_v6[0] = 0xff;
        candidate.ip = WireIpAddr::V6(multicast_v6);
        assert!(candidate.validate().is_err());
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

    fn exchange_candidate(ip: WireIpAddr, port: u16) -> IceCandidate {
        IceCandidate {
            foundation: [port as u8; 8],
            component: 1,
            transport: TransportProtocol::Udp,
            priority: compute_candidate_priority(CandidateType::Host, 100, 1),
            candidate_type: CandidateType::Host,
            relay_provider: RelayProvider::None,
            ip,
            port,
            related_address: None,
        }
    }

    #[test]
    fn candidate_exchange_round_trip_v4_and_v6() {
        for candidate in [
            exchange_candidate(WireIpAddr::V4([192, 0, 2, 1]), 4000),
            exchange_candidate(
                WireIpAddr::V6([0x20, 1, 0xdb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                4001,
            ),
        ] {
            let exchange = CandidateExchange {
                version: 1,
                exchange_id: 7,
                generation: 1,
                candidates: vec![candidate],
            };
            assert_eq!(
                CandidateExchange::decode(&exchange.encode().unwrap()).unwrap(),
                exchange
            );
        }
    }

    #[test]
    fn candidate_exchange_rejects_bounds_duplicates_and_mixed_family() {
        let c = exchange_candidate(WireIpAddr::V4([192, 0, 2, 1]), 4000);
        let mut too_many = vec![c; 9];
        for (i, item) in too_many.iter_mut().enumerate() {
            item.port += i as u16;
            item.foundation[0] = i as u8;
        }
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 1,
                candidates: too_many
            }
            .encode(),
            Err(ProtocolError::CandidateExchangeCount(9))
        );
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 0,
                generation: 1,
                candidates: vec![c]
            }
            .encode(),
            Err(ProtocolError::InvalidCandidateExchangeId)
        );
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 0,
                candidates: vec![c]
            }
            .encode(),
            Err(ProtocolError::InvalidCandidateGeneration)
        );
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 1,
                candidates: vec![c, c]
            }
            .encode(),
            Err(ProtocolError::DuplicateCandidate)
        );
        let mut same_endpoint = c;
        same_endpoint.foundation = [99; 8];
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 1,
                candidates: vec![c, same_endpoint]
            }
            .encode(),
            Err(ProtocolError::DuplicateCandidate)
        );
        let v6 = exchange_candidate(WireIpAddr::V6([1; 16]), 4001);
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 1,
                candidates: vec![c, v6]
            }
            .encode(),
            Err(ProtocolError::MixedCandidateAddressFamily)
        );
    }

    #[test]
    fn candidate_exchange_rejects_unsupported_and_trailing() {
        let mut c = exchange_candidate(WireIpAddr::V4([192, 0, 2, 1]), 4000);
        c.transport = TransportProtocol::Tcp;
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 1,
                candidates: vec![c]
            }
            .encode(),
            Err(ProtocolError::UnsupportedCandidateTransport)
        );
        let mut relayed = exchange_candidate(WireIpAddr::V4([192, 0, 2, 1]), 4000);
        relayed.candidate_type = CandidateType::Relayed;
        relayed.relay_provider = RelayProvider::Turn;
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 1,
                candidates: vec![relayed]
            }
            .encode(),
            Err(ProtocolError::UnsupportedCandidateType)
        );
        let mut related_family = exchange_candidate(WireIpAddr::V4([192, 0, 2, 1]), 4000);
        related_family.related_address = Some((WireIpAddr::V6([1; 16]), 4001));
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 1,
                candidates: vec![related_family]
            }
            .encode(),
            Err(ProtocolError::RelatedCandidateAddressFamily)
        );
        let c = exchange_candidate(WireIpAddr::V4([192, 0, 2, 1]), 4000);
        let mut bytes = CandidateExchange {
            version: 1,
            exchange_id: 1,
            generation: 1,
            candidates: vec![c],
        }
        .encode()
        .unwrap();
        bytes.push(0);
        assert!(matches!(
            CandidateExchange::decode(&bytes),
            Err(ProtocolError::PayloadLength { .. })
        ));
        bytes[13] = 2;
        assert!(matches!(
            CandidateExchange::decode(&bytes[..15]),
            Err(ProtocolError::Truncated { .. })
        ));
    }

    #[test]
    fn candidate_exchange_rejects_empty_wrong_version_and_count_nine() {
        let c = exchange_candidate(WireIpAddr::V4([192, 0, 2, 1]), 4000);
        assert_eq!(
            CandidateExchange {
                version: 1,
                exchange_id: 1,
                generation: 1,
                candidates: vec![]
            }
            .encode(),
            Err(ProtocolError::CandidateExchangeCount(0))
        );
        let eight = (0..8)
            .map(|i| exchange_candidate(WireIpAddr::V4([192, 0, 2, i + 1]), 4000 + i as u16))
            .collect();
        assert!(CandidateExchange {
            version: 1,
            exchange_id: 1,
            generation: 1,
            candidates: eight
        }
        .encode()
        .is_ok());
        let mut bytes = CandidateExchange {
            version: 1,
            exchange_id: 1,
            generation: 1,
            candidates: vec![c],
        }
        .encode()
        .unwrap();
        bytes[13] = 9;
        assert!(matches!(
            CandidateExchange::decode(&bytes),
            Err(ProtocolError::CandidateExchangeCount(9))
        ));
        bytes[0] = 2;
        assert_eq!(
            CandidateExchange::decode(&bytes),
            Err(ProtocolError::UnsupportedVersion(2))
        );
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

    fn ice_creds(ulen: usize, plen: usize) -> IceCredentialExchange {
        IceCredentialExchange::new(
            1,
            7,
            3,
            IceCredentialRole::Controlling,
            "A".repeat(ulen),
            "B".repeat(plen),
        )
        .unwrap()
    }

    #[test]
    fn ice_credentials_round_trip_and_debug_redaction() {
        let value = IceCredentialExchange::new(
            1,
            9,
            2,
            IceCredentialRole::Controlled,
            "uFrag".into(),
            "secretpasswordABCDEFGHIJKLMNOP".into(),
        )
        .unwrap();
        let encoded = value.encode().unwrap();
        assert_eq!(IceCredentialExchange::decode(&encoded).unwrap(), value);
        let debug = format!("{value:?}");
        assert!(!debug.contains("uFrag") && !debug.contains("secretpassword"));
        assert_eq!(value.password_len(), 30);
        assert_eq!(value.with_password(|p| p.len()), 30);
    }

    #[test]
    fn ice_credentials_boundaries_and_invalid_fields() {
        assert!(ice_creds(4, 22).encode().is_ok());
        assert!(ice_creds(64, 128).encode().is_ok());
        for version in [0, 2] {
            assert_eq!(
                IceCredentialExchange::new(
                    version,
                    1,
                    1,
                    IceCredentialRole::Controlling,
                    "ABCD".into(),
                    "ABCDEFGHIJKLMNOPQRSTUV".into()
                )
                .unwrap_err(),
                ProtocolError::UnsupportedVersion(version)
            );
        }
        assert!(matches!(
            IceCredentialExchange::new(
                1,
                0,
                1,
                IceCredentialRole::Controlling,
                "ABCD".into(),
                "ABCDEFGHIJKLMNOPQRSTUV".into()
            ),
            Err(ProtocolError::InvalidIceCredentialExchangeId)
        ));
        assert!(matches!(
            IceCredentialExchange::new(
                1,
                1,
                0,
                IceCredentialRole::Controlling,
                "ABCD".into(),
                "ABCDEFGHIJKLMNOPQRSTUV".into()
            ),
            Err(ProtocolError::InvalidIceCredentialGeneration)
        ));
        assert!(IceCredentialExchange::new(
            1,
            7,
            3,
            IceCredentialRole::Controlling,
            "AAA".into(),
            "B".repeat(22)
        )
        .is_err());
        assert!(IceCredentialExchange::new(
            1,
            7,
            3,
            IceCredentialRole::Controlling,
            "A".repeat(65),
            "B".repeat(22)
        )
        .is_err());
        assert!(IceCredentialExchange::new(
            1,
            7,
            3,
            IceCredentialRole::Controlling,
            "AAAA".into(),
            "B".repeat(21)
        )
        .is_err());
        assert!(IceCredentialExchange::new(
            1,
            7,
            3,
            IceCredentialRole::Controlling,
            "AAAA".into(),
            "B".repeat(129)
        )
        .is_err());
        assert!(IceCredentialExchange::new(
            1,
            1,
            1,
            IceCredentialRole::Controlling,
            "AB-D".into(),
            "ABCDEFGHIJKLMNOPQRSTUV".into()
        )
        .is_err());
    }

    #[test]
    fn ice_credentials_decode_is_exact_and_bounded() {
        let encoded = ice_creds(4, 22).encode().unwrap();
        for end in 0..18 {
            assert!(IceCredentialExchange::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            IceCredentialExchange::decode(&trailing),
            Err(ProtocolError::PayloadLength { .. })
        ));
        let mut declared = encoded.clone();
        declared[14..16].copy_from_slice(&5u16.to_be_bytes());
        assert!(IceCredentialExchange::decode(&declared).is_err());
        let mut oversized_ufrag = encoded.clone();
        oversized_ufrag[14..16].copy_from_slice(&65u16.to_be_bytes());
        assert!(matches!(
            IceCredentialExchange::decode(&oversized_ufrag),
            Err(ProtocolError::InvalidIceCredentialUfrag)
        ));
        let mut oversized_password = encoded.clone();
        oversized_password[16..18].copy_from_slice(&129u16.to_be_bytes());
        assert!(matches!(
            IceCredentialExchange::decode(&oversized_password),
            Err(ProtocolError::InvalidIceCredentialPassword)
        ));
        let mut invalid_ufrag = encoded.clone();
        invalid_ufrag[18] = b'-';
        assert!(matches!(
            IceCredentialExchange::decode(&invalid_ufrag),
            Err(ProtocolError::InvalidIceCredentialUfrag)
        ));
        assert!(matches!(
            IceCredentialExchange::decode(&vec![0; MAX_CONTROL_BYTES as usize + 1]),
            Err(ProtocolError::ControlLength(_))
        ));
        let mut role = encoded;
        role[13] = 9;
        assert!(matches!(
            IceCredentialExchange::decode(&role),
            Err(ProtocolError::InvalidIceCredentialRole(9))
        ));
    }

    #[test]
    fn ice_credentials_capability_flags_are_explicit() {
        let c = VideoCodecCapabilities {
            contract_version: 1,
            flags: video_capability_flags::H264_HIGH_420
                | video_capability_flags::AUTHENTICATED_ICE_CREDENTIALS,
            max_width: 2,
            max_height: 2,
            max_fps: 1,
        };
        assert!(c.supports_authenticated_ice_credentials());
        let selected = VideoStreamConfig {
            contract_version: 1,
            codec: VideoCodec::H264,
            profile: VideoProfile::H264High420,
            pixel_format: u32::from_le_bytes(*b"NV12"),
            stream_id: 1,
            codec_epoch: 1,
            width: 2,
            height: 2,
            fps: 1,
            target_bitrate_bps: 1,
            flags: video_stream_flags::AUTHENTICATED_ICE_CREDENTIALS,
        };
        assert!(VideoStreamConfig::decode(&selected.encode().unwrap())
            .unwrap()
            .supports_authenticated_ice_credentials());
        assert!(matches!(
            VideoStreamConfig {
                flags: 1 << 31,
                ..selected
            }
            .encode(),
            Err(ProtocolError::UnknownVideoStreamFlags(_))
        ));
        assert!(matches!(
            VideoStreamConfig {
                flags: video_stream_flags::AUTHENTICATED_CANDIDATE_EXCHANGE
                    | video_stream_flags::AUTHENTICATED_ICE_CREDENTIALS,
                ..selected
            }
            .encode(),
            Err(ProtocolError::ConflictingIceSignalingModes)
        ));
    }

    #[test]
    fn ice_probe_capability_requires_authenticated_credentials() {
        let offer = VideoCodecCapabilities {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            flags: video_capability_flags::RAW_NV12
                | video_capability_flags::AUTHENTICATED_ICE_CREDENTIALS
                | video_capability_flags::ICE_CONNECTIVITY_PROBE,
            max_width: 2,
            max_height: 2,
            max_fps: 1,
        };
        assert!(offer.encode().is_ok());
        assert!(offer.supports_ice_connectivity_probe());
        assert!(matches!(
            VideoCodecCapabilities {
                flags: video_capability_flags::RAW_NV12
                    | video_capability_flags::ICE_CONNECTIVITY_PROBE,
                ..offer
            }
            .encode(),
            Err(ProtocolError::IceProbeRequiresCredentials)
        ));

        let selected = VideoStreamConfig {
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
            flags: video_stream_flags::AUTHENTICATED_ICE_CREDENTIALS
                | video_stream_flags::ICE_CONNECTIVITY_PROBE,
        };
        assert!(selected.encode().is_ok());
        assert!(selected.supports_ice_connectivity_probe());
        assert!(matches!(
            VideoStreamConfig {
                flags: video_stream_flags::ICE_CONNECTIVITY_PROBE,
                ..selected
            }
            .encode(),
            Err(ProtocolError::IceProbeRequiresCredentials)
        ));
    }

    #[test]
    fn ice_probe_control_transcript_is_exact_and_stage_bound() {
        let stamp = quic::SessionStamp {
            session_id: 7,
            generation: 8,
            authorization_epoch: 9,
            display_epoch: 10,
            codec_epoch: 11,
        };
        let client_nonce = [0x11; 16];
        let host_nonce = [0x22; 16];
        let challenge = [0x33; 32];
        for stage in [
            IceProbeStage::ClientNominated,
            IceProbeStage::HostNominated,
            IceProbeStage::ClientReady,
            IceProbeStage::HostReady,
            IceProbeStage::ReadyAck,
            IceProbeStage::EchoRequest,
            IceProbeStage::EchoResponse,
            IceProbeStage::Complete,
        ] {
            let message = IceProbeMessage {
                version: IceProbeMessage::VERSION,
                stage,
                ice_generation: 1,
                stamp,
                client_nonce,
                host_nonce: if stage == IceProbeStage::ClientNominated {
                    [0; 16]
                } else {
                    host_nonce
                },
                challenge: if matches!(
                    stage,
                    IceProbeStage::EchoRequest
                        | IceProbeStage::EchoResponse
                        | IceProbeStage::Complete
                ) {
                    challenge
                } else {
                    [0; 32]
                },
            };
            assert_eq!(
                IceProbeMessage::decode(&message.encode().unwrap()).unwrap(),
                message
            );
        }
        let invalid = IceProbeMessage {
            version: IceProbeMessage::VERSION,
            stage: IceProbeStage::EchoRequest,
            ice_generation: 1,
            stamp,
            client_nonce: [0; 16],
            host_nonce,
            challenge,
        };
        assert!(matches!(
            invalid.encode(),
            Err(ProtocolError::InvalidIceProbeMessage)
        ));
        assert!(IceProbeMessage::decode(&[0; 3]).is_err());
    }

    fn rendezvous_registration(role: RendezvousRole) -> RendezvousRegistration {
        RendezvousRegistration {
            version: RendezvousRegistration::VERSION,
            role,
            generation: 1,
            ttl_seconds: 30,
            match_id: [0x44; 16],
            expected_peer_fingerprint: [0x55; 32],
            credentials: IceCredentialExchange::new(
                1,
                7,
                1,
                match role {
                    RendezvousRole::Initiator => IceCredentialRole::Controlling,
                    RendezvousRole::Responder => IceCredentialRole::Controlled,
                },
                "rendezvousUfrag".into(),
                "R".repeat(32),
            )
            .unwrap(),
            candidates: CandidateExchange {
                version: CandidateExchange::VERSION,
                exchange_id: 7,
                generation: 1,
                candidates: vec![exchange_candidate(WireIpAddr::V4([127, 0, 0, 1]), 5001)],
            },
        }
    }

    #[test]
    fn rendezvous_registration_round_trip_is_bounded_and_secret_safe() {
        let registration = rendezvous_registration(RendezvousRole::Initiator);
        let encoded = registration.encode().unwrap();
        assert_eq!(
            RendezvousRegistration::decode(&encoded).unwrap(),
            registration
        );
        let debug = format!("{registration:?}");
        assert!(!debug.contains("rendezvousUfrag"));
        assert!(!debug.contains(&"R".repeat(32)));
        for end in 0..RendezvousRegistration::HEADER_LEN {
            assert!(RendezvousRegistration::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(RendezvousRegistration::decode(&trailing).is_err());
        let mut declared = encoded.clone();
        declared[60..64].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(RendezvousRegistration::decode(&declared).is_err());
        let mut role = encoded;
        role[1] = 9;
        assert!(matches!(
            RendezvousRegistration::decode(&role),
            Err(ProtocolError::InvalidRendezvousRole(9))
        ));
        assert!(matches!(
            RendezvousRegistration::decode(&vec![0; RendezvousRegistration::MAX_ENCODED_LEN + 1]),
            Err(ProtocolError::RendezvousLength(_))
        ));
    }

    #[test]
    fn rendezvous_registration_rejects_identity_role_generation_and_ttl_drift() {
        let mut registration = rendezvous_registration(RendezvousRole::Initiator);
        registration.match_id = [0; 16];
        assert!(matches!(
            registration.encode(),
            Err(ProtocolError::InvalidRendezvousRegistration)
        ));
        let mut registration = rendezvous_registration(RendezvousRole::Initiator);
        registration.expected_peer_fingerprint = [0; 32];
        assert!(registration.encode().is_err());
        let mut registration = rendezvous_registration(RendezvousRole::Initiator);
        registration.ttl_seconds = 121;
        assert!(registration.encode().is_err());
        let mut registration = rendezvous_registration(RendezvousRole::Initiator);
        registration.candidates.generation = 2;
        assert!(registration.encode().is_err());
        let mut registration = rendezvous_registration(RendezvousRole::Initiator);
        registration.credentials = IceCredentialExchange::new(
            1,
            7,
            1,
            IceCredentialRole::Controlled,
            "rendezvousUfrag".into(),
            "R".repeat(32),
        )
        .unwrap();
        assert!(registration.encode().is_err());
    }
}
