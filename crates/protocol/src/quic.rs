//! QUIC application records.
//!
//! Quinn provides transport authentication, loss recovery, and stream framing.
//! These records only bind application routing to the session epochs and keep
//! every peer-controlled size bounded before an allocator or provider sees it.

use crate::{
    read_u32, read_u64, MediaHeader, MediaPacket, ProtocolError, MAX_CONTROL_BYTES,
    MEDIA_HEADER_LEN, WIRE_VERSION,
};

/// Bytes occupied by a [`SessionStamp`] in a QUIC application record.
pub const SESSION_STAMP_LEN: usize = 36;
/// Bytes in a reliable QUIC stream record header.
pub const STREAM_RECORD_HEADER_LEN: usize = 48;
/// Bytes prepended to a media fragment carried in a QUIC DATAGRAM.
pub const QUIC_MEDIA_HEADER_LEN: usize = 52;
/// Largest input record payload accepted by the protocol.
pub const MAX_INPUT_BYTES: u32 = 64 * 1024;

const STREAM_RECORD_MAGIC: [u8; 4] = *b"LDQS";
const MEDIA_DATAGRAM_MAGIC: [u8; 4] = *b"LDQM";

/// Session identity and lifecycle values that must agree at every provider
/// dispatch boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionStamp {
    /// Opaque nonzero pending or active session identifier.
    pub session_id: u64,
    /// Monotonic local dispatch generation for stale-work rejection.
    pub generation: u64,
    /// Host authorization generation; zero is valid only before authorization.
    pub authorization_epoch: u32,
    /// Selected display generation; zero is valid only before display selection.
    pub display_epoch: u32,
    /// Selected codec generation; zero is valid only before codec selection.
    pub codec_epoch: u32,
    /// Active network route generation. Every on-wire record requires nonzero.
    pub route_epoch: u64,
}

impl SessionStamp {
    /// Validates an identity that may still be in the pairing/control phase.
    pub fn validate_pending(self) -> Result<(), ProtocolError> {
        if self.session_id == 0 || self.generation == 0 || self.route_epoch == 0 {
            return Err(ProtocolError::InvalidSessionStamp);
        }
        Ok(())
    }

    fn validate_input(self) -> Result<(), ProtocolError> {
        self.validate_pending()?;
        if self.authorization_epoch == 0 || self.display_epoch == 0 {
            return Err(ProtocolError::InactiveInputStamp);
        }
        Ok(())
    }

    fn validate_media(self) -> Result<(), ProtocolError> {
        self.validate_pending()?;
        if self.authorization_epoch == 0 || self.display_epoch == 0 || self.codec_epoch == 0 {
            return Err(ProtocolError::InactiveMediaStamp);
        }
        Ok(())
    }

    fn encode_into(self, bytes: &mut [u8]) {
        bytes[0..8].copy_from_slice(&self.session_id.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.generation.to_be_bytes());
        bytes[16..20].copy_from_slice(&self.authorization_epoch.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.display_epoch.to_be_bytes());
        bytes[24..28].copy_from_slice(&self.codec_epoch.to_be_bytes());
        bytes[28..36].copy_from_slice(&self.route_epoch.to_be_bytes());
    }

    fn decode_from(bytes: &[u8], offset: usize) -> Self {
        Self {
            session_id: read_u64(bytes, offset),
            generation: read_u64(bytes, offset + 8),
            authorization_epoch: read_u32(bytes, offset + 16),
            display_epoch: read_u32(bytes, offset + 20),
            codec_epoch: read_u32(bytes, offset + 24),
            route_epoch: read_u64(bytes, offset + 28),
        }
    }
}

/// Reliable QUIC application lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamKind {
    /// Pairing, authorization, lifecycle, and decoder recovery records.
    Control = 1,
    /// Ordered keyboard, pointer, wheel, and state-snapshot records.
    Input = 2,
}

impl StreamKind {
    const fn payload_limit(self) -> u32 {
        match self {
            Self::Control => MAX_CONTROL_BYTES,
            Self::Input => MAX_INPUT_BYTES,
        }
    }
}

impl TryFrom<u8> for StreamKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::Input),
            other => Err(ProtocolError::UnknownStreamKind(other)),
        }
    }
}

/// Fixed-width reliable stream record header.
///
/// Layout (48 bytes):
/// `magic[4], version[1], kind[1], reserved[2], session_id[8],
/// generation[8], authorization_epoch[4], display_epoch[4],
/// codec_epoch[4], route_epoch[8], payload_len[4]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRecordHeader {
    /// Declared reliable lane.
    pub kind: StreamKind,
    /// Session lifecycle data for the payload.
    pub stamp: SessionStamp,
    /// Bytes immediately following this header.
    pub payload_len: u32,
}

impl StreamRecordHeader {
    /// Validates a header before any payload allocation or session dispatch.
    pub fn validate(self) -> Result<(), ProtocolError> {
        self.stamp.validate_pending()?;
        if self.payload_len > self.kind.payload_limit() {
            return Err(ProtocolError::StreamPayloadLength {
                kind: self.kind,
                limit: self.kind.payload_limit() as usize,
                actual: self.payload_len as usize,
            });
        }
        if self.kind == StreamKind::Input {
            self.stamp.validate_input()?;
        }
        Ok(())
    }

    /// Encodes the fixed-width header in network byte order.
    pub fn encode(self) -> Result<[u8; STREAM_RECORD_HEADER_LEN], ProtocolError> {
        self.validate()?;
        let mut bytes = [0_u8; STREAM_RECORD_HEADER_LEN];
        bytes[0..4].copy_from_slice(&STREAM_RECORD_MAGIC);
        bytes[4] = WIRE_VERSION;
        bytes[5] = self.kind as u8;
        self.stamp.encode_into(&mut bytes[8..44]);
        bytes[44..48].copy_from_slice(&self.payload_len.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes one fixed-width header. Callers reading a QUIC stream use
    /// [`payload_len`](Self::payload_len) to read the corresponding body.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < STREAM_RECORD_HEADER_LEN {
            return Err(ProtocolError::Truncated {
                expected: STREAM_RECORD_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != STREAM_RECORD_MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if bytes[4] != WIRE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(bytes[4]));
        }
        if bytes[6] != 0 || bytes[7] != 0 {
            return Err(ProtocolError::ReservedBits);
        }

        let header = Self {
            kind: StreamKind::try_from(bytes[5])?,
            stamp: SessionStamp::decode_from(bytes, 8),
            payload_len: read_u32(bytes, 44),
        };
        header.validate()?;
        Ok(header)
    }
}

/// Borrowed complete reliable QUIC application record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRecord<'a> {
    /// Declared reliable lane.
    pub kind: StreamKind,
    /// Session lifecycle data for the payload.
    pub stamp: SessionStamp,
    /// Complete payload for this record.
    pub payload: &'a [u8],
}

impl<'a> StreamRecord<'a> {
    /// Serializes one complete bounded record.
    pub fn encode(
        kind: StreamKind,
        stamp: SessionStamp,
        payload: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let limit = kind.payload_limit() as usize;
        if payload.len() > limit {
            return Err(ProtocolError::StreamPayloadLength {
                kind,
                limit,
                actual: payload.len(),
            });
        }
        let header = StreamRecordHeader {
            kind,
            stamp,
            payload_len: payload.len() as u32,
        };
        let encoded_header = header.encode()?;
        let mut out = Vec::with_capacity(STREAM_RECORD_HEADER_LEN + payload.len());
        out.extend_from_slice(&encoded_header);
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Decodes exactly one complete record, rejecting a partial or trailing body.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let header = StreamRecordHeader::decode(bytes)?;
        let expected = STREAM_RECORD_HEADER_LEN
            .checked_add(header.payload_len as usize)
            .ok_or(ProtocolError::PacketLength)?;
        if bytes.len() != expected {
            return Err(ProtocolError::PayloadLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            kind: header.kind,
            stamp: header.stamp,
            payload: &bytes[STREAM_RECORD_HEADER_LEN..],
        })
    }

    /// Decodes a complete record and rejects it when delivered on another lane.
    pub fn decode_for(expected: StreamKind, bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let record = Self::decode(bytes)?;
        if record.kind != expected {
            return Err(ProtocolError::StreamKindMismatch {
                expected,
                actual: record.kind,
            });
        }
        Ok(record)
    }
}

/// Borrowed media fragment in a QUIC DATAGRAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaDatagram<'a> {
    /// Session lifecycle data that must match the inner media fragment.
    pub stamp: SessionStamp,
    /// Sender-monotonic deadline; the receiver drops at or after this instant.
    pub expires_at_ns: u64,
    /// The exactly-one inner media fragment.
    pub packet: MediaPacket<'a>,
}

impl<'a> MediaDatagram<'a> {
    /// Encodes one complete media fragment without first materializing a nested
    /// [`MediaPacket`] buffer.
    pub fn encode(
        stamp: SessionStamp,
        expires_at_ns: u64,
        header: MediaHeader,
        payload: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        stamp.validate_media()?;
        if header.stream_id == 0 {
            return Err(ProtocolError::InvalidMediaStreamId);
        }
        if header.codec_epoch != stamp.codec_epoch {
            return Err(ProtocolError::MediaEpochMismatch {
                header_epoch: header.codec_epoch,
                stamp_epoch: stamp.codec_epoch,
            });
        }
        if payload.len() != header.fragment_len as usize {
            return Err(ProtocolError::PayloadLength {
                expected: header.fragment_len as usize,
                actual: payload.len(),
            });
        }
        let encoded_media_header = header.encode()?;
        let mut encoded_quic_header = [0_u8; QUIC_MEDIA_HEADER_LEN];
        encoded_quic_header[0..4].copy_from_slice(&MEDIA_DATAGRAM_MAGIC);
        encoded_quic_header[4] = WIRE_VERSION;
        stamp.encode_into(&mut encoded_quic_header[8..44]);
        encoded_quic_header[44..52].copy_from_slice(&expires_at_ns.to_be_bytes());

        let mut out = Vec::with_capacity(QUIC_MEDIA_HEADER_LEN + MEDIA_HEADER_LEN + payload.len());
        out.extend_from_slice(&encoded_quic_header);
        out.extend_from_slice(&encoded_media_header);
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Decodes one exact complete QUIC media DATAGRAM.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < QUIC_MEDIA_HEADER_LEN {
            return Err(ProtocolError::Truncated {
                expected: QUIC_MEDIA_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != MEDIA_DATAGRAM_MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if bytes[4] != WIRE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(bytes[4]));
        }
        if bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0 {
            return Err(ProtocolError::ReservedBits);
        }

        let stamp = SessionStamp::decode_from(bytes, 8);
        stamp.validate_media()?;
        let packet = MediaPacket::decode(&bytes[QUIC_MEDIA_HEADER_LEN..])?;
        if packet.header.stream_id == 0 {
            return Err(ProtocolError::InvalidMediaStreamId);
        }
        if packet.header.codec_epoch != stamp.codec_epoch {
            return Err(ProtocolError::MediaEpochMismatch {
                header_epoch: packet.header.codec_epoch,
                stamp_epoch: stamp.codec_epoch,
            });
        }
        Ok(Self {
            stamp,
            expires_at_ns: read_u64(bytes, 44),
            packet,
        })
    }

    /// Decodes and rejects media whose deadline has already elapsed.
    pub fn decode_at(bytes: &'a [u8], now_ns: u64) -> Result<Self, ProtocolError> {
        let datagram = Self::decode(bytes)?;
        if datagram.expires_at_ns <= now_ns {
            return Err(ProtocolError::ExpiredMediaDatagram);
        }
        Ok(datagram)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{media_flags, MediaHeader, MediaKind, ProtocolError, NO_DEPENDENCY};

    fn pending_stamp() -> SessionStamp {
        SessionStamp {
            session_id: 0x0123_4567_89AB_CDEF,
            generation: 7,
            authorization_epoch: 0,
            display_epoch: 0,
            codec_epoch: 0,
            route_epoch: 1,
        }
    }

    fn active_stamp() -> SessionStamp {
        SessionStamp {
            authorization_epoch: 3,
            display_epoch: 5,
            codec_epoch: 11,
            ..pending_stamp()
        }
    }

    fn media_header() -> MediaHeader {
        MediaHeader {
            kind: MediaKind::Video,
            flags: media_flags::KEYFRAME,
            stream_id: 2,
            codec_epoch: active_stamp().codec_epoch,
            frame_id: 41,
            dependency_frame_id: NO_DEPENDENCY,
            frame_len: 4,
            fragment_offset: 0,
            fragment_len: 4,
        }
    }

    #[test]
    fn control_record_round_trips_only_on_its_declared_lane() {
        let encoded = StreamRecord::encode(StreamKind::Control, pending_stamp(), b"pairing")
            .expect("encode control record");
        let decoded =
            StreamRecord::decode_for(StreamKind::Control, &encoded).expect("decode control record");

        assert_eq!(decoded.stamp, pending_stamp());
        assert_eq!(decoded.payload, b"pairing");
        assert!(matches!(
            StreamRecord::decode_for(StreamKind::Input, &encoded),
            Err(ProtocolError::StreamKindMismatch { .. })
        ));
    }

    #[test]
    fn stream_record_rejects_reserved_trailing_and_inactive_input_bytes() {
        let mut reserved = StreamRecord::encode(StreamKind::Control, pending_stamp(), b"ok")
            .expect("encode control record");
        reserved[6] = 1;
        assert_eq!(
            StreamRecord::decode(&reserved),
            Err(ProtocolError::ReservedBits)
        );

        let mut trailing = StreamRecord::encode(StreamKind::Control, pending_stamp(), b"ok")
            .expect("encode control record");
        trailing.push(0);
        assert!(matches!(
            StreamRecord::decode(&trailing),
            Err(ProtocolError::PayloadLength { .. })
        ));

        assert_eq!(
            StreamRecord::encode(StreamKind::Input, pending_stamp(), b"input"),
            Err(ProtocolError::InactiveInputStamp)
        );
    }

    #[test]
    fn stream_record_rejects_missing_session_identity() {
        let invalid = SessionStamp {
            session_id: 0,
            ..active_stamp()
        };
        assert_eq!(
            StreamRecord::encode(StreamKind::Control, invalid, b"control"),
            Err(ProtocolError::InvalidSessionStamp)
        );
        let invalid_route = SessionStamp {
            route_epoch: 0,
            ..active_stamp()
        };
        assert_eq!(
            StreamRecord::encode(StreamKind::Control, invalid_route, b"control"),
            Err(ProtocolError::InvalidSessionStamp)
        );
    }

    #[test]
    fn protocol_v2_encodes_route_epoch_in_reliable_and_media_headers() {
        let stamp = SessionStamp {
            route_epoch: 0x0102_0304_0506_0708,
            ..active_stamp()
        };
        let record = StreamRecord::encode(StreamKind::Control, stamp, b"x").unwrap();
        assert_eq!(record[4], 2);
        assert_eq!(&record[36..44], &stamp.route_epoch.to_be_bytes());
        assert_eq!(&record[44..48], &1_u32.to_be_bytes());
        assert_eq!(StreamRecord::decode(&record).unwrap().stamp, stamp);
        let mut v1_record = record.clone();
        v1_record[4] = 1;
        assert_eq!(
            StreamRecord::decode(&v1_record),
            Err(ProtocolError::UnsupportedVersion(1))
        );

        let datagram = MediaDatagram::encode(stamp, 99, media_header(), b"h264").unwrap();
        assert_eq!(datagram[4], 2);
        assert_eq!(&datagram[36..44], &stamp.route_epoch.to_be_bytes());
        assert_eq!(&datagram[44..52], &99_u64.to_be_bytes());
        assert_eq!(MediaDatagram::decode(&datagram).unwrap().stamp, stamp);
        let mut v1_datagram = datagram;
        v1_datagram[4] = 1;
        assert_eq!(
            MediaDatagram::decode(&v1_datagram),
            Err(ProtocolError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn media_datagram_round_trips_and_enforces_active_epochs() {
        let encoded = MediaDatagram::encode(active_stamp(), 1_000, media_header(), b"h264")
            .expect("encode media datagram");
        let decoded = MediaDatagram::decode_at(&encoded, 999).expect("decode media datagram");

        assert_eq!(decoded.stamp, active_stamp());
        assert_eq!(decoded.expires_at_ns, 1_000);
        assert_eq!(decoded.packet.header, media_header());
        assert_eq!(decoded.packet.payload, b"h264");
        assert_eq!(
            MediaDatagram::decode_at(&encoded, 1_000),
            Err(ProtocolError::ExpiredMediaDatagram)
        );
    }

    #[test]
    fn media_datagram_rejects_epoch_mismatch_and_trailing_bytes() {
        let mut mismatched = media_header();
        mismatched.codec_epoch += 1;
        assert!(matches!(
            MediaDatagram::encode(active_stamp(), 1_000, mismatched, b"h264"),
            Err(ProtocolError::MediaEpochMismatch { .. })
        ));

        let mut trailing = MediaDatagram::encode(active_stamp(), 1_000, media_header(), b"h264")
            .expect("encode media datagram");
        trailing.push(0);
        assert!(matches!(
            MediaDatagram::decode(&trailing),
            Err(ProtocolError::PayloadLength { .. })
        ));
    }
}
