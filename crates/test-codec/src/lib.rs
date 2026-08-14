//! Exact, dependency-free test codec for deterministic laboratory runs.
//!
//! This is not a production desktop codec. It exists to prove transport,
//! reconstruction, allocation limits, and telemetry before hardware video lands.

use latencydesk_frame::{checksum64, expected_len, FrameError, PixelFormat, RawFrame};
use std::fmt;

const MAGIC: [u8; 4] = *b"LDTC";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 44;
const MAX_ENCODED_BYTES: usize = 320 * 1024 * 1024;
const FLAG_PACKBITS: u16 = 1;

/// Exact PackBits-like byte codec.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExactTestCodec;

impl ExactTestCodec {
    pub fn encode(frame: &RawFrame) -> Result<Vec<u8>, CodecError> {
        let payload = encode_packbits(&frame.data)?;
        let payload_len = u32::try_from(payload.len()).map_err(|_| CodecError::AllocationLimit)?;
        let raw_len = u32::try_from(frame.data.len()).map_err(|_| CodecError::AllocationLimit)?;
        let mut output = Vec::with_capacity(
            HEADER_LEN
                .checked_add(payload.len())
                .ok_or(CodecError::AllocationLimit)?,
        );
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.push(frame.format as u8);
        output.extend_from_slice(&FLAG_PACKBITS.to_be_bytes());
        output.extend_from_slice(&frame.descriptor.width.to_be_bytes());
        output.extend_from_slice(&frame.descriptor.height.to_be_bytes());
        output.extend_from_slice(&frame.stride.to_be_bytes());
        output.extend_from_slice(&raw_len.to_be_bytes());
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(&frame.descriptor.capture_sequence.to_be_bytes());
        output.extend_from_slice(&frame.checksum64().to_be_bytes());
        debug_assert_eq!(output.len(), HEADER_LEN);
        output.extend_from_slice(&payload);
        Ok(output)
    }

    pub fn decode(bytes: &[u8], capture_timestamp_ns: u64) -> Result<RawFrame, CodecError> {
        if bytes.len() < HEADER_LEN {
            return Err(CodecError::Truncated);
        }
        if bytes[0..4] != MAGIC {
            return Err(CodecError::Magic);
        }
        if bytes[4] != VERSION {
            return Err(CodecError::Version(bytes[4]));
        }
        let format = PixelFormat::try_from(bytes[5]).map_err(CodecError::Frame)?;
        let flags = read_u16(bytes, 6);
        if flags != FLAG_PACKBITS {
            return Err(CodecError::Flags(flags));
        }
        let width = read_u32(bytes, 8);
        let height = read_u32(bytes, 12);
        let stride = read_u32(bytes, 16);
        let raw_len =
            usize::try_from(read_u32(bytes, 20)).map_err(|_| CodecError::AllocationLimit)?;
        let payload_len =
            usize::try_from(read_u32(bytes, 24)).map_err(|_| CodecError::AllocationLimit)?;
        let capture_sequence = read_u64(bytes, 28);
        let expected_checksum = read_u64(bytes, 36);
        let expected_raw =
            expected_len(width, height, format, stride).map_err(CodecError::Frame)?;
        if raw_len != expected_raw {
            return Err(CodecError::RawLength {
                declared: raw_len,
                expected: expected_raw,
            });
        }
        if payload_len > MAX_ENCODED_BYTES
            || HEADER_LEN.checked_add(payload_len) != Some(bytes.len())
        {
            return Err(CodecError::PayloadLength);
        }
        let data = decode_packbits(&bytes[HEADER_LEN..], raw_len)?;
        let actual_checksum = checksum64(&data);
        if actual_checksum != expected_checksum {
            return Err(CodecError::Checksum {
                expected: expected_checksum,
                actual: actual_checksum,
            });
        }
        RawFrame::new(
            width,
            height,
            format,
            stride,
            capture_sequence,
            capture_timestamp_ns,
            data,
        )
        .map_err(CodecError::Frame)
    }
}

fn encode_packbits(input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let worst_case = input
        .len()
        .checked_add(input.len() / 128)
        .and_then(|value| value.checked_add(2))
        .ok_or(CodecError::AllocationLimit)?;
    if worst_case > MAX_ENCODED_BYTES {
        return Err(CodecError::AllocationLimit);
    }
    let mut output = Vec::with_capacity(worst_case.min(MAX_ENCODED_BYTES));
    let mut cursor = 0;
    while cursor < input.len() {
        let run = repeated_run(input, cursor).min(130);
        if run >= 3 {
            output.push(0x80 | u8::try_from(run - 3).map_err(|_| CodecError::AllocationLimit)?);
            output.push(input[cursor]);
            cursor += run;
            continue;
        }

        let literal_start = cursor;
        cursor += 1;
        while cursor < input.len() && cursor - literal_start < 128 {
            let next_run = repeated_run(input, cursor).min(130);
            if next_run >= 3 {
                break;
            }
            cursor += 1;
        }
        let literal_len = cursor - literal_start;
        output.push(u8::try_from(literal_len - 1).map_err(|_| CodecError::AllocationLimit)?);
        output.extend_from_slice(&input[literal_start..cursor]);
        if output.len() > MAX_ENCODED_BYTES {
            return Err(CodecError::AllocationLimit);
        }
    }
    Ok(output)
}

fn decode_packbits(payload: &[u8], expected_len: usize) -> Result<Vec<u8>, CodecError> {
    let mut output = Vec::with_capacity(expected_len);
    let mut cursor = 0;
    while cursor < payload.len() {
        let control = payload[cursor];
        cursor += 1;
        if control & 0x80 != 0 {
            let count = usize::from(control & 0x7f) + 3;
            let value = *payload.get(cursor).ok_or(CodecError::MalformedRun)?;
            cursor += 1;
            let new_len = output
                .len()
                .checked_add(count)
                .ok_or(CodecError::AllocationLimit)?;
            if new_len > expected_len {
                return Err(CodecError::DecodedLength);
            }
            output.resize(new_len, value);
        } else {
            let count = usize::from(control) + 1;
            let end = cursor
                .checked_add(count)
                .ok_or(CodecError::AllocationLimit)?;
            let literal = payload
                .get(cursor..end)
                .ok_or(CodecError::MalformedLiteral)?;
            let new_len = output
                .len()
                .checked_add(count)
                .ok_or(CodecError::AllocationLimit)?;
            if new_len > expected_len {
                return Err(CodecError::DecodedLength);
            }
            output.extend_from_slice(literal);
            cursor = end;
        }
    }
    if output.len() != expected_len {
        return Err(CodecError::DecodedLength);
    }
    Ok(output)
}

fn repeated_run(input: &[u8], start: usize) -> usize {
    let Some(value) = input.get(start) else {
        return 0;
    };
    let mut end = start + 1;
    while end < input.len() && input[end] == *value && end - start < 130 {
        end += 1;
    }
    end - start
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    Magic,
    Version(u8),
    Flags(u16),
    RawLength { declared: usize, expected: usize },
    PayloadLength,
    MalformedRun,
    MalformedLiteral,
    DecodedLength,
    Checksum { expected: u64, actual: u64 },
    AllocationLimit,
    Frame(FrameError),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_frame::{FakeCapture, FakeCaptureConfig, Pattern};

    #[test]
    fn exact_round_trip_bgra() {
        let mut capture = FakeCapture::new(FakeCaptureConfig {
            width: 96,
            height: 64,
            format: PixelFormat::Bgra8,
            pattern: Pattern::TextLike,
            seed: 17,
        })
        .expect("capture");
        let frame = capture.capture(123).expect("frame");
        let encoded = ExactTestCodec::encode(&frame).expect("encode");
        let decoded = ExactTestCodec::decode(&encoded, 456).expect("decode");
        assert_eq!(decoded.data, frame.data);
        assert_eq!(
            decoded.descriptor.capture_sequence,
            frame.descriptor.capture_sequence
        );
    }

    #[test]
    fn corrupted_payload_fails_checksum_or_structure() {
        let mut capture = FakeCapture::new(FakeCaptureConfig {
            width: 32,
            height: 32,
            format: PixelFormat::Bgra8,
            pattern: Pattern::Gradient,
            seed: 1,
        })
        .expect("capture");
        let frame = capture.capture(0).expect("frame");
        let mut encoded = ExactTestCodec::encode(&frame).expect("encode");
        let last = encoded.len() - 1;
        encoded[last] ^= 0x40;
        assert!(ExactTestCodec::decode(&encoded, 0).is_err());
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        let mut encoded = vec![0_u8; HEADER_LEN];
        encoded[0..4].copy_from_slice(&MAGIC);
        encoded[4] = VERSION;
        encoded[5] = PixelFormat::Bgra8 as u8;
        encoded[6..8].copy_from_slice(&FLAG_PACKBITS.to_be_bytes());
        encoded[8..12].copy_from_slice(&1_u32.to_be_bytes());
        encoded[12..16].copy_from_slice(&1_u32.to_be_bytes());
        encoded[16..20].copy_from_slice(&4_u32.to_be_bytes());
        encoded[20..24].copy_from_slice(&4_u32.to_be_bytes());
        encoded[24..28].copy_from_slice(&2_u32.to_be_bytes());
        encoded.extend_from_slice(&[0xff, 0]);
        assert_eq!(
            ExactTestCodec::decode(&encoded, 0),
            Err(CodecError::DecodedLength)
        );
    }
}
