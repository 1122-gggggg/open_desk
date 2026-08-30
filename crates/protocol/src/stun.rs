//! Bounded RFC 8489 STUN Binding wire primitives.
//!
//! This module performs no DNS, socket I/O, retries, authentication, or route
//! selection. A reflexive address is untrusted connectivity metadata and never
//! substitutes for LatencyDesk's exact-peer mTLS or session authorization.

use core::fmt;

pub const HEADER_LEN: usize = 20;
pub const MAX_MESSAGE_BYTES: usize = 2_048;
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    #[must_use]
    pub const fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 12] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappedAddress {
    Ipv4 { address: [u8; 4], port: u16 },
    Ipv6 { address: [u8; 16], port: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingSuccess {
    pub transaction_id: TransactionId,
    pub mapped: MappedAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    Truncated { needed: usize, actual: usize },
    MessageTooLarge(usize),
    UnsupportedMessageType(u16),
    BadMagicCookie,
    UnalignedMessageLength(u16),
    MessageLength { declared: usize, actual: usize },
    TransactionMismatch,
    InvalidAttributeLength { kind: u16, length: u16 },
    UnknownRequiredAttribute(u16),
    UnexpectedAttribute(u16),
    DuplicateAttribute(u16),
    MissingXorMappedAddress,
    InvalidXorMappedAddress,
    MissingFingerprint,
    InvalidFingerprint,
    FingerprintNotLast,
}

impl fmt::Display for StunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for StunError {}

#[must_use]
pub fn encode_binding_request(transaction_id: TransactionId) -> Vec<u8> {
    let mut message = encode_header(BINDING_REQUEST, transaction_id);
    append_fingerprint(&mut message);
    message
}

pub fn decode_binding_request(
    bytes: &[u8],
    require_fingerprint: bool,
) -> Result<TransactionId, StunError> {
    let transaction_id = decode_header(bytes, BINDING_REQUEST)?;
    let mut fingerprint_seen = false;
    parse_attributes(bytes, |kind, value, offset, next_offset| match kind {
        FINGERPRINT => {
            validate_one_fingerprint(bytes, value, offset, next_offset, &mut fingerprint_seen)
        }
        XOR_MAPPED_ADDRESS => Err(StunError::UnexpectedAttribute(kind)),
        other if other < 0x8000 => Err(StunError::UnknownRequiredAttribute(other)),
        _ => Ok(()),
    })?;
    if require_fingerprint && !fingerprint_seen {
        return Err(StunError::MissingFingerprint);
    }
    Ok(transaction_id)
}

#[must_use]
pub fn encode_binding_success(transaction_id: TransactionId, mapped: MappedAddress) -> Vec<u8> {
    let mut message = encode_header(BINDING_SUCCESS_RESPONSE, transaction_id);
    let mut value = [0_u8; 20];
    value[0] = 0;
    let port = match mapped {
        MappedAddress::Ipv4 { port, .. } | MappedAddress::Ipv6 { port, .. } => port,
    } ^ (MAGIC_COOKIE >> 16) as u16;
    value[2..4].copy_from_slice(&port.to_be_bytes());
    let value_len = match mapped {
        MappedAddress::Ipv4 { address, .. } => {
            value[1] = 0x01;
            for (encoded, (plain, mask)) in value[4..8]
                .iter_mut()
                .zip(address.into_iter().zip(MAGIC_COOKIE.to_be_bytes()))
            {
                *encoded = plain ^ mask;
            }
            8
        }
        MappedAddress::Ipv6 { address, .. } => {
            value[1] = 0x02;
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction_id.as_bytes());
            for (encoded, (plain, mask)) in
                value[4..20].iter_mut().zip(address.into_iter().zip(mask))
            {
                *encoded = plain ^ mask;
            }
            20
        }
    };
    append_attribute(&mut message, XOR_MAPPED_ADDRESS, &value[..value_len]);
    append_fingerprint(&mut message);
    message
}

pub fn decode_binding_success(
    bytes: &[u8],
    expected_transaction_id: TransactionId,
    require_fingerprint: bool,
) -> Result<BindingSuccess, StunError> {
    let transaction_id = decode_header(bytes, BINDING_SUCCESS_RESPONSE)?;
    if transaction_id != expected_transaction_id {
        return Err(StunError::TransactionMismatch);
    }
    let mut mapped = None;
    let mut fingerprint_seen = false;
    parse_attributes(bytes, |kind, value, offset, next_offset| match kind {
        XOR_MAPPED_ADDRESS => {
            if mapped.is_some() {
                return Err(StunError::DuplicateAttribute(kind));
            }
            mapped = Some(decode_xor_mapped(value, transaction_id)?);
            Ok(())
        }
        FINGERPRINT => {
            validate_one_fingerprint(bytes, value, offset, next_offset, &mut fingerprint_seen)
        }
        other if other < 0x8000 => Err(StunError::UnknownRequiredAttribute(other)),
        _ => Ok(()),
    })?;
    if require_fingerprint && !fingerprint_seen {
        return Err(StunError::MissingFingerprint);
    }
    Ok(BindingSuccess {
        transaction_id,
        mapped: mapped.ok_or(StunError::MissingXorMappedAddress)?,
    })
}

fn encode_header(message_type: u16, transaction_id: TransactionId) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&message_type.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message.extend_from_slice(transaction_id.as_bytes());
    message
}

fn append_attribute(message: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = u16::try_from(value.len()).expect("STUN encoder values are statically bounded");
    message.extend_from_slice(&kind.to_be_bytes());
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(value);
    let padded = value.len().div_ceil(4) * 4;
    message.resize(message.len() + padded - value.len(), 0);
    set_message_length(message);
}

fn append_fingerprint(message: &mut Vec<u8>) {
    let offset = message.len();
    append_attribute(message, FINGERPRINT, &[0; 4]);
    let fingerprint = crc32(&message[..offset]) ^ FINGERPRINT_XOR;
    message[offset + 4..offset + 8].copy_from_slice(&fingerprint.to_be_bytes());
}

fn set_message_length(message: &mut [u8]) {
    let payload_len = u16::try_from(message.len() - HEADER_LEN)
        .expect("STUN encoder messages are statically bounded");
    message[2..4].copy_from_slice(&payload_len.to_be_bytes());
}

fn decode_header(bytes: &[u8], expected_type: u16) -> Result<TransactionId, StunError> {
    if bytes.len() < HEADER_LEN {
        return Err(StunError::Truncated {
            needed: HEADER_LEN,
            actual: bytes.len(),
        });
    }
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(StunError::MessageTooLarge(bytes.len()));
    }
    let message_type = read_u16(bytes, 0);
    if message_type != expected_type {
        return Err(StunError::UnsupportedMessageType(message_type));
    }
    let declared = read_u16(bytes, 2);
    if declared & 0x0003 != 0 {
        return Err(StunError::UnalignedMessageLength(declared));
    }
    if read_u32(bytes, 4) != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }
    let actual = bytes.len() - HEADER_LEN;
    if usize::from(declared) != actual {
        return Err(StunError::MessageLength {
            declared: usize::from(declared),
            actual,
        });
    }
    let mut transaction_id = [0_u8; 12];
    transaction_id.copy_from_slice(&bytes[8..20]);
    Ok(TransactionId::new(transaction_id))
}

fn parse_attributes(
    bytes: &[u8],
    mut visit: impl FnMut(u16, &[u8], usize, usize) -> Result<(), StunError>,
) -> Result<(), StunError> {
    let mut offset = HEADER_LEN;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(StunError::Truncated {
                needed: offset + 4,
                actual: bytes.len(),
            });
        }
        let kind = read_u16(bytes, offset);
        let length = read_u16(bytes, offset + 2);
        let value_start = offset + 4;
        let padded_len = usize::from(length).div_ceil(4) * 4;
        let next_offset = value_start
            .checked_add(padded_len)
            .ok_or(StunError::InvalidAttributeLength { kind, length })?;
        let value_end = value_start
            .checked_add(usize::from(length))
            .ok_or(StunError::InvalidAttributeLength { kind, length })?;
        if value_end > bytes.len() || next_offset > bytes.len() {
            return Err(StunError::InvalidAttributeLength { kind, length });
        }
        visit(kind, &bytes[value_start..value_end], offset, next_offset)?;
        offset = next_offset;
    }
    Ok(())
}

fn validate_one_fingerprint(
    bytes: &[u8],
    value: &[u8],
    offset: usize,
    next_offset: usize,
    seen: &mut bool,
) -> Result<(), StunError> {
    if *seen {
        return Err(StunError::DuplicateAttribute(FINGERPRINT));
    }
    if next_offset != bytes.len() {
        return Err(StunError::FingerprintNotLast);
    }
    if value.len() != 4 {
        return Err(StunError::InvalidAttributeLength {
            kind: FINGERPRINT,
            length: u16::try_from(value.len()).unwrap_or(u16::MAX),
        });
    }
    let expected = crc32(&bytes[..offset]) ^ FINGERPRINT_XOR;
    if read_u32(value, 0) != expected {
        return Err(StunError::InvalidFingerprint);
    }
    *seen = true;
    Ok(())
}

fn decode_xor_mapped(
    value: &[u8],
    transaction_id: TransactionId,
) -> Result<MappedAddress, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidXorMappedAddress);
    }
    let port = read_u16(value, 2) ^ (MAGIC_COOKIE >> 16) as u16;
    match value[1] {
        0x01 if value.len() == 8 => {
            let mut address = [0_u8; 4];
            for (plain, (encoded, mask)) in address
                .iter_mut()
                .zip(value[4..8].iter().copied().zip(MAGIC_COOKIE.to_be_bytes()))
            {
                *plain = encoded ^ mask;
            }
            Ok(MappedAddress::Ipv4 { address, port })
        }
        0x02 if value.len() == 20 => {
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction_id.as_bytes());
            let mut address = [0_u8; 16];
            for (plain, (encoded, mask)) in address
                .iter_mut()
                .zip(value[4..20].iter().copied().zip(mask))
            {
                *plain = encoded ^ mask;
            }
            Ok(MappedAddress::Ipv6 { address, port })
        }
        _ => Err(StunError::InvalidXorMappedAddress),
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
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

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSACTION: TransactionId = TransactionId::new([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76,
    ]);

    #[test]
    fn binding_request_round_trip_has_cookie_transaction_and_fingerprint() {
        let encoded = encode_binding_request(TRANSACTION);
        assert_eq!(encoded.len(), 28);
        assert_eq!(&encoded[0..2], &0x0001_u16.to_be_bytes());
        assert_eq!(&encoded[2..4], &8_u16.to_be_bytes());
        assert_eq!(&encoded[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&encoded[8..20], TRANSACTION.as_bytes());
        assert_eq!(decode_binding_request(&encoded, true), Ok(TRANSACTION));
    }

    #[test]
    fn binding_success_round_trips_ipv4_and_ipv6_xor_mapped_addresses() {
        for mapped in [
            MappedAddress::Ipv4 {
                address: [203, 0, 113, 7],
                port: 54_321,
            },
            MappedAddress::Ipv6 {
                address: [
                    0x20, 0x01, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xaa, 0xbb,
                ],
                port: 34_567,
            },
        ] {
            let encoded = encode_binding_success(TRANSACTION, mapped);
            let decoded = decode_binding_success(&encoded, TRANSACTION, true)
                .expect("binding success response");
            assert_eq!(decoded.transaction_id, TRANSACTION);
            assert_eq!(decoded.mapped, mapped);
        }
    }

    #[test]
    fn header_transaction_and_datagram_boundaries_fail_closed() {
        let valid = encode_binding_success(
            TRANSACTION,
            MappedAddress::Ipv4 {
                address: [198, 51, 100, 9],
                port: 9_999,
            },
        );
        assert_eq!(
            decode_binding_success(&valid[..HEADER_LEN - 1], TRANSACTION, true),
            Err(StunError::Truncated {
                needed: HEADER_LEN,
                actual: HEADER_LEN - 1,
            })
        );

        let mut bad_cookie = valid.clone();
        bad_cookie[4] ^= 1;
        assert_eq!(
            decode_binding_success(&bad_cookie, TRANSACTION, true),
            Err(StunError::BadMagicCookie)
        );

        let mut wrong_transaction = TRANSACTION.into_bytes();
        wrong_transaction[0] ^= 1;
        assert_eq!(
            decode_binding_success(&valid, TransactionId::new(wrong_transaction), true),
            Err(StunError::TransactionMismatch)
        );

        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[0; 4]);
        assert_eq!(
            decode_binding_success(&trailing, TRANSACTION, true),
            Err(StunError::MessageLength {
                declared: valid.len() - HEADER_LEN,
                actual: trailing.len() - HEADER_LEN,
            })
        );

        let mut unaligned = valid;
        unaligned[2..4].copy_from_slice(&5_u16.to_be_bytes());
        assert_eq!(
            decode_binding_success(&unaligned, TRANSACTION, true),
            Err(StunError::UnalignedMessageLength(5))
        );

        let oversized = vec![0_u8; MAX_MESSAGE_BYTES + 1];
        assert_eq!(
            decode_binding_success(&oversized, TRANSACTION, true),
            Err(StunError::MessageTooLarge(MAX_MESSAGE_BYTES + 1))
        );
    }

    #[test]
    fn fingerprint_is_last_optional_and_detects_any_covered_mutation() {
        let valid = encode_binding_success(
            TRANSACTION,
            MappedAddress::Ipv4 {
                address: [203, 0, 113, 9],
                port: 12_345,
            },
        );
        let mut tampered = valid.clone();
        tampered[27] ^= 1;
        assert_eq!(
            decode_binding_success(&tampered, TRANSACTION, true),
            Err(StunError::InvalidFingerprint)
        );

        let mut no_fingerprint = valid[..valid.len() - 8].to_vec();
        set_message_length(&mut no_fingerprint);
        assert_eq!(
            decode_binding_success(&no_fingerprint, TRANSACTION, true),
            Err(StunError::MissingFingerprint)
        );
        assert!(decode_binding_success(&no_fingerprint, TRANSACTION, false).is_ok());

        let mut not_last = encode_header(BINDING_SUCCESS_RESPONSE, TRANSACTION);
        append_fingerprint(&mut not_last);
        append_attribute(&mut not_last, 0x8022, b"software");
        assert_eq!(
            decode_binding_success(&not_last, TRANSACTION, true),
            Err(StunError::FingerprintNotLast)
        );
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn attributes_are_bounded_unique_and_comprehension_aware() {
        let mapped = MappedAddress::Ipv4 {
            address: [192, 0, 2, 1],
            port: 44_444,
        };
        let valid = encode_binding_success(TRANSACTION, mapped);
        let xor_value = valid[24..32].to_vec();

        let mut optional = valid[..valid.len() - 8].to_vec();
        set_message_length(&mut optional);
        append_attribute(&mut optional, 0x8022, b"abc");
        append_fingerprint(&mut optional);
        assert_eq!(
            decode_binding_success(&optional, TRANSACTION, true)
                .expect("unknown optional attribute")
                .mapped,
            mapped
        );

        let mut required = valid[..valid.len() - 8].to_vec();
        set_message_length(&mut required);
        append_attribute(&mut required, 0x0002, b"required");
        append_fingerprint(&mut required);
        assert_eq!(
            decode_binding_success(&required, TRANSACTION, true),
            Err(StunError::UnknownRequiredAttribute(0x0002))
        );

        let mut duplicate = valid[..valid.len() - 8].to_vec();
        set_message_length(&mut duplicate);
        append_attribute(&mut duplicate, XOR_MAPPED_ADDRESS, &xor_value);
        append_fingerprint(&mut duplicate);
        assert_eq!(
            decode_binding_success(&duplicate, TRANSACTION, true),
            Err(StunError::DuplicateAttribute(XOR_MAPPED_ADDRESS))
        );

        let mut missing = encode_header(BINDING_SUCCESS_RESPONSE, TRANSACTION);
        append_fingerprint(&mut missing);
        assert_eq!(
            decode_binding_success(&missing, TRANSACTION, true),
            Err(StunError::MissingXorMappedAddress)
        );

        let mut malformed = encode_header(BINDING_SUCCESS_RESPONSE, TRANSACTION);
        append_attribute(
            &mut malformed,
            XOR_MAPPED_ADDRESS,
            &[0, 3, 0, 1, 0, 0, 0, 0],
        );
        append_fingerprint(&mut malformed);
        assert_eq!(
            decode_binding_success(&malformed, TRANSACTION, true),
            Err(StunError::InvalidXorMappedAddress)
        );

        let mut truncated = valid;
        truncated[22..24].copy_from_slice(&100_u16.to_be_bytes());
        assert_eq!(
            decode_binding_success(&truncated, TRANSACTION, true),
            Err(StunError::InvalidAttributeLength {
                kind: XOR_MAPPED_ADDRESS,
                length: 100,
            })
        );
    }

    #[test]
    fn binding_request_rejects_required_or_response_only_attributes() {
        let mut optional = encode_header(BINDING_REQUEST, TRANSACTION);
        append_attribute(&mut optional, 0x8022, b"client");
        append_fingerprint(&mut optional);
        assert_eq!(decode_binding_request(&optional, true), Ok(TRANSACTION));

        let mut required = encode_header(BINDING_REQUEST, TRANSACTION);
        append_attribute(&mut required, 0x0002, &[]);
        append_fingerprint(&mut required);
        assert_eq!(
            decode_binding_request(&required, true),
            Err(StunError::UnknownRequiredAttribute(0x0002))
        );

        let response = encode_binding_success(
            TRANSACTION,
            MappedAddress::Ipv4 {
                address: [127, 0, 0, 1],
                port: 9,
            },
        );
        assert_eq!(
            decode_binding_request(&response, true),
            Err(StunError::UnsupportedMessageType(BINDING_SUCCESS_RESPONSE))
        );
    }
}
