//! Bounded RFC 8489 / RFC 8656 wire subset for a UDP TURN relay.
//!
//! This profile negotiates SHA-256 long-term credentials out of band. Legacy
//! MD5 key derivation and MESSAGE-INTEGRITY/SHA-1 are deliberately unsupported.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const MAX_DATAGRAM_BYTES: usize = 4 * 1024;
pub const CHANNEL_MIN: u16 = 0x4000;
pub const CHANNEL_MAX: u16 = 0x4fff;

const HEADER_LEN: usize = 20;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const MESSAGE_INTEGRITY_SHA256: u16 = 0x001c;
const USERNAME: u16 = 0x0006;
const ERROR_CODE: u16 = 0x0009;
const CHANNEL_NUMBER: u16 = 0x000c;
const LIFETIME: u16 = 0x000d;
const XOR_PEER_ADDRESS: u16 = 0x0012;
const DATA: u16 = 0x0013;
const REALM: u16 = 0x0014;
const NONCE: u16 = 0x0015;
const XOR_RELAYED_ADDRESS: u16 = 0x0016;
const REQUESTED_TRANSPORT: u16 = 0x0019;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Allocate,
    Refresh,
    CreatePermission,
    ChannelBind,
    Send,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub class: Class,
    pub method: Method,
    pub transaction_id: [u8; 12],
}

#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub attributes: Vec<Attribute>,
}

/// A message whose MESSAGE-INTEGRITY-SHA256 was verified against a
/// caller-selected key. Construction is restricted to [`verify_integrity`].
pub struct VerifiedMessage(Message);

impl VerifiedMessage {
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.0
    }

    #[must_use]
    pub fn into_message(self) -> Message {
        self.0
    }
}

impl fmt::Debug for VerifiedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VerifiedMessage")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Message")
            .field("header", &self.header)
            .field(
                "attributes",
                &self
                    .attributes
                    .iter()
                    .map(Attribute::redacted)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Attribute {
    Username(Vec<u8>),
    Realm(Vec<u8>),
    Nonce(Vec<u8>),
    MessageIntegritySha256([u8; 32]),
    RequestedTransport(u8),
    Lifetime(u32),
    XorPeerAddress(SocketAddr),
    XorRelayedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    ChannelNumber(u16),
    Data(Vec<u8>),
    ErrorCode { code: u16, reason: String },
}

impl Attribute {
    fn redacted(&self) -> String {
        match self {
            Self::Username(_) => "USERNAME(<redacted>)".into(),
            Self::Realm(_) => "REALM(<redacted>)".into(),
            Self::Nonce(_) => "NONCE(<redacted>)".into(),
            Self::MessageIntegritySha256(_) => "MESSAGE-INTEGRITY-SHA256(<redacted>)".into(),
            Self::Data(_) => "DATA(<redacted>)".into(),
            Self::RequestedTransport(value) => format!("REQUESTED-TRANSPORT({value})"),
            Self::Lifetime(value) => format!("LIFETIME({value})"),
            Self::XorPeerAddress(address) => format!("XOR-PEER-ADDRESS({address})"),
            Self::XorRelayedAddress(address) => format!("XOR-RELAYED-ADDRESS({address})"),
            Self::XorMappedAddress(address) => format!("XOR-MAPPED-ADDRESS({address})"),
            Self::ChannelNumber(channel) => format!("CHANNEL-NUMBER({channel:#06x})"),
            Self::ErrorCode { code, .. } => format!("ERROR-CODE({code})"),
        }
    }
}

impl Drop for Attribute {
    fn drop(&mut self) {
        match self {
            Self::Username(value) | Self::Realm(value) | Self::Nonce(value) | Self::Data(value) => {
                value.zeroize()
            }
            Self::MessageIntegritySha256(value) => value.zeroize(),
            Self::ErrorCode { reason, .. } => reason.zeroize(),
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    TooLarge,
    Truncated,
    InvalidHeader,
    InvalidLength,
    InvalidPadding,
    UnknownRequired(u16),
    Duplicate(u16),
    InvalidAttribute,
    InvalidTransaction,
    InvalidMethodClass,
    InvalidChannel,
    IntegrityMissing,
    IntegrityPosition,
    IntegrityMismatch,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl StdError for WireError {}

/// RFC 8489 SHA-256 password algorithm key for the local SHA-256-only profile.
pub fn derive_long_term_key_sha256(
    username: &[u8],
    realm: &[u8],
    password: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(username);
    hash.update(b":");
    hash.update(realm);
    hash.update(b":");
    hash.update(password);
    Zeroizing::new(hash.finalize().into())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts every key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Encodes a UDP ChannelData datagram. UDP padding is unnecessary, so it is
/// omitted; the decoder accepts either exact length or zero padding.
pub fn encode_channel_data(channel: u16, data: &[u8]) -> Result<Vec<u8>, WireError> {
    if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
        return Err(WireError::InvalidChannel);
    }
    if data.len() > u16::MAX as usize || data.len().saturating_add(4) > MAX_DATAGRAM_BYTES {
        return Err(WireError::TooLarge);
    }
    let mut output = Vec::with_capacity(4 + data.len());
    output.extend_from_slice(&channel.to_be_bytes());
    output.extend_from_slice(&(data.len() as u16).to_be_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

pub fn decode_channel_data(input: &[u8]) -> Result<(u16, &[u8]), WireError> {
    if input.len() > MAX_DATAGRAM_BYTES {
        return Err(WireError::TooLarge);
    }
    if input.len() < 4 {
        return Err(WireError::Truncated);
    }
    let channel = u16::from_be_bytes([input[0], input[1]]);
    if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
        return Err(WireError::InvalidChannel);
    }
    let data_len = u16::from_be_bytes([input[2], input[3]]) as usize;
    let exact = 4_usize
        .checked_add(data_len)
        .ok_or(WireError::InvalidLength)?;
    let padded = exact.checked_add(3).ok_or(WireError::InvalidLength)? & !3;
    if input.len() != exact && input.len() != padded {
        return Err(WireError::InvalidLength);
    }
    Ok((channel, &input[4..exact]))
}

pub fn encode(message: &Message) -> Result<Vec<u8>, WireError> {
    validate_header(message.header)?;
    let mut output = Vec::with_capacity(HEADER_LEN + 128);
    output.extend_from_slice(
        &encode_type(message.header.class, method_code(message.header.method)).to_be_bytes(),
    );
    output.extend_from_slice(&[0, 0]);
    output.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    output.extend_from_slice(&message.header.transaction_id);
    let mut seen = Vec::new();
    for (index, attribute) in message.attributes.iter().enumerate() {
        let (kind, value) = encode_attribute(attribute, message.header.transaction_id)?;
        let repeat_peer = kind == XOR_PEER_ADDRESS
            && message.header.method == Method::CreatePermission
            && message.header.class == Class::Request;
        if seen.contains(&kind) && !repeat_peer {
            return Err(WireError::Duplicate(kind));
        }
        if kind == MESSAGE_INTEGRITY_SHA256 && index + 1 != message.attributes.len() {
            return Err(WireError::IntegrityPosition);
        }
        seen.push(kind);
        append_attribute(&mut output, kind, &value)?;
    }
    finish_length(&mut output)?;
    Ok(output)
}

/// Adds a final MESSAGE-INTEGRITY-SHA256 attribute and computes RFC 8489
/// Section 14.6 HMAC input with the adjusted STUN header length.
pub fn encode_with_integrity(message: &Message, key: &[u8]) -> Result<Vec<u8>, WireError> {
    if message
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, Attribute::MessageIntegritySha256(_)))
    {
        return Err(WireError::Duplicate(MESSAGE_INTEGRITY_SHA256));
    }
    let mut output = encode(message)?;
    let final_len = output
        .len()
        .checked_add(ATTRIBUTE_HEADER_LEN + 32)
        .ok_or(WireError::TooLarge)?;
    if final_len > MAX_DATAGRAM_BYTES {
        return Err(WireError::TooLarge);
    }
    output[2..4].copy_from_slice(&((final_len - HEADER_LEN) as u16).to_be_bytes());
    let integrity = hmac_sha256(key, &output);
    append_attribute(&mut output, MESSAGE_INTEGRITY_SHA256, &integrity)?;
    debug_assert_eq!(output.len(), final_len);
    Ok(output)
}

pub fn decode(input: &[u8]) -> Result<Message, WireError> {
    let (header, body_len) = decode_header(input)?;
    let end = HEADER_LEN + body_len;
    let mut cursor = HEADER_LEN;
    let mut attributes = Vec::new();
    let mut seen = Vec::new();
    let mut integrity_seen = false;
    while cursor < end {
        let (kind, value, next) = read_raw_attribute(input, cursor, end)?;
        if integrity_seen {
            return Err(WireError::IntegrityPosition);
        }
        let repeat_peer = kind == XOR_PEER_ADDRESS
            && header.method == Method::CreatePermission
            && header.class == Class::Request;
        if seen.contains(&kind) && !repeat_peer {
            return Err(WireError::Duplicate(kind));
        }
        seen.push(kind);
        if kind == MESSAGE_INTEGRITY_SHA256 {
            integrity_seen = true;
        }
        if let Some(attribute) = decode_attribute(kind, value, header.transaction_id)? {
            attributes.push(attribute);
        }
        cursor = next;
    }
    Ok(Message { header, attributes })
}

/// Verifies the final SHA-256 integrity attribute in constant time, then
/// returns the strictly decoded message.
pub fn verify_integrity(input: &[u8], key: &[u8]) -> Result<VerifiedMessage, WireError> {
    let (_, body_len) = decode_header(input)?;
    let end = HEADER_LEN + body_len;
    let mut cursor = HEADER_LEN;
    let mut integrity = None;
    while cursor < end {
        let start = cursor;
        let (kind, value, next) = read_raw_attribute(input, cursor, end)?;
        if kind == MESSAGE_INTEGRITY_SHA256 {
            if value.len() != 32 || next != end || integrity.is_some() {
                return Err(WireError::IntegrityPosition);
            }
            integrity = Some((start, value));
        }
        cursor = next;
    }
    let (integrity_start, supplied) = integrity.ok_or(WireError::IntegrityMissing)?;
    let mut prefix = input[..integrity_start].to_vec();
    let integrity_end = integrity_start
        .checked_add(ATTRIBUTE_HEADER_LEN + 32)
        .ok_or(WireError::InvalidLength)?;
    prefix[2..4].copy_from_slice(&((integrity_end - HEADER_LEN) as u16).to_be_bytes());
    let expected = hmac_sha256(key, &prefix);
    if expected.ct_eq(supplied).unwrap_u8() != 1 {
        return Err(WireError::IntegrityMismatch);
    }
    Ok(VerifiedMessage(decode(input)?))
}

fn validate_header(header: Header) -> Result<(), WireError> {
    if header.transaction_id == [0; 12] {
        return Err(WireError::InvalidTransaction);
    }
    let valid = match header.class {
        Class::Request | Class::Success | Class::Error => matches!(
            header.method,
            Method::Allocate | Method::Refresh | Method::CreatePermission | Method::ChannelBind
        ),
        Class::Indication => matches!(header.method, Method::Send | Method::Data),
    };
    if !valid {
        return Err(WireError::InvalidMethodClass);
    }
    Ok(())
}

fn decode_header(input: &[u8]) -> Result<(Header, usize), WireError> {
    if input.len() > MAX_DATAGRAM_BYTES {
        return Err(WireError::TooLarge);
    }
    if input.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let encoded_type = u16::from_be_bytes([input[0], input[1]]);
    let (class, raw_method) = decode_type(encoded_type).ok_or(WireError::InvalidHeader)?;
    let method = decode_method(raw_method).ok_or(WireError::InvalidMethodClass)?;
    let body_len = u16::from_be_bytes([input[2], input[3]]) as usize;
    if input[4..8] != MAGIC_COOKIE.to_be_bytes()
        || body_len % 4 != 0
        || HEADER_LEN.checked_add(body_len) != Some(input.len())
    {
        return Err(WireError::InvalidLength);
    }
    let mut transaction_id = [0; 12];
    transaction_id.copy_from_slice(&input[8..20]);
    let header = Header {
        class,
        method,
        transaction_id,
    };
    validate_header(header)?;
    Ok((header, body_len))
}

fn append_attribute(output: &mut Vec<u8>, kind: u16, value: &[u8]) -> Result<(), WireError> {
    if value.len() > u16::MAX as usize {
        return Err(WireError::TooLarge);
    }
    let padding = (4 - value.len() % 4) % 4;
    let next = output
        .len()
        .checked_add(ATTRIBUTE_HEADER_LEN)
        .and_then(|length| length.checked_add(value.len()))
        .and_then(|length| length.checked_add(padding))
        .ok_or(WireError::TooLarge)?;
    if next > MAX_DATAGRAM_BYTES {
        return Err(WireError::TooLarge);
    }
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
    output.resize(next, 0);
    Ok(())
}

fn finish_length(output: &mut [u8]) -> Result<(), WireError> {
    if output.len() < HEADER_LEN || output.len() > MAX_DATAGRAM_BYTES {
        return Err(WireError::TooLarge);
    }
    let body_len = output.len() - HEADER_LEN;
    let encoded = u16::try_from(body_len).map_err(|_| WireError::TooLarge)?;
    output[2..4].copy_from_slice(&encoded.to_be_bytes());
    Ok(())
}

fn read_raw_attribute(
    input: &[u8],
    cursor: usize,
    end: usize,
) -> Result<(u16, &[u8], usize), WireError> {
    let value_start = cursor
        .checked_add(ATTRIBUTE_HEADER_LEN)
        .ok_or(WireError::InvalidLength)?;
    if value_start > end {
        return Err(WireError::Truncated);
    }
    let kind = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
    let value_len = u16::from_be_bytes([input[cursor + 2], input[cursor + 3]]) as usize;
    let value_end = value_start
        .checked_add(value_len)
        .ok_or(WireError::InvalidLength)?;
    if value_end > end {
        return Err(WireError::Truncated);
    }
    let padding = (4 - value_len % 4) % 4;
    let next = value_end
        .checked_add(padding)
        .ok_or(WireError::InvalidLength)?;
    if next > end {
        return Err(WireError::InvalidPadding);
    }
    Ok((kind, &input[value_start..value_end], next))
}

fn encode_attribute(
    attribute: &Attribute,
    transaction_id: [u8; 12],
) -> Result<(u16, Vec<u8>), WireError> {
    match attribute {
        Attribute::Username(value) => Ok((USERNAME, bounded_text(value, 1, 512)?)),
        Attribute::Realm(value) => Ok((REALM, bounded_text(value, 1, 127)?)),
        Attribute::Nonce(value) => Ok((NONCE, bounded_text(value, 1, 763)?)),
        Attribute::MessageIntegritySha256(value) => Ok((MESSAGE_INTEGRITY_SHA256, value.to_vec())),
        Attribute::RequestedTransport(protocol) => {
            Ok((REQUESTED_TRANSPORT, vec![*protocol, 0, 0, 0]))
        }
        Attribute::Lifetime(seconds) => Ok((LIFETIME, seconds.to_be_bytes().to_vec())),
        Attribute::XorPeerAddress(address) => Ok((
            XOR_PEER_ADDRESS,
            encode_xor_address(*address, transaction_id),
        )),
        Attribute::XorRelayedAddress(address) => Ok((
            XOR_RELAYED_ADDRESS,
            encode_xor_address(*address, transaction_id),
        )),
        Attribute::XorMappedAddress(address) => Ok((
            XOR_MAPPED_ADDRESS,
            encode_xor_address(*address, transaction_id),
        )),
        Attribute::ChannelNumber(channel) => {
            if !(CHANNEL_MIN..=CHANNEL_MAX).contains(channel) {
                return Err(WireError::InvalidChannel);
            }
            let mut value = channel.to_be_bytes().to_vec();
            value.extend_from_slice(&[0, 0]);
            Ok((CHANNEL_NUMBER, value))
        }
        Attribute::Data(data) => {
            if data.len() > MAX_DATAGRAM_BYTES - HEADER_LEN - ATTRIBUTE_HEADER_LEN {
                return Err(WireError::TooLarge);
            }
            Ok((DATA, data.clone()))
        }
        Attribute::ErrorCode { code, reason } => {
            if !(300..=699).contains(code)
                || reason.chars().count() >= 128
                || reason.len() > u16::MAX as usize - 4
            {
                return Err(WireError::InvalidAttribute);
            }
            let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
            value.extend_from_slice(reason.as_bytes());
            Ok((ERROR_CODE, value))
        }
    }
}

fn decode_attribute(
    kind: u16,
    value: &[u8],
    transaction_id: [u8; 12],
) -> Result<Option<Attribute>, WireError> {
    let attribute = match kind {
        USERNAME => Attribute::Username(bounded_text(value, 1, 512)?),
        REALM => Attribute::Realm(bounded_text(value, 1, 127)?),
        NONCE => Attribute::Nonce(bounded_text(value, 1, 763)?),
        MESSAGE_INTEGRITY_SHA256 if value.len() == 32 => {
            let mut integrity = [0; 32];
            integrity.copy_from_slice(value);
            Attribute::MessageIntegritySha256(integrity)
        }
        REQUESTED_TRANSPORT if value.len() == 4 => Attribute::RequestedTransport(value[0]),
        LIFETIME if value.len() == 4 => {
            Attribute::Lifetime(u32::from_be_bytes(value.try_into().expect("four bytes")))
        }
        XOR_PEER_ADDRESS => Attribute::XorPeerAddress(decode_xor_address(value, transaction_id)?),
        XOR_RELAYED_ADDRESS => {
            Attribute::XorRelayedAddress(decode_xor_address(value, transaction_id)?)
        }
        XOR_MAPPED_ADDRESS => {
            Attribute::XorMappedAddress(decode_xor_address(value, transaction_id)?)
        }
        CHANNEL_NUMBER
            if value.len() == 4
                && (CHANNEL_MIN..=CHANNEL_MAX)
                    .contains(&u16::from_be_bytes([value[0], value[1]])) =>
        {
            Attribute::ChannelNumber(u16::from_be_bytes([value[0], value[1]]))
        }
        DATA => Attribute::Data(value.to_vec()),
        ERROR_CODE if value.len() >= 4 => {
            let class = value[2] & 0x07;
            if !(3..=6).contains(&class) || value[3] > 99 {
                return Err(WireError::InvalidAttribute);
            }
            let code = u16::from(class) * 100 + u16::from(value[3]);
            let reason = std::str::from_utf8(&value[4..])
                .map_err(|_| WireError::InvalidAttribute)?
                .to_owned();
            if !(300..=699).contains(&code) || reason.chars().count() >= 128 {
                return Err(WireError::InvalidAttribute);
            }
            Attribute::ErrorCode { code, reason }
        }
        unknown if unknown >= 0x8000 => return Ok(None),
        unknown if !is_known_attribute(unknown) => {
            return Err(WireError::UnknownRequired(unknown));
        }
        _ => return Err(WireError::InvalidAttribute),
    };
    Ok(Some(attribute))
}

fn bounded_text(value: &[u8], min: usize, max: usize) -> Result<Vec<u8>, WireError> {
    if !(min..=max).contains(&value.len()) || std::str::from_utf8(value).is_err() {
        return Err(WireError::InvalidAttribute);
    }
    Ok(value.to_vec())
}

fn is_known_attribute(kind: u16) -> bool {
    matches!(
        kind,
        USERNAME
            | REALM
            | NONCE
            | MESSAGE_INTEGRITY_SHA256
            | REQUESTED_TRANSPORT
            | LIFETIME
            | XOR_PEER_ADDRESS
            | XOR_RELAYED_ADDRESS
            | XOR_MAPPED_ADDRESS
            | CHANNEL_NUMBER
            | DATA
            | ERROR_CODE
    )
}

fn encode_xor_address(address: SocketAddr, transaction_id: [u8; 12]) -> Vec<u8> {
    let mut value = Vec::with_capacity(20);
    value.push(0);
    let mask = address_mask(transaction_id);
    match address.ip() {
        IpAddr::V4(ip) => {
            value.push(0x01);
            value.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
            for (octet, mask_octet) in ip.octets().iter().zip(mask[..4].iter()) {
                value.push(octet ^ mask_octet);
            }
        }
        IpAddr::V6(ip) => {
            value.push(0x02);
            value.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
            for (octet, mask_octet) in ip.octets().iter().zip(mask.iter()) {
                value.push(octet ^ mask_octet);
            }
        }
    }
    value
}

fn decode_xor_address(value: &[u8], transaction_id: [u8; 12]) -> Result<SocketAddr, WireError> {
    if value.len() < 4 {
        return Err(WireError::InvalidAttribute);
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    if port == 0 {
        return Err(WireError::InvalidAttribute);
    }
    let mask = address_mask(transaction_id);
    match value[1] {
        0x01 if value.len() == 8 => {
            let mut octets = [0; 4];
            for index in 0..4 {
                octets[index] = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 if value.len() == 20 => {
            let mut octets = [0; 16];
            for index in 0..16 {
                octets[index] = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(WireError::InvalidAttribute),
    }
}

fn address_mask(transaction_id: [u8; 12]) -> [u8; 16] {
    let mut mask = [0; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(&transaction_id);
    mask
}

fn method_code(method: Method) -> u16 {
    match method {
        Method::Allocate => 0x003,
        Method::Refresh => 0x004,
        Method::Send => 0x006,
        Method::Data => 0x007,
        Method::CreatePermission => 0x008,
        Method::ChannelBind => 0x009,
    }
}

fn decode_method(value: u16) -> Option<Method> {
    Some(match value {
        0x003 => Method::Allocate,
        0x004 => Method::Refresh,
        0x006 => Method::Send,
        0x007 => Method::Data,
        0x008 => Method::CreatePermission,
        0x009 => Method::ChannelBind,
        _ => return None,
    })
}

fn encode_type(class: Class, method: u16) -> u16 {
    let class_bits = match class {
        Class::Request => 0,
        Class::Indication => 1,
        Class::Success => 2,
        Class::Error => 3,
    };
    ((method & 0x0f80) << 2)
        | ((method & 0x0070) << 1)
        | (method & 0x000f)
        | ((class_bits & 1) << 4)
        | ((class_bits & 2) << 7)
}

fn decode_type(value: u16) -> Option<(Class, u16)> {
    if value & 0xc000 != 0 {
        return None;
    }
    let method = ((value >> 2) & 0x0f80) | ((value >> 1) & 0x0070) | (value & 0x000f);
    let class_bits = ((value >> 4) & 1) | ((value >> 7) & 2);
    let class = match class_bits {
        0 => Class::Request,
        1 => Class::Indication,
        2 => Class::Success,
        3 => Class::Error,
        _ => return None,
    };
    Some((class, method))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(class: Class, method: Method, attributes: Vec<Attribute>) -> Message {
        Message {
            header: Header {
                class,
                method,
                transaction_id: [7; 12],
            },
            attributes,
        }
    }

    #[test]
    fn every_supported_request_method_round_trips() {
        for method in [
            Method::Allocate,
            Method::Refresh,
            Method::CreatePermission,
            Method::ChannelBind,
        ] {
            let original = message(Class::Request, method, Vec::new());
            assert_eq!(decode(&encode(&original).unwrap()).unwrap(), original);
        }
    }

    #[test]
    fn method_class_and_transaction_are_strict() {
        assert!(matches!(
            encode(&message(Class::Request, Method::Send, Vec::new())),
            Err(WireError::InvalidMethodClass)
        ));
        let mut invalid = message(Class::Request, Method::Allocate, Vec::new());
        invalid.header.transaction_id = [0; 12];
        assert!(matches!(
            encode(&invalid),
            Err(WireError::InvalidTransaction)
        ));
    }

    #[test]
    fn ipv4_and_ipv6_xor_addresses_round_trip_and_bind_transaction() {
        for address in [
            "192.0.2.44:49152".parse().unwrap(),
            "[2001:db8::1234]:49153".parse().unwrap(),
        ] {
            let original = message(
                Class::Request,
                Method::ChannelBind,
                vec![Attribute::XorPeerAddress(address)],
            );
            assert_eq!(decode(&encode(&original).unwrap()).unwrap(), original);
        }
        let first = encode_xor_address("[2001:db8::1]:5000".parse().unwrap(), [1; 12]);
        let second = encode_xor_address("[2001:db8::1]:5000".parse().unwrap(), [2; 12]);
        assert_ne!(first, second);
    }

    #[test]
    fn create_permission_allows_multiple_peers_but_other_duplicates_fail() {
        let peers = message(
            Class::Request,
            Method::CreatePermission,
            vec![
                Attribute::XorPeerAddress("192.0.2.1:5000".parse().unwrap()),
                Attribute::XorPeerAddress("192.0.2.2:5001".parse().unwrap()),
            ],
        );
        assert_eq!(decode(&encode(&peers).unwrap()).unwrap(), peers);
        let duplicate = message(
            Class::Request,
            Method::Allocate,
            vec![Attribute::Lifetime(600), Attribute::Lifetime(600)],
        );
        assert!(matches!(
            encode(&duplicate),
            Err(WireError::Duplicate(LIFETIME))
        ));
    }

    #[test]
    fn unknown_optional_is_ignored_and_required_is_rejected() {
        let base = encode(&message(Class::Request, Method::Allocate, Vec::new())).unwrap();
        for (kind, expected_ok) in [(0x8001_u16, true), (0x0001_u16, false)] {
            let mut encoded = base.clone();
            append_attribute(&mut encoded, kind, &[1, 2, 3, 4]).unwrap();
            finish_length(&mut encoded).unwrap();
            assert_eq!(decode(&encoded).is_ok(), expected_ok);
        }
    }

    #[test]
    fn channel_attribute_requires_new_rfc8656_range_and_zero_reserved_bits() {
        for channel in [CHANNEL_MIN, CHANNEL_MAX] {
            let original = message(
                Class::Request,
                Method::ChannelBind,
                vec![Attribute::ChannelNumber(channel)],
            );
            assert_eq!(decode(&encode(&original).unwrap()).unwrap(), original);
        }
        assert!(matches!(
            encode(&message(
                Class::Request,
                Method::ChannelBind,
                vec![Attribute::ChannelNumber(0x5000)],
            )),
            Err(WireError::InvalidChannel)
        ));
    }

    #[test]
    fn receiver_ignores_rfc_reserved_and_padding_octets() {
        let channel = message(
            Class::Request,
            Method::ChannelBind,
            vec![
                Attribute::ChannelNumber(CHANNEL_MIN),
                Attribute::XorPeerAddress("192.0.2.1:5000".parse().unwrap()),
            ],
        );
        let mut encoded = encode(&channel).unwrap();
        encoded[26] = 0xaa;
        encoded[27] = 0xbb;
        encoded[32] = 0xcc;
        assert_eq!(decode(&encoded).unwrap(), channel);

        let transport = message(
            Class::Request,
            Method::Allocate,
            vec![Attribute::RequestedTransport(17)],
        );
        let mut encoded = encode(&transport).unwrap();
        encoded[25..28].copy_from_slice(&[1, 2, 3]);
        assert_eq!(decode(&encoded).unwrap(), transport);

        let error = message(
            Class::Error,
            Method::Allocate,
            vec![Attribute::ErrorCode {
                code: 401,
                reason: "Unauthorized".into(),
            }],
        );
        let mut encoded = encode(&error).unwrap();
        encoded[24] = 1;
        encoded[25] = 2;
        encoded[26] |= 0xf8;
        assert_eq!(decode(&encoded).unwrap(), error);
    }

    #[test]
    fn error_code_bounds_and_utf8_are_strict() {
        for code in [299, 700] {
            assert!(encode(&message(
                Class::Error,
                Method::Allocate,
                vec![Attribute::ErrorCode {
                    code,
                    reason: "bad".into(),
                }],
            ))
            .is_err());
        }
        let valid = message(
            Class::Error,
            Method::Allocate,
            vec![Attribute::ErrorCode {
                code: 401,
                reason: "Unauthorized".into(),
            }],
        );
        assert_eq!(decode(&encode(&valid).unwrap()).unwrap(), valid);
    }

    #[test]
    fn channel_data_accepts_zero_unpadded_and_zero_padding() {
        assert_eq!(
            decode_channel_data(&encode_channel_data(CHANNEL_MIN, &[]).unwrap()).unwrap(),
            (CHANNEL_MIN, &[][..])
        );
        let unpadded = encode_channel_data(CHANNEL_MIN, &[1]).unwrap();
        assert_eq!(decode_channel_data(&unpadded).unwrap().1, &[1]);
        let mut padded = unpadded.clone();
        padded.extend_from_slice(&[0, 0, 0]);
        assert_eq!(decode_channel_data(&padded).unwrap().1, &[1]);
        *padded.last_mut().unwrap() = 1;
        assert_eq!(decode_channel_data(&padded).unwrap().1, &[1]);
        assert!(matches!(
            encode_channel_data(CHANNEL_MIN, &vec![0; MAX_DATAGRAM_BYTES]),
            Err(WireError::TooLarge)
        ));
    }

    #[test]
    fn malformed_lengths_padding_and_size_fail_closed() {
        assert!(matches!(decode(&[0; 19]), Err(WireError::Truncated)));
        let mut encoded = encode(&message(
            Class::Request,
            Method::Allocate,
            vec![Attribute::Username(b"abc".to_vec())],
        ))
        .unwrap();
        *encoded.last_mut().unwrap() = 1;
        assert!(decode(&encoded).is_ok());
        assert!(matches!(
            decode(&vec![0; MAX_DATAGRAM_BYTES + 1]),
            Err(WireError::TooLarge)
        ));
    }

    #[test]
    fn debug_never_renders_credentials_or_payload() {
        let value = message(
            Class::Indication,
            Method::Send,
            vec![
                Attribute::Username(b"secret-user".to_vec()),
                Attribute::Nonce(b"secret-nonce".to_vec()),
                Attribute::Data(b"secret-payload".to_vec()),
            ],
        );
        let rendered = format!("{value:?}");
        assert!(rendered.contains("<redacted>"));
        for secret in ["secret-user", "secret-nonce", "secret-payload"] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn long_term_sha256_key_matches_known_vector() {
        let key = derive_long_term_key_sha256(b"user", b"realm", b"pass");
        assert_eq!(
            key.as_ref(),
            &[
                0x07, 0xe9, 0x34, 0x11, 0x7a, 0xbd, 0x40, 0x83, 0x6e, 0x7c, 0x63, 0x29, 0xb5, 0x47,
                0x31, 0xb2, 0xb2, 0xd2, 0xa5, 0xf9, 0xa7, 0x1f, 0x54, 0x49, 0x22, 0xd7, 0x5e, 0x07,
                0x30, 0xd8, 0x25, 0x1b,
            ]
        );
    }

    #[test]
    fn message_integrity_round_trip_wrong_key_and_bit_flip() {
        let request = message(
            Class::Request,
            Method::Allocate,
            vec![
                Attribute::Username(b"user".to_vec()),
                Attribute::Realm(b"realm".to_vec()),
                Attribute::Nonce(b"nonce".to_vec()),
                Attribute::RequestedTransport(17),
            ],
        );
        let key = derive_long_term_key_sha256(b"user", b"realm", b"pass");
        let encoded = encode_with_integrity(&request, key.as_ref()).unwrap();
        let verified = verify_integrity(&encoded, key.as_ref()).unwrap();
        assert!(matches!(
            verified.message().attributes.last(),
            Some(Attribute::MessageIntegritySha256(_))
        ));
        assert!(matches!(
            verify_integrity(&encoded, b"wrong-key"),
            Err(WireError::IntegrityMismatch)
        ));
        let mut mutated = encoded;
        mutated[8] ^= 1;
        assert!(matches!(
            verify_integrity(&mutated, key.as_ref()),
            Err(WireError::IntegrityMismatch)
        ));
    }

    #[test]
    fn missing_duplicate_or_nonfinal_integrity_is_rejected() {
        let request = message(
            Class::Request,
            Method::Refresh,
            vec![Attribute::Lifetime(600)],
        );
        let plain = encode(&request).unwrap();
        assert!(matches!(
            verify_integrity(&plain, b"key"),
            Err(WireError::IntegrityMissing)
        ));
        let invalid = message(
            Class::Request,
            Method::Refresh,
            vec![
                Attribute::MessageIntegritySha256([0; 32]),
                Attribute::Lifetime(600),
            ],
        );
        assert!(matches!(
            encode(&invalid),
            Err(WireError::IntegrityPosition)
        ));
    }
}
