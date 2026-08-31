//! Bounded local RFC 8656 UDP TURN process and evidence client.
//!
//! The relay treats DATA and ChannelData as opaque bytes. It owns no desktop,
//! input, media, or end-to-end encryption key.

mod client;
mod server;

pub use client::run_client;
pub use server::serve;

use latencydesk_turn_relay::{wire::WireError, StateError};
use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_IDENTITY_BYTES: usize = 512;
const MAX_ALLOCATIONS: usize = 256;
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(3_600);

pub struct ServerConfig {
    pub relay_ip: IpAddr,
    realm: Zeroizing<Vec<u8>>,
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    pub max_allocations: usize,
    pub total_timeout: Duration,
    pub allow_loopback_lab: bool,
    pub exit_after_deallocations: usize,
}

impl ServerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay_ip: IpAddr,
        realm: Vec<u8>,
        username: Vec<u8>,
        password: Vec<u8>,
        max_allocations: usize,
        total_timeout: Duration,
        allow_loopback_lab: bool,
        exit_after_deallocations: usize,
    ) -> Result<Self, TurnServiceError> {
        for value in [&realm, &username] {
            if value.is_empty()
                || value.len() > MAX_IDENTITY_BYTES
                || std::str::from_utf8(value).is_err()
            {
                return Err(TurnServiceError::InvalidConfig);
            }
        }
        if password.len() < 16
            || password.len() > MAX_IDENTITY_BYTES
            || relay_ip.is_unspecified()
            || relay_ip.is_multicast()
            || !relay_ip.is_loopback()
            || !allow_loopback_lab
            || !(1..=MAX_ALLOCATIONS).contains(&max_allocations)
            || total_timeout.is_zero()
            || total_timeout > MAX_TOTAL_TIMEOUT
            || exit_after_deallocations > max_allocations
        {
            return Err(TurnServiceError::InvalidConfig);
        }
        Ok(Self {
            relay_ip,
            realm: Zeroizing::new(realm),
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
            max_allocations,
            total_timeout,
            allow_loopback_lab,
            exit_after_deallocations,
        })
    }

    pub(crate) fn realm(&self) -> &[u8] {
        self.realm.as_slice()
    }

    pub(crate) fn username(&self) -> &[u8] {
        self.username.as_slice()
    }

    pub(crate) fn password(&self) -> &[u8] {
        self.password.as_slice()
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerConfig")
            .field("relay_ip", &self.relay_ip)
            .field("realm", &"<redacted>")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("max_allocations", &self.max_allocations)
            .field("total_timeout", &self.total_timeout)
            .field("allow_loopback_lab", &self.allow_loopback_lab)
            .field("exit_after_deallocations", &self.exit_after_deallocations)
            .finish()
    }
}

pub struct ClientConfig {
    pub server: SocketAddr,
    pub bind: SocketAddr,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub peer: SocketAddr,
    pub timeout: Duration,
    pub channel: u16,
    pub send_payload: Vec<u8>,
    pub channel_payload: Vec<u8>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfig")
            .field("server", &self.server)
            .field("bind", &self.bind)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("peer", &self.peer)
            .field("timeout", &self.timeout)
            .field("channel", &self.channel)
            .field("send_payload", &"<redacted>")
            .field("channel_payload", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientReport {
    pub challenge_authenticated: bool,
    pub send_round_trip: bool,
    pub channel_round_trip: bool,
    pub deallocated: bool,
    pub relayed_address: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerReport {
    pub allocations_created: usize,
    pub deallocations: usize,
    pub rejected: usize,
    pub client_to_peer_datagrams: u64,
    pub peer_to_client_datagrams: u64,
    pub clean_shutdown: bool,
}

#[derive(Debug)]
pub enum TurnServiceError {
    InvalidConfig,
    Timeout,
    ResponseCode(u16),
    Randomness,
    Protocol(&'static str),
    Io(std::io::Error),
    Wire(WireError),
    State(StateError),
    Join(tokio::task::JoinError),
}

impl fmt::Display for TurnServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "TURN I/O failed: {error}"),
            Self::Wire(error) => write!(formatter, "TURN wire rejected: {error}"),
            Self::State(error) => write!(formatter, "TURN state rejected: {error}"),
            Self::Join(error) => write!(formatter, "TURN task failed: {error}"),
            other => write!(formatter, "{other:?}"),
        }
    }
}

impl StdError for TurnServiceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::State(error) => Some(error),
            Self::Join(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TurnServiceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<WireError> for TurnServiceError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<StateError> for TurnServiceError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<tokio::task::JoinError> for TurnServiceError {
    fn from(error: tokio::task::JoinError) -> Self {
        Self::Join(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_configuration_is_local_evidence_only() {
        assert!(ServerConfig::new(
            "192.0.2.1".parse().unwrap(),
            b"turn.example".to_vec(),
            b"alice".to_vec(),
            b"alice-password-with-entropy".to_vec(),
            4,
            Duration::from_secs(30),
            true,
            0,
        )
        .is_err());
        assert!(ServerConfig::new(
            "127.0.0.1".parse().unwrap(),
            b"turn.example".to_vec(),
            b"alice".to_vec(),
            b"alice-password-with-entropy".to_vec(),
            4,
            Duration::from_secs(30),
            false,
            0,
        )
        .is_err());
    }
}
