//! Bounded same-socket STUN server-reflexive address discovery.
//!
//! Discovery is connectivity metadata only. It neither authenticates a peer
//! nor authorizes a LatencyDesk session; exact-leaf mTLS remains mandatory.

use latencydesk_protocol::stun::{
    decode_binding_success, encode_binding_request, MappedAddress, StunError, TransactionId,
    MAX_MESSAGE_BYTES,
};
use std::error::Error;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAX_REQUESTS: u8 = 7;
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_INITIAL_RTO: Duration = Duration::from_secs(5);
const MAX_IGNORED_DATAGRAMS: u32 = 32;
const MAX_DRAINED_DATAGRAMS: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunDiscoveryConfig {
    initial_rto: Duration,
    max_requests: u8,
    total_timeout: Duration,
}

impl StunDiscoveryConfig {
    pub fn new(
        initial_rto: Duration,
        max_requests: u8,
        total_timeout: Duration,
    ) -> Result<Self, StunDiscoveryError> {
        if initial_rto.is_zero()
            || initial_rto > MAX_INITIAL_RTO
            || !(1..=MAX_REQUESTS).contains(&max_requests)
            || total_timeout < initial_rto
            || total_timeout > MAX_TOTAL_TIMEOUT
        {
            return Err(StunDiscoveryError::InvalidPolicy);
        }
        Ok(Self {
            initial_rto,
            max_requests,
            total_timeout,
        })
    }

    #[must_use]
    pub const fn initial_rto(self) -> Duration {
        self.initial_rto
    }

    #[must_use]
    pub const fn max_requests(self) -> u8 {
        self.max_requests
    }

    #[must_use]
    pub const fn total_timeout(self) -> Duration {
        self.total_timeout
    }
}

impl Default for StunDiscoveryConfig {
    fn default() -> Self {
        Self {
            initial_rto: Duration::from_millis(500),
            max_requests: MAX_REQUESTS,
            total_timeout: Duration::from_millis(39_500),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunDiscoveryReport {
    pub local_address: SocketAddr,
    pub mapped_address: SocketAddr,
    pub server_address: SocketAddr,
    pub requests_sent: u8,
    pub ignored_datagrams: u32,
    pub drained_datagrams: u32,
    pub elapsed: Duration,
}

#[derive(Debug)]
pub enum StunDiscoveryError {
    InvalidPolicy,
    InvalidServerAddress,
    AddressFamilyMismatch,
    InvalidMappedAddress,
    Randomness,
    TooManyUnexpectedDatagrams,
    Timeout {
        requests_sent: u8,
        ignored_datagrams: u32,
    },
    Io(io::Error),
}

impl fmt::Display for StunDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str("invalid bounded STUN discovery policy"),
            Self::InvalidServerAddress => formatter.write_str("invalid STUN server address"),
            Self::AddressFamilyMismatch => {
                formatter.write_str("STUN server and local UDP socket address families differ")
            }
            Self::InvalidMappedAddress => {
                formatter.write_str("STUN server returned an unusable reflexive address")
            }
            Self::Randomness => {
                formatter.write_str("operating-system randomness failed for STUN transaction ID")
            }
            Self::TooManyUnexpectedDatagrams => {
                formatter.write_str("too many unrelated datagrams during STUN discovery")
            }
            Self::Timeout {
                requests_sent,
                ignored_datagrams,
            } => write!(
                formatter,
                "STUN discovery timed out after {requests_sent} request(s) and {ignored_datagrams} ignored datagram(s)"
            ),
            Self::Io(error) => write!(formatter, "STUN socket I/O failed: {error}"),
        }
    }
}

impl Error for StunDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

pub fn discover_server_reflexive(
    socket: &UdpSocket,
    server_address: SocketAddr,
    config: StunDiscoveryConfig,
) -> Result<StunDiscoveryReport, StunDiscoveryError> {
    let mut transaction_id = [0_u8; 12];
    getrandom::getrandom(&mut transaction_id).map_err(|_| StunDiscoveryError::Randomness)?;
    discover_server_reflexive_with_transaction(
        socket,
        server_address,
        config,
        TransactionId::new(transaction_id),
    )
}

fn discover_server_reflexive_with_transaction(
    socket: &UdpSocket,
    server_address: SocketAddr,
    config: StunDiscoveryConfig,
    transaction_id: TransactionId,
) -> Result<StunDiscoveryReport, StunDiscoveryError> {
    validate_server_address(server_address)?;
    let local_address = socket.local_addr().map_err(StunDiscoveryError::Io)?;
    if local_address.is_ipv4() != server_address.is_ipv4() {
        return Err(StunDiscoveryError::AddressFamilyMismatch);
    }
    let original_timeout = socket.read_timeout().map_err(StunDiscoveryError::Io)?;
    let started = Instant::now();
    let result = run_transaction(
        socket,
        local_address,
        server_address,
        config,
        transaction_id,
        started,
    );
    let restore = socket
        .set_read_timeout(original_timeout)
        .map_err(StunDiscoveryError::Io);
    match (result, restore) {
        (Ok(report), Ok(())) => Ok(report),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), _) => Err(error),
    }
}

fn run_transaction(
    socket: &UdpSocket,
    local_address: SocketAddr,
    server_address: SocketAddr,
    config: StunDiscoveryConfig,
    transaction_id: TransactionId,
    started: Instant,
) -> Result<StunDiscoveryReport, StunDiscoveryError> {
    let request = encode_binding_request(transaction_id);
    let deadline = started + config.total_timeout;
    let mut rto = config.initial_rto;
    let mut requests_sent = 0_u8;
    let mut ignored_datagrams = 0_u32;
    let mut buffer = [0_u8; MAX_MESSAGE_BYTES + 1];

    while requests_sent < config.max_requests && Instant::now() < deadline {
        socket
            .send_to(&request, server_address)
            .map_err(StunDiscoveryError::Io)?;
        requests_sent += 1;
        let response_deadline = Instant::now()
            .checked_add(rto)
            .unwrap_or(deadline)
            .min(deadline);
        loop {
            let now = Instant::now();
            if now >= response_deadline {
                break;
            }
            let remaining = response_deadline.duration_since(now);
            socket
                .set_read_timeout(Some(remaining))
                .map_err(StunDiscoveryError::Io)?;
            match socket.recv_from(&mut buffer) {
                Ok((length, source)) => {
                    if source != server_address {
                        ignored_datagrams = count_ignored(ignored_datagrams)?;
                        continue;
                    }
                    match decode_binding_success(&buffer[..length], transaction_id, true) {
                        Ok(success) => {
                            let mapped_address = match socket_from_mapped(success.mapped) {
                                Ok(address) if address.is_ipv4() == local_address.is_ipv4() => {
                                    address
                                }
                                _ => {
                                    ignored_datagrams = count_ignored(ignored_datagrams)?;
                                    continue;
                                }
                            };
                            let drained_datagrams = drain_socket(socket)?;
                            return Ok(StunDiscoveryReport {
                                local_address,
                                mapped_address,
                                server_address,
                                requests_sent,
                                ignored_datagrams,
                                drained_datagrams,
                                elapsed: started.elapsed(),
                            });
                        }
                        Err(StunError::TransactionMismatch) => {
                            ignored_datagrams = count_ignored(ignored_datagrams)?;
                        }
                        Err(_) => {
                            ignored_datagrams = count_ignored(ignored_datagrams)?;
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(StunDiscoveryError::Io(error)),
            }
        }
        rto = rto.checked_mul(2).unwrap_or(MAX_INITIAL_RTO);
    }
    Err(StunDiscoveryError::Timeout {
        requests_sent,
        ignored_datagrams,
    })
}

fn count_ignored(current: u32) -> Result<u32, StunDiscoveryError> {
    let next = current.saturating_add(1);
    if next > MAX_IGNORED_DATAGRAMS {
        Err(StunDiscoveryError::TooManyUnexpectedDatagrams)
    } else {
        Ok(next)
    }
}

fn drain_socket(socket: &UdpSocket) -> Result<u32, StunDiscoveryError> {
    let original_timeout = socket.read_timeout().map_err(StunDiscoveryError::Io)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(1)))
        .map_err(StunDiscoveryError::Io)?;
    let mut buffer = [0_u8; MAX_MESSAGE_BYTES + 1];
    let mut drained = 0_u32;
    let result = loop {
        match socket.recv_from(&mut buffer) {
            Ok(_) => {
                drained = drained.saturating_add(1);
                if drained > MAX_DRAINED_DATAGRAMS {
                    break Err(StunDiscoveryError::TooManyUnexpectedDatagrams);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break Ok(drained);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(StunDiscoveryError::Io(error)),
        }
    };
    let restore = socket
        .set_read_timeout(original_timeout)
        .map_err(StunDiscoveryError::Io);
    match (result, restore) {
        (Ok(count), Ok(())) => Ok(count),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), _) => Err(error),
    }
}

fn validate_server_address(address: SocketAddr) -> Result<(), StunDiscoveryError> {
    let invalid = address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::BROADCAST);
    if invalid {
        Err(StunDiscoveryError::InvalidServerAddress)
    } else {
        Ok(())
    }
}

fn socket_from_mapped(mapped: MappedAddress) -> Result<SocketAddr, StunDiscoveryError> {
    let address = match mapped {
        MappedAddress::Ipv4 { address, port } => SocketAddr::from((Ipv4Addr::from(address), port)),
        MappedAddress::Ipv6 { address, port } => {
            SocketAddr::from((std::net::Ipv6Addr::from(address), port))
        }
    };
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        Err(StunDiscoveryError::InvalidMappedAddress)
    } else {
        Ok(address)
    }
}

#[cfg(test)]
fn mapped_from_socket(address: SocketAddr) -> MappedAddress {
    match address {
        SocketAddr::V4(address) => MappedAddress::Ipv4 {
            address: address.ip().octets(),
            port: address.port(),
        },
        SocketAddr::V6(address) => MappedAddress::Ipv6 {
            address: address.ip().octets(),
            port: address.port(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_protocol::stun::{decode_binding_request, encode_binding_success};
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant};

    const TRANSACTION: TransactionId = TransactionId::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    fn fast_policy(max_requests: u8) -> StunDiscoveryConfig {
        StunDiscoveryConfig::new(
            Duration::from_millis(10),
            max_requests,
            Duration::from_millis(100),
        )
        .expect("test policy")
    }

    #[test]
    fn binding_discovery_uses_and_preserves_the_exact_udp_socket() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server");
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("server timeout");
        let server_address = server.local_addr().expect("server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0_u8; 256];
            let (length, source) = server.recv_from(&mut buffer).expect("request");
            let transaction =
                decode_binding_request(&buffer[..length], true).expect("binding request");
            let mapped = mapped_from_socket(source);
            let response = encode_binding_success(transaction, mapped);
            server.send_to(&response, source).expect("response");
            source
        });

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        let original_timeout = Some(Duration::from_millis(321));
        socket
            .set_read_timeout(original_timeout)
            .expect("original timeout");
        let local_before = socket.local_addr().expect("client address");
        let report = discover_server_reflexive_with_transaction(
            &socket,
            server_address,
            fast_policy(1),
            TRANSACTION,
        )
        .expect("STUN discovery");
        assert_eq!(worker.join().expect("server thread"), local_before);
        assert_eq!(report.local_address, local_before);
        assert_eq!(report.mapped_address, local_before);
        assert_eq!(report.server_address, server_address);
        assert_eq!(report.requests_sent, 1);
        assert_eq!(report.ignored_datagrams, 0);
        assert_eq!(socket.local_addr().expect("same socket"), local_before);
        assert_eq!(
            socket.read_timeout().expect("restored timeout"),
            original_timeout
        );
    }

    #[test]
    fn wrong_source_and_transaction_are_ignored_before_exact_response() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server");
        let rogue = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("rogue");
        let server_address = server.local_addr().expect("server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0_u8; 256];
            let (length, source) = server.recv_from(&mut buffer).expect("request");
            let transaction =
                decode_binding_request(&buffer[..length], true).expect("binding request");
            let mapped = mapped_from_socket(source);
            rogue
                .send_to(&encode_binding_success(transaction, mapped), source)
                .expect("wrong-source response");
            let mut wrong = transaction.into_bytes();
            wrong[0] ^= 1;
            server
                .send_to(
                    &encode_binding_success(TransactionId::new(wrong), mapped),
                    source,
                )
                .expect("wrong-transaction response");
            server
                .send_to(&encode_binding_success(transaction, mapped), source)
                .expect("exact response");
        });

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        let report = discover_server_reflexive_with_transaction(
            &socket,
            server_address,
            fast_policy(1),
            TRANSACTION,
        )
        .expect("eventual exact response");
        worker.join().expect("server thread");
        assert_eq!(report.ignored_datagrams, 2);
    }

    #[test]
    fn authenticated_looking_but_unusable_mapping_is_ignored() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server");
        let server_address = server.local_addr().expect("server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0_u8; 256];
            let (length, source) = server.recv_from(&mut buffer).expect("request");
            let transaction =
                decode_binding_request(&buffer[..length], true).expect("binding request");
            server
                .send_to(
                    &encode_binding_success(
                        transaction,
                        MappedAddress::Ipv4 {
                            address: [0, 0, 0, 0],
                            port: 0,
                        },
                    ),
                    source,
                )
                .expect("unusable mapping");
            server
                .send_to(
                    &encode_binding_success(transaction, mapped_from_socket(source)),
                    source,
                )
                .expect("usable mapping");
        });
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        let report = discover_server_reflexive_with_transaction(
            &socket,
            server_address,
            fast_policy(1),
            TRANSACTION,
        )
        .expect("usable response wins");
        worker.join().expect("server thread");
        assert_eq!(report.ignored_datagrams, 1);
    }

    #[test]
    fn malformed_exact_server_response_fails_closed() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server");
        let server_address = server.local_addr().expect("server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0_u8; 256];
            let (_, source) = server.recv_from(&mut buffer).expect("request");
            server
                .send_to(&[0_u8; 20], source)
                .expect("malformed response");
        });
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        let result = discover_server_reflexive_with_transaction(
            &socket,
            server_address,
            fast_policy(1),
            TRANSACTION,
        );
        worker.join().expect("server thread");
        assert!(matches!(
            result,
            Err(StunDiscoveryError::Timeout {
                requests_sent: 1,
                ignored_datagrams: 1,
            })
        ));
    }

    #[test]
    fn retransmission_and_total_deadline_are_bounded() {
        let unused = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve address");
        let unused_address = unused.local_addr().expect("unused address");
        drop(unused);
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        let started = Instant::now();
        let result = discover_server_reflexive_with_transaction(
            &socket,
            unused_address,
            fast_policy(2),
            TRANSACTION,
        );
        assert!(matches!(
            result,
            Err(StunDiscoveryError::Timeout {
                requests_sent: 2,
                ignored_datagrams: 0,
            })
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn retransmission_reuses_the_bit_identical_request_and_transaction() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server");
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("server timeout");
        let server_address = server.local_addr().expect("server address");
        let worker = thread::spawn(move || {
            let mut first = [0_u8; 256];
            let mut second = [0_u8; 256];
            let (first_len, source) = server.recv_from(&mut first).expect("first request");
            let (second_len, second_source) =
                server.recv_from(&mut second).expect("second request");
            assert_eq!(source, second_source);
            assert_eq!(&first[..first_len], &second[..second_len]);
            let transaction =
                decode_binding_request(&second[..second_len], true).expect("binding request");
            server
                .send_to(
                    &encode_binding_success(transaction, mapped_from_socket(source)),
                    source,
                )
                .expect("response");
        });
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        let report = discover_server_reflexive_with_transaction(
            &socket,
            server_address,
            fast_policy(2),
            TRANSACTION,
        )
        .expect("second request succeeds");
        worker.join().expect("server thread");
        assert_eq!(report.requests_sent, 2);
    }

    #[test]
    fn invalid_server_policy_and_address_family_are_rejected() {
        assert!(StunDiscoveryConfig::new(Duration::ZERO, 1, Duration::from_secs(1)).is_err());
        assert!(
            StunDiscoveryConfig::new(Duration::from_millis(10), 0, Duration::from_secs(1)).is_err()
        );
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
        let invalid = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 3478));
        assert!(matches!(
            discover_server_reflexive_with_transaction(
                &socket,
                invalid,
                fast_policy(1),
                TRANSACTION
            ),
            Err(StunDiscoveryError::InvalidServerAddress)
        ));
        let ipv6 = "[::1]:3478".parse().expect("IPv6 server");
        assert!(matches!(
            discover_server_reflexive_with_transaction(&socket, ipv6, fast_policy(1), TRANSACTION),
            Err(StunDiscoveryError::AddressFamilyMismatch)
        ));
    }

    #[test]
    fn bounded_drain_does_not_change_nonblocking_mode() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("socket");
        socket.set_nonblocking(true).expect("nonblocking");
        assert_eq!(drain_socket(&socket).expect("empty drain"), 0);
        let mut byte = [0_u8; 1];
        let started = Instant::now();
        let error = socket.recv_from(&mut byte).expect_err("still nonblocking");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
