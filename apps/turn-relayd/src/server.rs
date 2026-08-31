use crate::{ServerConfig, ServerReport, TurnServiceError};
use latencydesk_turn_relay::wire::{self, Attribute, Class, Header, Message, Method};
use latencydesk_turn_relay::{
    AllocationCredentials, ChannelNumber, DeliveryRoute, PeerPolicy, Quota, RelayState, StateError,
    UdpTuple, DEFAULT_ALLOCATION_LIFETIME,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

const NONCE_LIFETIME_SECONDS: u64 = 600;
const MAX_CHALLENGES: usize = 1_024;
const MAX_RESPONSE_CACHE: usize = 1_024;
const RESPONSE_CACHE_SECONDS: u64 = 40;
const MAX_BUFFER: usize = wire::MAX_DATAGRAM_BYTES + 1;

struct Challenge {
    nonce: Zeroizing<Vec<u8>>,
    expires_at: u64,
}

struct CachedResponse {
    request_digest: [u8; 32],
    response: Vec<u8>,
    expires_at: u64,
}

enum CacheDecision<'a> {
    Replay(&'a [u8]),
    Admit,
    Reject,
}

struct RuntimeAllocation {
    socket: Arc<UdpSocket>,
    cancel: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

struct Counters {
    client_to_peer: AtomicU64,
    peer_to_client: AtomicU64,
}

struct PeerContext {
    relay: Arc<UdpSocket>,
    control: Arc<UdpSocket>,
    state: Arc<Mutex<RelayState>>,
    tuple: UdpTuple,
    deadline: tokio::time::Instant,
    started: Instant,
    counters: Arc<Counters>,
}

struct Runtime {
    control: Arc<UdpSocket>,
    config: ServerConfig,
    state: Arc<Mutex<RelayState>>,
    challenges: HashMap<SocketAddr, Challenge>,
    response_cache: HashMap<(SocketAddr, [u8; 12]), CachedResponse>,
    allocations: HashMap<UdpTuple, RuntimeAllocation>,
    counters: Arc<Counters>,
    started: Instant,
    deadline: tokio::time::Instant,
    report: ServerReport,
}

pub async fn serve(
    control: UdpSocket,
    config: ServerConfig,
) -> Result<ServerReport, TurnServiceError> {
    let control_address = control.local_addr()?;
    if control_address.ip().is_unspecified()
        || control_address.port() == 0
        || control_address.is_ipv4() != config.relay_ip.is_ipv4()
        || !control_address.ip().is_loopback()
        || !config.allow_loopback_lab
    {
        return Err(TurnServiceError::InvalidConfig);
    }
    let quota = Quota {
        max_allocations: config.max_allocations,
        max_allocations_per_user: config.max_allocations,
        max_permissions_per_allocation: 32,
        max_channels_per_allocation: 32,
        max_packets_per_allocation: 10_000_000,
        max_payload_bytes_per_allocation: 16 * 1024 * 1024 * 1024,
    };
    let policy = PeerPolicy {
        allow_ipv4: true,
        allow_ipv6: true,
        allow_well_known: false,
        allow_loopback_lab: config.allow_loopback_lab,
    };
    let total_timeout = config.total_timeout;
    let mut runtime = Runtime {
        control: Arc::new(control),
        config,
        state: Arc::new(Mutex::new(RelayState::new(quota, policy)?)),
        challenges: HashMap::new(),
        response_cache: HashMap::new(),
        allocations: HashMap::new(),
        counters: Arc::new(Counters {
            client_to_peer: AtomicU64::new(0),
            peer_to_client: AtomicU64::new(0),
        }),
        started: Instant::now(),
        deadline: tokio::time::Instant::now() + total_timeout,
        report: ServerReport {
            allocations_created: 0,
            deallocations: 0,
            rejected: 0,
            client_to_peer_datagrams: 0,
            peer_to_client_datagrams: 0,
            clean_shutdown: false,
        },
    };
    let mut buffer = [0_u8; MAX_BUFFER];
    loop {
        if runtime.config.exit_after_deallocations > 0
            && runtime.report.deallocations >= runtime.config.exit_after_deallocations
        {
            break;
        }
        let maintenance =
            (tokio::time::Instant::now() + Duration::from_secs(1)).min(runtime.deadline);
        let received =
            tokio::time::timeout_at(maintenance, runtime.control.recv_from(&mut buffer)).await;
        let (length, source) = match received {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => return Err(TurnServiceError::Io(error)),
            Err(_) if tokio::time::Instant::now() >= runtime.deadline => break,
            Err(_) => {
                runtime.prune().await;
                continue;
            }
        };
        if length == 0 || length > wire::MAX_DATAGRAM_BYTES {
            runtime.report.rejected = runtime.report.rejected.saturating_add(1);
            continue;
        }
        runtime.prune().await;
        if let Err(error) = runtime.handle_datagram(&buffer[..length], source).await {
            if matches!(error, TurnServiceError::Io(_)) {
                runtime.shutdown().await;
                return Err(error);
            }
            runtime.report.rejected = runtime.report.rejected.saturating_add(1);
        }
    }
    runtime.shutdown().await;
    runtime.report.client_to_peer_datagrams =
        runtime.counters.client_to_peer.load(Ordering::Relaxed);
    runtime.report.peer_to_client_datagrams =
        runtime.counters.peer_to_client.load(Ordering::Relaxed);
    runtime.report.clean_shutdown = runtime.allocations.is_empty();
    Ok(runtime.report)
}

impl Runtime {
    fn now(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn tuple(&self, source: SocketAddr) -> Result<UdpTuple, TurnServiceError> {
        let server = self.control.local_addr()?;
        if source.is_ipv4() != server.is_ipv4()
            || source.ip().is_unspecified()
            || source.ip().is_multicast()
            || source.port() == 0
        {
            return Err(TurnServiceError::Protocol("invalid TURN client source"));
        }
        Ok(UdpTuple {
            client: source,
            server,
        })
    }

    async fn prune(&mut self) {
        self.prune_at(self.now()).await;
    }

    async fn prune_at(&mut self, now: u64) {
        self.challenges
            .retain(|_, challenge| now < challenge.expires_at);
        self.response_cache
            .retain(|_, response| now < response.expires_at);
        let stale = {
            let mut state = self.state.lock().await;
            state.cleanup(now);
            self.allocations
                .keys()
                .copied()
                .filter(|tuple| state.allocation_info(tuple, now).is_err())
                .collect::<Vec<_>>()
        };
        for tuple in stale {
            self.remove_allocation(&tuple).await;
        }
    }

    async fn handle_datagram(
        &mut self,
        datagram: &[u8],
        source: SocketAddr,
    ) -> Result<(), TurnServiceError> {
        let tuple = self.tuple(source)?;
        if (0x40..=0x4f).contains(&datagram[0]) {
            let (channel, payload) = wire::decode_channel_data(datagram)?;
            let peer = self.state.lock().await.authorize_channel_data(
                &tuple,
                ChannelNumber(channel),
                payload.len() as u64,
                self.now(),
            )?;
            let allocation = self
                .allocations
                .get(&tuple)
                .ok_or(TurnServiceError::Protocol("allocation socket missing"))?;
            allocation.socket.send_to(payload, peer).await?;
            self.counters.client_to_peer.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let decoded = wire::decode(datagram)?;
        match decoded.header.class {
            Class::Indication if decoded.header.method == Method::Send => {
                self.handle_send_indication(&tuple, &decoded).await
            }
            Class::Request => self.handle_request(tuple, source, datagram, decoded).await,
            _ => Err(TurnServiceError::Protocol("unexpected TURN message class")),
        }
    }

    async fn handle_send_indication(
        &mut self,
        tuple: &UdpTuple,
        message: &Message,
    ) -> Result<(), TurnServiceError> {
        if message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, Attribute::MessageIntegritySha256(_)))
        {
            return Err(TurnServiceError::Protocol(
                "authenticated indication rejected",
            ));
        }
        let peer = single_peer(message)?;
        let payload = single_data(message)?;
        self.state
            .lock()
            .await
            .authorize_send(tuple, peer, payload.len() as u64, self.now())?;
        let allocation = self
            .allocations
            .get(tuple)
            .ok_or(TurnServiceError::Protocol("allocation socket missing"))?;
        allocation.socket.send_to(payload, peer).await?;
        self.counters.client_to_peer.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn handle_request(
        &mut self,
        tuple: UdpTuple,
        source: SocketAddr,
        encoded: &[u8],
        decoded: Message,
    ) -> Result<(), TurnServiceError> {
        let cache_key = (source, decoded.header.transaction_id);
        let request_digest: [u8; 32] = Sha256::digest(encoded).into();
        match self.cache_decision(&cache_key, request_digest)? {
            CacheDecision::Replay(response) => {
                self.control.send_to(response, source).await?;
                return Ok(());
            }
            CacheDecision::Reject => {
                self.report.rejected = self.report.rejected.saturating_add(1);
                return Ok(());
            }
            CacheDecision::Admit => {}
        }
        let response = match self.process_request(tuple, source, encoded, &decoded).await {
            Ok(response) => response,
            Err(TurnServiceError::Io(error)) => return Err(TurnServiceError::Io(error)),
            Err(error) => {
                self.report.rejected = self.report.rejected.saturating_add(1);
                let code = service_error_code(&error);
                let key = wire::derive_long_term_key_sha256(
                    self.config.username(),
                    self.config.realm(),
                    self.config.password(),
                );
                signed_error(
                    decoded.header.method,
                    decoded.header.transaction_id,
                    code,
                    "Request Rejected",
                    key.as_ref(),
                )?
            }
        };
        self.control.send_to(&response, source).await?;
        self.response_cache.insert(
            cache_key,
            CachedResponse {
                request_digest,
                response,
                expires_at: self.now().saturating_add(RESPONSE_CACHE_SECONDS),
            },
        );
        Ok(())
    }

    fn cache_decision(
        &self,
        key: &(SocketAddr, [u8; 12]),
        request_digest: [u8; 32],
    ) -> Result<CacheDecision<'_>, TurnServiceError> {
        if let Some(cached) = self.response_cache.get(key) {
            if cached.request_digest != request_digest {
                return Err(TurnServiceError::Protocol(
                    "transaction ID payload collision",
                ));
            }
            return Ok(CacheDecision::Replay(&cached.response));
        }
        if self.response_cache.len() >= MAX_RESPONSE_CACHE {
            return Ok(CacheDecision::Reject);
        }
        Ok(CacheDecision::Admit)
    }

    async fn process_request(
        &mut self,
        tuple: UdpTuple,
        source: SocketAddr,
        encoded: &[u8],
        decoded: &Message,
    ) -> Result<Vec<u8>, TurnServiceError> {
        if decoded.header.method == Method::Allocate {
            if !has_integrity(decoded) {
                return self.issue_challenge(
                    Method::Allocate,
                    decoded.header.transaction_id,
                    source,
                    401,
                );
            }
            let key = match self.authenticate_account(encoded, decoded, source) {
                Ok(key) => key,
                Err(AuthFailure::Stale) => {
                    return self.issue_challenge(
                        Method::Allocate,
                        decoded.header.transaction_id,
                        source,
                        438,
                    );
                }
                Err(AuthFailure::Unauthorized) => {
                    return self.issue_challenge(
                        Method::Allocate,
                        decoded.header.transaction_id,
                        source,
                        401,
                    );
                }
            };
            let transport = decoded
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    Attribute::RequestedTransport(protocol) => Some(*protocol),
                    _ => None,
                })
                .ok_or(TurnServiceError::Protocol("REQUESTED-TRANSPORT missing"))?;
            if transport != 17 {
                return signed_error(
                    Method::Allocate,
                    decoded.header.transaction_id,
                    442,
                    "Unsupported Transport Protocol",
                    key.as_ref(),
                );
            }
            let bind_address = SocketAddr::new(self.config.relay_ip, 0);
            let relay_socket = Arc::new(UdpSocket::bind(bind_address).await?);
            let relayed_address = relay_socket.local_addr()?;
            let requested_lifetime = decoded.attributes.iter().find_map(|attribute| {
                if let Attribute::Lifetime(seconds) = attribute {
                    Some(u64::from(*seconds))
                } else {
                    None
                }
            });
            let nonce = self
                .challenges
                .get(&source)
                .ok_or(TurnServiceError::Protocol("challenge disappeared"))?
                .nonce
                .to_vec();
            let auth_identity: [u8; 32] =
                Sha256::digest([self.config.username(), b"\0", self.config.realm()].concat())
                    .into();
            let credentials = AllocationCredentials::new(
                self.config.username().to_vec(),
                self.config.realm().to_vec(),
                nonce,
                auth_identity.to_vec(),
                *key,
            )?;
            let info = self.state.lock().await.create(
                tuple,
                credentials,
                relayed_address,
                self.now(),
                requested_lifetime,
            )?;
            self.spawn_peer_task(tuple, relay_socket);
            self.report.allocations_created += 1;
            return signed_success(
                Method::Allocate,
                decoded.header.transaction_id,
                vec![
                    Attribute::XorRelayedAddress(info.relayed_address),
                    Attribute::XorMappedAddress(source),
                    Attribute::Lifetime(DEFAULT_ALLOCATION_LIFETIME as u32),
                ],
                key.as_ref(),
            );
        }

        let authentication = {
            self.state
                .lock()
                .await
                .authenticate_request(&tuple, encoded, self.now())
        };
        let authenticated = match authentication {
            Ok(request) => request,
            Err(StateError::StaleNonce) => {
                return self.issue_challenge(
                    decoded.header.method,
                    decoded.header.transaction_id,
                    source,
                    438,
                );
            }
            Err(StateError::Integrity | StateError::WrongCredentials) => {
                return self.issue_challenge(
                    decoded.header.method,
                    decoded.header.transaction_id,
                    source,
                    401,
                );
            }
            Err(error) => return Err(error.into()),
        };
        let key = wire::derive_long_term_key_sha256(
            self.config.username(),
            self.config.realm(),
            self.config.password(),
        );
        match decoded.header.method {
            Method::Refresh => {
                let result = self
                    .state
                    .lock()
                    .await
                    .refresh(&authenticated, self.now())?;
                let lifetime = if result.is_some() {
                    DEFAULT_ALLOCATION_LIFETIME as u32
                } else {
                    0
                };
                if result.is_none() {
                    self.remove_allocation(&tuple).await;
                    self.report.deallocations += 1;
                }
                signed_success(
                    Method::Refresh,
                    decoded.header.transaction_id,
                    vec![Attribute::Lifetime(lifetime)],
                    key.as_ref(),
                )
            }
            Method::CreatePermission => {
                self.state
                    .lock()
                    .await
                    .create_permissions(&authenticated, self.now())?;
                signed_success(
                    Method::CreatePermission,
                    decoded.header.transaction_id,
                    vec![],
                    key.as_ref(),
                )
            }
            Method::ChannelBind => {
                self.state
                    .lock()
                    .await
                    .bind_channel(&authenticated, self.now())?;
                signed_success(
                    Method::ChannelBind,
                    decoded.header.transaction_id,
                    vec![],
                    key.as_ref(),
                )
            }
            _ => signed_error(
                decoded.header.method,
                decoded.header.transaction_id,
                400,
                "Bad Request",
                key.as_ref(),
            ),
        }
    }

    fn authenticate_account(
        &self,
        encoded: &[u8],
        decoded: &Message,
        source: SocketAddr,
    ) -> Result<Zeroizing<[u8; 32]>, AuthFailure> {
        let key = wire::derive_long_term_key_sha256(
            self.config.username(),
            self.config.realm(),
            self.config.password(),
        );
        if wire::verify_integrity(encoded, key.as_ref()).is_err() {
            return Err(AuthFailure::Unauthorized);
        }
        let username =
            single_bytes(decoded, BytesKind::Username).ok_or(AuthFailure::Unauthorized)?;
        let realm = single_bytes(decoded, BytesKind::Realm).ok_or(AuthFailure::Unauthorized)?;
        let nonce = single_bytes(decoded, BytesKind::Nonce).ok_or(AuthFailure::Unauthorized)?;
        if username != self.config.username() || realm != self.config.realm() {
            return Err(AuthFailure::Unauthorized);
        }
        let challenge = self.challenges.get(&source).ok_or(AuthFailure::Stale)?;
        if self.now() >= challenge.expires_at || nonce != challenge.nonce.as_slice() {
            return Err(AuthFailure::Stale);
        }
        Ok(key)
    }

    fn issue_challenge(
        &mut self,
        method: Method,
        transaction_id: [u8; 12],
        source: SocketAddr,
        code: u16,
    ) -> Result<Vec<u8>, TurnServiceError> {
        let nonce = random_nonce()?;
        if self.challenges.len() >= MAX_CHALLENGES && !self.challenges.contains_key(&source) {
            return Err(TurnServiceError::Protocol("challenge capacity reached"));
        }
        self.challenges.insert(
            source,
            Challenge {
                nonce: Zeroizing::new(nonce.clone()),
                expires_at: self.now().saturating_add(NONCE_LIFETIME_SECONDS),
            },
        );
        wire::encode(&Message {
            header: Header {
                class: Class::Error,
                method,
                transaction_id,
            },
            attributes: vec![
                Attribute::ErrorCode {
                    code,
                    reason: if code == 438 {
                        "Stale Nonce".into()
                    } else {
                        "Unauthenticated".into()
                    },
                },
                Attribute::Realm(self.config.realm().to_vec()),
                Attribute::Nonce(nonce),
            ],
        })
        .map_err(Into::into)
    }

    fn spawn_peer_task(&mut self, tuple: UdpTuple, socket: Arc<UdpSocket>) {
        let (cancel, cancel_rx) = oneshot::channel();
        let task = tokio::spawn(peer_loop(
            PeerContext {
                relay: socket.clone(),
                control: self.control.clone(),
                state: self.state.clone(),
                tuple,
                deadline: self.deadline,
                started: self.started,
                counters: self.counters.clone(),
            },
            cancel_rx,
        ));
        self.allocations.insert(
            tuple,
            RuntimeAllocation {
                socket,
                cancel: Some(cancel),
                task,
            },
        );
    }

    async fn remove_allocation(&mut self, tuple: &UdpTuple) {
        if let Some(mut runtime) = self.allocations.remove(tuple) {
            if let Some(cancel) = runtime.cancel.take() {
                let _ = cancel.send(());
            }
            if tokio::time::Instant::now() >= self.deadline
                || tokio::time::timeout_at(self.deadline, &mut runtime.task)
                    .await
                    .is_err()
            {
                runtime.task.abort();
                let _ = runtime.task.await;
            }
        }
    }

    async fn shutdown(&mut self) {
        let tuples = self.allocations.keys().copied().collect::<Vec<_>>();
        for tuple in tuples {
            self.remove_allocation(&tuple).await;
        }
    }
}

async fn peer_loop(context: PeerContext, mut cancel: oneshot::Receiver<()>) {
    let mut buffer = [0_u8; MAX_BUFFER];
    loop {
        let received = tokio::select! {
            _ = &mut cancel => break,
            result = tokio::time::timeout_at(context.deadline, context.relay.recv_from(&mut buffer)) => result,
        };
        let (length, source) = match received {
            Ok(Ok(value)) => value,
            _ => break,
        };
        if length > wire::MAX_DATAGRAM_BYTES {
            continue;
        }
        let route = match context.state.lock().await.route_peer_datagram(
            &context.tuple,
            source,
            length as u64,
            context.started.elapsed().as_secs(),
        ) {
            Ok(route) => route,
            Err(_) => continue,
        };
        let encoded = match route {
            DeliveryRoute::ChannelData(channel) => {
                wire::encode_channel_data(channel.0, &buffer[..length]).map_err(Into::into)
            }
            DeliveryRoute::DataIndication => random_transaction_id().and_then(|transaction_id| {
                wire::encode(&Message {
                    header: Header {
                        class: Class::Indication,
                        method: Method::Data,
                        transaction_id,
                    },
                    attributes: vec![
                        Attribute::XorPeerAddress(source),
                        Attribute::Data(buffer[..length].to_vec()),
                    ],
                })
                .map_err(Into::into)
            }),
        };
        let Ok(encoded) = encoded else { continue };
        if context
            .control
            .send_to(&encoded, context.tuple.client)
            .await
            .is_ok()
        {
            context
                .counters
                .peer_to_client
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

enum AuthFailure {
    Unauthorized,
    Stale,
}

enum BytesKind {
    Username,
    Realm,
    Nonce,
}

fn single_bytes(message: &Message, kind: BytesKind) -> Option<&[u8]> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match (&kind, attribute) {
            (BytesKind::Username, Attribute::Username(value))
            | (BytesKind::Realm, Attribute::Realm(value))
            | (BytesKind::Nonce, Attribute::Nonce(value)) => Some(value.as_slice()),
            _ => None,
        })
}

fn single_peer(message: &Message) -> Result<SocketAddr, TurnServiceError> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::XorPeerAddress(peer) => Some(*peer),
            _ => None,
        })
        .ok_or(TurnServiceError::Protocol("XOR-PEER-ADDRESS missing"))
}

fn single_data(message: &Message) -> Result<&[u8], TurnServiceError> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::Data(data) => Some(data.as_slice()),
            _ => None,
        })
        .ok_or(TurnServiceError::Protocol("DATA missing"))
}

fn has_integrity(message: &Message) -> bool {
    message
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, Attribute::MessageIntegritySha256(_)))
}

fn signed_success(
    method: Method,
    transaction_id: [u8; 12],
    attributes: Vec<Attribute>,
    key: &[u8],
) -> Result<Vec<u8>, TurnServiceError> {
    Ok(wire::encode_with_integrity(
        &Message {
            header: Header {
                class: Class::Success,
                method,
                transaction_id,
            },
            attributes,
        },
        key,
    )?)
}

fn signed_error(
    method: Method,
    transaction_id: [u8; 12],
    code: u16,
    reason: &str,
    key: &[u8],
) -> Result<Vec<u8>, TurnServiceError> {
    Ok(wire::encode_with_integrity(
        &Message {
            header: Header {
                class: Class::Error,
                method,
                transaction_id,
            },
            attributes: vec![Attribute::ErrorCode {
                code,
                reason: reason.into(),
            }],
        },
        key,
    )?)
}

fn service_error_code(error: &TurnServiceError) -> u16 {
    match error {
        TurnServiceError::State(
            StateError::DuplicateAllocation | StateError::MissingAllocation,
        ) => 437,
        TurnServiceError::State(StateError::UserQuota | StateError::GlobalQuota) => 486,
        TurnServiceError::State(StateError::InvalidPeer) => 403,
        TurnServiceError::State(
            StateError::PermissionQuota
            | StateError::ChannelQuota
            | StateError::TrafficQuota
            | StateError::RelayAddressInUse,
        ) => 508,
        _ => 400,
    }
}

fn random_nonce() -> Result<Vec<u8>, TurnServiceError> {
    let mut random = [0_u8; 24];
    getrandom::getrandom(&mut random).map_err(|_| TurnServiceError::Randomness)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(48);
    for byte in random {
        encoded.push(HEX[(byte >> 4) as usize]);
        encoded.push(HEX[(byte & 0x0f) as usize]);
    }
    Ok(encoded)
}

fn random_transaction_id() -> Result<[u8; 12], TurnServiceError> {
    let mut transaction_id = [0_u8; 12];
    getrandom::getrandom(&mut transaction_id).map_err(|_| TurnServiceError::Randomness)?;
    if transaction_id == [0; 12] {
        transaction_id[0] = 1;
    }
    Ok(transaction_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn empty_runtime() -> Runtime {
        let control = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let config = ServerConfig::new(
            "127.0.0.1".parse().unwrap(),
            b"turn.example".to_vec(),
            b"alice".to_vec(),
            b"alice-password-with-entropy".to_vec(),
            4,
            Duration::from_secs(5),
            true,
            0,
        )
        .unwrap();
        Runtime {
            control,
            config,
            state: Arc::new(Mutex::new(
                RelayState::new(
                    Quota {
                        max_allocations: 4,
                        max_allocations_per_user: 4,
                        max_permissions_per_allocation: 4,
                        max_channels_per_allocation: 4,
                        max_packets_per_allocation: 100,
                        max_payload_bytes_per_allocation: 100_000,
                    },
                    PeerPolicy {
                        allow_ipv4: true,
                        allow_ipv6: false,
                        allow_well_known: false,
                        allow_loopback_lab: true,
                    },
                )
                .unwrap(),
            )),
            challenges: HashMap::new(),
            response_cache: HashMap::new(),
            allocations: HashMap::new(),
            counters: Arc::new(Counters {
                client_to_peer: AtomicU64::new(0),
                peer_to_client: AtomicU64::new(0),
            }),
            started: Instant::now(),
            deadline: tokio::time::Instant::now() + Duration::from_secs(5),
            report: ServerReport {
                allocations_created: 0,
                deallocations: 0,
                rejected: 0,
                client_to_peer_datagrams: 0,
                peer_to_client_datagrams: 0,
                clean_shutdown: false,
            },
        }
    }

    #[tokio::test]
    async fn natural_allocation_expiry_reaps_runtime_socket_and_task() {
        let mut runtime = empty_runtime().await;
        let tuple = UdpTuple {
            client: "127.0.0.1:41000".parse().unwrap(),
            server: runtime.control.local_addr().unwrap(),
        };
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_address = relay.local_addr().unwrap();
        let key = wire::derive_long_term_key_sha256(
            runtime.config.username(),
            runtime.config.realm(),
            runtime.config.password(),
        );
        runtime
            .state
            .lock()
            .await
            .create(
                tuple,
                AllocationCredentials::new(
                    runtime.config.username().to_vec(),
                    runtime.config.realm().to_vec(),
                    b"nonce".to_vec(),
                    b"identity".to_vec(),
                    *key,
                )
                .unwrap(),
                relay_address,
                0,
                None,
            )
            .unwrap();
        let (cancel, cancel_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = cancel_rx.await;
        });
        runtime.allocations.insert(
            tuple,
            RuntimeAllocation {
                socket: relay,
                cancel: Some(cancel),
                task,
            },
        );
        runtime.prune_at(DEFAULT_ALLOCATION_LIFETIME).await;
        assert!(runtime.allocations.is_empty());
        assert_eq!(runtime.state.lock().await.allocation_count(), 0);
        let rebound = UdpSocket::bind(relay_address).await.unwrap();
        assert_eq!(rebound.local_addr().unwrap(), relay_address);
    }

    #[tokio::test]
    async fn full_response_cache_preserves_admitted_replay_and_rejects_new_admission() {
        let mut runtime = empty_runtime().await;
        let source: SocketAddr = "127.0.0.1:42000".parse().unwrap();
        for index in 0..MAX_RESPONSE_CACHE {
            let mut transaction_id = [0_u8; 12];
            transaction_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            runtime.response_cache.insert(
                (source, transaction_id),
                CachedResponse {
                    request_digest: [index as u8; 32],
                    response: vec![index as u8],
                    expires_at: 40,
                },
            );
        }
        let original = (source, [0; 12]);
        assert!(matches!(
            runtime.cache_decision(&original, [0; 32]).unwrap(),
            CacheDecision::Replay(&[0])
        ));
        assert!(matches!(
            runtime
                .cache_decision(&(source, [0xff; 12]), [9; 32])
                .unwrap(),
            CacheDecision::Reject
        ));
        assert!(runtime.cache_decision(&original, [1; 32]).is_err());
    }
}
