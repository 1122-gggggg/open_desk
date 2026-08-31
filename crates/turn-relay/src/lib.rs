//! Bounded RFC 8656 UDP allocation, permission, channel, and quota state.
//!
//! Wire parsing and socket I/O remain separate. Every timestamp is a
//! caller-supplied monotonic second count; wall-clock subtraction is forbidden.

pub mod wire;

use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const DEFAULT_ALLOCATION_LIFETIME: u64 = 600;
pub const MAX_ALLOCATION_LIFETIME: u64 = 600;
pub const PERMISSION_LIFETIME: u64 = 300;
pub const CHANNEL_LIFETIME: u64 = 600;
pub const QUARANTINE_LIFETIME: u64 = 300;

const MAX_GLOBAL_ALLOCATIONS: usize = 4_096;
const MAX_USER_ALLOCATIONS: usize = 256;
const MAX_PERMISSIONS: usize = 64;
const MAX_CHANNELS: usize = 64;
const MAX_TRAFFIC_PACKETS: u64 = 1_000_000_000;
const MAX_TRAFFIC_BYTES: u64 = 1 << 40;
const MAX_CREDENTIAL_BYTES: usize = 512;
static NEXT_STATE_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// TURN-over-UDP allocation key. RFC 8656 identifies an allocation by the
/// client/server transport 5-tuple; the transport is fixed to UDP by this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpTuple {
    pub client: SocketAddr,
    pub server: SocketAddr,
}

#[derive(Clone)]
pub struct AllocationCredentials {
    username: Zeroizing<Vec<u8>>,
    realm: Zeroizing<Vec<u8>>,
    nonce: Zeroizing<Vec<u8>>,
    auth_identity: Zeroizing<Vec<u8>>,
    integrity_key: Zeroizing<[u8; 32]>,
}

impl AllocationCredentials {
    pub fn new(
        username: Vec<u8>,
        realm: Vec<u8>,
        nonce: Vec<u8>,
        auth_identity: Vec<u8>,
        integrity_key: [u8; 32],
    ) -> Result<Self, StateError> {
        for value in [&username, &realm, &nonce] {
            if value.is_empty()
                || value.len() > MAX_CREDENTIAL_BYTES
                || std::str::from_utf8(value).is_err()
            {
                return Err(StateError::InvalidCredentials);
            }
        }
        if auth_identity.is_empty() || auth_identity.len() > MAX_CREDENTIAL_BYTES {
            return Err(StateError::InvalidCredentials);
        }
        Ok(Self {
            username: Zeroizing::new(username),
            realm: Zeroizing::new(realm),
            nonce: Zeroizing::new(nonce),
            auth_identity: Zeroizing::new(auth_identity),
            integrity_key: Zeroizing::new(integrity_key),
        })
    }

    #[must_use]
    pub fn username(&self) -> &[u8] {
        self.username.as_slice()
    }

    #[must_use]
    pub fn realm(&self) -> &[u8] {
        self.realm.as_slice()
    }

    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        self.nonce.as_slice()
    }
}

impl fmt::Debug for AllocationCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AllocationCredentials(<redacted>)")
    }
}

/// Sealed authorization for one integrity-verified request. Only
/// [`RelayState::authenticate_request`] can construct it.
pub struct AuthenticatedRequest {
    state_instance: u64,
    tuple: UdpTuple,
    allocation_incarnation: u64,
    credential_generation: u64,
    verified: wire::VerifiedMessage,
}

/// Redacted material for a signed stale-nonce challenge. The allocation owns
/// this snapshot and callers can only ask it to encode the fixed 438 response;
/// credential bytes and the integrity key never leave this module.
pub struct StaleNonceChallenge {
    realm: Zeroizing<Vec<u8>>,
    nonce: Zeroizing<Vec<u8>>,
    integrity_key: Zeroizing<[u8; 32]>,
}

impl StaleNonceChallenge {
    pub fn encode_signed_438(
        &self,
        method: wire::Method,
        transaction_id: [u8; 12],
    ) -> Result<Vec<u8>, wire::WireError> {
        if !matches!(
            method,
            wire::Method::Refresh | wire::Method::CreatePermission | wire::Method::ChannelBind
        ) {
            return Err(wire::WireError::InvalidMethodClass);
        }
        wire::encode_with_integrity(
            &wire::Message {
                header: wire::Header {
                    class: wire::Class::Error,
                    method,
                    transaction_id,
                },
                attributes: vec![
                    wire::Attribute::ErrorCode {
                        code: 438,
                        reason: "Stale Nonce".into(),
                    },
                    wire::Attribute::Realm(self.realm.to_vec()),
                    wire::Attribute::Nonce(self.nonce.to_vec()),
                ],
            },
            self.integrity_key.as_ref(),
        )
    }
}

impl fmt::Debug for StaleNonceChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaleNonceChallenge(<redacted>)")
    }
}

impl AuthenticatedRequest {
    #[must_use]
    pub const fn method(&self) -> wire::Method {
        self.verified.message().header.method
    }

    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 12] {
        self.verified.message().header.transaction_id
    }

    #[must_use]
    pub const fn message(&self) -> &wire::Message {
        self.verified.message()
    }
}

impl fmt::Debug for AuthenticatedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRequest")
            .field("state_instance", &self.state_instance)
            .field("tuple", &self.tuple)
            .field("allocation_incarnation", &self.allocation_incarnation)
            .field("credential_generation", &self.credential_generation)
            .field("message", &self.verified)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub max_allocations: usize,
    pub max_allocations_per_user: usize,
    pub max_permissions_per_allocation: usize,
    pub max_channels_per_allocation: usize,
    pub max_packets_per_allocation: u64,
    pub max_payload_bytes_per_allocation: u64,
}

impl Quota {
    fn validate(self) -> Result<Self, StateError> {
        if !(1..=MAX_GLOBAL_ALLOCATIONS).contains(&self.max_allocations)
            || !(1..=MAX_USER_ALLOCATIONS).contains(&self.max_allocations_per_user)
            || self.max_allocations_per_user > self.max_allocations
            || !(1..=MAX_PERMISSIONS).contains(&self.max_permissions_per_allocation)
            || !(1..=MAX_CHANNELS).contains(&self.max_channels_per_allocation)
            || !(1..=MAX_TRAFFIC_PACKETS).contains(&self.max_packets_per_allocation)
            || !(1..=MAX_TRAFFIC_BYTES).contains(&self.max_payload_bytes_per_allocation)
        {
            return Err(StateError::InvalidQuota);
        }
        Ok(self)
    }
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            max_allocations: 1_024,
            max_allocations_per_user: 8,
            max_permissions_per_allocation: 32,
            max_channels_per_allocation: 32,
            max_packets_per_allocation: MAX_TRAFFIC_PACKETS,
            max_payload_bytes_per_allocation: MAX_TRAFFIC_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerPolicy {
    pub allow_ipv4: bool,
    pub allow_ipv6: bool,
    pub allow_well_known: bool,
    pub allow_loopback_lab: bool,
}

impl Default for PeerPolicy {
    fn default() -> Self {
        Self {
            allow_ipv4: true,
            allow_ipv6: true,
            allow_well_known: false,
            allow_loopback_lab: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelNumber(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryRoute {
    ChannelData(ChannelNumber),
    DataIndication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficCounters {
    pub packets: u64,
    pub payload_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationInfo {
    pub relayed_address: SocketAddr,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    InvalidQuota,
    InvalidCredentials,
    InvalidTuple,
    InvalidRelay,
    RelayAddressInUse,
    DuplicateAllocation,
    MissingAllocation,
    ExpiredAllocation,
    GlobalQuota,
    UserQuota,
    PermissionQuota,
    ChannelQuota,
    TrafficQuota,
    InvalidPeer,
    InvalidChannel,
    ChannelCollision,
    ChannelQuarantined,
    NotPermitted,
    ChannelNotBound,
    WrongCredentials,
    StaleNonce,
    StaleAuthorization,
    IncarnationExhausted,
    Integrity,
    WrongRequestMethod,
    TimeOverflow,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl StdError for StateError {}

struct Permission {
    expires_at: u64,
}

struct ChannelBinding {
    peer: SocketAddr,
    expires_at: u64,
    quarantine_until: u64,
}

struct ExpiredBinding {
    channel: ChannelNumber,
    peer: SocketAddr,
    quarantine_until: u64,
}

struct Allocation {
    credentials: AllocationCredentials,
    incarnation: u64,
    credential_generation: u64,
    relayed_address: SocketAddr,
    expires_at: u64,
    permissions: HashMap<IpAddr, Permission>,
    channels: HashMap<ChannelNumber, ChannelBinding>,
    expired_bindings: Vec<ExpiredBinding>,
    counters: TrafficCounters,
}

impl Allocation {
    fn prune_children(&mut self, now: u64) {
        self.permissions
            .retain(|_, permission| now < permission.expires_at);
        let expired = self
            .channels
            .iter()
            .filter(|(_, binding)| now >= binding.expires_at)
            .map(|(channel, binding)| (*channel, binding.peer, binding.quarantine_until))
            .collect::<Vec<_>>();
        for (channel, peer, until) in expired {
            self.channels.remove(&channel);
            self.expired_bindings.push(ExpiredBinding {
                channel,
                peer,
                quarantine_until: until,
            });
        }
        self.expired_bindings
            .retain(|binding| now < binding.quarantine_until);
    }
}

pub struct RelayState {
    state_instance: u64,
    allocations: HashMap<UdpTuple, Allocation>,
    next_incarnation: u64,
    quota: Quota,
    policy: PeerPolicy,
}

impl RelayState {
    pub fn new(quota: Quota, policy: PeerPolicy) -> Result<Self, StateError> {
        let state_instance = NEXT_STATE_INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| StateError::IncarnationExhausted)?;
        Ok(Self {
            state_instance,
            allocations: HashMap::new(),
            next_incarnation: 0,
            quota: quota.validate()?,
            policy,
        })
    }

    #[must_use]
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    pub fn create(
        &mut self,
        key: UdpTuple,
        credentials: AllocationCredentials,
        relayed_address: SocketAddr,
        now: u64,
        requested_lifetime: Option<u64>,
    ) -> Result<AllocationInfo, StateError> {
        validate_tuple(key)?;
        validate_relay(self.policy, key, relayed_address)?;
        self.cleanup(now);
        if self.allocations.contains_key(&key) {
            return Err(StateError::DuplicateAllocation);
        }
        if self
            .allocations
            .values()
            .any(|allocation| allocation.relayed_address == relayed_address)
        {
            return Err(StateError::RelayAddressInUse);
        }
        if self.allocations.len() >= self.quota.max_allocations {
            return Err(StateError::GlobalQuota);
        }
        let user_allocations = self
            .allocations
            .values()
            .filter(|allocation| {
                constant_eq(allocation.credentials.username(), credentials.username())
                    && constant_eq(
                        allocation.credentials.auth_identity.as_slice(),
                        credentials.auth_identity.as_slice(),
                    )
            })
            .count();
        if user_allocations >= self.quota.max_allocations_per_user {
            return Err(StateError::UserQuota);
        }
        let lifetime = desired_lifetime(requested_lifetime);
        let expires_at = now.checked_add(lifetime).ok_or(StateError::TimeOverflow)?;
        let incarnation = self
            .next_incarnation
            .checked_add(1)
            .ok_or(StateError::IncarnationExhausted)?;
        self.next_incarnation = incarnation;
        self.allocations.insert(
            key,
            Allocation {
                credentials,
                incarnation,
                credential_generation: 1,
                relayed_address,
                expires_at,
                permissions: HashMap::new(),
                channels: HashMap::new(),
                expired_bindings: Vec::new(),
                counters: TrafficCounters {
                    packets: 0,
                    payload_bytes: 0,
                },
            },
        );
        Ok(AllocationInfo {
            relayed_address,
            expires_at,
        })
    }

    pub fn authenticate_request(
        &mut self,
        key: &UdpTuple,
        encoded_request: &[u8],
        now: u64,
    ) -> Result<AuthenticatedRequest, StateError> {
        self.authenticate_request_inner(key, encoded_request, now, false)
    }

    /// Validate an authenticated stale-nonce request and return the current
    /// nonce without mutating allocation state.  A stale challenge is
    /// idempotent: retransmissions or a new transaction carrying the same old
    /// nonce receive the same current nonce and cannot force nonce churn.
    pub fn stale_nonce_challenge(
        &mut self,
        key: &UdpTuple,
        encoded_request: &[u8],
        now: u64,
    ) -> Result<StaleNonceChallenge, StateError> {
        let request = self.authenticate_request_inner(key, encoded_request, now, true)?;
        let supplied_nonce = request_credentials(request.message())?.nonce;
        let allocation = self.live_allocation_mut(key, now)?;
        if constant_eq(allocation.credentials.nonce(), supplied_nonce) {
            return Err(StateError::StaleNonce);
        }
        Ok(StaleNonceChallenge {
            realm: allocation.credentials.realm.clone(),
            nonce: allocation.credentials.nonce.clone(),
            integrity_key: allocation.credentials.integrity_key.clone(),
        })
    }

    fn authenticate_request_inner(
        &mut self,
        key: &UdpTuple,
        encoded_request: &[u8],
        now: u64,
        allow_stale_nonce: bool,
    ) -> Result<AuthenticatedRequest, StateError> {
        let integrity_key = {
            let allocation = self.live_allocation_mut(key, now)?;
            Zeroizing::new(*allocation.credentials.integrity_key)
        };
        let verified = wire::verify_integrity(encoded_request, integrity_key.as_ref())
            .map_err(|_| StateError::Integrity)?;
        if verified.message().header.class != wire::Class::Request {
            return Err(StateError::WrongRequestMethod);
        }
        let request_credentials = request_credentials(verified.message())?;
        let state_instance = self.state_instance;
        let allocation = self.live_allocation_mut(key, now)?;
        if !constant_eq(
            allocation.credentials.username(),
            request_credentials.username,
        ) || !constant_eq(allocation.credentials.realm(), request_credentials.realm)
        {
            return Err(StateError::WrongCredentials);
        }
        if !allow_stale_nonce
            && !constant_eq(allocation.credentials.nonce(), request_credentials.nonce)
        {
            return Err(StateError::StaleNonce);
        }
        Ok(AuthenticatedRequest {
            state_instance,
            tuple: *key,
            allocation_incarnation: allocation.incarnation,
            credential_generation: allocation.credential_generation,
            verified,
        })
    }

    /// Rotate credentials for callers that already hold an authenticated
    /// request using the current nonce. Network stale-nonce recovery uses the
    /// idempotent [`RelayState::stale_nonce_challenge`] path instead.
    pub fn rotate_nonce(
        &mut self,
        request: &AuthenticatedRequest,
        nonce: Vec<u8>,
        now: u64,
    ) -> Result<(), StateError> {
        validate_credential_part(&nonce)?;
        let allocation = self.authorized_allocation_mut(request, now, request.method())?;
        let next_generation = allocation
            .credential_generation
            .checked_add(1)
            .ok_or(StateError::TimeOverflow)?;
        allocation.credentials.nonce = Zeroizing::new(nonce);
        allocation.credential_generation = next_generation;
        Ok(())
    }

    pub fn refresh(
        &mut self,
        request: &AuthenticatedRequest,
        now: u64,
    ) -> Result<Option<AllocationInfo>, StateError> {
        let key = request.tuple;
        self.authorized_allocation_mut(request, now, wire::Method::Refresh)?;
        let requested_lifetime = request_lifetime(request.message())?;
        if requested_lifetime == 0 {
            self.allocations
                .remove(&key)
                .ok_or(StateError::MissingAllocation)?;
            return Ok(None);
        }
        let lifetime = desired_lifetime(Some(requested_lifetime));
        let expires_at = now.checked_add(lifetime).ok_or(StateError::TimeOverflow)?;
        let allocation = self.authorized_allocation_mut(request, now, wire::Method::Refresh)?;
        allocation.expires_at = expires_at;
        Ok(Some(AllocationInfo {
            relayed_address: allocation.relayed_address,
            expires_at,
        }))
    }

    /// Atomically validates and installs every peer IP from one
    /// CreatePermission transaction.
    pub fn create_permissions(
        &mut self,
        request: &AuthenticatedRequest,
        now: u64,
    ) -> Result<(), StateError> {
        let peers = request_peers(request.message())?;
        if peers.is_empty() || peers.len() > self.quota.max_permissions_per_allocation {
            return Err(StateError::PermissionQuota);
        }
        let relayed_address = self
            .authorized_allocation_mut(request, now, wire::Method::CreatePermission)?
            .relayed_address;
        let mut unique_ips = HashSet::with_capacity(peers.len());
        for peer in &peers {
            validate_permission_ip(self.policy, relayed_address, peer.ip())?;
            unique_ips.insert(peer.ip());
        }
        let expires_at = now
            .checked_add(PERMISSION_LIFETIME)
            .ok_or(StateError::TimeOverflow)?;
        let max_permissions = self.quota.max_permissions_per_allocation;
        let allocation =
            self.authorized_allocation_mut(request, now, wire::Method::CreatePermission)?;
        let new_count = unique_ips
            .iter()
            .filter(|ip| !allocation.permissions.contains_key(ip))
            .count();
        if allocation.permissions.len().saturating_add(new_count) > max_permissions {
            return Err(StateError::PermissionQuota);
        }
        for ip in unique_ips {
            allocation.permissions.insert(ip, Permission { expires_at });
        }
        Ok(())
    }

    pub fn bind_channel(
        &mut self,
        request: &AuthenticatedRequest,
        now: u64,
    ) -> Result<(), StateError> {
        let (channel, peer) = request_channel(request.message())?;
        if !(wire::CHANNEL_MIN..=wire::CHANNEL_MAX).contains(&channel.0) {
            return Err(StateError::InvalidChannel);
        }
        let relayed_address = self
            .authorized_allocation_mut(request, now, wire::Method::ChannelBind)?
            .relayed_address;
        validate_peer(self.policy, relayed_address, peer)?;
        let permission_expires = now
            .checked_add(PERMISSION_LIFETIME)
            .ok_or(StateError::TimeOverflow)?;
        let channel_expires = now
            .checked_add(CHANNEL_LIFETIME)
            .ok_or(StateError::TimeOverflow)?;
        let quarantine_until = channel_expires
            .checked_add(QUARANTINE_LIFETIME)
            .ok_or(StateError::TimeOverflow)?;
        let max_permissions = self.quota.max_permissions_per_allocation;
        let max_channels = self.quota.max_channels_per_allocation;
        let allocation = self.authorized_allocation_mut(request, now, wire::Method::ChannelBind)?;
        if allocation.expired_bindings.iter().any(|expired| {
            now < expired.quarantine_until
                && ((expired.channel == channel && expired.peer != peer)
                    || (expired.peer == peer && expired.channel != channel))
        }) {
            return Err(StateError::ChannelQuarantined);
        }
        if allocation
            .channels
            .get(&channel)
            .is_some_and(|binding| binding.peer != peer)
            || allocation
                .channels
                .iter()
                .any(|(bound_channel, binding)| *bound_channel != channel && binding.peer == peer)
        {
            return Err(StateError::ChannelCollision);
        }
        let new_channel = !allocation.channels.contains_key(&channel);
        if new_channel && allocation.channels.len() >= max_channels {
            return Err(StateError::ChannelQuota);
        }
        let new_permission = !allocation.permissions.contains_key(&peer.ip());
        if new_permission && allocation.permissions.len() >= max_permissions {
            return Err(StateError::PermissionQuota);
        }
        allocation.permissions.insert(
            peer.ip(),
            Permission {
                expires_at: permission_expires,
            },
        );
        allocation.channels.insert(
            channel,
            ChannelBinding {
                peer,
                expires_at: channel_expires,
                quarantine_until,
            },
        );
        Ok(())
    }

    pub fn authorize_send(
        &mut self,
        key: &UdpTuple,
        peer: SocketAddr,
        payload_bytes: u64,
        now: u64,
    ) -> Result<(), StateError> {
        let relayed_address = self.live_allocation_mut(key, now)?.relayed_address;
        validate_peer(self.policy, relayed_address, peer)?;
        self.require_permission_and_account(key, peer, payload_bytes, now)
    }

    pub fn authorize_channel_data(
        &mut self,
        key: &UdpTuple,
        channel: ChannelNumber,
        payload_bytes: u64,
        now: u64,
    ) -> Result<SocketAddr, StateError> {
        let peer = self
            .live_allocation_mut(key, now)?
            .channels
            .get(&channel)
            .ok_or(StateError::ChannelNotBound)?
            .peer;
        self.require_permission_and_account(key, peer, payload_bytes, now)?;
        Ok(peer)
    }

    pub fn route_peer_datagram(
        &mut self,
        key: &UdpTuple,
        peer: SocketAddr,
        payload_bytes: u64,
        now: u64,
    ) -> Result<DeliveryRoute, StateError> {
        let relayed_address = self.live_allocation_mut(key, now)?.relayed_address;
        validate_permission_ip(self.policy, relayed_address, peer.ip())?;
        self.require_permission_and_account(key, peer, payload_bytes, now)?;
        let route = self
            .live_allocation_mut(key, now)?
            .channels
            .iter()
            .find(|(_, binding)| binding.peer == peer)
            .map_or(DeliveryRoute::DataIndication, |(channel, _)| {
                DeliveryRoute::ChannelData(*channel)
            });
        Ok(route)
    }

    pub fn allocation_info(
        &mut self,
        key: &UdpTuple,
        now: u64,
    ) -> Result<AllocationInfo, StateError> {
        let allocation = self.live_allocation_mut(key, now)?;
        Ok(AllocationInfo {
            relayed_address: allocation.relayed_address,
            expires_at: allocation.expires_at,
        })
    }

    pub fn counters(&mut self, key: &UdpTuple, now: u64) -> Result<TrafficCounters, StateError> {
        Ok(self.live_allocation_mut(key, now)?.counters)
    }

    pub fn cleanup(&mut self, now: u64) {
        self.allocations
            .retain(|_, allocation| now < allocation.expires_at);
    }

    fn live_allocation_mut(
        &mut self,
        key: &UdpTuple,
        now: u64,
    ) -> Result<&mut Allocation, StateError> {
        let allocation = self
            .allocations
            .get_mut(key)
            .ok_or(StateError::MissingAllocation)?;
        if now >= allocation.expires_at {
            return Err(StateError::ExpiredAllocation);
        }
        allocation.prune_children(now);
        Ok(allocation)
    }

    fn authorized_allocation_mut(
        &mut self,
        request: &AuthenticatedRequest,
        now: u64,
        expected_method: wire::Method,
    ) -> Result<&mut Allocation, StateError> {
        if request.method() != expected_method {
            return Err(StateError::WrongRequestMethod);
        }
        if request.state_instance != self.state_instance {
            return Err(StateError::StaleAuthorization);
        }
        let allocation = self.live_allocation_mut(&request.tuple, now)?;
        if allocation.incarnation != request.allocation_incarnation {
            return Err(StateError::StaleAuthorization);
        }
        if allocation.credential_generation != request.credential_generation {
            return Err(StateError::StaleNonce);
        }
        Ok(allocation)
    }

    fn require_permission_and_account(
        &mut self,
        key: &UdpTuple,
        peer: SocketAddr,
        payload_bytes: u64,
        now: u64,
    ) -> Result<(), StateError> {
        let max_packets = self.quota.max_packets_per_allocation;
        let max_bytes = self.quota.max_payload_bytes_per_allocation;
        let allocation = self.live_allocation_mut(key, now)?;
        if !allocation.permissions.contains_key(&peer.ip()) {
            return Err(StateError::NotPermitted);
        }
        let packets = allocation
            .counters
            .packets
            .checked_add(1)
            .ok_or(StateError::TrafficQuota)?;
        let payload_bytes = allocation
            .counters
            .payload_bytes
            .checked_add(payload_bytes)
            .ok_or(StateError::TrafficQuota)?;
        if packets > max_packets || payload_bytes > max_bytes {
            return Err(StateError::TrafficQuota);
        }
        allocation.counters = TrafficCounters {
            packets,
            payload_bytes,
        };
        Ok(())
    }
}

fn desired_lifetime(_requested: Option<u64>) -> u64 {
    // RFC 8656 ignores Allocate/Refresh values below the default, and this
    // product profile caps the server maximum at that same 600-second value.
    DEFAULT_ALLOCATION_LIFETIME.min(MAX_ALLOCATION_LIFETIME)
}

struct RequestCredentials<'a> {
    username: &'a [u8],
    realm: &'a [u8],
    nonce: &'a [u8],
}

fn request_credentials(message: &wire::Message) -> Result<RequestCredentials<'_>, StateError> {
    let mut username = None;
    let mut realm = None;
    let mut nonce = None;
    for attribute in &message.attributes {
        match attribute {
            wire::Attribute::Username(value) => username = Some(value.as_slice()),
            wire::Attribute::Realm(value) => realm = Some(value.as_slice()),
            wire::Attribute::Nonce(value) => nonce = Some(value.as_slice()),
            _ => {}
        }
    }
    match (username, realm, nonce) {
        (Some(username), Some(realm), Some(nonce)) => Ok(RequestCredentials {
            username,
            realm,
            nonce,
        }),
        _ => Err(StateError::WrongCredentials),
    }
}

fn request_lifetime(message: &wire::Message) -> Result<u64, StateError> {
    if message.header.method != wire::Method::Refresh {
        return Err(StateError::WrongRequestMethod);
    }
    Ok(message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            wire::Attribute::Lifetime(seconds) => Some(u64::from(*seconds)),
            _ => None,
        })
        .unwrap_or(DEFAULT_ALLOCATION_LIFETIME))
}

fn request_peers(message: &wire::Message) -> Result<Vec<SocketAddr>, StateError> {
    if message.header.method != wire::Method::CreatePermission {
        return Err(StateError::WrongRequestMethod);
    }
    let peers = message
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            wire::Attribute::XorPeerAddress(peer) => Some(*peer),
            _ => None,
        })
        .collect::<Vec<_>>();
    if peers.is_empty() {
        return Err(StateError::InvalidPeer);
    }
    Ok(peers)
}

fn request_channel(message: &wire::Message) -> Result<(ChannelNumber, SocketAddr), StateError> {
    if message.header.method != wire::Method::ChannelBind {
        return Err(StateError::WrongRequestMethod);
    }
    let mut channel = None;
    let mut peer = None;
    for attribute in &message.attributes {
        match attribute {
            wire::Attribute::ChannelNumber(value) => channel = Some(ChannelNumber(*value)),
            wire::Attribute::XorPeerAddress(value) => peer = Some(*value),
            _ => {}
        }
    }
    match (channel, peer) {
        (Some(channel), Some(peer)) => Ok((channel, peer)),
        _ => Err(StateError::InvalidChannel),
    }
}

fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.ct_eq(right).unwrap_u8() == 1
}

fn validate_credential_part(value: &[u8]) -> Result<(), StateError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES || std::str::from_utf8(value).is_err()
    {
        return Err(StateError::InvalidCredentials);
    }
    Ok(())
}

fn validate_tuple(key: UdpTuple) -> Result<(), StateError> {
    if !usable_address(key.client)
        || !usable_address(key.server)
        || key.client.is_ipv4() != key.server.is_ipv4()
        || key.client == key.server
    {
        return Err(StateError::InvalidTuple);
    }
    Ok(())
}

fn validate_relay(
    policy: PeerPolicy,
    key: UdpTuple,
    relayed_address: SocketAddr,
) -> Result<(), StateError> {
    if !usable_address(relayed_address)
        || relayed_address.is_ipv4() != key.server.is_ipv4()
        || (relayed_address.is_ipv4() && !policy.allow_ipv4)
        || (relayed_address.is_ipv6() && !policy.allow_ipv6)
        || (relayed_address.ip().is_loopback() && !policy.allow_loopback_lab)
    {
        return Err(StateError::InvalidRelay);
    }
    Ok(())
}

fn validate_peer(
    policy: PeerPolicy,
    relayed_address: SocketAddr,
    peer: SocketAddr,
) -> Result<(), StateError> {
    if !usable_address(peer)
        || peer.is_ipv4() != relayed_address.is_ipv4()
        || (peer.is_ipv4() && !policy.allow_ipv4)
        || (peer.is_ipv6() && !policy.allow_ipv6)
        || (peer.ip().is_loopback() && !policy.allow_loopback_lab)
        || (peer.port() < 1024 && !policy.allow_well_known)
    {
        return Err(StateError::InvalidPeer);
    }
    Ok(())
}

fn validate_permission_ip(
    policy: PeerPolicy,
    relayed_address: SocketAddr,
    peer_ip: IpAddr,
) -> Result<(), StateError> {
    if peer_ip.is_unspecified()
        || peer_ip.is_multicast()
        || matches!(peer_ip, IpAddr::V4(ip) if ip.is_broadcast())
        || peer_ip.is_ipv4() != relayed_address.is_ipv4()
        || (peer_ip.is_ipv4() && !policy.allow_ipv4)
        || (peer_ip.is_ipv6() && !policy.allow_ipv6)
        || (peer_ip.is_loopback() && !policy.allow_loopback_lab)
    {
        return Err(StateError::InvalidPeer);
    }
    Ok(())
}

fn usable_address(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
}
