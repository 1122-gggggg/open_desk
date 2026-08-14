//! Pinned-device and explicit host-approval policy.
//!
//! This module owns pairing, pinning, verified 1-RTT connection admission,
//! per-session capability grants, expiry, and revocation. Transport code must
//! derive a [`DeviceFingerprint`] from an authenticated device public key and
//! register a verified 1-RTT connection with a locally generated [`SessionId`].
//! Host access policy issues a monotonic local [`AuthorizationEpoch`], and
//! capability requests must reference the active [`ConnectionContext`].

use core::fmt;

/// Maximum number of device public-key fingerprints retained by one host.
pub const MAX_PINNED_DEVICES: usize = 64;

/// Maximum allowable duration for a pairing invitation (5 minutes).
pub const MAX_PAIRING_TTL_NS: u64 = 5 * 60 * 1_000_000_000;

/// Maximum allowable duration for an approved session grant (24 hours).
pub const MAX_SESSION_TTL_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

const CAPABILITY_MASK: u8 = Capability::View as u8 | Capability::Input as u8;

fn random_bytes<const N: usize>() -> Result<[u8; N], AccessError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| AccessError::RngFailure)?;
    Ok(buf)
}

fn generate_session_id() -> Result<SessionId, AccessError> {
    loop {
        let bytes = random_bytes::<8>()?;
        let val = u64::from_le_bytes(bytes);
        if val != 0 {
            return Ok(SessionId(val));
        }
    }
}

/// Fixed fingerprint of an authenticated device public key (e.g. SHA-256 SPKI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceFingerprint([u8; 32]);

impl DeviceFingerprint {
    /// Creates a validated device fingerprint from raw bytes. All-zero values
    /// are rejected.
    pub fn new(bytes: [u8; 32]) -> Result<Self, AccessError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(AccessError::InvalidFingerprint);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Opaque locally generated transport session identifier matching the 1-RTT
/// control header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u64);

impl SessionId {
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Monotonic local authorization epoch issued by host policy upon admitting
/// a verified 1-RTT connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuthorizationEpoch(u32);

impl AuthorizationEpoch {
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// A host-grantable capability. Deferred channels have no capability here and
/// therefore cannot be authorized by this v0.1 policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Capability {
    View = 1,
    Input = 2,
}

/// Validated set of requested or host-approved capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapabilitySet(u8);

impl CapabilitySet {
    /// Constructs a capability set from raw bits. Empty sets or unknown bits
    /// are rejected.
    pub fn from_bits(bits: u8) -> Result<Self, AccessError> {
        if bits == 0 || bits & !CAPABILITY_MASK != 0 {
            return Err(AccessError::InvalidCapabilities);
        }
        Ok(Self(bits))
    }

    #[must_use]
    pub const fn view_only() -> Self {
        Self(Capability::View as u8)
    }

    #[must_use]
    pub const fn view_and_input() -> Self {
        Self(Capability::View as u8 | Capability::Input as u8)
    }

    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability as u8 != 0
    }

    #[must_use]
    pub const fn is_subset_of(self, requested: Self) -> bool {
        self.0 & !requested.0 == 0
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Opaque binding representing an active verified 1-RTT transport connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionContext {
    device: DeviceFingerprint,
    session_id: SessionId,
    authorization_epoch: AuthorizationEpoch,
}

impl ConnectionContext {
    const fn new(
        device: DeviceFingerprint,
        session_id: SessionId,
        authorization_epoch: AuthorizationEpoch,
    ) -> Self {
        Self {
            device,
            session_id,
            authorization_epoch,
        }
    }

    #[must_use]
    pub const fn device(self) -> DeviceFingerprint {
        self.device
    }

    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn authorization_epoch(self) -> AuthorizationEpoch {
        self.authorization_epoch
    }
}

/// Opaque handle returned with a pairing invitation, required to cancel the specific pairing flow.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairingCancellationHandle {
    device: DeviceFingerprint,
    generation: u64,
    nonce: [u8; 16],
}

impl fmt::Debug for PairingCancellationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCancellationHandle")
            .field("device", &self.device)
            .field("generation", &self.generation)
            .field("nonce", &"<redacted>")
            .finish()
    }
}

impl PairingCancellationHandle {
    #[must_use]
    pub const fn device(self) -> DeviceFingerprint {
        self.device
    }
}

/// Out-of-band pairing invitation carrying CSPRNG secret entropy and bounded TTL.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PairingInvitation {
    device: DeviceFingerprint,
    secret: [u8; 32],
    cancellation_handle: PairingCancellationHandle,
    expires_at_ns: u64,
}

impl fmt::Debug for PairingInvitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingInvitation")
            .field("device", &self.device)
            .field("secret", &"<redacted>")
            .field("cancellation_handle", &self.cancellation_handle)
            .field("expires_at_ns", &self.expires_at_ns)
            .finish()
    }
}

impl PairingInvitation {
    #[must_use]
    pub const fn device(self) -> DeviceFingerprint {
        self.device
    }

    #[must_use]
    pub const fn secret(self) -> [u8; 32] {
        self.secret
    }

    #[must_use]
    pub const fn cancellation_handle(self) -> PairingCancellationHandle {
        self.cancellation_handle
    }

    #[must_use]
    pub const fn expires_at_ns(self) -> u64 {
        self.expires_at_ns
    }
}

/// Pairing proof presented by the client over an authenticated channel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PairingProof {
    device: DeviceFingerprint,
    secret: [u8; 32],
}

impl fmt::Debug for PairingProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingProof")
            .field("device", &self.device)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl PairingProof {
    /// Creates a pairing proof from device fingerprint and secret. All-zero secrets are rejected.
    pub fn new(device: DeviceFingerprint, secret: [u8; 32]) -> Result<Self, AccessError> {
        if secret.iter().all(|byte| *byte == 0) {
            return Err(AccessError::InvalidPairingSecret);
        }
        Ok(Self { device, secret })
    }

    #[must_use]
    pub const fn from_invitation(invitation: PairingInvitation) -> Self {
        Self {
            device: invitation.device,
            secret: invitation.secret,
        }
    }

    #[must_use]
    pub const fn device(self) -> DeviceFingerprint {
        self.device
    }

    #[must_use]
    pub const fn secret(self) -> [u8; 32] {
        self.secret
    }
}

/// Opaque handle returned upon matching confirmation, required for explicit host approval.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairingApprovalHandle {
    device: DeviceFingerprint,
    generation: u64,
    nonce: [u8; 16],
}

impl fmt::Debug for PairingApprovalHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingApprovalHandle")
            .field("device", &self.device)
            .field("generation", &self.generation)
            .field("nonce", &"<redacted>")
            .finish()
    }
}

impl PairingApprovalHandle {
    #[must_use]
    pub const fn device(self) -> DeviceFingerprint {
        self.device
    }
}

/// Opaque handle representing a pending capability request from an active connection.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionRequestHandle {
    device: DeviceFingerprint,
    session_id: SessionId,
    authorization_epoch: AuthorizationEpoch,
    requested_capabilities: CapabilitySet,
    generation: u64,
    nonce: [u8; 16],
}

impl fmt::Debug for SessionRequestHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRequestHandle")
            .field("device", &self.device)
            .field("session_id", &self.session_id)
            .field("authorization_epoch", &self.authorization_epoch)
            .field("requested_capabilities", &self.requested_capabilities)
            .field("generation", &self.generation)
            .field("nonce", &"<redacted>")
            .finish()
    }
}

impl SessionRequestHandle {
    #[must_use]
    pub const fn device(self) -> DeviceFingerprint {
        self.device
    }

    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn authorization_epoch(self) -> AuthorizationEpoch {
        self.authorization_epoch
    }

    #[must_use]
    pub const fn requested_capabilities(self) -> CapabilitySet {
        self.requested_capabilities
    }
}

/// Short-lived host authorization bound to one pinned device, session ID, and
/// local authorization epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionAuthorization {
    device: DeviceFingerprint,
    session_id: SessionId,
    authorization_epoch: AuthorizationEpoch,
    capabilities: CapabilitySet,
    expires_at_ns: u64,
}

impl SessionAuthorization {
    #[must_use]
    pub const fn device(self) -> DeviceFingerprint {
        self.device
    }

    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn authorization_epoch(self) -> AuthorizationEpoch {
        self.authorization_epoch
    }

    #[must_use]
    pub const fn capabilities(self) -> CapabilitySet {
        self.capabilities
    }

    #[must_use]
    pub const fn expires_at_ns(self) -> u64 {
        self.expires_at_ns
    }

    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.capabilities.contains(capability)
    }

    #[must_use]
    pub const fn is_expired(self, now_ns: u64) -> bool {
        self.expires_at_ns <= now_ns
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PendingPairing {
    device: DeviceFingerprint,
    secret: [u8; 32],
    cancellation_handle: PairingCancellationHandle,
    expires_at_ns: u64,
    generation: u64,
}

impl fmt::Debug for PendingPairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPairing")
            .field("device", &self.device)
            .field("secret", &"<redacted>")
            .field("cancellation_handle", &self.cancellation_handle)
            .field("expires_at_ns", &self.expires_at_ns)
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PendingApproval {
    handle: PairingApprovalHandle,
    cancellation_handle: PairingCancellationHandle,
    expires_at_ns: u64,
}

impl fmt::Debug for PendingApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingApproval")
            .field("handle", &self.handle)
            .field("cancellation_handle", &self.cancellation_handle)
            .field("expires_at_ns", &self.expires_at_ns)
            .finish()
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PairingState {
    #[default]
    Idle,
    AwaitingProof(PendingPairing),
    AwaitingHostApproval(PendingApproval),
}

impl fmt::Debug for PairingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => f.write_str("Idle"),
            Self::AwaitingProof(pending) => f.debug_tuple("AwaitingProof").field(pending).finish(),
            Self::AwaitingHostApproval(pending) => f
                .debug_tuple("AwaitingHostApproval")
                .field(pending)
                .finish(),
        }
    }
}

/// Bounded host-side policy for pairing, pinning, verified connection
/// admission, explicit approval, expiry, and immediate revocation.
#[derive(Debug)]
pub struct HostAccessPolicy {
    pinned_devices: Vec<DeviceFingerprint>,
    next_epoch: u32,
    next_generation: u64,
    pairing: PairingState,
    active_connection: Option<ConnectionContext>,
    pending_session: Option<SessionRequestHandle>,
    active_session: Option<SessionAuthorization>,
}

impl Default for HostAccessPolicy {
    fn default() -> Self {
        Self {
            pinned_devices: Vec::new(),
            next_epoch: 1,
            next_generation: 1,
            pairing: PairingState::Idle,
            active_connection: None,
            pending_session: None,
            active_session: None,
        }
    }
}

impl HostAccessPolicy {
    /// Creates a policy pre-populated with known pinned device fingerprints.
    pub fn from_pinned_devices(
        devices: impl IntoIterator<Item = DeviceFingerprint>,
    ) -> Result<Self, AccessError> {
        let mut policy = Self::default();
        for device in devices {
            policy.pin(device)?;
        }
        Ok(policy)
    }

    #[must_use]
    pub fn pinned_devices(&self) -> impl ExactSizeIterator<Item = DeviceFingerprint> + '_ {
        self.pinned_devices.iter().copied()
    }

    #[must_use]
    pub fn is_pinned(&self, device: DeviceFingerprint) -> bool {
        self.pinned_devices.contains(&device)
    }

    /// Starts a pairing flow for the exact device fingerprint shown in the
    /// local QR/out-of-band confirmation UI, creating a CSPRNG-backed secret and bounded deadline.
    pub fn begin_pairing(
        &mut self,
        device: DeviceFingerprint,
        ttl_ns: u64,
        now_ns: u64,
    ) -> Result<PairingInvitation, AccessError> {
        self.expire_pairing(now_ns);
        self.expire_active(now_ns);
        if self.is_pinned(device) {
            return Err(AccessError::DeviceAlreadyPinned);
        }
        if self.pinned_devices.len() >= MAX_PINNED_DEVICES {
            return Err(AccessError::PinnedDeviceLimit);
        }
        if self.pairing != PairingState::Idle {
            return Err(AccessError::PairingInProgress);
        }
        if self.pending_session.is_some()
            || self.active_session.is_some()
            || self.active_connection.is_some()
        {
            return Err(AccessError::SessionInProgress);
        }
        if ttl_ns == 0 || ttl_ns > MAX_PAIRING_TTL_NS {
            return Err(AccessError::InvalidTtl);
        }
        let expires_at_ns = now_ns
            .checked_add(ttl_ns)
            .ok_or(AccessError::InvalidExpiry)?;
        let secret = random_bytes::<32>()?;
        let cancellation_nonce = random_bytes::<16>()?;
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(AccessError::InvalidAuthorizationEpoch)?;

        let cancellation_handle = PairingCancellationHandle {
            device,
            generation,
            nonce: cancellation_nonce,
        };

        let pending = PendingPairing {
            device,
            secret,
            cancellation_handle,
            expires_at_ns,
            generation,
        };
        self.pairing = PairingState::AwaitingProof(pending);
        Ok(PairingInvitation {
            device,
            secret,
            cancellation_handle,
            expires_at_ns,
        })
    }

    /// Consumes the pending invitation and verifies the pairing proof.
    /// On any attempt, the invitation is atomically consumed. Returns an opaque
    /// approval handle only upon matching non-expired proof.
    pub fn confirm_pairing(
        &mut self,
        proof: PairingProof,
        now_ns: u64,
    ) -> Result<PairingApprovalHandle, AccessError> {
        match self.pairing {
            PairingState::AwaitingProof(pending) => {
                self.pairing = PairingState::Idle;
                if pending.expires_at_ns <= now_ns {
                    return Err(AccessError::PairingExpired);
                }
                if proof.device != pending.device || proof.secret != pending.secret {
                    return Err(AccessError::PairingMismatch);
                }
                let nonce = random_bytes::<16>()?;
                let handle = PairingApprovalHandle {
                    device: pending.device,
                    generation: pending.generation,
                    nonce,
                };
                self.pairing = PairingState::AwaitingHostApproval(PendingApproval {
                    handle,
                    cancellation_handle: pending.cancellation_handle,
                    expires_at_ns: pending.expires_at_ns,
                });
                Ok(handle)
            }
            PairingState::AwaitingHostApproval(_) => Err(AccessError::PairingAlreadyConfirmed),
            PairingState::Idle => Err(AccessError::NoPendingPairing),
        }
    }

    /// Pins the device only after the local host UI explicitly approves the exact
    /// pending handle and the approval deadline has not passed.
    pub fn approve_pairing(
        &mut self,
        handle: PairingApprovalHandle,
        now_ns: u64,
    ) -> Result<(), AccessError> {
        match self.pairing {
            PairingState::AwaitingHostApproval(pending) => {
                if pending.handle != handle {
                    return Err(AccessError::StalePairingHandle);
                }
                if pending.expires_at_ns <= now_ns {
                    self.pairing = PairingState::Idle;
                    return Err(AccessError::PairingExpired);
                }
                self.pairing = PairingState::Idle;
                self.pin(handle.device)?;
                Ok(())
            }
            PairingState::AwaitingProof(_) => Err(AccessError::PairingNotConfirmed),
            PairingState::Idle => Err(AccessError::NoPendingPairing),
        }
    }

    /// Rejects the current pairing request matching the exact handle without altering existing pins.
    pub fn reject_pairing(&mut self, handle: PairingApprovalHandle) -> Result<(), AccessError> {
        match self.pairing {
            PairingState::AwaitingHostApproval(pending) => {
                if pending.handle != handle {
                    return Err(AccessError::StalePairingHandle);
                }
                self.pairing = PairingState::Idle;
                Ok(())
            }
            PairingState::AwaitingProof(_) => Err(AccessError::PairingNotConfirmed),
            PairingState::Idle => Err(AccessError::NoPendingPairing),
        }
    }

    /// Cancels an active pairing attempt in progress if the provided cancellation handle matches exactly.
    pub fn cancel_pairing(&mut self, handle: PairingCancellationHandle) -> Result<(), AccessError> {
        match self.pairing {
            PairingState::AwaitingProof(pending) => {
                if pending.cancellation_handle != handle {
                    return Err(AccessError::StalePairingHandle);
                }
                self.pairing = PairingState::Idle;
                Ok(())
            }
            PairingState::AwaitingHostApproval(pending) => {
                if pending.cancellation_handle != handle {
                    return Err(AccessError::StalePairingHandle);
                }
                self.pairing = PairingState::Idle;
                Ok(())
            }
            PairingState::Idle => Err(AccessError::NoPendingPairing),
        }
    }

    /// Clears any expired pairing flow (awaiting proof or awaiting host approval),
    /// returning `true` if state was transitioned to idle.
    pub fn expire_pairing(&mut self, now_ns: u64) -> bool {
        match self.pairing {
            PairingState::AwaitingProof(pending) if pending.expires_at_ns <= now_ns => {
                self.pairing = PairingState::Idle;
                true
            }
            PairingState::AwaitingHostApproval(pending) if pending.expires_at_ns <= now_ns => {
                self.pairing = PairingState::Idle;
                true
            }
            _ => false,
        }
    }

    /// Admits a fresh 1-RTT connection from a pinned device after verified mutual
    /// authentication and key confirmation. Invalidation of previous sessions is atomic,
    /// and a fresh unpredictable session ID and monotonic authorization epoch are assigned.
    ///
    /// # Preconditions
    /// The caller MUST ensure that mutual TLS 1.3 authentication over full 1-RTT completed
    /// successfully without 0-RTT resumption, and that the peer certificate matches `device`.
    pub fn register_verified_one_rtt_connection(
        &mut self,
        device: DeviceFingerprint,
        now_ns: u64,
    ) -> Result<ConnectionContext, AccessError> {
        self.expire_pairing(now_ns);
        self.expire_active(now_ns);
        if !self.is_pinned(device) {
            return Err(AccessError::DeviceNotPinned);
        }
        if self.pairing != PairingState::Idle {
            return Err(AccessError::PairingInProgress);
        }

        let session_id = generate_session_id()?;
        let epoch_val = self.next_epoch;
        self.next_epoch = self
            .next_epoch
            .checked_add(1)
            .ok_or(AccessError::InvalidAuthorizationEpoch)?;
        let epoch = AuthorizationEpoch(epoch_val);

        self.pending_session = None;
        self.active_session = None;

        let context = ConnectionContext::new(device, session_id, epoch);
        self.active_connection = Some(context);
        Ok(context)
    }

    /// Explicitly closes the connection identified by `context`, revoking
    /// any associated active session and clearing connection state.
    pub fn close_connection(&mut self, context: ConnectionContext) -> Option<SessionAuthorization> {
        if self.active_connection == Some(context) {
            self.active_connection = None;
            self.pending_session = None;
            self.active_session.take()
        } else {
            None
        }
    }

    #[must_use]
    pub const fn active_connection(&self) -> Option<ConnectionContext> {
        self.active_connection
    }

    /// Admits a capability request only for the currently active, verified
    /// connection context from a pinned device, returning an opaque request handle.
    pub fn request_session(
        &mut self,
        context: ConnectionContext,
        requested_capabilities: CapabilitySet,
    ) -> Result<SessionRequestHandle, AccessError> {
        if self.pairing != PairingState::Idle {
            return Err(AccessError::PairingInProgress);
        }
        if !self.is_pinned(context.device) {
            return Err(AccessError::DeviceNotPinned);
        }
        let Some(active_conn) = self.active_connection else {
            return Err(AccessError::StaleConnectionContext);
        };
        if active_conn != context {
            return Err(AccessError::StaleConnectionContext);
        }
        if self.active_session.is_some() {
            return Err(AccessError::ActiveSessionExists);
        }
        if self.pending_session.is_some() {
            return Err(AccessError::SessionApprovalPending);
        }
        if !requested_capabilities.contains(Capability::View) {
            return Err(AccessError::ViewCapabilityRequired);
        }

        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(AccessError::InvalidAuthorizationEpoch)?;

        let nonce = random_bytes::<16>()?;
        let handle = SessionRequestHandle {
            device: context.device,
            session_id: context.session_id,
            authorization_epoch: context.authorization_epoch,
            requested_capabilities,
            generation,
            nonce,
        };
        self.pending_session = Some(handle);
        Ok(handle)
    }

    /// Creates an active authorization after explicit local host approval. The
    /// host chooses the duration (bounded by [`MAX_SESSION_TTL_NS`]) and may grant
    /// a subset of requested capabilities, but never more.
    pub fn approve_session(
        &mut self,
        handle: SessionRequestHandle,
        capabilities: CapabilitySet,
        ttl_ns: u64,
        now_ns: u64,
    ) -> Result<SessionAuthorization, AccessError> {
        self.expire_active(now_ns);
        if ttl_ns == 0 || ttl_ns > MAX_SESSION_TTL_NS {
            return Err(AccessError::InvalidTtl);
        }
        let expires_at_ns = now_ns
            .checked_add(ttl_ns)
            .ok_or(AccessError::InvalidExpiry)?;

        let pending = self.pending_session.ok_or(AccessError::NoPendingSession)?;
        if pending != handle {
            return Err(AccessError::StaleSessionHandle);
        }
        if !self.is_pinned(pending.device) {
            self.pending_session = None;
            return Err(AccessError::DeviceNotPinned);
        }
        let Some(active_conn) = self.active_connection else {
            self.pending_session = None;
            return Err(AccessError::StaleConnectionContext);
        };
        if active_conn.device != pending.device
            || active_conn.session_id != pending.session_id
            || active_conn.authorization_epoch != pending.authorization_epoch
        {
            self.pending_session = None;
            return Err(AccessError::StaleConnectionContext);
        }
        if !capabilities.contains(Capability::View)
            || !capabilities.is_subset_of(pending.requested_capabilities)
        {
            return Err(AccessError::ApprovalExceedsRequest);
        }

        let authorization = SessionAuthorization {
            device: pending.device,
            session_id: pending.session_id,
            authorization_epoch: pending.authorization_epoch,
            capabilities,
            expires_at_ns,
        };
        self.pending_session = None;
        self.active_session = Some(authorization);
        Ok(authorization)
    }

    /// Rejects the pending session request matching the handle.
    pub fn reject_session(&mut self, handle: SessionRequestHandle) -> Result<(), AccessError> {
        let pending = self.pending_session.ok_or(AccessError::NoPendingSession)?;
        if pending != handle {
            return Err(AccessError::StaleSessionHandle);
        }
        self.pending_session = None;
        Ok(())
    }

    #[must_use]
    pub const fn pending_request(&self) -> Option<SessionRequestHandle> {
        self.pending_session
    }

    /// Immediately revokes the active session and invalidates the connection context and authorization epoch.
    pub fn revoke_active(&mut self) -> Option<SessionAuthorization> {
        self.pending_session = None;
        self.active_connection = None;
        self.active_session.take()
    }

    /// Removes a pin, cancels pending pairings/sessions, clears connection
    /// state, and revokes any active session for that device.
    pub fn revoke_device(
        &mut self,
        device: DeviceFingerprint,
    ) -> Result<Option<SessionAuthorization>, AccessError> {
        let index = self
            .pinned_devices
            .iter()
            .position(|pinned| *pinned == device)
            .ok_or(AccessError::DeviceNotPinned)?;
        self.pinned_devices.remove(index);

        if self
            .active_connection
            .is_some_and(|conn| conn.device == device)
        {
            self.active_connection = None;
        }
        if self
            .pending_session
            .is_some_and(|request| request.device == device)
        {
            self.pending_session = None;
        }
        if matches!(
            self.pairing,
            PairingState::AwaitingProof(pending) if pending.device == device
        ) || matches!(
            self.pairing,
            PairingState::AwaitingHostApproval(pending) if pending.handle.device == device
        ) {
            self.pairing = PairingState::Idle;
        }
        if self
            .active_session
            .is_some_and(|grant| grant.device == device)
        {
            return Ok(self.active_session.take());
        }
        Ok(None)
    }

    /// Returns the active grant if it has not expired, otherwise revokes it and invalidates the connection epoch.
    pub fn active_grant(&mut self, now_ns: u64) -> Option<SessionAuthorization> {
        self.expire_active(now_ns);
        self.active_session
    }

    /// Checks the exact grant/connection/capability tuple and revokes expired
    /// authorization before returning.
    pub fn is_authorized(
        &mut self,
        grant: SessionAuthorization,
        capability: Capability,
        now_ns: u64,
    ) -> bool {
        self.active_grant(now_ns).is_some_and(|active| {
            active == grant
                && active.capabilities.contains(capability)
                && self.active_connection.is_some_and(|conn| {
                    conn.device == grant.device
                        && conn.session_id == grant.session_id
                        && conn.authorization_epoch == grant.authorization_epoch
                })
        })
    }

    fn pin(&mut self, device: DeviceFingerprint) -> Result<(), AccessError> {
        if self.is_pinned(device) {
            return Err(AccessError::DeviceAlreadyPinned);
        }
        if self.pinned_devices.len() >= MAX_PINNED_DEVICES {
            return Err(AccessError::PinnedDeviceLimit);
        }
        self.pinned_devices.push(device);
        Ok(())
    }

    fn expire_active(&mut self, now_ns: u64) {
        if self
            .active_session
            .is_some_and(|authorization| authorization.expires_at_ns <= now_ns)
        {
            self.active_session = None;
            self.active_connection = None;
            self.pending_session = None;
        }
    }
}

/// Rejected pairing, pinning, connection, request, approval, or revocation
/// operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    InvalidFingerprint,
    InvalidSessionId,
    InvalidAuthorizationEpoch,
    InvalidCapabilities,
    InvalidTtl,
    InvalidExpiry,
    InvalidPairingSecret,
    ViewCapabilityRequired,
    DeviceAlreadyPinned,
    DeviceNotPinned,
    PinnedDeviceLimit,
    PairingInProgress,
    NoPendingPairing,
    PairingMismatch,
    PairingExpired,
    PairingAlreadyConfirmed,
    PairingNotConfirmed,
    StalePairingHandle,
    ConnectionExists,
    NoActiveConnection,
    StaleConnectionContext,
    SessionInProgress,
    SessionApprovalPending,
    StaleSessionHandle,
    ActiveSessionExists,
    NoPendingSession,
    ApprovalExceedsRequest,
    AuthorizationExpired,
    RngFailure,
}

impl fmt::Display for AccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AccessError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(byte: u8) -> DeviceFingerprint {
        DeviceFingerprint::new([byte; 32]).expect("nonzero device fingerprint")
    }

    fn pair_and_pin(policy: &mut HostAccessPolicy, peer: DeviceFingerprint) {
        let invitation = policy
            .begin_pairing(peer, MAX_PAIRING_TTL_NS, 100)
            .expect("begin pairing");
        let proof = PairingProof::from_invitation(invitation);
        let handle = policy.confirm_pairing(proof, 150).expect("confirm pairing");
        policy
            .approve_pairing(handle, 200)
            .expect("approve pairing");
    }

    #[test]
    fn invalid_constructors_fail_closed() {
        assert_eq!(
            DeviceFingerprint::new([0u8; 32]),
            Err(AccessError::InvalidFingerprint)
        );
        assert!(DeviceFingerprint::new([1u8; 32]).is_ok());

        assert_eq!(
            CapabilitySet::from_bits(0),
            Err(AccessError::InvalidCapabilities)
        );
        assert_eq!(
            CapabilitySet::from_bits(0b100),
            Err(AccessError::InvalidCapabilities)
        );
        assert_eq!(
            CapabilitySet::from_bits(0b1000),
            Err(AccessError::InvalidCapabilities)
        );

        assert_eq!(
            PairingProof::new(device(1), [0u8; 32]),
            Err(AccessError::InvalidPairingSecret)
        );
        assert!(PairingProof::new(device(1), [1u8; 32]).is_ok());

        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, device(1));
        let ctx = policy
            .register_verified_one_rtt_connection(device(1), 100)
            .expect("conn");
        let input_only = CapabilitySet::from_bits(Capability::Input as u8).expect("input only");
        assert_eq!(
            policy.request_session(ctx, input_only),
            Err(AccessError::ViewCapabilityRequired)
        );
    }

    #[test]
    fn secret_bearing_types_redact_debug_formatting() {
        let peer = device(7);
        let secret = [0x5A; 32];
        let proof = PairingProof::new(peer, secret).expect("proof");
        let proof_debug = format!("{proof:?}");
        assert!(proof_debug.contains("<redacted>"));
        assert!(!proof_debug.contains(&format!("{secret:?}")));
        assert!(!proof_debug.contains(&format!("{:?}", &secret[..4])));
        assert!(!proof_debug.contains("90"));
        assert!(!proof_debug.contains("5a"));
        assert!(!proof_debug.contains("5A"));

        let mut policy = HostAccessPolicy::default();
        let invitation = policy
            .begin_pairing(peer, MAX_PAIRING_TTL_NS, 100)
            .expect("invitation");
        let inv_debug = format!("{invitation:?}");
        assert!(inv_debug.contains("<redacted>"));
        let inv_secret = invitation.secret();
        assert!(!inv_debug.contains(&format!("{inv_secret:?}")));
        assert!(!inv_debug.contains(&format!("{:?}", &inv_secret[..4])));
        let hex_chunk = format!(
            "{:02x}{:02x}{:02x}",
            inv_secret[0], inv_secret[1], inv_secret[2]
        );
        assert!(!inv_debug.contains(&hex_chunk));

        // Format PairingCancellationHandle
        let cancel_handle = invitation.cancellation_handle();
        let cancel_nonce = cancel_handle.nonce;
        let cancel_debug = format!("{cancel_handle:?}");
        assert!(cancel_debug.contains("<redacted>"));
        assert!(!cancel_debug.contains(&format!("{cancel_nonce:?}")));
        assert!(!inv_debug.contains(&format!("{cancel_nonce:?}")));

        // Format HostAccessPolicy while containing pending pairing secret and cancellation nonce (AwaitingProof)
        let policy_debug_proof = format!("{policy:?}");
        assert!(policy_debug_proof.contains("<redacted>"));
        assert!(!policy_debug_proof.contains(&format!("{inv_secret:?}")));
        assert!(!policy_debug_proof.contains(&hex_chunk));
        assert!(!policy_debug_proof.contains(&format!("{cancel_nonce:?}")));

        // Format PairingApprovalHandle and policy while awaiting host approval (AwaitingHostApproval)
        let handle = policy
            .confirm_pairing(PairingProof::from_invitation(invitation), 150)
            .expect("confirm");
        let approval_nonce = handle.nonce;
        let handle_debug = format!("{handle:?}");
        assert!(handle_debug.contains("<redacted>"));
        assert!(!handle_debug.contains(&format!("{approval_nonce:?}")));
        let policy_debug_approval = format!("{policy:?}");
        assert!(policy_debug_approval.contains("<redacted>"));
        assert!(!policy_debug_approval.contains(&format!("{inv_secret:?}")));
        assert!(!policy_debug_approval.contains(&format!("{approval_nonce:?}")));
        assert!(!policy_debug_approval.contains(&format!("{cancel_nonce:?}")));

        // Approve pairing, admit verified connection, and request session
        policy.approve_pairing(handle, 200).expect("approve");
        let ctx = policy
            .register_verified_one_rtt_connection(peer, 250)
            .expect("conn");
        let req_handle = policy
            .request_session(ctx, CapabilitySet::view_only())
            .expect("req");
        let req_nonce = req_handle.nonce;

        // Format SessionRequestHandle and policy while pending session approval
        let req_debug = format!("{req_handle:?}");
        assert!(req_debug.contains("<redacted>"));
        assert!(!req_debug.contains(&format!("{req_nonce:?}")));
        let policy_debug_session = format!("{policy:?}");
        assert!(policy_debug_session.contains("<redacted>"));
        assert!(!policy_debug_session.contains(&format!("{req_nonce:?}")));
    }

    #[test]
    fn pairing_requires_proof_confirmation_and_host_approval() {
        let peer = device(7);
        let other = device(8);
        let mut policy = HostAccessPolicy::default();

        let invitation = policy
            .begin_pairing(peer, MAX_PAIRING_TTL_NS, 100)
            .expect("begin pairing");
        assert_eq!(invitation.device(), peer);
        assert_eq!(invitation.expires_at_ns(), 100 + MAX_PAIRING_TTL_NS);

        // Confirming with wrong device fails and consumes invitation
        let wrong_proof = PairingProof::new(other, invitation.secret()).expect("wrong proof");
        assert_eq!(
            policy.confirm_pairing(wrong_proof, 150),
            Err(AccessError::PairingMismatch)
        );
        // Consumed, so retry fails
        assert_eq!(
            policy.confirm_pairing(PairingProof::from_invitation(invitation), 150),
            Err(AccessError::NoPendingPairing)
        );

        // Start fresh pairing
        let invitation2 = policy
            .begin_pairing(peer, MAX_PAIRING_TTL_NS, 200)
            .expect("begin pairing 2");
        let proof2 = PairingProof::from_invitation(invitation2);
        let handle = policy
            .confirm_pairing(proof2, 250)
            .expect("confirm pairing");
        assert_eq!(handle.device(), peer);

        // Cannot confirm again while awaiting host approval
        assert_eq!(
            policy.confirm_pairing(proof2, 250),
            Err(AccessError::PairingAlreadyConfirmed)
        );

        assert_eq!(policy.approve_pairing(handle, 300), Ok(()));
        assert!(policy.is_pinned(peer));
    }

    #[test]
    fn pairing_proof_one_use_on_mismatch_and_expiry() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();

        // 1. Mismatch test: invitation is consumed on attempt with wrong secret
        let inv1 = policy.begin_pairing(peer, 1_000, 100).expect("begin 1");
        let wrong_secret_proof = PairingProof::new(peer, [0xAA; 32]).expect("wrong secret proof");
        assert_eq!(
            policy.confirm_pairing(wrong_secret_proof, 150),
            Err(AccessError::PairingMismatch)
        );
        assert_eq!(
            policy.confirm_pairing(PairingProof::from_invitation(inv1), 150),
            Err(AccessError::NoPendingPairing)
        );

        // 2. Expiry test: invitation is consumed on expired attempt
        let inv2 = policy.begin_pairing(peer, 1_000, 200).expect("begin 2");
        assert_eq!(
            policy.confirm_pairing(PairingProof::from_invitation(inv2), 1_200),
            Err(AccessError::PairingExpired)
        );
        assert_eq!(
            policy.confirm_pairing(PairingProof::from_invitation(inv2), 1_200),
            Err(AccessError::NoPendingPairing)
        );
    }

    #[test]
    fn stale_pairing_handles_rejected_after_new_flow() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();

        let inv1 = policy
            .begin_pairing(peer, MAX_PAIRING_TTL_NS, 100)
            .expect("begin 1");
        let handle1 = policy
            .confirm_pairing(PairingProof::from_invitation(inv1), 150)
            .expect("confirm 1");

        // Host rejects handle1
        assert_eq!(policy.reject_pairing(handle1), Ok(()));

        // Start and confirm second pairing flow
        let inv2 = policy
            .begin_pairing(peer, MAX_PAIRING_TTL_NS, 200)
            .expect("begin 2");
        let handle2 = policy
            .confirm_pairing(PairingProof::from_invitation(inv2), 250)
            .expect("confirm 2");

        assert_ne!(handle1, handle2);

        // Attempting to use stale handle1 is rejected
        assert_eq!(
            policy.approve_pairing(handle1, 300),
            Err(AccessError::StalePairingHandle)
        );
        assert_eq!(
            policy.reject_pairing(handle1),
            Err(AccessError::StalePairingHandle)
        );

        // Current handle2 succeeds
        assert_eq!(policy.approve_pairing(handle2, 300), Ok(()));
        assert!(policy.is_pinned(peer));
    }

    #[test]
    fn cross_policy_pairing_approval_handles_cannot_cross_approve() {
        let peer = device(7);
        let mut policy_a = HostAccessPolicy::default();
        let mut policy_b = HostAccessPolicy::default();

        let inv_a = policy_a
            .begin_pairing(peer, MAX_PAIRING_TTL_NS, 100)
            .expect("begin pairing a");
        let handle_a = policy_a
            .confirm_pairing(PairingProof::from_invitation(inv_a), 150)
            .expect("confirm pairing a");

        let inv_b = policy_b
            .begin_pairing(peer, MAX_PAIRING_TTL_NS, 100)
            .expect("begin pairing b");
        let handle_b = policy_b
            .confirm_pairing(PairingProof::from_invitation(inv_b), 150)
            .expect("confirm pairing b");

        // Distinct CSPRNG nonces ensure handles from reconstructed policies never collide
        assert_ne!(handle_a, handle_b);

        // Using handle_a on policy_b is rejected as stale handle
        assert_eq!(
            policy_b.approve_pairing(handle_a, 200),
            Err(AccessError::StalePairingHandle)
        );
        assert_eq!(
            policy_b.reject_pairing(handle_a),
            Err(AccessError::StalePairingHandle)
        );

        // Policy B remains in pending approval state and handle_b succeeds
        assert_eq!(policy_b.approve_pairing(handle_b, 200), Ok(()));
        assert!(policy_b.is_pinned(peer));
        assert!(!policy_a.is_pinned(peer));

        // Policy A remains in pending approval state and handle_a succeeds
        assert_eq!(policy_a.approve_pairing(handle_a, 200), Ok(()));
        assert!(policy_a.is_pinned(peer));
    }

    #[test]
    fn abandoned_awaiting_proof_pairing_expires_and_unblocks_operations() {
        let peer = device(7);
        let pinned_peer = device(8);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, pinned_peer);

        // Start a pairing flow with 1000 ns TTL starting at t = 100 (expires at 1_100)
        let _inv = policy
            .begin_pairing(peer, 1_000, 100)
            .expect("begin pairing");

        // While awaiting proof (before deadline), pairing is in progress
        assert_eq!(
            policy.begin_pairing(peer, 1_000, 500),
            Err(AccessError::PairingInProgress)
        );
        assert_eq!(
            policy.register_verified_one_rtt_connection(pinned_peer, 500),
            Err(AccessError::PairingInProgress)
        );

        // After deadline (t = 1_100), begin_pairing auto-expires abandoned flow and succeeds
        let inv2 = policy
            .begin_pairing(peer, 1_000, 1_100)
            .expect("begin pairing after expiry");
        assert_eq!(inv2.expires_at_ns(), 2_100);

        // Abandon second pairing flow; after its deadline (t = 2_200), connection admission unblocks
        let ctx = policy
            .register_verified_one_rtt_connection(pinned_peer, 2_200)
            .expect("connection after second pairing expiry");
        assert_eq!(ctx.device(), pinned_peer);
    }

    #[test]
    fn awaiting_approval_pairing_expires_on_deadline() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();

        // Begin pairing at t = 100 with TTL = 1000 (expires at 1100)
        let inv = policy
            .begin_pairing(peer, 1_000, 100)
            .expect("begin pairing");
        let proof = PairingProof::from_invitation(inv);

        // Confirm proof at t = 200 (within deadline)
        let handle = policy.confirm_pairing(proof, 200).expect("confirm pairing");

        // Approving after deadline (t = 1100) fails with PairingExpired and clears state
        assert_eq!(
            policy.approve_pairing(handle, 1_100),
            Err(AccessError::PairingExpired)
        );
        assert!(!policy.is_pinned(peer));

        // Policy is now Idle, so a new pairing flow works immediately
        let inv2 = policy
            .begin_pairing(peer, 1_000, 1_200)
            .expect("begin new pairing");
        let proof2 = PairingProof::from_invitation(inv2);
        let handle2 = policy
            .confirm_pairing(proof2, 1_300)
            .expect("confirm new pairing");
        assert_eq!(policy.approve_pairing(handle2, 1_400), Ok(()));
        assert!(policy.is_pinned(peer));
    }

    #[test]
    fn awaiting_host_approval_auto_expiry_unblocks_pairing_and_connections() {
        let peer = device(7);
        let pinned_peer = device(8);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, pinned_peer);

        // Flow 1: Begin pairing at t = 100 with TTL = 1000 (expires at 1100)
        let inv1 = policy
            .begin_pairing(peer, 1_000, 100)
            .expect("begin pairing 1");
        let proof1 = PairingProof::from_invitation(inv1);
        let _handle1 = policy
            .confirm_pairing(proof1, 200)
            .expect("confirm pairing 1");

        // While in AwaitingHostApproval before deadline, pairing is in progress
        assert_eq!(
            policy.begin_pairing(device(9), 1_000, 500),
            Err(AccessError::PairingInProgress)
        );
        assert_eq!(
            policy.register_verified_one_rtt_connection(pinned_peer, 500),
            Err(AccessError::PairingInProgress)
        );

        // At deadline (t = 1100), starting a new pairing directly auto-expires flow 1 without calling approve/reject/cancel
        let inv2 = policy
            .begin_pairing(device(9), 1_000, 1_100)
            .expect("begin pairing directly at deadline");
        assert_eq!(inv2.expires_at_ns(), 2_100);

        // Confirm flow 2 at t = 1200, advancing to AwaitingHostApproval (expires at 2100)
        let proof2 = PairingProof::from_invitation(inv2);
        let _handle2 = policy
            .confirm_pairing(proof2, 1_200)
            .expect("confirm pairing 2");

        // At deadline (t = 2100), registering a verified connection directly auto-expires flow 2 without calling approve/reject/cancel
        let ctx = policy
            .register_verified_one_rtt_connection(pinned_peer, 2_100)
            .expect("register connection directly at deadline");
        assert_eq!(ctx.device(), pinned_peer);
    }

    #[test]
    fn exact_cancellation_and_delayed_cross_flow_cancellation() {
        let peer_a = device(7);
        let peer_b = device(8);
        let mut policy = HostAccessPolicy::default();

        // Cancellation on idle policy fails
        let fake_handle = PairingCancellationHandle {
            device: peer_a,
            generation: 1,
            nonce: [0x42; 16],
        };
        assert_eq!(
            policy.cancel_pairing(fake_handle),
            Err(AccessError::NoPendingPairing)
        );

        // --- Part 1: Exact cancellation in AwaitingProof ---
        let inv_a1 = policy.begin_pairing(peer_a, 1_000, 100).expect("begin a1");
        let handle_a1 = inv_a1.cancellation_handle();
        assert_eq!(handle_a1.device(), peer_a);

        // Mismatched cancellation handle is rejected and leaves state in AwaitingProof
        let wrong_handle = PairingCancellationHandle {
            device: peer_a,
            generation: handle_a1.generation + 99,
            nonce: handle_a1.nonce,
        };
        assert_eq!(
            policy.cancel_pairing(wrong_handle),
            Err(AccessError::StalePairingHandle)
        );

        // Matching handle cancels flow
        assert_eq!(policy.cancel_pairing(handle_a1), Ok(()));
        assert_eq!(
            policy.cancel_pairing(handle_a1),
            Err(AccessError::NoPendingPairing)
        );

        // --- Part 2: Exact cancellation in AwaitingHostApproval ---
        let inv_a2 = policy.begin_pairing(peer_a, 1_000, 200).expect("begin a2");
        let handle_a2 = inv_a2.cancellation_handle();
        let approval_a2 = policy
            .confirm_pairing(PairingProof::from_invitation(inv_a2), 250)
            .expect("confirm a2");

        // Wrong cancellation handle rejected and preserves AwaitingHostApproval
        assert_eq!(
            policy.cancel_pairing(handle_a1),
            Err(AccessError::StalePairingHandle)
        );

        // Correct cancellation handle cancels flow
        assert_eq!(policy.cancel_pairing(handle_a2), Ok(()));
        // Stale approval handle cannot be approved after cancel
        assert_eq!(
            policy.approve_pairing(approval_a2, 300),
            Err(AccessError::NoPendingPairing)
        );

        // --- Part 3: Delayed A-cancel against B in AwaitingProof; B remains completable ---
        let inv_a3 = policy.begin_pairing(peer_a, 1_000, 300).expect("begin a3"); // expires at 1300
        let handle_a3 = inv_a3.cancellation_handle();

        // At t = 1300, start flow B
        let inv_b = policy.begin_pairing(peer_b, 1_000, 1_300).expect("begin b");

        // Delayed cancellation from flow A arrives while flow B is in AwaitingProof
        assert_eq!(
            policy.cancel_pairing(handle_a3),
            Err(AccessError::StalePairingHandle)
        );

        // Flow B is undisturbed and remains completable
        let proof_b = PairingProof::from_invitation(inv_b);
        let approval_b = policy.confirm_pairing(proof_b, 1_350).expect("confirm b");
        assert_eq!(policy.approve_pairing(approval_b, 1_400), Ok(()));
        assert!(policy.is_pinned(peer_b));
        assert!(!policy.is_pinned(peer_a));

        // Clean up peer_b pin to prepare for Part 4
        policy.revoke_device(peer_b).expect("revoke b");

        // --- Part 4: Delayed A-cancel against B in AwaitingHostApproval; B remains completable ---
        let inv_a4 = policy
            .begin_pairing(peer_a, 1_000, 2_000)
            .expect("begin a4"); // expires at 3000
        let handle_a4 = inv_a4.cancellation_handle();

        // At t = 3000, start flow B and advance to AwaitingHostApproval
        let inv_b2 = policy
            .begin_pairing(peer_b, 1_000, 3_000)
            .expect("begin b2");
        let proof_b2 = PairingProof::from_invitation(inv_b2);
        let approval_b2 = policy.confirm_pairing(proof_b2, 3_050).expect("confirm b2");

        // Delayed cancellation from flow A arrives while flow B is in AwaitingHostApproval
        assert_eq!(
            policy.cancel_pairing(handle_a4),
            Err(AccessError::StalePairingHandle)
        );

        // Flow B remains in AwaitingHostApproval and can be approved
        assert_eq!(policy.approve_pairing(approval_b2, 3_100), Ok(()));
        assert!(policy.is_pinned(peer_b));
        assert!(!policy.is_pinned(peer_a));
    }

    #[test]
    fn randomness_guarantees_isolate_secrets_session_ids_and_request_nonces() {
        let peer = device(7);

        // 1. Different invitation secrets and cancellation handles across policies
        let mut pol_a = HostAccessPolicy::default();
        let mut pol_b = HostAccessPolicy::default();
        let inv_a = pol_a
            .begin_pairing(peer, 1_000, 100)
            .expect("begin pairing a");
        let inv_b = pol_b
            .begin_pairing(peer, 1_000, 100)
            .expect("begin pairing b");
        assert_ne!(inv_a.secret(), inv_b.secret());
        assert_ne!(inv_a.cancellation_handle(), inv_b.cancellation_handle());

        // 2. Different secrets across consecutive flows on same policy, old proof rejected on new flow
        let mut policy = HostAccessPolicy::default();
        let inv1 = policy.begin_pairing(peer, 1_000, 100).expect("begin 1");
        let proof1 = PairingProof::from_invitation(inv1);
        policy
            .cancel_pairing(inv1.cancellation_handle())
            .expect("cancel 1");
        let inv2 = policy.begin_pairing(peer, 1_000, 200).expect("begin 2");
        assert_ne!(inv1.secret(), inv2.secret());
        assert_ne!(inv1.cancellation_handle(), inv2.cancellation_handle());
        // Old proof from flow 1 presented to flow 2 fails with PairingMismatch and consumes flow 2
        assert_eq!(
            policy.confirm_pairing(proof1, 250),
            Err(AccessError::PairingMismatch)
        );
        assert_eq!(
            policy.confirm_pairing(PairingProof::from_invitation(inv2), 250),
            Err(AccessError::NoPendingPairing)
        );

        // 3. First connection session IDs across reconstructed policies are nonzero and distinct
        let mut p1 = HostAccessPolicy::default();
        let mut p2 = HostAccessPolicy::default();
        pair_and_pin(&mut p1, peer);
        pair_and_pin(&mut p2, peer);
        let c1 = p1
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn p1");
        let c2 = p2
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn p2");
        assert_ne!(c1.session_id().value(), 0);
        assert_ne!(c2.session_id().value(), 0);
        assert_ne!(c1.session_id(), c2.session_id());

        // 4. Request-handle nonce alone prevents cross-policy identical-tuple approve/reject
        let mut pol_x = HostAccessPolicy::default();
        let mut pol_y = HostAccessPolicy::default();
        pair_and_pin(&mut pol_x, peer);
        pair_and_pin(&mut pol_y, peer);
        let ctx_x = pol_x
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn x");
        let req_x = pol_x
            .request_session(ctx_x, CapabilitySet::view_only())
            .expect("req x");

        // Force policy Y to have the exact same active connection context and generation
        pol_y.active_connection = Some(ctx_x);
        let req_y = pol_y
            .request_session(ctx_x, CapabilitySet::view_only())
            .expect("req y");

        // Verify identical fields except CSPRNG nonce
        assert_eq!(req_x.device(), req_y.device());
        assert_eq!(req_x.session_id(), req_y.session_id());
        assert_eq!(req_x.authorization_epoch(), req_y.authorization_epoch());
        assert_eq!(
            req_x.requested_capabilities(),
            req_y.requested_capabilities()
        );
        assert_eq!(req_x.generation, req_y.generation);
        assert_ne!(req_x.nonce, req_y.nonce);
        assert_ne!(req_x, req_y);

        // Attempting to approve/reject req_x on policy Y fails due to nonce mismatch alone
        assert_eq!(
            pol_y.approve_session(req_x, CapabilitySet::view_only(), 1_000, 100),
            Err(AccessError::StaleSessionHandle)
        );
        assert_eq!(
            pol_y.reject_session(req_x),
            Err(AccessError::StaleSessionHandle)
        );

        // Matching req_y on policy Y succeeds
        let grant_y = pol_y
            .approve_session(req_y, CapabilitySet::view_only(), 1_000, 100)
            .expect("approve req y");
        assert!(pol_y.is_authorized(grant_y, Capability::View, 150));
    }

    #[test]
    fn unknown_device_cannot_connect_or_request_session() {
        let unknown = device(99);
        let mut policy = HostAccessPolicy::default();
        assert_eq!(
            policy.register_verified_one_rtt_connection(unknown, 100),
            Err(AccessError::DeviceNotPinned)
        );
    }

    #[test]
    fn fresh_connection_gets_nonzero_session_id_and_monotonic_epoch() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, peer);

        let ctx1 = policy
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn 1");
        assert_ne!(ctx1.session_id().value(), 0);
        assert_eq!(ctx1.authorization_epoch().value(), 1);
        assert_eq!(ctx1.device(), peer);

        let ctx2 = policy
            .register_verified_one_rtt_connection(peer, 200)
            .expect("conn 2");
        assert_ne!(ctx2.session_id().value(), 0);
        assert_eq!(ctx2.authorization_epoch().value(), 2);
        assert_eq!(ctx2.device(), peer);
        assert!(ctx2.authorization_epoch().value() > ctx1.authorization_epoch().value());
    }

    #[test]
    fn stale_context_and_request_rejection() {
        let peer = device(7);
        let peer2 = device(8);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, peer);
        pair_and_pin(&mut policy, peer2);

        let ctx1 = policy
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn 1");

        // 1. Partial-context matches: same device, same session, different epoch rejected
        let diff_epoch_ctx = ConnectionContext::new(
            ctx1.device(),
            ctx1.session_id(),
            AuthorizationEpoch(ctx1.authorization_epoch().value() + 42),
        );
        assert_eq!(
            policy.request_session(diff_epoch_ctx, CapabilitySet::view_only()),
            Err(AccessError::StaleConnectionContext)
        );

        // 2. Partial-context matches: same device, different session, same epoch rejected
        let diff_session_ctx = ConnectionContext::new(
            ctx1.device(),
            SessionId(ctx1.session_id().value() ^ 0xDEAD),
            ctx1.authorization_epoch(),
        );
        assert_eq!(
            policy.request_session(diff_session_ctx, CapabilitySet::view_only()),
            Err(AccessError::StaleConnectionContext)
        );

        // 3. Partial-context matches: different device, same session, same epoch rejected
        let diff_dev_ctx =
            ConnectionContext::new(peer2, ctx1.session_id(), ctx1.authorization_epoch());
        assert_eq!(
            policy.request_session(diff_dev_ctx, CapabilitySet::view_only()),
            Err(AccessError::StaleConnectionContext)
        );

        // Active connection context can request session
        let req_handle = policy
            .request_session(ctx1, CapabilitySet::view_only())
            .expect("request ctx1");

        // New connection arrives while request is pending approval
        let _ctx2 = policy
            .register_verified_one_rtt_connection(peer, 300)
            .expect("conn 2");

        // Approval of the superseded request handle fails
        assert_eq!(
            policy.approve_session(req_handle, CapabilitySet::view_only(), 1_000, 300),
            Err(AccessError::NoPendingSession)
        );
    }

    #[test]
    fn stale_session_handles_rejected_after_new_request() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, peer);

        let ctx = policy
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn");
        let req1 = policy
            .request_session(ctx, CapabilitySet::view_only())
            .expect("req 1");

        // Host rejects req1
        assert_eq!(policy.reject_session(req1), Ok(()));

        // Submit new request on same connection with identical requested capabilities
        let req2 = policy
            .request_session(ctx, CapabilitySet::view_only())
            .expect("req 2");
        assert_ne!(req1, req2);
        assert_eq!(req1.device(), req2.device());
        assert_eq!(req1.session_id(), req2.session_id());
        assert_eq!(req1.authorization_epoch(), req2.authorization_epoch());
        assert_eq!(req1.requested_capabilities(), req2.requested_capabilities());

        // Stale req1 handle cannot be approved or rejected
        assert_eq!(
            policy.approve_session(req1, CapabilitySet::view_only(), 1_000, 100),
            Err(AccessError::StaleSessionHandle)
        );
        assert_eq!(
            policy.reject_session(req1),
            Err(AccessError::StaleSessionHandle)
        );

        // Valid req2 can be approved
        let grant = policy
            .approve_session(req2, CapabilitySet::view_only(), 1_000, 100)
            .expect("approve req 2");
        assert!(policy.is_authorized(grant, Capability::View, 150));
    }

    #[test]
    fn full_context_close_connection_semantics() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, peer);

        let ctx1 = policy
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn 1");
        let req1 = policy
            .request_session(ctx1, CapabilitySet::view_only())
            .expect("req 1");
        let grant1 = policy
            .approve_session(req1, CapabilitySet::view_only(), 1_000, 100)
            .expect("grant 1");
        assert_eq!(policy.active_connection(), Some(ctx1));

        // Registering a second connection supersedes ctx1
        let ctx2 = policy
            .register_verified_one_rtt_connection(peer, 200)
            .expect("conn 2");
        assert_eq!(policy.active_connection(), Some(ctx2));

        // Closing stale ctx1 does nothing and returns None
        assert_eq!(policy.close_connection(ctx1), None);
        assert_eq!(policy.active_connection(), Some(ctx2));

        // Stale context with same session_id but different authorization_epoch returns None
        let stale_epoch_ctx = ConnectionContext::new(
            ctx2.device(),
            ctx2.session_id(),
            AuthorizationEpoch(ctx2.authorization_epoch().value() + 99),
        );
        assert_eq!(policy.close_connection(stale_epoch_ctx), None);
        assert_eq!(policy.active_connection(), Some(ctx2));

        // Stale context with different session_id returns None
        let stale_session_ctx = ConnectionContext::new(
            ctx2.device(),
            SessionId(ctx2.session_id().value() ^ 0xFFFF),
            ctx2.authorization_epoch(),
        );
        assert_eq!(policy.close_connection(stale_session_ctx), None);
        assert_eq!(policy.active_connection(), Some(ctx2));

        // Establish an active session on ctx2
        let req2 = policy
            .request_session(ctx2, CapabilitySet::view_only())
            .expect("req 2");
        let grant2 = policy
            .approve_session(req2, CapabilitySet::view_only(), 1_000, 200)
            .expect("grant 2");
        assert_eq!(policy.active_grant(250), Some(grant2));

        // Closing current ctx2 clears active connection, returns active grant, and cleans up
        assert_eq!(policy.close_connection(ctx2), Some(grant2));
        assert_eq!(policy.active_connection(), None);
        assert_eq!(policy.active_grant(250), None);
        assert_eq!(policy.pending_request(), None);

        // grant1 and grant2 are no longer authorized
        assert!(!policy.is_authorized(grant1, Capability::View, 150));
        assert!(!policy.is_authorized(grant2, Capability::View, 250));
    }

    #[test]
    fn subset_approval_and_overgrant_rejection() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, peer);

        // Case A: Request view_only, approve view_and_input -> rejected
        let ctx1 = policy
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn 1");
        let req_view = policy
            .request_session(ctx1, CapabilitySet::view_only())
            .expect("req view");
        assert_eq!(
            policy.approve_session(req_view, CapabilitySet::view_and_input(), 1_000, 100),
            Err(AccessError::ApprovalExceedsRequest)
        );
        let grant_view = policy
            .approve_session(req_view, CapabilitySet::view_only(), 1_000, 100)
            .expect("approve view");
        assert!(policy.is_authorized(grant_view, Capability::View, 150));
        assert!(!policy.is_authorized(grant_view, Capability::Input, 150));

        // Case B: Request view_and_input, approve subset view_only -> accepted
        let ctx2 = policy
            .register_verified_one_rtt_connection(peer, 200)
            .expect("conn 2");
        let req_all = policy
            .request_session(ctx2, CapabilitySet::view_and_input())
            .expect("req all");
        let grant_subset = policy
            .approve_session(req_all, CapabilitySet::view_only(), 1_000, 100)
            .expect("approve subset");
        assert!(policy.is_authorized(grant_subset, Capability::View, 150));
        assert!(!policy.is_authorized(grant_subset, Capability::Input, 150));
    }

    #[test]
    fn ttl_bounds_and_overflow_protection() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();

        // Pairing TTL bounds
        assert_eq!(
            policy.begin_pairing(peer, 0, 100),
            Err(AccessError::InvalidTtl)
        );
        assert_eq!(
            policy.begin_pairing(peer, MAX_PAIRING_TTL_NS + 1, 100),
            Err(AccessError::InvalidTtl)
        );
        assert_eq!(
            policy.begin_pairing(peer, MAX_PAIRING_TTL_NS, u64::MAX),
            Err(AccessError::InvalidExpiry)
        );

        // Session TTL bounds
        pair_and_pin(&mut policy, peer);
        let ctx = policy
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn");
        let req = policy
            .request_session(ctx, CapabilitySet::view_only())
            .expect("req");

        assert_eq!(
            policy.approve_session(req, CapabilitySet::view_only(), 0, 100),
            Err(AccessError::InvalidTtl)
        );
        assert_eq!(
            policy.approve_session(req, CapabilitySet::view_only(), MAX_SESSION_TTL_NS + 1, 100),
            Err(AccessError::InvalidTtl)
        );
        assert_eq!(
            policy.approve_session(
                req,
                CapabilitySet::view_only(),
                MAX_SESSION_TTL_NS,
                u64::MAX
            ),
            Err(AccessError::InvalidExpiry)
        );
    }

    #[test]
    fn active_revoke_and_expiry_permanently_invalidate_epoch_and_connection() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, peer);

        // Revocation flow
        let ctx1 = policy
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn 1");
        let req1 = policy
            .request_session(ctx1, CapabilitySet::view_only())
            .expect("req 1");
        let grant1 = policy
            .approve_session(req1, CapabilitySet::view_only(), 1_000, 100)
            .expect("grant 1");

        assert_eq!(policy.revoke_active(), Some(grant1));
        assert_eq!(policy.active_connection(), None);
        assert_eq!(policy.active_grant(150), None);
        assert!(!policy.is_authorized(grant1, Capability::View, 150));
        assert_eq!(
            policy.request_session(ctx1, CapabilitySet::view_only()),
            Err(AccessError::StaleConnectionContext)
        );

        // Expiry flow
        let ctx2 = policy
            .register_verified_one_rtt_connection(peer, 200)
            .expect("conn 2");
        let req2 = policy
            .request_session(ctx2, CapabilitySet::view_only())
            .expect("req 2");
        let grant2 = policy
            .approve_session(req2, CapabilitySet::view_only(), 100, 100)
            .expect("grant 2"); // expires at 200

        assert!(policy.is_authorized(grant2, Capability::View, 199));
        assert!(!policy.is_authorized(grant2, Capability::View, 200));
        assert_eq!(policy.active_grant(200), None);
        assert_eq!(policy.active_connection(), None);
        assert_eq!(
            policy.request_session(ctx2, CapabilitySet::view_only()),
            Err(AccessError::StaleConnectionContext)
        );
    }

    #[test]
    fn device_revoke_cleans_all_state_and_pins() {
        let peer = device(7);
        let mut policy = HostAccessPolicy::default();
        pair_and_pin(&mut policy, peer);

        let ctx = policy
            .register_verified_one_rtt_connection(peer, 100)
            .expect("conn");
        let req = policy
            .request_session(ctx, CapabilitySet::view_only())
            .expect("req");
        let grant = policy
            .approve_session(req, CapabilitySet::view_only(), 1_000, 100)
            .expect("grant");

        assert_eq!(policy.revoke_device(peer), Ok(Some(grant)));
        assert!(!policy.is_pinned(peer));
        assert_eq!(policy.active_connection(), None);
        assert_eq!(policy.active_grant(150), None);
        assert!(!policy.is_authorized(grant, Capability::View, 150));
        assert_eq!(
            policy.revoke_device(peer),
            Err(AccessError::DeviceNotPinned)
        );
        assert_eq!(
            policy.register_verified_one_rtt_connection(peer, 200),
            Err(AccessError::DeviceNotPinned)
        );
    }

    #[test]
    fn pinned_device_limits_and_enumeration() {
        let mut devices = Vec::new();
        for i in 1..=MAX_PINNED_DEVICES as u8 {
            devices.push(device(i));
        }

        let mut policy =
            HostAccessPolicy::from_pinned_devices(devices.clone()).expect("from pinned devices");
        assert_eq!(policy.pinned_devices().len(), MAX_PINNED_DEVICES);

        // Adding 65th device exceeds limit
        let extra = device(255);
        assert_eq!(
            policy.begin_pairing(extra, MAX_PAIRING_TTL_NS, 100),
            Err(AccessError::PinnedDeviceLimit)
        );

        // Pinned device cannot pair again
        assert_eq!(
            policy.begin_pairing(devices[0], MAX_PAIRING_TTL_NS, 100),
            Err(AccessError::DeviceAlreadyPinned)
        );
    }
}
