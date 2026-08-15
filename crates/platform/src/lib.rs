//! Cross-platform capture, input, cursor, and presentation contracts.
//!
//! Platform implementations are synchronous state machines at this boundary.
//! Async runtimes, COM callbacks, portal callbacks, and GPU fences remain inside
//! providers and may never bypass queue/resource limits in the shared core.
#![allow(clippy::result_large_err)]

use latencydesk_input::AppliedInput;
use latencydesk_media::{FrameDescriptor, ImportPath};
use latencydesk_surface::OwnedSurface;
use std::collections::VecDeque;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const MAX_PEER_ALIAS_BYTES: usize = 64;

/// Public view of a persistent TLS device identity.
///
/// The platform store retains private key material in OS user-secret storage;
/// the safe core receives only the immutable SPKI fingerprint needed to bind a
/// pairing attempt to the authenticated TLS peer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceIdentity {
    spki_fingerprint: [u8; 32],
}

impl DeviceIdentity {
    /// Constructs the public identity view from a verified TLS SPKI fingerprint.
    pub fn from_tls_spki_fingerprint(fingerprint: [u8; 32]) -> Result<Self, PlatformError> {
        if fingerprint.iter().all(|byte| *byte == 0) {
            return Err(PlatformError::InvalidIdentity);
        }
        Ok(Self {
            spki_fingerprint: fingerprint,
        })
    }

    #[must_use]
    pub const fn spki_fingerprint(self) -> [u8; 32] {
        self.spki_fingerprint
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceIdentity(<redacted>)")
    }
}

/// Locally selected label for one persistent peer identity.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PeerAlias(String);

impl PeerAlias {
    pub fn new(alias: impl Into<String>) -> Result<Self, PlatformError> {
        let alias = alias.into();
        if alias.is_empty()
            || alias.len() > MAX_PEER_ALIAS_BYTES
            || alias.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(PlatformError::InvalidPeerAlias);
        }
        Ok(Self(alias))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PeerAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerAlias(<redacted>)")
    }
}

/// Persistent pin for one peer TLS SPKI fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerPin([u8; 32]);

impl PeerPin {
    pub fn from_tls_spki_fingerprint(fingerprint: [u8; 32]) -> Result<Self, PlatformError> {
        if fingerprint.iter().all(|byte| *byte == 0) {
            return Err(PlatformError::InvalidPeerPin);
        }
        Ok(Self(fingerprint))
    }

    #[must_use]
    pub const fn spki_fingerprint(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for PeerPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerPin(<redacted>)")
    }
}

/// Platform-owned persistent identity and peer-pin storage.
///
/// Implementations must use OS user-secret facilities for private identity
/// material. This contract deliberately offers no filesystem fallback.
pub trait DeviceIdentityStore: Send + Sync {
    fn load_or_create_identity(&self) -> Result<DeviceIdentity, PlatformError>;
    fn load_peer_pin(&self, alias: &PeerAlias) -> Result<Option<PeerPin>, PlatformError>;
    fn store_peer_pin(&self, alias: &PeerAlias, pin: PeerPin) -> Result<(), PlatformError>;
}

/// Runtime provider lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    Idle,
    Starting,
    Running,
    Reconfiguring,
    Suspended,
    Draining,
    Revoked,
    Failed,
    Stopped,
}

/// Capture event emitted by a native provider.
#[derive(Debug)]
pub enum CaptureEvent {
    /// A provider-owned surface after the native capture lease has been
    /// synchronously detached with a validated ownership ledger.
    Frame(EpochBoundSurface),
    Reconfigure {
        display_epoch: u32,
        descriptor: FrameDescriptor,
    },
    AccessLost,
    /// The capture API masked protected pixels. The affected display epoch is
    /// invalidated; the caller must recover before encoding another frame.
    ProtectedContent {
        display_epoch: u32,
    },
    PermissionRevoked,
    EndOfStream,
}

/// An owned surface carrying the authoritative display generation from its
/// validated capture/decode ledger. Safe callers cannot relabel the epoch.
///
/// ```compile_fail
/// fn forge(surface: latencydesk_surface::OwnedSurface) {
///     let _ = latencydesk_platform::EpochBoundSurface::new(surface).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// fn forge(surface: latencydesk_surface::OwnedSurface) {
///     let _ = latencydesk_platform::EpochBoundSurface::from_trusted_provider(surface, ());
/// }
/// ```
///
/// ```compile_fail
/// fn extract(frame: latencydesk_platform::EpochBoundSurface) {
///     let _surface = frame.into_surface();
/// }
/// ```
pub struct EpochBoundSurface {
    surface: OwnedSurface,
    display_epoch: u32,
    presentation_authorization: Arc<AtomicBool>,
}

impl EpochBoundSurface {
    /// Creates an epoch-authoritative frame at a trusted provider boundary.
    ///
    /// The caller must have validated that the surface's copy ledger was
    /// produced for the exact native source observation and provider epoch,
    /// and `presentation_authorization` must represent that exact source
    /// generation. Invalidation closes it even while this value is retained.
    /// Generic pool/import metadata is not such authority by itself.
    fn from_trusted_provider(
        surface: OwnedSurface,
        presentation_authorization: Arc<AtomicBool>,
    ) -> Result<Self, PlatformError> {
        let display_epoch = surface
            .copy_ledger()
            .map_err(|_| PlatformError::InvalidSurface)?
            .source_lease
            .provider_epoch;
        if display_epoch == 0 {
            return Err(PlatformError::InvalidSurface);
        }
        Ok(Self {
            surface,
            display_epoch,
            presentation_authorization,
        })
    }

    #[must_use]
    pub const fn display_epoch(&self) -> u32 {
        self.display_epoch
    }

    #[must_use]
    pub const fn surface(&self) -> &OwnedSurface {
        &self.surface
    }

    pub fn validate(&self) -> Result<(), PlatformError> {
        if !self.presentation_authorization.load(Ordering::Acquire) {
            return Err(PlatformError::PermissionRevoked);
        }
        let ledger = self
            .surface
            .copy_ledger()
            .map_err(|_| PlatformError::InvalidSurface)?;
        if self.display_epoch == 0 || ledger.source_lease.provider_epoch != self.display_epoch {
            return Err(PlatformError::InvalidSurface);
        }
        self.surface
            .descriptor()
            .map_err(|_| PlatformError::InvalidSurface)?
            .validate()
            .map_err(|_| PlatformError::InvalidSurface)?;
        if !self.presentation_authorization.load(Ordering::Acquire) {
            return Err(PlatformError::PermissionRevoked);
        }
        Ok(())
    }
}

impl fmt::Debug for EpochBoundSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EpochBoundSurface")
            .field("surface", &self.surface)
            .field("display_epoch", &self.display_epoch)
            .finish_non_exhaustive()
    }
}

/// Opaque, single-poll authority to publish a provider-validated frame.
///
/// Safe consumers cannot construct this capability. [`CaptureBackend::poll`]
/// creates it and lends it only to the provider implementation for that call.
///
/// ```compile_fail
/// let _ = latencydesk_platform::CaptureFramePublisher { _private: () };
/// ```
#[derive(Debug)]
pub struct CaptureFramePublisher {
    _private: (),
}

impl CaptureFramePublisher {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Binds an already validated provider epoch to its live presentation
    /// authorization. Only [`CaptureBackend::poll`] creates this capability;
    /// consumers cannot construct one outside a provider call.
    #[doc(hidden)]
    pub fn bind(
        &mut self,
        surface: OwnedSurface,
        presentation_authorization: Arc<AtomicBool>,
    ) -> Result<EpochBoundSurface, PlatformError> {
        EpochBoundSurface::from_trusted_provider(surface, presentation_authorization)
    }
}

/// Whole-output/window capture provider.
pub trait CaptureBackend {
    fn name(&self) -> &'static str;
    fn state(&self) -> ProviderState;
    fn start(&mut self) -> Result<(), PlatformError>;
    /// Polls through a fresh opaque publication capability. Implementations
    /// cannot retain the capability beyond this call.
    fn poll(&mut self, timeout_ns: u64) -> Result<Option<CaptureEvent>, PlatformError> {
        let mut publisher = CaptureFramePublisher::new();
        self.poll_with_publisher(timeout_ns, &mut publisher)
    }
    /// Provider-side poll entry point. Frame variants must be constructed with
    /// `publisher`; safe non-provider callers cannot manufacture one.
    #[doc(hidden)]
    fn poll_with_publisher(
        &mut self,
        timeout_ns: u64,
        publisher: &mut CaptureFramePublisher,
    ) -> Result<Option<CaptureEvent>, PlatformError>;
    fn stop(&mut self) -> Result<(), PlatformError>;
    fn diagnostics(&self) -> ProviderDiagnostics;
}

/// Copy-only metadata needed before a native encoder accepts a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderPreflight {
    pub display_epoch: u32,
    pub descriptor: FrameDescriptor,
}

/// Fail-closed handoff of an epoch-authoritative surface to a native encoder.
///
/// Preflight exposes only copied metadata. The encoder must call
/// [`Self::submit`] before accessing [`EncodeSubmission::frame`].
#[derive(Debug)]
pub struct EncoderSubmissionGuard {
    frame: Option<EpochBoundSurface>,
}

impl EncoderSubmissionGuard {
    fn new(frame: EpochBoundSurface) -> Self {
        Self { frame: Some(frame) }
    }

    #[must_use]
    pub fn preflight(&self) -> EncoderPreflight {
        let frame = self
            .frame
            .as_ref()
            .expect("encoder submission guard must contain its frame");
        EncoderPreflight {
            display_epoch: frame.display_epoch(),
            descriptor: frame
                .surface()
                .descriptor()
                .expect("validated epoch-bound frame retains its descriptor"),
        }
    }

    /// Transfers this exact frame to native encoder ownership.
    pub fn submit(mut self) -> Result<EncodeSubmission, EncodeFailure> {
        let frame = self
            .frame
            .as_ref()
            .expect("encoder submission guard must contain its frame");
        if let Err(error) = frame.validate() {
            return Err(EncodeFailure {
                error,
                frame: self.frame.take().expect("encoder frame"),
            });
        }
        Ok(EncodeSubmission {
            frame: Some(self.frame.take().expect("encoder frame")),
        })
    }

    /// Returns the frame only when the encoder has not begun native work.
    #[must_use]
    pub fn reject(mut self, error: PlatformError) -> EncodeFailure {
        EncodeFailure {
            error,
            frame: self
                .frame
                .take()
                .expect("encoder submission guard must contain its frame"),
        }
    }
}

/// A native encoder-owned frame submission.
///
/// Dropping an uncompleted submission retains the frame. The encoder must
/// release it only after its completion primitive proves native access ended.
#[must_use = "the encoder must retain this submission until native completion"]
#[derive(Debug)]
pub struct EncodeSubmission {
    frame: Option<EpochBoundSurface>,
}

impl EncodeSubmission {
    #[must_use]
    pub fn frame(&self) -> &EpochBoundSurface {
        self.frame
            .as_ref()
            .expect("encode submission must contain its frame until release")
    }

    /// Returns the exact frame only after a native encoder rejects it before
    /// beginning any access.
    #[must_use]
    pub fn reject(mut self, error: PlatformError) -> EncodeFailure {
        EncodeFailure {
            error,
            frame: self
                .frame
                .take()
                .expect("encode submission must contain its frame until release"),
        }
    }

    fn release(mut self) {
        drop(
            self.frame
                .take()
                .expect("encode submission must contain its frame until release"),
        );
    }
}

impl Drop for EncodeSubmission {
    fn drop(&mut self) {
        if let Some(frame) = self.frame.take() {
            std::mem::forget(frame);
        }
    }
}

/// A failed pre-submission encode transition with the exact retained frame.
#[derive(Debug)]
pub struct EncodeFailure {
    pub error: PlatformError,
    frame: EpochBoundSurface,
}

impl EncodeFailure {
    #[must_use]
    pub fn into_frame(self) -> EpochBoundSurface {
        self.frame
    }
}

/// Native encoder lifecycle for epoch-authoritative capture or decode surfaces.
///
/// Implementations must call [`EncoderSubmissionGuard::submit`] before native
/// access, report completion only after the exact native completion primitive,
/// and quiesce all submitted work before destruction.
pub trait EncodeBackend {
    fn name(&self) -> &'static str;

    fn prepare(
        &mut self,
        frame: EpochBoundSurface,
    ) -> Result<EncoderSubmissionGuard, PlatformError> {
        frame.validate()?;
        Ok(EncoderSubmissionGuard::new(frame))
    }

    fn encode(
        &mut self,
        submission: EncoderSubmissionGuard,
    ) -> Result<EncodeSubmission, EncodeFailure>;

    fn poll_encode_completion(
        &mut self,
        submission: &EncodeSubmission,
    ) -> Result<NativePresentationCompletion, PlatformError>;

    fn release_encoded(&mut self, submission: EncodeSubmission) -> Result<(), PlatformError> {
        submission.release();
        Ok(())
    }

    fn quiesce_encoding(&mut self) -> Result<(), PlatformError>;
    fn diagnostics(&self) -> ProviderDiagnostics;
}

/// Native input injector. It receives only reconciled actions.
pub trait InputBackend {
    fn name(&self) -> &'static str;
    fn inject(&mut self, action: AppliedInput) -> Result<(), PlatformError>;
    fn release_all(&mut self, actions: &[AppliedInput]) -> Result<(), PlatformError>;
    fn diagnostics(&self) -> ProviderDiagnostics;
}

/// Native renderer. The core presents at most one continuity-valid newest frame.
///
/// The coordinator owns the renderer for each submission's whole lifetime; it
/// never lets a different backend attest completion or recovery.
///
/// # Contract
///
/// Platform provider crates own the unsafe FFI/GPU boundary. Implementations
/// MUST uphold these obligations:
///
/// - inspect [`PresentationSubmissionGuard::preflight`] only for copied,
///   non-surface metadata, then call [`PresentationSubmissionGuard::submit`]
///   before native work can access the guarded surface; return only the
///   [`PresentSubmission`] produced from that exact guard, or use
///   [`PresentationSubmissionGuard::reject`] only when no native work can
///   access it;
/// - return [`NativePresentationCompletion::Complete`] only after the exact
///   submission's native completion fence proves the surface is no longer used;
/// - return `Ok(())` from [`Self::quiesce_presentation`] only after every
///   native operation initiated through this backend can no longer access an
///   outstanding presentation surface;
/// - make the backend's own destructor synchronize or abort all native work.
///   The coordinator's destructor cannot safely invoke fallible provider code
///   and therefore retains an unquiesced surface rather than releasing it.
pub trait RenderBackend {
    fn name(&self) -> &'static str;
    fn present(
        &mut self,
        submission: PresentationSubmissionGuard,
    ) -> Result<PresentSubmission, RenderFailure>;
    /// Returns this exact submission's native completion state.
    fn poll_present_completion(
        &mut self,
        submission: &PresentSubmission,
    ) -> Result<NativePresentationCompletion, PlatformError>;
    /// Quiesces every native presentation operation this renderer initiated.
    fn quiesce_presentation(&mut self) -> Result<(), PlatformError>;
    fn set_cursor(&mut self, cursor: CursorUpdate<'_>) -> Result<(), PlatformError>;
    fn diagnostics(&self) -> ProviderDiagnostics;
}

/// Stable diagnostics surfaced to users and benchmark artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDiagnostics {
    pub provider: String,
    pub state: ProviderState,
    pub adapter: Option<String>,
    pub format: Option<String>,
    pub import_path: Option<ImportPath>,
    pub queue_depth: usize,
    pub dropped: u64,
    pub last_error: Option<String>,
}

impl ProviderDiagnostics {
    #[must_use]
    pub fn idle(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            state: ProviderState::Idle,
            adapter: None,
            format: None,
            import_path: None,
            queue_depth: 0,
            dropped: 0,
            last_error: None,
        }
    }
}

/// One decoded surface eligible for presentation.
#[derive(Debug)]
pub struct PresentableFrame {
    pub surface: EpochBoundSurface,
    pub codec_epoch: u32,
    pub frame_id: u64,
    pub ready_ns: u64,
    pub deadline_ns: u64,
    pub recovery_point: bool,
}

impl PresentableFrame {
    #[must_use]
    pub const fn display_epoch(&self) -> u32 {
        self.surface.display_epoch()
    }

    pub fn validate(&self) -> Result<(), PlatformError> {
        if self.deadline_ns <= self.ready_ns {
            return Err(PlatformError::InvalidDeadline);
        }
        self.surface.validate()
    }

    fn preflight(&self) -> Result<PresentationPreflight, PlatformError> {
        Ok(PresentationPreflight {
            descriptor: self
                .surface
                .surface()
                .descriptor()
                .map_err(|_| PlatformError::InvalidSurface)?,
            display_epoch: self.display_epoch(),
            codec_epoch: self.codec_epoch,
            frame_id: self.frame_id,
            ready_ns: self.ready_ns,
            deadline_ns: self.deadline_ns,
            recovery_point: self.recovery_point,
        })
    }
}

/// Copyable metadata available before the native surface is submitted.
///
/// It intentionally omits [`OwnedSurface`], so a renderer cannot begin native
/// access and still return a pre-submission [`RenderFailure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationPreflight {
    pub descriptor: FrameDescriptor,
    pub display_epoch: u32,
    pub codec_epoch: u32,
    pub frame_id: u64,
    pub ready_ns: u64,
    pub deadline_ns: u64,
    pub recovery_point: bool,
}

/// Unforgeable-within-safe-Rust identity for one coordinator-owned lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PresentationLeaseIdentity {
    coordinator_id: u64,
    lease_id: u64,
}

static NEXT_PRESENTATION_COORDINATOR_ID: AtomicU64 = AtomicU64::new(1);

fn next_presentation_coordinator_id() -> Option<u64> {
    loop {
        let current = NEXT_PRESENTATION_COORDINATOR_ID.load(Ordering::Relaxed);
        if current == 0 {
            return None;
        }
        let next = current.checked_add(1).unwrap_or(0);
        if NEXT_PRESENTATION_COORDINATOR_ID
            .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Some(current);
        }
    }
}

/// Native completion state for the exact submission supplied to a renderer.
///
/// Only the coordinator that owns that submission may release its surface. A
/// provider's `Complete` declaration is valid only after its native fence has
/// completed; enforcement of that FFI/GPU condition belongs to the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativePresentationCompletion {
    Pending,
    Complete,
}

/// Opaque coordinator-owned lease for exactly one queued frame.
#[derive(Debug)]
struct PresentationLease {
    identity: PresentationLeaseIdentity,
    frame: PresentableFrame,
    preflight: PresentationPreflight,
}

impl PresentationLease {
    fn new(
        identity: PresentationLeaseIdentity,
        frame: PresentableFrame,
    ) -> Result<Self, PlatformError> {
        frame.validate()?;
        let preflight = frame.preflight()?;
        Ok(Self {
            identity,
            frame,
            preflight,
        })
    }
}

/// Fail-closed handoff of one presentation surface to a native renderer.
///
/// The guard leaks its bounded lease if it is dropped without an explicit
/// [`Self::submit`] or [`Self::reject`] transition. This prevents unwind or an
/// accidental early return from releasing a surface after native submission.
#[derive(Debug)]
pub struct PresentationSubmissionGuard {
    lease: Option<PresentationLease>,
}

impl PresentationSubmissionGuard {
    fn new(lease: PresentationLease) -> Self {
        Self { lease: Some(lease) }
    }

    fn take_lease(&mut self) -> PresentationLease {
        self.lease
            .take()
            .expect("presentation submission guard must contain its lease")
    }

    /// Returns copied metadata for preflight only. Native surface access begins
    /// only after [`Self::submit`] transfers the lease into a submission token.
    #[must_use]
    pub fn preflight(&self) -> PresentationPreflight {
        self.lease
            .as_ref()
            .expect("presentation submission guard must contain its lease")
            .preflight
    }

    /// Records that native submission accepted this exact guarded surface.
    pub fn submit(
        mut self,
        submit_ns: u64,
        queue_depth_after_submit: usize,
    ) -> Result<PresentSubmission, RenderFailure> {
        if let Err(error) = self
            .lease
            .as_ref()
            .expect("presentation submission guard must contain its lease")
            .frame
            .validate()
        {
            return Err(RenderFailure {
                error,
                lease: self.take_lease(),
            });
        }
        Ok(PresentSubmission {
            lease: Some(self.take_lease()),
            submit_ns,
            queue_depth_after_submit,
        })
    }

    /// Returns the exact surface only when no native operation can access it.
    #[must_use]
    pub fn reject(mut self, error: PlatformError) -> RenderFailure {
        RenderFailure {
            error,
            lease: self.take_lease(),
        }
    }
}

impl Drop for PresentationSubmissionGuard {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            std::mem::forget(lease);
        }
    }
}
/// Provider-local confirmation of native present submission, never scanout.
///
/// An unreturned submission retains its bounded surface on drop. Only the
/// coordinator's proven completion or quiescence path may release it.
#[must_use = "the coordinator must retain the submission until native completion"]
#[derive(Debug)]
pub struct PresentSubmission {
    lease: Option<PresentationLease>,
    pub submit_ns: u64,
    pub queue_depth_after_submit: usize,
}

impl PresentSubmission {
    fn lease(&self) -> &PresentationLease {
        self.lease
            .as_ref()
            .expect("present submission must contain its lease until release")
    }

    /// Native access is deliberately unavailable until the guard has entered
    /// the submitted state, so a pre-submission rejection cannot release a
    /// surface that native work has already received.
    #[must_use]
    pub fn frame(&self) -> &PresentableFrame {
        &self.lease().frame
    }

    #[must_use]
    pub fn id(&self) -> u64 {
        self.lease().identity.lease_id
    }

    fn identity(&self) -> PresentationLeaseIdentity {
        self.lease().identity
    }

    fn into_lease(mut self) -> PresentationLease {
        self.lease
            .take()
            .expect("present submission must contain its lease until release")
    }

    fn release(mut self) {
        drop(
            self.lease
                .take()
                .expect("present submission must contain its lease until release"),
        );
    }
}

impl Drop for PresentSubmission {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            std::mem::forget(lease);
        }
    }
}

/// A renderer's terminal pre-submission failure.
#[derive(Debug)]
pub struct RenderFailure {
    error: PlatformError,
    lease: PresentationLease,
}

/// Bounded newest-frame presentation queue.
#[derive(Debug)]
pub struct PresentationQueue {
    capacity: usize,
    items: VecDeque<PresentableFrame>,
    latest_epoch: Option<(u32, u32)>,
    latest_frame_id: Option<u64>,
    stats: PresentationQueueStats,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationQueueStats {
    pub accepted: u64,
    pub dropped_expired: u64,
    pub dropped_stale: u64,
    pub dropped_capacity: u64,
    pub high_watermark: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePushOutcome {
    Queued,
    RejectedExpired,
    RejectedStale,
    QueuedAfterDroppingOldest,
}

impl PresentationQueue {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "presentation capacity must be nonzero");
        assert!(capacity <= 16, "presentation queue must stay shallow");
        Self {
            capacity,
            items: VecDeque::with_capacity(capacity),
            latest_epoch: None,
            latest_frame_id: None,
            stats: PresentationQueueStats::default(),
        }
    }

    pub fn push(
        &mut self,
        frame: PresentableFrame,
        now_ns: u64,
    ) -> Result<QueuePushOutcome, PlatformError> {
        frame.validate()?;
        if frame.deadline_ns <= now_ns {
            self.stats.dropped_expired = self.stats.dropped_expired.saturating_add(1);
            return Ok(QueuePushOutcome::RejectedExpired);
        }
        let epoch = (frame.display_epoch(), frame.codec_epoch);
        let stale = match self.latest_epoch {
            Some(latest) if epoch < latest => true,
            Some(latest) if epoch == latest => self
                .latest_frame_id
                .is_some_and(|latest_id| frame.frame_id <= latest_id),
            _ => false,
        };
        if stale {
            self.stats.dropped_stale = self.stats.dropped_stale.saturating_add(1);
            return Ok(QueuePushOutcome::RejectedStale);
        }
        if self.latest_epoch.is_some_and(|latest| epoch > latest) {
            self.drop_queued();
        }
        self.latest_epoch = Some(epoch);
        self.latest_frame_id = Some(frame.frame_id);
        let outcome = if self.items.len() == self.capacity {
            let _ = self.items.pop_front();
            self.stats.dropped_capacity = self.stats.dropped_capacity.saturating_add(1);
            QueuePushOutcome::QueuedAfterDroppingOldest
        } else {
            QueuePushOutcome::Queued
        };
        self.items.push_back(frame);
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        self.stats.high_watermark = self.stats.high_watermark.max(self.items.len());
        Ok(outcome)
    }

    /// Removes expired frames and returns the newest remaining frame. All older
    /// queued frames are dropped, preventing presentation backlog growth.
    pub fn pop_newest(&mut self, now_ns: u64) -> Result<Option<PresentableFrame>, PlatformError> {
        let mut dropped_expired = 0_u64;
        self.items.retain(|frame| {
            if frame.deadline_ns <= now_ns {
                dropped_expired = dropped_expired.saturating_add(1);
                false
            } else {
                true
            }
        });
        self.stats.dropped_expired = self.stats.dropped_expired.saturating_add(dropped_expired);
        let Some(newest) = self.items.pop_back() else {
            return Ok(None);
        };
        self.drop_queued();
        newest.validate()?;
        Ok(Some(newest))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[must_use]
    pub const fn stats(&self) -> PresentationQueueStats {
        self.stats
    }

    fn drop_queued(&mut self) {
        let dropped = self.items.len() as u64;
        self.items.clear();
        self.stats.dropped_capacity = self.stats.dropped_capacity.saturating_add(dropped);
    }

    fn reset_continuity(&mut self, epoch: Option<(u32, u32)>) {
        self.drop_queued();
        self.latest_epoch = epoch;
        self.latest_frame_id = None;
    }
}

/// Provider-confirmed native submission identity and timing.
///
/// `submit_ns` records provider submission, never display scanout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentReceipt {
    pub display_epoch: u32,
    pub codec_epoch: u32,
    pub frame_id: u64,
    pub submit_ns: u64,
    pub queue_depth_after_submit: usize,
}

/// Concrete action taken when a decoded frame reaches the presentation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationAction {
    Queued(QueuePushOutcome),
    Presented(PresentReceipt),
    AwaitingCompletion,
    Idle,
}

/// Completion state for the one native submission retained by the coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationCompletion {
    Idle,
    Pending,
    Released,
}

/// A submitted frame can be completion-polled. A proof mismatch, unproven
/// return, or interrupted handoff requires verified renderer quiescence before
/// the coordinator can resume; its surface remains retained.
#[derive(Debug)]
enum InFlightPresentation {
    Submitted(PresentSubmission),
    #[allow(dead_code)]
    RequiresQuiescence(PresentSubmission),
    Unproven(PresentationLease),
    HandoffInProgress,
}

impl InFlightPresentation {
    fn epochs(&self) -> Option<(u32, u32)> {
        match self {
            Self::Submitted(submission) | Self::RequiresQuiescence(submission) => {
                let frame = &submission.lease().frame;
                Some((frame.display_epoch(), frame.codec_epoch))
            }
            Self::Unproven(lease) => Some((lease.frame.display_epoch(), lease.frame.codec_epoch)),
            Self::HandoffInProgress => None,
        }
    }

    fn requires_quiesce(&self) -> bool {
        !matches!(self, Self::Submitted(_))
    }

    #[allow(dead_code)]
    fn into_requires_quiescence(self) -> Self {
        match self {
            Self::Submitted(submission) => Self::RequiresQuiescence(submission),
            other => other,
        }
    }

    fn finalize_after_quiesce(self) {
        match self {
            Self::Submitted(submission) | Self::RequiresQuiescence(submission) => {
                submission.release()
            }
            Self::Unproven(lease) => std::mem::forget(lease),
            Self::HandoffInProgress => {}
        }
    }
}

/// Owns one renderer and its sole native submission lifetime.
///
/// Call [`Self::shutdown`] before normal teardown. If a caller drops this
/// coordinator with an unquiesced submission, its `Drop` implementation leaks
/// the bounded surface rather than risking a native-use-after-release.
#[derive(Debug)]
pub struct PresentationCoordinator<R> {
    renderer: R,
    queue: PresentationQueue,
    in_flight: Option<InFlightPresentation>,
    coordinator_id: Option<u64>,
    next_lease_id: Option<u64>,
    cursor_mode: CursorMode,
    stats: PresentationCoordinatorStats,
}

impl<R> Drop for PresentationCoordinator<R> {
    fn drop(&mut self) {
        if let Some(in_flight) = self.in_flight.take() {
            std::mem::forget(in_flight);
        }
    }
}

/// Presentation decisions suitable for bounded telemetry and benchmarks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationCoordinatorStats {
    pub accepted: u64,
    pub rejected_expired: u64,
    pub rejected_stale: u64,
    pub rendered: u64,
    pub completed: u64,
    pub cancelled: u64,
    pub blocked_in_flight: u64,
    pub recovery_required: u64,
    pub renderer_failures: u64,
    pub epoch_resets: u64,
}

impl<R: RenderBackend> PresentationCoordinator<R> {
    /// Creates the v0.1 single-slot newest-frame presentation boundary.
    #[must_use]
    pub fn new(renderer: R) -> Self {
        Self::with_cursor_mode(renderer, CursorMode::Metadata)
    }

    /// Creates a presentation boundary with its session-wide cursor policy.
    #[must_use]
    pub fn with_cursor_mode(renderer: R, cursor_mode: CursorMode) -> Self {
        Self {
            renderer,
            queue: PresentationQueue::new(1),
            in_flight: None,
            coordinator_id: next_presentation_coordinator_id(),
            next_lease_id: Some(1),
            cursor_mode,
            stats: PresentationCoordinatorStats::default(),
        }
    }

    /// Takes ownership of a decoded surface and queues it only if it can still
    /// be presented in the current display/codec continuity generation.
    pub fn submit(
        &mut self,
        frame: PresentableFrame,
        now_ns: u64,
    ) -> Result<PresentationAction, PlatformError> {
        if frame.display_epoch() == 0 || frame.codec_epoch == 0 {
            return Err(PlatformError::InvalidState);
        }
        if self
            .in_flight
            .as_ref()
            .is_some_and(InFlightPresentation::requires_quiesce)
        {
            return Err(PlatformError::PresentationRecoveryRequired);
        }
        let incoming_epoch = (frame.display_epoch(), frame.codec_epoch);
        if self.in_flight.as_ref().is_some_and(|in_flight| {
            in_flight
                .epochs()
                .is_some_and(|epoch| incoming_epoch > epoch)
        }) {
            return Err(PlatformError::PresentationInFlight);
        }
        let previous_epoch = self.queue.latest_epoch;
        let outcome = self.queue.push(frame, now_ns)?;
        match outcome {
            QueuePushOutcome::Queued | QueuePushOutcome::QueuedAfterDroppingOldest => {
                self.stats.accepted = self.stats.accepted.saturating_add(1);
                if previous_epoch.is_some_and(|epoch| incoming_epoch > epoch) {
                    self.stats.epoch_resets = self.stats.epoch_resets.saturating_add(1);
                }
            }
            QueuePushOutcome::RejectedExpired => {
                self.stats.rejected_expired = self.stats.rejected_expired.saturating_add(1);
            }
            QueuePushOutcome::RejectedStale => {
                self.stats.rejected_stale = self.stats.rejected_stale.saturating_add(1);
            }
        }
        Ok(PresentationAction::Queued(outcome))
    }

    /// Submits the newest non-expired frame to this coordinator's native
    /// renderer. `submit_ns` is provider submission time, never scanout time.
    pub fn present_next(&mut self, now_ns: u64) -> Result<PresentationAction, PlatformError> {
        if let Some(in_flight) = self.in_flight.as_ref() {
            if in_flight.requires_quiesce() {
                return Err(PlatformError::PresentationRecoveryRequired);
            }
            self.stats.blocked_in_flight = self.stats.blocked_in_flight.saturating_add(1);
            return Ok(PresentationAction::AwaitingCompletion);
        }
        let Some(frame) = self.queue.pop_newest(now_ns)? else {
            return Ok(PresentationAction::Idle);
        };
        frame.validate()?;
        let coordinator_id = self
            .coordinator_id
            .ok_or(PlatformError::PresentationLeaseExhausted)?;
        let lease_id = self
            .next_lease_id
            .ok_or(PlatformError::PresentationLeaseExhausted)?;
        self.next_lease_id = lease_id.checked_add(1);
        let identity = PresentationLeaseIdentity {
            coordinator_id,
            lease_id,
        };
        let display_epoch = frame.display_epoch();
        let codec_epoch = frame.codec_epoch;
        let frame_id = frame.frame_id;
        let lease = PresentationLease::new(identity, frame)?;
        self.in_flight = Some(InFlightPresentation::HandoffInProgress);
        let submission = catch_unwind(AssertUnwindSafe(|| {
            self.renderer
                .present(PresentationSubmissionGuard::new(lease))
        }));
        match submission {
            Ok(Ok(submission)) => {
                if submission.identity() != identity {
                    self.in_flight = Some(InFlightPresentation::Unproven(submission.into_lease()));
                    self.stats.recovery_required = self.stats.recovery_required.saturating_add(1);
                    self.stats.renderer_failures = self.stats.renderer_failures.saturating_add(1);
                    return Err(PlatformError::RendererReturnedMismatchedLease);
                }
                let receipt = PresentReceipt {
                    display_epoch,
                    codec_epoch,
                    frame_id,
                    submit_ns: submission.submit_ns,
                    queue_depth_after_submit: submission.queue_depth_after_submit,
                };
                self.in_flight = Some(InFlightPresentation::Submitted(submission));
                self.stats.rendered = self.stats.rendered.saturating_add(1);
                Ok(PresentationAction::Presented(receipt))
            }
            Ok(Err(RenderFailure { error, lease })) => {
                if lease.identity != identity {
                    self.in_flight = Some(InFlightPresentation::Unproven(lease));
                    self.stats.recovery_required = self.stats.recovery_required.saturating_add(1);
                    self.stats.renderer_failures = self.stats.renderer_failures.saturating_add(1);
                    Err(PlatformError::RendererReturnedMismatchedLease)
                } else {
                    self.in_flight = None;
                    drop(lease);
                    self.stats.renderer_failures = self.stats.renderer_failures.saturating_add(1);
                    Err(error)
                }
            }
            Err(_) => {
                self.stats.recovery_required = self.stats.recovery_required.saturating_add(1);
                self.stats.renderer_failures = self.stats.renderer_failures.saturating_add(1);
                Err(PlatformError::RendererPanicked)
            }
        }
    }

    /// Polls this coordinator's renderer before releasing the sole in-flight
    /// surface. Provider-contract violations require explicit quiescence.
    pub fn poll_present_completion(&mut self) -> Result<PresentationCompletion, PlatformError> {
        let completion = {
            let (renderer, in_flight) = (&mut self.renderer, &self.in_flight);
            match in_flight.as_ref() {
                None => return Ok(PresentationCompletion::Idle),
                Some(InFlightPresentation::RequiresQuiescence(_))
                | Some(InFlightPresentation::Unproven(_))
                | Some(InFlightPresentation::HandoffInProgress) => {
                    return Err(PlatformError::PresentationRecoveryRequired);
                }
                Some(InFlightPresentation::Submitted(submission)) => {
                    renderer.poll_present_completion(submission)
                }
            }
        };
        let completion = match completion {
            Ok(completion) => completion,
            Err(error) => {
                self.stats.renderer_failures = self.stats.renderer_failures.saturating_add(1);
                return Err(error);
            }
        };
        if completion == NativePresentationCompletion::Pending {
            return Ok(PresentationCompletion::Pending);
        }
        let Some(InFlightPresentation::Submitted(submission)) = self.in_flight.take() else {
            return Err(PlatformError::InvalidState);
        };
        submission.release();
        self.stats.completed = self.stats.completed.saturating_add(1);
        Ok(PresentationCompletion::Released)
    }

    /// Requires native quiescence before releasing an in-flight surface during
    /// a device, display, decoder, or provider-contract recovery path.
    pub fn cancel_in_flight(&mut self) -> Result<bool, PlatformError> {
        if self.in_flight.is_none() {
            return Ok(false);
        }
        match self.renderer.quiesce_presentation() {
            Ok(()) => {}
            Err(error) => {
                self.stats.renderer_failures = self.stats.renderer_failures.saturating_add(1);
                return Err(error);
            }
        }
        if let Some(in_flight) = self.in_flight.take() {
            in_flight.finalize_after_quiesce();
        }
        self.stats.cancelled = self.stats.cancelled.saturating_add(1);
        Ok(true)
    }

    #[allow(dead_code)]
    fn require_in_flight_quiescence(&mut self) {
        if let Some(in_flight) = self.in_flight.take() {
            self.in_flight = Some(in_flight.into_requires_quiescence());
        }
    }

    /// Quiesces native presentation and releases all queued, non-submitted
    /// surfaces before normal teardown.
    pub fn shutdown(&mut self) -> Result<(), PlatformError> {
        self.cancel_in_flight()?;
        self.queue.reset_continuity(None);
        Ok(())
    }

    /// Explicitly changes display or decoder continuity. Pending frames belong
    /// to the old epoch and are dropped before this method returns. A caller
    /// must quiesce and cancel any native submission first.
    pub fn reset_epochs(
        &mut self,
        display_epoch: u32,
        codec_epoch: u32,
    ) -> Result<(), PlatformError> {
        if let Some(in_flight) = self.in_flight.as_ref() {
            return Err(if in_flight.requires_quiesce() {
                PlatformError::PresentationRecoveryRequired
            } else {
                PlatformError::PresentationInFlight
            });
        }
        if display_epoch == 0 || codec_epoch == 0 {
            return Err(PlatformError::InvalidState);
        }
        self.queue
            .reset_continuity(Some((display_epoch, codec_epoch)));
        self.stats.epoch_resets = self.stats.epoch_resets.saturating_add(1);
        Ok(())
    }
    /// Forwards local cursor metadata only when the session negotiated metadata
    /// cursor rendering; embedded and hidden cursor modes accept no overlay.
    pub fn set_cursor(&mut self, cursor: CursorUpdate<'_>) -> Result<(), PlatformError> {
        if self.cursor_mode != CursorMode::Metadata {
            return Err(PlatformError::CursorModeConflict);
        }
        self.renderer.set_cursor(cursor)
    }

    #[must_use]
    pub const fn cursor_mode(&self) -> CursorMode {
        self.cursor_mode
    }

    #[must_use]
    pub fn diagnostics(&self) -> ProviderDiagnostics {
        self.renderer.diagnostics()
    }

    #[must_use]
    pub fn has_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    #[must_use]
    pub const fn queue_stats(&self) -> PresentationQueueStats {
        self.queue.stats()
    }

    #[must_use]
    pub const fn stats(&self) -> PresentationCoordinatorStats {
        self.stats
    }
}

/// Cursor mode negotiated with capture/render providers.
///
/// The active mode is fixed for a session: local metadata rendering and an
/// embedded video cursor are mutually exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorMode {
    Embedded,
    Metadata,
    Hidden,
}

/// Borrowed cursor update. Shape payload is strictly bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorUpdate<'a> {
    pub cursor_id: u64,
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub width: u16,
    pub height: u16,
    pub rgba: Option<&'a [u8]>,
}

impl CursorUpdate<'_> {
    pub const MAX_DIMENSION: u16 = 512;
    pub const MAX_BYTES: usize = 512 * 512 * 4;

    pub fn validate(&self) -> Result<(), PlatformError> {
        if self.width > Self::MAX_DIMENSION || self.height > Self::MAX_DIMENSION {
            return Err(PlatformError::CursorBounds);
        }
        if let Some(rgba) = self.rgba {
            let expected = usize::from(self.width)
                .checked_mul(usize::from(self.height))
                .and_then(|pixels| pixels.checked_mul(4))
                .ok_or(PlatformError::CursorBounds)?;
            if rgba.len() != expected || rgba.len() > Self::MAX_BYTES {
                return Err(PlatformError::CursorBounds);
            }
        }
        Ok(())
    }
}

/// Output rotation used for capture/input coordinate conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    R0,
    R90,
    R180,
    R270,
}

/// Provider-neutral transform for absolute pointer coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinateTransform {
    pub source_width: u32,
    pub source_height: u32,
    pub target_width: u32,
    pub target_height: u32,
    pub rotation: Rotation,
}

impl CoordinateTransform {
    pub fn map(self, x: u32, y: u32) -> Result<(u32, u32), PlatformError> {
        if self.source_width == 0
            || self.source_height == 0
            || self.target_width == 0
            || self.target_height == 0
            || x >= self.source_width
            || y >= self.source_height
        {
            return Err(PlatformError::CoordinateBounds);
        }
        let (rotated_x, rotated_y, rotated_width, rotated_height) = match self.rotation {
            Rotation::R0 => (x, y, self.source_width, self.source_height),
            Rotation::R90 => (
                self.source_height - 1 - y,
                x,
                self.source_height,
                self.source_width,
            ),
            Rotation::R180 => (
                self.source_width - 1 - x,
                self.source_height - 1 - y,
                self.source_width,
                self.source_height,
            ),
            Rotation::R270 => (
                y,
                self.source_width - 1 - x,
                self.source_height,
                self.source_width,
            ),
        };
        Ok((
            scale_coordinate(rotated_x, rotated_width, self.target_width),
            scale_coordinate(rotated_y, rotated_height, self.target_height),
        ))
    }
}

fn scale_coordinate(value: u32, source: u32, target: u32) -> u32 {
    if source <= 1 || target <= 1 {
        return 0;
    }
    let numerator = u64::from(value) * u64::from(target - 1);
    (numerator / u64::from(source - 1)) as u32
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    InvalidIdentity,
    InvalidPeerAlias,
    InvalidPeerPin,
    InvalidState,
    InvalidSurface,
    InvalidDeadline,
    QueueFull,
    AccessLost,
    PermissionDenied,
    PermissionRevoked,
    Unsupported,
    DeviceLost,
    CursorBounds,
    CoordinateBounds,
    PresentationInFlight,
    PresentationRecoveryRequired,
    PresentationLeaseExhausted,
    CursorModeConflict,
    RendererReturnedMismatchedLease,
    RendererPanicked,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PlatformError {}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_media::{
        CopyEvidenceGrade, CopyLedger, DeviceIdentity, ImportPath, LeaseCompletion, MemoryDomain,
        SourceLeaseIdentity, SurfaceLayout, SynchronizationProof, TransferEdge,
    };
    use latencydesk_surface::SurfacePool;
    use std::sync::Arc;

    #[derive(Default)]
    struct RecordingRenderer {
        presented: Vec<u64>,
        completion_ids: Vec<u64>,
        cursor_updates: u64,
        fail: bool,
        panic_after_submit: bool,
        fail_completion: bool,
        quiesce_fail: bool,
        complete: bool,
        revoke_before_submit: Option<Arc<AtomicBool>>,
        quiesce_calls: u64,
        returned_lease: Option<PresentationLease>,
        returned_submission: Option<PresentSubmission>,
    }

    impl RenderBackend for RecordingRenderer {
        fn name(&self) -> &'static str {
            "recording-renderer"
        }

        fn present(
            &mut self,
            submission: PresentationSubmissionGuard,
        ) -> Result<PresentSubmission, RenderFailure> {
            if self.panic_after_submit {
                let _submission = submission.submit(10, 0).expect("live authorization");
                panic!("recording renderer panics after native submission");
            }
            if self.fail {
                if let Some(returned_lease) = self.returned_lease.take() {
                    drop(submission);
                    return Err(RenderFailure {
                        error: PlatformError::DeviceLost,
                        lease: returned_lease,
                    });
                }
                return Err(submission.reject(PlatformError::DeviceLost));
            }
            if let Some(returned_submission) = self.returned_submission.take() {
                drop(submission);
                return Ok(returned_submission);
            }
            let preflight = submission.preflight();
            if let Some(authorization) = self.revoke_before_submit.take() {
                authorization.store(false, Ordering::Release);
            }
            let submission = submission.submit(10, 0)?;
            self.presented.push(preflight.frame_id);
            Ok(submission)
        }

        fn poll_present_completion(
            &mut self,
            submission: &PresentSubmission,
        ) -> Result<NativePresentationCompletion, PlatformError> {
            self.completion_ids.push(submission.id());
            if self.fail_completion {
                Err(PlatformError::DeviceLost)
            } else if self.complete {
                Ok(NativePresentationCompletion::Complete)
            } else {
                Ok(NativePresentationCompletion::Pending)
            }
        }

        fn quiesce_presentation(&mut self) -> Result<(), PlatformError> {
            self.quiesce_calls = self.quiesce_calls.saturating_add(1);
            if self.quiesce_fail {
                Err(PlatformError::DeviceLost)
            } else {
                self.complete = true;
                Ok(())
            }
        }

        fn set_cursor(&mut self, cursor: CursorUpdate<'_>) -> Result<(), PlatformError> {
            cursor.validate()?;
            self.cursor_updates = self.cursor_updates.saturating_add(1);
            Ok(())
        }

        fn diagnostics(&self) -> ProviderDiagnostics {
            ProviderDiagnostics::idle(self.name())
        }
    }

    fn presentable(pool: &SurfacePool, frame_id: u64, deadline_ns: u64) -> PresentableFrame {
        presentable_with_epoch(pool, frame_id, deadline_ns, 1)
    }

    fn presentable_with_epoch(
        pool: &SurfacePool,
        frame_id: u64,
        deadline_ns: u64,
        display_epoch: u32,
    ) -> PresentableFrame {
        presentable_with_authorization(pool, frame_id, deadline_ns, display_epoch).0
    }

    fn presentable_with_authorization(
        pool: &SurfacePool,
        frame_id: u64,
        deadline_ns: u64,
        display_epoch: u32,
    ) -> (PresentableFrame, Arc<AtomicBool>) {
        let descriptor = FrameDescriptor {
            width: 100,
            height: 50,
            format_fourcc: 0,
            memory_domain: MemoryDomain::Cpu,
            capture_sequence: frame_id,
            capture_timestamp_ns: 0,
        };
        let ledger = CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: display_epoch,
                capture_sequence: descriptor.capture_sequence,
            },
            source_device: DeviceIdentity::Unknown,
            destination_device: DeviceIdentity::Unknown,
            source_layout: SurfaceLayout {
                memory_domain: descriptor.memory_domain,
                format_fourcc: descriptor.format_fourcc,
                plane_count: 1,
                modifier: None,
            },
            destination_layout: SurfaceLayout {
                memory_domain: descriptor.memory_domain,
                format_fourcc: descriptor.format_fourcc,
                plane_count: 1,
                modifier: None,
            },
            transfer_edge: TransferEdge::DecodeToPresenter,
            path: ImportPath::CpuCopy,
            synchronization: SynchronizationProof::CpuSynchronous,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: CopyEvidenceGrade::CompletionProven,
        };
        let owned = pool
            .acquire_capture(descriptor)
            .expect("lease")
            .import(ledger)
            .expect("owned");
        let authorization = Arc::new(AtomicBool::new(true));
        let surface = CaptureFramePublisher::new()
            .bind(owned, Arc::clone(&authorization))
            .expect("epoch-bound surface");
        (
            PresentableFrame {
                surface,
                codec_epoch: 1,
                frame_id,
                ready_ns: 1,
                deadline_ns,
                recovery_point: frame_id == 1,
            },
            authorization,
        )
    }

    #[test]
    fn encoder_submission_retains_exact_epoch_bound_surface_until_release() {
        let pool = SurfacePool::new(1);
        let (frame, _) = presentable_with_authorization(&pool, 7, 100, 3);
        let guard = EncoderSubmissionGuard::new(frame.surface);

        assert_eq!(guard.preflight().display_epoch, 3);
        assert_eq!(guard.preflight().descriptor.capture_sequence, 7);
        let submission = guard.submit().expect("live frame submits");
        assert_eq!(submission.frame().display_epoch(), 3);
        assert_eq!(pool.in_use(), 1);

        submission.release();
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn encoder_submission_rejects_revoked_frame_without_native_handoff() {
        let pool = SurfacePool::new(1);
        let (frame, authorization) = presentable_with_authorization(&pool, 7, 100, 3);
        let guard = EncoderSubmissionGuard::new(frame.surface);
        authorization.store(false, Ordering::Release);

        let failure = guard.submit().expect_err("revoked frame rejects");
        assert_eq!(failure.error, PlatformError::PermissionRevoked);
        assert_eq!(
            failure.into_frame().validate(),
            Err(PlatformError::PermissionRevoked)
        );
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn retained_frame_authorization_closes_before_later_admission() {
        let pool = SurfacePool::new(1);
        let (frame, authorization) = presentable_with_authorization(&pool, 1, 100, 1);

        authorization.store(false, Ordering::Release);

        assert_eq!(frame.validate(), Err(PlatformError::PermissionRevoked));
        assert_eq!(pool.in_use(), 1);
        drop(frame);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn queued_frame_revoked_before_present_is_rejected() {
        let pool = SurfacePool::new(1);
        let (frame, authorization) = presentable_with_authorization(&pool, 1, 100, 1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator.submit(frame, 2).expect("live frame queues");

        authorization.store(false, Ordering::Release);

        assert_eq!(
            coordinator.present_next(3),
            Err(PlatformError::PermissionRevoked)
        );
        assert!(coordinator.renderer.presented.is_empty());
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn revocation_at_renderer_submission_admission_fails_closed() {
        let pool = SurfacePool::new(1);
        let (frame, authorization) = presentable_with_authorization(&pool, 1, 100, 1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator.submit(frame, 2).expect("live frame queues");
        coordinator.renderer.revoke_before_submit = Some(authorization);

        assert_eq!(
            coordinator.present_next(3),
            Err(PlatformError::PermissionRevoked)
        );
        assert!(coordinator.renderer.presented.is_empty());
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn queue_returns_newest_and_releases_older_surfaces() {
        let pool = SurfacePool::new(4);
        let mut queue = PresentationQueue::new(3);
        for frame_id in 1..=3 {
            queue
                .push(presentable(&pool, frame_id, 100), 2)
                .expect("push");
        }
        let newest = queue
            .pop_newest(3)
            .expect("valid queued frame")
            .expect("newest");
        assert_eq!(newest.frame_id, 3);
        assert_eq!(queue.len(), 0);
        assert_eq!(pool.in_use(), 1);
        drop(newest);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn queue_drops_expired_newest_frame_when_deadlines_are_nonmonotonic() {
        let pool = SurfacePool::new(2);
        let mut queue = PresentationQueue::new(2);
        queue
            .push(presentable(&pool, 1, 100), 2)
            .expect("live frame queues");
        queue
            .push(presentable(&pool, 2, 3), 2)
            .expect("not-yet-expired frame queues");

        let newest = queue
            .pop_newest(4)
            .expect("valid queued frame")
            .expect("live frame remains");

        assert_eq!(newest.frame_id, 1);
        assert_eq!(queue.stats().dropped_expired, 1);
        drop(newest);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn coordinate_rotation_is_bounded() {
        let transform = CoordinateTransform {
            source_width: 1920,
            source_height: 1080,
            target_width: 1080,
            target_height: 1920,
            rotation: Rotation::R90,
        };
        assert_eq!(transform.map(0, 0).expect("map"), (1079, 0));
        assert_eq!(transform.map(1919, 1079).expect("map"), (0, 1919));
    }

    #[test]
    fn cursor_payload_must_match_dimensions() {
        let update = CursorUpdate {
            cursor_id: 1,
            visible: true,
            x: 0,
            y: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 2,
            height: 2,
            rgba: Some(&[0; 15]),
        };
        assert_eq!(update.validate(), Err(PlatformError::CursorBounds));
    }

    #[test]
    fn embedded_cursor_mode_rejects_local_cursor_metadata() {
        let mut coordinator = PresentationCoordinator::with_cursor_mode(
            RecordingRenderer::default(),
            CursorMode::Embedded,
        );
        let update = CursorUpdate {
            cursor_id: 1,
            visible: true,
            x: 0,
            y: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 1,
            height: 1,
            rgba: Some(&[0; 4]),
        };

        assert_eq!(
            coordinator.set_cursor(update),
            Err(PlatformError::CursorModeConflict)
        );
        assert_eq!(coordinator.renderer.cursor_updates, 0);
    }

    #[test]
    fn metadata_cursor_mode_forwards_valid_local_cursor_metadata() {
        let mut coordinator = PresentationCoordinator::with_cursor_mode(
            RecordingRenderer::default(),
            CursorMode::Metadata,
        );
        let update = CursorUpdate {
            cursor_id: 1,
            visible: true,
            x: 0,
            y: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 1,
            height: 1,
            rgba: Some(&[0; 4]),
        };

        assert_eq!(coordinator.set_cursor(update), Ok(()));
        assert_eq!(coordinator.renderer.cursor_updates, 1);
    }

    #[test]
    fn coordinator_retains_the_newest_surface_until_native_completion() {
        let pool = SurfacePool::new(3);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        assert_eq!(
            coordinator.submit(presentable(&pool, 1, 100), 2),
            Ok(PresentationAction::Queued(QueuePushOutcome::Queued))
        );
        assert_eq!(
            coordinator.submit(presentable(&pool, 2, 100), 2),
            Ok(PresentationAction::Queued(
                QueuePushOutcome::QueuedAfterDroppingOldest
            ))
        );
        assert_eq!(coordinator.queue_stats().high_watermark, 1);
        assert_eq!(
            coordinator.present_next(3),
            Ok(PresentationAction::Presented(PresentReceipt {
                display_epoch: 1,
                codec_epoch: 1,
                frame_id: 2,
                submit_ns: 10,
                queue_depth_after_submit: 0,
            }))
        );
        assert_eq!(coordinator.renderer.presented, vec![2]);
        assert!(coordinator.has_in_flight());
        assert_eq!(pool.in_use(), 1);
        assert_eq!(
            coordinator.poll_present_completion(),
            Ok(PresentationCompletion::Pending)
        );
        assert_eq!(coordinator.renderer.completion_ids, vec![1]);
        assert_eq!(pool.in_use(), 1);
        coordinator.renderer.complete = true;
        assert_eq!(
            coordinator.poll_present_completion(),
            Ok(PresentationCompletion::Released)
        );
        assert!(!coordinator.has_in_flight());
        assert_eq!(pool.in_use(), 0);
        assert_eq!(coordinator.stats().rendered, 1);
        assert_eq!(coordinator.stats().completed, 1);
    }

    #[test]
    fn coordinator_rejects_stale_frame_without_handing_it_to_renderer() {
        let pool = SurfacePool::new(2);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator
            .submit(presentable(&pool, 2, 100), 2)
            .expect("first frame queues");
        assert_eq!(
            coordinator.submit(presentable(&pool, 1, 100), 2),
            Ok(PresentationAction::Queued(QueuePushOutcome::RejectedStale))
        );
        coordinator.present_next(3).expect("newest frame presents");
        assert_eq!(coordinator.renderer.presented, vec![2]);
        assert_eq!(coordinator.stats().rejected_stale, 1);
        coordinator.renderer.complete = true;
        assert_eq!(
            coordinator.poll_present_completion(),
            Ok(PresentationCompletion::Released)
        );
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn coordinator_rejects_zero_epoch_before_queueing() {
        let pool = SurfacePool::new(1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        let mut invalid = presentable(&pool, 1, 100);
        invalid.surface.display_epoch = 0;
        assert_eq!(
            coordinator.submit(invalid, 2),
            Err(PlatformError::InvalidState)
        );
        assert_eq!(coordinator.queue_stats().accepted, 0);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn coordinator_rejects_epoch_relabel_that_disagrees_with_surface_ledger() {
        let pool = SurfacePool::new(1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        let mut invalid = presentable(&pool, 1, 100);
        invalid.surface.display_epoch = 2;

        assert_eq!(
            coordinator.submit(invalid, 2),
            Err(PlatformError::InvalidSurface)
        );
        assert_eq!(coordinator.queue_stats().accepted, 0);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn coordinator_drops_queued_frames_on_epoch_change() {
        let pool = SurfacePool::new(2);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("first frame queues");
        let next_epoch = presentable_with_epoch(&pool, 2, 100, 2);
        assert_eq!(
            coordinator.submit(next_epoch, 2),
            Ok(PresentationAction::Queued(QueuePushOutcome::Queued))
        );
        assert_eq!(
            coordinator.present_next(3),
            Ok(PresentationAction::Presented(PresentReceipt {
                display_epoch: 2,
                codec_epoch: 1,
                frame_id: 2,
                submit_ns: 10,
                queue_depth_after_submit: 0,
            }))
        );
        assert_eq!(coordinator.renderer.presented, vec![2]);
        assert_eq!(coordinator.stats().epoch_resets, 1);
        coordinator.renderer.complete = true;
        assert_eq!(
            coordinator.poll_present_completion(),
            Ok(PresentationCompletion::Released)
        );
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn explicit_epoch_reset_accepts_a_reinitialized_stream() {
        let pool = SurfacePool::new(2);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        let mut previous_stream_frame = presentable_with_epoch(&pool, 8, 100, 9);
        previous_stream_frame.codec_epoch = 5;
        coordinator
            .submit(previous_stream_frame, 2)
            .expect("previous stream frame queues");
        coordinator
            .reset_epochs(1, 1)
            .expect("new stream establishes its epochs");
        assert_eq!(
            coordinator.submit(presentable(&pool, 1, 100), 2),
            Ok(PresentationAction::Queued(QueuePushOutcome::Queued))
        );
        assert_eq!(
            coordinator.present_next(3),
            Ok(PresentationAction::Presented(PresentReceipt {
                display_epoch: 1,
                codec_epoch: 1,
                frame_id: 1,
                submit_ns: 10,
                queue_depth_after_submit: 0,
            }))
        );
        assert_eq!(coordinator.renderer.presented, vec![1]);
        coordinator.renderer.complete = true;
        assert_eq!(
            coordinator.poll_present_completion(),
            Ok(PresentationCompletion::Released)
        );
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn pre_submission_failure_returns_the_surface_without_quiescing() {
        let pool = SurfacePool::new(1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer {
            fail: true,
            ..RecordingRenderer::default()
        });
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("frame queues");
        assert_eq!(coordinator.present_next(3), Err(PlatformError::DeviceLost));
        assert_eq!(coordinator.stats().renderer_failures, 1);
        assert_eq!(coordinator.renderer.quiesce_calls, 0);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn coordinator_waits_for_native_completion_before_submitting_next_frame() {
        let pool = SurfacePool::new(2);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("first frame queues");
        coordinator.present_next(3).expect("first frame submits");
        coordinator
            .submit(presentable(&pool, 2, 100), 4)
            .expect("second frame queues");
        assert_eq!(
            coordinator.present_next(5),
            Ok(PresentationAction::AwaitingCompletion)
        );
        assert_eq!(coordinator.renderer.presented, vec![1]);
        assert_eq!(pool.in_use(), 2);
        coordinator.renderer.complete = true;
        assert_eq!(
            coordinator.poll_present_completion(),
            Ok(PresentationCompletion::Released)
        );
        assert_eq!(pool.in_use(), 1);
        coordinator.present_next(6).expect("second frame submits");
        assert_eq!(coordinator.renderer.presented, vec![1, 2]);
        assert_eq!(coordinator.stats().blocked_in_flight, 1);
        assert_eq!(pool.in_use(), 1);
        assert_eq!(
            coordinator.poll_present_completion(),
            Ok(PresentationCompletion::Released)
        );
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn completion_error_preserves_the_submitted_surface_for_retry() {
        let pool = SurfacePool::new(1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("frame queues");
        coordinator.present_next(3).expect("frame submits");
        coordinator.renderer.fail_completion = true;
        assert_eq!(
            coordinator.poll_present_completion(),
            Err(PlatformError::DeviceLost)
        );
        assert!(coordinator.has_in_flight());
        assert_eq!(pool.in_use(), 1);
        coordinator.renderer.fail_completion = false;
        coordinator.renderer.complete = true;
        assert_eq!(
            coordinator.poll_present_completion(),
            Ok(PresentationCompletion::Released)
        );
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn failed_quiescence_preserves_the_submitted_surface_for_retry() {
        let pool = SurfacePool::new(1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("frame queues");
        coordinator.present_next(3).expect("frame submits");
        coordinator.renderer.quiesce_fail = true;
        assert_eq!(
            coordinator.cancel_in_flight(),
            Err(PlatformError::DeviceLost)
        );
        assert!(coordinator.has_in_flight());
        assert_eq!(pool.in_use(), 1);
        coordinator.renderer.quiesce_fail = false;
        assert_eq!(coordinator.cancel_in_flight(), Ok(true));
        assert_eq!(coordinator.renderer.quiesce_calls, 2);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn epoch_reset_requires_native_quiescence_before_releasing_in_flight_surface() {
        let pool = SurfacePool::new(1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("frame queues");
        coordinator.present_next(3).expect("frame submits");
        assert_eq!(
            coordinator.reset_epochs(2, 1),
            Err(PlatformError::PresentationInFlight)
        );
        assert_eq!(pool.in_use(), 1);
        assert_eq!(coordinator.cancel_in_flight(), Ok(true));
        assert_eq!(coordinator.renderer.quiesce_calls, 1);
        assert_eq!(coordinator.stats().cancelled, 1);
        assert_eq!(pool.in_use(), 0);
        assert_eq!(coordinator.reset_epochs(2, 1), Ok(()));
    }

    #[test]
    fn foreign_success_with_same_local_lease_id_requires_fail_closed_recovery() {
        let pool = SurfacePool::new(3);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        let foreign_identity = PresentationLeaseIdentity {
            coordinator_id: coordinator
                .coordinator_id
                .expect("coordinator identity")
                .checked_add(1)
                .unwrap_or(1),
            lease_id: 1,
        };
        let returned_submission = PresentationSubmissionGuard::new(
            PresentationLease::new(foreign_identity, presentable(&pool, 2, 100))
                .expect("valid test surface"),
        )
        .submit(10, 0)
        .expect("live foreign submission");
        coordinator.renderer.returned_submission = Some(returned_submission);
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("frame queues");
        assert_eq!(
            coordinator.present_next(3),
            Err(PlatformError::RendererReturnedMismatchedLease)
        );
        assert!(coordinator.has_in_flight());
        assert_eq!(coordinator.stats().recovery_required, 1);
        assert_eq!(coordinator.stats().renderer_failures, 1);
        assert_eq!(
            coordinator.submit(presentable(&pool, 3, 100), 4),
            Err(PlatformError::PresentationRecoveryRequired)
        );
        assert_eq!(pool.in_use(), 2);
        assert_eq!(
            coordinator.poll_present_completion(),
            Err(PlatformError::PresentationRecoveryRequired)
        );
        assert_eq!(coordinator.cancel_in_flight(), Ok(true));
        assert_eq!(coordinator.renderer.quiesce_calls, 1);
        assert_eq!(pool.in_use(), 2);
    }

    #[test]
    fn foreign_failure_with_same_local_lease_id_requires_fail_closed_recovery() {
        let pool = SurfacePool::new(2);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer {
            fail: true,
            ..RecordingRenderer::default()
        });
        let foreign_identity = PresentationLeaseIdentity {
            coordinator_id: coordinator
                .coordinator_id
                .expect("coordinator identity")
                .checked_add(1)
                .unwrap_or(1),
            lease_id: 1,
        };
        coordinator.renderer.returned_lease = Some(
            PresentationLease::new(foreign_identity, presentable(&pool, 2, 100))
                .expect("valid test surface"),
        );
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("frame queues");
        assert_eq!(
            coordinator.present_next(3),
            Err(PlatformError::RendererReturnedMismatchedLease)
        );
        assert!(coordinator.has_in_flight());
        assert_eq!(coordinator.stats().recovery_required, 1);
        assert_eq!(coordinator.stats().renderer_failures, 1);
        assert_eq!(pool.in_use(), 2);
        assert_eq!(coordinator.cancel_in_flight(), Ok(true));
        assert_eq!(coordinator.renderer.quiesce_calls, 1);
        assert_eq!(pool.in_use(), 2);
    }

    #[test]
    fn panic_after_native_submission_requires_quiescence_and_retains_surface() {
        let pool = SurfacePool::new(2);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer {
            panic_after_submit: true,
            ..RecordingRenderer::default()
        });
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("frame queues");

        assert_eq!(
            coordinator.present_next(3),
            Err(PlatformError::RendererPanicked)
        );
        assert!(coordinator.has_in_flight());
        assert_eq!(coordinator.stats().recovery_required, 1);
        assert_eq!(coordinator.stats().renderer_failures, 1);
        assert_eq!(
            coordinator.poll_present_completion(),
            Err(PlatformError::PresentationRecoveryRequired)
        );
        assert_eq!(
            coordinator.submit(presentable(&pool, 2, 100), 4),
            Err(PlatformError::PresentationRecoveryRequired)
        );
        assert_eq!(coordinator.cancel_in_flight(), Ok(true));
        assert_eq!(coordinator.renderer.quiesce_calls, 1);
        assert_eq!(pool.in_use(), 1);
    }

    #[test]
    fn shutdown_quiesces_before_releasing_an_in_flight_surface() {
        let pool = SurfacePool::new(1);
        let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
        coordinator
            .submit(presentable(&pool, 1, 100), 2)
            .expect("frame queues");
        coordinator.present_next(3).expect("frame submits");
        assert_eq!(coordinator.shutdown(), Ok(()));
        assert_eq!(coordinator.renderer.quiesce_calls, 1);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn dropping_an_unquiesced_coordinator_retains_its_surface() {
        let pool = SurfacePool::new(1);
        {
            let mut coordinator = PresentationCoordinator::new(RecordingRenderer::default());
            coordinator
                .submit(presentable(&pool, 1, 100), 2)
                .expect("frame queues");
            coordinator.present_next(3).expect("frame submits");
            assert_eq!(pool.in_use(), 1);
        }
        assert_eq!(pool.in_use(), 1);
    }
}
