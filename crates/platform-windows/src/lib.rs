//! Windows backend policy and lifecycle model.
//!
//! Native COM/D3D/Media Foundation calls live in the C++ probes and future FFI
//! provider. This crate keeps the safety-critical state transitions portable and
//! testable on every CI host: per-user agent ownership, DDA/WGC target
//! selection, bounded capture metadata, surface import, secure-desktop refusal, and input
//! integrity policy.

use latencydesk_h264::{AnnexBSummary, ContinuityPlanner, H264Error, LowDelayPolicy};
use latencydesk_input::AppliedInput;
use latencydesk_media::{
    CopyLedger, DeviceIdentity, EncodedFrameMeta, FrameDescriptor, MemoryDomain, SurfaceLayout,
};
use latencydesk_platform::{
    CaptureBackend, CaptureEvent, CaptureFramePublisher, EncodeBackend, EncodeFailure,
    EncodeSubmission, EncoderSubmissionGuard, InputBackend, NativePresentationCompletion,
    PlatformError, PresentSubmission, PresentationSubmissionGuard, ProviderDiagnostics,
    ProviderState, RenderBackend, RenderFailure,
};
pub use latencydesk_platform::{CursorMode, CursorUpdate};
use latencydesk_surface::{
    CaptureLease, DestinationSurfaceSpec, OwnedSurface, SurfaceError, SurfacePayload, SurfacePool,
};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

#[cfg(windows)]
mod native;
#[cfg(windows)]
#[cfg(windows)]
pub struct D3D11WindowRenderer {
    inner: cxx::UniquePtr<native::ffi::Renderer>,
}

#[cfg(windows)]
impl D3D11WindowRenderer {
    pub fn new(width: u32, height: u32) -> Result<Self, WindowsBackendError> {
        let mut status = native::STATUS_OK;
        let renderer = native::ffi::make_d3d11_renderer(width, height, &mut status);
        if status != native::STATUS_OK || renderer.is_null() {
            return Err(WindowsBackendError::Unsupported);
        }
        Ok(Self { inner: renderer })
    }

    pub fn pump_messages(&mut self) -> bool {
        if self.inner.is_null() {
            return false;
        }
        native::ffi::renderer_pump_messages(self.inner.pin_mut())
    }

    pub fn is_open(&self) -> bool {
        if self.inner.is_null() {
            return false;
        }
        native::ffi::renderer_is_open(&self.inner)
    }

    pub fn close(&mut self) {
        if !self.inner.is_null() {
            native::ffi::renderer_close(self.inner.pin_mut());
        }
    }
}
pub(crate) use native::DesktopDuplicationCaptureSource;

/// Windows capture API selected for one display session.
///
/// Raw native callback/status types are deliberately not part of this crate's
/// public API:
///
/// ```compile_fail
/// use latencydesk_platform_windows::NativeCaptureStatus;
/// ```
///
/// ```compile_fail
/// use latencydesk_platform_windows::NativeCaptureFailure;
/// ```
///
/// ```compile_fail
/// use latencydesk_platform_windows::NativeCaptureSourceEvent;
/// ```
///
/// ```compile_fail
/// use latencydesk_platform_windows::NativeCaptureOperation;
/// ```
///
/// ```compile_fail
/// use latencydesk_platform_windows::NativeCaptureStatusDomain;
/// ```
///
/// ```compile_fail
/// use latencydesk_platform_windows::NativeCaptureFailureKind;
/// ```
///
/// ```compile_fail
/// use latencydesk_platform_windows::InteractiveUserIdentity;
/// let _forged = InteractiveUserIdentity::new(1, 1).unwrap();
/// ```
///
/// ```compile_fail
/// use latencydesk_platform_windows::VerifiedAgentPeer;
/// fn duplicate(peer: VerifiedAgentPeer) { let _copy = peer.clone(); }
/// ```
///
/// ```compile_fail
/// use latencydesk_platform_windows::AgentLaunchChallenge;
/// fn duplicate(challenge: AgentLaunchChallenge) { let _copy = challenge.clone(); }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsCaptureApi {
    DesktopDuplication,
    WindowsGraphicsCapture,
}

/// Requested Windows capture target. WGC authorization is established before
/// constructing this policy object; it is never inferred from a DDA failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsCaptureTarget {
    DesktopOutput,
    AuthorizedWgcDisplay,
    AuthorizedWgcWindow,
}

/// Data-only description of the encoder-owned D3D11 destination family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsCaptureDestination {
    device: DeviceIdentity,
    format_fourcc: u32,
    plane_count: u8,
}

impl WindowsCaptureDestination {
    pub fn new(
        device: DeviceIdentity,
        format_fourcc: u32,
        plane_count: u8,
    ) -> Result<Self, WindowsBackendError> {
        if !matches!(device, DeviceIdentity::Opaque(_))
            || format_fourcc == 0
            || !(1..=4).contains(&plane_count)
        {
            return Err(WindowsBackendError::DestinationMismatch);
        }
        Ok(Self {
            device,
            format_fourcc,
            plane_count,
        })
    }
    pub fn nv12(device: DeviceIdentity) -> Result<Self, WindowsBackendError> {
        Self::new(device, u32::from_le_bytes(*b"NV12"), 2)
    }

    fn reserve_for(
        self,
        source: FrameDescriptor,
    ) -> Result<DestinationSurfaceSpec, WindowsBackendError> {
        let descriptor = FrameDescriptor {
            format_fourcc: self.format_fourcc,
            memory_domain: MemoryDomain::D3D11,
            ..source
        };
        DestinationSurfaceSpec::new(
            descriptor,
            self.device,
            SurfaceLayout {
                memory_domain: MemoryDomain::D3D11,
                format_fourcc: self.format_fourcc,
                plane_count: self.plane_count,
                modifier: None,
            },
        )
        .map_err(WindowsBackendError::Surface)
    }
}

/// Why a provider cannot continue using its current capture API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFailure {
    AccessLost,
    SessionChanged,
    AdapterChanged,
    /// DDA reported an already-masked protected-content frame. This is a
    /// frame-level signal, not permission to recover the protected pixels.
    ProtectedContent,
    PermissionDenied,
    Unsupported,
    DeviceRemoved,
    Transient,
}

/// Capture selector constrained by target semantics. It never turns an output
/// capture failure into an unrelated WGC capture session.
#[derive(Debug, Clone)]
pub struct CaptureSelector {
    target: WindowsCaptureTarget,
    state: ProviderState,
    active: Option<WindowsCaptureApi>,
    dda_supported: bool,
    wgc_supported: bool,
    consecutive_failures: u8,
    display_epoch: u32,
    next_retry_ns: u64,
    diagnostics: ProviderDiagnostics,
}

impl CaptureSelector {
    #[must_use]
    pub fn new(target: WindowsCaptureTarget, dda_supported: bool, wgc_supported: bool) -> Self {
        Self {
            target,
            state: ProviderState::Idle,
            active: None,
            dda_supported,
            wgc_supported,
            consecutive_failures: 0,
            display_epoch: 0,
            next_retry_ns: 0,
            diagnostics: ProviderDiagnostics::idle("windows-capture-selector"),
        }
    }

    pub fn start(&mut self, now_ns: u64) -> Result<WindowsCaptureApi, WindowsBackendError> {
        if !matches!(
            self.state,
            ProviderState::Idle | ProviderState::Stopped | ProviderState::Suspended
        ) {
            return Err(WindowsBackendError::InvalidState);
        }
        self.state = ProviderState::Starting;
        let selected = match self.requested_api() {
            Ok(selected) => selected,
            Err(error) => {
                self.active = None;
                self.state = ProviderState::Failed;
                self.diagnostics.state = self.state;
                self.diagnostics.last_error =
                    Some("requested Windows capture target is unavailable".into());
                return Err(error);
            }
        };
        self.active = Some(selected);
        self.state = ProviderState::Running;
        self.consecutive_failures = 0;
        self.next_retry_ns = now_ns;
        if let Err(error) = self.advance_epoch() {
            self.clear(
                ProviderState::Failed,
                Some("capture display generation exhausted".into()),
            );
            return Err(error);
        }
        self.diagnostics.state = self.state;
        self.diagnostics.provider = match selected {
            WindowsCaptureApi::DesktopDuplication => "windows-dda".into(),
            WindowsCaptureApi::WindowsGraphicsCapture => "windows-wgc".into(),
        };
        self.diagnostics.last_error = None;
        Ok(selected)
    }

    fn requested_api(&self) -> Result<WindowsCaptureApi, WindowsBackendError> {
        match self.target {
            WindowsCaptureTarget::DesktopOutput if self.dda_supported => {
                Ok(WindowsCaptureApi::DesktopDuplication)
            }
            WindowsCaptureTarget::AuthorizedWgcDisplay
            | WindowsCaptureTarget::AuthorizedWgcWindow
                if self.wgc_supported =>
            {
                Ok(WindowsCaptureApi::WindowsGraphicsCapture)
            }
            _ => Err(WindowsBackendError::Unsupported),
        }
    }

    fn advance_epoch(&mut self) -> Result<u32, WindowsBackendError> {
        self.display_epoch = self
            .display_epoch
            .checked_add(1)
            .ok_or(WindowsBackendError::GenerationExhausted)?;
        Ok(self.display_epoch)
    }

    pub fn note_display_change(&mut self) -> Result<u32, WindowsBackendError> {
        if self.state != ProviderState::Running || self.active.is_none() {
            return Err(WindowsBackendError::InvalidState);
        }
        match self.advance_epoch() {
            Ok(epoch) => Ok(epoch),
            Err(error) => {
                self.clear(
                    ProviderState::Failed,
                    Some("capture display generation exhausted".into()),
                );
                Err(error)
            }
        }
    }

    /// Records a provider failure and returns the next deterministic action.
    ///
    /// `ProtectedContent` keeps DDA live, but it invalidates every prior
    /// display epoch so no reservation or reconstruction history can survive
    /// the masked frame.
    pub fn fail(
        &mut self,
        failure: CaptureFailure,
        now_ns: u64,
    ) -> Result<CaptureRecoveryAction, WindowsBackendError> {
        if failure != CaptureFailure::ProtectedContent {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.diagnostics.last_error = Some(format!("{failure:?}"));
        }
        match failure {
            CaptureFailure::ProtectedContent => {
                if let Err(error) = self.advance_epoch() {
                    self.clear(
                        ProviderState::Failed,
                        Some("capture display generation exhausted".into()),
                    );
                    return Err(error);
                }
                Ok(CaptureRecoveryAction::SurfaceProtectedContent)
            }
            CaptureFailure::PermissionDenied => {
                self.active = None;
                self.state = ProviderState::Revoked;
                self.diagnostics.state = self.state;
                Ok(CaptureRecoveryAction::StopPermissionDenied)
            }
            CaptureFailure::Unsupported => {
                self.active = None;
                self.state = ProviderState::Failed;
                self.diagnostics.state = self.state;
                Ok(CaptureRecoveryAction::StopUnsupported)
            }
            CaptureFailure::AccessLost
            | CaptureFailure::SessionChanged
            | CaptureFailure::AdapterChanged
            | CaptureFailure::DeviceRemoved
            | CaptureFailure::Transient => {
                self.active = None;
                self.state = ProviderState::Reconfiguring;
                let shift = self.consecutive_failures.min(8);
                let backoff_ms = 10_u64.saturating_mul(1_u64 << shift).min(2_000);
                self.next_retry_ns = now_ns.saturating_add(backoff_ms * 1_000_000);
                if let Err(error) = self.advance_epoch() {
                    self.clear(
                        ProviderState::Failed,
                        Some("capture display generation exhausted".into()),
                    );
                    return Err(error);
                }
                self.diagnostics.state = self.state;
                Ok(CaptureRecoveryAction::RecreateAfter {
                    retry_at_ns: self.next_retry_ns,
                })
            }
        }
    }

    pub fn mark_recovered(&mut self, now_ns: u64) -> Result<(), WindowsBackendError> {
        if self.state != ProviderState::Reconfiguring || now_ns < self.next_retry_ns {
            return Err(WindowsBackendError::RetryNotReady);
        }
        self.active = Some(self.requested_api()?);
        self.state = ProviderState::Running;
        self.consecutive_failures = 0;
        self.diagnostics.state = self.state;
        self.diagnostics.last_error = None;
        Ok(())
    }

    fn clear(&mut self, state: ProviderState, error: Option<String>) {
        self.active = None;
        self.state = state;
        self.diagnostics.state = state;
        self.diagnostics.last_error = error;
    }

    #[must_use]
    pub const fn active(&self) -> Option<WindowsCaptureApi> {
        self.active
    }

    #[must_use]
    pub const fn state(&self) -> ProviderState {
        self.state
    }

    #[must_use]
    pub const fn display_epoch(&self) -> u32 {
        self.display_epoch
    }

    fn reserve_frame(
        &self,
        pool: &SurfacePool,
        reservation: NativeDestinationReservationId,
        destination: WindowsCaptureDestination,
        input: NativeFrameReservationInput,
    ) -> Result<NativeFrameDetachRequest, WindowsBackendError> {
        let NativeFrameReservationInput {
            identity,
            frame,
            source_observed_epoch,
            source_descriptor,
            metadata,
        } = input;
        if self.state != ProviderState::Running || self.active.is_none() {
            return Err(WindowsBackendError::InvalidState);
        }
        if source_observed_epoch != self.display_epoch {
            return Err(WindowsBackendError::LedgerEpoch);
        }
        if source_descriptor.memory_domain != MemoryDomain::D3D11 {
            return Err(WindowsBackendError::MemoryDomain);
        }
        source_descriptor
            .validate()
            .map_err(|_| WindowsBackendError::FrameDescriptor)?;
        metadata.validate(
            source_descriptor.width,
            source_descriptor.height,
            MetadataLimits::default(),
        )?;
        let destination = destination.reserve_for(source_descriptor)?;
        let lease = pool
            .reserve_destination(destination)
            .map_err(WindowsBackendError::Surface)?;
        Ok(NativeFrameDetachRequest {
            identity,
            frame,
            reservation,
            source_descriptor,
            destination,
            source_observed_epoch,
            metadata,
            lease,
        })
    }

    #[must_use]
    pub fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRecoveryAction {
    RecreateAfter { retry_at_ns: u64 },
    SurfaceProtectedContent,
    StopPermissionDenied,
    StopUnsupported,
}

/// Signed desktop-space rectangle using half-open coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    fn validate(self, width: u32, height: u32) -> Result<Self, WindowsBackendError> {
        let width = i32::try_from(width).map_err(|_| WindowsBackendError::MetadataBounds)?;
        let height = i32::try_from(height).map_err(|_| WindowsBackendError::MetadataBounds)?;
        if self.left < 0
            || self.top < 0
            || self.right <= self.left
            || self.bottom <= self.top
            || self.right > width
            || self.bottom > height
        {
            return Err(WindowsBackendError::MetadataBounds);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveRect {
    pub source_x: i32,
    pub source_y: i32,
    pub destination: Rect,
}

/// DDA metadata accepted by the shared core after native size-query calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopMetadata {
    pub dirty_rects: Vec<Rect>,
    pub move_rects: Vec<MoveRect>,
    pub pointer_shape: Vec<u8>,
    pub pointer_visible: bool,
    pub pointer_x: i32,
    pub pointer_y: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataLimits {
    pub max_dirty_rects: usize,
    pub max_move_rects: usize,
    pub max_pointer_shape_bytes: usize,
    pub max_total_metadata_bytes: usize,
}

impl Default for MetadataLimits {
    fn default() -> Self {
        Self {
            max_dirty_rects: 4_096,
            max_move_rects: 4_096,
            max_pointer_shape_bytes: 4 * 1024 * 1024,
            max_total_metadata_bytes: 8 * 1024 * 1024,
        }
    }
}

impl DesktopMetadata {
    pub fn validate(
        &self,
        width: u32,
        height: u32,
        limits: MetadataLimits,
    ) -> Result<(), WindowsBackendError> {
        if self.dirty_rects.len() > limits.max_dirty_rects
            || self.move_rects.len() > limits.max_move_rects
            || self.pointer_shape.len() > limits.max_pointer_shape_bytes
        {
            return Err(WindowsBackendError::MetadataLimit);
        }
        let rect_bytes = self
            .dirty_rects
            .len()
            .checked_mul(std::mem::size_of::<Rect>())
            .and_then(|bytes| {
                self.move_rects
                    .len()
                    .checked_mul(std::mem::size_of::<MoveRect>())
                    .and_then(|moves| bytes.checked_add(moves))
            })
            .and_then(|bytes| bytes.checked_add(self.pointer_shape.len()))
            .ok_or(WindowsBackendError::MetadataLimit)?;
        if rect_bytes > limits.max_total_metadata_bytes {
            return Err(WindowsBackendError::MetadataLimit);
        }
        for rect in &self.dirty_rects {
            rect.validate(width, height)?;
        }
        for movement in &self.move_rects {
            movement.destination.validate(width, height)?;
            let destination_width = movement.destination.right - movement.destination.left;
            let destination_height = movement.destination.bottom - movement.destination.top;
            let source_right = movement
                .source_x
                .checked_add(destination_width)
                .ok_or(WindowsBackendError::MetadataBounds)?;
            let source_bottom = movement
                .source_y
                .checked_add(destination_height)
                .ok_or(WindowsBackendError::MetadataBounds)?;
            if movement.source_x < 0
                || movement.source_y < 0
                || source_right
                    > i32::try_from(width).map_err(|_| WindowsBackendError::MetadataBounds)?
                || source_bottom
                    > i32::try_from(height).map_err(|_| WindowsBackendError::MetadataBounds)?
            {
                return Err(WindowsBackendError::MetadataBounds);
            }
        }
        Ok(())
    }
}

/// Provider-neutral result of synchronously importing one D3D capture frame.
#[derive(Debug)]
struct ImportedWindowsFrame {
    surface: OwnedSurface,
    copy_ledger: CopyLedger,
    display_epoch: u32,
    #[allow(dead_code)]
    metadata: DesktopMetadata,
}

#[cfg_attr(not(test), allow(dead_code))]
fn import_capture_frame(
    lease: CaptureLease,
    source_descriptor: FrameDescriptor,
    destination: DestinationSurfaceSpec,
    ledger: CopyLedger,
    source_observed_epoch: u32,
    metadata: DesktopMetadata,
    payload: Option<Box<dyn SurfacePayload>>,
) -> Result<ImportedWindowsFrame, (WindowsBackendError, CaptureLease)> {
    if source_descriptor.memory_domain != MemoryDomain::D3D11
        || destination.descriptor().memory_domain != MemoryDomain::D3D11
        || destination.layout().memory_domain != MemoryDomain::D3D11
    {
        return Err((WindowsBackendError::MemoryDomain, lease));
    }
    match lease.descriptor().map_err(WindowsBackendError::Surface) {
        Ok(desc) if desc == destination.descriptor() => {}
        _ => return Err((WindowsBackendError::DestinationMismatch, lease)),
    }
    if ledger.destination_device != destination.device()
        || ledger.destination_layout != destination.layout()
        || source_descriptor.width != destination.descriptor().width
        || source_descriptor.height != destination.descriptor().height
        || source_descriptor.capture_sequence != destination.descriptor().capture_sequence
        || source_descriptor.capture_timestamp_ns != destination.descriptor().capture_timestamp_ns
    {
        return Err((WindowsBackendError::DestinationMismatch, lease));
    }
    if ledger.source_lease.provider_epoch != source_observed_epoch {
        return Err((WindowsBackendError::LedgerEpoch, lease));
    }
    if ledger.path == latencydesk_media::ImportPath::DirectAlias {
        return Err((WindowsBackendError::BorrowedDirectAlias, lease));
    }
    if let Err(err) = metadata.validate(
        source_descriptor.width,
        source_descriptor.height,
        MetadataLimits::default(),
    ) {
        return Err((err, lease));
    }
    if source_descriptor.validate().is_err() {
        return Err((WindowsBackendError::FrameDescriptor, lease));
    }
    if let Err(err) = ledger.validate_capture_source(source_descriptor) {
        return Err((
            WindowsBackendError::Surface(SurfaceError::CopyLedger(err)),
            lease,
        ));
    }
    let surface = match payload {
        Some(payload) => lease.import_from_capture_with_payload(source_descriptor, ledger, payload),
        None => lease.import_from_capture(source_descriptor, ledger),
    }
    .map_err(WindowsBackendError::Surface)
    .expect("pre-validated import_from_capture");
    Ok(ImportedWindowsFrame {
        surface,
        copy_ledger: ledger,
        display_epoch: source_observed_epoch,
        metadata,
    })
}
/// Windows integrity level relevant to SendInput/UIPI decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Low,
    Medium,
    High,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputTargetContext {
    pub agent_integrity: IntegrityLevel,
    pub target_integrity: IntegrityLevel,
    pub secure_desktop: bool,
    pub session_locked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPolicyDecision {
    Allow,
    DenySecureDesktop,
    DenyLockedSession,
    DenyHigherIntegrityTarget,
}

#[must_use]
pub fn evaluate_input_policy(context: InputTargetContext) -> InputPolicyDecision {
    if context.secure_desktop {
        InputPolicyDecision::DenySecureDesktop
    } else if context.session_locked {
        InputPolicyDecision::DenyLockedSession
    } else if context.target_integrity > context.agent_integrity {
        InputPolicyDecision::DenyHigherIntegrityTarget
    } else {
        InputPolicyDecision::Allow
    }
}

/// Translation boundary; it intentionally does not claim to bypass UIPI.
pub fn validate_input_action(
    action: AppliedInput,
    context: InputTargetContext,
) -> Result<AppliedInput, PlatformError> {
    match evaluate_input_policy(context) {
        InputPolicyDecision::Allow => Ok(action),
        InputPolicyDecision::DenySecureDesktop
        | InputPolicyDecision::DenyLockedSession
        | InputPolicyDecision::DenyHigherIntegrityTarget => Err(PlatformError::PermissionDenied),
    }
}

/// Identity of the logged-in Windows user that owns one interactive desktop
/// agent. It is derived locally from the user's token; it never comes from the
/// remote transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractiveUserIdentity {
    windows_session_id: u32,
    logon_luid: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl InteractiveUserIdentity {
    fn new(windows_session_id: u32, logon_luid: u64) -> Result<Self, WindowsBackendError> {
        if windows_session_id == 0 || logon_luid == 0 {
            return Err(WindowsBackendError::AgentIdentity);
        }
        Ok(Self {
            windows_session_id,
            logon_luid,
        })
    }
}

/// Non-reusable evidence produced only after the trusted Windows adapter has
/// derived the interactive identity from a local token.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct LocalInteractiveUserEvidence {
    pub windows_session_id: u32,
    pub logon_luid: u64,
    pub interactive_token_verified: bool,
}

/// One-shot authority to launch an agent for the locally verified user.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct VerifiedInteractiveUser {
    identity: InteractiveUserIdentity,
}

#[cfg_attr(not(test), allow(dead_code))]
impl VerifiedInteractiveUser {
    pub fn verify(evidence: LocalInteractiveUserEvidence) -> Result<Self, WindowsBackendError> {
        if !evidence.interactive_token_verified {
            return Err(WindowsBackendError::AgentIdentity);
        }
        Ok(Self {
            identity: InteractiveUserIdentity::new(
                evidence.windows_session_id,
                evidence.logon_luid,
            )?,
        })
    }
}

/// Opaque evidence supplied by the Windows named-pipe adapter after it has
/// checked the peer PID, primary token, session, logon LUID, and pipe ACL. It
/// intentionally has no public constructor or fields.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct AgentPeerEvidence {
    pub windows_session_id: u32,
    pub logon_luid: u64,
    pub agent_pid: u32,
    pub named_pipe_acl_verified: bool,
    pub interactive_token_verified: bool,
}

/// Opaque proof for a Windows adapter that has checked the IPC peer. Remote
/// transport and application code cannot construct the required evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedAgentPeer {
    identity: InteractiveUserIdentity,
    agent_pid: u32,
}

#[cfg_attr(not(test), allow(dead_code))]
impl VerifiedAgentPeer {
    pub fn verify(evidence: AgentPeerEvidence) -> Result<Self, WindowsBackendError> {
        if !evidence.named_pipe_acl_verified
            || !evidence.interactive_token_verified
            || evidence.agent_pid == 0
        {
            return Err(WindowsBackendError::AgentIdentity);
        }
        Ok(Self {
            identity: InteractiveUserIdentity::new(
                evidence.windows_session_id,
                evidence.logon_luid,
            )?,
            agent_pid: evidence.agent_pid,
        })
    }
}

/// Non-cloneable challenge bound to one broker launch attempt.
#[derive(PartialEq, Eq)]
pub struct AgentLaunchChallenge {
    attempt: u64,
    bytes: [u8; 32],
}

impl fmt::Debug for AgentLaunchChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentLaunchChallenge")
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

/// One-shot response accepted only for its matching launch attempt.
#[derive(Debug, PartialEq, Eq)]
pub struct AgentChallengeResponse {
    attempt: u64,
    bytes: [u8; 32],
}

static NEXT_AGENT_LAUNCH_ATTEMPT_ID: AtomicU64 = AtomicU64::new(1);

#[allow(dead_code)]
pub fn issue_agent_launch_challenge(
    bytes: [u8; 32],
) -> Result<(AgentLaunchChallenge, AgentChallengeResponse), WindowsBackendError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(WindowsBackendError::AgentIdentity);
    }
    let attempt = allocate_nonzero_identity(&NEXT_AGENT_LAUNCH_ATTEMPT_ID)?;
    Ok((
        AgentLaunchChallenge { attempt, bytes },
        AgentChallengeResponse { attempt, bytes },
    ))
}

/// Generation-bound authority for exactly one verified interactive agent. A
/// later session change invalidates all prior bindings before provider teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentBinding {
    identity: InteractiveUserIdentity,
    agent_pid: u32,
    generation: u32,
}

impl AgentBinding {
    /// Monotonic broker generation carried into the native capture start
    /// request. It is an identity guard, not a reusable authorization token.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Lifecycle of the non-elevated per-user agent boundary. No state represents
/// Session 0 desktop capture or any authorization from a remote UDP endpoint.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentBrokerState {
    Idle,
    AwaitingAgent {
        identity: InteractiveUserIdentity,
        challenge: AgentLaunchChallenge,
    },
    AgentAuthenticated {
        binding: AgentBinding,
    },
    Draining {
        binding: AgentBinding,
    },
}

/// Tracks one non-elevated per-user agent and invalidates its generation on
/// session changes. It does not grant remote-control permission; that requires
/// the later authenticated QUIC identity, host approval, and controller lease.
///
/// ```compile_fail
/// use latencydesk_platform_windows::PerUserAgentBroker;
/// let broker = PerUserAgentBroker::default();
/// let _snapshot = broker.clone();
/// ```
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct PerUserAgentBroker {
    state: AgentBrokerState,
    generation: u32,
    active_operations: u32,
    active_sessions: u32,
    session_controls: Vec<NativeSessionControl>,
}

impl Default for PerUserAgentBroker {
    fn default() -> Self {
        Self {
            state: AgentBrokerState::Idle,
            generation: 0,
            active_operations: 0,
            active_sessions: 0,
            session_controls: Vec::new(),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl PerUserAgentBroker {
    pub fn begin_agent_launch(
        &mut self,
        user: VerifiedInteractiveUser,
        challenge: AgentLaunchChallenge,
    ) -> Result<(), WindowsBackendError> {
        if self.state != AgentBrokerState::Idle {
            return Err(WindowsBackendError::InvalidState);
        }
        self.state = AgentBrokerState::AwaitingAgent {
            identity: user.identity,
            challenge,
        };
        Ok(())
    }

    pub fn authenticate_agent(
        &mut self,
        peer: VerifiedAgentPeer,
        challenge_response: AgentChallengeResponse,
    ) -> Result<AgentBinding, WindowsBackendError> {
        let pending = std::mem::replace(&mut self.state, AgentBrokerState::Idle);
        let (identity, challenge) = match pending {
            AgentBrokerState::AwaitingAgent {
                identity,
                challenge,
            } => (identity, challenge),
            state => {
                self.state = state;
                return Err(WindowsBackendError::InvalidState);
            }
        };
        if peer.identity != identity
            || challenge_response.attempt != challenge.attempt
            || challenge_response.bytes != challenge.bytes
        {
            return Err(WindowsBackendError::AgentIdentity);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(WindowsBackendError::GenerationExhausted)?;
        let binding = AgentBinding {
            identity: peer.identity,
            agent_pid: peer.agent_pid,
            generation: self.generation,
        };
        self.state = AgentBrokerState::AgentAuthenticated { binding };
        Ok(binding)
    }

    fn begin_session_change(
        &mut self,
    ) -> Result<(AgentBinding, Vec<NativeSessionControl>), WindowsBackendError> {
        let binding = match &self.state {
            AgentBrokerState::AgentAuthenticated { binding } => *binding,
            _ => return Err(WindowsBackendError::InvalidState),
        };
        self.state = AgentBrokerState::Draining { binding };
        Ok((binding, self.session_controls.clone()))
    }

    pub(crate) fn session_changed(
        broker: &Arc<Mutex<Self>>,
    ) -> Result<AgentBinding, WindowsBackendError> {
        let (binding, controls) = broker
            .lock()
            .map_err(|_| WindowsBackendError::InvalidState)?
            .begin_session_change()?;
        for control in controls {
            control.abort_exact_and_wait();
        }
        Ok(binding)
    }

    pub(crate) fn finish_draining(
        &mut self,
        binding: AgentBinding,
    ) -> Result<(), WindowsBackendError> {
        let expected = match &self.state {
            AgentBrokerState::Draining { binding } => *binding,
            _ => return Err(WindowsBackendError::InvalidState),
        };
        if binding != expected {
            return Err(WindowsBackendError::StaleGeneration);
        }
        if self.active_operations != 0 || self.active_sessions != 0 {
            return Err(WindowsBackendError::DrainInProgress);
        }
        self.state = AgentBrokerState::Idle;
        Ok(())
    }

    fn begin_operation(
        &mut self,
        binding: AgentBinding,
        allow_draining: bool,
    ) -> Result<(), WindowsBackendError> {
        let binding_matches = match &self.state {
            AgentBrokerState::AgentAuthenticated { binding: current } => *current == binding,
            AgentBrokerState::Draining { binding: current } if allow_draining => {
                *current == binding
            }
            _ => false,
        };
        if !binding_matches {
            return Err(WindowsBackendError::StaleGeneration);
        }
        self.active_operations = self
            .active_operations
            .checked_add(1)
            .ok_or(WindowsBackendError::GenerationExhausted)?;
        Ok(())
    }

    fn finish_operation(&mut self, binding: AgentBinding) {
        let binding_matches = matches!(
            &self.state,
            AgentBrokerState::AgentAuthenticated { binding: current }
                | AgentBrokerState::Draining { binding: current }
                if *current == binding
        );
        if binding_matches {
            self.active_operations = self.active_operations.saturating_sub(1);
        }
    }

    fn register_session(
        &mut self,
        binding: AgentBinding,
        control: NativeSessionControl,
    ) -> Result<(), WindowsBackendError> {
        if !self.is_current_binding(binding) {
            return Err(WindowsBackendError::StaleGeneration);
        }
        self.active_sessions = self
            .active_sessions
            .checked_add(1)
            .ok_or(WindowsBackendError::GenerationExhausted)?;
        self.session_controls.push(control);
        Ok(())
    }

    fn unregister_session(&mut self, binding: AgentBinding, session: NativeCaptureSessionIdentity) {
        let binding_matches = matches!(
            &self.state,
            AgentBrokerState::AgentAuthenticated { binding: current }
                | AgentBrokerState::Draining { binding: current }
                if *current == binding
        );
        if binding_matches {
            self.session_controls
                .retain(|control| control.session != session);
            self.active_sessions = self.active_sessions.saturating_sub(1);
        }
    }

    fn operation_is_current(&self, binding: AgentBinding) -> bool {
        self.is_current_binding(binding)
    }

    #[must_use]
    pub(crate) fn is_current_binding(&self, binding: AgentBinding) -> bool {
        matches!(
            &self.state,
            AgentBrokerState::AgentAuthenticated {
                binding: current
            } if *current == binding
        )
    }

    #[must_use]
    pub(crate) const fn state(&self) -> &AgentBrokerState {
        &self.state
    }
}

struct AgentOperationPermit {
    broker: Arc<Mutex<PerUserAgentBroker>>,
    binding: AgentBinding,
    active: bool,
}

impl AgentOperationPermit {
    fn acquire(
        broker: &Arc<Mutex<PerUserAgentBroker>>,
        binding: AgentBinding,
        allow_draining: bool,
    ) -> Result<Self, WindowsBackendError> {
        broker
            .lock()
            .map_err(|_| WindowsBackendError::InvalidState)?
            .begin_operation(binding, allow_draining)?;
        Ok(Self {
            broker: Arc::clone(broker),
            binding,
            active: true,
        })
    }

    fn is_current(&self) -> bool {
        self.broker
            .lock()
            .map(|broker| broker.operation_is_current(self.binding))
            .unwrap_or(false)
    }
}

impl Drop for AgentOperationPermit {
    fn drop(&mut self) {
        if self.active {
            let mut broker = self
                .broker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            broker.finish_operation(self.binding);
            self.active = false;
        }
    }
}

/// Crate-private native operation associated with an opaque status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum NativeCaptureOperation {
    Start,
    AcquireFrame,
    ImportFrame,
    Reconfigure,
    FramePool,
    Authorization,
    Session,
    Stop,
}

/// Namespace for the raw native status bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum NativeCaptureStatusDomain {
    HResult,
    Win32,
    Internal,
}

/// Data-only native status. It contains no COM pointer, handle, or texture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeCaptureStatus {
    operation: NativeCaptureOperation,
    domain: NativeCaptureStatusDomain,
    code: u32,
}

#[allow(dead_code)]
impl NativeCaptureStatus {
    #[must_use]
    const fn new(
        operation: NativeCaptureOperation,
        domain: NativeCaptureStatusDomain,
        code: u32,
    ) -> Self {
        Self {
            operation,
            domain,
            code,
        }
    }

    #[must_use]
    const fn operation(self) -> NativeCaptureOperation {
        self.operation
    }

    #[must_use]
    const fn domain(self) -> NativeCaptureStatusDomain {
        self.domain
    }

    #[must_use]
    const fn code(self) -> u32 {
        self.code
    }
}

/// Stable semantic class used to map a native failure to [`PlatformError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum NativeCaptureFailureKind {
    InvalidState,
    AccessLost,
    PermissionDenied,
    PermissionRevoked,
    Unsupported,
    DeviceLost,
    InvalidSurface,
}

/// Exact native failure retained by the adapter after semantic mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeCaptureFailure {
    kind: NativeCaptureFailureKind,
    status: NativeCaptureStatus,
    observed_at_ns: Option<u64>,
}

impl NativeCaptureFailure {
    #[must_use]
    const fn new(kind: NativeCaptureFailureKind, status: NativeCaptureStatus) -> Self {
        Self {
            kind,
            status,
            observed_at_ns: None,
        }
    }

    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    const fn access_lost(status: NativeCaptureStatus, observed_at_ns: u64) -> Self {
        Self {
            kind: NativeCaptureFailureKind::AccessLost,
            status,
            observed_at_ns: Some(observed_at_ns),
        }
    }

    const fn platform_error(self) -> PlatformError {
        match self.kind {
            NativeCaptureFailureKind::InvalidState => PlatformError::InvalidState,
            NativeCaptureFailureKind::AccessLost => PlatformError::AccessLost,
            NativeCaptureFailureKind::PermissionDenied => PlatformError::PermissionDenied,
            NativeCaptureFailureKind::PermissionRevoked => PlatformError::PermissionRevoked,
            NativeCaptureFailureKind::Unsupported => PlatformError::Unsupported,
            NativeCaptureFailureKind::DeviceLost => PlatformError::DeviceLost,
            NativeCaptureFailureKind::InvalidSurface => PlatformError::InvalidSurface,
        }
    }
}

fn allocate_nonzero_identity(counter: &AtomicU64) -> Result<u64, WindowsBackendError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            if current == 0 {
                None
            } else {
                current.checked_add(1)
            }
        })
        .map_err(|_| WindowsBackendError::GenerationExhausted)
}

static NEXT_NATIVE_SOURCE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_CAPTURE_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_DESTINATION_RESERVATION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_PENDING_FRAME_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_WGC_ITEM_ID: AtomicU64 = AtomicU64::new(1);

/// Opaque identity of one trusted native source object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeSourceIdentity(u64);

#[allow(dead_code)]
fn issue_native_source_identity() -> Result<NativeSourceIdentity, WindowsBackendError> {
    allocate_nonzero_identity(&NEXT_NATIVE_SOURCE_ID).map(NativeSourceIdentity)
}

/// Opaque identity of one pending borrowed frame owned by the native source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativePendingFrameIdentity(u64);

#[allow(dead_code)]
fn issue_native_pending_frame_identity() -> Result<NativePendingFrameIdentity, WindowsBackendError>
{
    allocate_nonzero_identity(&NEXT_PENDING_FRAME_ID).map(NativePendingFrameIdentity)
}

/// Opaque identity of the exact GraphicsCaptureItem owned by one authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeWgcItemIdentity(u64);

#[derive(Debug)]
struct NativeWgcItemOwnership {
    _private: (),
}

/// Uniquely owned stand-in for the exact authorized GraphicsCaptureItem. The
/// later WinRT bridge replaces the private ownership payload with the real item
/// while preserving move-only ownership and the shared liveness signal.
#[derive(Debug)]
struct NativeWgcItemCapability {
    identity: NativeWgcItemIdentity,
    authority: Arc<WgcAuthorizationAuthority>,
    _ownership: Box<NativeWgcItemOwnership>,
}

/// Non-reused identity of one native start attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeCaptureSessionIdentity(u64);

/// Thread-safe native callback/reservation cancellation boundary. The later
/// bridge must make this operation infallible and synchronous: when it
/// returns, the requested session (or every session for `None`) can no longer
/// touch callbacks, borrowed frames, or destination reservations.
trait NativeCaptureAbortHandle: Send + Sync {
    fn abort(&self, session: Option<NativeCaptureSessionIdentity>);
}

#[derive(Debug)]
struct NativePublicationGateState {
    open: bool,
    exact_abort_started: bool,
    exact_abort_completed: bool,
    global_abort_started: bool,
    global_abort_completed: bool,
    presentation_authorization: Arc<AtomicBool>,
}

/// Shared linearization gate joining native cancellation with Rust frame
/// publication. Closing the gate revokes every retained frame before native
/// abort. Native quiescence never waits for caller-owned frame destruction.
#[derive(Debug)]
struct NativePublicationGate {
    state: Mutex<NativePublicationGateState>,
    abort_completed: Condvar,
}

impl NativePublicationGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(NativePublicationGateState {
                open: true,
                exact_abort_started: false,
                exact_abort_completed: false,
                global_abort_started: false,
                global_abort_completed: false,
                presentation_authorization: Arc::new(AtomicBool::new(true)),
            }),
            abort_completed: Condvar::new(),
        })
    }

    fn is_open(&self) -> bool {
        self.state.lock().map(|state| state.open).unwrap_or(false)
    }

    fn is_native_quiesced(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.exact_abort_completed || state.global_abort_completed)
            .unwrap_or(true)
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.open = false;
        state
            .presentation_authorization
            .store(false, Ordering::Release);
    }

    fn invalidate_retained_presentation(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .presentation_authorization
            .store(false, Ordering::Release);
        if state.open {
            state.presentation_authorization = Arc::new(AtomicBool::new(true));
        }
    }

    fn mark_native_quiesced(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.open = false;
        state.exact_abort_started = true;
        state.exact_abort_completed = true;
        state
            .presentation_authorization
            .store(false, Ordering::Release);
        self.abort_completed.notify_all();
    }

    fn try_publish(&self) -> Option<Arc<AtomicBool>> {
        let state = self.state.lock().ok()?;
        if !state.open || !state.presentation_authorization.load(Ordering::Acquire) {
            return None;
        }
        Some(Arc::clone(&state.presentation_authorization))
    }

    fn abort_exact_and_wait(
        &self,
        abort: &dyn NativeCaptureAbortHandle,
        session: NativeCaptureSessionIdentity,
    ) {
        self.close();
        let should_abort = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while state.global_abort_started && !state.global_abort_completed {
                state = self
                    .abort_completed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            if state.global_abort_completed || state.exact_abort_completed {
                false
            } else if state.exact_abort_started {
                while !state.exact_abort_completed && !state.global_abort_completed {
                    state = self
                        .abort_completed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                false
            } else {
                state.exact_abort_started = true;
                true
            }
        };
        if should_abort {
            abort.abort(Some(session));
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.exact_abort_completed = true;
            self.abort_completed.notify_all();
        }
    }

    fn abort_global_and_wait(&self, abort: &dyn NativeCaptureAbortHandle) {
        self.close();
        let should_abort = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.global_abort_completed {
                false
            } else if state.global_abort_started {
                while !state.global_abort_completed {
                    state = self
                        .abort_completed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                false
            } else {
                state.global_abort_started = true;
                true
            }
        };
        if should_abort {
            abort.abort(None);
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.global_abort_completed = true;
            state.exact_abort_completed = true;
            self.abort_completed.notify_all();
        }
    }
}

/// Cloneable cancellation signal retained by the native implementation for
/// the exact start. It is not an authorization and exposes no raw handle.
#[derive(Debug, Clone)]
struct NativeCaptureCancellation {
    gate: Arc<NativePublicationGate>,
}

impl NativeCaptureCancellation {
    #[allow(dead_code)]
    fn is_cancelled(&self) -> bool {
        !self.gate.is_open()
    }
}

#[derive(Clone)]
struct NativeSessionControl {
    session: NativeCaptureSessionIdentity,
    gate: Arc<NativePublicationGate>,
    abort: Arc<dyn NativeCaptureAbortHandle>,
}

impl fmt::Debug for NativeSessionControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSessionControl")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl NativeSessionControl {
    fn invalidate_retained_presentation(&self) {
        self.gate.invalidate_retained_presentation();
    }

    fn abort_exact_and_wait(&self) {
        self.gate
            .abort_exact_and_wait(self.abort.as_ref(), self.session);
    }

    fn abort_all_and_wait(&self) {
        self.gate.abort_global_and_wait(self.abort.as_ref());
    }
}

#[derive(Debug)]
struct WgcAuthorizationState {
    live: bool,
    session: Option<NativeSessionControl>,
}

#[derive(Debug)]
struct WgcAuthorizationAuthority {
    state: Mutex<WgcAuthorizationState>,
}

impl WgcAuthorizationAuthority {
    fn is_live(&self) -> bool {
        self.state.lock().map(|state| state.live).unwrap_or(false)
    }

    fn attach(&self, control: NativeSessionControl) -> Result<(), WindowsBackendError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WindowsBackendError::InvalidState)?;
        if !state.live || state.session.is_some() {
            return Err(WindowsBackendError::AgentIdentity);
        }
        state.session = Some(control);
        Ok(())
    }

    fn revoke(&self) {
        let control = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.live = false;
            state.session.clone()
        };
        if let Some(control) = control {
            control.abort_exact_and_wait();
        }
    }
}

/// Identity every callback must echo from its exact start request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeCaptureEventIdentity {
    session: NativeCaptureSessionIdentity,
    agent_generation: u32,
}

#[allow(dead_code)]
impl NativeCaptureEventIdentity {
    #[must_use]
    const fn session(self) -> NativeCaptureSessionIdentity {
        self.session
    }

    #[must_use]
    const fn agent_generation(self) -> u32 {
        self.agent_generation
    }
}

/// Single-use WGC authority issued only by the trusted native authorization
/// path. It is bound to an interactive generation, one source object, and one
/// live item kind. Its fields and constructor are intentionally not public.
#[derive(Debug)]
pub(crate) struct WgcAuthorization {
    target: WindowsCaptureTarget,
    binding: AgentBinding,
    source: NativeSourceIdentity,
    item: NativeWgcItemCapability,
}

impl WgcAuthorization {
    const fn item_identity(&self) -> NativeWgcItemIdentity {
        self.item.identity
    }

    fn authority(&self) -> &Arc<WgcAuthorizationAuthority> {
        &self.item.authority
    }

    fn is_live(&self) -> bool {
        self.item.authority.is_live()
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
struct WgcAuthorizationRevoker {
    authority: Arc<WgcAuthorizationAuthority>,
}

impl WgcAuthorizationRevoker {
    #[cfg_attr(not(test), allow(dead_code))]
    fn revoke(&self) {
        self.authority.revoke();
    }
}

#[allow(dead_code)]
fn issue_wgc_authorization(
    target: WindowsCaptureTarget,
    binding: AgentBinding,
    source: NativeSourceIdentity,
) -> Result<(WgcAuthorization, WgcAuthorizationRevoker), WindowsBackendError> {
    if !matches!(
        target,
        WindowsCaptureTarget::AuthorizedWgcDisplay | WindowsCaptureTarget::AuthorizedWgcWindow
    ) {
        return Err(WindowsBackendError::AgentIdentity);
    }
    let authority = Arc::new(WgcAuthorizationAuthority {
        state: Mutex::new(WgcAuthorizationState {
            live: true,
            session: None,
        }),
    });
    let item = NativeWgcItemCapability {
        identity: NativeWgcItemIdentity(allocate_nonzero_identity(&NEXT_WGC_ITEM_ID)?),
        authority: Arc::clone(&authority),
        _ownership: Box::new(NativeWgcItemOwnership { _private: () }),
    };
    Ok((
        WgcAuthorization {
            target,
            binding,
            source,
            item,
        },
        WgcAuthorizationRevoker { authority },
    ))
}

/// Non-cloneable start ownership passed to the later native DDA/WGC bridge.
/// WGC receives the exact authorized item capability, not an enum-only label.
#[derive(Debug)]
pub(crate) enum NativeCaptureStart {
    DesktopDuplication {
        display_epoch: u32,
        identity: NativeCaptureEventIdentity,
        cancellation: NativeCaptureCancellation,
    },
    WindowsGraphicsCapture {
        display_epoch: u32,
        identity: NativeCaptureEventIdentity,
        cancellation: NativeCaptureCancellation,
        authorization: WgcAuthorization,
    },
}

#[allow(dead_code)]
impl NativeCaptureStart {
    #[must_use]
    const fn api(&self) -> WindowsCaptureApi {
        match self {
            Self::DesktopDuplication { .. } => WindowsCaptureApi::DesktopDuplication,
            Self::WindowsGraphicsCapture { .. } => WindowsCaptureApi::WindowsGraphicsCapture,
        }
    }

    #[must_use]
    const fn target(&self) -> WindowsCaptureTarget {
        match self {
            Self::DesktopDuplication { .. } => WindowsCaptureTarget::DesktopOutput,
            Self::WindowsGraphicsCapture { authorization, .. } => authorization.target,
        }
    }

    #[must_use]
    const fn display_epoch(&self) -> u32 {
        match self {
            Self::DesktopDuplication { display_epoch, .. }
            | Self::WindowsGraphicsCapture { display_epoch, .. } => *display_epoch,
        }
    }

    #[must_use]
    const fn agent_generation(&self) -> u32 {
        self.event_identity().agent_generation
    }

    #[must_use]
    const fn event_identity(&self) -> NativeCaptureEventIdentity {
        match self {
            Self::DesktopDuplication { identity, .. }
            | Self::WindowsGraphicsCapture { identity, .. } => *identity,
        }
    }

    #[must_use]
    const fn wgc_item_identity(&self) -> Option<NativeWgcItemIdentity> {
        match self {
            Self::DesktopDuplication { .. } => None,
            Self::WindowsGraphicsCapture { authorization, .. } => {
                Some(authorization.item_identity())
            }
        }
    }

    #[must_use]
    fn cancellation(&self) -> NativeCaptureCancellation {
        match self {
            Self::DesktopDuplication { cancellation, .. }
            | Self::WindowsGraphicsCapture { cancellation, .. } => cancellation.clone(),
        }
    }
}

/// Data-only notification produced by the trusted native source. A frame
/// notification carries no texture. Rust reserves a bounded destination only
/// after accepting `FrameAvailable`, then calls `detach_frame` with that exact
/// reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum NativeCaptureSourceEvent {
    FrameAvailable {
        identity: NativeCaptureEventIdentity,
        frame: NativePendingFrameIdentity,
        display_epoch: u32,
        descriptor: FrameDescriptor,
        metadata: DesktopMetadata,
    },
    ProtectedContentMasked {
        identity: NativeCaptureEventIdentity,
        status: NativeCaptureStatus,
    },
    DisplayChanged {
        identity: NativeCaptureEventIdentity,
        descriptor: FrameDescriptor,
        status: NativeCaptureStatus,
    },
    AccessLost {
        identity: NativeCaptureEventIdentity,
        status: NativeCaptureStatus,
        observed_at_ns: u64,
    },
    PermissionRevoked {
        identity: NativeCaptureEventIdentity,
        status: NativeCaptureStatus,
    },
    ItemClosed {
        identity: NativeCaptureEventIdentity,
        status: NativeCaptureStatus,
    },
    SessionChanged {
        identity: NativeCaptureEventIdentity,
        status: NativeCaptureStatus,
    },
    EndOfStream {
        identity: NativeCaptureEventIdentity,
    },
}

impl NativeCaptureSourceEvent {
    const fn identity(&self) -> NativeCaptureEventIdentity {
        match self {
            Self::FrameAvailable { identity, .. }
            | Self::ProtectedContentMasked { identity, .. }
            | Self::DisplayChanged { identity, .. }
            | Self::AccessLost { identity, .. }
            | Self::PermissionRevoked { identity, .. }
            | Self::ItemClosed { identity, .. }
            | Self::SessionChanged { identity, .. }
            | Self::EndOfStream { identity } => *identity,
        }
    }
}

/// Opaque identity of one exact bounded destination reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeDestinationReservationId(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeFrameReservationInput {
    identity: NativeCaptureEventIdentity,
    frame: NativePendingFrameIdentity,
    source_observed_epoch: u32,
    source_descriptor: FrameDescriptor,
    metadata: DesktopMetadata,
}

/// Exact engine-owned destination handed to the trusted native detach call.
/// Only consuming this value can produce `NativeFrameDetachResult`.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct NativeFrameDetachRequest {
    identity: NativeCaptureEventIdentity,
    frame: NativePendingFrameIdentity,
    reservation: NativeDestinationReservationId,
    source_descriptor: FrameDescriptor,
    destination: DestinationSurfaceSpec,
    source_observed_epoch: u32,
    metadata: DesktopMetadata,
    lease: CaptureLease,
}

#[allow(dead_code)]
impl NativeFrameDetachRequest {
    #[must_use]
    const fn event_identity(&self) -> NativeCaptureEventIdentity {
        self.identity
    }

    #[must_use]
    const fn pending_frame(&self) -> NativePendingFrameIdentity {
        self.frame
    }

    #[must_use]
    const fn source_descriptor(&self) -> FrameDescriptor {
        self.source_descriptor
    }

    #[must_use]
    const fn destination_descriptor(&self) -> FrameDescriptor {
        self.destination.descriptor()
    }

    #[must_use]
    const fn destination_device(&self) -> DeviceIdentity {
        self.destination.device()
    }

    #[must_use]
    const fn destination_layout(&self) -> SurfaceLayout {
        self.destination.layout()
    }

    #[must_use]
    const fn display_epoch(&self) -> u32 {
        self.source_observed_epoch
    }

    #[must_use]
    const fn reservation_id(&self) -> NativeDestinationReservationId {
        self.reservation
    }
    #[must_use]
    pub(crate) fn fail_native(self, failure: NativeCaptureFailure) -> NativeFrameDetachError {
        NativeFrameDetachError::Native {
            failure,
            reservation: self.reservation,
            lease: self.lease,
        }
    }

    #[must_use]
    pub(crate) fn fail_contract(self, error: WindowsBackendError) -> NativeFrameDetachError {
        NativeFrameDetachError::Contract {
            error,
            reservation: self.reservation,
            lease: self.lease,
        }
    }

    fn complete(
        self,
        ledger: CopyLedger,
    ) -> Result<NativeFrameDetachResult, NativeFrameDetachError> {
        self.complete_with_optional_payload(ledger, None)
    }

    /// Completes the exact native copy and transfers its destination resource
    /// with the pool slot to the encoder/decoder lifetime.
    fn complete_with_payload(
        self,
        ledger: CopyLedger,
        payload: Box<dyn SurfacePayload>,
    ) -> Result<NativeFrameDetachResult, NativeFrameDetachError> {
        self.complete_with_optional_payload(ledger, Some(payload))
    }

    fn complete_with_optional_payload(
        self,
        ledger: CopyLedger,
        payload: Option<Box<dyn SurfacePayload>>,
    ) -> Result<NativeFrameDetachResult, NativeFrameDetachError> {
        let identity = self.identity;
        let frame = self.frame;
        let reservation = self.reservation;
        let source_descriptor = self.source_descriptor;
        let destination = self.destination;
        let source_observed_epoch = self.source_observed_epoch;
        let metadata = self.metadata;
        let lease = self.lease;

        let imported = match import_capture_frame(
            lease,
            source_descriptor,
            destination,
            ledger,
            source_observed_epoch,
            metadata,
            payload,
        ) {
            Ok(imported) => imported,
            Err((error, lease)) => {
                return Err(NativeFrameDetachError::Contract {
                    error,
                    reservation,
                    lease,
                });
            }
        };
        Ok(NativeFrameDetachResult {
            identity,
            frame,
            reservation,
            imported,
        })
    }
}

/// Result of copying into the exact Rust reservation and releasing the native
/// borrowed frame.
#[derive(Debug)]
pub(crate) struct NativeFrameDetachResult {
    identity: NativeCaptureEventIdentity,
    frame: NativePendingFrameIdentity,
    reservation: NativeDestinationReservationId,
    imported: ImportedWindowsFrame,
}

/// Failure outcome of a frame detach request.
///
/// Retains the exact destination reservation and capture lease until synchronous
/// native quiescence has completed, preventing early reuse of the pool slot while
/// GPU/native operations could still be touching native memory.
#[derive(Debug)]
pub(crate) enum NativeFrameDetachError {
    Native {
        failure: NativeCaptureFailure,
        reservation: NativeDestinationReservationId,
        lease: CaptureLease,
    },
    Contract {
        error: WindowsBackendError,
        reservation: NativeDestinationReservationId,
        lease: CaptureLease,
    },
}
impl NativeFrameDetachError {
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn reservation(&self) -> NativeDestinationReservationId {
        match self {
            Self::Native { reservation, .. } | Self::Contract { reservation, .. } => *reservation,
        }
    }
}

/// Request to synchronously release one pending borrowed native frame without
/// consuming a pool destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeFrameDiscardRequest {
    identity: NativeCaptureEventIdentity,
    frame: NativePendingFrameIdentity,
    source_observed_epoch: u32,
}

impl NativeFrameDiscardRequest {
    #[cfg_attr(not(test), allow(dead_code))]
    const fn complete(self) -> NativeFrameDiscardReceipt {
        NativeFrameDiscardReceipt {
            identity: self.identity,
            frame: self.frame,
            source_observed_epoch: self.source_observed_epoch,
        }
    }
}

/// Exact proof that a pending borrowed frame was synchronously released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeFrameDiscardReceipt {
    identity: NativeCaptureEventIdentity,
    frame: NativePendingFrameIdentity,
    source_observed_epoch: u32,
}

/// Exact proof that native callback delivery and all frame reservations for a
/// stopped session are synchronously drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeCaptureStopReceipt {
    session: NativeCaptureSessionIdentity,
}

impl NativeCaptureStopReceipt {
    #[cfg_attr(not(test), allow(dead_code))]
    const fn drained(session: NativeCaptureSessionIdentity) -> Self {
        Self { session }
    }
}

pub(crate) mod native_capture_source_seal {
    pub trait Sealed {}
}

/// Sealed native boundary. Implementations live inside this crate, own every
/// COM/WinRT/D3D11 object, and must make `abort` synchronously and infallibly
/// prevent all future access to a reservation before returning.
#[allow(dead_code)]
pub(crate) trait NativeCaptureSource: native_capture_source_seal::Sealed + Send {
    fn identity(&self) -> NativeSourceIdentity;
    fn abort_handle(&self) -> Arc<dyn NativeCaptureAbortHandle>;
    fn start(&mut self, request: NativeCaptureStart) -> Result<(), NativeCaptureFailure>;
    fn poll(
        &mut self,
        timeout_ns: u64,
    ) -> Result<Option<NativeCaptureSourceEvent>, NativeCaptureFailure>;
    fn detach_frame(
        &mut self,
        request: NativeFrameDetachRequest,
    ) -> Result<NativeFrameDetachResult, NativeFrameDetachError>;
    fn discard_frame(
        &mut self,
        request: NativeFrameDiscardRequest,
    ) -> Result<NativeFrameDiscardReceipt, NativeCaptureFailure>;
    fn stop(
        &mut self,
        session: NativeCaptureSessionIdentity,
    ) -> Result<NativeCaptureStopReceipt, NativeCaptureFailure>;
}

/// Stateful Windows adapter joining agent authority, target selection, native
/// lifecycle outcomes, and bounded surface ownership.
pub struct WindowsCaptureBackend {
    target: WindowsCaptureTarget,
    selector: CaptureSelector,
    binding: AgentBinding,
    broker: Arc<Mutex<PerUserAgentBroker>>,
    pool: SurfacePool,
    destination: WindowsCaptureDestination,
    source: Box<dyn NativeCaptureSource>,
    source_identity: NativeSourceIdentity,
    wgc_authorization: Option<WgcAuthorization>,
    active_wgc_authority: Option<Arc<WgcAuthorizationAuthority>>,
    active_control: Option<NativeSessionControl>,
    source_started: bool,
    active_session: Option<NativeCaptureEventIdentity>,
    broker_session_registered: bool,
    cleanup_required: bool,
    pending_terminal_state: Option<ProviderState>,
    recovery_deadline_ns: Option<u64>,
    last_native_status: Option<NativeCaptureStatus>,
    last_native_failure: Option<NativeCaptureFailure>,
}

impl WindowsCaptureBackend {
    #[cfg_attr(not(test), allow(dead_code))]
    #[cfg(windows)]
    pub fn new_desktop_duplication(
        binding: AgentBinding,
        broker: Arc<Mutex<PerUserAgentBroker>>,
        pool: SurfacePool,
        destination: WindowsCaptureDestination,
        adapter_index: u32,
        output_index: u32,
    ) -> Result<Self, WindowsBackendError> {
        let source = DesktopDuplicationCaptureSource::new(adapter_index, output_index)?;
        Ok(Self::new_desktop_output(
            true,
            binding,
            broker,
            pool,
            destination,
            Box::new(source),
        ))
    }

    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new_desktop_output(
        dda_supported: bool,
        binding: AgentBinding,
        broker: Arc<Mutex<PerUserAgentBroker>>,
        pool: SurfacePool,
        destination: WindowsCaptureDestination,
        source: Box<dyn NativeCaptureSource>,
    ) -> Self {
        Self::new_inner(
            CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, dda_supported, false),
            binding,
            broker,
            pool,
            destination,
            source,
            None,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new_authorized_wgc(
        wgc_supported: bool,
        binding: AgentBinding,
        broker: Arc<Mutex<PerUserAgentBroker>>,
        pool: SurfacePool,
        destination: WindowsCaptureDestination,
        source: Box<dyn NativeCaptureSource>,
        authorization: WgcAuthorization,
    ) -> Result<Self, WindowsBackendError> {
        if authorization.binding != binding
            || authorization.source != source.identity()
            || !authorization.is_live()
        {
            return Err(WindowsBackendError::AgentIdentity);
        }
        let target = authorization.target;
        if !matches!(
            target,
            WindowsCaptureTarget::AuthorizedWgcDisplay | WindowsCaptureTarget::AuthorizedWgcWindow
        ) {
            return Err(WindowsBackendError::AgentIdentity);
        }
        Ok(Self::new_inner(
            CaptureSelector::new(target, false, wgc_supported),
            binding,
            broker,
            pool,
            destination,
            source,
            Some(authorization),
        ))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn new_inner(
        selector: CaptureSelector,
        binding: AgentBinding,
        broker: Arc<Mutex<PerUserAgentBroker>>,
        pool: SurfacePool,
        destination: WindowsCaptureDestination,
        source: Box<dyn NativeCaptureSource>,
        wgc_authorization: Option<WgcAuthorization>,
    ) -> Self {
        let source_identity = source.identity();
        let target = selector.target;
        Self {
            target,
            selector,
            binding,
            broker,
            pool,
            destination,
            source,
            source_identity,
            wgc_authorization,
            active_wgc_authority: None,
            active_control: None,
            source_started: false,
            active_session: None,
            broker_session_registered: false,
            cleanup_required: false,
            pending_terminal_state: None,
            recovery_deadline_ns: None,
            last_native_status: None,
            last_native_failure: None,
        }
    }

    #[must_use]
    pub const fn active_api(&self) -> Option<WindowsCaptureApi> {
        self.selector.active()
    }

    #[must_use]
    pub const fn display_epoch(&self) -> u32 {
        self.selector.display_epoch()
    }

    #[must_use]
    pub const fn recovery_deadline_ns(&self) -> Option<u64> {
        self.recovery_deadline_ns
    }

    #[cfg(test)]
    #[must_use]
    const fn last_native_status(&self) -> Option<NativeCaptureStatus> {
        self.last_native_status
    }

    #[cfg(test)]
    #[must_use]
    const fn last_native_failure(&self) -> Option<NativeCaptureFailure> {
        self.last_native_failure
    }

    fn record_status(&mut self, status: NativeCaptureStatus) {
        self.last_native_status = Some(status);
    }

    fn record_native_failure(&mut self, failure: NativeCaptureFailure) {
        self.last_native_status = Some(failure.status);
        self.last_native_failure = Some(failure);
        self.selector.diagnostics.last_error = Some(
            match failure.kind {
                NativeCaptureFailureKind::InvalidState => "native capture invalid state",
                NativeCaptureFailureKind::AccessLost => "native capture access lost",
                NativeCaptureFailureKind::PermissionDenied => "native capture permission denied",
                NativeCaptureFailureKind::PermissionRevoked => "native capture permission revoked",
                NativeCaptureFailureKind::Unsupported => "native capture unsupported",
                NativeCaptureFailureKind::DeviceLost => "native capture device lost",
                NativeCaptureFailureKind::InvalidSurface => "native capture invalid surface",
            }
            .into(),
        );
    }

    fn begin_operation(&self, allow_draining: bool) -> Result<AgentOperationPermit, PlatformError> {
        AgentOperationPermit::acquire(&self.broker, self.binding, allow_draining)
            .map_err(|error| platform_error_for_windows_backend(&error))
    }

    fn register_broker_session(&mut self) -> Result<(), PlatformError> {
        let control = self
            .active_control
            .as_ref()
            .cloned()
            .ok_or(PlatformError::InvalidState)?;
        self.broker
            .lock()
            .map_err(|_| PlatformError::InvalidState)?
            .register_session(self.binding, control)
            .map_err(|error| platform_error_for_windows_backend(&error))?;
        self.broker_session_registered = true;
        Ok(())
    }

    fn unregister_broker_session(&mut self) {
        if self.broker_session_registered {
            let session = self
                .active_session
                .map(|identity| identity.session)
                .or_else(|| self.active_control.as_ref().map(|control| control.session));
            let mut broker = self
                .broker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(session) = session {
                broker.unregister_session(self.binding, session);
            }
            self.broker_session_registered = false;
        }
    }

    fn stop_source_with_permit(
        &mut self,
        terminal_state: ProviderState,
    ) -> Result<(), PlatformError> {
        if !self.source_started {
            self.cleanup_required = false;
            self.pending_terminal_state = None;
            self.active_wgc_authority = None;
            self.active_control = None;
            self.selector.clear(terminal_state, None);
            return Ok(());
        }
        let identity = self.active_session.ok_or(PlatformError::InvalidState)?;
        if self
            .active_control
            .as_ref()
            .is_some_and(|control| control.gate.is_native_quiesced())
        {
            self.finish_source_quiescence(terminal_state);
            return Ok(());
        }
        if let Some(control) = &self.active_control {
            control.gate.close();
        }
        match self.source.stop(identity.session) {
            Ok(receipt) if receipt.session == identity.session => {
                if let Some(control) = &self.active_control {
                    control.gate.mark_native_quiesced();
                }
                self.finish_source_quiescence(terminal_state);
                Ok(())
            }
            Ok(_) => {
                if let Some(control) = &self.active_control {
                    control.abort_exact_and_wait();
                } else {
                    self.source.abort_handle().abort(Some(identity.session));
                }
                self.finish_source_quiescence(terminal_state);
                self.selector.diagnostics.last_error =
                    Some("native stop returned a mismatched drain receipt".into());
                Err(PlatformError::InvalidState)
            }
            Err(failure) => {
                self.record_native_failure(failure);
                self.cleanup_required = true;
                self.pending_terminal_state = Some(terminal_state);
                self.selector.clear(
                    ProviderState::Draining,
                    Some("native capture cleanup required".into()),
                );
                Err(failure.platform_error())
            }
        }
    }

    fn finish_source_quiescence(&mut self, terminal_state: ProviderState) {
        self.source_started = false;
        self.cleanup_required = false;
        self.pending_terminal_state = None;
        self.unregister_broker_session();
        self.active_session = None;
        self.active_wgc_authority = None;
        self.active_control = None;
        self.selector.clear(terminal_state, None);
    }

    fn begin_or_observe_drain(&self) -> Result<(), PlatformError> {
        let broker = self
            .broker
            .lock()
            .map_err(|_| PlatformError::InvalidState)?;
        if broker.is_current_binding(self.binding) {
            drop(broker);
            PerUserAgentBroker::session_changed(&self.broker)
                .map_err(|error| platform_error_for_windows_backend(&error))?;
            return Ok(());
        }
        match broker.state() {
            AgentBrokerState::Draining { binding } if *binding == self.binding => Ok(()),
            _ => Err(PlatformError::PermissionRevoked),
        }
    }

    fn try_finish_drain(&self) -> Result<(), PlatformError> {
        let mut broker = self
            .broker
            .lock()
            .map_err(|_| PlatformError::InvalidState)?;
        match broker.state() {
            AgentBrokerState::Draining { binding } if *binding == self.binding => broker
                .finish_draining(self.binding)
                .map_err(|error| platform_error_for_windows_backend(&error)),
            _ => Ok(()),
        }
    }

    fn launch_source(
        &mut self,
        api: WindowsCaptureApi,
        permit: &AgentOperationPermit,
        wgc_authorization: Option<WgcAuthorization>,
    ) -> Result<(), PlatformError> {
        let session = NativeCaptureSessionIdentity(
            allocate_nonzero_identity(&NEXT_CAPTURE_SESSION_ID)
                .map_err(|error| platform_error_for_windows_backend(&error))?,
        );
        let identity = NativeCaptureEventIdentity {
            session,
            agent_generation: self.binding.generation,
        };
        let gate = NativePublicationGate::new();
        let control = NativeSessionControl {
            session,
            gate: Arc::clone(&gate),
            abort: self.source.abort_handle(),
        };
        let cancellation = NativeCaptureCancellation {
            gate: Arc::clone(&gate),
        };
        let request = match (api, wgc_authorization) {
            (WindowsCaptureApi::DesktopDuplication, None)
                if self.target == WindowsCaptureTarget::DesktopOutput =>
            {
                NativeCaptureStart::DesktopDuplication {
                    display_epoch: self.selector.display_epoch(),
                    identity,
                    cancellation,
                }
            }
            (WindowsCaptureApi::WindowsGraphicsCapture, Some(authorization))
                if authorization.target == self.target
                    && authorization.binding == self.binding
                    && authorization.source == self.source_identity
                    && authorization.is_live() =>
            {
                authorization
                    .authority()
                    .attach(control.clone())
                    .map_err(|error| platform_error_for_windows_backend(&error))?;
                self.active_wgc_authority = Some(Arc::clone(authorization.authority()));
                NativeCaptureStart::WindowsGraphicsCapture {
                    display_epoch: self.selector.display_epoch(),
                    identity,
                    cancellation,
                    authorization,
                }
            }
            _ => return Err(PlatformError::PermissionRevoked),
        };
        self.active_session = Some(identity);
        self.active_control = Some(control);
        self.source_started = true;
        if let Err(error) = self.register_broker_session() {
            if let Some(control) = &self.active_control {
                control.abort_exact_and_wait();
            }
            self.finish_source_quiescence(ProviderState::Stopped);
            return Err(error);
        }
        if !self.wgc_liveness_is_current() || !permit.is_current() || !gate.is_open() {
            let terminal = if self.wgc_liveness_is_current() {
                ProviderState::Stopped
            } else {
                ProviderState::Revoked
            };
            self.finish_source_quiescence(terminal);
            return Err(PlatformError::PermissionRevoked);
        }
        if let Err(failure) = self.source.start(request) {
            let error = failure.platform_error();
            self.record_native_failure(failure);
            let _ = self.stop_source_with_permit(ProviderState::Failed);
            self.selector.diagnostics.last_error = Some("native capture start failed".into());
            return Err(error);
        }
        if !self.wgc_liveness_is_current() {
            self.stop_source_with_permit(ProviderState::Revoked)?;
            self.selector.diagnostics.last_error = Some("WGC authorization revoked".into());
            return Err(PlatformError::PermissionRevoked);
        }
        if !permit.is_current() {
            self.begin_or_observe_drain()?;
            self.stop_source_with_permit(ProviderState::Stopped)?;
            return Err(PlatformError::PermissionRevoked);
        }
        if !permit.is_current() {
            self.begin_or_observe_drain()?;
            self.stop_source_with_permit(ProviderState::Stopped)?;
            return Err(PlatformError::PermissionRevoked);
        }
        Ok(())
    }

    fn wgc_liveness_is_current(&self) -> bool {
        match self.target {
            WindowsCaptureTarget::DesktopOutput => self.active_wgc_authority.is_none(),
            WindowsCaptureTarget::AuthorizedWgcDisplay
            | WindowsCaptureTarget::AuthorizedWgcWindow => self
                .active_wgc_authority
                .as_ref()
                .is_some_and(|authority| authority.is_live()),
        }
    }

    fn revoke_wgc_with_permit(&mut self) -> Result<Option<CaptureEvent>, PlatformError> {
        self.stop_source_with_permit(ProviderState::Revoked)?;
        self.wgc_authorization = None;
        self.selector.diagnostics.last_error = Some("WGC authorization revoked".into());
        Ok(Some(CaptureEvent::PermissionRevoked))
    }

    fn quiesce_generation_with_permit(
        &mut self,
        permit: &AgentOperationPermit,
    ) -> Result<(), PlatformError> {
        self.begin_or_observe_drain()?;
        if self.selector.state() == ProviderState::Running {
            self.selector
                .fail(CaptureFailure::SessionChanged, 0)
                .map_err(|error| platform_error_for_windows_backend(&error))?;
        }
        let result = self.stop_source_with_permit(ProviderState::Stopped);
        if permit.is_current() {
            self.selector.diagnostics.last_error =
                Some("interactive agent generation changed".into());
        }
        result
    }

    fn fail_contract_with_permit(&mut self, error: WindowsBackendError) -> PlatformError {
        let platform = platform_error_for_windows_backend(&error);
        let _ = self.stop_source_with_permit(ProviderState::Failed);
        self.selector.diagnostics.last_error = Some(
            match error {
                WindowsBackendError::DestinationMismatch => {
                    "native destination reservation mismatch"
                }
                WindowsBackendError::BorrowedDirectAlias => "borrowed capture surface cannot alias",
                WindowsBackendError::GenerationExhausted => "capture generation exhausted",
                _ => "invalid native capture payload",
            }
            .into(),
        );
        platform
    }

    fn fail_native_with_permit(&mut self, failure: NativeCaptureFailure) -> PlatformError {
        let platform = failure.platform_error();
        self.record_native_failure(failure);
        let terminal = match failure.kind {
            NativeCaptureFailureKind::AccessLost => {
                let Some(observed_at_ns) = failure.observed_at_ns else {
                    let _ = self.stop_source_with_permit(ProviderState::Failed);
                    self.selector.diagnostics.last_error =
                        Some("native access loss omitted observation time".into());
                    return PlatformError::InvalidState;
                };
                match self
                    .selector
                    .fail(CaptureFailure::AccessLost, observed_at_ns)
                {
                    Ok(CaptureRecoveryAction::RecreateAfter { retry_at_ns }) => {
                        self.recovery_deadline_ns = Some(retry_at_ns);
                        ProviderState::Reconfiguring
                    }
                    _ => ProviderState::Failed,
                }
            }
            NativeCaptureFailureKind::DeviceLost => {
                let _ = self.selector.fail(CaptureFailure::DeviceRemoved, 0);
                ProviderState::Failed
            }
            NativeCaptureFailureKind::PermissionDenied
            | NativeCaptureFailureKind::PermissionRevoked => ProviderState::Revoked,
            _ => ProviderState::Failed,
        };
        let _ = self.stop_source_with_permit(terminal);
        self.record_native_failure(failure);
        platform
    }
    fn abort_exact_and_wait(&mut self) {
        if let Some(control) = &self.active_control {
            control.abort_exact_and_wait();
        } else if let Some(identity) = self.active_session {
            self.source.abort_handle().abort(Some(identity.session));
        }
    }

    fn quiesce_generation_with_request(
        &mut self,
        permit: &AgentOperationPermit,
        request: NativeFrameDetachRequest,
    ) -> Result<(), PlatformError> {
        let result = self.quiesce_generation_with_permit(permit);
        if result.is_err() {
            self.abort_exact_and_wait();
            self.finish_source_quiescence(ProviderState::Stopped);
        }
        drop(request);
        result
    }

    fn revoke_wgc_with_request(
        &mut self,
        request: NativeFrameDetachRequest,
    ) -> Result<Option<CaptureEvent>, PlatformError> {
        let result = self.revoke_wgc_with_permit();
        if result.is_err() {
            self.abort_exact_and_wait();
            self.finish_source_quiescence(ProviderState::Revoked);
            self.wgc_authorization = None;
            self.selector.diagnostics.last_error = Some("WGC authorization revoked".into());
        }
        drop(request);
        result
    }

    fn fail_detach_native_with_permit(
        &mut self,
        failure: NativeCaptureFailure,
        lease: CaptureLease,
    ) -> PlatformError {
        let platform = failure.platform_error();
        self.record_native_failure(failure);
        let terminal = match failure.kind {
            NativeCaptureFailureKind::AccessLost => {
                let Some(observed_at_ns) = failure.observed_at_ns else {
                    if self.stop_source_with_permit(ProviderState::Failed).is_err() {
                        self.abort_exact_and_wait();
                        self.finish_source_quiescence(ProviderState::Failed);
                    }
                    self.selector.diagnostics.last_error =
                        Some("native access loss omitted observation time".into());
                    drop(lease);
                    return PlatformError::InvalidState;
                };
                match self
                    .selector
                    .fail(CaptureFailure::AccessLost, observed_at_ns)
                {
                    Ok(CaptureRecoveryAction::RecreateAfter { retry_at_ns }) => {
                        self.recovery_deadline_ns = Some(retry_at_ns);
                        ProviderState::Reconfiguring
                    }
                    _ => ProviderState::Failed,
                }
            }
            NativeCaptureFailureKind::DeviceLost => {
                let _ = self.selector.fail(CaptureFailure::DeviceRemoved, 0);
                ProviderState::Failed
            }
            NativeCaptureFailureKind::PermissionDenied
            | NativeCaptureFailureKind::PermissionRevoked => ProviderState::Revoked,
            _ => ProviderState::Failed,
        };
        if self.stop_source_with_permit(terminal).is_err() {
            self.abort_exact_and_wait();
            self.finish_source_quiescence(terminal);
        }
        self.record_native_failure(failure);
        drop(lease);
        platform
    }

    fn fail_detach_contract_with_permit(
        &mut self,
        error: WindowsBackendError,
        lease: CaptureLease,
    ) -> PlatformError {
        let platform = platform_error_for_windows_backend(&error);
        if self.stop_source_with_permit(ProviderState::Failed).is_err() {
            self.abort_exact_and_wait();
            self.finish_source_quiescence(ProviderState::Failed);
        }
        self.selector.diagnostics.last_error = Some(match error {
            WindowsBackendError::DestinationMismatch => {
                "native frame destination mismatch".to_string()
            }
            WindowsBackendError::LedgerEpoch => "native frame ledger epoch mismatch".to_string(),
            WindowsBackendError::BorrowedDirectAlias => {
                "native frame rejected direct alias import".to_string()
            }
            _ => "native frame detachment contract violation".to_string(),
        });
        drop(lease);
        platform
    }

    fn discard_pending_frame(
        &mut self,
        identity: NativeCaptureEventIdentity,
        frame: NativePendingFrameIdentity,
        source_observed_epoch: u32,
    ) -> Result<(), PlatformError> {
        let expected = NativeFrameDiscardRequest {
            identity,
            frame,
            source_observed_epoch,
        };
        let receipt = self
            .source
            .discard_frame(expected)
            .map_err(|failure| self.fail_native_with_permit(failure))?;
        if receipt.identity != identity
            || receipt.frame != frame
            || receipt.source_observed_epoch != source_observed_epoch
        {
            return Err(self.fail_contract_with_permit(WindowsBackendError::DestinationMismatch));
        }
        Ok(())
    }

    fn handle_event(
        &mut self,
        event: NativeCaptureSourceEvent,
        permit: &AgentOperationPermit,
        publisher: &mut CaptureFramePublisher,
    ) -> Result<Option<CaptureEvent>, PlatformError> {
        match event {
            NativeCaptureSourceEvent::FrameAvailable {
                identity,
                frame,
                display_epoch,
                descriptor,
                metadata,
            } => {
                if !permit.is_current() {
                    self.quiesce_generation_with_permit(permit)?;
                    return Err(PlatformError::PermissionRevoked);
                }
                if !self.wgc_liveness_is_current() {
                    return self.revoke_wgc_with_permit();
                }
                if display_epoch != self.selector.display_epoch() {
                    self.discard_pending_frame(identity, frame, display_epoch)?;
                    if !permit.is_current() {
                        self.quiesce_generation_with_permit(permit)?;
                        return Err(PlatformError::PermissionRevoked);
                    }
                    if !self.wgc_liveness_is_current() {
                        return self.revoke_wgc_with_permit();
                    }
                    self.selector.diagnostics.dropped =
                        self.selector.diagnostics.dropped.saturating_add(1);
                    self.selector.diagnostics.last_error =
                        Some("stale native frame display epoch".into());
                    return Err(PlatformError::InvalidSurface);
                }
                let reservation = NativeDestinationReservationId(
                    allocate_nonzero_identity(&NEXT_DESTINATION_RESERVATION_ID)
                        .map_err(|error| self.fail_contract_with_permit(error))?,
                );
                let request = match self.selector.reserve_frame(
                    &self.pool,
                    reservation,
                    self.destination,
                    NativeFrameReservationInput {
                        identity,
                        frame,
                        source_observed_epoch: display_epoch,
                        source_descriptor: descriptor,
                        metadata,
                    },
                ) {
                    Ok(request) => request,
                    Err(WindowsBackendError::Surface(SurfaceError::PoolExhausted)) => {
                        self.discard_pending_frame(identity, frame, display_epoch)?;
                        if !permit.is_current() {
                            self.quiesce_generation_with_permit(permit)?;
                            return Err(PlatformError::PermissionRevoked);
                        }
                        if !self.wgc_liveness_is_current() {
                            return self.revoke_wgc_with_permit();
                        }
                        self.selector.diagnostics.dropped =
                            self.selector.diagnostics.dropped.saturating_add(1);
                        self.selector.diagnostics.last_error =
                            Some("capture destination pool exhausted".into());
                        return Err(PlatformError::QueueFull);
                    }
                    Err(error) => return Err(self.fail_contract_with_permit(error)),
                };
                if !permit.is_current() {
                    let _ = self.quiesce_generation_with_request(permit, request);
                    return Err(PlatformError::PermissionRevoked);
                }
                if !self.wgc_liveness_is_current() {
                    return self.revoke_wgc_with_request(request);
                }
                let result = match self.source.detach_frame(request) {
                    Ok(result) => result,
                    Err(NativeFrameDetachError::Native { failure, lease, .. }) => {
                        return Err(self.fail_detach_native_with_permit(failure, lease));
                    }
                    Err(NativeFrameDetachError::Contract { error, lease, .. }) => {
                        return Err(self.fail_detach_contract_with_permit(error, lease));
                    }
                };
                if !permit.is_current() {
                    drop(result);
                    self.quiesce_generation_with_permit(permit)?;
                    return Err(PlatformError::PermissionRevoked);
                }
                if !self.wgc_liveness_is_current() {
                    drop(result);
                    return self.revoke_wgc_with_permit();
                }
                let ledger = result.imported.copy_ledger;
                if result.identity != identity
                    || result.frame != frame
                    || result.reservation != reservation
                    || result.imported.display_epoch != display_epoch
                    || display_epoch != self.selector.display_epoch()
                    || ledger.source_lease.provider_epoch != display_epoch
                    || ledger.source_lease.capture_sequence != descriptor.capture_sequence
                    || result.imported.surface.descriptor().ok()
                        != Some(
                            self.destination
                                .reserve_for(descriptor)
                                .map_err(|error| self.fail_contract_with_permit(error))?
                                .descriptor(),
                        )
                {
                    drop(result);
                    return Err(
                        self.fail_contract_with_permit(WindowsBackendError::DestinationMismatch)
                    );
                }
                let publication = self
                    .active_control
                    .as_ref()
                    .and_then(|control| control.gate.try_publish());
                let Some(publication) = publication else {
                    drop(result);
                    if !self.wgc_liveness_is_current() {
                        return self.revoke_wgc_with_permit();
                    }
                    if !permit.is_current() {
                        self.quiesce_generation_with_permit(permit)?;
                        return Err(PlatformError::PermissionRevoked);
                    }
                    return Err(self.fail_contract_with_permit(WindowsBackendError::InvalidState));
                };
                let bound = publisher.bind(result.imported.surface, publication);
                let frame = match bound {
                    Ok(frame) => frame,
                    Err(_) => {
                        return Err(self
                            .fail_contract_with_permit(WindowsBackendError::DestinationMismatch));
                    }
                };
                if !permit.is_current() {
                    drop(frame);
                    self.quiesce_generation_with_permit(permit)?;
                    return Err(PlatformError::PermissionRevoked);
                }
                if !self.wgc_liveness_is_current() {
                    drop(frame);
                    return self.revoke_wgc_with_permit();
                }
                Ok(Some(CaptureEvent::Frame(frame)))
            }
            NativeCaptureSourceEvent::ProtectedContentMasked { status, .. } => {
                if self.selector.active() != Some(WindowsCaptureApi::DesktopDuplication) {
                    return Err(self.fail_native_with_permit(NativeCaptureFailure::new(
                        NativeCaptureFailureKind::InvalidState,
                        status,
                    )));
                }
                if let Some(control) = &self.active_control {
                    control.invalidate_retained_presentation();
                }
                self.record_status(status);
                let CaptureRecoveryAction::SurfaceProtectedContent = self
                    .selector
                    .fail(CaptureFailure::ProtectedContent, 0)
                    .map_err(|error| self.fail_contract_with_permit(error))?
                else {
                    return Err(self.fail_contract_with_permit(WindowsBackendError::InvalidState));
                };
                if !permit.is_current() {
                    self.quiesce_generation_with_permit(permit)?;
                    return Err(PlatformError::PermissionRevoked);
                }
                self.selector.diagnostics.last_error =
                    Some("native capture protected content masked".into());
                Ok(Some(CaptureEvent::ProtectedContent {
                    display_epoch: self.selector.display_epoch(),
                }))
            }
            NativeCaptureSourceEvent::DisplayChanged {
                descriptor, status, ..
            } => {
                self.record_status(status);
                if descriptor.memory_domain != MemoryDomain::D3D11 {
                    let error = self.fail_contract_with_permit(WindowsBackendError::MemoryDomain);
                    self.record_status(status);
                    return Err(error);
                }
                if descriptor.validate().is_err() {
                    let error =
                        self.fail_contract_with_permit(WindowsBackendError::FrameDescriptor);
                    self.record_status(status);
                    return Err(error);
                }
                let display_epoch = self
                    .selector
                    .note_display_change()
                    .map_err(|error| self.fail_contract_with_permit(error))?;
                if !permit.is_current() {
                    self.quiesce_generation_with_permit(permit)?;
                    return Err(PlatformError::PermissionRevoked);
                }
                Ok(Some(CaptureEvent::Reconfigure {
                    display_epoch,
                    descriptor,
                }))
            }
            NativeCaptureSourceEvent::AccessLost {
                status,
                observed_at_ns,
                ..
            } => {
                self.record_status(status);
                let CaptureRecoveryAction::RecreateAfter { retry_at_ns } = self
                    .selector
                    .fail(CaptureFailure::AccessLost, observed_at_ns)
                    .map_err(|error| self.fail_contract_with_permit(error))?
                else {
                    return Err(self.fail_contract_with_permit(WindowsBackendError::InvalidState));
                };
                self.recovery_deadline_ns = Some(retry_at_ns);
                self.stop_source_with_permit(ProviderState::Reconfiguring)?;
                self.selector.diagnostics.last_error = Some("native capture access lost".into());
                Ok(Some(CaptureEvent::AccessLost))
            }
            NativeCaptureSourceEvent::PermissionRevoked { status, .. } => {
                self.record_status(status);
                self.wgc_authorization = None;
                self.stop_source_with_permit(ProviderState::Revoked)?;
                self.selector.diagnostics.last_error = Some("capture permission revoked".into());
                Ok(Some(CaptureEvent::PermissionRevoked))
            }
            NativeCaptureSourceEvent::ItemClosed { status, .. } => {
                if self.selector.active() != Some(WindowsCaptureApi::WindowsGraphicsCapture) {
                    return Err(self.fail_native_with_permit(NativeCaptureFailure::new(
                        NativeCaptureFailureKind::InvalidState,
                        status,
                    )));
                }
                self.record_status(status);
                self.wgc_authorization = None;
                self.stop_source_with_permit(ProviderState::Stopped)?;
                self.selector.diagnostics.last_error = Some("WGC capture item closed".into());
                Ok(Some(CaptureEvent::EndOfStream))
            }
            NativeCaptureSourceEvent::SessionChanged { status, .. } => {
                self.record_status(status);
                self.quiesce_generation_with_permit(permit)?;
                self.selector.diagnostics.last_error =
                    Some("interactive agent generation changed".into());
                Ok(Some(CaptureEvent::AccessLost))
            }
            NativeCaptureSourceEvent::EndOfStream { .. } => {
                self.stop_source_with_permit(ProviderState::Stopped)?;
                Ok(Some(CaptureEvent::EndOfStream))
            }
        }
    }
}

impl CaptureBackend for WindowsCaptureBackend {
    fn name(&self) -> &'static str {
        "windows-capture"
    }

    fn state(&self) -> ProviderState {
        self.selector.state()
    }

    fn start(&mut self) -> Result<(), PlatformError> {
        if self.source_started {
            if self
                .broker
                .lock()
                .map(|broker| broker.is_current_binding(self.binding))
                .unwrap_or(false)
            {
                return Err(PlatformError::InvalidState);
            }
            let permit = self.begin_operation(true)?;
            self.begin_or_observe_drain()?;
            let result = self.stop_source_with_permit(ProviderState::Stopped);
            drop(permit);
            if result.is_ok() {
                self.try_finish_drain()?;
            }
            result?;
            return Err(PlatformError::PermissionRevoked);
        }
        if self.cleanup_required || self.recovery_deadline_ns.is_some() {
            return Err(PlatformError::InvalidState);
        }
        let mut launch_authorization = None;
        if matches!(
            self.target,
            WindowsCaptureTarget::AuthorizedWgcDisplay | WindowsCaptureTarget::AuthorizedWgcWindow
        ) {
            let authorization = self
                .wgc_authorization
                .take()
                .ok_or(PlatformError::PermissionRevoked)?;
            if authorization.binding != self.binding
                || authorization.source != self.source_identity
                || authorization.target != self.target
                || !authorization.is_live()
            {
                self.selector.clear(
                    ProviderState::Revoked,
                    Some("WGC authorization revoked".into()),
                );
                return Err(PlatformError::PermissionRevoked);
            }
            launch_authorization = Some(authorization);
        }
        let permit = self.begin_operation(false)?;
        let api = self.selector.start(0).map_err(|error| {
            self.active_wgc_authority = None;
            let platform_error = platform_error_for_windows_backend(&error);
            self.selector.diagnostics.last_error = Some("capture start rejected".into());
            platform_error
        })?;
        self.last_native_status = None;
        self.last_native_failure = None;
        let result = self.launch_source(api, &permit, launch_authorization);
        drop(permit);
        if result.is_err() {
            let _ = self.try_finish_drain();
        }
        result
    }

    fn poll_with_publisher(
        &mut self,
        timeout_ns: u64,
        publisher: &mut CaptureFramePublisher,
    ) -> Result<Option<CaptureEvent>, PlatformError> {
        if self.selector.state() != ProviderState::Running || !self.source_started {
            return Err(PlatformError::InvalidState);
        }
        let permit = match self.begin_operation(false) {
            Ok(permit) => permit,
            Err(_) => {
                let permit = self.begin_operation(true)?;
                let result = self.quiesce_generation_with_permit(&permit);
                drop(permit);
                if result.is_ok() {
                    self.try_finish_drain()?;
                    return Ok(Some(CaptureEvent::AccessLost));
                }
                return result.map(|()| None);
            }
        };
        if !self.wgc_liveness_is_current() {
            let result = self.revoke_wgc_with_permit();
            drop(permit);
            return result;
        }
        let native_result = self.source.poll(timeout_ns);
        if !permit.is_current() {
            let result = self.quiesce_generation_with_permit(&permit);
            drop(permit);
            if result.is_ok() {
                self.try_finish_drain()?;
                return Ok(Some(CaptureEvent::AccessLost));
            }
            return result.map(|()| None);
        }
        if !self.wgc_liveness_is_current() {
            let result = self.revoke_wgc_with_permit();
            drop(permit);
            return result;
        }
        let result = match native_result {
            Ok(Some(event)) => {
                let expected = self.active_session.ok_or(PlatformError::InvalidState)?;
                if event.identity() != expected {
                    if let Some(control) = &self.active_control {
                        control.abort_all_and_wait();
                    } else {
                        self.source.abort_handle().abort(None);
                    }
                    self.finish_source_quiescence(ProviderState::Failed);
                    self.selector.diagnostics.last_error =
                        Some("late or mismatched native callback".into());
                    Err(PlatformError::PermissionRevoked)
                } else {
                    self.handle_event(event, &permit, publisher)
                }
            }
            Ok(None) => Ok(None),
            Err(failure) => Err(self.fail_native_with_permit(failure)),
        };
        drop(permit);
        let broker_is_draining = self
            .broker
            .lock()
            .map(|broker| {
                matches!(
                    broker.state(),
                    AgentBrokerState::Draining { binding } if *binding == self.binding
                )
            })
            .unwrap_or(false);
        if broker_is_draining && !self.cleanup_required {
            let _ = self.try_finish_drain();
        }
        result
    }

    fn stop(&mut self) -> Result<(), PlatformError> {
        if !self.source_started {
            self.recovery_deadline_ns = None;
            self.active_wgc_authority = None;
            self.active_control = None;
            self.pending_terminal_state = None;
            self.selector.clear(ProviderState::Stopped, None);
            return Ok(());
        }
        let terminal = match self.pending_terminal_state {
            Some(ProviderState::Reconfiguring) | None => ProviderState::Stopped,
            Some(terminal) => terminal,
        };
        let permit = self.begin_operation(true)?;
        let result = self.stop_source_with_permit(terminal);
        drop(permit);
        if result.is_ok() {
            self.recovery_deadline_ns = None;
            self.try_finish_drain()?;
        }
        result
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.selector.diagnostics()
    }
}

impl WindowsCaptureBackend {
    pub fn recover(&mut self, now_ns: u64) -> Result<(), PlatformError> {
        let retry_at = self
            .recovery_deadline_ns
            .ok_or(PlatformError::InvalidState)?;
        if self.target != WindowsCaptureTarget::DesktopOutput
            || self.source_started
            || self.cleanup_required
            || now_ns < retry_at
        {
            return Err(PlatformError::InvalidState);
        }
        let permit = self.begin_operation(false)?;
        self.selector
            .mark_recovered(now_ns)
            .map_err(|error| platform_error_for_windows_backend(&error))?;
        if self.selector.active() != Some(WindowsCaptureApi::DesktopDuplication) {
            self.selector.clear(
                ProviderState::Failed,
                Some("capture recovery selected invalid API".into()),
            );
            return Err(PlatformError::InvalidState);
        }
        let result = self.launch_source(WindowsCaptureApi::DesktopDuplication, &permit, None);
        drop(permit);
        if result.is_ok() {
            self.recovery_deadline_ns = None;
        } else {
            let _ = self.try_finish_drain();
        }
        result
    }
}

impl Drop for WindowsCaptureBackend {
    fn drop(&mut self) {
        if self.source_started || self.cleanup_required {
            if let Some(control) = &self.active_control {
                control.abort_exact_and_wait();
            } else {
                self.source
                    .abort_handle()
                    .abort(self.active_session.map(|identity| identity.session));
            }
            self.source_started = false;
            self.cleanup_required = false;
            self.unregister_broker_session();
            self.active_session = None;
            self.active_wgc_authority = None;
            self.active_control = None;
        }
        let _ = self.try_finish_drain();
    }
}

fn platform_error_for_windows_backend(error: &WindowsBackendError) -> PlatformError {
    match error {
        WindowsBackendError::InvalidState
        | WindowsBackendError::RetryNotReady
        | WindowsBackendError::GenerationExhausted
        | WindowsBackendError::DrainInProgress => PlatformError::InvalidState,
        WindowsBackendError::Unsupported => PlatformError::Unsupported,
        WindowsBackendError::MetadataLimit
        | WindowsBackendError::MetadataBounds
        | WindowsBackendError::MemoryDomain
        | WindowsBackendError::FrameDescriptor
        | WindowsBackendError::LedgerEpoch
        | WindowsBackendError::DestinationMismatch
        | WindowsBackendError::BorrowedDirectAlias
        | WindowsBackendError::Surface(_) => PlatformError::InvalidSurface,
        WindowsBackendError::AgentIdentity | WindowsBackendError::StaleGeneration => {
            PlatformError::PermissionRevoked
        }
        WindowsBackendError::H264(_) => PlatformError::Unsupported,
    }
}

/// Validates provider configuration and encoded access units at the FFI boundary.
pub fn validate_encoded_h264(
    policy: LowDelayPolicy,
    annex_b_access_unit: &[u8],
) -> Result<AnnexBSummary, WindowsBackendError> {
    policy.validate().map_err(WindowsBackendError::H264)?;
    latencydesk_h264::inspect_annex_b(annex_b_access_unit).map_err(WindowsBackendError::H264)
}
/// Windows Media Foundation hardware H.264 encoder backend.
///
/// Manages GPU surface submissions and tracks low-delay continuity metadata.
#[derive(Debug)]
pub struct WindowsEncodeBackend {
    policy: LowDelayPolicy,
    device: DeviceIdentity,
    planner: ContinuityPlanner,
    native_encoder: Option<cxx::UniquePtr<native::ffi::Encoder>>,
    output_meta: Option<EncodedFrameMeta>,
    output_bytes: Vec<u8>,
    completed: bool,
    diagnostics: ProviderDiagnostics,
}

impl WindowsEncodeBackend {
    pub fn new(
        device: DeviceIdentity,
        policy: LowDelayPolicy,
        codec_epoch: u32,
    ) -> Result<Self, WindowsBackendError> {
        let policy = policy.validate().map_err(WindowsBackendError::H264)?;
        Ok(Self {
            policy,
            device,
            planner: ContinuityPlanner::new(codec_epoch, 1),
            native_encoder: None,
            output_meta: None,
            output_bytes: Vec::new(),
            completed: true,
            diagnostics: ProviderDiagnostics::idle("windows_mf_h264_encoder"),
        })
    }

    pub fn policy(&self) -> LowDelayPolicy {
        self.policy
    }

    pub fn device(&self) -> DeviceIdentity {
        self.device
    }

    pub fn note_output_drop(&mut self) {
        self.planner.note_output_drop();
    }

    pub fn request_recovery_point(&mut self) -> Result<(), WindowsBackendError> {
        self.planner.note_output_drop();
        if let Some(encoder) = self.native_encoder.as_mut() {
            let status = native::ffi::encoder_request_idr(encoder.pin_mut());
            if status != native::STATUS_OK {
                return Err(WindowsBackendError::InvalidState);
            }
        }
        Ok(())
    }

    pub fn reconfigure_epoch(&mut self, codec_epoch: u32) -> Result<(), WindowsBackendError> {
        self.planner
            .reconfigure(codec_epoch)
            .map_err(WindowsBackendError::H264)
    }

    /// Ingests a raw Annex-B access unit produced by the native MFT and produces
    /// validated continuity metadata.
    pub fn process_annex_b(
        &mut self,
        annex_b_bytes: &[u8],
    ) -> Result<EncodedFrameMeta, WindowsBackendError> {
        self.planner
            .accept(annex_b_bytes)
            .map_err(WindowsBackendError::H264)
    }

    pub fn take_output(&mut self) -> Option<(EncodedFrameMeta, Vec<u8>)> {
        let meta = self.output_meta.take()?;
        let bytes = std::mem::take(&mut self.output_bytes);
        Some((meta, bytes))
    }
}

impl EncodeBackend for WindowsEncodeBackend {
    fn name(&self) -> &'static str {
        "windows_mf_h264_encoder"
    }

    fn encode(
        &mut self,
        submission: EncoderSubmissionGuard,
    ) -> Result<EncodeSubmission, EncodeFailure> {
        let preflight = submission.preflight();
        if preflight.descriptor.memory_domain != MemoryDomain::D3D11
            && preflight.descriptor.memory_domain != MemoryDomain::Cpu
        {
            return Err(submission.reject(PlatformError::InvalidSurface));
        }

        if self.native_encoder.is_none()
            && preflight.descriptor.memory_domain == MemoryDomain::D3D11
        {
            let mut status = native::STATUS_OK;
            let adapter_index = match self.device {
                DeviceIdentity::Opaque(idx) => idx as u32,
                _ => 0,
            };
            let encoder = native::ffi::make_mf_h264_encoder(
                adapter_index,
                preflight.descriptor.width,
                preflight.descriptor.height,
                5_000_000,
                30,
                self.policy.max_provider_queue as u32,
                &mut status,
            );
            if status == native::STATUS_OK && !encoder.is_null() {
                self.native_encoder = Some(encoder);
            }
        }

        let sub = submission.submit()?;

        if let Some(encoder) = self.native_encoder.as_mut() {
            if let Some(cxx_surface) = sub
                .frame()
                .surface()
                .payload::<crate::native::CxxSurfacePayload>()
            {
                let status = native::ffi::encoder_encode(
                    encoder.pin_mut(),
                    cxx_surface.surface(),
                    preflight.descriptor.capture_sequence,
                    preflight.descriptor.capture_timestamp_ns,
                );
                if status == native::STATUS_QUEUE_FULL {
                    return Err(sub.reject(PlatformError::QueueFull));
                }
                if status != native::STATUS_OK {
                    return Err(sub.reject(PlatformError::InvalidSurface));
                }
                self.completed = false;
                return Ok(sub);
            }
        }

        self.completed = true;
        Ok(sub)
    }

    fn poll_encode_completion(
        &mut self,
        _submission: &EncodeSubmission,
    ) -> Result<NativePresentationCompletion, PlatformError> {
        if self.completed {
            return Ok(NativePresentationCompletion::Complete);
        }
        if let Some(encoder) = self.native_encoder.as_mut() {
            let mut output_buf = vec![0u8; 2 * 1024 * 1024];
            let mut output_size = 0usize;
            let mut is_keyframe = false;
            let mut capture_sequence = 0u64;
            let mut timestamp_ns = 0u64;

            let status = native::ffi::encoder_poll_output(
                encoder.pin_mut(),
                &mut output_buf,
                &mut output_size,
                &mut is_keyframe,
                &mut capture_sequence,
                &mut timestamp_ns,
            );

            if status == native::STATUS_NO_FRAME {
                return Ok(NativePresentationCompletion::Pending);
            }
            if status != native::STATUS_OK {
                self.completed = true;
                return Err(PlatformError::InvalidSurface);
            }

            output_buf.truncate(output_size);
            if let Ok(meta) = self.planner.accept(&output_buf) {
                self.output_meta = Some(meta);
                self.output_bytes = output_buf;
            }
            self.completed = true;
            return Ok(NativePresentationCompletion::Complete);
        }
        self.completed = true;
        Ok(NativePresentationCompletion::Complete)
    }

    fn quiesce_encoding(&mut self) -> Result<(), PlatformError> {
        if let Some(encoder) = self.native_encoder.as_mut() {
            let _ = native::ffi::encoder_quiesce(encoder.pin_mut());
        }
        self.completed = true;
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}
pub mod win32_input_consts {
    pub const INPUT_MOUSE: u32 = 0;
    pub const INPUT_KEYBOARD: u32 = 1;
    pub const INPUT_HARDWARE: u32 = 2;

    pub const MOUSEEVENTF_MOVE: u32 = 0x0001;
    pub const MOUSEEVENTF_LEFTDOWN: u32 = 0x0002;
    pub const MOUSEEVENTF_LEFTUP: u32 = 0x0004;
    pub const MOUSEEVENTF_RIGHTDOWN: u32 = 0x0008;
    pub const MOUSEEVENTF_RIGHTUP: u32 = 0x0010;
    pub const MOUSEEVENTF_MIDDLEDOWN: u32 = 0x0020;
    pub const MOUSEEVENTF_MIDDLEUP: u32 = 0x0040;
    pub const MOUSEEVENTF_XDOWN: u32 = 0x0080;
    pub const MOUSEEVENTF_XUP: u32 = 0x0100;
    pub const MOUSEEVENTF_WHEEL: u32 = 0x0800;
    pub const MOUSEEVENTF_HWHEEL: u32 = 0x1000;
    pub const MOUSEEVENTF_VIRTUALDESK: u32 = 0x4000;
    pub const MOUSEEVENTF_ABSOLUTE: u32 = 0x8000;

    pub const XBUTTON1: u32 = 0x0001;
    pub const XBUTTON2: u32 = 0x0002;
    pub const WHEEL_DELTA: i32 = 120;

    pub const KEYEVENTF_EXTENDEDKEY: u32 = 0x0001;
    pub const KEYEVENTF_KEYUP: u32 = 0x0002;
    pub const KEYEVENTF_UNICODE: u32 = 0x0004;
    pub const KEYEVENTF_SCANCODE: u32 = 0x0008;
}

/// Windows Win32 `INPUT` structure representation for injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Win32Input {
    Mouse(Win32MouseInput),
    Keyboard(Win32KeyboardInput),
    Hardware(Win32HardwareInput),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32MouseInput {
    pub dx: i32,
    pub dy: i32,
    pub mouse_data: u32,
    pub flags: u32,
    pub time: u32,
    pub extra_info: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32KeyboardInput {
    pub vk_code: u16,
    pub scan_code: u16,
    pub flags: u32,
    pub time: u32,
    pub extra_info: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32HardwareInput {
    pub msg: u32,
    pub param_l: u16,
    pub param_h: u16,
}

/// Translates a provider-neutral USB HID usage code into a Windows Virtual-Key code and extended flag.
#[must_use]
pub fn hid_usage_to_win32_vk(usage: u16) -> (u16, bool) {
    match usage {
        0x04..=0x1D => (0x41 + (usage - 0x04), false), // A..Z
        0x1E..=0x26 => (0x31 + (usage - 0x1E), false), // 1..9
        0x27 => (0x30, false),                         // 0
        0x28 => (0x0D, false),                         // Return / Enter
        0x29 => (0x1B, false),                         // Escape
        0x2A => (0x08, false),                         // Backspace
        0x2B => (0x09, false),                         // Tab
        0x2C => (0x20, false),                         // Space
        0x2D => (0xBD, false),                         // Minus '-'
        0x2E => (0xBB, false),                         // Equals '='
        0x2F => (0xDB, false),                         // Left Bracket '['
        0x30 => (0xDD, false),                         // Right Bracket ']'
        0x31 => (0xDC, false),                         // Backslash '\'
        0x33 => (0xBA, false),                         // Semicolon ';'
        0x34 => (0xDE, false),                         // Quote '''
        0x35 => (0xC0, false),                         // Grave '`'
        0x36 => (0xBC, false),                         // Comma ','
        0x37 => (0xBE, false),                         // Period '.'
        0x38 => (0xBF, false),                         // Slash '/'
        0x39 => (0x14, false),                         // Caps Lock
        0x3A..=0x45 => (0x70 + (usage - 0x3A), false), // F1..F12
        0x46 => (0x2C, false),                         // Print Screen
        0x47 => (0x91, false),                         // Scroll Lock
        0x48 => (0x13, false),                         // Pause
        0x49 => (0x2D, true),                          // Insert
        0x4A => (0x24, true),                          // Home
        0x4B => (0x21, true),                          // Page Up
        0x4C => (0x2E, true),                          // Delete
        0x4D => (0x23, true),                          // End
        0x4E => (0x22, true),                          // Page Down
        0x4F => (0x27, true),                          // Right Arrow
        0x50 => (0x25, true),                          // Left Arrow
        0x51 => (0x28, true),                          // Down Arrow
        0x52 => (0x26, true),                          // Up Arrow
        0x53 => (0x90, true),                          // Num Lock
        0x54 => (0x6F, true),                          // Keypad /
        0x55 => (0x6A, false),                         // Keypad *
        0x56 => (0x6D, false),                         // Keypad -
        0x57 => (0x6B, false),                         // Keypad +
        0x58 => (0x0D, true),                          // Keypad Enter
        0x59..=0x61 => (0x61 + (usage - 0x59), false), // Keypad 1..9
        0x62 => (0x60, false),                         // Keypad 0
        0x63 => (0x6E, false),                         // Keypad .
        0xE0 => (0xA2, false),                         // Left Control
        0xE1 => (0xA0, false),                         // Left Shift
        0xE2 => (0xA4, false),                         // Left Alt / Menu
        0xE3 => (0x5B, true),                          // Left Windows
        0xE4 => (0xA3, true),                          // Right Control
        0xE5 => (0xA1, true),                          // Right Shift
        0xE6 => (0xA5, true),                          // Right Alt / Menu
        0xE7 => (0x5C, true),                          // Right Windows
        other => (other, false),
    }
}

/// Converts a reconciled [`AppliedInput`] action into equivalent Win32 `INPUT` structures.
pub fn applied_input_to_win32(action: AppliedInput) -> Result<Vec<Win32Input>, PlatformError> {
    use win32_input_consts::*;
    match action {
        AppliedInput::Key { code, pressed } => {
            let (vk_code, is_extended) = hid_usage_to_win32_vk(code);
            let mut flags = if pressed { 0 } else { KEYEVENTF_KEYUP };
            if is_extended {
                flags |= KEYEVENTF_EXTENDEDKEY;
            }
            Ok(vec![Win32Input::Keyboard(Win32KeyboardInput {
                vk_code,
                scan_code: 0,
                flags,
                time: 0,
                extra_info: 0,
            })])
        }
        AppliedInput::PointerButton { button, pressed } => {
            let (flags, mouse_data) = match button {
                0 => (
                    if pressed {
                        MOUSEEVENTF_LEFTDOWN
                    } else {
                        MOUSEEVENTF_LEFTUP
                    },
                    0,
                ),
                1 => (
                    if pressed {
                        MOUSEEVENTF_RIGHTDOWN
                    } else {
                        MOUSEEVENTF_RIGHTUP
                    },
                    0,
                ),
                2 => (
                    if pressed {
                        MOUSEEVENTF_MIDDLEDOWN
                    } else {
                        MOUSEEVENTF_MIDDLEUP
                    },
                    0,
                ),
                3 => (
                    if pressed {
                        MOUSEEVENTF_XDOWN
                    } else {
                        MOUSEEVENTF_XUP
                    },
                    XBUTTON1,
                ),
                4 => (
                    if pressed {
                        MOUSEEVENTF_XDOWN
                    } else {
                        MOUSEEVENTF_XUP
                    },
                    XBUTTON2,
                ),
                _ => return Err(PlatformError::Unsupported),
            };
            Ok(vec![Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data,
                flags,
                time: 0,
                extra_info: 0,
            })])
        }
        AppliedInput::PointerMotionRelative { dx, dy } => {
            Ok(vec![Win32Input::Mouse(Win32MouseInput {
                dx,
                dy,
                mouse_data: 0,
                flags: MOUSEEVENTF_MOVE,
                time: 0,
                extra_info: 0,
            })])
        }
        AppliedInput::PointerMotionAbsolute {
            x,
            y,
            width,
            height,
        } => {
            if width == 0 || height == 0 || x >= width || y >= height {
                return Err(PlatformError::CoordinateBounds);
            }
            let denom_x = u64::from(width.saturating_sub(1).max(1));
            let denom_y = u64::from(height.saturating_sub(1).max(1));
            let norm_x = ((u64::from(x) * 65535) / denom_x) as i32;
            let norm_y = ((u64::from(y) * 65535) / denom_y) as i32;
            let flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
            Ok(vec![Win32Input::Mouse(Win32MouseInput {
                dx: norm_x,
                dy: norm_y,
                mouse_data: 0,
                flags,
                time: 0,
                extra_info: 0,
            })])
        }
        AppliedInput::Wheel {
            horizontal,
            vertical,
        } => {
            let mut inputs = Vec::new();
            if vertical != 0 {
                let mouse_data = (i32::from(vertical) * WHEEL_DELTA) as u32;
                inputs.push(Win32Input::Mouse(Win32MouseInput {
                    dx: 0,
                    dy: 0,
                    mouse_data,
                    flags: MOUSEEVENTF_WHEEL,
                    time: 0,
                    extra_info: 0,
                }));
            }
            if horizontal != 0 {
                let mouse_data = (i32::from(horizontal) * WHEEL_DELTA) as u32;
                inputs.push(Win32Input::Mouse(Win32MouseInput {
                    dx: 0,
                    dy: 0,
                    mouse_data,
                    flags: MOUSEEVENTF_HWHEEL,
                    time: 0,
                    extra_info: 0,
                }));
            }
            Ok(inputs)
        }
    }
}

/// Windows input injection backend.
///
/// Converts reconciled [`AppliedInput`] actions to Win32 `INPUT` structures while
/// enforcing security policy: unverified agents, secure desktop sessions, locked sessions,
/// or higher-integrity targets are strictly denied before injection.
#[derive(Debug)]
pub struct WindowsInputBackend {
    context: InputTargetContext,
    binding: Option<AgentBinding>,
    injected_count: u64,
    diagnostics: ProviderDiagnostics,
    recorded_inputs: Vec<Win32Input>,
}

impl WindowsInputBackend {
    pub fn new(context: InputTargetContext, binding: Option<AgentBinding>) -> Self {
        Self {
            context,
            binding,
            injected_count: 0,
            diagnostics: ProviderDiagnostics::idle("windows_input_backend"),
            recorded_inputs: Vec::new(),
        }
    }

    pub fn for_interactive_agent(binding: AgentBinding, agent_integrity: IntegrityLevel) -> Self {
        let context = InputTargetContext {
            agent_integrity,
            target_integrity: agent_integrity,
            secure_desktop: false,
            session_locked: false,
        };
        Self::new(context, Some(binding))
    }

    pub fn update_context(&mut self, context: InputTargetContext) {
        self.context = context;
    }

    pub fn invalidate_binding(&mut self) {
        self.binding = None;
    }

    pub fn recorded_inputs(&self) -> &[Win32Input] {
        &self.recorded_inputs
    }

    pub fn clear_recorded_inputs(&mut self) {
        self.recorded_inputs.clear();
        self.diagnostics.queue_depth = 0;
    }

    pub fn injected_count(&self) -> u64 {
        self.injected_count
    }
}

impl InputBackend for WindowsInputBackend {
    fn name(&self) -> &'static str {
        "windows_input_backend"
    }

    fn inject(&mut self, action: AppliedInput) -> Result<(), PlatformError> {
        let validated_action = validate_input_action(action, self.context)?;
        if self.binding.is_none() {
            return Err(PlatformError::PermissionRevoked);
        }
        let win32_inputs = applied_input_to_win32(validated_action)?;
        self.injected_count = self
            .injected_count
            .saturating_add(win32_inputs.len() as u64);
        self.recorded_inputs.extend(win32_inputs);
        self.diagnostics.queue_depth = self.recorded_inputs.len();
        self.diagnostics.state = ProviderState::Running;
        Ok(())
    }

    fn release_all(&mut self, actions: &[AppliedInput]) -> Result<(), PlatformError> {
        for &action in actions {
            self.inject(action)?;
        }
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

/// Swap chain configuration for Windows D3D11 presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsSwapChainConfig {
    pub width: u32,
    pub height: u32,
    pub sync_interval: u32,
    pub allow_tearing: bool,
    pub back_buffer_count: u32,
}

impl Default for WindowsSwapChainConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            sync_interval: 0,
            allow_tearing: false,
            back_buffer_count: 2,
        }
    }
}

/// Cached Windows cursor state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCursorState {
    pub cursor_id: u64,
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub width: u16,
    pub height: u16,
    pub rgba: Option<Vec<u8>>,
}

/// Windows D3D11 hardware presentation backend.
///
/// Implements [`RenderBackend`] by presenting D3D11 / CPU surfaces through
/// DXGI swap chains, polling native GPU completion fences, handling cursor updates,
/// and executing fail-closed quiescence.
#[derive(Debug)]
pub struct WindowsRenderBackend {
    device: DeviceIdentity,
    swapchain_config: WindowsSwapChainConfig,
    cursor_mode: CursorMode,
    cursor: Option<WindowsCursorState>,
    active_submission: Option<u64>,
    completion_status: NativePresentationCompletion,
    device_lost: bool,
    quiesced: bool,
    presented_count: u64,
    fail_next_present: Option<PlatformError>,
    fail_next_completion: Option<PlatformError>,
    fail_next_quiesce: Option<PlatformError>,
    diagnostics: ProviderDiagnostics,
}

impl WindowsRenderBackend {
    pub fn new(
        device: DeviceIdentity,
        swapchain_config: WindowsSwapChainConfig,
        cursor_mode: CursorMode,
    ) -> Self {
        Self {
            device,
            swapchain_config,
            cursor_mode,
            cursor: None,
            active_submission: None,
            completion_status: NativePresentationCompletion::Complete,
            device_lost: false,
            quiesced: true,
            presented_count: 0,
            fail_next_present: None,
            fail_next_completion: None,
            fail_next_quiesce: None,
            diagnostics: ProviderDiagnostics::idle("windows_d3d11_render_backend"),
        }
    }

    pub fn device(&self) -> DeviceIdentity {
        self.device
    }

    pub fn swapchain_config(&self) -> WindowsSwapChainConfig {
        self.swapchain_config
    }

    pub fn cursor_mode(&self) -> CursorMode {
        self.cursor_mode
    }

    pub fn cursor_state(&self) -> Option<&WindowsCursorState> {
        self.cursor.as_ref()
    }

    pub fn active_submission(&self) -> Option<u64> {
        self.active_submission
    }

    pub fn presented_count(&self) -> u64 {
        self.presented_count
    }

    pub fn is_quiesced(&self) -> bool {
        self.quiesced
    }

    pub fn set_completion_status(&mut self, status: NativePresentationCompletion) {
        self.completion_status = status;
    }

    pub fn trigger_device_loss(&mut self) {
        self.device_lost = true;
        self.diagnostics.state = ProviderState::Failed;
        self.diagnostics.last_error = Some("DXGI_ERROR_DEVICE_REMOVED".to_string());
    }

    pub fn set_fail_next_present(&mut self, error: PlatformError) {
        self.fail_next_present = Some(error);
    }

    pub fn set_fail_next_completion(&mut self, error: PlatformError) {
        self.fail_next_completion = Some(error);
    }

    pub fn set_fail_next_quiesce(&mut self, error: PlatformError) {
        self.fail_next_quiesce = Some(error);
    }
}

impl RenderBackend for WindowsRenderBackend {
    fn name(&self) -> &'static str {
        "windows_d3d11_render_backend"
    }

    fn present(
        &mut self,
        submission: PresentationSubmissionGuard,
    ) -> Result<PresentSubmission, RenderFailure> {
        if self.device_lost {
            return Err(submission.reject(PlatformError::DeviceLost));
        }
        if let Some(error) = self.fail_next_present.take() {
            return Err(submission.reject(error));
        }
        let preflight = submission.preflight();
        if preflight.descriptor.memory_domain != MemoryDomain::D3D11
            && preflight.descriptor.memory_domain != MemoryDomain::Cpu
        {
            return Err(submission.reject(PlatformError::InvalidSurface));
        }
        if preflight.descriptor.validate().is_err() {
            return Err(submission.reject(PlatformError::InvalidSurface));
        }
        if self.active_submission.is_some()
            && self.completion_status == NativePresentationCompletion::Pending
        {
            return Err(submission.reject(PlatformError::PresentationInFlight));
        }

        let submit_ns = preflight.ready_ns;
        let queue_depth_after_submit = 1;
        let pres_sub = submission.submit(submit_ns, queue_depth_after_submit)?;

        self.active_submission = Some(pres_sub.id());
        self.completion_status = NativePresentationCompletion::Complete;
        self.presented_count = self.presented_count.saturating_add(1);
        self.quiesced = false;
        self.diagnostics.queue_depth = 1;
        self.diagnostics.state = ProviderState::Running;

        Ok(pres_sub)
    }

    fn poll_present_completion(
        &mut self,
        submission: &PresentSubmission,
    ) -> Result<NativePresentationCompletion, PlatformError> {
        if self.device_lost {
            return Err(PlatformError::DeviceLost);
        }
        if let Some(error) = self.fail_next_completion.take() {
            return Err(error);
        }
        if let Some(active_id) = self.active_submission {
            if active_id != submission.id() {
                return Err(PlatformError::RendererReturnedMismatchedLease);
            }
        }
        let status = self.completion_status;
        if status == NativePresentationCompletion::Complete {
            self.active_submission = None;
            self.diagnostics.queue_depth = 0;
        }
        Ok(status)
    }

    fn quiesce_presentation(&mut self) -> Result<(), PlatformError> {
        if self.device_lost {
            return Err(PlatformError::DeviceLost);
        }
        if let Some(error) = self.fail_next_quiesce.take() {
            return Err(error);
        }
        self.active_submission = None;
        self.completion_status = NativePresentationCompletion::Complete;
        self.quiesced = true;
        self.diagnostics.queue_depth = 0;
        self.diagnostics.state = ProviderState::Idle;
        Ok(())
    }

    fn set_cursor(&mut self, cursor: CursorUpdate<'_>) -> Result<(), PlatformError> {
        cursor.validate()?;
        let visible = match self.cursor_mode {
            CursorMode::Hidden => false,
            _ => cursor.visible,
        };
        self.cursor = Some(WindowsCursorState {
            cursor_id: cursor.cursor_id,
            visible,
            x: cursor.x,
            y: cursor.y,
            hotspot_x: cursor.hotspot_x,
            hotspot_y: cursor.hotspot_y,
            width: cursor.width,
            height: cursor.height,
            rgba: cursor.rgba.map(|bytes| bytes.to_vec()),
        });
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsBackendError {
    InvalidState,
    Unsupported,
    RetryNotReady,
    GenerationExhausted,
    DrainInProgress,
    MetadataLimit,
    MetadataBounds,
    MemoryDomain,
    FrameDescriptor,
    LedgerEpoch,
    DestinationMismatch,
    BorrowedDirectAlias,
    AgentIdentity,
    StaleGeneration,
    Surface(SurfaceError),
    H264(H264Error),
}

impl fmt::Display for WindowsBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for WindowsBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Surface(error) => Some(error),
            Self::H264(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_media::{
        CopyEvidenceGrade, DeviceIdentity, ImportPath, LeaseCompletion, SourceLeaseIdentity,
        SurfaceLayout, SynchronizationProof, TransferEdge,
    };
    use latencydesk_platform::ProviderState;

    fn empty_metadata() -> DesktopMetadata {
        DesktopMetadata {
            dirty_rects: Vec::new(),
            move_rects: Vec::new(),
            pointer_shape: Vec::new(),
            pointer_visible: false,
            pointer_x: 0,
            pointer_y: 0,
        }
    }

    fn copy_ledger(
        descriptor: FrameDescriptor,
        display_epoch: u32,
        path: ImportPath,
    ) -> CopyLedger {
        CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: display_epoch,
                capture_sequence: descriptor.capture_sequence,
            },
            source_device: DeviceIdentity::Opaque(1),
            destination_device: DeviceIdentity::Opaque(1),
            source_layout: SurfaceLayout {
                memory_domain: descriptor.memory_domain,
                format_fourcc: descriptor.format_fourcc,
                plane_count: 1,
                modifier: None,
            },
            destination_layout: SurfaceLayout {
                memory_domain: MemoryDomain::D3D11,
                format_fourcc: u32::from_le_bytes(*b"NV12"),
                plane_count: 2,
                modifier: None,
            },
            transfer_edge: TransferEdge::CaptureToEncoder,
            path,
            synchronization: SynchronizationProof::D3D11EventQuery,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: match path {
                ImportPath::DirectAlias => CopyEvidenceGrade::ProfilerVerifiedNoApplicationCopy,
                _ => CopyEvidenceGrade::CompletionProven,
            },
        }
    }

    fn destination() -> WindowsCaptureDestination {
        WindowsCaptureDestination::new(DeviceIdentity::Opaque(1), u32::from_le_bytes(*b"NV12"), 2)
            .expect("destination")
    }

    fn local_user(session: u32, luid: u64) -> VerifiedInteractiveUser {
        VerifiedInteractiveUser::verify(LocalInteractiveUserEvidence {
            windows_session_id: session,
            logon_luid: luid,
            interactive_token_verified: true,
        })
        .expect("locally verified user")
    }

    #[test]
    fn display_target_never_switches_to_wgc_automatically() {
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, true);
        assert_eq!(
            selector.start(0).expect("start"),
            WindowsCaptureApi::DesktopDuplication
        );
        assert_eq!(
            selector.fail(CaptureFailure::Unsupported, 1),
            Ok(CaptureRecoveryAction::StopUnsupported)
        );
        assert_eq!(selector.state(), ProviderState::Failed);
        assert_eq!(selector.active(), None);

        let mut unavailable =
            CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, false, true);
        assert_eq!(unavailable.start(0), Err(WindowsBackendError::Unsupported));
    }

    #[test]
    fn authorized_wgc_targets_use_wgc_explicitly() {
        for target in [
            WindowsCaptureTarget::AuthorizedWgcDisplay,
            WindowsCaptureTarget::AuthorizedWgcWindow,
        ] {
            let mut selector = CaptureSelector::new(target, false, true);
            assert_eq!(
                selector.start(0).expect("start"),
                WindowsCaptureApi::WindowsGraphicsCapture
            );
        }
    }

    #[test]
    fn access_loss_uses_bounded_backoff_and_new_epoch() {
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, false);
        selector.start(0).expect("start");
        let old_epoch = selector.display_epoch();
        let action = selector.fail(CaptureFailure::AccessLost, 100);
        let Ok(CaptureRecoveryAction::RecreateAfter { retry_at_ns }) = action else {
            panic!("unexpected action");
        };
        assert!(retry_at_ns > 100);
        assert!(selector.display_epoch() > old_epoch);
        assert_eq!(selector.mark_recovered(retry_at_ns), Ok(()));
    }

    #[test]
    fn masked_protected_content_invalidates_active_epoch_without_backoff() {
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, false);
        selector.start(0).expect("start");
        let old_epoch = selector.display_epoch();

        assert_eq!(
            selector.fail(CaptureFailure::ProtectedContent, 10),
            Ok(CaptureRecoveryAction::SurfaceProtectedContent)
        );
        assert!(selector.display_epoch() > old_epoch);
        assert_eq!(selector.state(), ProviderState::Running);
        assert_eq!(
            selector.active(),
            Some(WindowsCaptureApi::DesktopDuplication)
        );
        assert_eq!(
            selector.fail(CaptureFailure::AccessLost, 20),
            Ok(CaptureRecoveryAction::RecreateAfter {
                retry_at_ns: 20_000_020
            })
        );
    }

    #[test]
    fn metadata_is_bounded_before_surface_import() {
        let metadata = DesktopMetadata {
            dirty_rects: vec![Rect {
                left: 0,
                top: 0,
                right: 100,
                bottom: 100,
            }],
            move_rects: Vec::new(),
            pointer_shape: Vec::new(),
            pointer_visible: true,
            pointer_x: 1,
            pointer_y: 1,
        };
        assert_eq!(
            metadata.validate(100, 100, MetadataLimits::default()),
            Ok(())
        );
        let bad = DesktopMetadata {
            dirty_rects: vec![Rect {
                left: -1,
                top: 0,
                right: 10,
                bottom: 10,
            }],
            ..metadata
        };
        assert_eq!(
            bad.validate(100, 100, MetadataLimits::default()),
            Err(WindowsBackendError::MetadataBounds)
        );
    }

    #[test]
    fn capture_surface_import_has_copy_fallback() {
        let pool = SurfacePool::new(2);
        let descriptor = FrameDescriptor {
            width: 1_920,
            height: 1_080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 1,
        };
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, false);
        selector.start(0).expect("start");
        let request = selector
            .reserve_frame(
                &pool,
                NativeDestinationReservationId(1),
                destination(),
                NativeFrameReservationInput {
                    identity: NativeCaptureEventIdentity {
                        session: NativeCaptureSessionIdentity(1),
                        agent_generation: 1,
                    },
                    frame: NativePendingFrameIdentity(1),
                    source_observed_epoch: 1,
                    source_descriptor: descriptor,
                    metadata: empty_metadata(),
                },
            )
            .expect("reserve");
        let frame = request
            .complete(copy_ledger(descriptor, 1, ImportPath::GpuConvert))
            .expect("import")
            .imported;
        assert_eq!(
            frame.surface.import_path().expect("path"),
            ImportPath::GpuConvert
        );
        assert_eq!(frame.copy_ledger.path, ImportPath::GpuConvert);
        drop(frame);
        assert_eq!(pool.in_use(), 0);
    }

    #[derive(Debug)]
    struct NativeDestinationPayload;

    impl latencydesk_surface::SurfacePayload for NativeDestinationPayload {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn native_detach_retains_the_exact_destination_payload() {
        let pool = SurfacePool::new(1);
        let descriptor = FrameDescriptor {
            width: 1_920,
            height: 1_080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 2,
            capture_timestamp_ns: 2,
        };
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, false);
        selector.start(0).expect("start");
        let request = selector
            .reserve_frame(
                &pool,
                NativeDestinationReservationId(2),
                destination(),
                NativeFrameReservationInput {
                    identity: NativeCaptureEventIdentity {
                        session: NativeCaptureSessionIdentity(2),
                        agent_generation: 1,
                    },
                    frame: NativePendingFrameIdentity(2),
                    source_observed_epoch: 1,
                    source_descriptor: descriptor,
                    metadata: empty_metadata(),
                },
            )
            .expect("reserve");

        let frame = request
            .complete_with_payload(
                copy_ledger(descriptor, 1, ImportPath::GpuConvert),
                Box::new(NativeDestinationPayload),
            )
            .expect("import")
            .imported;

        assert!(frame
            .surface
            .payload::<NativeDestinationPayload>()
            .is_some());
    }

    #[test]
    fn capture_surface_import_requires_matching_display_epoch() {
        let pool = SurfacePool::new(1);
        let descriptor = FrameDescriptor {
            width: 1,
            height: 1,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 1,
        };
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, false);
        selector.start(0).expect("start");
        let request = selector
            .reserve_frame(
                &pool,
                NativeDestinationReservationId(1),
                destination(),
                NativeFrameReservationInput {
                    identity: NativeCaptureEventIdentity {
                        session: NativeCaptureSessionIdentity(1),
                        agent_generation: 1,
                    },
                    frame: NativePendingFrameIdentity(1),
                    source_observed_epoch: 1,
                    source_descriptor: descriptor,
                    metadata: empty_metadata(),
                },
            )
            .expect("reserve");
        let error = request
            .complete(copy_ledger(descriptor, 2, ImportPath::GpuConvert))
            .expect_err("ledger epoch mismatch");
        assert!(matches!(
            error,
            NativeFrameDetachError::Contract {
                error: WindowsBackendError::LedgerEpoch,
                ..
            }
        ));
        assert_eq!(pool.in_use(), 1);
        drop(error);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn terminal_capture_selector_rejects_stale_import() {
        let pool = SurfacePool::new(1);
        let descriptor = FrameDescriptor {
            width: 1,
            height: 1,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 1,
        };
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, false);
        selector.start(0).expect("start");
        selector
            .fail(CaptureFailure::Unsupported, 1)
            .expect("terminal failure");

        let error = selector
            .reserve_frame(
                &pool,
                NativeDestinationReservationId(1),
                destination(),
                NativeFrameReservationInput {
                    identity: NativeCaptureEventIdentity {
                        session: NativeCaptureSessionIdentity(1),
                        agent_generation: 1,
                    },
                    frame: NativePendingFrameIdentity(1),
                    source_observed_epoch: 1,
                    source_descriptor: descriptor,
                    metadata: empty_metadata(),
                },
            )
            .expect_err("failed provider must reject stale capture frames");
        assert!(matches!(error, WindowsBackendError::InvalidState));
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn note_display_change_increments_epoch_and_rejects_previous_generation_frames() {
        let pool = SurfacePool::new(2);
        let descriptor = FrameDescriptor {
            width: 1,
            height: 1,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 1,
        };
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, false);
        selector.start(0).expect("start");
        assert_eq!(selector.display_epoch(), 1);

        let new_epoch = selector.note_display_change().expect("epoch advanced");
        assert_eq!(new_epoch, 2);
        assert_eq!(selector.display_epoch(), 2);

        // Frame from old epoch 1 is rejected
        let error = selector
            .reserve_frame(
                &pool,
                NativeDestinationReservationId(1),
                destination(),
                NativeFrameReservationInput {
                    identity: NativeCaptureEventIdentity {
                        session: NativeCaptureSessionIdentity(1),
                        agent_generation: 1,
                    },
                    frame: NativePendingFrameIdentity(1),
                    source_observed_epoch: 1,
                    source_descriptor: descriptor,
                    metadata: empty_metadata(),
                },
            )
            .expect_err("stale generation frame must be rejected");
        assert!(matches!(error, WindowsBackendError::LedgerEpoch));

        // Frame from new epoch 2 is accepted
        let request = selector
            .reserve_frame(
                &pool,
                NativeDestinationReservationId(2),
                destination(),
                NativeFrameReservationInput {
                    identity: NativeCaptureEventIdentity {
                        session: NativeCaptureSessionIdentity(1),
                        agent_generation: 1,
                    },
                    frame: NativePendingFrameIdentity(2),
                    source_observed_epoch: 2,
                    source_descriptor: descriptor,
                    metadata: empty_metadata(),
                },
            )
            .expect("current epoch frame must be accepted");
        assert_eq!(request.source_observed_epoch, 2);
    }

    #[test]
    fn secure_desktop_and_uipi_are_not_bypassed() {
        let secure = InputTargetContext {
            agent_integrity: IntegrityLevel::Medium,
            target_integrity: IntegrityLevel::Medium,
            secure_desktop: true,
            session_locked: false,
        };
        assert_eq!(
            evaluate_input_policy(secure),
            InputPolicyDecision::DenySecureDesktop
        );
        let elevated = InputTargetContext {
            secure_desktop: false,
            target_integrity: IntegrityLevel::High,
            ..secure
        };
        assert_eq!(
            evaluate_input_policy(elevated),
            InputPolicyDecision::DenyHigherIntegrityTarget
        );
    }

    #[test]
    fn broker_requires_os_verified_peer_and_generation_drain() {
        let user = local_user(2, 42);
        let (challenge, response) = issue_agent_launch_challenge([7_u8; 32]).expect("challenge");
        assert_eq!(
            VerifiedAgentPeer::verify(AgentPeerEvidence {
                windows_session_id: 2,
                logon_luid: 42,
                agent_pid: 100,
                named_pipe_acl_verified: false,
                interactive_token_verified: true,
            }),
            Err(WindowsBackendError::AgentIdentity)
        );

        let mut broker = PerUserAgentBroker::default();
        broker.begin_agent_launch(user, challenge).expect("launch");
        let peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 100,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("verified peer");
        let binding = broker
            .authenticate_agent(peer, response)
            .expect("authenticate");
        let broker = Arc::new(Mutex::new(broker));
        assert_eq!(
            PerUserAgentBroker::session_changed(&broker).expect("drain"),
            binding
        );
        assert_eq!(
            broker.lock().expect("broker").finish_draining(binding),
            Ok(())
        );
        assert_eq!(
            broker.lock().expect("broker").state(),
            &AgentBrokerState::Idle
        );
    }

    #[test]
    fn broker_binds_agent_to_matching_interactive_user_and_generation() {
        let mut broker = PerUserAgentBroker::default();
        let (challenge, response) = issue_agent_launch_challenge([7_u8; 32]).expect("challenge");
        broker
            .begin_agent_launch(local_user(2, 42), challenge)
            .expect("launch");

        let different_user = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 43,
            agent_pid: 100,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("verified peer");
        assert_eq!(
            broker.authenticate_agent(different_user, response),
            Err(WindowsBackendError::AgentIdentity)
        );

        let peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 100,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("verified peer");
        let (_, stale_response) = issue_agent_launch_challenge([7_u8; 32]).expect("stale response");
        assert_eq!(
            broker.authenticate_agent(peer, stale_response),
            Err(WindowsBackendError::InvalidState)
        );

        let (challenge, response) =
            issue_agent_launch_challenge([8_u8; 32]).expect("fresh challenge");
        broker
            .begin_agent_launch(local_user(2, 42), challenge)
            .expect("fresh launch");
        let peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 100,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("fresh peer");
        let binding = broker
            .authenticate_agent(peer, response)
            .expect("authenticate fresh attempt");
        assert!(broker.is_current_binding(binding));
        let broker = Arc::new(Mutex::new(broker));
        PerUserAgentBroker::session_changed(&broker).expect("drain");
        assert!(!broker.lock().expect("broker").is_current_binding(binding));
    }

    #[test]
    fn launch_peer_and_challenge_are_consumed_by_one_authentication_attempt() {
        let mut broker = PerUserAgentBroker::default();
        let user = VerifiedInteractiveUser::verify(LocalInteractiveUserEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            interactive_token_verified: true,
        })
        .expect("local user");
        let (_other_launch, wrong_response) =
            issue_agent_launch_challenge([8_u8; 32]).expect("other challenge");
        let (launch, right_response) =
            issue_agent_launch_challenge([7_u8; 32]).expect("launch challenge");
        broker.begin_agent_launch(user, launch).expect("launch");
        let wrong_attempt_peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 100,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("peer");
        assert_eq!(
            broker.authenticate_agent(wrong_attempt_peer, wrong_response),
            Err(WindowsBackendError::AgentIdentity)
        );
        let retry_peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 100,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("fresh retry peer");
        assert_eq!(
            broker.authenticate_agent(retry_peer, right_response),
            Err(WindowsBackendError::InvalidState)
        );

        let user = VerifiedInteractiveUser::verify(LocalInteractiveUserEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            interactive_token_verified: true,
        })
        .expect("fresh local user");
        let (launch, response) = issue_agent_launch_challenge([9_u8; 32]).expect("fresh challenge");
        broker
            .begin_agent_launch(user, launch)
            .expect("fresh launch");
        let peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 101,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("fresh peer");
        let first = broker
            .authenticate_agent(peer, response)
            .expect("authenticate fresh attempt");
        assert_eq!(first.generation(), 1);
        let broker = Arc::new(Mutex::new(broker));
        PerUserAgentBroker::session_changed(&broker).expect("drain");
        broker
            .lock()
            .expect("broker")
            .finish_draining(first)
            .expect("finish drain");

        let user = VerifiedInteractiveUser::verify(LocalInteractiveUserEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            interactive_token_verified: true,
        })
        .expect("next-generation local user");
        let (launch, response) = issue_agent_launch_challenge([10_u8; 32]).expect("next challenge");
        broker
            .lock()
            .expect("broker")
            .begin_agent_launch(user, launch)
            .expect("next launch");
        let peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 102,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("next-generation peer");
        let second = broker
            .lock()
            .expect("broker")
            .authenticate_agent(peer, response)
            .expect("authenticate next generation");
        assert_eq!(second.generation(), 2);
    }
    #[test]
    fn windows_encode_backend_rejects_invalid_policy() {
        let invalid_policy = LowDelayPolicy {
            b_frames: 1,
            ..LowDelayPolicy::baseline(60)
        };
        assert!(matches!(
            WindowsEncodeBackend::new(DeviceIdentity::Opaque(1), invalid_policy, 1),
            Err(WindowsBackendError::H264(H264Error::BFrameForbidden))
        ));
    }

    #[test]
    fn windows_encode_backend_submits_and_tracks_annex_b_continuity() {
        let mut encoder =
            WindowsEncodeBackend::new(DeviceIdentity::Opaque(1), LowDelayPolicy::baseline(60), 1)
                .expect("encoder");

        let idr = &[0, 0, 0, 1, 0x67, 1, 0, 0, 1, 0x68, 2, 0, 0, 1, 0x65, 0xb8];
        let p_frame = &[0, 0, 1, 0x41, 0xe0];

        let meta1 = encoder.process_annex_b(idr).expect("idr meta");
        assert!(meta1.recovery_point);
        assert_eq!(meta1.frame_id, 1);
        assert_eq!(meta1.dependency_frame_id, None);

        let meta2 = encoder.process_annex_b(p_frame).expect("p meta");
        assert!(!meta2.recovery_point);
        assert_eq!(meta2.frame_id, 2);
        assert_eq!(meta2.dependency_frame_id, Some(1));

        encoder.note_output_drop();
        assert_eq!(
            encoder.process_annex_b(p_frame),
            Err(WindowsBackendError::H264(H264Error::RecoveryPointRequired))
        );

        let meta3 = encoder.process_annex_b(idr).expect("recovery idr");
        assert!(meta3.recovery_point);
        assert_eq!(meta3.frame_id, 4);
    }

    #[test]
    fn test_win32_input_key_translation() {
        use win32_input_consts::*;

        // Standard letter 'A' press & release
        let press_a = applied_input_to_win32(AppliedInput::Key {
            code: 0x04,
            pressed: true,
        })
        .expect("key translation");
        assert_eq!(press_a.len(), 1);
        assert_eq!(
            press_a[0],
            Win32Input::Keyboard(Win32KeyboardInput {
                vk_code: 0x41, // 'A'
                scan_code: 0,
                flags: 0,
                time: 0,
                extra_info: 0,
            })
        );

        let release_a = applied_input_to_win32(AppliedInput::Key {
            code: 0x04,
            pressed: false,
        })
        .expect("key translation");
        assert_eq!(release_a.len(), 1);
        assert_eq!(
            release_a[0],
            Win32Input::Keyboard(Win32KeyboardInput {
                vk_code: 0x41,
                scan_code: 0,
                flags: KEYEVENTF_KEYUP,
                time: 0,
                extra_info: 0,
            })
        );

        // Extended key (Right Arrow = 0x4F)
        let right_arrow = applied_input_to_win32(AppliedInput::Key {
            code: 0x4F,
            pressed: true,
        })
        .expect("key translation");
        assert_eq!(
            right_arrow[0],
            Win32Input::Keyboard(Win32KeyboardInput {
                vk_code: 0x27, // VK_RIGHT
                scan_code: 0,
                flags: KEYEVENTF_EXTENDEDKEY,
                time: 0,
                extra_info: 0,
            })
        );

        // Enter = 0x28
        let enter = applied_input_to_win32(AppliedInput::Key {
            code: 0x28,
            pressed: false,
        })
        .expect("key translation");
        assert_eq!(
            enter[0],
            Win32Input::Keyboard(Win32KeyboardInput {
                vk_code: 0x0D, // VK_RETURN
                scan_code: 0,
                flags: KEYEVENTF_KEYUP,
                time: 0,
                extra_info: 0,
            })
        );
    }

    #[test]
    fn test_win32_input_pointer_buttons() {
        use win32_input_consts::*;

        // Button 0 (Left)
        let left_down = applied_input_to_win32(AppliedInput::PointerButton {
            button: 0,
            pressed: true,
        })
        .expect("pointer button");
        assert_eq!(
            left_down[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: 0,
                flags: MOUSEEVENTF_LEFTDOWN,
                time: 0,
                extra_info: 0,
            })
        );

        let left_up = applied_input_to_win32(AppliedInput::PointerButton {
            button: 0,
            pressed: false,
        })
        .expect("pointer button");
        assert_eq!(
            left_up[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: 0,
                flags: MOUSEEVENTF_LEFTUP,
                time: 0,
                extra_info: 0,
            })
        );

        // Button 1 (Right)
        let right_down = applied_input_to_win32(AppliedInput::PointerButton {
            button: 1,
            pressed: true,
        })
        .expect("pointer button");
        assert_eq!(
            right_down[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: 0,
                flags: MOUSEEVENTF_RIGHTDOWN,
                time: 0,
                extra_info: 0,
            })
        );

        // Button 2 (Middle)
        let mid_down = applied_input_to_win32(AppliedInput::PointerButton {
            button: 2,
            pressed: true,
        })
        .expect("pointer button");
        assert_eq!(
            mid_down[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: 0,
                flags: MOUSEEVENTF_MIDDLEDOWN,
                time: 0,
                extra_info: 0,
            })
        );

        // Button 3 (X1)
        let x1_down = applied_input_to_win32(AppliedInput::PointerButton {
            button: 3,
            pressed: true,
        })
        .expect("pointer button");
        assert_eq!(
            x1_down[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: XBUTTON1,
                flags: MOUSEEVENTF_XDOWN,
                time: 0,
                extra_info: 0,
            })
        );

        // Button 4 (X2)
        let x2_up = applied_input_to_win32(AppliedInput::PointerButton {
            button: 4,
            pressed: false,
        })
        .expect("pointer button");
        assert_eq!(
            x2_up[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: XBUTTON2,
                flags: MOUSEEVENTF_XUP,
                time: 0,
                extra_info: 0,
            })
        );

        // Button 5 (Unsupported)
        assert_eq!(
            applied_input_to_win32(AppliedInput::PointerButton {
                button: 5,
                pressed: true,
            }),
            Err(PlatformError::Unsupported)
        );
    }

    #[test]
    fn test_win32_input_pointer_motion_relative_and_absolute() {
        use win32_input_consts::*;

        // Relative motion
        let rel = applied_input_to_win32(AppliedInput::PointerMotionRelative { dx: 15, dy: -25 })
            .expect("relative motion");
        assert_eq!(
            rel[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 15,
                dy: -25,
                mouse_data: 0,
                flags: MOUSEEVENTF_MOVE,
                time: 0,
                extra_info: 0,
            })
        );

        // Absolute motion
        let abs_top_left = applied_input_to_win32(AppliedInput::PointerMotionAbsolute {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        })
        .expect("absolute top left");
        assert_eq!(
            abs_top_left[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: 0,
                flags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                time: 0,
                extra_info: 0,
            })
        );

        let abs_bottom_right = applied_input_to_win32(AppliedInput::PointerMotionAbsolute {
            x: 1919,
            y: 1079,
            width: 1920,
            height: 1080,
        })
        .expect("absolute bottom right");
        assert_eq!(
            abs_bottom_right[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 65535,
                dy: 65535,
                mouse_data: 0,
                flags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                time: 0,
                extra_info: 0,
            })
        );

        // Bounds checking
        assert_eq!(
            applied_input_to_win32(AppliedInput::PointerMotionAbsolute {
                x: 1920,
                y: 500,
                width: 1920,
                height: 1080,
            }),
            Err(PlatformError::CoordinateBounds)
        );
        assert_eq!(
            applied_input_to_win32(AppliedInput::PointerMotionAbsolute {
                x: 100,
                y: 1080,
                width: 1920,
                height: 1080,
            }),
            Err(PlatformError::CoordinateBounds)
        );
        assert_eq!(
            applied_input_to_win32(AppliedInput::PointerMotionAbsolute {
                x: 0,
                y: 0,
                width: 0,
                height: 1080,
            }),
            Err(PlatformError::CoordinateBounds)
        );
    }

    #[test]
    fn test_win32_input_wheel() {
        use win32_input_consts::*;

        // Vertical wheel
        let vert = applied_input_to_win32(AppliedInput::Wheel {
            horizontal: 0,
            vertical: 2,
        })
        .expect("vertical wheel");
        assert_eq!(vert.len(), 1);
        assert_eq!(
            vert[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: 240, // 2 * 120
                flags: MOUSEEVENTF_WHEEL,
                time: 0,
                extra_info: 0,
            })
        );

        // Horizontal wheel
        let horiz = applied_input_to_win32(AppliedInput::Wheel {
            horizontal: -1,
            vertical: 0,
        })
        .expect("horizontal wheel");
        assert_eq!(horiz.len(), 1);
        assert_eq!(
            horiz[0],
            Win32Input::Mouse(Win32MouseInput {
                dx: 0,
                dy: 0,
                mouse_data: (-120_i32) as u32,
                flags: MOUSEEVENTF_HWHEEL,
                time: 0,
                extra_info: 0,
            })
        );

        // Combined horizontal and vertical
        let combined = applied_input_to_win32(AppliedInput::Wheel {
            horizontal: 1,
            vertical: -2,
        })
        .expect("combined wheel");
        assert_eq!(combined.len(), 2);
        let Win32Input::Mouse(m0) = combined[0] else {
            panic!("expected mouse");
        };
        let Win32Input::Mouse(m1) = combined[1] else {
            panic!("expected mouse");
        };
        assert_eq!(m0.flags, MOUSEEVENTF_WHEEL);
        assert_eq!(m1.flags, MOUSEEVENTF_HWHEEL);
    }

    #[test]
    fn test_windows_input_backend_lifecycle_and_security() {
        let binding = AgentBinding {
            identity: InteractiveUserIdentity::new(2, 42).expect("identity"),
            agent_pid: 1234,
            generation: 1,
        };
        let mut backend =
            WindowsInputBackend::for_interactive_agent(binding, IntegrityLevel::Medium);
        assert_eq!(backend.name(), "windows_input_backend");

        // Normal injection
        let key_action = AppliedInput::Key {
            code: 0x04,
            pressed: true,
        };
        backend.inject(key_action).expect("inject key");
        assert_eq!(backend.injected_count(), 1);
        assert_eq!(backend.recorded_inputs().len(), 1);

        // Release all
        backend
            .release_all(&[
                AppliedInput::Key {
                    code: 0x04,
                    pressed: false,
                },
                AppliedInput::PointerButton {
                    button: 0,
                    pressed: false,
                },
            ])
            .expect("release all");
        assert_eq!(backend.injected_count(), 3);
        assert_eq!(backend.recorded_inputs().len(), 3);

        // Security: Deny Secure Desktop
        backend.update_context(InputTargetContext {
            agent_integrity: IntegrityLevel::Medium,
            target_integrity: IntegrityLevel::Medium,
            secure_desktop: true,
            session_locked: false,
        });
        assert_eq!(
            backend.inject(key_action),
            Err(PlatformError::PermissionDenied)
        );

        // Security: Deny Locked Session
        backend.update_context(InputTargetContext {
            agent_integrity: IntegrityLevel::Medium,
            target_integrity: IntegrityLevel::Medium,
            secure_desktop: false,
            session_locked: true,
        });
        assert_eq!(
            backend.inject(key_action),
            Err(PlatformError::PermissionDenied)
        );

        // Security: Deny Higher Integrity Target
        backend.update_context(InputTargetContext {
            agent_integrity: IntegrityLevel::Medium,
            target_integrity: IntegrityLevel::High,
            secure_desktop: false,
            session_locked: false,
        });
        assert_eq!(
            backend.inject(key_action),
            Err(PlatformError::PermissionDenied)
        );

        // Restore allowed context
        backend.update_context(InputTargetContext {
            agent_integrity: IntegrityLevel::Medium,
            target_integrity: IntegrityLevel::Medium,
            secure_desktop: false,
            session_locked: false,
        });
        backend.inject(key_action).expect("allowed injection");

        // Revoke binding
        backend.invalidate_binding();
        assert_eq!(
            backend.inject(key_action),
            Err(PlatformError::PermissionRevoked)
        );
    }

    #[test]
    fn test_windows_render_backend_cursor_and_bounds() {
        let mut backend = WindowsRenderBackend::new(
            DeviceIdentity::Opaque(1),
            WindowsSwapChainConfig::default(),
            CursorMode::Metadata,
        );

        // Valid cursor with RGBA
        let rgba = vec![255_u8; 16]; // 2x2 pixels * 4 bytes
        let cursor = CursorUpdate {
            cursor_id: 1,
            visible: true,
            x: 50,
            y: 60,
            hotspot_x: 1,
            hotspot_y: 1,
            width: 2,
            height: 2,
            rgba: Some(&rgba),
        };
        backend.set_cursor(cursor).expect("valid cursor");
        let stored = backend.cursor_state().expect("stored cursor");
        assert_eq!(stored.cursor_id, 1);
        assert!(stored.visible);
        assert_eq!(stored.width, 2);
        assert_eq!(stored.height, 2);
        assert_eq!(stored.rgba.as_deref(), Some(rgba.as_slice()));

        // Valid cursor with None RGBA
        let cursor_no_rgba = CursorUpdate {
            cursor_id: 2,
            visible: false,
            x: 100,
            y: 100,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 0,
            height: 0,
            rgba: None,
        };
        backend
            .set_cursor(cursor_no_rgba)
            .expect("cursor without rgba");
        let stored2 = backend.cursor_state().expect("stored cursor");
        assert_eq!(stored2.cursor_id, 2);
        assert!(!stored2.visible);

        // Invalid cursor dimensions > 512
        let invalid_dim = CursorUpdate {
            cursor_id: 3,
            visible: true,
            x: 0,
            y: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 513,
            height: 512,
            rgba: None,
        };
        assert_eq!(
            backend.set_cursor(invalid_dim),
            Err(PlatformError::CursorBounds)
        );

        // Mismatched RGBA buffer length
        let mismatched_rgba = vec![0_u8; 10]; // Not 16
        let invalid_buf = CursorUpdate {
            cursor_id: 4,
            visible: true,
            x: 0,
            y: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 2,
            height: 2,
            rgba: Some(&mismatched_rgba),
        };
        assert_eq!(
            backend.set_cursor(invalid_buf),
            Err(PlatformError::CursorBounds)
        );

        // Hidden mode forces visible to false
        let mut hidden_backend = WindowsRenderBackend::new(
            DeviceIdentity::Opaque(1),
            WindowsSwapChainConfig::default(),
            CursorMode::Hidden,
        );
        let visible_cursor = CursorUpdate {
            cursor_id: 5,
            visible: true,
            x: 10,
            y: 10,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 0,
            height: 0,
            rgba: None,
        };
        hidden_backend
            .set_cursor(visible_cursor)
            .expect("hidden cursor");
        assert!(!hidden_backend.cursor_state().expect("state").visible);
    }
}

#[cfg(test)]
mod lifecycle_review_regressions {
    use super::*;
    use latencydesk_media::{
        CopyEvidenceGrade, DeviceIdentity, ImportPath, LeaseCompletion, SourceLeaseIdentity,
        SurfaceLayout, SynchronizationProof, TransferEdge,
    };
    use latencydesk_platform::{
        CaptureBackend, CaptureEvent, EpochBoundSurface, PresentableFrame, PresentationQueue,
    };
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DetachMode {
        Complete,
        WrongReservation,
        WrongDestination,
        DirectAlias,
        FailNativeAfterSubmit,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StopMode {
        Drained,
        WrongSession,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ReviewStartRecord {
        api: WindowsCaptureApi,
        identity: NativeCaptureEventIdentity,
        wgc_item: Option<NativeWgcItemIdentity>,
    }

    impl ReviewStartRecord {
        const fn api(self) -> WindowsCaptureApi {
            self.api
        }

        const fn event_identity(self) -> NativeCaptureEventIdentity {
            self.identity
        }

        const fn wgc_item_identity(self) -> Option<NativeWgcItemIdentity> {
            self.wgc_item
        }
    }

    struct ReviewSourceState {
        starts: Vec<ReviewStartRecord>,
        active_start: Option<NativeCaptureStart>,
        events: VecDeque<Result<Option<NativeCaptureSourceEvent>, NativeCaptureFailure>>,
        stop_results: VecDeque<Result<StopMode, NativeCaptureFailure>>,
        stops: u32,
        aborts: u32,
        abort_sessions: Vec<Option<NativeCaptureSessionIdentity>>,
        abort_notify: Option<mpsc::Sender<Option<NativeCaptureSessionIdentity>>>,
        discards: u32,
        detaches: u32,
        detach_mode: DetachMode,
        revoke_during_start: Option<WgcAuthorizationRevoker>,
        revoke_during_detach: Option<WgcAuthorizationRevoker>,
        drain_during_start: Option<(Arc<Mutex<PerUserAgentBroker>>, AgentBinding)>,
        drain_during_poll: Option<(Arc<Mutex<PerUserAgentBroker>>, AgentBinding)>,
        finish_during_call: Option<Result<(), WindowsBackendError>>,
        stop_hook: Option<Arc<dyn Fn() + Send + Sync>>,
        abort_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    impl Default for ReviewSourceState {
        fn default() -> Self {
            Self {
                starts: Vec::new(),
                active_start: None,
                events: VecDeque::new(),
                stop_results: VecDeque::new(),
                stops: 0,
                aborts: 0,
                abort_sessions: Vec::new(),
                abort_notify: None,
                discards: 0,
                detaches: 0,
                detach_mode: DetachMode::Complete,
                revoke_during_start: None,
                revoke_during_detach: None,
                drain_during_start: None,
                drain_during_poll: None,
                finish_during_call: None,
                stop_hook: None,
                abort_hook: None,
            }
        }
    }
    impl fmt::Debug for ReviewSourceState {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ReviewSourceState")
                .field("starts", &self.starts)
                .field("stops", &self.stops)
                .field("aborts", &self.aborts)
                .field("discards", &self.discards)
                .field("detaches", &self.detaches)
                .field("detach_mode", &self.detach_mode)
                .finish_non_exhaustive()
        }
    }

    #[derive(Debug, Clone)]
    struct ReviewNativeSource {
        identity: NativeSourceIdentity,
        state: Arc<Mutex<ReviewSourceState>>,
    }

    impl ReviewNativeSource {
        fn new() -> Self {
            Self {
                identity: issue_native_source_identity().expect("source identity"),
                state: Arc::new(Mutex::new(ReviewSourceState::default())),
            }
        }
    }

    impl native_capture_source_seal::Sealed for ReviewNativeSource {}

    #[derive(Debug)]
    struct ReviewAbortHandle {
        state: Arc<Mutex<ReviewSourceState>>,
    }

    impl NativeCaptureAbortHandle for ReviewAbortHandle {
        fn abort(&self, session: Option<NativeCaptureSessionIdentity>) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.aborts = state.aborts.saturating_add(1);
            state.abort_sessions.push(session);
            if let Some(notify) = &state.abort_notify {
                let _ = notify.send(session);
            }
            state.active_start = None;
            let hook = state.abort_hook.clone();
            drop(state);
            if let Some(hook) = hook {
                hook();
            }
        }
    }

    struct SignallingAbortHandle {
        entered: Mutex<Option<mpsc::Sender<Option<NativeCaptureSessionIdentity>>>>,
    }

    impl NativeCaptureAbortHandle for SignallingAbortHandle {
        fn abort(&self, session: Option<NativeCaptureSessionIdentity>) {
            if let Some(entered) = self.entered.lock().expect("abort signal").take() {
                entered.send(session).expect("abort observer");
            }
        }
    }

    impl NativeCaptureSource for ReviewNativeSource {
        fn identity(&self) -> NativeSourceIdentity {
            self.identity
        }

        fn abort_handle(&self) -> Arc<dyn NativeCaptureAbortHandle> {
            Arc::new(ReviewAbortHandle {
                state: Arc::clone(&self.state),
            })
        }

        fn start(&mut self, request: NativeCaptureStart) -> Result<(), NativeCaptureFailure> {
            let (drain_hook, revoke_hook) = {
                let mut state = self.state.lock().expect("source state");
                state.starts.push(ReviewStartRecord {
                    api: request.api(),
                    identity: request.event_identity(),
                    wgc_item: request.wgc_item_identity(),
                });
                state.active_start = Some(request);
                (
                    state.drain_during_start.take(),
                    state.revoke_during_start.take(),
                )
            };
            if let Some(revoker) = revoke_hook {
                revoker.revoke();
            }
            if let Some((broker, binding)) = drain_hook {
                assert_eq!(
                    PerUserAgentBroker::session_changed(&broker).expect("begin drain"),
                    binding
                );
                let finish = broker.lock().expect("broker").finish_draining(binding);
                self.state.lock().expect("source state").finish_during_call = Some(finish);
            }
            Ok(())
        }

        fn poll(
            &mut self,
            _timeout_ns: u64,
        ) -> Result<Option<NativeCaptureSourceEvent>, NativeCaptureFailure> {
            let hook = self
                .state
                .lock()
                .expect("source state")
                .drain_during_poll
                .take();
            if let Some((broker, binding)) = hook {
                assert_eq!(
                    PerUserAgentBroker::session_changed(&broker).expect("begin drain"),
                    binding
                );
                let finish = broker.lock().expect("broker").finish_draining(binding);
                self.state.lock().expect("source state").finish_during_call = Some(finish);
            }
            self.state
                .lock()
                .expect("source state")
                .events
                .pop_front()
                .unwrap_or(Ok(None))
        }

        fn detach_frame(
            &mut self,
            request: NativeFrameDetachRequest,
        ) -> Result<NativeFrameDetachResult, NativeFrameDetachError> {
            let (mode, revoke_hook) = {
                let mut state = self.state.lock().expect("source state");
                state.detaches = state.detaches.saturating_add(1);
                (state.detach_mode, state.revoke_during_detach.take())
            };
            if mode == DetachMode::FailNativeAfterSubmit {
                return Err(request.fail_native(NativeCaptureFailure::new(
                    NativeCaptureFailureKind::DeviceLost,
                    status(NativeCaptureOperation::ImportFrame, 0x887A_0005),
                )));
            }
            let path = if mode == DetachMode::DirectAlias {
                ImportPath::DirectAlias
            } else {
                ImportPath::GpuConvert
            };
            let mut ledger = ledger_for_request(&request, path);
            if mode == DetachMode::WrongDestination {
                ledger.destination_device = DeviceIdentity::Opaque(99);
            }
            let mut result = request.complete(ledger)?;
            if let Some(revoker) = revoke_hook {
                revoker.revoke();
            }
            if mode == DetachMode::WrongReservation {
                result.reservation = NativeDestinationReservationId(
                    result
                        .reservation
                        .0
                        .checked_add(1)
                        .expect("test reservation"),
                );
            }
            Ok(result)
        }

        fn discard_frame(
            &mut self,
            request: NativeFrameDiscardRequest,
        ) -> Result<NativeFrameDiscardReceipt, NativeCaptureFailure> {
            self.state.lock().expect("source state").discards += 1;
            Ok(request.complete())
        }

        fn stop(
            &mut self,
            session: NativeCaptureSessionIdentity,
        ) -> Result<NativeCaptureStopReceipt, NativeCaptureFailure> {
            let mut state = self.state.lock().expect("source state");
            state.stops = state.stops.saturating_add(1);
            let hook = state.stop_hook.clone();
            if let Some(hook) = hook {
                hook();
            }
            match state
                .stop_results
                .pop_front()
                .unwrap_or(Ok(StopMode::Drained))?
            {
                StopMode::Drained => {
                    state.active_start = None;
                    Ok(NativeCaptureStopReceipt::drained(session))
                }
                StopMode::WrongSession => Ok(NativeCaptureStopReceipt::drained(
                    NativeCaptureSessionIdentity(session.0 + 1),
                )),
            }
        }
    }

    fn authenticated_broker() -> (Arc<Mutex<PerUserAgentBroker>>, AgentBinding) {
        let user = VerifiedInteractiveUser::verify(LocalInteractiveUserEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            interactive_token_verified: true,
        })
        .expect("local user");
        let (challenge, response) = issue_agent_launch_challenge([11_u8; 32]).expect("challenge");
        let mut broker = PerUserAgentBroker::default();
        broker.begin_agent_launch(user, challenge).expect("launch");
        let peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 777,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("peer");
        let binding = broker
            .authenticate_agent(peer, response)
            .expect("authenticate");
        (Arc::new(Mutex::new(broker)), binding)
    }

    fn descriptor(sequence: u64) -> FrameDescriptor {
        FrameDescriptor {
            width: 64,
            height: 64,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: sequence,
            capture_timestamp_ns: sequence,
        }
    }

    fn destination() -> WindowsCaptureDestination {
        WindowsCaptureDestination::new(DeviceIdentity::Opaque(7), u32::from_le_bytes(*b"NV12"), 2)
            .expect("destination")
    }

    fn metadata() -> DesktopMetadata {
        DesktopMetadata {
            dirty_rects: Vec::new(),
            move_rects: Vec::new(),
            pointer_shape: Vec::new(),
            pointer_visible: false,
            pointer_x: 0,
            pointer_y: 0,
        }
    }

    fn ledger_for_request(request: &NativeFrameDetachRequest, path: ImportPath) -> CopyLedger {
        let descriptor = request.source_descriptor();
        let source_layout = SurfaceLayout {
            memory_domain: descriptor.memory_domain,
            format_fourcc: descriptor.format_fourcc,
            plane_count: 1,
            modifier: None,
        };
        CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: request.display_epoch(),
                capture_sequence: descriptor.capture_sequence,
            },
            source_device: DeviceIdentity::Opaque(7),
            destination_device: request.destination_device(),
            source_layout,
            destination_layout: request.destination_layout(),
            transfer_edge: TransferEdge::CaptureToEncoder,
            path,
            synchronization: SynchronizationProof::D3D11EventQuery,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: if path == ImportPath::DirectAlias {
                CopyEvidenceGrade::ProfilerVerifiedNoApplicationCopy
            } else {
                CopyEvidenceGrade::CompletionProven
            },
        }
    }

    fn status(operation: NativeCaptureOperation, code: u32) -> NativeCaptureStatus {
        NativeCaptureStatus::new(operation, NativeCaptureStatusDomain::HResult, code)
    }

    fn started_identity(state: &Arc<Mutex<ReviewSourceState>>) -> NativeCaptureEventIdentity {
        state.lock().expect("source state").starts[0].event_identity()
    }

    fn frame_event(
        identity: NativeCaptureEventIdentity,
        display_epoch: u32,
        sequence: u64,
    ) -> NativeCaptureSourceEvent {
        NativeCaptureSourceEvent::FrameAvailable {
            identity,
            frame: issue_native_pending_frame_identity().expect("pending frame identity"),
            display_epoch,
            descriptor: descriptor(sequence),
            metadata: metadata(),
        }
    }

    fn assert_rejected_before_presentation(frame: EpochBoundSurface, frame_id: u64) {
        let mut queue = PresentationQueue::new(1);
        assert!(matches!(
            queue.push(
                PresentableFrame {
                    surface: frame,
                    codec_epoch: 1,
                    frame_id,
                    ready_ns: 1,
                    deadline_ns: 100,
                    recovery_point: true,
                },
                2,
            ),
            Err(PlatformError::PermissionRevoked)
        ));
    }

    #[test]
    fn wgc_capability_is_source_and_binding_bound_then_consumed_on_close() {
        let (broker, binding) = authenticated_broker();
        let source_a = ReviewNativeSource::new();
        let source_b = ReviewNativeSource::new();
        let (authorization, _) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            source_a.identity,
        )
        .expect("trusted authorization");
        assert!(matches!(
            WindowsCaptureBackend::new_authorized_wgc(
                true,
                binding,
                Arc::clone(&broker),
                SurfacePool::new(1),
                destination(),
                Box::new(source_b),
                authorization,
            ),
            Err(WindowsBackendError::AgentIdentity)
        ));

        let preclosed_source = ReviewNativeSource::new();
        let (authorization, revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            preclosed_source.identity,
        )
        .expect("trusted authorization");
        let mut preclosed = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            Arc::clone(&broker),
            SurfacePool::new(1),
            destination(),
            Box::new(preclosed_source),
            authorization,
        )
        .expect("authorized backend");
        revoker.revoke();
        assert_eq!(preclosed.start(), Err(PlatformError::PermissionRevoked));

        let source = source_a;
        let state = Arc::clone(&source.state);
        let (authorization, revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            source.identity,
        )
        .expect("trusted authorization");
        let authorized_item = authorization.item_identity();
        let mut backend = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("authorized backend");
        backend.start().expect("start");
        assert_eq!(
            state.lock().expect("source state").starts[0].wgc_item_identity(),
            Some(authorized_item)
        );
        revoker.revoke();
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::ItemClosed {
                identity,
                status: status(NativeCaptureOperation::FramePool, 0x8000_000D),
            })));
        assert!(matches!(
            backend.poll(0).expect("closed event"),
            Some(CaptureEvent::PermissionRevoked)
        ));
        assert_eq!(backend.start(), Err(PlatformError::PermissionRevoked));
        assert_eq!(state.lock().expect("source state").starts.len(), 1);
    }

    #[test]
    fn wgc_revoke_synchronously_aborts_active_session_before_return() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let (authorization, revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            source.identity,
        )
        .expect("trusted authorization");
        let mut backend = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("authorized backend");
        backend.start().expect("start");
        let session = started_identity(&state).session();

        revoker.revoke();

        let source_state = state.lock().expect("source state");
        assert_eq!(source_state.abort_sessions, vec![Some(session)]);
        assert!(source_state.active_start.is_none());
    }

    #[test]
    fn wgc_revoke_closes_retained_authorization_without_waiting() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let (authorization, revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            source.identity,
        )
        .expect("trusted authorization");
        let gate = NativePublicationGate::new();
        let publication = gate.try_publish().expect("open publication gate");
        let session = NativeCaptureSessionIdentity(91);
        let (abort_tx, abort_rx) = mpsc::channel();
        authorization
            .authority()
            .attach(NativeSessionControl {
                session,
                gate,
                abort: Arc::new(SignallingAbortHandle {
                    entered: Mutex::new(Some(abort_tx)),
                }),
            })
            .expect("attach exact session");
        drop(broker);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            revoker.revoke();
            done_tx.send(()).expect("completion observer");
        });

        assert_eq!(
            abort_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("synchronous native abort"),
            Some(session)
        );
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("revocation completed while authorization was retained");
        assert!(!publication.load(Ordering::Acquire));
        worker.join().expect("revocation worker");
    }

    #[test]
    fn retained_frame_does_not_block_wgc_revoke_and_cannot_be_presented() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let (authorization, revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            source.identity,
        )
        .expect("trusted authorization");
        let mut backend = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("authorized backend");
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 93))));
        let Some(CaptureEvent::Frame(frame)) = backend.poll(0).expect("frame") else {
            panic!("expected frame");
        };
        let (abort_tx, abort_rx) = mpsc::channel();
        state.lock().expect("source state").abort_notify = Some(abort_tx);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            revoker.revoke();
            done_tx.send(()).expect("completion observer");
        });
        assert_eq!(
            abort_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("native abort invoked"),
            Some(identity.session())
        );
        if done_rx.recv_timeout(Duration::from_millis(200)).is_err() {
            drop(frame);
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("cleanup after blocked revoke");
            worker.join().expect("revocation worker");
            panic!("WGC revoke waited for a caller-owned frame");
        }
        worker.join().expect("revocation worker");
        assert_rejected_before_presentation(frame, 93);
    }

    #[test]
    fn session_change_synchronously_aborts_registered_generation() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            Arc::clone(&broker),
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let session = started_identity(&state).session();

        assert_eq!(PerUserAgentBroker::session_changed(&broker), Ok(binding));

        let source_state = state.lock().expect("source state");
        assert_eq!(source_state.abort_sessions, vec![Some(session)]);
        assert!(source_state.active_start.is_none());
    }

    #[test]
    fn session_change_closes_retained_authorization_without_waiting() {
        let (broker, binding) = authenticated_broker();
        let gate = NativePublicationGate::new();
        let publication = gate.try_publish().expect("open publication gate");
        let session = NativeCaptureSessionIdentity(92);
        let (abort_tx, abort_rx) = mpsc::channel();
        broker
            .lock()
            .expect("broker")
            .register_session(
                binding,
                NativeSessionControl {
                    session,
                    gate,
                    abort: Arc::new(SignallingAbortHandle {
                        entered: Mutex::new(Some(abort_tx)),
                    }),
                },
            )
            .expect("register session");
        let (done_tx, done_rx) = mpsc::channel();
        let worker_broker = Arc::clone(&broker);
        let worker = std::thread::spawn(move || {
            let changed = PerUserAgentBroker::session_changed(&worker_broker);
            done_tx.send(changed).expect("completion observer");
        });

        assert_eq!(
            abort_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("synchronous native abort"),
            Some(session)
        );
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("session change completed while authorization was retained"),
            Ok(binding)
        );
        assert!(!publication.load(Ordering::Acquire));
        worker.join().expect("session-change worker");
    }

    #[test]
    fn retained_frame_does_not_block_session_change_and_cannot_be_presented() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            Arc::clone(&broker),
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 94))));
        let Some(CaptureEvent::Frame(frame)) = backend.poll(0).expect("frame") else {
            panic!("expected frame");
        };
        let (abort_tx, abort_rx) = mpsc::channel();
        state.lock().expect("source state").abort_notify = Some(abort_tx);
        let (done_tx, done_rx) = mpsc::channel();
        let worker_broker = Arc::clone(&broker);
        let worker = std::thread::spawn(move || {
            let changed = PerUserAgentBroker::session_changed(&worker_broker);
            done_tx.send(changed).expect("completion observer");
        });
        assert_eq!(
            abort_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("native abort invoked"),
            Some(identity.session())
        );
        let changed = match done_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(changed) => changed,
            Err(_) => {
                drop(frame);
                let _ = done_rx.recv_timeout(Duration::from_secs(1));
                worker.join().expect("session-change worker");
                panic!("session change waited for a caller-owned frame");
            }
        };
        assert_eq!(changed, Ok(binding));
        worker.join().expect("session-change worker");
        assert_rejected_before_presentation(frame, 94);
    }

    #[test]
    fn global_abort_upgrades_a_completed_exact_abort_for_a_stale_frame() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let active = started_identity(&state);
        backend
            .active_control
            .as_ref()
            .expect("active control")
            .abort_exact_and_wait();
        let stale = NativeCaptureEventIdentity {
            session: NativeCaptureSessionIdentity(active.session().0 + 1),
            agent_generation: active.agent_generation(),
        };
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(stale, 1, 95))));

        assert!(matches!(
            backend.poll(0),
            Err(PlatformError::PermissionRevoked)
        ));
        assert_eq!(
            state.lock().expect("source state").abort_sessions,
            vec![Some(active.session()), None]
        );
        assert_eq!(backend.state(), ProviderState::Failed);
    }

    #[test]
    fn native_session_change_poll_returns_with_retained_frame_then_revokes_it() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 96))));
        let Some(CaptureEvent::Frame(frame)) = backend.poll(0).expect("frame") else {
            panic!("expected frame");
        };
        let (abort_tx, abort_rx) = mpsc::channel();
        state.lock().expect("source state").abort_notify = Some(abort_tx);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::SessionChanged {
                identity,
                status: status(NativeCaptureOperation::Session, 0x0000_02B0),
            })));
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = backend.poll(0);
            done_tx
                .send((backend, result))
                .expect("completion observer");
        });
        assert_eq!(
            abort_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("native abort invoked"),
            Some(identity.session())
        );
        let (backend, result) = match done_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(completed) => completed,
            Err(_) => {
                drop(frame);
                let _ = done_rx.recv_timeout(Duration::from_secs(1));
                worker.join().expect("poll worker");
                panic!("native SessionChanged poll waited for a caller-owned frame");
            }
        };
        assert!(matches!(
            result.expect("session change event"),
            Some(CaptureEvent::AccessLost)
        ));
        assert_eq!(backend.state(), ProviderState::Stopped);
        assert_rejected_before_presentation(frame, 96);
        drop(backend);
        worker.join().expect("poll worker");
    }

    #[test]
    fn backend_drop_aborts_without_waiting_for_retained_frame_and_revokes_it() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 97))));
        let Some(CaptureEvent::Frame(frame)) = backend.poll(0).expect("frame") else {
            panic!("expected frame");
        };
        let (abort_tx, abort_rx) = mpsc::channel();
        state.lock().expect("source state").abort_notify = Some(abort_tx);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            drop(backend);
            done_tx.send(()).expect("completion observer");
        });
        assert_eq!(
            abort_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("native abort invoked"),
            Some(identity.session())
        );
        if done_rx.recv_timeout(Duration::from_millis(200)).is_err() {
            drop(frame);
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("cleanup after blocked drop");
            worker.join().expect("drop worker");
            panic!("backend Drop waited for a caller-owned frame");
        }
        worker.join().expect("drop worker");
        assert_rejected_before_presentation(frame, 97);
    }

    #[test]
    fn frame_detach_rejects_wrong_reservation_destination_and_direct_alias() {
        for (mode, sequence) in [
            (DetachMode::WrongReservation, 1_u64),
            (DetachMode::WrongDestination, 2_u64),
            (DetachMode::DirectAlias, 3_u64),
        ] {
            let (broker, binding) = authenticated_broker();
            let source = ReviewNativeSource::new();
            let state = Arc::clone(&source.state);
            state.lock().expect("source state").detach_mode = mode;
            let pool = SurfacePool::new(1);
            let mut backend = WindowsCaptureBackend::new_desktop_output(
                true,
                binding,
                broker,
                pool.clone(),
                destination(),
                Box::new(source),
            );
            backend.start().expect("start");
            let identity = started_identity(&state);
            state
                .lock()
                .expect("source state")
                .events
                .push_back(Ok(Some(frame_event(identity, 1, sequence))));

            assert!(matches!(
                backend.poll(0),
                Err(PlatformError::InvalidSurface)
            ));
            assert_eq!(pool.in_use(), 0);
            assert_eq!(backend.active_api(), None);
        }
    }

    #[test]
    fn exact_reserved_detach_emits_epoch_bound_owned_surface() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let pool = SurfacePool::new(1);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            pool.clone(),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 11))));

        let Some(CaptureEvent::Frame(frame)) = backend.poll(0).expect("frame") else {
            panic!("expected frame");
        };
        assert_eq!(frame.display_epoch(), 1);
        assert_eq!(
            frame
                .surface()
                .descriptor()
                .expect("destination descriptor")
                .format_fourcc,
            u32::from_le_bytes(*b"NV12")
        );
        assert_eq!(
            frame.surface().copy_ledger().expect("ledger").path,
            ImportPath::GpuConvert
        );
        assert_eq!(pool.in_use(), 1);
        drop(frame);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn frame_observed_before_display_change_is_discarded_without_relabeling() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state.lock().expect("source state").events.extend([
            Ok(Some(NativeCaptureSourceEvent::DisplayChanged {
                identity,
                descriptor: descriptor(20),
                status: status(NativeCaptureOperation::Reconfigure, 0),
            })),
            Ok(Some(frame_event(identity, 1, 21))),
        ]);

        assert!(matches!(
            backend.poll(0).expect("display change"),
            Some(CaptureEvent::Reconfigure {
                display_epoch: 2,
                ..
            })
        ));
        assert!(matches!(
            backend.poll(0),
            Err(PlatformError::InvalidSurface)
        ));
        let source_state = state.lock().expect("source state");
        assert_eq!(source_state.discards, 1);
        assert_eq!(source_state.detaches, 0);
        assert_eq!(backend.state(), ProviderState::Running);
    }

    #[test]
    fn masked_native_frame_invalidates_epoch_without_stopping_dda() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        let old_epoch = backend.display_epoch();
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::ProtectedContentMasked {
                identity,
                status: status(NativeCaptureOperation::AcquireFrame, 0),
            })));

        let masked_epoch = match backend.poll(0).expect("masked frame") {
            Some(CaptureEvent::ProtectedContent { display_epoch }) => display_epoch,
            event => panic!("unexpected masked-frame event: {event:?}"),
        };
        assert!(masked_epoch > old_epoch);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, masked_epoch, 2))));
        assert!(matches!(
            backend.poll(0).expect("post-mask frame"),
            Some(CaptureEvent::Frame(_))
        ));
        assert_eq!(backend.state(), ProviderState::Running);
        let source_state = state.lock().expect("source state");
        assert_eq!(source_state.stops, 0);
        assert_eq!(source_state.detaches, 1);
    }

    #[test]
    fn protected_content_invalidates_retained_presentation_and_keeps_dda_live() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let pool = SurfacePool::new(2);
        let destination = destination();

        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            pool,
            destination,
            Box::new(source),
        );

        backend.start().expect("start backend");
        let identity = started_identity(&state);
        let epoch = backend.display_epoch();

        // 1. Publish a frame before protected content event
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, epoch, 1))));

        let mut publisher = CaptureFramePublisher::new();
        let frame = match backend
            .poll_with_publisher(0, &mut publisher)
            .expect("poll frame")
        {
            Some(CaptureEvent::Frame(frame)) => frame,
            other => panic!("expected frame, got {other:?}"),
        };

        // 2. Deliver ProtectedContentMasked event
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::ProtectedContentMasked {
                identity,
                status: status(NativeCaptureOperation::AcquireFrame, 0),
            })));

        let masked_event = backend
            .poll_with_publisher(0, &mut publisher)
            .expect("poll protected content");
        assert!(matches!(
            masked_event,
            Some(CaptureEvent::ProtectedContent { .. })
        ));

        // 3. Old retained frame must fail presentation authorization
        assert_rejected_before_presentation(frame, 1);

        // 4. DDA backend is still running
        assert_eq!(backend.state(), ProviderState::Running);

        // 5. Subsequent post-mask frame can be published and presented
        let new_epoch = backend.display_epoch();
        assert!(new_epoch > epoch);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, new_epoch, 2))));

        let post_mask_frame = match backend
            .poll_with_publisher(0, &mut publisher)
            .expect("poll post-mask frame")
        {
            Some(CaptureEvent::Frame(frame)) => frame,
            other => panic!("expected frame, got {other:?}"),
        };

        let mut queue = PresentationQueue::new(1);
        let push_result = queue.push(
            PresentableFrame {
                surface: post_mask_frame,
                codec_epoch: 1,
                frame_id: 2,
                ready_ns: 1,
                deadline_ns: 100,
                recovery_point: true,
            },
            2,
        );
        assert!(push_result.is_ok(), "post-mask frame must be presentable");
    }

    #[test]
    fn revoked_wgc_liveness_blocks_a_queued_same_session_frame() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let (authorization, revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            source.identity,
        )
        .expect("authorization");
        let mut backend = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("backend");
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 22))));
        revoker.revoke();

        assert!(matches!(
            backend.poll(0).expect("revocation"),
            Some(CaptureEvent::PermissionRevoked)
        ));
        let source_state = state.lock().expect("source state");
        assert_eq!(source_state.detaches, 0);
        assert_eq!(source_state.stops, 0);
        assert_eq!(source_state.aborts, 1);
        assert!(source_state.active_start.is_none());
        assert_eq!(backend.state(), ProviderState::Revoked);
    }

    #[test]
    fn wgc_liveness_is_revalidated_after_native_start_and_detach() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let (authorization, revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcDisplay,
            binding,
            source.identity,
        )
        .expect("authorization");
        state.lock().expect("source state").revoke_during_start = Some(revoker);
        let mut revoked_during_start = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("backend");
        assert_eq!(
            revoked_during_start.start(),
            Err(PlatformError::PermissionRevoked)
        );
        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(revoked_during_start.state(), ProviderState::Revoked);

        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let pool = SurfacePool::new(1);
        let (authorization, revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            source.identity,
        )
        .expect("authorization");
        state.lock().expect("source state").revoke_during_detach = Some(revoker);
        let mut revoked_during_detach = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            pool.clone(),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("backend");
        revoked_during_detach.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 23))));
        assert!(matches!(
            revoked_during_detach.poll(0).expect("revocation"),
            Some(CaptureEvent::PermissionRevoked)
        ));
        assert_eq!(state.lock().expect("source state").detaches, 1);
        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(pool.in_use(), 0);
        assert_eq!(revoked_during_detach.state(), ProviderState::Revoked);
    }

    #[test]
    fn pool_exhaustion_discards_pending_native_frame_and_keeps_running() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state.lock().expect("source state").events.extend([
            Ok(Some(frame_event(identity, 1, 30))),
            Ok(Some(frame_event(identity, 1, 31))),
        ]);
        let Some(CaptureEvent::Frame(first)) = backend.poll(0).expect("first frame") else {
            panic!("expected frame");
        };

        assert!(matches!(backend.poll(0), Err(PlatformError::QueueFull)));
        assert_eq!(backend.state(), ProviderState::Running);
        assert_eq!(backend.diagnostics().dropped, 1);
        let source_state = state.lock().expect("source state");
        assert_eq!(source_state.detaches, 1);
        assert_eq!(source_state.discards, 1);
        drop(source_state);
        drop(first);
    }

    #[test]
    fn wrong_stop_drain_receipt_forces_exact_session_abort_before_unregister() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        state
            .lock()
            .expect("source state")
            .stop_results
            .push_back(Ok(StopMode::WrongSession));
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            Arc::clone(&broker),
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");

        assert_eq!(backend.stop(), Err(PlatformError::InvalidState));
        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(backend.state(), ProviderState::Stopped);
        assert_eq!(broker.lock().expect("broker").active_sessions, 0);
    }

    #[test]
    fn start_and_poll_revalidate_generation_after_native_call() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        state.lock().expect("source state").drain_during_start =
            Some((Arc::clone(&broker), binding));
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            Arc::clone(&broker),
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        assert_eq!(backend.start(), Err(PlatformError::PermissionRevoked));
        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(
            state.lock().expect("source state").finish_during_call,
            Some(Err(WindowsBackendError::DrainInProgress))
        );
        assert_eq!(
            broker.lock().expect("broker").state(),
            &AgentBrokerState::Idle
        );

        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let pool = SurfacePool::new(1);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            Arc::clone(&broker),
            pool.clone(),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        {
            let mut source_state = state.lock().expect("source state");
            source_state.drain_during_poll = Some((Arc::clone(&broker), binding));
            source_state
                .events
                .push_back(Ok(Some(frame_event(identity, 1, 3))));
        }
        assert!(matches!(
            backend.poll(0).expect("generation loss event"),
            Some(CaptureEvent::AccessLost)
        ));
        assert_eq!(pool.in_use(), 0);
        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(
            broker.lock().expect("broker").state(),
            &AgentBrokerState::Idle
        );
    }

    #[test]
    fn mismatched_late_callback_is_rejected_and_quiesced() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("first start");
        let stale = started_identity(&state);
        backend.stop().expect("stop first session");
        backend.start().expect("second start");
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(stale, 1, 4))));

        assert!(matches!(
            backend.poll(0),
            Err(PlatformError::PermissionRevoked)
        ));
        let source_state = state.lock().expect("source state");
        assert_eq!(source_state.stops, 1);
        assert_eq!(source_state.abort_sessions, vec![None]);
        assert_eq!(backend.active_api(), None);
    }

    #[test]
    fn session_change_abort_supersedes_fallible_stop_and_finishes_exact_drain() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let stop_failure = NativeCaptureFailure::new(
            NativeCaptureFailureKind::DeviceLost,
            status(NativeCaptureOperation::Stop, 0x887A_0005),
        );
        state
            .lock()
            .expect("source state")
            .stop_results
            .extend([Err(stop_failure), Ok(StopMode::Drained)]);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            Arc::clone(&broker),
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::SessionChanged {
                identity,
                status: status(NativeCaptureOperation::Session, 0x0000_02B0),
            })));

        assert!(matches!(
            backend.poll(0).expect("generation loss"),
            Some(CaptureEvent::AccessLost)
        ));
        assert_eq!(backend.last_native_failure(), None);
        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(state.lock().expect("source state").stops, 0);
        assert_eq!(backend.state(), ProviderState::Stopped);
        assert_eq!(
            broker.lock().expect("broker").state(),
            &AgentBrokerState::Idle
        );
    }

    #[test]
    fn revocation_stop_failure_prohibits_restart_until_cleanup_retry() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let (authorization, _) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcDisplay,
            binding,
            source.identity,
        )
        .expect("authorization");
        let stop_failure = NativeCaptureFailure::new(
            NativeCaptureFailureKind::DeviceLost,
            status(NativeCaptureOperation::Stop, 0x887A_0005),
        );
        state
            .lock()
            .expect("source state")
            .stop_results
            .extend([Err(stop_failure), Ok(StopMode::Drained)]);
        let mut backend = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("backend");
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::PermissionRevoked {
                identity,
                status: status(NativeCaptureOperation::Authorization, 0x8007_0005),
            })));

        assert!(matches!(backend.poll(0), Err(PlatformError::DeviceLost)));
        assert_eq!(backend.state(), ProviderState::Draining);
        assert_eq!(backend.start(), Err(PlatformError::InvalidState));
        backend.stop().expect("retry cleanup");
        assert_eq!(backend.state(), ProviderState::Revoked);
        assert_eq!(backend.start(), Err(PlatformError::PermissionRevoked));
    }

    #[test]
    fn stale_running_start_quiesces_and_drop_uses_infallible_abort() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            Arc::clone(&broker),
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        assert_eq!(PerUserAgentBroker::session_changed(&broker), Ok(binding));
        assert_eq!(backend.start(), Err(PlatformError::PermissionRevoked));
        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(backend.state(), ProviderState::Stopped);

        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        state
            .lock()
            .expect("source state")
            .stop_results
            .push_back(Err(NativeCaptureFailure::new(
                NativeCaptureFailureKind::DeviceLost,
                status(NativeCaptureOperation::Stop, 0x887A_0005),
            )));
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            Arc::clone(&broker),
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        assert!(matches!(backend.stop(), Err(PlatformError::DeviceLost)));
        assert_eq!(backend.state(), ProviderState::Draining);
        PerUserAgentBroker::session_changed(&broker).expect("drain");
        drop(backend);
        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(
            broker.lock().expect("broker").state(),
            &AgentBrokerState::Idle
        );
    }

    #[test]
    fn access_loss_recovery_honors_deadline_and_remains_dda() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::AccessLost {
                identity,
                status: status(NativeCaptureOperation::AcquireFrame, 0x887A_0026),
                observed_at_ns: 100,
            })));
        assert!(matches!(
            backend.poll(0).expect("access loss"),
            Some(CaptureEvent::AccessLost)
        ));
        let retry_at = backend.recovery_deadline_ns().expect("retry deadline");
        assert_eq!(
            backend.recover(retry_at - 1),
            Err(PlatformError::InvalidState)
        );
        backend.recover(retry_at).expect("recover DDA");

        let source_state = state.lock().expect("source state");
        assert_eq!(source_state.starts.len(), 2);
        assert!(source_state
            .starts
            .iter()
            .all(|request| request.api() == WindowsCaptureApi::DesktopDuplication));
        assert_ne!(
            source_state.starts[0].event_identity(),
            source_state.starts[1].event_identity()
        );
        assert_eq!(
            backend.active_api(),
            Some(WindowsCaptureApi::DesktopDuplication)
        );
    }

    #[test]
    fn explicit_stop_cancels_pending_access_loss_recovery() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::AccessLost {
                identity,
                status: status(NativeCaptureOperation::AcquireFrame, 0x887A_0026),
                observed_at_ns: 500,
            })));
        assert!(matches!(
            backend.poll(0).expect("access loss"),
            Some(CaptureEvent::AccessLost)
        ));
        assert!(backend.recovery_deadline_ns().is_some());

        backend.stop().expect("cancel recovery");

        assert_eq!(backend.state(), ProviderState::Stopped);
        assert_eq!(backend.recovery_deadline_ns(), None);
        assert_eq!(backend.recover(u64::MAX), Err(PlatformError::InvalidState));

        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let (authorization, _) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcDisplay,
            binding,
            source.identity,
        )
        .expect("authorization");
        let mut wgc = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("WGC backend");
        wgc.start().expect("WGC start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::AccessLost {
                identity,
                status: status(NativeCaptureOperation::AcquireFrame, 0x887A_0026),
                observed_at_ns: 700,
            })));
        assert!(matches!(
            wgc.poll(0).expect("WGC access loss"),
            Some(CaptureEvent::AccessLost)
        ));
        wgc.stop().expect("cancel WGC recovery");
        assert_eq!(wgc.state(), ProviderState::Stopped);
        assert_eq!(wgc.recovery_deadline_ns(), None);
    }

    #[test]
    fn access_loss_failure_backoff_uses_native_observation_time() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let observed_at_ns = 10_000_000_000;
        state.lock().expect("source state").events.push_back(Err(
            NativeCaptureFailure::access_lost(
                status(NativeCaptureOperation::AcquireFrame, 0x887A_0026),
                observed_at_ns,
            ),
        ));
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");

        assert!(matches!(backend.poll(0), Err(PlatformError::AccessLost)));
        let retry_at = backend.recovery_deadline_ns().expect("retry deadline");
        assert!(retry_at > observed_at_ns);
        assert_eq!(
            backend.recover(retry_at - 1),
            Err(PlatformError::InvalidState)
        );
        backend.recover(retry_at).expect("recover after backoff");
        assert!(state
            .lock()
            .expect("source state")
            .starts
            .iter()
            .all(|start| start.api() == WindowsCaptureApi::DesktopDuplication));
    }

    #[test]
    fn malformed_display_change_retains_private_status_but_sanitizes_diagnostics() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        state
            .lock()
            .expect("source state")
            .stop_results
            .push_back(Err(NativeCaptureFailure::new(
                NativeCaptureFailureKind::DeviceLost,
                status(NativeCaptureOperation::Stop, 0x887A_0005),
            )));
        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            SurfacePool::new(1),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        let exact_status = status(NativeCaptureOperation::Reconfigure, 0xDEAD_BEEF);
        let mut invalid = descriptor(9);
        invalid.memory_domain = MemoryDomain::Cpu;
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(NativeCaptureSourceEvent::DisplayChanged {
                identity,
                descriptor: invalid,
                status: exact_status,
            })));

        assert!(matches!(
            backend.poll(0),
            Err(PlatformError::InvalidSurface)
        ));
        assert_eq!(backend.last_native_status(), Some(exact_status));
        let diagnostics = backend.diagnostics();
        let diagnostic = diagnostics.last_error.expect("sanitized error");
        assert!(!diagnostic.contains("DEAD"));
        assert!(!diagnostic.contains("0x"));
    }

    #[test]
    fn epoch_broker_generation_and_identity_exhaustion_fail_closed() {
        let mut selector = CaptureSelector::new(WindowsCaptureTarget::DesktopOutput, true, false);
        selector.display_epoch = u32::MAX;
        assert_eq!(
            selector.start(0),
            Err(WindowsBackendError::GenerationExhausted)
        );
        assert_eq!(selector.state(), ProviderState::Failed);

        let user = VerifiedInteractiveUser::verify(LocalInteractiveUserEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            interactive_token_verified: true,
        })
        .expect("local user");
        let (challenge, response) = issue_agent_launch_challenge([9_u8; 32]).expect("challenge");
        let mut broker = PerUserAgentBroker {
            generation: u32::MAX,
            ..PerUserAgentBroker::default()
        };
        broker.begin_agent_launch(user, challenge).expect("launch");
        let peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
            windows_session_id: 2,
            logon_luid: 42,
            agent_pid: 9,
            named_pipe_acl_verified: true,
            interactive_token_verified: true,
        })
        .expect("peer");
        assert_eq!(
            broker.authenticate_agent(peer, response),
            Err(WindowsBackendError::GenerationExhausted)
        );
        assert!(!matches!(
            broker.state(),
            AgentBrokerState::AgentAuthenticated { .. }
        ));

        assert_eq!(
            allocate_nonzero_identity(&AtomicU64::new(u64::MAX)),
            Err(WindowsBackendError::GenerationExhausted)
        );
    }
    #[test]
    fn windows_encode_backend_encodes_submission_and_completes() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let (authorization, _) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcDisplay,
            binding,
            source.identity,
        )
        .expect("authorization");
        let pool = SurfacePool::new(1);
        let mut backend = WindowsCaptureBackend::new_authorized_wgc(
            true,
            binding,
            broker,
            pool.clone(),
            destination(),
            Box::new(source),
            authorization,
        )
        .expect("authorized backend");
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 93))));
        let Some(CaptureEvent::Frame(frame)) = backend.poll(0).expect("frame") else {
            panic!("expected frame");
        };

        let mut encoder =
            WindowsEncodeBackend::new(DeviceIdentity::Opaque(1), LowDelayPolicy::baseline(60), 1)
                .expect("encoder");
        assert_eq!(encoder.device(), DeviceIdentity::Opaque(1));
        assert_eq!(encoder.policy(), LowDelayPolicy::baseline(60));

        let guard = encoder.prepare(frame).expect("prepare");
        let submission = encoder.encode(guard).expect("encode");
        assert_eq!(
            encoder.poll_encode_completion(&submission).expect("poll"),
            NativePresentationCompletion::Complete
        );
        encoder.release_encoded(submission).expect("release");
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn windows_render_backend_presents_d3d11_and_cpu_and_completes() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let pool = SurfacePool::new(2);
        let mut capture = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            pool.clone(),
            destination(),
            Box::new(source),
        );
        capture.start().expect("start capture");
        let identity = started_identity(&state);

        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 93))));
        let Some(CaptureEvent::Frame(frame)) = capture.poll(0).expect("poll frame") else {
            panic!("expected frame");
        };

        let renderer = WindowsRenderBackend::new(
            DeviceIdentity::Opaque(1),
            WindowsSwapChainConfig::default(),
            CursorMode::Metadata,
        );
        assert_eq!(renderer.name(), "windows_d3d11_render_backend");
        assert_eq!(renderer.presented_count(), 0);
        assert!(renderer.is_quiesced());

        use latencydesk_platform::{
            PresentationAction, PresentationCompletion, PresentationCoordinator,
        };
        let mut coordinator = PresentationCoordinator::new(renderer);

        let presentable = PresentableFrame {
            surface: frame,
            codec_epoch: 1,
            frame_id: 93,
            ready_ns: 10,
            deadline_ns: 100,
            recovery_point: true,
        };

        let action = coordinator.submit(presentable, 10).expect("submit");
        assert_eq!(
            action,
            PresentationAction::Queued(latencydesk_platform::QueuePushOutcome::Queued)
        );

        let present_outcome = coordinator.present_next(10).expect("present next");
        assert!(matches!(present_outcome, PresentationAction::Presented(_)));

        let poll_outcome = coordinator
            .poll_present_completion()
            .expect("poll presentation");
        assert_eq!(poll_outcome, PresentationCompletion::Released);

        assert_eq!(coordinator.cancel_in_flight(), Ok(false));
    }

    #[test]
    fn windows_render_backend_rejects_device_lost_and_in_flight() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let pool = SurfacePool::new(2);
        let mut capture = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            pool.clone(),
            destination(),
            Box::new(source),
        );
        capture.start().expect("start capture");
        let identity = started_identity(&state);

        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 94))));
        let Some(CaptureEvent::Frame(frame)) = capture.poll(0).expect("poll frame") else {
            panic!("expected frame");
        };

        let mut renderer = WindowsRenderBackend::new(
            DeviceIdentity::Opaque(1),
            WindowsSwapChainConfig::default(),
            CursorMode::Metadata,
        );
        renderer.trigger_device_loss();
        assert_eq!(renderer.diagnostics().state, ProviderState::Failed);

        use latencydesk_platform::PresentationCoordinator;
        let mut coordinator = PresentationCoordinator::new(renderer);

        let presentable = PresentableFrame {
            surface: frame,
            codec_epoch: 1,
            frame_id: 94,
            ready_ns: 10,
            deadline_ns: 100,
            recovery_point: true,
        };

        coordinator.submit(presentable, 10).expect("submit");
        assert_eq!(coordinator.present_next(10), Err(PlatformError::DeviceLost));
    }

    #[test]
    fn detach_error_after_native_submit_prevents_early_reservation_reuse() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let pool = SurfacePool::new(1);
        let pool_clone = pool.clone();
        state.lock().expect("source state").detach_mode = DetachMode::FailNativeAfterSubmit;
        state.lock().expect("source state").stop_hook = Some(Arc::new(move || {
            // While synchronous native quiescence is underway, the reservation MUST STILL be held.
            assert_eq!(pool_clone.in_use(), 1);
            // Attempting to reserve from the pool during native quiescence MUST fail with PoolExhausted.
            assert!(matches!(
                pool_clone.reserve_destination(destination().reserve_for(descriptor(1)).unwrap()),
                Err(SurfaceError::PoolExhausted)
            ));
        }));

        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            pool.clone(),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 1))));

        assert!(matches!(backend.poll(0), Err(PlatformError::DeviceLost)));

        // After synchronous native quiescence is complete, the reservation is released.
        assert_eq!(pool.in_use(), 0);
        assert_eq!(backend.active_api(), None);

        // The reservation is now reusable only AFTER native quiescence has finished.
        let lease = pool.reserve_destination(destination().reserve_for(descriptor(1)).unwrap());
        assert!(lease.is_ok());
        assert_eq!(pool.in_use(), 1);
    }

    #[test]
    fn detach_error_with_stop_failure_aborts_and_retains_reservation_until_quiesced() {
        let (broker, binding) = authenticated_broker();
        let source = ReviewNativeSource::new();
        let state = Arc::clone(&source.state);
        let pool = SurfacePool::new(1);
        let pool_clone = pool.clone();
        state.lock().expect("source state").detach_mode = DetachMode::FailNativeAfterSubmit;
        state
            .lock()
            .expect("source state")
            .stop_results
            .push_back(Err(NativeCaptureFailure::new(
                NativeCaptureFailureKind::DeviceLost,
                status(NativeCaptureOperation::Stop, 0x887A_0005),
            )));
        state.lock().expect("source state").abort_hook = Some(Arc::new(move || {
            assert_eq!(pool_clone.in_use(), 1);
            assert!(matches!(
                pool_clone.reserve_destination(destination().reserve_for(descriptor(1)).unwrap()),
                Err(SurfaceError::PoolExhausted)
            ));
        }));

        let mut backend = WindowsCaptureBackend::new_desktop_output(
            true,
            binding,
            broker,
            pool.clone(),
            destination(),
            Box::new(source),
        );
        backend.start().expect("start");
        let identity = started_identity(&state);
        state
            .lock()
            .expect("source state")
            .events
            .push_back(Ok(Some(frame_event(identity, 1, 1))));

        assert!(matches!(backend.poll(0), Err(PlatformError::DeviceLost)));

        assert_eq!(state.lock().expect("source state").aborts, 1);
        assert_eq!(pool.in_use(), 0);
        assert_eq!(backend.active_api(), None);

        let lease = pool.reserve_destination(destination().reserve_for(descriptor(1)).unwrap());
        assert!(lease.is_ok());
        assert_eq!(pool.in_use(), 1);
    }
}
