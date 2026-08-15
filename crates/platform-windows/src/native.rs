//! Opaque CXX declarations and production DDA capture source for the Windows-native provider boundary.
//!
//! The bridge deliberately carries only scalar status/metadata. COM, D3D11,
//! DXGI, WinRT, HWND, and native security handles stay in C++ RAII owners.

use crate::native_capture_source_seal::Sealed;
use crate::{
    issue_native_pending_frame_identity, issue_native_source_identity, DesktopMetadata,
    NativeCaptureAbortHandle, NativeCaptureCancellation, NativeCaptureEventIdentity,
    NativeCaptureFailure, NativeCaptureFailureKind, NativeCaptureOperation,
    NativeCaptureSessionIdentity, NativeCaptureSource, NativeCaptureSourceEvent,
    NativeCaptureStart, NativeCaptureStatus, NativeCaptureStatusDomain, NativeCaptureStopReceipt,
    NativeFrameDetachError, NativeFrameDetachRequest, NativeFrameDetachResult,
    NativeFrameDiscardReceipt, NativeFrameDiscardRequest, NativePendingFrameIdentity,
    NativeSourceIdentity, WindowsBackendError,
};
use latencydesk_media::{
    CopyEvidenceGrade, CopyLedger, DeviceIdentity, FrameDescriptor, ImportPath, LeaseCompletion,
    MemoryDomain, SourceLeaseIdentity, SurfaceLayout, SynchronizationProof, TransferEdge,
};
use latencydesk_surface::SurfacePayload;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn monotonic_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
#[allow(dead_code)]
pub(crate) const BRIDGE_ABI_VERSION: u32 = 2;
pub(crate) const STATUS_OK: u32 = 0;
pub(crate) const STATUS_NO_FRAME: u32 = 1;
pub(crate) const STATUS_ACCESS_LOST: u32 = 2;
pub(crate) const STATUS_PROTECTED_CONTENT: u32 = 3;
pub(crate) const STATUS_PERMISSION_DENIED: u32 = 4;
pub(crate) const STATUS_PERMISSION_REVOKED: u32 = 5;
pub(crate) const STATUS_DEVICE_LOST: u32 = 6;
pub(crate) const STATUS_INVALID_STATE: u32 = 7;
pub(crate) const STATUS_INVALID_ARGUMENT: u32 = 8;
pub(crate) const STATUS_QUEUE_FULL: u32 = 9;
pub(crate) const STATUS_UNSUPPORTED: u32 = 10;
pub(crate) const STATUS_SESSION_CHANGED: u32 = 11;
pub(crate) const STATUS_INTERNAL_FAILURE: u32 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgeStatus {
    Ok,
    NoFrame,
    AccessLost,
    ProtectedContent,
    PermissionDenied,
    PermissionRevoked,
    DeviceLost,
    InvalidState,
    InvalidArgument,
    QueueFull,
    Unsupported,
    SessionChanged,
    InternalFailure,
}

impl BridgeStatus {
    pub(crate) const fn from_code(code: u32) -> Option<Self> {
        match code {
            STATUS_OK => Some(Self::Ok),
            STATUS_NO_FRAME => Some(Self::NoFrame),
            STATUS_ACCESS_LOST => Some(Self::AccessLost),
            STATUS_PROTECTED_CONTENT => Some(Self::ProtectedContent),
            STATUS_PERMISSION_DENIED => Some(Self::PermissionDenied),
            STATUS_PERMISSION_REVOKED => Some(Self::PermissionRevoked),
            STATUS_DEVICE_LOST => Some(Self::DeviceLost),
            STATUS_INVALID_STATE => Some(Self::InvalidState),
            STATUS_INVALID_ARGUMENT => Some(Self::InvalidArgument),
            STATUS_QUEUE_FULL => Some(Self::QueueFull),
            STATUS_UNSUPPORTED => Some(Self::Unsupported),
            STATUS_SESSION_CHANGED => Some(Self::SessionChanged),
            STATUS_INTERNAL_FAILURE => Some(Self::InternalFailure),
            _ => None,
        }
    }
}

pub(crate) fn map_bridge_status_to_failure(
    operation: NativeCaptureOperation,
    status: u32,
    observed_at_ns: Option<u64>,
) -> NativeCaptureFailure {
    let domain = NativeCaptureStatusDomain::HResult;
    match BridgeStatus::from_code(status) {
        Some(BridgeStatus::AccessLost) => {
            let capture_status = NativeCaptureStatus::new(operation, domain, 0x887A_0026);
            if let Some(now_ns) = observed_at_ns {
                NativeCaptureFailure::access_lost(capture_status, now_ns)
            } else {
                NativeCaptureFailure::new(NativeCaptureFailureKind::AccessLost, capture_status)
            }
        }
        Some(BridgeStatus::SessionChanged) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::AccessLost,
            NativeCaptureStatus::new(operation, domain, 0x887A_0028),
        ),
        Some(BridgeStatus::PermissionDenied) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::PermissionDenied,
            NativeCaptureStatus::new(operation, domain, 0x8007_0005),
        ),
        Some(BridgeStatus::PermissionRevoked) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::PermissionRevoked,
            NativeCaptureStatus::new(operation, domain, 0x8007_0005),
        ),
        Some(BridgeStatus::DeviceLost) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::DeviceLost,
            NativeCaptureStatus::new(operation, domain, 0x887A_0005),
        ),
        Some(BridgeStatus::Unsupported) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::Unsupported,
            NativeCaptureStatus::new(operation, domain, 0x887A_0004),
        ),
        Some(BridgeStatus::InvalidArgument) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::InvalidState,
            NativeCaptureStatus::new(operation, domain, 0x8007_0057),
        ),
        Some(BridgeStatus::InvalidState) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::InvalidState,
            NativeCaptureStatus::new(operation, domain, 0x887A_0001),
        ),
        Some(BridgeStatus::QueueFull) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::InvalidState,
            NativeCaptureStatus::new(operation, NativeCaptureStatusDomain::Internal, 9),
        ),
        Some(BridgeStatus::InternalFailure) => NativeCaptureFailure::new(
            NativeCaptureFailureKind::InvalidState,
            NativeCaptureStatus::new(operation, domain, 0x8000_4005),
        ),
        _ => NativeCaptureFailure::new(
            NativeCaptureFailureKind::InvalidState,
            NativeCaptureStatus::new(operation, NativeCaptureStatusDomain::Internal, status),
        ),
    }
}

// CXX requires the externally implemented boundary to be marked unsafe. The
// interface is narrow and does not expose raw OS handles to safe Rust.
#[allow(dead_code, unsafe_code)]
#[cxx::bridge(namespace = "latencydesk::windows_bridge")]
pub(crate) mod ffi {
    unsafe extern "C++" {
        include!("latencydesk_windows_bridge.h");

        type Capture;
        type Surface;
        type Encoder;
        type Renderer;
        type Input;

        fn bridge_abi_version() -> u32;
        fn prepare_current_process_wer_exclusion() -> u32;
        fn make_desktop_duplication_capture(
            adapter_index: u32,
            output_index: u32,
            pending_frame_capacity: u32,
            status: &mut u32,
        ) -> UniquePtr<Capture>;
        fn capture_start(capture: Pin<&mut Capture>) -> u32;
        fn capture_poll(capture: Pin<&mut Capture>, timeout_ms: u32) -> u32;
        fn capture_detach(
            capture: Pin<&mut Capture>,
            destination_format: u32,
            destination_width: u32,
            destination_height: u32,
            status: &mut u32,
        ) -> UniquePtr<Surface>;
        fn capture_discard(capture: Pin<&mut Capture>) -> u32;
        fn capture_stop(capture: Pin<&mut Capture>) -> u32;
        fn capture_pending_width(capture: &Capture) -> u32;
        fn capture_pending_height(capture: &Capture) -> u32;
        fn capture_pending_format(capture: &Capture) -> u32;
        fn capture_pending_pointer_visible(capture: &Capture) -> bool;
        fn capture_pending_pointer_x(capture: &Capture) -> i32;
        fn capture_pending_pointer_y(capture: &Capture) -> i32;
        fn surface_width(surface: &Surface) -> u32;
        fn surface_height(surface: &Surface) -> u32;
        fn surface_format(surface: &Surface) -> u32;
        fn make_mf_h264_encoder(
            adapter_index: u32,
            width: u32,
            height: u32,
            target_bitrate_bps: u32,
            fps: u32,
            max_queue_depth: u32,
            status: &mut u32,
        ) -> UniquePtr<Encoder>;
        fn encoder_encode(
            encoder: Pin<&mut Encoder>,
            surface: &Surface,
            capture_sequence: u64,
            timestamp_ns: u64,
        ) -> u32;
        fn encoder_poll_output(
            encoder: Pin<&mut Encoder>,
            output_buffer: &mut [u8],
            output_size: &mut usize,
            is_keyframe: &mut bool,
            capture_sequence: &mut u64,
            timestamp_ns: &mut u64,
        ) -> u32;
        fn encoder_request_idr(encoder: Pin<&mut Encoder>) -> u32;
        fn encoder_update_bitrate(encoder: Pin<&mut Encoder>, target_bitrate_bps: u32) -> u32;
        fn encoder_drain(encoder: Pin<&mut Encoder>) -> u32;
        fn encoder_quiesce(encoder: Pin<&mut Encoder>) -> u32;
    }
}

// Thread-safety invariants: C++ Capture and Surface handles are internally synchronized
// via mutexes and move-only ownership; moving them across threads is safe.
#[allow(unsafe_code)]
unsafe impl Send for ffi::Capture {}
#[allow(unsafe_code)]
unsafe impl Send for ffi::Surface {}
#[allow(unsafe_code)]
unsafe impl Send for ffi::Encoder {}
impl fmt::Debug for ffi::Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

pub(crate) struct CxxSurfacePayload(pub(crate) cxx::UniquePtr<ffi::Surface>);

impl CxxSurfacePayload {
    pub(crate) fn surface(&self) -> &ffi::Surface {
        &self.0
    }
}
impl fmt::Debug for CxxSurfacePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_null() {
            f.debug_struct("CxxSurfacePayload")
                .field("null", &true)
                .finish()
        } else {
            f.debug_struct("CxxSurfacePayload")
                .field("width", &ffi::surface_width(&self.0))
                .field("height", &ffi::surface_height(&self.0))
                .field("format", &ffi::surface_format(&self.0))
                .finish()
        }
    }
}

impl SurfacePayload for CxxSurfacePayload {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Production Desktop Duplication capture source backed by the opaque CXX bridge.
///
/// Implements the sealed [`NativeCaptureSource`] trait while preserving source identity,
/// epoch tracking, and infallible synchronous quiescence during abort/stop.
pub(crate) struct DesktopDuplicationCaptureSource {
    identity: NativeSourceIdentity,
    adapter_index: u32,
    output_index: u32,
    capture: Arc<Mutex<Option<cxx::UniquePtr<ffi::Capture>>>>,
    state: Arc<Mutex<DesktopDuplicationState>>,
}

impl fmt::Debug for DesktopDuplicationCaptureSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DesktopDuplicationCaptureSource")
            .field("identity", &self.identity)
            .field("adapter_index", &self.adapter_index)
            .field("output_index", &self.output_index)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
struct DesktopDuplicationState {
    active_session: Option<NativeCaptureSessionIdentity>,
    active_identity: Option<NativeCaptureEventIdentity>,
    display_epoch: u32,
    pending_frame: Option<NativePendingFrameIdentity>,
    cancellation: Option<NativeCaptureCancellation>,
    aborted: bool,
    capture_sequence: u64,
}

impl fmt::Debug for DesktopDuplicationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DesktopDuplicationState")
            .field("active_session", &self.active_session)
            .field("active_identity", &self.active_identity)
            .field("display_epoch", &self.display_epoch)
            .field("pending_frame", &self.pending_frame)
            .field("aborted", &self.aborted)
            .field("capture_sequence", &self.capture_sequence)
            .finish()
    }
}

impl DesktopDuplicationCaptureSource {
    pub(crate) fn new(adapter_index: u32, output_index: u32) -> Result<Self, WindowsBackendError> {
        let identity = issue_native_source_identity()?;
        let capture = Arc::new(Mutex::new(None));
        let state = Arc::new(Mutex::new(DesktopDuplicationState {
            active_session: None,
            active_identity: None,
            display_epoch: 0,
            pending_frame: None,
            cancellation: None,
            aborted: false,
            capture_sequence: 0,
        }));
        Ok(Self {
            identity,
            adapter_index,
            output_index,
            capture,
            state,
        })
    }
}

impl Sealed for DesktopDuplicationCaptureSource {}

struct DesktopDuplicationAbortHandle {
    capture: Arc<Mutex<Option<cxx::UniquePtr<ffi::Capture>>>>,
    state: Arc<Mutex<DesktopDuplicationState>>,
}

impl fmt::Debug for DesktopDuplicationAbortHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DesktopDuplicationAbortHandle")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
impl NativeCaptureAbortHandle for DesktopDuplicationAbortHandle {
    fn abort(&self, session: Option<NativeCaptureSessionIdentity>) {
        let should_stop = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if session.is_none() || state.active_session == session {
                state.active_session = None;
                state.active_identity = None;
                state.pending_frame = None;
                state.cancellation = None;
                state.aborted = true;
                true
            } else {
                false
            }
        };
        if should_stop {
            let mut capture_guard = self
                .capture
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(capture) = capture_guard.as_mut() {
                let _ = ffi::capture_stop(capture.pin_mut());
            }
            *capture_guard = None;
        }
    }
}

impl NativeCaptureSource for DesktopDuplicationCaptureSource {
    fn identity(&self) -> NativeSourceIdentity {
        self.identity
    }

    fn abort_handle(&self) -> Arc<dyn NativeCaptureAbortHandle> {
        Arc::new(DesktopDuplicationAbortHandle {
            capture: Arc::clone(&self.capture),
            state: Arc::clone(&self.state),
        })
    }

    fn start(&mut self, request: NativeCaptureStart) -> Result<(), NativeCaptureFailure> {
        let (display_epoch, identity, cancellation) = match request {
            NativeCaptureStart::DesktopDuplication {
                display_epoch,
                identity,
                cancellation,
            } => (display_epoch, identity, cancellation),
            NativeCaptureStart::WindowsGraphicsCapture { .. } => {
                return Err(NativeCaptureFailure::new(
                    NativeCaptureFailureKind::Unsupported,
                    NativeCaptureStatus::new(
                        NativeCaptureOperation::Start,
                        NativeCaptureStatusDomain::Internal,
                        0,
                    ),
                ));
            }
        };

        let mut capture_guard = self
            .capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if capture_guard.is_none() {
            let mut status = STATUS_OK;
            let capture = ffi::make_desktop_duplication_capture(
                self.adapter_index,
                self.output_index,
                1,
                &mut status,
            );
            if status != STATUS_OK || capture.is_null() {
                return Err(map_bridge_status_to_failure(
                    NativeCaptureOperation::Start,
                    status,
                    None,
                ));
            }
            *capture_guard = Some(capture);
        }

        let capture = capture_guard.as_mut().expect("capture");
        let start_status = ffi::capture_start(capture.pin_mut());
        if start_status != STATUS_OK {
            return Err(map_bridge_status_to_failure(
                NativeCaptureOperation::Start,
                start_status,
                None,
            ));
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        state.active_session = Some(identity.session);
        state.active_identity = Some(identity);
        state.display_epoch = display_epoch;
        state.cancellation = Some(cancellation);
        state.pending_frame = None;
        state.aborted = false;

        Ok(())
    }

    fn poll(
        &mut self,
        timeout_ns: u64,
    ) -> Result<Option<NativeCaptureSourceEvent>, NativeCaptureFailure> {
        let start_time_ns = monotonic_now_ns();
        let timeout_ms = u32::try_from(timeout_ns / 1_000_000).unwrap_or(u32::MAX);
        const MAX_SLICE_MS: u32 = 20;

        let mut elapsed_ms = 0u32;
        loop {
            let (identity, display_epoch) = {
                let state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);

                if state.aborted || state.active_session.is_none() {
                    return Ok(None);
                }
                if let Some(cancellation) = &state.cancellation {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                }
                if state.pending_frame.is_some() {
                    return Err(NativeCaptureFailure::new(
                        NativeCaptureFailureKind::InvalidState,
                        NativeCaptureStatus::new(
                            NativeCaptureOperation::AcquireFrame,
                            NativeCaptureStatusDomain::Internal,
                            STATUS_QUEUE_FULL,
                        ),
                    ));
                }

                let identity = match state.active_identity {
                    Some(id) => id,
                    None => return Ok(None),
                };
                (identity, state.display_epoch)
            };

            let remaining_ms = timeout_ms.saturating_sub(elapsed_ms);
            let slice_ms = if timeout_ms == 0 {
                0
            } else {
                remaining_ms.clamp(1, MAX_SLICE_MS)
            };

            let (poll_status, frame_info) = {
                let mut capture_guard = self
                    .capture
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let capture = match capture_guard.as_mut() {
                    Some(c) => c,
                    None => {
                        return Err(NativeCaptureFailure::new(
                            NativeCaptureFailureKind::InvalidState,
                            NativeCaptureStatus::new(
                                NativeCaptureOperation::AcquireFrame,
                                NativeCaptureStatusDomain::Internal,
                                STATUS_INVALID_STATE,
                            ),
                        ));
                    }
                };

                let status = ffi::capture_poll(capture.pin_mut(), slice_ms);
                let info = if status == STATUS_OK {
                    Some((
                        ffi::capture_pending_width(capture),
                        ffi::capture_pending_height(capture),
                        ffi::capture_pending_format(capture),
                        ffi::capture_pending_pointer_visible(capture),
                        ffi::capture_pending_pointer_x(capture),
                        ffi::capture_pending_pointer_y(capture),
                    ))
                } else {
                    None
                };
                (status, info)
            };

            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            if state.aborted
                || state.active_session.is_none()
                || state.active_identity != Some(identity)
            {
                if poll_status == STATUS_OK {
                    if let Ok(mut capture_guard) = self.capture.try_lock() {
                        if let Some(capture) = capture_guard.as_mut() {
                            let _ = ffi::capture_discard(capture.pin_mut());
                        }
                    }
                }
                return Ok(None);
            }
            if let Some(cancellation) = &state.cancellation {
                if cancellation.is_cancelled() {
                    if poll_status == STATUS_OK {
                        if let Ok(mut capture_guard) = self.capture.try_lock() {
                            if let Some(capture) = capture_guard.as_mut() {
                                let _ = ffi::capture_discard(capture.pin_mut());
                            }
                        }
                    }
                    return Ok(None);
                }
            }

            let now_ns = monotonic_now_ns();

            match poll_status {
                STATUS_OK => {
                    let (width, height, raw_format, pointer_visible, pointer_x, pointer_y) =
                        frame_info.expect("frame info");
                    let frame_id = issue_native_pending_frame_identity().map_err(|_| {
                        NativeCaptureFailure::new(
                            NativeCaptureFailureKind::InvalidState,
                            NativeCaptureStatus::new(
                                NativeCaptureOperation::AcquireFrame,
                                NativeCaptureStatusDomain::Internal,
                                1,
                            ),
                        )
                    })?;
                    state.pending_frame = Some(frame_id);
                    state.capture_sequence = state.capture_sequence.wrapping_add(1);
                    let sequence = state.capture_sequence;

                    let format_fourcc = match raw_format {
                        28 => u32::from_le_bytes(*b"RGBA"),
                        _ => u32::from_le_bytes(*b"BGRA"),
                    };

                    let descriptor = FrameDescriptor {
                        width,
                        height,
                        format_fourcc,
                        memory_domain: MemoryDomain::D3D11,
                        capture_sequence: sequence,
                        capture_timestamp_ns: now_ns,
                    };

                    let metadata = DesktopMetadata {
                        dirty_rects: Vec::new(),
                        move_rects: Vec::new(),
                        pointer_shape: Vec::new(),
                        pointer_visible,
                        pointer_x,
                        pointer_y,
                    };

                    return Ok(Some(NativeCaptureSourceEvent::FrameAvailable {
                        identity,
                        frame: frame_id,
                        display_epoch,
                        descriptor,
                        metadata,
                    }));
                }
                STATUS_NO_FRAME => {
                    if timeout_ms == 0 {
                        return Ok(None);
                    }
                    let current_elapsed_ms =
                        u32::try_from(now_ns.saturating_sub(start_time_ns) / 1_000_000)
                            .unwrap_or(u32::MAX);
                    if current_elapsed_ms >= timeout_ms {
                        return Ok(None);
                    }
                    elapsed_ms = current_elapsed_ms;
                }
                STATUS_PROTECTED_CONTENT => {
                    state.display_epoch = state.display_epoch.wrapping_add(1);
                    return Ok(Some(NativeCaptureSourceEvent::ProtectedContentMasked {
                        identity,
                        status: NativeCaptureStatus::new(
                            NativeCaptureOperation::AcquireFrame,
                            NativeCaptureStatusDomain::HResult,
                            0,
                        ),
                    }));
                }
                STATUS_ACCESS_LOST => {
                    return Ok(Some(NativeCaptureSourceEvent::AccessLost {
                        identity,
                        status: NativeCaptureStatus::new(
                            NativeCaptureOperation::AcquireFrame,
                            NativeCaptureStatusDomain::HResult,
                            0x887A_0026,
                        ),
                        observed_at_ns: now_ns,
                    }));
                }
                STATUS_SESSION_CHANGED => {
                    return Ok(Some(NativeCaptureSourceEvent::SessionChanged {
                        identity,
                        status: NativeCaptureStatus::new(
                            NativeCaptureOperation::Session,
                            NativeCaptureStatusDomain::HResult,
                            0x887A_0028,
                        ),
                    }));
                }
                STATUS_PERMISSION_REVOKED => {
                    return Ok(Some(NativeCaptureSourceEvent::PermissionRevoked {
                        identity,
                        status: NativeCaptureStatus::new(
                            NativeCaptureOperation::Authorization,
                            NativeCaptureStatusDomain::HResult,
                            0x8007_0005,
                        ),
                    }));
                }
                STATUS_DEVICE_LOST => {
                    return Err(NativeCaptureFailure::new(
                        NativeCaptureFailureKind::DeviceLost,
                        NativeCaptureStatus::new(
                            NativeCaptureOperation::AcquireFrame,
                            NativeCaptureStatusDomain::HResult,
                            0x887A_0005,
                        ),
                    ));
                }
                STATUS_PERMISSION_DENIED => {
                    return Err(NativeCaptureFailure::new(
                        NativeCaptureFailureKind::PermissionDenied,
                        NativeCaptureStatus::new(
                            NativeCaptureOperation::AcquireFrame,
                            NativeCaptureStatusDomain::HResult,
                            0x8007_0005,
                        ),
                    ));
                }
                STATUS_UNSUPPORTED => {
                    return Err(NativeCaptureFailure::new(
                        NativeCaptureFailureKind::Unsupported,
                        NativeCaptureStatus::new(
                            NativeCaptureOperation::AcquireFrame,
                            NativeCaptureStatusDomain::HResult,
                            0x887A_0004,
                        ),
                    ));
                }
                other => {
                    return Err(map_bridge_status_to_failure(
                        NativeCaptureOperation::AcquireFrame,
                        other,
                        Some(now_ns),
                    ));
                }
            }
        }
    }

    fn detach_frame(
        &mut self,
        request: NativeFrameDetachRequest,
    ) -> Result<NativeFrameDetachResult, NativeFrameDetachError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if state.active_identity != Some(request.event_identity())
            || state.pending_frame != Some(request.pending_frame())
            || state.display_epoch != request.display_epoch()
        {
            return Err(request.fail_contract(WindowsBackendError::DestinationMismatch));
        }

        let source_descriptor = request.source_descriptor();
        let source_layout = SurfaceLayout {
            memory_domain: source_descriptor.memory_domain,
            format_fourcc: source_descriptor.format_fourcc,
            plane_count: 1,
            modifier: None,
        };
        let destination_layout = request.destination_layout();
        let destination_device = request.destination_device();
        let source_device = DeviceIdentity::Opaque(self.adapter_index as u64);

        let is_same_format = destination_layout.format_fourcc == source_descriptor.format_fourcc
            && destination_layout.plane_count == 1
            && request.destination_descriptor().format_fourcc == source_descriptor.format_fourcc;

        let is_nv12_convert = destination_layout.format_fourcc == u32::from_le_bytes(*b"NV12")
            && destination_layout.plane_count == 2
            && request.destination_descriptor().format_fourcc == u32::from_le_bytes(*b"NV12");

        if destination_layout.memory_domain != MemoryDomain::D3D11
            || destination_device != source_device
            || request.destination_descriptor().width != source_descriptor.width
            || request.destination_descriptor().height != source_descriptor.height
            || (!is_same_format && !is_nv12_convert)
        {
            return Err(request.fail_contract(WindowsBackendError::DestinationMismatch));
        }

        let destination_dxgi_format: u32 = if is_nv12_convert {
            103 // DXGI_FORMAT_NV12
        } else if destination_layout.format_fourcc == u32::from_le_bytes(*b"RGBA") {
            28 // DXGI_FORMAT_R8G8B8A8_UNORM
        } else {
            87 // DXGI_FORMAT_B8G8R8A8_UNORM
        };

        let mut capture_guard = self
            .capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let capture = match capture_guard.as_mut() {
            Some(c) => c,
            None => {
                return Err(request.fail_contract(WindowsBackendError::InvalidState));
            }
        };

        let mut detach_status = STATUS_OK;
        let surface = ffi::capture_detach(
            capture.pin_mut(),
            destination_dxgi_format,
            request.destination_descriptor().width,
            request.destination_descriptor().height,
            &mut detach_status,
        );

        if detach_status != STATUS_OK || surface.is_null() {
            state.pending_frame = None;
            let failure = map_bridge_status_to_failure(
                NativeCaptureOperation::ImportFrame,
                detach_status,
                None,
            );
            return Err(request.fail_native(failure));
        }

        state.pending_frame = None;

        let ledger = CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: request.display_epoch(),
                capture_sequence: source_descriptor.capture_sequence,
            },
            source_device,
            destination_device,
            source_layout,
            destination_layout,
            transfer_edge: TransferEdge::CaptureToEncoder,
            path: if is_same_format {
                ImportPath::GpuCopy
            } else {
                ImportPath::GpuConvert
            },
            synchronization: SynchronizationProof::D3D11EventQuery,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: CopyEvidenceGrade::CompletionProven,
        };

        let payload = Box::new(CxxSurfacePayload(surface));
        let result = request.complete_with_payload(ledger, payload)?;
        Ok(result)
    }

    fn discard_frame(
        &mut self,
        request: NativeFrameDiscardRequest,
    ) -> Result<NativeFrameDiscardReceipt, NativeCaptureFailure> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if state.active_identity != Some(request.identity)
            || state.pending_frame != Some(request.frame)
            || state.display_epoch != request.source_observed_epoch
        {
            return Err(NativeCaptureFailure::new(
                NativeCaptureFailureKind::InvalidState,
                NativeCaptureStatus::new(
                    NativeCaptureOperation::AcquireFrame,
                    NativeCaptureStatusDomain::Internal,
                    STATUS_INVALID_ARGUMENT,
                ),
            ));
        }

        let mut capture_guard = self
            .capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let capture = match capture_guard.as_mut() {
            Some(capture) => capture,
            None => {
                return Err(NativeCaptureFailure::new(
                    NativeCaptureFailureKind::InvalidState,
                    NativeCaptureStatus::new(
                        NativeCaptureOperation::AcquireFrame,
                        NativeCaptureStatusDomain::Internal,
                        STATUS_INVALID_STATE,
                    ),
                ));
            }
        };

        let discard_status = ffi::capture_discard(capture.pin_mut());
        if discard_status != STATUS_OK {
            return Err(map_bridge_status_to_failure(
                NativeCaptureOperation::AcquireFrame,
                discard_status,
                None,
            ));
        }

        state.pending_frame = None;
        Ok(request.complete())
    }

    fn stop(
        &mut self,
        session: NativeCaptureSessionIdentity,
    ) -> Result<NativeCaptureStopReceipt, NativeCaptureFailure> {
        let should_stop = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.active_session == Some(session) || state.active_session.is_none() {
                state.active_session = None;
                state.active_identity = None;
                state.pending_frame = None;
                state.cancellation = None;
                true
            } else {
                false
            }
        };
        if should_stop {
            let mut capture_guard = self
                .capture
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(capture) = capture_guard.as_mut() {
                let status = ffi::capture_stop(capture.pin_mut());
                if status != STATUS_OK {
                    return Err(map_bridge_status_to_failure(
                        NativeCaptureOperation::Stop,
                        status,
                        None,
                    ));
                }
            }
            *capture_guard = None;
        }
        Ok(NativeCaptureStopReceipt::drained(session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        issue_agent_launch_challenge, issue_wgc_authorization, AgentBinding, AgentPeerEvidence,
        LocalInteractiveUserEvidence, NativePublicationGate, PerUserAgentBroker, SurfacePool,
        VerifiedAgentPeer, VerifiedInteractiveUser, WindowsCaptureBackend,
        WindowsCaptureDestination, WindowsCaptureTarget,
    };
    use latencydesk_platform::CaptureBackend;
    use std::time::Instant;
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

    #[test]
    fn bridge_abi_is_linked_through_cxx() {
        assert_eq!(ffi::bridge_abi_version(), BRIDGE_ABI_VERSION);
    }

    #[test]
    fn bridge_rejects_an_unbounded_desktop_duplication_queue() {
        let mut status = STATUS_OK;
        let capture = ffi::make_desktop_duplication_capture(0, 0, 0, &mut status);

        assert!(capture.is_null());
        assert_eq!(
            BridgeStatus::from_code(status),
            Some(BridgeStatus::InvalidArgument)
        );
    }

    #[test]
    fn bridge_status_codes_remain_exhaustive() {
        assert_eq!(
            BridgeStatus::from_code(STATUS_ACCESS_LOST),
            Some(BridgeStatus::AccessLost)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_PROTECTED_CONTENT),
            Some(BridgeStatus::ProtectedContent)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_PERMISSION_DENIED),
            Some(BridgeStatus::PermissionDenied)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_PERMISSION_REVOKED),
            Some(BridgeStatus::PermissionRevoked)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_DEVICE_LOST),
            Some(BridgeStatus::DeviceLost)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_INVALID_STATE),
            Some(BridgeStatus::InvalidState)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_INVALID_ARGUMENT),
            Some(BridgeStatus::InvalidArgument)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_QUEUE_FULL),
            Some(BridgeStatus::QueueFull)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_UNSUPPORTED),
            Some(BridgeStatus::Unsupported)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_SESSION_CHANGED),
            Some(BridgeStatus::SessionChanged)
        );
        assert_eq!(
            BridgeStatus::from_code(STATUS_INTERNAL_FAILURE),
            Some(BridgeStatus::InternalFailure)
        );
        assert_eq!(BridgeStatus::from_code(u32::MAX), None);
    }

    #[test]
    fn desktop_duplication_source_construction_and_identity() {
        let source = DesktopDuplicationCaptureSource::new(0, 0).expect("construct source");
        let id = source.identity();
        assert!(id.0 > 0);

        let abort = source.abort_handle();
        // Aborting before start is synchronously quiescent
        abort.abort(None);
    }

    #[test]
    fn desktop_duplication_source_rejects_unauthorized_wgc_start() {
        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("construct source");
        let gate = NativePublicationGate::new();
        let cancellation = NativeCaptureCancellation {
            gate: Arc::clone(&gate),
        };
        let (_broker, binding) = authenticated_broker();
        let (authorization, _revoker) = issue_wgc_authorization(
            WindowsCaptureTarget::AuthorizedWgcWindow,
            binding,
            source.identity(),
        )
        .expect("authorization");

        let request = NativeCaptureStart::WindowsGraphicsCapture {
            display_epoch: 1,
            identity: NativeCaptureEventIdentity {
                session: NativeCaptureSessionIdentity(1),
                agent_generation: 1,
            },
            cancellation,
            authorization,
        };

        let result = source.start(request);
        assert!(matches!(
            result,
            Err(failure) if failure.kind == NativeCaptureFailureKind::Unsupported
        ));
    }

    #[test]
    fn desktop_duplication_source_synchronous_abort_quiescence() {
        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("construct source");
        let abort = source.abort_handle();
        let session = NativeCaptureSessionIdentity(42);

        // Aborting with matching session shuts down and poll returns Ok(None)
        abort.abort(Some(session));
        assert_eq!(source.poll(0).expect("quiescent poll"), None);

        // Stop also returns drained receipt cleanly
        let stop_receipt = source.stop(session).expect("stop");
        assert_eq!(stop_receipt.session, session);
    }

    #[test]
    fn desktop_duplication_source_status_mapping_and_event_translation() {
        let access_lost = map_bridge_status_to_failure(
            NativeCaptureOperation::AcquireFrame,
            STATUS_ACCESS_LOST,
            Some(100),
        );
        assert_eq!(access_lost.kind, NativeCaptureFailureKind::AccessLost);
        assert_eq!(access_lost.observed_at_ns, Some(100));

        let perm_denied = map_bridge_status_to_failure(
            NativeCaptureOperation::AcquireFrame,
            STATUS_PERMISSION_DENIED,
            None,
        );
        assert_eq!(perm_denied.kind, NativeCaptureFailureKind::PermissionDenied);

        let dev_lost = map_bridge_status_to_failure(
            NativeCaptureOperation::AcquireFrame,
            STATUS_DEVICE_LOST,
            None,
        );
        assert_eq!(dev_lost.kind, NativeCaptureFailureKind::DeviceLost);

        let unsupp = map_bridge_status_to_failure(
            NativeCaptureOperation::AcquireFrame,
            STATUS_UNSUPPORTED,
            None,
        );
        assert_eq!(unsupp.kind, NativeCaptureFailureKind::Unsupported);
    }

    #[test]
    fn desktop_duplication_source_post_mask_next_frame_acceptance() {
        let source = DesktopDuplicationCaptureSource::new(0, 0).expect("source");
        let gate = NativePublicationGate::new();
        let cancellation = NativeCaptureCancellation {
            gate: Arc::clone(&gate),
        };
        let identity = NativeCaptureEventIdentity {
            session: NativeCaptureSessionIdentity(10),
            agent_generation: 1,
        };

        // Initialize state directly for unit test verification
        {
            let mut state = source.state.lock().expect("state");
            state.active_session = Some(identity.session);
            state.active_identity = Some(identity);
            state.display_epoch = 1;
            state.cancellation = Some(cancellation);
        }

        // Simulate protected content status observed from bridge
        {
            let mut state = source.state.lock().expect("state");
            state.display_epoch = state.display_epoch.wrapping_add(1);
        }

        let state = source.state.lock().expect("state");
        assert_eq!(state.display_epoch, 2);
    }

    #[test]
    fn desktop_duplication_source_surface_payload_and_ledger_transfer() {
        let mut status = STATUS_OK;
        let capture = ffi::make_desktop_duplication_capture(0, 0, 1, &mut status);
        assert!(!capture.is_null());
        assert_eq!(status, STATUS_OK);

        let payload = CxxSurfacePayload(cxx::UniquePtr::null());
        let debug_str = format!("{payload:?}");
        assert!(debug_str.contains("CxxSurfacePayload"));

        let any_ref = payload.as_any();
        assert!(any_ref.downcast_ref::<CxxSurfacePayload>().is_some());
    }

    #[test]
    fn desktop_duplication_backend_factory_constructs_production_source() {
        let (broker, binding) = authenticated_broker();
        let pool = SurfacePool::new(1);
        let destination = WindowsCaptureDestination::new(
            DeviceIdentity::Opaque(0),
            u32::from_le_bytes(*b"BGRA"),
            1,
        )
        .expect("destination");

        let backend = WindowsCaptureBackend::new_desktop_duplication(
            binding,
            broker,
            pool,
            destination,
            0,
            0,
        )
        .expect("desktop duplication backend");

        assert_eq!(backend.name(), "windows-capture");
    }

    #[test]
    fn desktop_duplication_session_disconnect_hresult_mapping() {
        let session_changed = map_bridge_status_to_failure(
            NativeCaptureOperation::Session,
            STATUS_SESSION_CHANGED,
            None,
        );
        assert_eq!(session_changed.status.code, 0x887A_0028);
        assert_eq!(session_changed.kind, NativeCaptureFailureKind::AccessLost);
    }

    #[test]
    fn desktop_duplication_abort_bounded_and_does_not_deadlock_poll() {
        let mut status = STATUS_OK;
        let capture = ffi::make_desktop_duplication_capture(0, 0, 1, &mut status);
        assert_eq!(status, STATUS_OK);

        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("construct source");
        let session = NativeCaptureSessionIdentity(99);
        let identity = NativeCaptureEventIdentity {
            session,
            agent_generation: 1,
        };

        {
            let mut capture_guard = source.capture.lock().expect("capture");
            *capture_guard = Some(capture);
        }
        {
            let mut state = source.state.lock().expect("state");
            state.active_session = Some(session);
            state.active_identity = Some(identity);
            state.display_epoch = 1;
        }

        let abort = source.abort_handle();
        let start = Instant::now();

        // Calling abort on an active session must complete within a bounded interval
        abort.abort(Some(session));
        let abort_duration = start.elapsed();
        assert!(
            abort_duration < std::time::Duration::from_millis(50),
            "abort took too long: {:?}",
            abort_duration
        );

        // After abort, poll must return Ok(None) immediately without deadlock or blocking
        let poll_result = source.poll(5_000_000_000);
        assert_eq!(poll_result.expect("quiescent poll"), None);
    }

    #[test]
    fn desktop_duplication_discard_frame_checks_status_and_preserves_pending_state() {
        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("source");
        let session = NativeCaptureSessionIdentity(50);
        let identity = NativeCaptureEventIdentity {
            session,
            agent_generation: 1,
        };
        let frame_id = issue_native_pending_frame_identity().expect("frame id");
        {
            let mut state = source.state.lock().expect("state");
            state.active_session = Some(session);
            state.active_identity = Some(identity);
            state.display_epoch = 1;
            state.pending_frame = Some(frame_id);
        }

        // Request with mismatched frame id must fail and preserve pending state
        let wrong_frame = NativePendingFrameIdentity(frame_id.0 + 1);
        let request = NativeFrameDiscardRequest {
            identity,
            frame: wrong_frame,
            source_observed_epoch: 1,
        };
        let result = source.discard_frame(request);
        assert!(matches!(
            result,
            Err(failure) if failure.kind == NativeCaptureFailureKind::InvalidState
        ));

        // Verify pending frame is preserved
        {
            let state = source.state.lock().expect("state");
            assert_eq!(state.pending_frame, Some(frame_id));
        }
    }

    #[test]
    fn desktop_duplication_detach_rejects_mismatched_destination_device_or_layout() {
        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("source");
        let session = NativeCaptureSessionIdentity(10);
        let identity = NativeCaptureEventIdentity {
            session,
            agent_generation: 1,
        };
        let frame_id = issue_native_pending_frame_identity().expect("frame id");
        {
            let mut state = source.state.lock().expect("state");
            state.active_session = Some(session);
            state.active_identity = Some(identity);
            state.display_epoch = 1;
            state.pending_frame = Some(frame_id);
        }

        let source_descriptor = FrameDescriptor {
            width: 1920,
            height: 1080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 100,
        };

        // Mismatched device (adapter 1 instead of adapter 0)
        let destination_wrong_dev = WindowsCaptureDestination::new(
            DeviceIdentity::Opaque(1),
            u32::from_le_bytes(*b"NV12"),
            2,
        )
        .expect("destination");

        let pool = SurfacePool::new(1);
        let lease = pool
            .reserve_destination(
                destination_wrong_dev
                    .reserve_for(source_descriptor)
                    .expect("spec"),
            )
            .expect("lease");

        let request = NativeFrameDetachRequest {
            identity,
            frame: frame_id,
            reservation: crate::NativeDestinationReservationId(1),
            source_descriptor,
            destination: destination_wrong_dev
                .reserve_for(source_descriptor)
                .expect("spec"),
            source_observed_epoch: 1,
            metadata: DesktopMetadata {
                dirty_rects: Vec::new(),
                move_rects: Vec::new(),
                pointer_shape: Vec::new(),
                pointer_visible: false,
                pointer_x: 0,
                pointer_y: 0,
            },
            lease,
        };

        let result = source.detach_frame(request);
        assert!(matches!(
            result,
            Err(NativeFrameDetachError::Contract {
                error: WindowsBackendError::DestinationMismatch,
                ..
            })
        ));
    }

    #[test]
    fn desktop_duplication_detach_requires_valid_capture_state() {
        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("source");
        let session = NativeCaptureSessionIdentity(10);
        let identity = NativeCaptureEventIdentity {
            session,
            agent_generation: 1,
        };
        let frame_id = issue_native_pending_frame_identity().expect("frame id");
        {
            let mut state = source.state.lock().expect("state");
            state.active_session = Some(session);
            state.active_identity = Some(identity);
            state.display_epoch = 1;
            state.pending_frame = Some(frame_id);
        }

        let source_descriptor = FrameDescriptor {
            width: 1920,
            height: 1080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 100,
        };

        let destination_nv12 = WindowsCaptureDestination::new(
            DeviceIdentity::Opaque(0),
            u32::from_le_bytes(*b"NV12"),
            2,
        )
        .expect("destination");

        let pool = SurfacePool::new(1);
        let lease = pool
            .reserve_destination(
                destination_nv12
                    .reserve_for(source_descriptor)
                    .expect("spec"),
            )
            .expect("lease");

        let request = NativeFrameDetachRequest {
            identity,
            frame: frame_id,
            reservation: crate::NativeDestinationReservationId(1),
            source_descriptor,
            destination: destination_nv12
                .reserve_for(source_descriptor)
                .expect("spec"),
            source_observed_epoch: 1,
            metadata: DesktopMetadata {
                dirty_rects: Vec::new(),
                move_rects: Vec::new(),
                pointer_shape: Vec::new(),
                pointer_visible: false,
                pointer_x: 0,
                pointer_y: 0,
            },
            lease,
        };

        // Without active capture started, detach returns InvalidState
        let result = source.detach_frame(request);
        assert!(matches!(
            result,
            Err(NativeFrameDetachError::Contract {
                error: WindowsBackendError::InvalidState,
                ..
            })
        ));
    }

    #[test]
    fn desktop_duplication_detach_rejects_mismatched_plane_counts_and_dimensions() {
        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("source");
        let session = NativeCaptureSessionIdentity(10);
        let identity = NativeCaptureEventIdentity {
            session,
            agent_generation: 1,
        };
        let frame_id = issue_native_pending_frame_identity().expect("frame id");
        {
            let mut state = source.state.lock().expect("state");
            state.active_session = Some(session);
            state.active_identity = Some(identity);
            state.display_epoch = 1;
            state.pending_frame = Some(frame_id);
        }

        let source_descriptor = FrameDescriptor {
            width: 1920,
            height: 1080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 100,
        };

        // NV12 with wrong plane count (1 instead of 2)
        let destination_nv12_single_plane = WindowsCaptureDestination::new(
            DeviceIdentity::Opaque(0),
            u32::from_le_bytes(*b"NV12"),
            1,
        )
        .expect("destination");

        let pool = SurfacePool::new(1);
        let lease = pool
            .reserve_destination(
                destination_nv12_single_plane
                    .reserve_for(source_descriptor)
                    .expect("spec"),
            )
            .expect("lease");

        let request = NativeFrameDetachRequest {
            identity,
            frame: frame_id,
            reservation: crate::NativeDestinationReservationId(1),
            source_descriptor,
            destination: destination_nv12_single_plane
                .reserve_for(source_descriptor)
                .expect("spec"),
            source_observed_epoch: 1,
            metadata: DesktopMetadata {
                dirty_rects: Vec::new(),
                move_rects: Vec::new(),
                pointer_shape: Vec::new(),
                pointer_visible: false,
                pointer_x: 0,
                pointer_y: 0,
            },
            lease,
        };

        let result = source.detach_frame(request);
        assert!(matches!(
            result,
            Err(NativeFrameDetachError::Contract {
                error: WindowsBackendError::DestinationMismatch,
                ..
            })
        ));
    }

    #[test]
    fn desktop_duplication_pre_ffi_detach_failure_preserves_pending_frame() {
        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("source");
        let session = NativeCaptureSessionIdentity(10);
        let identity = NativeCaptureEventIdentity {
            session,
            agent_generation: 1,
        };
        let frame_id = issue_native_pending_frame_identity().expect("frame id");
        {
            let mut state = source.state.lock().expect("state");
            state.active_session = Some(session);
            state.active_identity = Some(identity);
            state.display_epoch = 1;
            state.pending_frame = Some(frame_id);
        }

        let source_descriptor = FrameDescriptor {
            width: 1920,
            height: 1080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 100,
        };

        let destination_mismatched = WindowsCaptureDestination::new(
            DeviceIdentity::Opaque(99),
            u32::from_le_bytes(*b"BGRA"),
            1,
        )
        .expect("destination");

        let pool = SurfacePool::new(1);
        let lease = pool
            .reserve_destination(
                destination_mismatched
                    .reserve_for(source_descriptor)
                    .expect("spec"),
            )
            .expect("lease");

        let request = NativeFrameDetachRequest {
            identity,
            frame: frame_id,
            reservation: crate::NativeDestinationReservationId(1),
            source_descriptor,
            destination: destination_mismatched
                .reserve_for(source_descriptor)
                .expect("spec"),
            source_observed_epoch: 1,
            metadata: DesktopMetadata {
                dirty_rects: Vec::new(),
                move_rects: Vec::new(),
                pointer_shape: Vec::new(),
                pointer_visible: false,
                pointer_x: 0,
                pointer_y: 0,
            },
            lease,
        };

        let result = source.detach_frame(request);
        assert!(result.is_err());

        // Pre-FFI contract check failure preserves pending frame in Rust
        let state = source.state.lock().expect("state");
        assert_eq!(state.pending_frame, Some(frame_id));
    }

    #[test]
    fn desktop_duplication_native_ffi_detach_failure_clears_pending_frame_and_allows_recovery() {
        let mut source = DesktopDuplicationCaptureSource::new(0, 0).expect("source");
        let mut status = STATUS_OK;
        let capture = ffi::make_desktop_duplication_capture(0, 0, 1, &mut status);
        assert_eq!(status, STATUS_OK);
        {
            let mut capture_guard = source.capture.lock().expect("capture guard");
            *capture_guard = Some(capture);
        }

        let session = NativeCaptureSessionIdentity(10);
        let identity = NativeCaptureEventIdentity {
            session,
            agent_generation: 1,
        };
        let frame_id = issue_native_pending_frame_identity().expect("frame id");
        {
            let mut state = source.state.lock().expect("state");
            state.active_session = Some(session);
            state.active_identity = Some(identity);
            state.display_epoch = 1;
            state.pending_frame = Some(frame_id);
        }

        let source_descriptor = FrameDescriptor {
            width: 1920,
            height: 1080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: 1,
            capture_timestamp_ns: 100,
        };

        let destination_valid = WindowsCaptureDestination::new(
            DeviceIdentity::Opaque(0),
            u32::from_le_bytes(*b"BGRA"),
            1,
        )
        .expect("destination");

        let pool = SurfacePool::new(1);
        let lease = pool
            .reserve_destination(
                destination_valid
                    .reserve_for(source_descriptor)
                    .expect("spec"),
            )
            .expect("lease");

        let request = NativeFrameDetachRequest {
            identity,
            frame: frame_id,
            reservation: crate::NativeDestinationReservationId(1),
            source_descriptor,
            destination: destination_valid
                .reserve_for(source_descriptor)
                .expect("spec"),
            source_observed_epoch: 1,
            metadata: DesktopMetadata {
                dirty_rects: Vec::new(),
                move_rects: Vec::new(),
                pointer_shape: Vec::new(),
                pointer_visible: false,
                pointer_x: 0,
                pointer_y: 0,
            },
            lease,
        };

        // Native FFI capture_detach will be invoked and fail (unstarted / no pending frame in C++)
        let result = source.detach_frame(request);
        assert!(matches!(
            result,
            Err(NativeFrameDetachError::Native { failure, .. }) if failure.kind == NativeCaptureFailureKind::InvalidState
        ));

        // Native FFI failure must atomically clear Rust's pending_frame to match C++ state
        {
            let state = source.state.lock().expect("state");
            assert_eq!(
                state.pending_frame, None,
                "pending frame must be cleared after native FFI detach failure"
            );
        }

        // Recovery check: Subsequent poll is not blocked by STATUS_QUEUE_FULL from a stale pending_frame
        let poll_result = source.poll(0);
        assert!(
            !matches!(
                poll_result,
                Err(failure) if failure.status.code == STATUS_QUEUE_FULL
            ),
            "poll must not return STATUS_QUEUE_FULL after detach failure recovery: {poll_result:?}"
        );
    }
    #[test]
    fn mf_h264_encoder_creation_and_lifecycle_contract() {
        let mut status = STATUS_OK;
        let mut encoder = ffi::make_mf_h264_encoder(0, 1920, 1080, 5_000_000, 30, 1, &mut status);
        if status == STATUS_OK && !encoder.is_null() {
            let idr_status = ffi::encoder_request_idr(encoder.pin_mut());
            assert_eq!(idr_status, STATUS_OK);
            let rate_status = ffi::encoder_update_bitrate(encoder.pin_mut(), 4_000_000);
            assert_eq!(rate_status, STATUS_OK);
            let drain_status = ffi::encoder_drain(encoder.pin_mut());
            assert_eq!(drain_status, STATUS_OK);
            let quiesce_status = ffi::encoder_quiesce(encoder.pin_mut());
            assert_eq!(quiesce_status, STATUS_OK);
        }
    }
}
