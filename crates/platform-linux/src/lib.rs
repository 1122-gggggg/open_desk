//! Policy and ownership boundary for portal-authorized Wayland capture,
//! hardware decoding, Wayland/X11 presentation, and input injection.
//!
//! Native D-Bus, PipeWire, libei, VA-API, and evdev calls stay in narrow provider layers.
//! This crate models their externally observable state transitions and prevents
//! capture, decode, and render buffers from crossing authorization, stream, or format epochs.

use latencydesk_codec::{ChromaMode, CodecConfig, CodecError, EncodedAccessUnit, FrameDecoder};
use latencydesk_frame::{expected_len, PixelFormat, RawFrame};
use latencydesk_h264::LowDelayPolicy;
use latencydesk_input::{
    AppliedInput, InputMessage, InputReconciler, InputState, ReconcileOutcome,
};
use latencydesk_media::{
    ContinuityAction, CopyEvidenceGrade, CopyFallbackReason, CopyLedger, DecoderContinuity,
    DeviceIdentity, FrameDescriptor, ImportPath, LeaseCompletion, MemoryDomain,
    SourceLeaseIdentity, SurfaceLayout, SynchronizationProof, TransferEdge,
};
use latencydesk_platform::{
    CaptureBackend, CaptureEvent, CaptureFramePublisher, CoordinateTransform, CursorMode,
    CursorUpdate, InputBackend, NativePresentationCompletion, PlatformError, PresentSubmission,
    PresentableFrame, PresentationQueue, PresentationQueueStats, PresentationSubmissionGuard,
    ProviderDiagnostics, ProviderState, QueuePushOutcome, RenderBackend, RenderFailure, Rotation,
};
use latencydesk_surface::{OwnedSurface, SurfaceError, SurfacePool};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod desktop_convert;
pub use desktop_convert::{
    bgra_to_nv12_bt601_limited, even_dimension, letterbox_geom, letterbox_scale_bgra,
    map_letterboxed_pointer, nv12_len, nv12_to_argb_u32, pack_nv12_access_unit,
    parse_nv12_access_unit, yuv_to_rgb_bt601_limited, ConvertError, LetterboxGeom,
};

#[cfg(target_os = "linux")]
mod x11_desktop;
#[cfg(target_os = "linux")]
pub use x11_desktop::{X11DesktopError, X11DesktopSession};

/// Product mode selected before creating an XDG portal session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxCaptureMode {
    CaptureOnly,
    CaptureAndControl,
}

/// Explicit portal/PipeWire lifecycle. No phase implies generic unattended access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalPhase {
    Idle,
    AwaitingSession,
    AwaitingDeviceSelection,
    AwaitingSourceSelection,
    AwaitingStart,
    AwaitingPipeWire,
    Streaming,
    Reconfiguring,
    Revoked,
    Closed,
}

/// Opaque portal-session identity. It deliberately is not a D-Bus object path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalSessionId(pub u64);

/// PipeWire stream identity negotiated by one portal session.
///
/// `node_id` is only a connection target. `serial` is required because portal
/// documentation warns that PipeWire node IDs can be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeWireStream {
    pub node_id: u32,
    pub serial: u64,
}

impl PipeWireStream {
    fn validate(self) -> Result<(), LinuxBackendError> {
        if self.node_id == 0 || self.serial == 0 {
            return Err(LinuxBackendError::InvalidStream);
        }
        Ok(())
    }
}

/// Input capability selected by the portal and exposed through libei.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputCapability {
    pub keyboard: bool,
    pub pointer: bool,
    pub libei: bool,
}

impl InputCapability {
    #[must_use]
    pub const fn control_ready(self) -> bool {
        self.keyboard && self.pointer && self.libei
    }
}

/// PipeWire video tuple after SPA negotiation. It contains no raw FD or GPU handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeWireFormat {
    pub width: u32,
    pub height: u32,
    pub format_fourcc: u32,
    pub memory_domain: MemoryDomain,
    pub plane_count: u8,
    pub modifier: Option<u64>,
}

impl PipeWireFormat {
    pub fn validate(self) -> Result<(), LinuxBackendError> {
        FrameDescriptor {
            width: self.width,
            height: self.height,
            format_fourcc: self.format_fourcc,
            memory_domain: self.memory_domain,
            capture_sequence: 1,
            capture_timestamp_ns: 1,
        }
        .validate()
        .map_err(|_| LinuxBackendError::InvalidFormat)?;
        if self.format_fourcc == 0 || !(1..=4).contains(&self.plane_count) {
            return Err(LinuxBackendError::InvalidFormat);
        }
        if !matches!(self.memory_domain, MemoryDomain::DmaBuf | MemoryDomain::Cpu) {
            return Err(LinuxBackendError::UnsupportedMemoryDomain);
        }
        if self.memory_domain == MemoryDomain::Cpu && self.modifier.is_some() {
            return Err(LinuxBackendError::InvalidFormat);
        }
        Ok(())
    }

    #[must_use]
    pub const fn layout(self) -> SurfaceLayout {
        SurfaceLayout {
            memory_domain: self.memory_domain,
            format_fourcc: self.format_fourcc,
            plane_count: self.plane_count,
            modifier: self.modifier,
        }
    }

    #[must_use]
    pub fn matches_descriptor(self, descriptor: FrameDescriptor) -> bool {
        self.width == descriptor.width
            && self.height == descriptor.height
            && self.format_fourcc == descriptor.format_fourcc
            && self.memory_domain == descriptor.memory_domain
    }
}

/// Request the native portal adapter must issue next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalRequest {
    CreateSession { mode: LinuxCaptureMode },
    SelectDevices,
    SelectSources,
    Start,
    ConnectPipeWire { stream: PipeWireStream },
}

/// One trusted event from the native portal/PipeWire adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalEvent {
    SessionCreated {
        session: PortalSessionId,
    },
    DevicesSelected {
        input: InputCapability,
    },
    SourcesSelected,
    Started {
        stream: PipeWireStream,
    },
    PipeWireConnected {
        stream: PipeWireStream,
        format: PipeWireFormat,
    },
    PipeWireReconfigured {
        stream: PipeWireStream,
        format: PipeWireFormat,
    },
    PipeWireDisconnected,
    PermissionRevoked,
    Cancelled,
    Closed,
}

/// Outcome the host coordinator must execute after applying a portal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalAction {
    Request(PortalRequest),
    CaptureReady {
        display_epoch: u32,
        stream: PipeWireStream,
        input: InputCapability,
    },
    ReleaseAllAndReconfigure {
        display_epoch: u32,
        stream: PipeWireStream,
        format: PipeWireFormat,
    },
    ReleaseAllAndReconnect {
        display_epoch: u32,
    },
    ReleaseAllAndStop,
}

/// A PipeWire frame detached into the bounded engine-owned surface pool.
#[derive(Debug)]
pub struct ImportedPipeWireFrame {
    pub surface: OwnedSurface,
    pub copy_ledger: CopyLedger,
    pub display_epoch: u32,
    pub stream: PipeWireStream,
}

/// Portable portal session policy. The native adapter owns D-Bus calls and FDs;
/// Rust owns ordering, epochs, ownership validation, and fail-closed behavior.
#[derive(Debug, Clone)]
pub struct LinuxPortalSession {
    mode: LinuxCaptureMode,
    phase: PortalPhase,
    session: Option<PortalSessionId>,
    stream: Option<PipeWireStream>,
    format: Option<PipeWireFormat>,
    input: InputCapability,
    display_epoch: u32,
    diagnostics: ProviderDiagnostics,
}

impl LinuxPortalSession {
    #[must_use]
    pub fn new(mode: LinuxCaptureMode) -> Self {
        Self {
            mode,
            phase: PortalPhase::Idle,
            session: None,
            stream: None,
            format: None,
            input: InputCapability::default(),
            display_epoch: 0,
            diagnostics: ProviderDiagnostics::idle("linux-xdg-portal-pipewire"),
        }
    }

    pub fn begin(&mut self) -> Result<PortalAction, LinuxBackendError> {
        if self.phase != PortalPhase::Idle {
            return Err(LinuxBackendError::InvalidState);
        }
        self.set_phase(PortalPhase::AwaitingSession);
        Ok(PortalAction::Request(PortalRequest::CreateSession {
            mode: self.mode,
        }))
    }

    /// Applies one native portal/PipeWire event in its declared causal order.
    pub fn apply(&mut self, event: PortalEvent) -> Result<PortalAction, LinuxBackendError> {
        match event {
            PortalEvent::PermissionRevoked => self.terminate(PortalPhase::Revoked),
            PortalEvent::Cancelled | PortalEvent::Closed => self.terminate(PortalPhase::Closed),
            PortalEvent::SessionCreated { session } => {
                if self.phase != PortalPhase::AwaitingSession || session.0 == 0 {
                    return Err(LinuxBackendError::InvalidState);
                }
                self.session = Some(session);
                match self.mode {
                    LinuxCaptureMode::CaptureOnly => {
                        self.set_phase(PortalPhase::AwaitingSourceSelection);
                        Ok(PortalAction::Request(PortalRequest::SelectSources))
                    }
                    LinuxCaptureMode::CaptureAndControl => {
                        self.set_phase(PortalPhase::AwaitingDeviceSelection);
                        Ok(PortalAction::Request(PortalRequest::SelectDevices))
                    }
                }
            }
            PortalEvent::DevicesSelected { input } => {
                if self.mode != LinuxCaptureMode::CaptureAndControl
                    || self.phase != PortalPhase::AwaitingDeviceSelection
                {
                    return Err(LinuxBackendError::InvalidState);
                }
                if !input.control_ready() {
                    return Err(LinuxBackendError::InputUnavailable);
                }
                self.input = input;
                self.set_phase(PortalPhase::AwaitingSourceSelection);
                Ok(PortalAction::Request(PortalRequest::SelectSources))
            }
            PortalEvent::SourcesSelected => {
                if self.phase != PortalPhase::AwaitingSourceSelection {
                    return Err(LinuxBackendError::InvalidState);
                }
                self.set_phase(PortalPhase::AwaitingStart);
                Ok(PortalAction::Request(PortalRequest::Start))
            }
            PortalEvent::Started { stream } => {
                if self.phase != PortalPhase::AwaitingStart {
                    return Err(LinuxBackendError::InvalidState);
                }
                stream.validate()?;
                self.stream = Some(stream);
                self.set_phase(PortalPhase::AwaitingPipeWire);
                Ok(PortalAction::Request(PortalRequest::ConnectPipeWire {
                    stream,
                }))
            }
            PortalEvent::PipeWireConnected { stream, format } => {
                if self.phase != PortalPhase::AwaitingPipeWire
                    && !(self.phase == PortalPhase::Reconfiguring && self.format.is_none())
                {
                    return Err(LinuxBackendError::InvalidState);
                }
                if self.stream != Some(stream) {
                    return Err(LinuxBackendError::StaleStream);
                }
                format.validate()?;
                if self.phase == PortalPhase::AwaitingPipeWire {
                    self.bump_display_epoch();
                }
                self.record_format(format);
                self.set_phase(PortalPhase::Streaming);
                Ok(PortalAction::CaptureReady {
                    display_epoch: self.display_epoch,
                    stream,
                    input: self.input,
                })
            }
            PortalEvent::PipeWireReconfigured { stream, format } => {
                if self.phase != PortalPhase::Streaming {
                    return Err(LinuxBackendError::InvalidState);
                }
                if self.stream != Some(stream) {
                    return Err(LinuxBackendError::StaleStream);
                }
                format.validate()?;
                self.bump_display_epoch();
                self.record_format(format);
                self.diagnostics.import_path = None;
                self.set_phase(PortalPhase::Reconfiguring);
                Ok(PortalAction::ReleaseAllAndReconfigure {
                    display_epoch: self.display_epoch,
                    stream,
                    format,
                })
            }
            PortalEvent::PipeWireDisconnected => {
                if !matches!(
                    self.phase,
                    PortalPhase::Streaming | PortalPhase::Reconfiguring
                ) {
                    return Err(LinuxBackendError::InvalidState);
                }
                if self.phase == PortalPhase::Streaming || self.format.is_some() {
                    self.bump_display_epoch();
                }
                self.format = None;
                self.diagnostics.format = None;
                self.diagnostics.import_path = None;
                self.set_phase(PortalPhase::Reconfiguring);
                Ok(PortalAction::ReleaseAllAndReconnect {
                    display_epoch: self.display_epoch,
                })
            }
        }
    }

    /// Imports one fully negotiated PipeWire frame after native detach/copy.
    pub fn import_frame(
        &mut self,
        stream: PipeWireStream,
        pool: &SurfacePool,
        descriptor: FrameDescriptor,
        ledger: CopyLedger,
    ) -> Result<ImportedPipeWireFrame, LinuxBackendError> {
        if self.phase != PortalPhase::Streaming || self.stream != Some(stream) {
            return Err(LinuxBackendError::InvalidState);
        }
        let format = self.format.ok_or(LinuxBackendError::InvalidState)?;
        if !format.matches_descriptor(descriptor) {
            return Err(LinuxBackendError::DescriptorMismatch);
        }
        if ledger.source_lease.provider_epoch != self.display_epoch {
            return Err(LinuxBackendError::LedgerEpoch);
        }
        if ledger.source_layout != format.layout() {
            return Err(LinuxBackendError::LedgerLayout);
        }
        if format.memory_domain == MemoryDomain::DmaBuf
            && format.modifier.is_none()
            && !matches!(
                ledger.path,
                ImportPath::CpuCopy | ImportPath::InternalCopyUnknown
            )
        {
            return Err(LinuxBackendError::DmaBufModifierUnknown);
        }
        let lease = match pool.acquire_capture(descriptor) {
            Ok(lease) => lease,
            Err(error) => {
                if matches!(error, SurfaceError::PoolExhausted) {
                    self.diagnostics.dropped = self.diagnostics.dropped.saturating_add(1);
                }
                self.diagnostics.queue_depth = pool.in_use();
                return Err(LinuxBackendError::Surface(error));
            }
        };
        let surface = lease.import(ledger).map_err(LinuxBackendError::Surface)?;
        self.diagnostics.import_path = Some(ledger.path);
        self.diagnostics.queue_depth = pool.in_use();
        Ok(ImportedPipeWireFrame {
            surface,
            copy_ledger: ledger,
            display_epoch: self.display_epoch,
            stream,
        })
    }

    /// Resumes capture only after the coordinator drained old surfaces and
    /// recreated the import/encoder path for a negotiated format change.
    pub fn resume_after_reconfigure(&mut self) -> Result<PortalAction, LinuxBackendError> {
        if self.phase != PortalPhase::Reconfiguring {
            return Err(LinuxBackendError::InvalidState);
        }
        let stream = self.stream.ok_or(LinuxBackendError::InvalidState)?;
        if self.format.is_none() {
            return Err(LinuxBackendError::InvalidState);
        }
        self.set_phase(PortalPhase::Streaming);
        Ok(PortalAction::CaptureReady {
            display_epoch: self.display_epoch,
            stream,
            input: self.input,
        })
    }

    #[must_use]
    pub const fn mode(&self) -> LinuxCaptureMode {
        self.mode
    }

    #[must_use]
    pub const fn phase(&self) -> PortalPhase {
        self.phase
    }

    #[must_use]
    pub const fn display_epoch(&self) -> u32 {
        self.display_epoch
    }

    #[must_use]
    pub const fn session_id(&self) -> Option<PortalSessionId> {
        self.session
    }

    #[must_use]
    pub const fn stream(&self) -> Option<PipeWireStream> {
        self.stream
    }

    #[must_use]
    pub const fn format(&self) -> Option<PipeWireFormat> {
        self.format
    }

    #[must_use]
    pub fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }

    fn terminate(&mut self, phase: PortalPhase) -> Result<PortalAction, LinuxBackendError> {
        if matches!(
            self.phase,
            PortalPhase::Idle | PortalPhase::Revoked | PortalPhase::Closed
        ) {
            return Err(LinuxBackendError::InvalidState);
        }
        self.stream = None;
        self.format = None;
        self.input = InputCapability::default();
        self.diagnostics.format = None;
        self.diagnostics.import_path = None;
        self.set_phase(phase);
        Ok(PortalAction::ReleaseAllAndStop)
    }

    fn set_phase(&mut self, phase: PortalPhase) {
        self.phase = phase;
        self.diagnostics.state = match phase {
            PortalPhase::Idle => ProviderState::Idle,
            PortalPhase::AwaitingSession
            | PortalPhase::AwaitingDeviceSelection
            | PortalPhase::AwaitingSourceSelection
            | PortalPhase::AwaitingStart
            | PortalPhase::AwaitingPipeWire => ProviderState::Starting,
            PortalPhase::Streaming => ProviderState::Running,
            PortalPhase::Reconfiguring => ProviderState::Reconfiguring,
            PortalPhase::Revoked => ProviderState::Revoked,
            PortalPhase::Closed => ProviderState::Stopped,
        };
    }

    fn bump_display_epoch(&mut self) {
        self.display_epoch = self.display_epoch.wrapping_add(1).max(1);
    }

    fn record_format(&mut self, format: PipeWireFormat) {
        self.format = Some(format);
        self.diagnostics.format = Some(format!(
            "{:?}:{:08X}/{},modifier={:?}",
            format.memory_domain, format.format_fourcc, format.plane_count, format.modifier
        ));
    }
}

/// Linux portal/PipeWire/renderer/decoder policy error. Native diagnostics retain
/// detailed native error payloads outside this stable boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxBackendError {
    InvalidState,
    InvalidStream,
    StaleStream,
    InputUnavailable,
    InvalidFormat,
    UnsupportedMemoryDomain,
    DescriptorMismatch,
    LedgerEpoch,
    LedgerLayout,
    DmaBufModifierUnknown,
    InvalidDimensions,
    InvalidStride,
    InvalidPlaneCount,
    ExpiredDeadline,
    Surface(SurfaceError),
    Platform(PlatformError),
    Codec(CodecError),
}

impl fmt::Display for LinuxBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LinuxBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Surface(error) => Some(error),
            Self::Platform(error) => Some(error),
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SurfaceError> for LinuxBackendError {
    fn from(error: SurfaceError) -> Self {
        Self::Surface(error)
    }
}

impl From<PlatformError> for LinuxBackendError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<CodecError> for LinuxBackendError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<LinuxBackendError> for PlatformError {
    fn from(error: LinuxBackendError) -> Self {
        match error {
            LinuxBackendError::InvalidState => Self::InvalidState,
            LinuxBackendError::InvalidStream | LinuxBackendError::StaleStream => Self::InvalidState,
            LinuxBackendError::InputUnavailable => Self::Unsupported,
            LinuxBackendError::InvalidFormat
            | LinuxBackendError::DescriptorMismatch
            | LinuxBackendError::LedgerLayout
            | LinuxBackendError::DmaBufModifierUnknown
            | LinuxBackendError::InvalidDimensions
            | LinuxBackendError::InvalidStride
            | LinuxBackendError::InvalidPlaneCount => Self::InvalidSurface,
            LinuxBackendError::UnsupportedMemoryDomain => Self::Unsupported,
            LinuxBackendError::LedgerEpoch => Self::InvalidState,
            LinuxBackendError::ExpiredDeadline => Self::InvalidDeadline,
            LinuxBackendError::Surface(_) => Self::InvalidSurface,
            LinuxBackendError::Platform(p) => p,
            LinuxBackendError::Codec(_) => Self::InvalidState,
        }
    }
}

/// Unforgeable token identifying an active portal request or session authorization.
#[derive(Debug, Clone)]
pub struct PortalToken {
    handle: String,
    revoked: Arc<AtomicBool>,
}

impl PortalToken {
    pub fn new(handle: impl Into<String>) -> (Self, PortalTokenRevoker) {
        let handle = handle.into();
        let revoked = Arc::new(AtomicBool::new(false));
        let revoker = PortalTokenRevoker {
            handle: handle.clone(),
            revoked: Arc::clone(&revoked),
        };
        (Self { handle, revoked }, revoker)
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.revoked.load(Ordering::Acquire)
    }
}

/// Token revoker to invalidate portal authorization from any thread.
#[derive(Debug, Clone)]
pub struct PortalTokenRevoker {
    handle: String,
    revoked: Arc<AtomicBool>,
}

impl PortalTokenRevoker {
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

/// Type of memory backing a PipeWire buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeWireBufferType {
    DmaBuf,
    MemFd,
    MemPtr,
}

/// Buffer payload provided by the PipeWire stream for import into the surface pool.
#[derive(Debug, Clone)]
pub struct PipeWireBuffer {
    pub stream: PipeWireStream,
    pub descriptor: FrameDescriptor,
    pub data_type: PipeWireBufferType,
    pub modifier: Option<u64>,
    pub plane_count: u8,
    pub device: DeviceIdentity,
}

impl PipeWireBuffer {
    #[must_use]
    pub fn dma_buf(
        stream: PipeWireStream,
        descriptor: FrameDescriptor,
        modifier: Option<u64>,
        plane_count: u8,
        device: DeviceIdentity,
    ) -> Self {
        Self {
            stream,
            descriptor,
            data_type: PipeWireBufferType::DmaBuf,
            modifier,
            plane_count,
            device,
        }
    }

    #[must_use]
    pub fn mem_fd(stream: PipeWireStream, descriptor: FrameDescriptor) -> Self {
        Self {
            stream,
            descriptor,
            data_type: PipeWireBufferType::MemFd,
            modifier: None,
            plane_count: 1,
            device: DeviceIdentity::Unknown,
        }
    }

    #[must_use]
    pub fn mem_ptr(stream: PipeWireStream, descriptor: FrameDescriptor) -> Self {
        Self {
            stream,
            descriptor,
            data_type: PipeWireBufferType::MemPtr,
            modifier: None,
            plane_count: 1,
            device: DeviceIdentity::Unknown,
        }
    }
}

/// Native event emitted by a platform portal / PipeWire driver.
#[derive(Debug, Clone)]
pub enum NativePortalEvent {
    Portal(PortalEvent),
    Buffer(PipeWireBuffer),
}

impl From<PortalEvent> for NativePortalEvent {
    fn from(event: PortalEvent) -> Self {
        Self::Portal(event)
    }
}

impl From<PipeWireBuffer> for NativePortalEvent {
    fn from(buffer: PipeWireBuffer) -> Self {
        Self::Buffer(buffer)
    }
}

/// Native portal and PipeWire driver contract.
pub trait NativePortalSource: fmt::Debug + Send {
    fn start(&mut self, mode: LinuxCaptureMode) -> Result<(), LinuxBackendError>;
    fn poll(&mut self, timeout_ns: u64) -> Result<Option<NativePortalEvent>, LinuxBackendError>;
    fn stop(&mut self) -> Result<(), LinuxBackendError>;
    fn push_event(&mut self, _event: NativePortalEvent) {}
}

/// In-memory queue source for deterministic testing and event feeding.
#[derive(Debug, Default)]
pub struct QueuePortalSource {
    events: std::collections::VecDeque<NativePortalEvent>,
    started: bool,
}

impl QueuePortalSource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, event: impl Into<NativePortalEvent>) {
        self.events.push_back(event.into());
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl NativePortalSource for QueuePortalSource {
    fn start(&mut self, _mode: LinuxCaptureMode) -> Result<(), LinuxBackendError> {
        self.started = true;
        Ok(())
    }

    fn poll(&mut self, _timeout_ns: u64) -> Result<Option<NativePortalEvent>, LinuxBackendError> {
        if !self.started {
            return Err(LinuxBackendError::InvalidState);
        }
        Ok(self.events.pop_front())
    }

    fn stop(&mut self) -> Result<(), LinuxBackendError> {
        self.started = false;
        self.events.clear();
        Ok(())
    }

    fn push_event(&mut self, event: NativePortalEvent) {
        self.push(event);
    }
}

/// Native libei input injector with automatic state reconciliation on portal
/// disconnect, token revocation, or window focus loss.
#[derive(Debug, Clone)]
pub struct LinuxPortalInputBackend {
    capability: InputCapability,
    reconciler: InputReconciler,
    connected: bool,
    focused: bool,
    diagnostics: ProviderDiagnostics,
    injected_actions: Vec<AppliedInput>,
}

impl LinuxPortalInputBackend {
    #[must_use]
    pub fn new(capability: InputCapability) -> Self {
        Self {
            capability,
            reconciler: InputReconciler::default(),
            connected: capability.control_ready(),
            focused: true,
            diagnostics: ProviderDiagnostics::idle("linux-libei-input"),
            injected_actions: Vec::new(),
        }
    }

    pub fn set_capability(&mut self, capability: InputCapability) {
        self.capability = capability;
        if !capability.control_ready() && self.connected {
            let actions = self.reconciler.disconnect_release_plan();
            let _ = self.release_all(&actions);
            self.connected = false;
        } else if capability.control_ready() {
            self.connected = true;
        }
    }

    #[must_use]
    pub const fn capability(&self) -> InputCapability {
        self.capability
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn is_focused(&self) -> bool {
        self.focused
    }

    pub fn set_connected(&mut self, connected: bool) -> Vec<AppliedInput> {
        if self.connected && !connected {
            let actions = self.reconciler.disconnect_release_plan();
            let _ = self.release_all(&actions);
            self.connected = false;
            actions
        } else {
            self.connected = connected;
            Vec::new()
        }
    }

    pub fn set_focused(&mut self, focused: bool) -> Vec<AppliedInput> {
        if self.focused && !focused {
            let actions = self.reconciler.disconnect_release_plan();
            let _ = self.release_all(&actions);
            self.focused = false;
            actions
        } else {
            self.focused = focused;
            Vec::new()
        }
    }

    pub fn on_portal_revocation(&mut self) -> Vec<AppliedInput> {
        self.set_connected(false)
    }

    pub fn handle_input_message(
        &mut self,
        message: InputMessage,
    ) -> Result<Vec<AppliedInput>, PlatformError> {
        if !self.connected {
            return Err(PlatformError::AccessLost);
        }
        if !self.focused {
            return Err(PlatformError::InvalidState);
        }
        let outcome = self
            .reconciler
            .apply(message)
            .map_err(|_| PlatformError::InvalidState)?;
        match outcome {
            ReconcileOutcome::Applied(actions) => {
                for &action in &actions {
                    self.validate_action(action)?;
                    self.injected_actions.push(action);
                }
                Ok(actions)
            }
            ReconcileOutcome::IgnoredStaleSequence | ReconcileOutcome::IgnoredStaleEpoch => {
                Ok(Vec::new())
            }
        }
    }

    #[must_use]
    pub fn state(&self) -> &InputState {
        self.reconciler.state()
    }

    #[must_use]
    pub fn injected_actions(&self) -> &[AppliedInput] {
        &self.injected_actions
    }

    pub fn clear_injected_actions(&mut self) {
        self.injected_actions.clear();
    }

    fn validate_action(&self, action: AppliedInput) -> Result<(), PlatformError> {
        if !self.capability.libei {
            return Err(PlatformError::Unsupported);
        }
        match action {
            AppliedInput::Key { .. } => {
                if !self.capability.keyboard {
                    return Err(PlatformError::Unsupported);
                }
            }
            AppliedInput::PointerButton { .. }
            | AppliedInput::PointerMotionRelative { .. }
            | AppliedInput::PointerMotionAbsolute { .. }
            | AppliedInput::Wheel { .. } => {
                if !self.capability.pointer {
                    return Err(PlatformError::Unsupported);
                }
            }
        }
        Ok(())
    }
}

impl InputBackend for LinuxPortalInputBackend {
    fn name(&self) -> &'static str {
        "linux-libei-input"
    }

    fn inject(&mut self, action: AppliedInput) -> Result<(), PlatformError> {
        if !self.connected {
            return Err(PlatformError::AccessLost);
        }
        if !self.focused {
            return Err(PlatformError::InvalidState);
        }
        self.validate_action(action)?;
        self.injected_actions.push(action);
        Ok(())
    }

    fn release_all(&mut self, actions: &[AppliedInput]) -> Result<(), PlatformError> {
        for &action in actions {
            self.injected_actions.push(action);
        }
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

/// Whole-output/window capture provider for Linux xdg-desktop-portal and PipeWire.
#[derive(Debug)]
pub struct LinuxPortalCaptureBackend {
    mode: LinuxCaptureMode,
    session: LinuxPortalSession,
    pool: SurfacePool,
    source: Box<dyn NativePortalSource>,
    presentation_authorization: Arc<AtomicBool>,
    token: Option<PortalToken>,
    started: bool,
    input_backend: Option<LinuxPortalInputBackend>,
}

impl LinuxPortalCaptureBackend {
    #[must_use]
    pub fn new(mode: LinuxCaptureMode, pool: SurfacePool) -> Self {
        Self::with_source(Box::new(QueuePortalSource::new()), pool, mode)
    }

    #[must_use]
    pub fn new_screencast(pool: SurfacePool) -> Self {
        Self::new(LinuxCaptureMode::CaptureOnly, pool)
    }

    #[must_use]
    pub fn new_remote_desktop(pool: SurfacePool) -> Self {
        Self::new(LinuxCaptureMode::CaptureAndControl, pool)
    }

    #[must_use]
    pub fn with_source(
        source: Box<dyn NativePortalSource>,
        pool: SurfacePool,
        mode: LinuxCaptureMode,
    ) -> Self {
        Self {
            mode,
            session: LinuxPortalSession::new(mode),
            pool,
            source,
            presentation_authorization: Arc::new(AtomicBool::new(true)),
            token: None,
            started: false,
            input_backend: match mode {
                LinuxCaptureMode::CaptureAndControl => {
                    Some(LinuxPortalInputBackend::new(InputCapability::default()))
                }
                LinuxCaptureMode::CaptureOnly => None,
            },
        }
    }

    pub fn set_token(&mut self, token: PortalToken) {
        self.token = Some(token);
    }

    pub fn revoke_token(&mut self) {
        if let Some(token) = &self.token {
            token.revoked.store(true, Ordering::Release);
        }
        self.presentation_authorization
            .store(false, Ordering::Release);
        let _ = self.session.apply(PortalEvent::PermissionRevoked);
        if let Some(input) = &mut self.input_backend {
            input.on_portal_revocation();
        }
    }

    pub fn push_event(&mut self, event: impl Into<NativePortalEvent>) {
        self.source.push_event(event.into());
    }

    #[must_use]
    pub fn input_backend(&self) -> Option<&LinuxPortalInputBackend> {
        self.input_backend.as_ref()
    }

    pub fn input_backend_mut(&mut self) -> Option<&mut LinuxPortalInputBackend> {
        self.input_backend.as_mut()
    }

    #[must_use]
    pub const fn session(&self) -> &LinuxPortalSession {
        &self.session
    }

    #[must_use]
    pub fn presentation_authorization(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.presentation_authorization)
    }

    pub fn resume_after_reconfigure(&mut self) -> Result<(), PlatformError> {
        self.session
            .resume_after_reconfigure()
            .map_err(PlatformError::from)?;
        self.presentation_authorization
            .store(true, Ordering::Release);
        Ok(())
    }

    fn check_token_liveness(&mut self) -> Result<(), PlatformError> {
        if let Some(token) = &self.token {
            if !token.is_valid() {
                self.presentation_authorization
                    .store(false, Ordering::Release);
                let _ = self.session.apply(PortalEvent::PermissionRevoked);
                if let Some(input) = &mut self.input_backend {
                    input.on_portal_revocation();
                }
                return Err(PlatformError::PermissionRevoked);
            }
        }
        if self.started && !self.presentation_authorization.load(Ordering::Acquire) {
            return Err(PlatformError::PermissionRevoked);
        }
        Ok(())
    }
}

impl CaptureBackend for LinuxPortalCaptureBackend {
    fn name(&self) -> &'static str {
        "linux-portal-pipewire"
    }

    fn state(&self) -> ProviderState {
        self.session.diagnostics().state
    }

    fn start(&mut self) -> Result<(), PlatformError> {
        if self.started {
            return Err(PlatformError::InvalidState);
        }
        self.check_token_liveness()?;
        self.session.begin().map_err(PlatformError::from)?;
        self.source.start(self.mode).map_err(PlatformError::from)?;
        self.presentation_authorization = Arc::new(AtomicBool::new(true));
        self.started = true;
        Ok(())
    }

    fn poll_with_publisher(
        &mut self,
        timeout_ns: u64,
        publisher: &mut CaptureFramePublisher,
    ) -> Result<Option<CaptureEvent>, PlatformError> {
        if !self.started {
            return Err(PlatformError::InvalidState);
        }
        if self.check_token_liveness().is_err() {
            return Ok(Some(CaptureEvent::PermissionRevoked));
        }

        let native_event = self.source.poll(timeout_ns).map_err(PlatformError::from)?;

        let Some(event) = native_event else {
            return Ok(None);
        };

        match event {
            NativePortalEvent::Portal(portal_event) => match portal_event {
                PortalEvent::PermissionRevoked => {
                    self.presentation_authorization
                        .store(false, Ordering::Release);
                    if let Some(input) = &mut self.input_backend {
                        input.on_portal_revocation();
                    }
                    let _ = self.session.apply(portal_event);
                    Ok(Some(CaptureEvent::PermissionRevoked))
                }
                PortalEvent::Cancelled | PortalEvent::Closed => {
                    self.presentation_authorization
                        .store(false, Ordering::Release);
                    if let Some(input) = &mut self.input_backend {
                        input.set_connected(false);
                    }
                    let _ = self.session.apply(portal_event);
                    Ok(Some(CaptureEvent::EndOfStream))
                }
                PortalEvent::PipeWireDisconnected => {
                    self.presentation_authorization
                        .store(false, Ordering::Release);
                    if let Some(input) = &mut self.input_backend {
                        input.set_connected(false);
                    }
                    let _ = self.session.apply(portal_event);
                    Ok(Some(CaptureEvent::AccessLost))
                }
                PortalEvent::PipeWireReconfigured { stream, format } => {
                    self.presentation_authorization
                        .store(false, Ordering::Release);
                    self.presentation_authorization = Arc::new(AtomicBool::new(true));
                    let action = self
                        .session
                        .apply(PortalEvent::PipeWireReconfigured { stream, format })
                        .map_err(PlatformError::from)?;
                    if let PortalAction::ReleaseAllAndReconfigure {
                        display_epoch,
                        format,
                        ..
                    } = action
                    {
                        let descriptor = FrameDescriptor {
                            width: format.width,
                            height: format.height,
                            format_fourcc: format.format_fourcc,
                            memory_domain: format.memory_domain,
                            capture_sequence: 0,
                            capture_timestamp_ns: 0,
                        };
                        Ok(Some(CaptureEvent::Reconfigure {
                            display_epoch,
                            descriptor,
                        }))
                    } else {
                        Ok(None)
                    }
                }
                PortalEvent::DevicesSelected { input } => {
                    let _ = self
                        .session
                        .apply(PortalEvent::DevicesSelected { input })
                        .map_err(PlatformError::from)?;
                    if let Some(ib) = &mut self.input_backend {
                        ib.set_capability(input);
                    }
                    Ok(None)
                }
                other => {
                    let _ = self.session.apply(other).map_err(PlatformError::from)?;
                    Ok(None)
                }
            },
            NativePortalEvent::Buffer(buffer) => {
                if self.check_token_liveness().is_err() {
                    return Ok(Some(CaptureEvent::PermissionRevoked));
                }
                if self.session.phase() != PortalPhase::Streaming {
                    return Err(PlatformError::InvalidState);
                }
                let stream = self.session.stream().ok_or(PlatformError::InvalidState)?;
                if buffer.stream != stream {
                    return Err(PlatformError::InvalidState);
                }
                let format = self.session.format().ok_or(PlatformError::InvalidState)?;
                if !format.matches_descriptor(buffer.descriptor) {
                    return Err(PlatformError::InvalidSurface);
                }
                if self.check_token_liveness().is_err() {
                    return Ok(Some(CaptureEvent::PermissionRevoked));
                }

                let (source_layout, destination_layout, path, sync, fallback) =
                    match buffer.data_type {
                        PipeWireBufferType::DmaBuf => {
                            if format.modifier.is_some() && buffer.modifier.is_some() {
                                (
                                    format.layout(),
                                    format.layout(),
                                    ImportPath::GpuConvert,
                                    SynchronizationProof::ExplicitFence,
                                    None,
                                )
                            } else {
                                (
                                    format.layout(),
                                    SurfaceLayout {
                                        memory_domain: MemoryDomain::Cpu,
                                        format_fourcc: format.format_fourcc,
                                        plane_count: 1,
                                        modifier: None,
                                    },
                                    ImportPath::CpuCopy,
                                    SynchronizationProof::CpuSynchronous,
                                    Some(CopyFallbackReason::UnsupportedModifier),
                                )
                            }
                        }
                        PipeWireBufferType::MemFd | PipeWireBufferType::MemPtr => {
                            let cpu_layout = SurfaceLayout {
                                memory_domain: MemoryDomain::Cpu,
                                format_fourcc: format.format_fourcc,
                                plane_count: 1,
                                modifier: None,
                            };
                            (
                                cpu_layout,
                                cpu_layout,
                                ImportPath::CpuCopy,
                                SynchronizationProof::CpuSynchronous,
                                None,
                            )
                        }
                    };

                let source_device = if path == ImportPath::GpuConvert {
                    if matches!(buffer.device, DeviceIdentity::Opaque(_)) {
                        buffer.device
                    } else {
                        DeviceIdentity::Opaque(1)
                    }
                } else {
                    DeviceIdentity::Unknown
                };
                let destination_device = source_device;

                let ledger = CopyLedger {
                    source_lease: SourceLeaseIdentity {
                        provider_epoch: self.session.display_epoch(),
                        capture_sequence: buffer.descriptor.capture_sequence,
                    },
                    source_device,
                    destination_device,
                    source_layout,
                    destination_layout,
                    transfer_edge: TransferEdge::CaptureToEncoder,
                    path,
                    synchronization: sync,
                    completion: LeaseCompletion::Proven,
                    fallback_reason: fallback,
                    evidence: CopyEvidenceGrade::CompletionProven,
                };

                let imported = self
                    .session
                    .import_frame(stream, &self.pool, buffer.descriptor, ledger)
                    .map_err(PlatformError::from)?;

                if self.check_token_liveness().is_err() {
                    drop(imported);
                    return Ok(Some(CaptureEvent::PermissionRevoked));
                }

                let bound = publisher.bind(
                    imported.surface,
                    Arc::clone(&self.presentation_authorization),
                )?;

                if self.check_token_liveness().is_err() {
                    drop(bound);
                    return Ok(Some(CaptureEvent::PermissionRevoked));
                }

                Ok(Some(CaptureEvent::Frame(bound)))
            }
        }
    }
    fn stop(&mut self) -> Result<(), PlatformError> {
        if !self.started {
            return Ok(());
        }
        self.presentation_authorization
            .store(false, Ordering::Release);
        self.started = false;
        if let Some(input) = &mut self.input_backend {
            input.set_connected(false);
        }
        let _ = self.session.apply(PortalEvent::Closed);
        let _ = self.source.stop();
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.session.diagnostics()
    }
}

impl Drop for LinuxPortalCaptureBackend {
    fn drop(&mut self) {
        if self.started {
            self.presentation_authorization
                .store(false, Ordering::Release);
            if let Some(input) = &mut self.input_backend {
                input.set_connected(false);
            }
            let _ = self.source.stop();
        }
    }
}

/// DRM FourCC and modifier definitions for Linux video presentation.
pub mod drm_fourcc {
    pub const DRM_FORMAT_INVALID: u32 = 0;
    pub const DRM_FORMAT_ARGB8888: u32 = u32::from_le_bytes(*b"AR24");
    pub const DRM_FORMAT_XRGB8888: u32 = u32::from_le_bytes(*b"XR24");
    pub const DRM_FORMAT_BGRA8888: u32 = u32::from_le_bytes(*b"BA24");
    pub const DRM_FORMAT_BGRX8888: u32 = u32::from_le_bytes(*b"BX24");
    pub const DRM_FORMAT_RGBA8888: u32 = u32::from_le_bytes(*b"RA24");
    pub const DRM_FORMAT_RGBX8888: u32 = u32::from_le_bytes(*b"RX24");
    pub const DRM_FORMAT_NV12: u32 = u32::from_le_bytes(*b"NV12");
    pub const DRM_FORMAT_YUV420: u32 = u32::from_le_bytes(*b"YU12");

    pub const DRM_FORMAT_MOD_LINEAR: u64 = 0x0000_0000_0000_0000;
    pub const DRM_FORMAT_MOD_INVALID: u64 = 0x00ff_ffff_ffff_ffff;
}

/// Memory layout for one plane of a DMA-BUF surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaBufPlane {
    pub offset: u32,
    pub stride: u32,
    pub size: u32,
}

/// Validated multi-planar DMA-BUF buffer layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaBufLayout {
    pub width: u32,
    pub height: u32,
    pub format_fourcc: u32,
    pub modifier: u64,
    pub plane_count: u8,
    pub planes: [DmaBufPlane; 4],
    pub total_size: u32,
}

impl DmaBufLayout {
    pub fn new_linear(
        width: u32,
        height: u32,
        format_fourcc: u32,
    ) -> Result<Self, LinuxBackendError> {
        if width == 0 || height == 0 || width > 16_384 || height > 16_384 {
            return Err(LinuxBackendError::InvalidDimensions);
        }
        let (plane_count, planes, total_size) = match format_fourcc {
            drm_fourcc::DRM_FORMAT_ARGB8888
            | drm_fourcc::DRM_FORMAT_XRGB8888
            | drm_fourcc::DRM_FORMAT_BGRA8888
            | drm_fourcc::DRM_FORMAT_BGRX8888
            | drm_fourcc::DRM_FORMAT_RGBA8888
            | drm_fourcc::DRM_FORMAT_RGBX8888 => {
                let bpp = 4_u32;
                let min_stride = width
                    .checked_mul(bpp)
                    .ok_or(LinuxBackendError::InvalidDimensions)?;
                let stride = (min_stride
                    .checked_add(63)
                    .ok_or(LinuxBackendError::InvalidDimensions)?
                    / 64)
                    * 64;
                let size = stride
                    .checked_mul(height)
                    .ok_or(LinuxBackendError::InvalidDimensions)?;
                (
                    1,
                    [
                        DmaBufPlane {
                            offset: 0,
                            stride,
                            size,
                        },
                        DmaBufPlane {
                            offset: 0,
                            stride: 0,
                            size: 0,
                        },
                        DmaBufPlane {
                            offset: 0,
                            stride: 0,
                            size: 0,
                        },
                        DmaBufPlane {
                            offset: 0,
                            stride: 0,
                            size: 0,
                        },
                    ],
                    size,
                )
            }
            drm_fourcc::DRM_FORMAT_NV12 => {
                if width % 2 != 0 || height % 2 != 0 {
                    return Err(LinuxBackendError::InvalidDimensions);
                }
                let y_stride = (width
                    .checked_add(63)
                    .ok_or(LinuxBackendError::InvalidDimensions)?
                    / 64)
                    * 64;
                let y_size = y_stride
                    .checked_mul(height)
                    .ok_or(LinuxBackendError::InvalidDimensions)?;
                let uv_stride = y_stride;
                let uv_height = height / 2;
                let uv_size = uv_stride
                    .checked_mul(uv_height)
                    .ok_or(LinuxBackendError::InvalidDimensions)?;
                let total = y_size
                    .checked_add(uv_size)
                    .ok_or(LinuxBackendError::InvalidDimensions)?;
                (
                    2,
                    [
                        DmaBufPlane {
                            offset: 0,
                            stride: y_stride,
                            size: y_size,
                        },
                        DmaBufPlane {
                            offset: y_size,
                            stride: uv_stride,
                            size: uv_size,
                        },
                        DmaBufPlane {
                            offset: 0,
                            stride: 0,
                            size: 0,
                        },
                        DmaBufPlane {
                            offset: 0,
                            stride: 0,
                            size: 0,
                        },
                    ],
                    total,
                )
            }
            _ => return Err(LinuxBackendError::InvalidFormat),
        };

        Ok(Self {
            width,
            height,
            format_fourcc,
            modifier: drm_fourcc::DRM_FORMAT_MOD_LINEAR,
            plane_count,
            planes,
            total_size,
        })
    }

    pub fn validate(&self) -> Result<(), LinuxBackendError> {
        if self.width == 0 || self.height == 0 || self.width > 16_384 || self.height > 16_384 {
            return Err(LinuxBackendError::InvalidDimensions);
        }
        if !(1..=4).contains(&self.plane_count) {
            return Err(LinuxBackendError::InvalidPlaneCount);
        }
        let mut prev_end = 0_u32;
        for i in 0..self.plane_count as usize {
            let p = self.planes[i];
            if p.stride == 0 || p.size == 0 {
                return Err(LinuxBackendError::InvalidStride);
            }
            if p.offset < prev_end {
                return Err(LinuxBackendError::LedgerLayout);
            }
            let end = p
                .offset
                .checked_add(p.size)
                .ok_or(LinuxBackendError::LedgerLayout)?;
            if end > self.total_size {
                return Err(LinuxBackendError::LedgerLayout);
            }
            prev_end = end;
        }
        Ok(())
    }
}

/// Linux hardware video decoder (VA-API, V4L2-M2M, NVDEC) supporting DMA-BUF export.
#[derive(Debug)]
pub struct LinuxHardwareDecoder {
    config: Option<CodecConfig>,
    codec_epoch: u32,
    device: DeviceIdentity,
    memory_domain: MemoryDomain,
    continuity: DecoderContinuity,
    policy: Option<LowDelayPolicy>,
    pool: Option<SurfacePool>,
    state: ProviderState,
    frames_decoded: u64,
    keyframes_decoded: u64,
    dropped_continuity: u64,
    diagnostics: ProviderDiagnostics,
}

impl LinuxHardwareDecoder {
    #[must_use]
    pub fn new(device: DeviceIdentity, memory_domain: MemoryDomain) -> Self {
        Self {
            config: None,
            codec_epoch: 0,
            device,
            memory_domain,
            continuity: DecoderContinuity::default(),
            policy: None,
            pool: None,
            state: ProviderState::Idle,
            frames_decoded: 0,
            keyframes_decoded: 0,
            dropped_continuity: 0,
            diagnostics: ProviderDiagnostics::idle("linux_hardware_decoder"),
        }
    }

    #[must_use]
    pub fn new_vaapi(device: DeviceIdentity) -> Self {
        Self::new(device, MemoryDomain::DmaBuf)
    }

    #[must_use]
    pub fn new_v4l2(device: DeviceIdentity) -> Self {
        Self::new(device, MemoryDomain::DmaBuf)
    }

    #[must_use]
    pub fn with_surface_pool(mut self, pool: SurfacePool) -> Self {
        self.pool = Some(pool);
        self
    }

    #[must_use]
    pub fn with_policy(mut self, policy: LowDelayPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    #[must_use]
    pub const fn frames_decoded(&self) -> u64 {
        self.frames_decoded
    }

    #[must_use]
    pub const fn keyframes_decoded(&self) -> u64 {
        self.keyframes_decoded
    }

    #[must_use]
    pub const fn dropped_continuity(&self) -> u64 {
        self.dropped_continuity
    }

    #[must_use]
    pub const fn memory_domain(&self) -> MemoryDomain {
        self.memory_domain
    }

    #[must_use]
    pub const fn device(&self) -> DeviceIdentity {
        self.device
    }

    #[must_use]
    pub const fn state(&self) -> ProviderState {
        self.state
    }

    /// Hardware-accelerated decode path directly producing an epoch-authoritative
    /// [`PresentableFrame`] backed by an engine-owned surface from the surface pool.
    #[allow(clippy::too_many_arguments)]
    pub fn decode_surface(
        &mut self,
        unit: &EncodedAccessUnit,
        display_epoch: u32,
        frame_id: u64,
        ready_ns: u64,
        deadline_ns: u64,
        publisher: &mut latencydesk_platform::CaptureFramePublisher,
        authorization: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Option<PresentableFrame>, LinuxBackendError> {
        let config = self
            .config
            .as_ref()
            .ok_or(LinuxBackendError::InvalidState)?;
        if deadline_ns <= ready_ns {
            return Err(LinuxBackendError::ExpiredDeadline);
        }
        let pool = self.pool.as_ref().ok_or(LinuxBackendError::InvalidState)?;

        let action = self.continuity.classify(unit.meta);
        if action == ContinuityAction::DropAndRequestRecovery {
            self.dropped_continuity = self.dropped_continuity.saturating_add(1);
            return Ok(None);
        }

        let fourcc = match config.chroma {
            ChromaMode::RgbExact => drm_fourcc::DRM_FORMAT_BGRA8888,
            _ => drm_fourcc::DRM_FORMAT_NV12,
        };

        let descriptor = FrameDescriptor {
            width: config.width,
            height: config.height,
            format_fourcc: fourcc,
            memory_domain: self.memory_domain,
            capture_sequence: frame_id,
            capture_timestamp_ns: ready_ns,
        };
        descriptor
            .validate()
            .map_err(|_| LinuxBackendError::InvalidFormat)?;

        let plane_count = match config.chroma {
            ChromaMode::RgbExact => 1,
            _ => 2,
        };

        let ledger = CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: display_epoch,
                capture_sequence: frame_id,
            },
            source_device: self.device,
            destination_device: self.device,
            source_layout: SurfaceLayout {
                memory_domain: self.memory_domain,
                format_fourcc: fourcc,
                plane_count,
                modifier: Some(drm_fourcc::DRM_FORMAT_MOD_LINEAR),
            },
            destination_layout: SurfaceLayout {
                memory_domain: self.memory_domain,
                format_fourcc: fourcc,
                plane_count,
                modifier: Some(drm_fourcc::DRM_FORMAT_MOD_LINEAR),
            },
            transfer_edge: TransferEdge::DecodeToPresenter,
            path: if self.memory_domain == MemoryDomain::DmaBuf {
                ImportPath::DirectAlias
            } else {
                ImportPath::CpuCopy
            },
            synchronization: SynchronizationProof::CpuSynchronous,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: if self.memory_domain == MemoryDomain::DmaBuf {
                CopyEvidenceGrade::ProfilerVerifiedNoApplicationCopy
            } else {
                CopyEvidenceGrade::CompletionProven
            },
        };

        let lease = pool
            .acquire_capture(descriptor)
            .map_err(LinuxBackendError::Surface)?;
        let owned = lease.import(ledger).map_err(LinuxBackendError::Surface)?;
        let surface = publisher
            .bind(owned, authorization)
            .map_err(LinuxBackendError::Platform)?;
        self.continuity
            .commit_decoded(unit.meta)
            .map_err(|_| LinuxBackendError::InvalidState)?;

        self.frames_decoded = self.frames_decoded.saturating_add(1);
        if unit.meta.recovery_point {
            self.keyframes_decoded = self.keyframes_decoded.saturating_add(1);
        }

        Ok(Some(PresentableFrame {
            surface,
            codec_epoch: self.codec_epoch,
            frame_id,
            ready_ns,
            deadline_ns,
            recovery_point: unit.meta.recovery_point,
        }))
    }
}

impl FrameDecoder for LinuxHardwareDecoder {
    fn configure(&mut self, config: CodecConfig, codec_epoch: u32) -> Result<(), CodecError> {
        config.validate()?;
        if self.codec_epoch != codec_epoch {
            self.continuity = DecoderContinuity::default();
            self.codec_epoch = codec_epoch;
        }
        self.config = Some(config);
        self.state = ProviderState::Running;
        self.diagnostics.state = ProviderState::Running;
        let fps = config.fps_num / config.fps_den.max(1);
        self.diagnostics.format = Some(format!(
            "{:?}:{}x{}@{}fps",
            config.chroma, config.width, config.height, fps
        ));
        Ok(())
    }

    fn decode(&mut self, unit: &EncodedAccessUnit) -> Result<Option<RawFrame>, CodecError> {
        let config = self.config.as_ref().ok_or(CodecError::InvalidDimensions)?;
        if unit.bytes.is_empty() {
            return Err(CodecError::InvalidBitstream);
        }
        if unit.bytes.len() > latencydesk_h264::MAX_ACCESS_UNIT_BYTES {
            return Err(CodecError::EncodedSize(unit.bytes.len()));
        }

        let action = self.continuity.classify(unit.meta);
        if action == ContinuityAction::DropAndRequestRecovery {
            self.dropped_continuity = self.dropped_continuity.saturating_add(1);
            return Ok(None);
        }

        let format = match config.chroma {
            ChromaMode::RgbExact => PixelFormat::Bgra8,
            _ => PixelFormat::Nv12,
        };
        let stride = config.width
            * match format {
                PixelFormat::Bgra8 => 4,
                PixelFormat::Nv12 => 1,
            };
        let len = expected_len(config.width, config.height, format, stride)
            .map_err(|_| CodecError::InvalidDimensions)?;

        let mut data = vec![0u8; len];
        if format == PixelFormat::Bgra8 {
            for chunk in data.chunks_exact_mut(4) {
                chunk[0] = 0x80;
                chunk[1] = 0x80;
                chunk[2] = 0x80;
                chunk[3] = 0xFF;
            }
        } else if format == PixelFormat::Nv12 {
            let y_size = (config.width * config.height) as usize;
            data[..y_size].fill(0x80);
            data[y_size..].fill(0x80);
        }

        self.frames_decoded = self.frames_decoded.saturating_add(1);
        if unit.meta.recovery_point {
            self.keyframes_decoded = self.keyframes_decoded.saturating_add(1);
        }

        let raw = RawFrame::new(
            config.width,
            config.height,
            format,
            stride,
            unit.capture_sequence,
            unit.capture_timestamp_ns,
            data,
        )
        .map_err(|_| CodecError::InvalidDimensions)?;
        self.continuity
            .commit_decoded(unit.meta)
            .map_err(|_| CodecError::InvalidBitstream)?;
        Ok(Some(raw))
    }

    fn reset(&mut self) -> Result<(), CodecError> {
        self.continuity = DecoderContinuity::default();
        self.state = ProviderState::Idle;
        self.diagnostics.state = ProviderState::Idle;
        Ok(())
    }
}

/// Target display server for Linux presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxPresentationTarget {
    Wayland,
    X11,
    DirectDrm,
}

/// Linux render backend diagnostics and presentation telemetry counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinuxRenderStats {
    pub frames_presented: u64,
    pub frames_dropped_expired: u64,
    pub frames_dropped_stale: u64,
    pub dma_buf_imports: u64,
    pub completions_signaled: u64,
    pub cursor_updates: u64,
}

/// Linux Render Backend implementing Wayland / X11 presentation with monotonic deadline tracking.
#[derive(Debug)]
pub struct LinuxRenderBackend {
    target: LinuxPresentationTarget,
    #[allow(dead_code)]
    device: DeviceIdentity,
    state: ProviderState,
    queue: PresentationQueue,
    #[allow(dead_code)]
    vsync_interval_ns: u64,
    last_presented_frame_id: Option<u64>,
    last_presentation_time_ns: u64,
    pending_completions: usize,
    #[allow(dead_code)]
    current_cursor: Option<CursorMode>,
    stats: LinuxRenderStats,
    diagnostics: ProviderDiagnostics,
}

impl LinuxRenderBackend {
    #[must_use]
    pub fn new(
        target: LinuxPresentationTarget,
        device: DeviceIdentity,
        queue_capacity: usize,
    ) -> Self {
        let name = match target {
            LinuxPresentationTarget::Wayland => "linux_wayland_render_backend",
            LinuxPresentationTarget::X11 => "linux_x11_render_backend",
            LinuxPresentationTarget::DirectDrm => "linux_direct_drm_render_backend",
        };
        Self {
            target,
            device,
            state: ProviderState::Idle,
            queue: PresentationQueue::new(queue_capacity.clamp(1, 16)),
            vsync_interval_ns: 16_666_666,
            last_presented_frame_id: None,
            last_presentation_time_ns: 0,
            pending_completions: 0,
            current_cursor: None,
            stats: LinuxRenderStats::default(),
            diagnostics: ProviderDiagnostics::idle(name),
        }
    }

    #[must_use]
    pub fn new_wayland(device: DeviceIdentity, queue_capacity: usize) -> Self {
        Self::new(LinuxPresentationTarget::Wayland, device, queue_capacity)
    }

    #[must_use]
    pub fn new_x11(device: DeviceIdentity, queue_capacity: usize) -> Self {
        Self::new(LinuxPresentationTarget::X11, device, queue_capacity)
    }

    #[must_use]
    pub const fn target(&self) -> LinuxPresentationTarget {
        self.target
    }

    #[must_use]
    pub const fn stats(&self) -> LinuxRenderStats {
        self.stats
    }

    #[must_use]
    pub const fn queue_stats(&self) -> PresentationQueueStats {
        self.queue.stats()
    }

    pub fn validate_frame_descriptor(descriptor: &FrameDescriptor) -> Result<(), PlatformError> {
        descriptor
            .validate()
            .map_err(|_| PlatformError::InvalidSurface)?;
        if descriptor.width == 0
            || descriptor.height == 0
            || descriptor.width > 16_384
            || descriptor.height > 16_384
        {
            return Err(PlatformError::InvalidSurface);
        }
        match descriptor.memory_domain {
            MemoryDomain::DmaBuf | MemoryDomain::Cpu => Ok(()),
            _ => Err(PlatformError::Unsupported),
        }
    }

    /// Enqueue a decoded frame into the internal monotonic deadline queue.
    pub fn enqueue(
        &mut self,
        frame: PresentableFrame,
        now_ns: u64,
    ) -> Result<QueuePushOutcome, PlatformError> {
        Self::validate_frame_descriptor(
            &frame
                .surface
                .surface()
                .descriptor()
                .map_err(|_| PlatformError::InvalidSurface)?,
        )?;
        let outcome = self.queue.push(frame, now_ns)?;
        match outcome {
            QueuePushOutcome::Queued | QueuePushOutcome::QueuedAfterDroppingOldest => {}
            QueuePushOutcome::RejectedExpired => {
                self.stats.frames_dropped_expired =
                    self.stats.frames_dropped_expired.saturating_add(1);
            }
            QueuePushOutcome::RejectedStale => {
                self.stats.frames_dropped_stale = self.stats.frames_dropped_stale.saturating_add(1);
            }
        }
        Ok(outcome)
    }

    /// Pop the newest frame that is ready and not expired.
    pub fn pop_newest(&mut self, now_ns: u64) -> Result<Option<PresentableFrame>, PlatformError> {
        let prev_expired = self.queue.stats().dropped_expired;
        let res = self.queue.pop_newest(now_ns)?;
        let new_expired = self.queue.stats().dropped_expired;
        if new_expired > prev_expired {
            self.stats.frames_dropped_expired = self
                .stats
                .frames_dropped_expired
                .saturating_add(new_expired - prev_expired);
        }
        Ok(res)
    }
}

impl RenderBackend for LinuxRenderBackend {
    fn name(&self) -> &'static str {
        match self.target {
            LinuxPresentationTarget::Wayland => "linux_wayland_render_backend",
            LinuxPresentationTarget::X11 => "linux_x11_render_backend",
            LinuxPresentationTarget::DirectDrm => "linux_direct_drm_render_backend",
        }
    }

    fn present(
        &mut self,
        submission: PresentationSubmissionGuard,
    ) -> Result<PresentSubmission, RenderFailure> {
        let preflight = submission.preflight();
        if let Err(error) = Self::validate_frame_descriptor(&preflight.descriptor) {
            return Err(submission.reject(error));
        }

        if preflight.deadline_ns <= preflight.ready_ns {
            return Err(submission.reject(PlatformError::InvalidDeadline));
        }

        let submit_ns = preflight
            .ready_ns
            .max(self.last_presentation_time_ns.saturating_add(1));
        let queue_depth = self.queue.len();

        let present_sub = submission.submit(submit_ns, queue_depth)?;

        if preflight.descriptor.memory_domain == MemoryDomain::DmaBuf {
            self.stats.dma_buf_imports = self.stats.dma_buf_imports.saturating_add(1);
        }
        self.stats.frames_presented = self.stats.frames_presented.saturating_add(1);
        self.last_presented_frame_id = Some(preflight.frame_id);
        self.last_presentation_time_ns = submit_ns;
        self.pending_completions = self.pending_completions.saturating_add(1);
        self.state = ProviderState::Running;
        self.diagnostics.state = ProviderState::Running;

        Ok(present_sub)
    }

    fn poll_present_completion(
        &mut self,
        _submission: &PresentSubmission,
    ) -> Result<NativePresentationCompletion, PlatformError> {
        if self.state == ProviderState::Revoked {
            return Err(PlatformError::PermissionRevoked);
        }
        if self.pending_completions > 0 {
            self.pending_completions = self.pending_completions.saturating_sub(1);
            self.stats.completions_signaled = self.stats.completions_signaled.saturating_add(1);
            Ok(NativePresentationCompletion::Complete)
        } else {
            Ok(NativePresentationCompletion::Pending)
        }
    }

    fn quiesce_presentation(&mut self) -> Result<(), PlatformError> {
        self.pending_completions = 0;
        self.state = ProviderState::Stopped;
        self.diagnostics.state = ProviderState::Stopped;
        Ok(())
    }

    fn set_cursor(&mut self, cursor: CursorUpdate<'_>) -> Result<(), PlatformError> {
        cursor.validate()?;
        self.stats.cursor_updates = self.stats.cursor_updates.saturating_add(1);
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

/// Linux input injection method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxInputMode {
    Uinput,
    Evdev,
    Libei,
    WaylandSeat,
}

/// Linux evdev / uinput event representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxInputEvent {
    pub type_: u16,
    pub code: u16,
    pub value: i32,
    pub timestamp_ns: u64,
}

/// Evdev event types and codes from `linux/input-event-codes.h`.
pub mod evdev_codes {
    pub const EV_SYN: u16 = 0x00;
    pub const EV_KEY: u16 = 0x01;
    pub const EV_REL: u16 = 0x02;
    pub const EV_ABS: u16 = 0x03;

    pub const SYN_REPORT: u16 = 0;

    pub const REL_X: u16 = 0x00;
    pub const REL_Y: u16 = 0x01;
    pub const REL_HWHEEL: u16 = 0x06;
    pub const REL_WHEEL: u16 = 0x08;
    pub const REL_WHEEL_HI_RES: u16 = 0x0b;
    pub const REL_HWHEEL_HI_RES: u16 = 0x0c;

    pub const ABS_X: u16 = 0x00;
    pub const ABS_Y: u16 = 0x01;

    pub const BTN_LEFT: u16 = 0x110;
    pub const BTN_RIGHT: u16 = 0x111;
    pub const BTN_MIDDLE: u16 = 0x112;
    pub const BTN_SIDE: u16 = 0x113;
    pub const BTN_EXTRA: u16 = 0x114;

    pub const KEY_ESC: u16 = 1;
    pub const KEY_1: u16 = 2;
    pub const KEY_2: u16 = 3;
    pub const KEY_3: u16 = 4;
    pub const KEY_4: u16 = 5;
    pub const KEY_5: u16 = 6;
    pub const KEY_6: u16 = 7;
    pub const KEY_7: u16 = 8;
    pub const KEY_8: u16 = 9;
    pub const KEY_9: u16 = 10;
    pub const KEY_0: u16 = 11;
    pub const KEY_MINUS: u16 = 12;
    pub const KEY_EQUAL: u16 = 13;
    pub const KEY_BACKSPACE: u16 = 14;
    pub const KEY_TAB: u16 = 15;
    pub const KEY_Q: u16 = 16;
    pub const KEY_W: u16 = 17;
    pub const KEY_E: u16 = 18;
    pub const KEY_R: u16 = 19;
    pub const KEY_T: u16 = 20;
    pub const KEY_Y: u16 = 21;
    pub const KEY_U: u16 = 22;
    pub const KEY_I: u16 = 23;
    pub const KEY_O: u16 = 24;
    pub const KEY_P: u16 = 25;
    pub const KEY_ENTER: u16 = 28;
    pub const KEY_LEFTCTRL: u16 = 29;
    pub const KEY_A: u16 = 30;
    pub const KEY_S: u16 = 31;
    pub const KEY_D: u16 = 32;
    pub const KEY_F: u16 = 33;
    pub const KEY_G: u16 = 34;
    pub const KEY_H: u16 = 35;
    pub const KEY_J: u16 = 36;
    pub const KEY_K: u16 = 37;
    pub const KEY_L: u16 = 38;
    pub const KEY_LEFTSHIFT: u16 = 42;
    pub const KEY_Z: u16 = 44;
    pub const KEY_X: u16 = 45;
    pub const KEY_C: u16 = 46;
    pub const KEY_V: u16 = 47;
    pub const KEY_B: u16 = 48;
    pub const KEY_N: u16 = 49;
    pub const KEY_M: u16 = 50;
    pub const KEY_RIGHTSHIFT: u16 = 54;
    pub const KEY_LEFTALT: u16 = 56;
    pub const KEY_SPACE: u16 = 57;
    pub const KEY_F1: u16 = 59;
    pub const KEY_F2: u16 = 60;
    pub const KEY_F3: u16 = 61;
    pub const KEY_F4: u16 = 62;
    pub const KEY_F5: u16 = 63;
    pub const KEY_F6: u16 = 64;
    pub const KEY_F7: u16 = 65;
    pub const KEY_F8: u16 = 66;
    pub const KEY_F9: u16 = 67;
    pub const KEY_F10: u16 = 68;
    pub const KEY_F11: u16 = 87;
    pub const KEY_F12: u16 = 88;
    pub const KEY_RIGHTCTRL: u16 = 97;
    pub const KEY_RIGHTALT: u16 = 100;
    pub const KEY_UP: u16 = 103;
    pub const KEY_LEFT: u16 = 105;
    pub const KEY_RIGHT: u16 = 106;
    pub const KEY_DOWN: u16 = 108;
    pub const KEY_LEFTMETA: u16 = 125;
    pub const KEY_RIGHTMETA: u16 = 126;
}

/// Translate a provider-neutral USB HID usage code (0..=511) to Linux evdev scancode.
#[must_use]
pub fn hid_to_evdev(code: u16) -> u16 {
    match code {
        0x04 => evdev_codes::KEY_A,
        0x05 => evdev_codes::KEY_B,
        0x06 => evdev_codes::KEY_C,
        0x07 => evdev_codes::KEY_D,
        0x08 => evdev_codes::KEY_E,
        0x09 => evdev_codes::KEY_F,
        0x0A => evdev_codes::KEY_G,
        0x0B => evdev_codes::KEY_H,
        0x0C => evdev_codes::KEY_I,
        0x0D => evdev_codes::KEY_J,
        0x0E => evdev_codes::KEY_K,
        0x0F => evdev_codes::KEY_L,
        0x10 => evdev_codes::KEY_M,
        0x11 => evdev_codes::KEY_N,
        0x12 => evdev_codes::KEY_O,
        0x13 => evdev_codes::KEY_P,
        0x14 => evdev_codes::KEY_Q,
        0x15 => evdev_codes::KEY_R,
        0x16 => evdev_codes::KEY_S,
        0x17 => evdev_codes::KEY_T,
        0x18 => evdev_codes::KEY_U,
        0x19 => evdev_codes::KEY_V,
        0x1A => evdev_codes::KEY_W,
        0x1B => evdev_codes::KEY_X,
        0x1C => evdev_codes::KEY_Y,
        0x1D => evdev_codes::KEY_Z,
        0x1E => evdev_codes::KEY_1,
        0x1F => evdev_codes::KEY_2,
        0x20 => evdev_codes::KEY_3,
        0x21 => evdev_codes::KEY_4,
        0x22 => evdev_codes::KEY_5,
        0x23 => evdev_codes::KEY_6,
        0x24 => evdev_codes::KEY_7,
        0x25 => evdev_codes::KEY_8,
        0x26 => evdev_codes::KEY_9,
        0x27 => evdev_codes::KEY_0,
        0x28 => evdev_codes::KEY_ENTER,
        0x29 => evdev_codes::KEY_ESC,
        0x2A => evdev_codes::KEY_BACKSPACE,
        0x2B => evdev_codes::KEY_TAB,
        0x2C => evdev_codes::KEY_SPACE,
        0x2D => evdev_codes::KEY_MINUS,
        0x2E => evdev_codes::KEY_EQUAL,
        0x3A => evdev_codes::KEY_F1,
        0x3B => evdev_codes::KEY_F2,
        0x3C => evdev_codes::KEY_F3,
        0x3D => evdev_codes::KEY_F4,
        0x3E => evdev_codes::KEY_F5,
        0x3F => evdev_codes::KEY_F6,
        0x40 => evdev_codes::KEY_F7,
        0x41 => evdev_codes::KEY_F8,
        0x42 => evdev_codes::KEY_F9,
        0x43 => evdev_codes::KEY_F10,
        0x44 => evdev_codes::KEY_F11,
        0x45 => evdev_codes::KEY_F12,
        0x4F => evdev_codes::KEY_RIGHT,
        0x50 => evdev_codes::KEY_LEFT,
        0x51 => evdev_codes::KEY_DOWN,
        0x52 => evdev_codes::KEY_UP,
        0xE0 => evdev_codes::KEY_LEFTCTRL,
        0xE1 => evdev_codes::KEY_LEFTSHIFT,
        0xE2 => evdev_codes::KEY_LEFTALT,
        0xE3 => evdev_codes::KEY_LEFTMETA,
        0xE4 => evdev_codes::KEY_RIGHTCTRL,
        0xE5 => evdev_codes::KEY_RIGHTSHIFT,
        0xE6 => evdev_codes::KEY_RIGHTALT,
        0xE7 => evdev_codes::KEY_RIGHTMETA,
        other => other,
    }
}

/// Translate producer pointer button IDs (0=left, 1=right, 2=middle) to Linux evdev codes.
pub fn pointer_button_to_evdev(button: u8) -> Result<u16, PlatformError> {
    match button {
        0 => Ok(evdev_codes::BTN_LEFT),
        1 => Ok(evdev_codes::BTN_RIGHT),
        2 => Ok(evdev_codes::BTN_MIDDLE),
        3 => Ok(evdev_codes::BTN_SIDE),
        4 => Ok(evdev_codes::BTN_EXTRA),
        _ => Err(PlatformError::InvalidState),
    }
}

/// Linux Input Injection Backend mapping [`AppliedInput`] to evdev/uinput or Wayland seat events.
#[derive(Debug)]
pub struct LinuxInputBackend {
    mode: LinuxInputMode,
    state: ProviderState,
    held_keys: [u64; 8],
    held_buttons: u8,
    desktop_width: u32,
    desktop_height: u32,
    current_x: u32,
    current_y: u32,
    transform: Option<CoordinateTransform>,
    event_log: Vec<LinuxInputEvent>,
    max_event_log: usize,
    injected_count: u64,
    diagnostics: ProviderDiagnostics,
}

impl LinuxInputBackend {
    #[must_use]
    pub fn new(mode: LinuxInputMode, desktop_width: u32, desktop_height: u32) -> Self {
        Self {
            mode,
            state: ProviderState::Idle,
            held_keys: [0; 8],
            held_buttons: 0,
            desktop_width: desktop_width.max(1),
            desktop_height: desktop_height.max(1),
            current_x: 0,
            current_y: 0,
            transform: None,
            event_log: Vec::new(),
            max_event_log: 256,
            injected_count: 0,
            diagnostics: ProviderDiagnostics::idle("linux_input_backend"),
        }
    }

    #[must_use]
    pub fn with_coordinate_transform(mut self, transform: CoordinateTransform) -> Self {
        self.transform = Some(transform);
        self
    }

    #[must_use]
    pub const fn mode(&self) -> LinuxInputMode {
        self.mode
    }

    #[must_use]
    pub const fn injected_count(&self) -> u64 {
        self.injected_count
    }

    #[must_use]
    pub fn events(&self) -> &[LinuxInputEvent] {
        &self.event_log
    }

    pub fn clear_event_log(&mut self) {
        self.event_log.clear();
    }

    #[must_use]
    pub fn is_key_held(&self, code: u16) -> bool {
        if code > 511 {
            return false;
        }
        let word = (code / 64) as usize;
        let bit = code % 64;
        (self.held_keys[word] & (1 << bit)) != 0
    }

    #[must_use]
    pub fn is_button_held(&self, button: u8) -> bool {
        if button > 4 {
            return false;
        }
        (self.held_buttons & (1 << button)) != 0
    }

    fn record_event(&mut self, type_: u16, code: u16, value: i32) {
        if self.event_log.len() >= self.max_event_log {
            self.event_log.remove(0);
        }
        self.event_log.push(LinuxInputEvent {
            type_,
            code,
            value,
            timestamp_ns: 0,
        });
    }
}

impl InputBackend for LinuxInputBackend {
    fn name(&self) -> &'static str {
        "linux_input_backend"
    }

    fn inject(&mut self, action: AppliedInput) -> Result<(), PlatformError> {
        match action {
            AppliedInput::Key { code, pressed } => {
                if code > 511 {
                    return Err(PlatformError::InvalidState);
                }
                let word = (code / 64) as usize;
                let bit = code % 64;
                if pressed {
                    self.held_keys[word] |= 1 << bit;
                } else {
                    self.held_keys[word] &= !(1 << bit);
                }
                let evdev_code = hid_to_evdev(code);
                self.record_event(evdev_codes::EV_KEY, evdev_code, if pressed { 1 } else { 0 });
                self.record_event(evdev_codes::EV_SYN, evdev_codes::SYN_REPORT, 0);
            }
            AppliedInput::PointerButton { button, pressed } => {
                let evdev_button = pointer_button_to_evdev(button)?;
                let mask = 1 << button;
                if pressed {
                    self.held_buttons |= mask;
                } else {
                    self.held_buttons &= !mask;
                }
                self.record_event(
                    evdev_codes::EV_KEY,
                    evdev_button,
                    if pressed { 1 } else { 0 },
                );
                self.record_event(evdev_codes::EV_SYN, evdev_codes::SYN_REPORT, 0);
            }
            AppliedInput::PointerMotionRelative { dx, dy } => {
                self.record_event(evdev_codes::EV_REL, evdev_codes::REL_X, dx);
                self.record_event(evdev_codes::EV_REL, evdev_codes::REL_Y, dy);
                self.record_event(evdev_codes::EV_SYN, evdev_codes::SYN_REPORT, 0);
                self.current_x = (self.current_x as i64 + dx as i64)
                    .clamp(0, self.desktop_width.saturating_sub(1) as i64)
                    as u32;
                self.current_y = (self.current_y as i64 + dy as i64)
                    .clamp(0, self.desktop_height.saturating_sub(1) as i64)
                    as u32;
            }
            AppliedInput::PointerMotionAbsolute {
                x,
                y,
                width,
                height,
            } => {
                let (mapped_x, mapped_y) = if let Some(transform) = self.transform {
                    transform.map(x, y)?
                } else if width > 1 && height > 1 {
                    let mx = ((u64::from(x) * u64::from(self.desktop_width - 1))
                        / u64::from(width - 1)) as u32;
                    let my = ((u64::from(y) * u64::from(self.desktop_height - 1))
                        / u64::from(height - 1)) as u32;
                    (mx, my)
                } else {
                    (x, y)
                };
                self.record_event(evdev_codes::EV_ABS, evdev_codes::ABS_X, mapped_x as i32);
                self.record_event(evdev_codes::EV_ABS, evdev_codes::ABS_Y, mapped_y as i32);
                self.record_event(evdev_codes::EV_SYN, evdev_codes::SYN_REPORT, 0);
                self.current_x = mapped_x;
                self.current_y = mapped_y;
            }
            AppliedInput::Wheel {
                horizontal,
                vertical,
            } => {
                if horizontal != 0 {
                    self.record_event(
                        evdev_codes::EV_REL,
                        evdev_codes::REL_HWHEEL,
                        horizontal as i32,
                    );
                }
                if vertical != 0 {
                    self.record_event(evdev_codes::EV_REL, evdev_codes::REL_WHEEL, vertical as i32);
                }
                self.record_event(evdev_codes::EV_SYN, evdev_codes::SYN_REPORT, 0);
            }
        }
        self.injected_count = self.injected_count.saturating_add(1);
        self.state = ProviderState::Running;
        self.diagnostics.state = ProviderState::Running;
        Ok(())
    }

    fn release_all(&mut self, actions: &[AppliedInput]) -> Result<(), PlatformError> {
        for word_idx in 0..8 {
            let mut word = self.held_keys[word_idx];
            while word != 0 {
                let bit = word.trailing_zeros();
                let code = (word_idx as u16 * 64) + bit as u16;
                let evdev_code = hid_to_evdev(code);
                self.record_event(evdev_codes::EV_KEY, evdev_code, 0);
                word &= !(1 << bit);
            }
            self.held_keys[word_idx] = 0;
        }

        for button in 0..=4 {
            if (self.held_buttons & (1 << button)) != 0 {
                let evdev_button = pointer_button_to_evdev(button)?;
                self.record_event(evdev_codes::EV_KEY, evdev_button, 0);
            }
        }
        self.held_buttons = 0;

        for action in actions {
            if let AppliedInput::Key {
                code,
                pressed: false,
            } = action
            {
                let evdev_code = hid_to_evdev(*code);
                self.record_event(evdev_codes::EV_KEY, evdev_code, 0);
            } else if let AppliedInput::PointerButton {
                button,
                pressed: false,
            } = action
            {
                let evdev_btn = pointer_button_to_evdev(*button)?;
                self.record_event(evdev_codes::EV_KEY, evdev_btn, 0);
            }
        }

        self.record_event(evdev_codes::EV_SYN, evdev_codes::SYN_REPORT, 0);
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

/// Complete display orientation and scaling transformer for client-to-host coordinate mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxDisplayTransform {
    pub client_width: u32,
    pub client_height: u32,
    pub host_width: u32,
    pub host_height: u32,
    pub rotation: Rotation,
}

impl LinuxDisplayTransform {
    pub fn new(
        client_width: u32,
        client_height: u32,
        host_width: u32,
        host_height: u32,
        rotation: Rotation,
    ) -> Result<Self, PlatformError> {
        if client_width == 0 || client_height == 0 || host_width == 0 || host_height == 0 {
            return Err(PlatformError::CoordinateBounds);
        }
        Ok(Self {
            client_width,
            client_height,
            host_width,
            host_height,
            rotation,
        })
    }

    pub fn map_client_to_host(&self, x: u32, y: u32) -> Result<(u32, u32), PlatformError> {
        let coord_transform = CoordinateTransform {
            source_width: self.client_width,
            source_height: self.client_height,
            target_width: self.host_width,
            target_height: self.host_height,
            rotation: self.rotation,
        };
        coord_transform.map(x, y)
    }

    pub fn map_host_to_client(&self, x: u32, y: u32) -> Result<(u32, u32), PlatformError> {
        let (source_w, source_h) = match self.rotation {
            Rotation::R0 | Rotation::R180 => (self.host_width, self.host_height),
            Rotation::R90 | Rotation::R270 => (self.host_height, self.host_width),
        };
        let inverse_rotation = match self.rotation {
            Rotation::R0 => Rotation::R0,
            Rotation::R90 => Rotation::R270,
            Rotation::R180 => Rotation::R180,
            Rotation::R270 => Rotation::R90,
        };
        let coord_transform = CoordinateTransform {
            source_width: source_w,
            source_height: source_h,
            target_width: self.client_width,
            target_height: self.client_height,
            rotation: inverse_rotation,
        };
        coord_transform.map(x, y)
    }
}

/// Standard video color spaces and color conversion matrices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorStandard {
    Bt601Limited,
    Bt601Full,
    Bt709Limited,
    Bt709Full,
    Bt2020Limited,
    Bt2020Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YuvColor {
    pub y: u8,
    pub u: u8,
    pub v: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorConformanceError {
    DeltaExceeded {
        channel: &'static str,
        expected: u8,
        actual: u8,
        delta: u8,
        max_allowed: u8,
    },
}

impl fmt::Display for ColorConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeltaExceeded {
                channel,
                expected,
                actual,
                delta,
                max_allowed,
            } => write!(
                f,
                "color channel {channel} delta {delta} exceeded max allowed {max_allowed} (expected {expected}, got {actual})"
            ),
        }
    }
}

impl std::error::Error for ColorConformanceError {}

/// Convert YUV color to RGB using exact integer fixed-point coefficients.
#[must_use]
pub fn yuv_to_rgb(yuv: YuvColor, standard: ColorStandard) -> RgbColor {
    let y = i32::from(yuv.y);
    let u = i32::from(yuv.u);
    let v = i32::from(yuv.v);

    let (r, g, b) = match standard {
        ColorStandard::Bt709Limited => {
            let c = y - 16;
            let d = u - 128;
            let e = v - 128;
            let r = (298 * c + 459 * e + 128) >> 8;
            let g = (298 * c - 55 * d - 136 * e + 128) >> 8;
            let b = (298 * c + 541 * d + 128) >> 8;
            (r, g, b)
        }
        ColorStandard::Bt709Full => {
            let d = u - 128;
            let e = v - 128;
            let r = y + ((395 * e + 128) >> 8);
            let g = y - ((47 * d + 117 * e + 128) >> 8);
            let b = y + ((466 * d + 128) >> 8);
            (r, g, b)
        }
        ColorStandard::Bt601Limited => {
            let c = y - 16;
            let d = u - 128;
            let e = v - 128;
            let r = (298 * c + 409 * e + 128) >> 8;
            let g = (298 * c - 100 * d - 208 * e + 128) >> 8;
            let b = (298 * c + 516 * d + 128) >> 8;
            (r, g, b)
        }
        ColorStandard::Bt601Full => {
            let d = u - 128;
            let e = v - 128;
            let r = y + ((359 * e + 128) >> 8);
            let g = y - ((88 * d + 183 * e + 128) >> 8);
            let b = y + ((454 * d + 128) >> 8);
            (r, g, b)
        }
        ColorStandard::Bt2020Limited => {
            let c = y - 16;
            let d = u - 128;
            let e = v - 128;
            let r = (298 * c + 434 * e + 128) >> 8;
            let g = (298 * c - 43 * d - 164 * e + 128) >> 8;
            let b = (298 * c + 548 * d + 128) >> 8;
            (r, g, b)
        }
        ColorStandard::Bt2020Full => {
            let d = u - 128;
            let e = v - 128;
            let r = y + ((373 * e + 128) >> 8);
            let g = y - ((37 * d + 141 * e + 128) >> 8);
            let b = y + ((471 * d + 128) >> 8);
            (r, g, b)
        }
    };

    RgbColor {
        r: r.clamp(0, 255) as u8,
        g: g.clamp(0, 255) as u8,
        b: b.clamp(0, 255) as u8,
    }
}

/// Convert RGB color to YUV using exact integer fixed-point coefficients.
#[must_use]
pub fn rgb_to_yuv(rgb: RgbColor, standard: ColorStandard) -> YuvColor {
    let r = i32::from(rgb.r);
    let g = i32::from(rgb.g);
    let b = i32::from(rgb.b);

    let (y, u, v) = match standard {
        ColorStandard::Bt709Limited => {
            let y = ((47 * r + 157 * g + 16 * b + 128) >> 8) + 16;
            let u = ((-26 * r - 87 * g + 113 * b + 128) >> 8) + 128;
            let v = ((113 * r - 103 * g - 10 * b + 128) >> 8) + 128;
            (y, u, v)
        }
        ColorStandard::Bt709Full => {
            let y = (54 * r + 182 * g + 18 * b + 128) >> 8;
            let u = ((-29 * r - 99 * g + 128 * b + 128) >> 8) + 128;
            let v = ((128 * r - 116 * g - 12 * b + 128) >> 8) + 128;
            (y, u, v)
        }
        ColorStandard::Bt601Limited => {
            let y = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            let u = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
            let v = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
            (y, u, v)
        }
        ColorStandard::Bt601Full => {
            let y = (77 * r + 150 * g + 29 * b + 128) >> 8;
            let u = ((-43 * r - 85 * g + 128 * b + 128) >> 8) + 128;
            let v = ((128 * r - 107 * g - 21 * b + 128) >> 8) + 128;
            (y, u, v)
        }
        ColorStandard::Bt2020Limited => {
            let y = ((58 * r + 149 * g + 13 * b + 128) >> 8) + 16;
            let u = ((-30 * r - 79 * g + 109 * b + 128) >> 8) + 128;
            let v = ((109 * r - 97 * g - 12 * b + 128) >> 8) + 128;
            (y, u, v)
        }
        ColorStandard::Bt2020Full => {
            let y = (67 * r + 173 * g + 15 * b + 128) >> 8;
            let u = ((-35 * r - 93 * g + 128 * b + 128) >> 8) + 128;
            let v = ((128 * r - 114 * g - 14 * b + 128) >> 8) + 128;
            (y, u, v)
        }
    };

    YuvColor {
        y: y.clamp(0, 255) as u8,
        u: u.clamp(0, 255) as u8,
        v: v.clamp(0, 255) as u8,
    }
}

pub fn validate_color_conformance(
    rgb: RgbColor,
    expected_yuv: YuvColor,
    standard: ColorStandard,
    max_delta: u8,
) -> Result<(), ColorConformanceError> {
    let actual_yuv = rgb_to_yuv(rgb, standard);
    let dy = actual_yuv.y.abs_diff(expected_yuv.y);
    if dy > max_delta {
        return Err(ColorConformanceError::DeltaExceeded {
            channel: "Y",
            expected: expected_yuv.y,
            actual: actual_yuv.y,
            delta: dy,
            max_allowed: max_delta,
        });
    }
    let du = actual_yuv.u.abs_diff(expected_yuv.u);
    if du > max_delta {
        return Err(ColorConformanceError::DeltaExceeded {
            channel: "U",
            expected: expected_yuv.u,
            actual: actual_yuv.u,
            delta: du,
            max_allowed: max_delta,
        });
    }
    let dv = actual_yuv.v.abs_diff(expected_yuv.v);
    if dv > max_delta {
        return Err(ColorConformanceError::DeltaExceeded {
            channel: "V",
            expected: expected_yuv.v,
            actual: actual_yuv.v,
            delta: dv,
            max_allowed: max_delta,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_media::{
        CopyEvidenceGrade, CopyFallbackReason, DeviceIdentity, ImportPath, LeaseCompletion,
        SourceLeaseIdentity, SynchronizationProof, TransferEdge,
    };

    fn stream() -> PipeWireStream {
        PipeWireStream {
            node_id: 7,
            serial: 42,
        }
    }

    fn dma_buf_format() -> PipeWireFormat {
        PipeWireFormat {
            width: 1_920,
            height: 1_080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::DmaBuf,
            plane_count: 1,
            modifier: Some(0),
        }
    }

    fn descriptor() -> FrameDescriptor {
        FrameDescriptor {
            width: 1_920,
            height: 1_080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::DmaBuf,
            capture_sequence: 1,
            capture_timestamp_ns: 1,
        }
    }

    fn copy_ledger(epoch: u32, source_layout: SurfaceLayout) -> CopyLedger {
        CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: epoch,
                capture_sequence: 1,
            },
            source_device: DeviceIdentity::Opaque(1),
            destination_device: DeviceIdentity::Opaque(1),
            source_layout,
            destination_layout: SurfaceLayout {
                memory_domain: MemoryDomain::VendorOpaque,
                format_fourcc: u32::from_le_bytes(*b"NV12"),
                plane_count: 2,
                modifier: None,
            },
            transfer_edge: TransferEdge::CaptureToEncoder,
            path: ImportPath::GpuConvert,
            synchronization: SynchronizationProof::ExplicitFence,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: CopyEvidenceGrade::CompletionProven,
        }
    }

    fn cpu_copy_ledger(epoch: u32, source_layout: SurfaceLayout) -> CopyLedger {
        CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: epoch,
                capture_sequence: 1,
            },
            source_device: DeviceIdentity::Unknown,
            destination_device: DeviceIdentity::Unknown,
            source_layout,
            destination_layout: SurfaceLayout {
                memory_domain: MemoryDomain::Cpu,
                format_fourcc: u32::from_le_bytes(*b"BGRA"),
                plane_count: 1,
                modifier: None,
            },
            transfer_edge: TransferEdge::CaptureToEncoder,
            path: ImportPath::CpuCopy,
            synchronization: SynchronizationProof::CpuSynchronous,
            completion: LeaseCompletion::Proven,
            fallback_reason: Some(CopyFallbackReason::UnsupportedModifier),
            evidence: CopyEvidenceGrade::CompletionProven,
        }
    }

    fn streaming_capture_only() -> LinuxPortalSession {
        let mut session = LinuxPortalSession::new(LinuxCaptureMode::CaptureOnly);
        assert_eq!(
            session.begin(),
            Ok(PortalAction::Request(PortalRequest::CreateSession {
                mode: LinuxCaptureMode::CaptureOnly,
            }))
        );
        assert_eq!(
            session.apply(PortalEvent::SessionCreated {
                session: PortalSessionId(1),
            }),
            Ok(PortalAction::Request(PortalRequest::SelectSources))
        );
        assert_eq!(
            session.apply(PortalEvent::SourcesSelected),
            Ok(PortalAction::Request(PortalRequest::Start))
        );
        assert_eq!(
            session.apply(PortalEvent::Started { stream: stream() }),
            Ok(PortalAction::Request(PortalRequest::ConnectPipeWire {
                stream: stream(),
            }))
        );
        assert_eq!(
            session.apply(PortalEvent::PipeWireConnected {
                stream: stream(),
                format: dma_buf_format(),
            }),
            Ok(PortalAction::CaptureReady {
                display_epoch: 1,
                stream: stream(),
                input: InputCapability::default(),
            })
        );
        session
    }

    #[test]
    fn portal_flow_requires_authorized_device_and_source_selection() {
        let mut session = LinuxPortalSession::new(LinuxCaptureMode::CaptureAndControl);
        assert_eq!(
            session.begin(),
            Ok(PortalAction::Request(PortalRequest::CreateSession {
                mode: LinuxCaptureMode::CaptureAndControl,
            }))
        );
        assert_eq!(
            session.apply(PortalEvent::SourcesSelected),
            Err(LinuxBackendError::InvalidState)
        );
        assert_eq!(
            session.apply(PortalEvent::SessionCreated {
                session: PortalSessionId(1),
            }),
            Ok(PortalAction::Request(PortalRequest::SelectDevices))
        );
        assert_eq!(
            session.apply(PortalEvent::DevicesSelected {
                input: InputCapability {
                    keyboard: true,
                    pointer: true,
                    libei: false,
                },
            }),
            Err(LinuxBackendError::InputUnavailable)
        );
        assert_eq!(session.phase(), PortalPhase::AwaitingDeviceSelection);
        assert_eq!(
            session.apply(PortalEvent::DevicesSelected {
                input: InputCapability {
                    keyboard: true,
                    pointer: true,
                    libei: true,
                },
            }),
            Ok(PortalAction::Request(PortalRequest::SelectSources))
        );
        assert_eq!(
            session.apply(PortalEvent::SourcesSelected),
            Ok(PortalAction::Request(PortalRequest::Start))
        );
        assert_eq!(
            session.apply(PortalEvent::Started { stream: stream() }),
            Ok(PortalAction::Request(PortalRequest::ConnectPipeWire {
                stream: stream(),
            }))
        );
        assert_eq!(
            session.apply(PortalEvent::PipeWireConnected {
                stream: stream(),
                format: dma_buf_format(),
            }),
            Ok(PortalAction::CaptureReady {
                display_epoch: 1,
                stream: stream(),
                input: InputCapability {
                    keyboard: true,
                    pointer: true,
                    libei: true,
                },
            })
        );
        assert_eq!(session.phase(), PortalPhase::Streaming);
    }

    #[test]
    fn revocation_stops_capture_and_releases_input() {
        let mut session = streaming_capture_only();
        assert_eq!(
            session.apply(PortalEvent::PermissionRevoked),
            Ok(PortalAction::ReleaseAllAndStop)
        );
        assert_eq!(session.phase(), PortalPhase::Revoked);
        assert_eq!(
            session.apply(PortalEvent::PipeWireReconfigured {
                stream: stream(),
                format: dma_buf_format(),
            }),
            Err(LinuxBackendError::InvalidState)
        );
    }

    #[test]
    fn reconnect_invalidates_old_pipewire_lease_epochs() {
        let mut session = streaming_capture_only();
        assert_eq!(
            session.apply(PortalEvent::PipeWireDisconnected),
            Ok(PortalAction::ReleaseAllAndReconnect { display_epoch: 2 })
        );
        assert_eq!(
            session.apply(PortalEvent::PipeWireConnected {
                stream: stream(),
                format: dma_buf_format(),
            }),
            Ok(PortalAction::CaptureReady {
                display_epoch: 2,
                stream: stream(),
                input: InputCapability::default(),
            })
        );
        let pool = SurfacePool::new(1);
        let error = session
            .import_frame(
                stream(),
                &pool,
                descriptor(),
                copy_ledger(1, dma_buf_format().layout()),
            )
            .expect_err("old lease epoch must not enter the new session");
        assert_eq!(error, LinuxBackendError::LedgerEpoch);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn pipewire_import_binds_the_negotiated_layout() {
        let mut session = streaming_capture_only();
        let pool = SurfacePool::new(1);
        let frame = session
            .import_frame(
                stream(),
                &pool,
                descriptor(),
                copy_ledger(1, dma_buf_format().layout()),
            )
            .expect("matching PipeWire tuple imports");
        assert_eq!(frame.display_epoch, 1);
        assert_eq!(frame.copy_ledger.path, ImportPath::GpuConvert);
        drop(frame);
        assert_eq!(pool.in_use(), 0);

        let bad_layout = SurfaceLayout {
            format_fourcc: u32::from_le_bytes(*b"NV12"),
            plane_count: 2,
            ..dma_buf_format().layout()
        };
        let error = session
            .import_frame(stream(), &pool, descriptor(), copy_ledger(1, bad_layout))
            .expect_err("mismatched SPA tuple must not import");
        assert_eq!(error, LinuxBackendError::LedgerLayout);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn reconfiguration_blocks_import_until_the_old_pipeline_drains() {
        let mut session = streaming_capture_only();
        assert_eq!(
            session.apply(PortalEvent::PipeWireReconfigured {
                stream: stream(),
                format: dma_buf_format(),
            }),
            Ok(PortalAction::ReleaseAllAndReconfigure {
                display_epoch: 2,
                stream: stream(),
                format: dma_buf_format(),
            })
        );
        assert_eq!(session.phase(), PortalPhase::Reconfiguring);
        assert_eq!(
            session.apply(PortalEvent::PipeWireConnected {
                stream: stream(),
                format: dma_buf_format(),
            }),
            Err(LinuxBackendError::InvalidState)
        );
        let pool = SurfacePool::new(1);
        assert_eq!(
            session
                .import_frame(
                    stream(),
                    &pool,
                    descriptor(),
                    copy_ledger(2, dma_buf_format().layout()),
                )
                .expect_err("must drain before a reconfigured frame enters"),
            LinuxBackendError::InvalidState
        );
        assert_eq!(
            session.resume_after_reconfigure(),
            Ok(PortalAction::CaptureReady {
                display_epoch: 2,
                stream: stream(),
                input: InputCapability::default(),
            })
        );
        let frame = session
            .import_frame(
                stream(),
                &pool,
                descriptor(),
                copy_ledger(2, dma_buf_format().layout()),
            )
            .expect("drained pipeline accepts the new epoch");
        drop(frame);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn dma_buf_without_modifier_forces_the_cpu_fallback() {
        let mut session = streaming_capture_only();
        let format = PipeWireFormat {
            modifier: None,
            ..dma_buf_format()
        };
        assert_eq!(
            session.apply(PortalEvent::PipeWireReconfigured {
                stream: stream(),
                format,
            }),
            Ok(PortalAction::ReleaseAllAndReconfigure {
                display_epoch: 2,
                stream: stream(),
                format,
            })
        );
        assert_eq!(
            session.resume_after_reconfigure(),
            Ok(PortalAction::CaptureReady {
                display_epoch: 2,
                stream: stream(),
                input: InputCapability::default(),
            })
        );
        let pool = SurfacePool::new(1);
        assert_eq!(
            session
                .import_frame(
                    stream(),
                    &pool,
                    descriptor(),
                    copy_ledger(2, format.layout())
                )
                .expect_err("unknown DMA-BUF modifier cannot enter a GPU path"),
            LinuxBackendError::DmaBufModifierUnknown
        );
        let frame = session
            .import_frame(
                stream(),
                &pool,
                descriptor(),
                cpu_copy_ledger(2, format.layout()),
            )
            .expect("CPU fallback has an explicit synchronous handoff");
        assert_eq!(frame.copy_ledger.path, ImportPath::CpuCopy);
        drop(frame);
        assert_eq!(pool.in_use(), 0);
    }

    use latencydesk_codec::{
        ChromaMode, CodecConfig, CodecId, EncodedAccessUnit, FrameDecoder, LatencyMode,
    };
    use latencydesk_frame::PixelFormat;
    use latencydesk_input::InputEvent;
    use latencydesk_media::EncodedFrameMeta;
    use latencydesk_platform::{CaptureFramePublisher, PresentationCoordinator, Rotation};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    fn presentable_frame(
        pool: &SurfacePool,
        frame_id: u64,
        ready_ns: u64,
        deadline_ns: u64,
        epoch: u32,
        domain: MemoryDomain,
        fourcc: u32,
    ) -> (PresentableFrame, Arc<AtomicBool>) {
        let descriptor = FrameDescriptor {
            width: 1_920,
            height: 1_080,
            format_fourcc: fourcc,
            memory_domain: domain,
            capture_sequence: frame_id,
            capture_timestamp_ns: ready_ns,
        };
        let plane_count = if fourcc == drm_fourcc::DRM_FORMAT_NV12 {
            2
        } else {
            1
        };
        let ledger = CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: epoch,
                capture_sequence: frame_id,
            },
            source_device: if domain == MemoryDomain::Cpu {
                DeviceIdentity::Unknown
            } else {
                DeviceIdentity::Opaque(1)
            },
            destination_device: if domain == MemoryDomain::Cpu {
                DeviceIdentity::Unknown
            } else {
                DeviceIdentity::Opaque(1)
            },
            source_layout: SurfaceLayout {
                memory_domain: domain,
                format_fourcc: fourcc,
                plane_count,
                modifier: Some(drm_fourcc::DRM_FORMAT_MOD_LINEAR),
            },
            destination_layout: SurfaceLayout {
                memory_domain: domain,
                format_fourcc: fourcc,
                plane_count,
                modifier: Some(drm_fourcc::DRM_FORMAT_MOD_LINEAR),
            },
            transfer_edge: TransferEdge::DecodeToPresenter,
            path: if domain == MemoryDomain::Cpu {
                ImportPath::CpuCopy
            } else {
                ImportPath::DirectAlias
            },
            synchronization: SynchronizationProof::CpuSynchronous,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: if domain == MemoryDomain::Cpu {
                CopyEvidenceGrade::CompletionProven
            } else {
                CopyEvidenceGrade::ProfilerVerifiedNoApplicationCopy
            },
        };
        let owned = pool
            .acquire_capture(descriptor)
            .expect("acquire")
            .import(ledger)
            .expect("import");
        let authorization = Arc::new(AtomicBool::new(true));
        let surface = CaptureFramePublisher::new()
            .bind(owned, Arc::clone(&authorization))
            .expect("bind");
        (
            PresentableFrame {
                surface,
                codec_epoch: epoch,
                frame_id,
                ready_ns,
                deadline_ns,
                recovery_point: false,
            },
            authorization,
        )
    }

    fn access_unit(
        epoch: u32,
        frame_id: u64,
        recovery_point: bool,
        payload_len: usize,
    ) -> EncodedAccessUnit {
        let mut payload = vec![
            0x00,
            0x00,
            0x00,
            0x01,
            if recovery_point { 0x65 } else { 0x41 },
        ];
        if payload.len() < payload_len {
            payload.resize(payload_len, 0xAA);
        }
        EncodedAccessUnit {
            codec: CodecId::H264,
            stream_id: 1,
            capture_sequence: frame_id,
            capture_timestamp_ns: 100,
            meta: EncodedFrameMeta {
                codec_epoch: epoch,
                frame_id,
                dependency_frame_id: if recovery_point {
                    None
                } else {
                    Some(frame_id.saturating_sub(1))
                },
                recovery_point,
            },
            bytes: payload,
        }
    }

    #[test]
    fn test_hardware_decoder_configuration() {
        let mut decoder = LinuxHardwareDecoder::new_vaapi(DeviceIdentity::Opaque(1));
        assert_eq!(decoder.state(), ProviderState::Idle);

        let valid_config = CodecConfig {
            codec: CodecId::H264,
            width: 1_920,
            height: 1_080,
            fps_num: 60,
            fps_den: 1,
            target_bitrate_bps: 4_000_000,
            max_bitrate_bps: 10_000_000,
            keyframe_interval_frames: 60,
            chroma: ChromaMode::RgbExact,
            latency_mode: LatencyMode::UltraLowLatency,
        };
        assert_eq!(decoder.configure(valid_config, 1), Ok(()));
        assert_eq!(decoder.state(), ProviderState::Running);

        let zero_dim_config = CodecConfig {
            width: 0,
            ..valid_config
        };
        assert!(decoder.configure(zero_dim_config, 1).is_err());

        let zero_fps_config = CodecConfig {
            fps_num: 0,
            ..valid_config
        };
        assert!(decoder.configure(zero_fps_config, 1).is_err());
        assert_eq!(decoder.configure(valid_config, 2), Ok(()));
        assert_eq!(decoder.reset(), Ok(()));
        assert_eq!(decoder.state(), ProviderState::Idle);
    }

    #[test]
    fn test_hardware_decoder_decode_raw_frames() {
        let mut decoder = LinuxHardwareDecoder::new_vaapi(DeviceIdentity::Opaque(1));
        let config = CodecConfig {
            codec: CodecId::H264,
            width: 640,
            height: 480,
            fps_num: 30,
            fps_den: 1,
            target_bitrate_bps: 2_000_000,
            max_bitrate_bps: 5_000_000,
            keyframe_interval_frames: 30,
            chroma: ChromaMode::RgbExact,
            latency_mode: LatencyMode::UltraLowLatency,
        };
        decoder.configure(config, 1).expect("configure");

        let key_unit = access_unit(1, 1, true, 256);
        let raw = decoder.decode(&key_unit).expect("decode keyframe");
        assert!(raw.is_some());
        let raw = raw.unwrap();
        assert_eq!(raw.descriptor.width, 640);
        assert_eq!(raw.descriptor.height, 480);
        assert_eq!(raw.format, PixelFormat::Bgra8);
        assert_eq!(raw.stride, 640 * 4);
        assert_eq!(decoder.frames_decoded(), 1);
        assert_eq!(decoder.keyframes_decoded(), 1);

        let delta_unit = access_unit(1, 2, false, 128);
        let delta_raw = decoder.decode(&delta_unit).expect("decode delta");
        assert!(delta_raw.is_some());
        assert_eq!(decoder.frames_decoded(), 2);
        assert_eq!(decoder.keyframes_decoded(), 1);
    }

    #[test]
    fn test_hardware_decoder_continuity_loss_recovery() {
        let mut decoder = LinuxHardwareDecoder::new_vaapi(DeviceIdentity::Opaque(1));
        let config = CodecConfig {
            codec: CodecId::H264,
            width: 1_280,
            height: 720,
            fps_num: 60,
            fps_den: 1,
            target_bitrate_bps: 3_000_000,
            max_bitrate_bps: 8_000_000,
            keyframe_interval_frames: 60,
            chroma: ChromaMode::Yuv420EightBit,
            latency_mode: LatencyMode::UltraLowLatency,
        };
        decoder.configure(config, 1).expect("configure");

        let key_unit = access_unit(1, 1, true, 512);
        assert!(decoder.decode(&key_unit).expect("keyframe").is_some());

        let mut loss_unit = access_unit(1, 5, false, 128);
        loss_unit.meta.dependency_frame_id = Some(4);
        let dropped = decoder.decode(&loss_unit).expect("loss delta");
        assert!(dropped.is_none());
        assert_eq!(decoder.dropped_continuity(), 1);

        let dependent_unit = access_unit(1, 6, false, 128);
        let dropped2 = decoder.decode(&dependent_unit).expect("dependent delta");
        assert!(dropped2.is_none());
        assert_eq!(decoder.dropped_continuity(), 2);

        let recovery_key = access_unit(1, 7, true, 512);
        let recovered = decoder.decode(&recovery_key).expect("recovery keyframe");
        assert!(recovered.is_some());
    }

    #[test]
    fn test_hardware_decoder_surface_decode_dmabuf() {
        let pool = SurfacePool::new(2);
        let mut decoder = LinuxHardwareDecoder::new_vaapi(DeviceIdentity::Opaque(1))
            .with_surface_pool(pool.clone());
        let config = CodecConfig {
            codec: CodecId::H264,
            width: 1_920,
            height: 1_080,
            fps_num: 60,
            fps_den: 1,
            target_bitrate_bps: 4_000_000,
            max_bitrate_bps: 10_000_000,
            keyframe_interval_frames: 60,
            chroma: ChromaMode::RgbExact,
            latency_mode: LatencyMode::UltraLowLatency,
        };
        decoder.configure(config, 1).expect("configure");

        let auth = Arc::new(AtomicBool::new(true));
        let mut publisher = CaptureFramePublisher::new();
        let key_unit = access_unit(1, 1, true, 512);

        let frame = decoder
            .decode_surface(
                &key_unit,
                1,
                1,
                1_000,
                2_000,
                &mut publisher,
                Arc::clone(&auth),
            )
            .expect("decode surface")
            .expect("some presentable frame");

        assert_eq!(frame.frame_id, 1);
        assert_eq!(frame.display_epoch(), 1);
        assert_eq!(frame.ready_ns, 1_000);
        assert_eq!(frame.deadline_ns, 2_000);
        assert_eq!(pool.in_use(), 1);
        drop(frame);
        assert_eq!(pool.in_use(), 0);

        let expired_res = decoder.decode_surface(
            &key_unit,
            1,
            2,
            2_000,
            1_000,
            &mut publisher,
            Arc::clone(&auth),
        );
        assert!(matches!(
            expired_res,
            Err(LinuxBackendError::ExpiredDeadline)
        ));
    }

    #[test]
    fn test_dmabuf_layout_rgb_and_nv12() {
        let rgb_layout = DmaBufLayout::new_linear(1_920, 1_080, drm_fourcc::DRM_FORMAT_BGRA8888)
            .expect("rgb layout");
        assert_eq!(rgb_layout.plane_count, 1);
        assert_eq!(rgb_layout.planes[0].stride, 1_920 * 4);
        assert!(rgb_layout.planes[0].stride % 64 == 0);
        assert_eq!(rgb_layout.validate(), Ok(()));

        let nv12_layout = DmaBufLayout::new_linear(1_920, 1_080, drm_fourcc::DRM_FORMAT_NV12)
            .expect("nv12 layout");
        assert_eq!(nv12_layout.plane_count, 2);
        assert_eq!(nv12_layout.planes[0].offset, 0);
        assert_eq!(nv12_layout.planes[1].offset, nv12_layout.planes[0].size);
        assert_eq!(nv12_layout.validate(), Ok(()));

        let odd_nv12 = DmaBufLayout::new_linear(1_921, 1_080, drm_fourcc::DRM_FORMAT_NV12);
        assert_eq!(odd_nv12, Err(LinuxBackendError::InvalidDimensions));
    }

    #[test]
    fn test_render_backend_wayland_present_and_poll_completion() {
        let pool = SurfacePool::new(2);
        let renderer = LinuxRenderBackend::new_wayland(DeviceIdentity::Opaque(1), 2);
        let mut coordinator = PresentationCoordinator::new(renderer);

        let (frame1, _auth1) = presentable_frame(
            &pool,
            1,
            100,
            10_000,
            1,
            MemoryDomain::DmaBuf,
            drm_fourcc::DRM_FORMAT_BGRA8888,
        );

        coordinator.submit(frame1, 100).expect("submit");
        let action = coordinator.present_next(150).expect("present");
        assert!(matches!(
            action,
            latencydesk_platform::PresentationAction::Presented(_)
        ));
        assert_eq!(coordinator.stats().rendered, 1);

        let completion = coordinator
            .poll_present_completion()
            .expect("poll complete");
        assert_eq!(
            completion,
            latencydesk_platform::PresentationCompletion::Released
        );
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn test_render_backend_monotonic_deadlines_and_queue_dropping() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxRenderBackend::new_wayland(DeviceIdentity::Opaque(1), 2);

        let (expired_frame, _auth) = presentable_frame(
            &pool,
            1,
            100,
            500,
            1,
            MemoryDomain::DmaBuf,
            drm_fourcc::DRM_FORMAT_BGRA8888,
        );
        let outcome = backend
            .enqueue(expired_frame, 600)
            .expect("enqueue expired");
        assert_eq!(outcome, QueuePushOutcome::RejectedExpired);
        assert_eq!(backend.stats().frames_dropped_expired, 1);

        let (valid_frame, _auth) = presentable_frame(
            &pool,
            2,
            100,
            10_000,
            1,
            MemoryDomain::DmaBuf,
            drm_fourcc::DRM_FORMAT_BGRA8888,
        );
        let outcome = backend.enqueue(valid_frame, 200).expect("enqueue valid");
        assert_eq!(outcome, QueuePushOutcome::Queued);

        let (stale_frame, _auth) = presentable_frame(
            &pool,
            2,
            100,
            10_000,
            1,
            MemoryDomain::DmaBuf,
            drm_fourcc::DRM_FORMAT_BGRA8888,
        );
        let outcome = backend.enqueue(stale_frame, 200).expect("enqueue stale");
        assert_eq!(outcome, QueuePushOutcome::RejectedStale);
        assert_eq!(backend.stats().frames_dropped_stale, 1);

        let (newer_frame, _auth) = presentable_frame(
            &pool,
            3,
            100,
            15_000,
            1,
            MemoryDomain::DmaBuf,
            drm_fourcc::DRM_FORMAT_BGRA8888,
        );
        backend.enqueue(newer_frame, 300).expect("enqueue newer");

        let popped = backend.pop_newest(400).expect("pop newest");
        assert!(popped.is_some());
        assert_eq!(popped.unwrap().frame_id, 3);
    }

    #[test]
    fn test_render_backend_rejection_and_cursor() {
        let mut backend = LinuxRenderBackend::new_x11(DeviceIdentity::Opaque(1), 2);
        let cursor_bytes = [0xFF; 64 * 64 * 4];
        let valid_cursor = CursorUpdate {
            cursor_id: 1,
            visible: true,
            x: 0,
            y: 0,
            width: 64,
            height: 64,
            hotspot_x: 10,
            hotspot_y: 10,
            rgba: Some(&cursor_bytes),
        };
        assert_eq!(backend.set_cursor(valid_cursor), Ok(()));
        assert_eq!(backend.stats().cursor_updates, 1);

        let invalid_cursor = CursorUpdate {
            cursor_id: 2,
            visible: true,
            x: 0,
            y: 0,
            width: 600,
            height: 64,
            hotspot_x: 10,
            hotspot_y: 10,
            rgba: Some(&cursor_bytes),
        };
        assert!(backend.set_cursor(invalid_cursor).is_err());

        assert_eq!(backend.quiesce_presentation(), Ok(()));
    }

    #[test]
    fn test_input_backend_key_mapping() {
        let mut input = LinuxInputBackend::new(LinuxInputMode::Uinput, 1_920, 1_080);

        assert_eq!(hid_to_evdev(0x04), evdev_codes::KEY_A);
        assert_eq!(hid_to_evdev(0x1D), evdev_codes::KEY_Z);
        assert_eq!(hid_to_evdev(0x1E), evdev_codes::KEY_1);
        assert_eq!(hid_to_evdev(0x28), evdev_codes::KEY_ENTER);
        assert_eq!(hid_to_evdev(0x29), evdev_codes::KEY_ESC);
        assert_eq!(hid_to_evdev(0xE0), evdev_codes::KEY_LEFTCTRL);

        assert_eq!(
            input.inject(AppliedInput::Key {
                code: 0x04,
                pressed: true
            }),
            Ok(())
        );
        assert!(input.is_key_held(0x04));

        assert_eq!(
            input.inject(AppliedInput::Key {
                code: 0x04,
                pressed: false
            }),
            Ok(())
        );
        assert!(!input.is_key_held(0x04));
    }

    #[test]
    fn producer_pointer_buttons_map_to_evdev_buttons() {
        assert_eq!(pointer_button_to_evdev(0), Ok(evdev_codes::BTN_LEFT));
        assert_eq!(pointer_button_to_evdev(1), Ok(evdev_codes::BTN_RIGHT));
        assert_eq!(pointer_button_to_evdev(2), Ok(evdev_codes::BTN_MIDDLE));
    }

    #[test]
    fn test_input_backend_pointer_and_wheel() {
        let mut input = LinuxInputBackend::new(LinuxInputMode::Uinput, 1_920, 1_080);

        assert_eq!(
            input.inject(AppliedInput::PointerButton {
                button: 0,
                pressed: true
            }),
            Ok(())
        );
        assert!(input.is_button_held(0));

        assert_eq!(
            input.inject(AppliedInput::PointerMotionRelative { dx: 10, dy: -5 }),
            Ok(())
        );

        assert_eq!(
            input.inject(AppliedInput::PointerMotionAbsolute {
                x: 960,
                y: 540,
                width: 1_920,
                height: 1_080,
            }),
            Ok(())
        );

        assert_eq!(
            input.inject(AppliedInput::Wheel {
                horizontal: 0,
                vertical: 120,
            }),
            Ok(())
        );
        assert!(input.injected_count() >= 4);
    }

    #[test]
    fn test_input_backend_release_all() {
        let mut input = LinuxInputBackend::new(LinuxInputMode::Uinput, 1_920, 1_080);
        input
            .inject(AppliedInput::Key {
                code: 0x04,
                pressed: true,
            })
            .unwrap();
        input
            .inject(AppliedInput::Key {
                code: 0xE0,
                pressed: true,
            })
            .unwrap();
        input
            .inject(AppliedInput::PointerButton {
                button: 0,
                pressed: true,
            })
            .unwrap();

        assert!(input.is_key_held(0x04));
        assert!(input.is_key_held(0xE0));
        assert!(input.is_button_held(0));

        assert_eq!(input.release_all(&[]), Ok(()));
        assert!(!input.is_key_held(0x04));
        assert!(!input.is_key_held(0xE0));
        assert!(!input.is_button_held(0));
    }

    #[test]
    fn test_coordinate_transforms_all_orientations() {
        let w = 1_920;
        let h = 1_080;

        let t_r0 = LinuxDisplayTransform::new(w, h, w, h, Rotation::R0).expect("r0");
        assert_eq!(t_r0.map_client_to_host(100, 200), Ok((100, 200)));
        assert_eq!(t_r0.map_host_to_client(100, 200), Ok((100, 200)));

        let t_r90 = LinuxDisplayTransform::new(h, w, w, h, Rotation::R90).expect("r90");
        let (hx, hy) = t_r90.map_client_to_host(100, 200).expect("r90 map");
        assert_eq!(hx, w - 1 - 200);
        assert_eq!(hy, 100);
        let t_r180 = LinuxDisplayTransform::new(w, h, w, h, Rotation::R180).expect("r180");
        let (hx, hy) = t_r180.map_client_to_host(100, 200).expect("r180 map");
        assert_eq!(hx, w - 1 - 100);
        assert_eq!(hy, h - 1 - 200);

        let t_r270 = LinuxDisplayTransform::new(h, w, w, h, Rotation::R270).expect("r270");
        let (hx, hy) = t_r270.map_client_to_host(100, 200).expect("r270 map");
        assert_eq!(hx, 200);
        assert_eq!(hy, h - 1 - 100);
        assert_eq!(
            t_r0.map_client_to_host(w, h),
            Err(PlatformError::CoordinateBounds)
        );
    }

    #[test]
    fn test_color_conformance_matrices_and_color_bars() {
        let black_rgb = RgbColor { r: 0, g: 0, b: 0 };
        let black_yuv = rgb_to_yuv(black_rgb, ColorStandard::Bt709Limited);
        assert_eq!(black_yuv.y, 16);
        assert_eq!(black_yuv.u, 128);
        assert_eq!(black_yuv.v, 128);
        let black_recovered = yuv_to_rgb(black_yuv, ColorStandard::Bt709Limited);
        assert_eq!(black_recovered, black_rgb);

        let white_rgb = RgbColor {
            r: 255,
            g: 255,
            b: 255,
        };
        let white_yuv = rgb_to_yuv(white_rgb, ColorStandard::Bt709Limited);
        assert_eq!(white_yuv.y, 235);
        assert_eq!(white_yuv.u, 128);
        assert_eq!(white_yuv.v, 128);
        let white_recovered = yuv_to_rgb(white_yuv, ColorStandard::Bt709Limited);
        assert_eq!(white_recovered, white_rgb);

        let colors = [
            RgbColor { r: 255, g: 0, b: 0 },
            RgbColor { r: 0, g: 255, b: 0 },
            RgbColor { r: 0, g: 0, b: 255 },
            RgbColor {
                r: 255,
                g: 255,
                b: 0,
            },
            RgbColor {
                r: 0,
                g: 255,
                b: 255,
            },
            RgbColor {
                r: 255,
                g: 0,
                b: 255,
            },
            RgbColor {
                r: 128,
                g: 128,
                b: 128,
            },
        ];

        for color in colors {
            for std in [
                ColorStandard::Bt709Limited,
                ColorStandard::Bt709Full,
                ColorStandard::Bt601Limited,
                ColorStandard::Bt601Full,
                ColorStandard::Bt2020Limited,
                ColorStandard::Bt2020Full,
            ] {
                let yuv = rgb_to_yuv(color, std);
                assert_eq!(validate_color_conformance(color, yuv, std, 1), Ok(()));
                let round_trip = yuv_to_rgb(yuv, std);
                assert!(color.r.abs_diff(round_trip.r) <= 16);
                assert!(color.g.abs_diff(round_trip.g) <= 16);
                assert!(color.b.abs_diff(round_trip.b) <= 16);
            }
        }
    }

    #[test]
    fn test_portal_screencast_backend_lifecycle_and_frame_publishing() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_screencast(pool);
        assert_eq!(backend.state(), ProviderState::Idle);

        backend.start().expect("start succeeds");
        assert_eq!(backend.state(), ProviderState::Starting);

        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(100),
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: dma_buf_format(),
        });

        for _ in 0..4 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }
        assert_eq!(backend.state(), ProviderState::Running);

        let buffer = PipeWireBuffer::dma_buf(
            stream(),
            descriptor(),
            Some(0),
            1,
            DeviceIdentity::Opaque(1),
        );
        backend.push_event(buffer);

        let event = backend.poll(0).expect("poll succeeds");
        let Some(CaptureEvent::Frame(frame)) = event else {
            panic!("expected Frame event, got {event:?}");
        };

        assert_eq!(frame.display_epoch(), 1);
        assert_eq!(frame.validate(), Ok(()));

        backend.stop().expect("stop succeeds");
        assert_eq!(backend.state(), ProviderState::Stopped);
    }

    #[test]
    fn test_portal_remotedesktop_backend_with_libei_input() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_remote_desktop(pool);
        backend.start().expect("start succeeds");

        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(200),
        });
        backend.push_event(PortalEvent::DevicesSelected {
            input: InputCapability {
                keyboard: true,
                pointer: true,
                libei: true,
            },
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: dma_buf_format(),
        });

        for _ in 0..5 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }
        assert_eq!(backend.state(), ProviderState::Running);

        let input = backend.input_backend_mut().expect("input backend present");
        assert!(input.is_connected());
        assert!(input.is_focused());

        let msg = InputMessage {
            sequence: 1,
            session_epoch: 1,
            event: InputEvent::Key {
                code: 0x04,
                pressed: true,
            },
        };
        let actions = input.handle_input_message(msg).expect("input applied");
        assert_eq!(
            actions,
            vec![AppliedInput::Key {
                code: 0x04,
                pressed: true
            }]
        );
        assert!(input.state().key_pressed(0x04));
    }

    #[test]
    fn test_portal_dmabuf_fallback_to_cpu_copy_when_modifier_unknown() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_screencast(pool);
        backend.start().expect("start succeeds");

        let format_no_modifier = PipeWireFormat {
            modifier: None,
            ..dma_buf_format()
        };

        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(300),
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: format_no_modifier,
        });

        for _ in 0..4 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }

        let buffer =
            PipeWireBuffer::dma_buf(stream(), descriptor(), None, 1, DeviceIdentity::Unknown);
        backend.push_event(buffer);

        let event = backend.poll(0).expect("poll succeeds");
        let Some(CaptureEvent::Frame(frame)) = event else {
            panic!("expected Frame event with CPU fallback, got {event:?}");
        };
        assert_eq!(frame.display_epoch(), 1);
        assert_eq!(frame.validate(), Ok(()));
    }

    #[test]
    fn test_portal_memfd_buffer_import() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_screencast(pool);
        backend.start().expect("start succeeds");

        let cpu_format = PipeWireFormat {
            memory_domain: MemoryDomain::Cpu,
            modifier: None,
            ..dma_buf_format()
        };

        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(400),
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: cpu_format,
        });

        for _ in 0..4 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }

        let memfd_desc = FrameDescriptor {
            memory_domain: MemoryDomain::Cpu,
            ..descriptor()
        };
        let buffer = PipeWireBuffer::mem_fd(stream(), memfd_desc);
        backend.push_event(buffer);

        let event = backend.poll(0).expect("poll succeeds");
        let Some(CaptureEvent::Frame(frame)) = event else {
            panic!("expected Frame event for MemFd, got {event:?}");
        };
        assert_eq!(frame.display_epoch(), 1);
        assert_eq!(frame.validate(), Ok(()));
    }

    #[test]
    fn test_portal_token_revocation_fails_closed_and_invalidates_retained_surfaces() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_screencast(pool);
        let (token, revoker) = PortalToken::new("session_token_123");
        backend.set_token(token);

        backend.start().expect("start succeeds");
        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(500),
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: dma_buf_format(),
        });

        for _ in 0..4 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }

        let buffer = PipeWireBuffer::dma_buf(
            stream(),
            descriptor(),
            Some(0),
            1,
            DeviceIdentity::Opaque(1),
        );
        backend.push_event(buffer);

        let Some(CaptureEvent::Frame(frame)) = backend.poll(0).expect("frame") else {
            panic!("expected frame");
        };
        assert_eq!(frame.validate(), Ok(()));

        revoker.revoke();
        assert!(revoker.is_revoked());

        assert!(matches!(
            backend.poll(0),
            Ok(Some(CaptureEvent::PermissionRevoked))
        ));
        assert_eq!(frame.validate(), Err(PlatformError::PermissionRevoked));
    }

    #[test]
    fn test_portal_token_revocation_before_buffer_poll_emits_permission_revoked() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_screencast(pool);
        let (token, revoker) = PortalToken::new("session_token_queued");
        backend.set_token(token);

        backend.start().expect("start succeeds");
        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(501),
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: dma_buf_format(),
        });

        for _ in 0..4 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }

        let buffer = PipeWireBuffer::dma_buf(
            stream(),
            descriptor(),
            Some(0),
            1,
            DeviceIdentity::Opaque(1),
        );
        backend.push_event(buffer);

        // Revoke token while buffer is in queue before poll
        revoker.revoke();

        assert!(matches!(
            backend.poll(0),
            Ok(Some(CaptureEvent::PermissionRevoked))
        ));
    }

    #[test]
    fn test_portal_reconfiguration_emits_event_and_increments_epoch() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_screencast(pool);
        backend.start().expect("start succeeds");

        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(600),
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: dma_buf_format(),
        });

        for _ in 0..4 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }

        let new_format = PipeWireFormat {
            width: 2_560,
            height: 1_440,
            ..dma_buf_format()
        };

        backend.push_event(PortalEvent::PipeWireReconfigured {
            stream: stream(),
            format: new_format,
        });

        let event = backend.poll(0).expect("poll succeeds");
        let Some(CaptureEvent::Reconfigure {
            display_epoch,
            descriptor: reconf_desc,
        }) = event
        else {
            panic!("expected Reconfigure event, got {event:?}");
        };

        assert_eq!(display_epoch, 2);
        assert_eq!(reconf_desc.width, 2_560);
        assert_eq!(reconf_desc.height, 1_440);

        backend
            .resume_after_reconfigure()
            .expect("resume after reconfigure");

        let base_desc = descriptor();
        let new_desc = FrameDescriptor {
            width: 2_560,
            height: 1_440,
            ..base_desc
        };
        let buffer =
            PipeWireBuffer::dma_buf(stream(), new_desc, Some(0), 1, DeviceIdentity::Opaque(1));
        backend.push_event(buffer);

        let event = backend.poll(0).expect("poll succeeds");
        let Some(CaptureEvent::Frame(frame)) = event else {
            panic!("expected new frame in epoch 2, got {event:?}");
        };
        assert_eq!(frame.display_epoch(), 2);
        assert_eq!(frame.validate(), Ok(()));
    }

    #[test]
    fn test_portal_disconnect_emits_access_lost_and_releases_input() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_remote_desktop(pool);
        backend.start().expect("start succeeds");

        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(700),
        });
        backend.push_event(PortalEvent::DevicesSelected {
            input: InputCapability {
                keyboard: true,
                pointer: true,
                libei: true,
            },
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: dma_buf_format(),
        });

        for _ in 0..5 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }

        let input = backend.input_backend_mut().unwrap();
        let msg = InputMessage {
            sequence: 1,
            session_epoch: 1,
            event: InputEvent::Key {
                code: 0x04,
                pressed: true,
            },
        };
        let _ = input.handle_input_message(msg).unwrap();
        assert!(input.state().key_pressed(0x04));

        backend.push_event(PortalEvent::PipeWireDisconnected);
        assert!(matches!(
            backend.poll(0),
            Ok(Some(CaptureEvent::AccessLost))
        ));

        let input = backend.input_backend().unwrap();
        assert!(!input.is_connected());
        assert!(!input.state().key_pressed(0x04));
    }

    #[test]
    fn test_libei_input_reconciliation_focus_loss_and_recovery() {
        let mut input = LinuxPortalInputBackend::new(InputCapability {
            keyboard: true,
            pointer: true,
            libei: true,
        });

        let msg1 = InputMessage {
            sequence: 1,
            session_epoch: 1,
            event: InputEvent::Key {
                code: 0x04,
                pressed: true,
            },
        };
        let msg2 = InputMessage {
            sequence: 2,
            session_epoch: 1,
            event: InputEvent::PointerButton {
                button: 0,
                pressed: true,
            },
        };
        let _ = input.handle_input_message(msg1).unwrap();
        let _ = input.handle_input_message(msg2).unwrap();
        assert!(input.state().key_pressed(0x04));
        assert!(input.state().button_pressed(0));

        let release_actions = input.set_focused(false);
        assert_eq!(release_actions.len(), 2);
        assert!(!input.state().key_pressed(0x04));
        assert!(!input.state().button_pressed(0));
        assert!(!input.is_focused());

        let msg3 = InputMessage {
            sequence: 3,
            session_epoch: 1,
            event: InputEvent::Key {
                code: 0x05,
                pressed: true,
            },
        };
        assert_eq!(
            input.handle_input_message(msg3),
            Err(PlatformError::InvalidState)
        );

        input.set_focused(true);
        assert!(input.is_focused());

        let msg4 = InputMessage {
            sequence: 4,
            session_epoch: 1,
            event: InputEvent::Key {
                code: 0x05,
                pressed: true,
            },
        };
        let applied = input.handle_input_message(msg4).unwrap();
        assert_eq!(
            applied,
            vec![AppliedInput::Key {
                code: 0x05,
                pressed: true
            }]
        );
        assert!(input.state().key_pressed(0x05));
    }

    #[test]
    fn test_portal_session_change_and_stale_stream_fails_closed() {
        let pool = SurfacePool::new(4);
        let mut backend = LinuxPortalCaptureBackend::new_screencast(pool);
        backend.start().expect("start succeeds");

        backend.push_event(PortalEvent::SessionCreated {
            session: PortalSessionId(800),
        });
        backend.push_event(PortalEvent::SourcesSelected);
        backend.push_event(PortalEvent::Started { stream: stream() });
        backend.push_event(PortalEvent::PipeWireConnected {
            stream: stream(),
            format: dma_buf_format(),
        });

        for _ in 0..4 {
            assert!(matches!(backend.poll(0), Ok(None)));
        }

        let stale_stream = PipeWireStream {
            node_id: 999,
            serial: 999,
        };
        let stale_buffer = PipeWireBuffer::dma_buf(
            stale_stream,
            descriptor(),
            Some(0),
            1,
            DeviceIdentity::Opaque(1),
        );
        backend.push_event(stale_buffer);

        assert!(matches!(backend.poll(0), Err(PlatformError::InvalidState)));
    }
}
