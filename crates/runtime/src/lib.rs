//! Secure runtime composition boundary for native LatencyDesk roles.
//!
//! A role runtime owns provider lifetimes and admits work only through an
//! authenticated [`SessionGate`]. It does not retain peer identities, TLS
//! material, pairing prompts, or SAS values.
//!
//! ```compile_fail
//! use latencydesk_socket_transport::SecureSessionRuntime;
//! let _ = SecureSessionRuntime::new();
//! ```

use latencydesk_input::{AppliedInput, InputMessage, ReconcileOutcome};
use latencydesk_media::{ContinuityAction, DecoderContinuity, EncodedFrameMeta};
use latencydesk_platform::{
    CaptureBackend, CaptureEvent, EncodeBackend, EncodeSubmission, InputBackend,
    NativePresentationCompletion, PlatformError, PresentableFrame, PresentationAction,
    PresentationCompletion, PresentationCoordinator, ProviderDiagnostics, RenderBackend,
};
use latencydesk_protocol::{
    media_flags,
    quic::{MediaDatagram, SessionStamp, QUIC_MEDIA_HEADER_LEN},
    MediaHeader, ProtocolError, NO_DEPENDENCY,
};
use latencydesk_session::runtime::{
    AuthorityError, DispatchPermit, DispatchStamp, SessionGate, SessionInputError,
};
use latencydesk_socket_transport::quic::MediaSendOutcome;
use latencydesk_transport::{
    IngestOutcome, ReassembledFrame, Reassembler, ReassemblyConfig, TransportError,
};
use std::fmt;

/// Observable lifecycle state of a runtime role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProgress {
    PairingPending,
    AwaitingLocalApproval,
    Streaming,
    Recovering,
    Closing,
    Closed,
}

/// A non-secret terminal or recovery reason for runtime diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCloseReason {
    Requested,
    RecoveryRequired,
    CaptureEnded,
}

/// Safe-to-persist runtime counters and epoch snapshots.
///
/// This deliberately excludes the session ID, peer identity, certificate,
/// pairing evidence, SAS, raw input, pixels, and provider-owned handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeDiagnostics {
    pub progress: RuntimeProgress,
    pub generation: Option<u64>,
    pub authorization_epoch: Option<u32>,
    pub display_epoch: Option<u32>,
    pub codec_epoch: Option<u32>,
    pub admitted_control_records: u64,
    pub expired_media_datagrams: u64,
    pub stale_media_datagrams: u64,
    pub recovery_transitions: u64,
    pub close_reason: Option<RuntimeCloseReason>,
}

impl Default for RuntimeDiagnostics {
    fn default() -> Self {
        Self {
            progress: RuntimeProgress::PairingPending,
            generation: None,
            authorization_epoch: None,
            display_epoch: None,
            codec_epoch: None,
            admitted_control_records: 0,
            expired_media_datagrams: 0,
            stale_media_datagrams: 0,
            recovery_transitions: 0,
            close_reason: None,
        }
    }
}

impl RuntimeDiagnostics {
    fn observe_stamp(&mut self, stamp: DispatchStamp) {
        self.generation = Some(stamp.generation());
        self.authorization_epoch = Some(stamp.authorization_epoch());
        self.display_epoch = Some(stamp.display_epoch());
        self.codec_epoch = Some(stamp.codec_epoch());
    }

    fn set_progress(&mut self, progress: RuntimeProgress) {
        self.progress = progress;
    }
}

/// Failure reported by a role runtime.
#[derive(Debug)]
pub enum RuntimeError {
    Authority(AuthorityError),
    SessionInput(SessionInputError),
    Platform(PlatformError),
    Transport(TransportError),
    Protocol(ProtocolError),
    InvalidProgress(RuntimeProgress),
    CaptureEpochMismatch { expected: u32, actual: u32 },
    DecodedFrameMismatch,
    ReleaseDeadlineElapsed,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::SessionInput(error) => Some(error),
            Self::Platform(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::InvalidProgress(_)
            | Self::CaptureEpochMismatch { .. }
            | Self::DecodedFrameMismatch
            | Self::ReleaseDeadlineElapsed => None,
        }
    }
}

impl From<AuthorityError> for RuntimeError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<SessionInputError> for RuntimeError {
    fn from(error: SessionInputError) -> Self {
        Self::SessionInput(error)
    }
}

impl From<PlatformError> for RuntimeError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<TransportError> for RuntimeError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<ProtocolError> for RuntimeError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Encoder/output boundary used by [`HostRuntime`].
///
/// Native code owns the exact encoded access unit and transport submission. The
/// runtime calls this only after `EncodeSubmission` has completed and been
/// released, with a freshly rechecked dispatch stamp.
pub trait HostMediaBackend: EncodeBackend {
    fn send_completed_media(
        &mut self,
        stamp: DispatchStamp,
        now_ns: u64,
    ) -> Result<MediaSendOutcome, RuntimeError>;
}

/// Decoder boundary used by [`ClientRuntime`].
///
/// A decoder receives only a fully reassembled, continuity-valid access unit
/// whose outer QUIC stamp exactly matches the active authority. The continuity
/// action tells it when a recovery point must reset native decoder state.
pub trait DecodeBackend {
    fn decode(
        &mut self,
        frame: ReassembledFrame,
        continuity: ContinuityAction,
        stamp: DispatchStamp,
        now_ns: u64,
    ) -> Result<PresentableFrame, RuntimeError>;
    fn quiesce_decoding(&mut self) -> Result<(), RuntimeError>;
    fn diagnostics(&self) -> ProviderDiagnostics;
}

/// Client-local input ownership boundary.
///
/// On every close or recovery this receives the session authority's release
/// plan before decoder or renderer teardown begins.
pub trait LocalInputBackend {
    fn release_all(&mut self, actions: &[AppliedInput]) -> Result<(), RuntimeError>;
    fn diagnostics(&self) -> ProviderDiagnostics;
}

/// Result of one host coordination step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAction {
    IgnoredNotStreaming,
    DroppedStaleStamp,
    Idle,
    AwaitingEncodeCompletion,
    EncodeSubmitted(DispatchStamp),
    EncodePending,
    MediaSent(MediaSendOutcome),
    InputApplied(usize),
    Recovering,
    Closed,
}

/// Result of one client media admission step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientMediaAction {
    IgnoredNotStreaming,
    DroppedExpired,
    DroppedStaleStamp,
    ReassemblyPending,
    Duplicate,
    DecodedQueued,
    RecoveryRequired,
}

/// Result of admitting an ordered control record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlAction {
    IgnoredNotStreaming,
    DroppedStaleStamp,
    Admitted,
}

struct InFlightEncode {
    permit: DispatchPermit,
    submission: EncodeSubmission,
}

/// Host-side coordinator for capture, encoding, native input, and authority.
pub struct HostRuntime<C, E, I, S> {
    capture: C,
    encoder: E,
    input: I,
    session: S,
    in_flight_encode: Option<InFlightEncode>,
    progress: RuntimeProgress,
    diagnostics: RuntimeDiagnostics,
}

impl<C, E, I, S> HostRuntime<C, E, I, S> {
    #[must_use]
    pub fn new(capture: C, encoder: E, input: I, session: S) -> Self {
        Self {
            capture,
            encoder,
            input,
            session,
            in_flight_encode: None,
            progress: RuntimeProgress::PairingPending,
            diagnostics: RuntimeDiagnostics::default(),
        }
    }

    #[must_use]
    pub const fn progress(&self) -> RuntimeProgress {
        self.progress
    }

    #[must_use]
    pub const fn diagnostics(&self) -> RuntimeDiagnostics {
        self.diagnostics
    }

    /// Records that pairing has reached its local confirmation UI.
    pub fn await_local_approval(&mut self) -> Result<(), RuntimeError> {
        if self.progress != RuntimeProgress::PairingPending {
            return Err(RuntimeError::InvalidProgress(self.progress));
        }
        self.progress = RuntimeProgress::AwaitingLocalApproval;
        self.diagnostics
            .set_progress(RuntimeProgress::AwaitingLocalApproval);
        Ok(())
    }
}

impl<C, E, I, S> HostRuntime<C, E, I, S>
where
    C: CaptureBackend,
    E: HostMediaBackend,
    I: InputBackend,
    S: SessionGate,
{
    /// Starts native work only after the authority produces and rechecks an
    /// active dispatch permit.
    pub fn activate(&mut self, now_ns: u64) -> Result<DispatchStamp, RuntimeError> {
        if !matches!(
            self.progress,
            RuntimeProgress::PairingPending | RuntimeProgress::AwaitingLocalApproval
        ) {
            return Err(RuntimeError::InvalidProgress(self.progress));
        }
        let permit = self.session.acquire_dispatch(now_ns)?;
        let stamp = self.session.recheck(&permit, now_ns)?;
        if let Err(error) = self.capture.start() {
            return self.recover_after(now_ns, error.into());
        }
        if let Err(error) = self.session.recheck(&permit, now_ns) {
            return self.recover_after(now_ns, error.into());
        }
        self.set_progress(RuntimeProgress::Streaming);
        self.diagnostics.observe_stamp(stamp);
        Ok(stamp)
    }

    /// Captures and starts one exact native encoder submission. At most one
    /// captured surface can be in flight until its completion is proven.
    pub fn poll_capture(
        &mut self,
        timeout_ns: u64,
        now_ns: u64,
    ) -> Result<HostAction, RuntimeError> {
        if self.progress != RuntimeProgress::Streaming {
            return Ok(HostAction::IgnoredNotStreaming);
        }
        if self.in_flight_encode.is_some() {
            return Ok(HostAction::AwaitingEncodeCompletion);
        }

        let permit = match self.active_permit(now_ns) {
            Ok(permit) => permit,
            Err(error) => return self.recover_after(now_ns, error),
        };
        let stamp = permit.stamp();
        let event = match self.capture.poll(timeout_ns) {
            Ok(event) => event,
            Err(error) => return self.recover_after(now_ns, error.into()),
        };
        let Some(event) = event else {
            return Ok(HostAction::Idle);
        };

        match event {
            CaptureEvent::Frame(frame) => {
                if frame.display_epoch() != stamp.display_epoch() {
                    let error = RuntimeError::CaptureEpochMismatch {
                        expected: stamp.display_epoch(),
                        actual: frame.display_epoch(),
                    };
                    drop(frame);
                    return self.recover_after(now_ns, error);
                }
                if let Err(error) = self.session.recheck(&permit, now_ns) {
                    return self.recover_after(now_ns, error.into());
                }
                let guard = match self.encoder.prepare(frame) {
                    Ok(guard) => guard,
                    Err(error) => return self.recover_after(now_ns, error.into()),
                };
                if let Err(error) = self.session.recheck(&permit, now_ns) {
                    return self.recover_after(now_ns, error.into());
                }
                let submission = match self.encoder.encode(guard) {
                    Ok(submission) => submission,
                    Err(failure) => {
                        let error = RuntimeError::Platform(failure.error);
                        return self.recover_after(now_ns, error);
                    }
                };
                self.in_flight_encode = Some(InFlightEncode { permit, submission });
                self.diagnostics.observe_stamp(stamp);
                Ok(HostAction::EncodeSubmitted(stamp))
            }
            CaptureEvent::Reconfigure { .. }
            | CaptureEvent::ProtectedContent { .. }
            | CaptureEvent::AccessLost
            | CaptureEvent::PermissionRevoked => {
                self.enter_recovery(now_ns)?;
                Ok(HostAction::Recovering)
            }
            CaptureEvent::EndOfStream => {
                self.close_inner(
                    now_ns,
                    RuntimeProgress::Closed,
                    RuntimeCloseReason::CaptureEnded,
                )?;
                Ok(HostAction::Closed)
            }
        }
    }

    /// Polls the exact native encoder completion, releases its guarded surface,
    /// then dispatches the associated media with a fresh authority recheck.
    pub fn poll_encode_completion(&mut self, now_ns: u64) -> Result<HostAction, RuntimeError> {
        if self.progress != RuntimeProgress::Streaming {
            return Ok(HostAction::IgnoredNotStreaming);
        }
        let Some(in_flight) = self.in_flight_encode.as_ref() else {
            return Ok(HostAction::Idle);
        };
        let permit = in_flight.permit;
        if let Err(error) = self.session.recheck(&permit, now_ns) {
            return self.recover_after(now_ns, error.into());
        }
        let completion = match self.encoder.poll_encode_completion(&in_flight.submission) {
            Ok(completion) => completion,
            Err(error) => return self.recover_after(now_ns, error.into()),
        };
        if completion == NativePresentationCompletion::Pending {
            return Ok(HostAction::EncodePending);
        }
        if let Err(error) = self.session.recheck(&permit, now_ns) {
            return self.recover_after(now_ns, error.into());
        }
        let submission = self
            .in_flight_encode
            .take()
            .expect("in-flight encode checked above")
            .submission;
        if let Err(error) = self.encoder.release_encoded(submission) {
            return self.recover_after(now_ns, error.into());
        }
        if let Err(error) = self.session.recheck(&permit, now_ns) {
            return self.recover_after(now_ns, error.into());
        }
        let stamp = permit.stamp();
        let outcome = match self.encoder.send_completed_media(stamp, now_ns) {
            Ok(outcome) => outcome,
            Err(error) => return self.recover_after(now_ns, error),
        };
        self.diagnostics.observe_stamp(stamp);
        Ok(HostAction::MediaSent(outcome))
    }

    /// Admits a bounded ordered input record, reconciles it inside the session
    /// authority, and rechecks the permit immediately before every injection.
    pub fn ingest_input(
        &mut self,
        transport_stamp: SessionStamp,
        message: InputMessage,
        now_ns: u64,
    ) -> Result<HostAction, RuntimeError> {
        if self.progress != RuntimeProgress::Streaming {
            return Ok(HostAction::IgnoredNotStreaming);
        }
        let permit = match self.active_permit(now_ns) {
            Ok(permit) => permit,
            Err(error) => return self.recover_after(now_ns, error),
        };
        let stamp = permit.stamp();
        if !matches_transport_stamp(stamp, transport_stamp) {
            return Ok(HostAction::DroppedStaleStamp);
        }
        let outcome = self.session.apply_input(message, now_ns)?;
        let ReconcileOutcome::Applied(actions) = outcome else {
            return Ok(HostAction::InputApplied(0));
        };
        for action in &actions {
            if let Err(error) = self.session.recheck(&permit, now_ns) {
                return self.recover_after(now_ns, error.into());
            }
            if let Err(error) = self.input.inject(*action) {
                return self.recover_after(now_ns, error.into());
            }
        }
        self.diagnostics.observe_stamp(stamp);
        Ok(HostAction::InputApplied(actions.len()))
    }

    /// Releases all held input before quiescing capture or encoding.
    pub fn close(&mut self, now_ns: u64) -> Result<HostAction, RuntimeError> {
        if self.progress == RuntimeProgress::Closed {
            return Ok(HostAction::Closed);
        }
        if self.progress == RuntimeProgress::Recovering {
            self.set_progress(RuntimeProgress::Closed);
            return Ok(HostAction::Closed);
        }
        self.close_inner(
            now_ns,
            RuntimeProgress::Closed,
            RuntimeCloseReason::Requested,
        )?;
        Ok(HostAction::Closed)
    }

    fn active_permit(&mut self, now_ns: u64) -> Result<DispatchPermit, RuntimeError> {
        let permit = self.session.acquire_dispatch(now_ns)?;
        let stamp = self.session.recheck(&permit, now_ns)?;
        self.diagnostics.observe_stamp(stamp);
        Ok(permit)
    }

    fn recover_after<T>(&mut self, now_ns: u64, error: RuntimeError) -> Result<T, RuntimeError> {
        match self.enter_recovery(now_ns) {
            Ok(()) => Err(error),
            Err(close_error) => Err(close_error),
        }
    }

    fn enter_recovery(&mut self, now_ns: u64) -> Result<(), RuntimeError> {
        self.close_inner(
            now_ns,
            RuntimeProgress::Recovering,
            RuntimeCloseReason::RecoveryRequired,
        )
    }

    fn close_inner(
        &mut self,
        now_ns: u64,
        next_progress: RuntimeProgress,
        reason: RuntimeCloseReason,
    ) -> Result<(), RuntimeError> {
        self.set_progress(RuntimeProgress::Closing);
        let closed = self.session.close()?;
        let release_deadline_ns = closed.release_deadline_ns();
        let mut ledger = closed.into_input_ledger();
        let releases = ledger.release_plan();

        let input_result = self
            .input
            .release_all(&releases)
            .map_err(RuntimeError::from);
        let encoder_result = self.drain_encoder();
        let capture_result = self.capture.stop().map_err(RuntimeError::from);

        self.set_progress(next_progress);
        self.diagnostics.close_reason = Some(reason);
        if next_progress == RuntimeProgress::Recovering {
            self.diagnostics.recovery_transitions =
                self.diagnostics.recovery_transitions.saturating_add(1);
        }
        if now_ns >= release_deadline_ns {
            return Err(RuntimeError::ReleaseDeadlineElapsed);
        }
        input_result?;
        encoder_result?;
        capture_result?;
        Ok(())
    }

    fn drain_encoder(&mut self) -> Result<(), RuntimeError> {
        self.encoder.quiesce_encoding()?;
        if let Some(in_flight) = self.in_flight_encode.take() {
            self.encoder.release_encoded(in_flight.submission)?;
        }
        Ok(())
    }

    fn set_progress(&mut self, progress: RuntimeProgress) {
        self.progress = progress;
        self.diagnostics.set_progress(progress);
    }
}

/// Client-side coordinator for media reassembly, decode, presentation, local
/// input release, and authority.
pub struct ClientRuntime<D, R, I, S> {
    decoder: D,
    presentation: PresentationCoordinator<R>,
    local_input: I,
    session: S,
    reassembler: Reassembler,
    continuity: DecoderContinuity,
    progress: RuntimeProgress,
    diagnostics: RuntimeDiagnostics,
}

impl<D, R: RenderBackend, I, S> ClientRuntime<D, R, I, S> {
    pub fn new(
        decoder: D,
        renderer: R,
        local_input: I,
        session: S,
        reassembly: ReassemblyConfig,
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            decoder,
            presentation: PresentationCoordinator::new(renderer),
            local_input,
            session,
            reassembler: Reassembler::new(reassembly)?,
            continuity: DecoderContinuity::default(),
            progress: RuntimeProgress::PairingPending,
            diagnostics: RuntimeDiagnostics::default(),
        })
    }

    #[must_use]
    pub const fn progress(&self) -> RuntimeProgress {
        self.progress
    }

    #[must_use]
    pub const fn diagnostics(&self) -> RuntimeDiagnostics {
        self.diagnostics
    }

    /// Records that pairing has reached its local confirmation UI.
    pub fn await_local_approval(&mut self) -> Result<(), RuntimeError> {
        if self.progress != RuntimeProgress::PairingPending {
            return Err(RuntimeError::InvalidProgress(self.progress));
        }
        self.progress = RuntimeProgress::AwaitingLocalApproval;
        self.diagnostics
            .set_progress(RuntimeProgress::AwaitingLocalApproval);
        Ok(())
    }
}

impl<D, R, I, S> ClientRuntime<D, R, I, S>
where
    D: DecodeBackend,
    R: RenderBackend,
    I: LocalInputBackend,
    S: SessionGate,
{
    /// Starts decode and presentation only after an exact active dispatch permit
    /// has been acquired and rechecked.
    pub fn activate(&mut self, now_ns: u64) -> Result<DispatchStamp, RuntimeError> {
        if !matches!(
            self.progress,
            RuntimeProgress::PairingPending | RuntimeProgress::AwaitingLocalApproval
        ) {
            return Err(RuntimeError::InvalidProgress(self.progress));
        }
        let permit = self.session.acquire_dispatch(now_ns)?;
        let stamp = self.session.recheck(&permit, now_ns)?;
        self.set_progress(RuntimeProgress::Streaming);
        self.diagnostics.observe_stamp(stamp);
        Ok(stamp)
    }

    /// Validates a QUIC media DATAGRAM before reassembly. An expired datagram is
    /// dropped before it can occupy reassembly or delay control admission.
    pub fn ingest_media(
        &mut self,
        datagram: &[u8],
        now_ns: u64,
    ) -> Result<ClientMediaAction, RuntimeError> {
        if self.progress != RuntimeProgress::Streaming {
            return Ok(ClientMediaAction::IgnoredNotStreaming);
        }
        let media = match MediaDatagram::decode_at(datagram, now_ns) {
            Ok(media) => media,
            Err(ProtocolError::ExpiredMediaDatagram) => {
                self.diagnostics.expired_media_datagrams =
                    self.diagnostics.expired_media_datagrams.saturating_add(1);
                return Ok(ClientMediaAction::DroppedExpired);
            }
            Err(error) => return Err(error.into()),
        };
        let permit = match self.active_permit(now_ns) {
            Ok(permit) => permit,
            Err(error) => return self.recover_after(now_ns, error),
        };
        let stamp = permit.stamp();
        if !matches_transport_stamp(stamp, media.stamp) {
            self.diagnostics.stale_media_datagrams =
                self.diagnostics.stale_media_datagrams.saturating_add(1);
            return Ok(ClientMediaAction::DroppedStaleStamp);
        }
        let header = media.packet.header;
        let inner_datagram = &datagram[QUIC_MEDIA_HEADER_LEN..];
        let reassembly = self.reassembler.ingest(inner_datagram, now_ns)?;
        match reassembly {
            IngestOutcome::Pending { .. } => Ok(ClientMediaAction::ReassemblyPending),
            IngestOutcome::Duplicate { .. } => Ok(ClientMediaAction::Duplicate),
            IngestOutcome::Complete(frame) => {
                let meta = encoded_meta(header);
                let action = self.continuity.classify(meta);
                if action == ContinuityAction::DropAndRequestRecovery {
                    self.enter_recovery(now_ns)?;
                    return Ok(ClientMediaAction::RecoveryRequired);
                }
                if let Err(error) = self.session.recheck(&permit, now_ns) {
                    return self.recover_after(now_ns, error.into());
                }
                let presentable = match self.decoder.decode(frame, action, stamp, now_ns) {
                    Ok(presentable) => presentable,
                    Err(error) => return self.recover_after(now_ns, error),
                };
                if !matches_presentable(&presentable, stamp, header) {
                    drop(presentable);
                    return self.recover_after(now_ns, RuntimeError::DecodedFrameMismatch);
                }
                if self.continuity.commit_decoded(meta).is_err() {
                    drop(presentable);
                    return self.recover_after(now_ns, RuntimeError::DecodedFrameMismatch);
                }
                if let Err(error) = self.presentation.submit(presentable, now_ns) {
                    return self.recover_after(now_ns, error.into());
                }
                self.diagnostics.observe_stamp(stamp);
                Ok(ClientMediaAction::DecodedQueued)
            }
        }
    }

    /// Performs the non-native control admission that is independent from media
    /// reassembly and therefore remains available after stale or expired media.
    pub fn admit_control(
        &mut self,
        transport_stamp: SessionStamp,
        now_ns: u64,
    ) -> Result<ControlAction, RuntimeError> {
        if self.progress != RuntimeProgress::Streaming {
            return Ok(ControlAction::IgnoredNotStreaming);
        }
        let permit = match self.active_permit(now_ns) {
            Ok(permit) => permit,
            Err(error) => return self.recover_after(now_ns, error),
        };
        let stamp = permit.stamp();
        if !matches_transport_stamp(stamp, transport_stamp) {
            return Ok(ControlAction::DroppedStaleStamp);
        }
        self.diagnostics.admitted_control_records =
            self.diagnostics.admitted_control_records.saturating_add(1);
        Ok(ControlAction::Admitted)
    }

    /// Submits the newest valid decoded frame only after the authority's final
    /// recheck. The presentation coordinator owns the guard through completion.
    pub fn present_next(&mut self, now_ns: u64) -> Result<PresentationAction, RuntimeError> {
        if self.progress != RuntimeProgress::Streaming {
            return Ok(PresentationAction::Idle);
        }
        let permit = match self.active_permit(now_ns) {
            Ok(permit) => permit,
            Err(error) => return self.recover_after(now_ns, error),
        };
        if let Err(error) = self.session.recheck(&permit, now_ns) {
            return self.recover_after(now_ns, error.into());
        }
        match self.presentation.present_next(now_ns) {
            Ok(action) => Ok(action),
            Err(error) => self.recover_after(now_ns, error.into()),
        }
    }

    /// Polls the renderer's exact completion primitive before its guarded
    /// presentation surface can be released.
    pub fn poll_present_completion(
        &mut self,
        now_ns: u64,
    ) -> Result<PresentationCompletion, RuntimeError> {
        if self.progress != RuntimeProgress::Streaming {
            return Ok(PresentationCompletion::Idle);
        }
        let permit = match self.active_permit(now_ns) {
            Ok(permit) => permit,
            Err(error) => return self.recover_after(now_ns, error),
        };
        if let Err(error) = self.session.recheck(&permit, now_ns) {
            return self.recover_after(now_ns, error.into());
        }
        match self.presentation.poll_present_completion() {
            Ok(completion) => Ok(completion),
            Err(error) => self.recover_after(now_ns, error.into()),
        }
    }

    /// Releases local input before decoder and renderer teardown.
    pub fn close(&mut self, now_ns: u64) -> Result<(), RuntimeError> {
        if self.progress == RuntimeProgress::Closed {
            return Ok(());
        }
        if self.progress == RuntimeProgress::Recovering {
            self.set_progress(RuntimeProgress::Closed);
            return Ok(());
        }
        self.close_inner(
            now_ns,
            RuntimeProgress::Closed,
            RuntimeCloseReason::Requested,
        )
    }

    fn active_permit(&mut self, now_ns: u64) -> Result<DispatchPermit, RuntimeError> {
        let permit = self.session.acquire_dispatch(now_ns)?;
        let stamp = self.session.recheck(&permit, now_ns)?;
        self.diagnostics.observe_stamp(stamp);
        Ok(permit)
    }

    fn recover_after<T>(&mut self, now_ns: u64, error: RuntimeError) -> Result<T, RuntimeError> {
        match self.enter_recovery(now_ns) {
            Ok(()) => Err(error),
            Err(close_error) => Err(close_error),
        }
    }

    fn enter_recovery(&mut self, now_ns: u64) -> Result<(), RuntimeError> {
        self.close_inner(
            now_ns,
            RuntimeProgress::Recovering,
            RuntimeCloseReason::RecoveryRequired,
        )
    }

    fn close_inner(
        &mut self,
        now_ns: u64,
        next_progress: RuntimeProgress,
        reason: RuntimeCloseReason,
    ) -> Result<(), RuntimeError> {
        self.set_progress(RuntimeProgress::Closing);
        let closed = self.session.close()?;
        let release_deadline_ns = closed.release_deadline_ns();
        let mut ledger = closed.into_input_ledger();
        let releases = ledger.release_plan();

        let input_result = self.local_input.release_all(&releases);
        let decoder_result = self.decoder.quiesce_decoding();
        let presentation_result = self.presentation.shutdown().map_err(RuntimeError::from);

        self.set_progress(next_progress);
        self.diagnostics.close_reason = Some(reason);
        if next_progress == RuntimeProgress::Recovering {
            self.diagnostics.recovery_transitions =
                self.diagnostics.recovery_transitions.saturating_add(1);
        }
        if now_ns >= release_deadline_ns {
            return Err(RuntimeError::ReleaseDeadlineElapsed);
        }
        input_result?;
        decoder_result?;
        presentation_result?;
        Ok(())
    }

    fn set_progress(&mut self, progress: RuntimeProgress) {
        self.progress = progress;
        self.diagnostics.set_progress(progress);
    }
}

fn matches_transport_stamp(dispatch: DispatchStamp, transport: SessionStamp) -> bool {
    dispatch.session_id().value() == transport.session_id
        && dispatch.generation() == transport.generation
        && dispatch.authorization_epoch() == transport.authorization_epoch
        && dispatch.display_epoch() == transport.display_epoch
        && dispatch.codec_epoch() == transport.codec_epoch
}

fn encoded_meta(header: MediaHeader) -> EncodedFrameMeta {
    EncodedFrameMeta {
        codec_epoch: header.codec_epoch,
        frame_id: header.frame_id,
        dependency_frame_id: (header.dependency_frame_id != NO_DEPENDENCY)
            .then_some(header.dependency_frame_id),
        recovery_point: header.flags & media_flags::KEYFRAME != 0,
    }
}

fn matches_presentable(
    frame: &PresentableFrame,
    stamp: DispatchStamp,
    header: MediaHeader,
) -> bool {
    frame.display_epoch() == stamp.display_epoch()
        && frame.codec_epoch == stamp.codec_epoch()
        && frame.frame_id == header.frame_id
        && frame.recovery_point == (header.flags & media_flags::KEYFRAME != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_input::InputEvent;
    use latencydesk_media::{
        CopyEvidenceGrade, CopyLedger, DeviceIdentity as MediaDeviceIdentity, FrameDescriptor,
        ImportPath, LeaseCompletion, MemoryDomain, SourceLeaseIdentity, SurfaceLayout,
        SynchronizationProof, TransferEdge,
    };
    use latencydesk_platform::{
        CaptureFramePublisher, CursorUpdate, DeviceIdentity, DeviceIdentityStore, EncodeFailure,
        EncoderSubmissionGuard, PeerAlias, PeerPin, PresentSubmission, PresentationSubmissionGuard,
        ProviderState, RenderFailure,
    };
    use latencydesk_protocol::MediaKind;
    use latencydesk_session::{
        authorization::{CapabilitySet, SessionId},
        pairing::{PairingCoordinator, PairingEvidence, PairingStart},
        runtime::{InputLedger, SessionAuthority},
    };
    use latencydesk_surface::SurfacePool;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy)]
    struct RecordingIdentityStore {
        identity: DeviceIdentity,
        peer_pin: PeerPin,
    }

    impl DeviceIdentityStore for RecordingIdentityStore {
        fn load_or_create_identity(&self) -> Result<DeviceIdentity, PlatformError> {
            Ok(self.identity)
        }

        fn load_peer_pin(&self, _alias: &PeerAlias) -> Result<Option<PeerPin>, PlatformError> {
            Ok(Some(self.peer_pin))
        }

        fn store_peer_pin(&self, _alias: &PeerAlias, _pin: PeerPin) -> Result<(), PlatformError> {
            Ok(())
        }
    }

    fn authority(capabilities: CapabilitySet) -> SessionAuthority {
        let session_id = SessionId::new(7).expect("session ID");
        let local_fingerprint = [1; 32];
        let peer_fingerprint = [2; 32];
        let identity =
            DeviceIdentity::from_tls_spki_fingerprint(local_fingerprint).expect("local identity");
        let peer_pin = PeerPin::from_tls_spki_fingerprint(peer_fingerprint).expect("peer pin");
        let evidence = PairingEvidence::new(
            session_id,
            local_fingerprint,
            peer_fingerprint,
            800,
            capabilities,
        )
        .expect("pairing evidence");
        let mut pairing = PairingCoordinator::new(RecordingIdentityStore { identity, peer_pin });
        let accepted = match pairing
            .begin(
                PeerAlias::new("test peer").expect("alias"),
                evidence,
                peer_fingerprint,
                10,
            )
            .expect("pinned pairing")
        {
            PairingStart::Accepted(accepted) => accepted,
            PairingStart::AwaitingSas(_) => panic!("existing pin bypasses SAS"),
        };
        let stamp = DispatchStamp::new(session_id, 1, 2, 3, 4).expect("dispatch stamp");
        SessionAuthority::new(accepted, stamp, InputLedger::default(), 700, 600)
            .expect("session authority")
    }

    fn session_stamp(stamp: DispatchStamp) -> SessionStamp {
        SessionStamp {
            session_id: stamp.session_id().value(),
            generation: stamp.generation(),
            authorization_epoch: stamp.authorization_epoch(),
            display_epoch: stamp.display_epoch(),
            codec_epoch: stamp.codec_epoch(),
            route_epoch: 1,
        }
    }

    fn media_datagram(stamp: SessionStamp, expires_at_ns: u64, frame_id: u64) -> Vec<u8> {
        let payload = [0, 0, 0, 1, 0x65];
        MediaDatagram::encode(
            stamp,
            expires_at_ns,
            MediaHeader {
                kind: MediaKind::Video,
                flags: media_flags::KEYFRAME,
                stream_id: 1,
                codec_epoch: stamp.codec_epoch,
                frame_id,
                dependency_frame_id: NO_DEPENDENCY,
                frame_len: payload.len() as u32,
                fragment_offset: 0,
                fragment_len: payload.len() as u16,
            },
            &payload,
        )
        .expect("valid media datagram")
    }

    fn presentable_frame(frame_id: u64) -> PresentableFrame {
        let pool = SurfacePool::new(1);
        let descriptor = FrameDescriptor {
            width: 64,
            height: 64,
            format_fourcc: 0,
            memory_domain: MemoryDomain::Cpu,
            capture_sequence: frame_id,
            capture_timestamp_ns: 1,
        };
        let ledger = CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: 3,
                capture_sequence: frame_id,
            },
            source_device: MediaDeviceIdentity::Unknown,
            destination_device: MediaDeviceIdentity::Unknown,
            source_layout: SurfaceLayout {
                memory_domain: MemoryDomain::Cpu,
                format_fourcc: 0,
                plane_count: 1,
                modifier: None,
            },
            destination_layout: SurfaceLayout {
                memory_domain: MemoryDomain::Cpu,
                format_fourcc: 0,
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
            .expect("capture lease")
            .import(ledger)
            .expect("owned surface");
        let surface = CaptureFramePublisher::new()
            .bind(owned, Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .expect("epoch-bound surface");
        PresentableFrame {
            surface,
            codec_epoch: 4,
            frame_id,
            ready_ns: 1,
            deadline_ns: 500,
            recovery_point: true,
        }
    }

    #[derive(Default)]
    struct RecordingCapture {
        frame: Option<latencydesk_platform::EpochBoundSurface>,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordingCapture {
        fn with_calls(calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self { frame: None, calls }
        }

        fn with_frame(
            frame: latencydesk_platform::EpochBoundSurface,
            calls: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                frame: Some(frame),
                calls,
            }
        }
    }

    impl CaptureBackend for RecordingCapture {
        fn name(&self) -> &'static str {
            "recording-capture"
        }

        fn state(&self) -> ProviderState {
            ProviderState::Running
        }

        fn start(&mut self) -> Result<(), PlatformError> {
            self.calls.lock().expect("calls lock").push("capture_start");
            Ok(())
        }

        fn poll_with_publisher(
            &mut self,
            _timeout_ns: u64,
            _publisher: &mut CaptureFramePublisher,
        ) -> Result<Option<CaptureEvent>, PlatformError> {
            self.calls.lock().expect("calls lock").push("capture");
            Ok(self.frame.take().map(CaptureEvent::Frame))
        }

        fn stop(&mut self) -> Result<(), PlatformError> {
            self.calls.lock().expect("calls lock").push("capture_stop");
            Ok(())
        }

        fn diagnostics(&self) -> ProviderDiagnostics {
            ProviderDiagnostics::idle(self.name())
        }
    }

    struct RecordingEncoder {
        calls: Arc<Mutex<Vec<&'static str>>>,
        completed: bool,
    }

    impl RecordingEncoder {
        fn new(calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                calls,
                completed: true,
            }
        }
    }

    impl EncodeBackend for RecordingEncoder {
        fn name(&self) -> &'static str {
            "recording-encoder"
        }

        fn encode(
            &mut self,
            submission: EncoderSubmissionGuard,
        ) -> Result<EncodeSubmission, EncodeFailure> {
            self.calls.lock().expect("calls lock").push("encode");
            submission.submit()
        }

        fn poll_encode_completion(
            &mut self,
            _submission: &EncodeSubmission,
        ) -> Result<NativePresentationCompletion, PlatformError> {
            self.calls.lock().expect("calls lock").push("encode_poll");
            Ok(if self.completed {
                NativePresentationCompletion::Complete
            } else {
                NativePresentationCompletion::Pending
            })
        }

        fn quiesce_encoding(&mut self) -> Result<(), PlatformError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push("encoder_quiesce");
            Ok(())
        }

        fn diagnostics(&self) -> ProviderDiagnostics {
            ProviderDiagnostics::idle(self.name())
        }
    }

    impl HostMediaBackend for RecordingEncoder {
        fn send_completed_media(
            &mut self,
            _stamp: DispatchStamp,
            _now_ns: u64,
        ) -> Result<MediaSendOutcome, RuntimeError> {
            self.calls.lock().expect("calls lock").push("media_send");
            Ok(MediaSendOutcome::Sent)
        }
    }

    struct RecordingInput {
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordingInput {
        fn new(calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self { calls }
        }
    }

    impl InputBackend for RecordingInput {
        fn name(&self) -> &'static str {
            "recording-input"
        }

        fn inject(&mut self, _action: AppliedInput) -> Result<(), PlatformError> {
            self.calls.lock().expect("calls lock").push("input_inject");
            Ok(())
        }

        fn release_all(&mut self, _actions: &[AppliedInput]) -> Result<(), PlatformError> {
            self.calls.lock().expect("calls lock").push("input_release");
            Ok(())
        }

        fn diagnostics(&self) -> ProviderDiagnostics {
            ProviderDiagnostics::idle(self.name())
        }
    }

    struct RecordingDecoder {
        frame: Option<PresentableFrame>,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordingDecoder {
        fn new(frame: Option<PresentableFrame>, calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self { frame, calls }
        }
    }

    impl DecodeBackend for RecordingDecoder {
        fn decode(
            &mut self,
            _frame: ReassembledFrame,
            continuity: ContinuityAction,
            _stamp: DispatchStamp,
            _now_ns: u64,
        ) -> Result<PresentableFrame, RuntimeError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(match continuity {
                    ContinuityAction::ResetAndDecode => "decode_reset",
                    ContinuityAction::Decode | ContinuityAction::DropAndRequestRecovery => "decode",
                });
            self.frame.take().ok_or(RuntimeError::DecodedFrameMismatch)
        }

        fn quiesce_decoding(&mut self) -> Result<(), RuntimeError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push("decoder_quiesce");
            Ok(())
        }

        fn diagnostics(&self) -> ProviderDiagnostics {
            ProviderDiagnostics::idle("recording-decoder")
        }
    }

    struct RecordingRenderer {
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordingRenderer {
        fn new(calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self { calls }
        }
    }

    impl RenderBackend for RecordingRenderer {
        fn name(&self) -> &'static str {
            "recording-renderer"
        }

        fn present(
            &mut self,
            submission: PresentationSubmissionGuard,
        ) -> Result<PresentSubmission, RenderFailure> {
            self.calls.lock().expect("calls lock").push("render");
            submission.submit(10, 0)
        }

        fn poll_present_completion(
            &mut self,
            _submission: &PresentSubmission,
        ) -> Result<NativePresentationCompletion, PlatformError> {
            self.calls.lock().expect("calls lock").push("render_poll");
            Ok(NativePresentationCompletion::Complete)
        }

        fn quiesce_presentation(&mut self) -> Result<(), PlatformError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push("renderer_quiesce");
            Ok(())
        }

        fn set_cursor(&mut self, _cursor: CursorUpdate<'_>) -> Result<(), PlatformError> {
            Ok(())
        }

        fn diagnostics(&self) -> ProviderDiagnostics {
            ProviderDiagnostics::idle(self.name())
        }
    }

    struct RecordingLocalInput {
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordingLocalInput {
        fn new(calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self { calls }
        }
    }

    impl LocalInputBackend for RecordingLocalInput {
        fn release_all(&mut self, _actions: &[AppliedInput]) -> Result<(), RuntimeError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push("local_input_release");
            Ok(())
        }

        fn diagnostics(&self) -> ProviderDiagnostics {
            ProviderDiagnostics::idle("recording-local-input")
        }
    }

    #[test]
    fn unapproved_media_never_invokes_encode_decode_or_render() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut host = HostRuntime::new(
            RecordingCapture::with_calls(Arc::clone(&calls)),
            RecordingEncoder::new(Arc::clone(&calls)),
            RecordingInput::new(Arc::clone(&calls)),
            authority(CapabilitySet::view_only()),
        );
        assert!(matches!(
            host.poll_capture(0, 10),
            Ok(HostAction::IgnoredNotStreaming)
        ));

        let mut client = ClientRuntime::new(
            RecordingDecoder::new(None, Arc::clone(&calls)),
            RecordingRenderer::new(Arc::clone(&calls)),
            RecordingLocalInput::new(Arc::clone(&calls)),
            authority(CapabilitySet::view_only()),
            ReassemblyConfig::default(),
        )
        .expect("client runtime");
        let stale = SessionStamp {
            session_id: 7,
            generation: 1,
            authorization_epoch: 2,
            display_epoch: 3,
            codec_epoch: 4,
            route_epoch: 1,
        };
        assert_eq!(
            client
                .ingest_media(&media_datagram(stale, 500, 1), 10)
                .expect("unapproved media is ignored"),
            ClientMediaAction::IgnoredNotStreaming
        );
        assert!(calls.lock().expect("calls lock").is_empty());
    }

    #[test]
    fn stale_generation_never_invokes_decoder_or_renderer() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut client = ClientRuntime::new(
            RecordingDecoder::new(None, Arc::clone(&calls)),
            RecordingRenderer::new(Arc::clone(&calls)),
            RecordingLocalInput::new(Arc::clone(&calls)),
            authority(CapabilitySet::view_and_input()),
            ReassemblyConfig::default(),
        )
        .expect("client runtime");
        let stamp = client.activate(10).expect("active authority");
        let mut stale = session_stamp(stamp);
        stale.generation = stale.generation.saturating_add(1);

        assert_eq!(
            client
                .ingest_media(&media_datagram(stale, 500, 1), 10)
                .expect("stale media is dropped"),
            ClientMediaAction::DroppedStaleStamp
        );
        assert!(calls.lock().expect("calls lock").is_empty());
    }

    #[test]
    fn stale_input_stamp_never_invokes_input_provider() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut host = HostRuntime::new(
            RecordingCapture::with_calls(Arc::clone(&calls)),
            RecordingEncoder::new(Arc::clone(&calls)),
            RecordingInput::new(Arc::clone(&calls)),
            authority(CapabilitySet::view_and_input()),
        );
        let stamp = host.activate(10).expect("active authority");
        let mut stale = session_stamp(stamp);
        stale.generation = stale.generation.saturating_add(1);

        assert_eq!(
            host.ingest_input(
                stale,
                InputMessage {
                    session_epoch: 2,
                    sequence: 1,
                    event: InputEvent::Key {
                        code: 42,
                        pressed: true,
                    },
                },
                10,
            )
            .expect("stale input is dropped"),
            HostAction::DroppedStaleStamp
        );
        assert!(!calls.lock().expect("calls lock").contains(&"input_inject"));
    }

    #[test]
    fn input_release_precedes_non_input_draining() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut host = HostRuntime::new(
            RecordingCapture::with_calls(Arc::clone(&calls)),
            RecordingEncoder::new(Arc::clone(&calls)),
            RecordingInput::new(Arc::clone(&calls)),
            authority(CapabilitySet::view_and_input()),
        );
        let stamp = host.activate(10).expect("active authority");
        assert_eq!(
            host.ingest_input(
                session_stamp(stamp),
                InputMessage {
                    session_epoch: 2,
                    sequence: 1,
                    event: InputEvent::Key {
                        code: 42,
                        pressed: true,
                    },
                },
                10,
            )
            .expect("input admitted"),
            HostAction::InputApplied(1)
        );
        assert!(matches!(host.close(20), Ok(HostAction::Closed)));

        let calls = calls.lock().expect("calls lock");
        let release = calls
            .iter()
            .position(|call| *call == "input_release")
            .expect("input release");
        let encoder = calls
            .iter()
            .position(|call| *call == "encoder_quiesce")
            .expect("encoder quiesce");
        let capture = calls
            .iter()
            .position(|call| *call == "capture_stop")
            .expect("capture stop");
        assert!(release < encoder);
        assert!(release < capture);

        let client_calls = Arc::new(Mutex::new(Vec::new()));
        let mut client = ClientRuntime::new(
            RecordingDecoder::new(Some(presentable_frame(1)), Arc::clone(&client_calls)),
            RecordingRenderer::new(Arc::clone(&client_calls)),
            RecordingLocalInput::new(Arc::clone(&client_calls)),
            authority(CapabilitySet::view_only()),
            ReassemblyConfig::default(),
        )
        .expect("client runtime");
        let stamp = client.activate(10).expect("active client authority");
        assert_eq!(
            client
                .ingest_media(&media_datagram(session_stamp(stamp), 500, 1), 10)
                .expect("client media"),
            ClientMediaAction::DecodedQueued
        );
        assert!(matches!(
            client.present_next(10).expect("client present"),
            PresentationAction::Presented(_)
        ));
        client.close(20).expect("client close");

        let calls = client_calls.lock().expect("client calls lock");
        let release = calls
            .iter()
            .position(|call| *call == "local_input_release")
            .expect("local input release");
        let decoder = calls
            .iter()
            .position(|call| *call == "decoder_quiesce")
            .expect("decoder quiesce");
        let renderer = calls
            .iter()
            .position(|call| *call == "renderer_quiesce")
            .expect("renderer quiesce");
        assert!(release < decoder);
        assert!(release < renderer);
    }

    #[test]
    fn close_is_idempotent_after_recovery() {
        let host_calls = Arc::new(Mutex::new(Vec::new()));
        let mut host = HostRuntime::new(
            RecordingCapture::with_calls(Arc::clone(&host_calls)),
            RecordingEncoder::new(Arc::clone(&host_calls)),
            RecordingInput::new(Arc::clone(&host_calls)),
            authority(CapabilitySet::view_and_input()),
        );
        host.activate(10).expect("active host authority");
        host.enter_recovery(20).expect("host recovery");
        assert_eq!(
            host.close(21).expect("host closes after recovery"),
            HostAction::Closed
        );
        assert_eq!(host.progress(), RuntimeProgress::Closed);
        assert_eq!(
            host_calls
                .lock()
                .expect("host calls lock")
                .iter()
                .filter(|call| **call == "input_release")
                .count(),
            1
        );

        let client_calls = Arc::new(Mutex::new(Vec::new()));
        let mut client = ClientRuntime::new(
            RecordingDecoder::new(None, Arc::clone(&client_calls)),
            RecordingRenderer::new(Arc::clone(&client_calls)),
            RecordingLocalInput::new(Arc::clone(&client_calls)),
            authority(CapabilitySet::view_and_input()),
            ReassemblyConfig::default(),
        )
        .expect("client runtime");
        client.activate(10).expect("active client authority");
        client.enter_recovery(20).expect("client recovery");
        client.close(21).expect("client closes after recovery");
        assert_eq!(client.progress(), RuntimeProgress::Closed);
        assert_eq!(
            client_calls
                .lock()
                .expect("client calls lock")
                .iter()
                .filter(|call| **call == "local_input_release")
                .count(),
            1
        );
    }

    #[test]
    fn expired_media_cannot_block_control_admission() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut client = ClientRuntime::new(
            RecordingDecoder::new(None, Arc::clone(&calls)),
            RecordingRenderer::new(Arc::clone(&calls)),
            RecordingLocalInput::new(Arc::clone(&calls)),
            authority(CapabilitySet::view_and_input()),
            ReassemblyConfig::default(),
        )
        .expect("client runtime");
        let stamp = client.activate(10).expect("active authority");

        assert_eq!(
            client
                .ingest_media(&media_datagram(session_stamp(stamp), 10, 1), 10)
                .expect("expired media drops"),
            ClientMediaAction::DroppedExpired
        );
        assert_eq!(
            client
                .admit_control(session_stamp(stamp), 10)
                .expect("control remains available"),
            ControlAction::Admitted
        );
        assert!(calls.lock().expect("calls lock").is_empty());
    }

    #[test]
    fn host_releases_after_exact_encode_completion_then_sends_media() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let presentable = presentable_frame(1);
        let mut host = HostRuntime::new(
            RecordingCapture::with_frame(presentable.surface, Arc::clone(&calls)),
            RecordingEncoder::new(Arc::clone(&calls)),
            RecordingInput::new(Arc::clone(&calls)),
            authority(CapabilitySet::view_and_input()),
        );
        let stamp = host.activate(10).expect("active authority");

        assert_eq!(
            host.poll_capture(0, 10).expect("capture"),
            HostAction::EncodeSubmitted(stamp)
        );
        assert_eq!(
            host.poll_encode_completion(10).expect("encode completion"),
            HostAction::MediaSent(MediaSendOutcome::Sent)
        );
        let calls = calls.lock().expect("calls lock");
        assert!(calls.contains(&"capture_start"));
        assert!(calls.contains(&"encode_poll"));
        assert!(calls.contains(&"media_send"));
    }

    #[test]
    fn valid_media_reassembles_decodes_and_presents_through_completion() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut client = ClientRuntime::new(
            RecordingDecoder::new(Some(presentable_frame(1)), Arc::clone(&calls)),
            RecordingRenderer::new(Arc::clone(&calls)),
            RecordingLocalInput::new(Arc::clone(&calls)),
            authority(CapabilitySet::view_and_input()),
            ReassemblyConfig::default(),
        )
        .expect("client runtime");
        let stamp = client.activate(10).expect("active authority");

        assert_eq!(
            client
                .ingest_media(&media_datagram(session_stamp(stamp), 500, 1), 10)
                .expect("media admitted"),
            ClientMediaAction::DecodedQueued
        );
        assert!(matches!(
            client.present_next(10).expect("present"),
            PresentationAction::Presented(_)
        ));
        assert_eq!(
            client.poll_present_completion(10).expect("completion"),
            PresentationCompletion::Released
        );
        let calls = calls.lock().expect("calls lock");
        assert!(calls.contains(&"decode_reset"));
        assert!(calls.contains(&"render"));
        assert!(calls.contains(&"render_poll"));
    }
}
