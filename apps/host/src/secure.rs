//! Fail-closed product host path over exact-certificate mutual TLS and QUIC.

use super::HostArgs;

#[cfg(not(any(target_os = "linux", windows)))]
use std::error::Error;

#[cfg(not(any(target_os = "linux", windows)))]
const UNSUPPORTED_PLATFORM: &str = "secure hosting is currently supported only on Linux X11 and Windows; other platforms are rejected before opening a socket because their product capture/input providers are not implemented (use --unsafe-udp-lab only for isolated compatibility testing)";

const CLEAN_APPLICATION_CLOSE_CODE: u32 = 0;
const HOST_FAILURE_APPLICATION_CLOSE_CODE: u32 = 1;

const fn host_application_close_code(succeeded: bool) -> u32 {
    if succeeded {
        CLEAN_APPLICATION_CLOSE_CODE
    } else {
        HOST_FAILURE_APPLICATION_CLOSE_CODE
    }
}

#[cfg(any(target_os = "linux", windows))]
#[derive(Clone, Debug)]
struct InputLaneFailure(std::sync::Arc<InputLaneFailureState>);

#[cfg(any(target_os = "linux", windows))]
#[derive(Debug)]
struct InputLaneFailureState {
    message: String,
    #[cfg(target_os = "linux")]
    disposition: InputLaneFailureDisposition,
    observed_by_stream: std::sync::atomic::AtomicBool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputLaneFailureDisposition {
    Fatal,
    RetryablePeerLoss,
}

#[cfg(any(target_os = "linux", windows))]
impl InputLaneFailure {
    fn new(message: String) -> Self {
        Self(std::sync::Arc::new(InputLaneFailureState {
            message,
            #[cfg(target_os = "linux")]
            disposition: InputLaneFailureDisposition::Fatal,
            observed_by_stream: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    #[cfg(target_os = "linux")]
    fn peer_connection_lost(message: String) -> Self {
        Self::with_disposition(message, InputLaneFailureDisposition::RetryablePeerLoss)
    }

    #[cfg(target_os = "linux")]
    fn with_disposition(message: String, disposition: InputLaneFailureDisposition) -> Self {
        Self(std::sync::Arc::new(InputLaneFailureState {
            message,
            disposition,
            observed_by_stream: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    #[cfg(target_os = "linux")]
    fn is_retryable_connection_loss(&self) -> bool {
        self.0.disposition == InputLaneFailureDisposition::RetryablePeerLoss
    }

    fn mark_observed(&self) {
        self.0
            .observed_by_stream
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn was_observed(&self) -> bool {
        self.0
            .observed_by_stream
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(any(target_os = "linux", windows))]
impl std::fmt::Display for InputLaneFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0.message)
    }
}

#[cfg(any(target_os = "linux", windows))]
impl std::error::Error for InputLaneFailure {}

#[cfg(test)]
mod close_code_tests {
    use super::*;

    #[test]
    fn application_close_code_is_zero_only_for_host_success() {
        assert_eq!(host_application_close_code(true), 0);
        assert_eq!(host_application_close_code(false), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn input_lane_failure_preserves_retryable_peer_loss_disposition() {
        let fatal = InputLaneFailure::new("provider failed".into());
        let peer_loss = InputLaneFailure::peer_connection_lost("path timed out".into());

        assert!(!fatal.is_retryable_connection_loss());
        assert!(peer_loss.is_retryable_connection_loss());
    }
}

/// Runs the secure product path. Unsupported platforms fail before loading
/// credentials, creating a socket, or opening a capture/input provider.
#[cfg(not(any(target_os = "linux", windows)))]
pub async fn run(_args: &HostArgs) -> Result<(), Box<dyn Error>> {
    Err(UNSUPPORTED_PLATFORM.into())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::HostArgs;
    use latencydesk_h264::{H264Error, LowDelayPolicy, SoftwareH264Encoder};
    use latencydesk_input::{InputMessage, InputReconciler, ReconcileOutcome};
    use latencydesk_platform_linux::{
        letterbox_geom, nv12_len, pack_nv12_access_unit_into, X11DesktopSession,
    };
    use latencydesk_protocol::{
        media_flags, select_host_codec, ControlKind, MediaKind, VideoCodec, VideoCodecCapabilities,
        VideoProfile, VideoStreamConfig, VIDEO_CODEC_CONTRACT_VERSION,
    };
    use latencydesk_session::lifecycle::ProductStampAllocator;
    use latencydesk_socket_transport::identity::{
        accept_exact_peer_with_timeout, certificate_fingerprint, load_certificate_der,
        mtls_server_config, IdentityError, TlsIdentity,
    };
    use latencydesk_socket_transport::product::{ProductSession, ProductSessionError};
    use latencydesk_socket_transport::quic::{bind_server, QuicTransportError};
    use latencydesk_transport::FragmentSpec;
    use std::borrow::Cow;
    use std::error::Error;
    use std::num::NonZeroU64;
    use std::path::Path;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::MissedTickBehavior;

    const LOG_FRAME_INTERVAL: u64 = 60;
    const AUTHENTICATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

    #[derive(Debug, Clone, Copy)]
    struct CapturePlan {
        stream: VideoStreamConfig,
        max_width: u32,
        max_height: u32,
    }

    fn frame_period(fps: u32) -> Option<Duration> {
        let fps = NonZeroU64::new(u64::from(fps))?;
        Some(Duration::from_nanos(1_000_000_000_u64.div_ceil(fps.get())))
    }

    const fn frame_log_due(frame_id: u64) -> bool {
        frame_id == 1 || frame_id % LOG_FRAME_INTERVAL == 0
    }

    #[derive(Default)]
    struct MediaDropLog {
        pending: u64,
    }

    impl MediaDropLog {
        fn record(&mut self, frame_id: u64) -> Option<u64> {
            self.pending = self.pending.saturating_add(1);
            self.take_if_due(frame_id)
        }

        fn take_if_due(&mut self, frame_id: u64) -> Option<u64> {
            if self.pending == 0 || !frame_log_due(frame_id) {
                return None;
            }
            Some(std::mem::take(&mut self.pending))
        }
    }

    macro_rules! close_endpoint {
        ($endpoint:expr, $succeeded:expr, $reason:expr) => {{
            $endpoint.close(
                super::host_application_close_code($succeeded).into(),
                $reason,
            );
            $endpoint.wait_idle().await;
        }};
    }

    /// The media lane only receives bounded lifecycle notifications. Input
    /// payloads never cross this channel, so a slow encoder cannot delay XTEST.
    #[derive(Debug, Clone)]
    enum InputWorkerStatus {
        Completed,
        Failed(super::InputLaneFailure),
    }

    const INPUT_STATUS_CAPACITY: usize = 1;

    enum ScheduledWork {
        Shutdown(std::io::Result<()>),
        Media,
        Input(Option<InputWorkerStatus>),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SessionEnd {
        PeerCompleted,
        PeerLost,
        FrameLimit,
        HostShutdown,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ListenerDecision {
        AcceptSuccessor,
        Complete,
        ReconnectCapacityExhausted,
    }

    const fn listener_decision(
        session_end: SessionEnd,
        ended_sessions: u32,
        maximum_sessions: u32,
    ) -> ListenerDecision {
        match session_end {
            SessionEnd::HostShutdown => ListenerDecision::Complete,
            SessionEnd::PeerLost if ended_sessions >= maximum_sessions => {
                ListenerDecision::ReconnectCapacityExhausted
            }
            SessionEnd::PeerCompleted | SessionEnd::PeerLost | SessionEnd::FrameLimit
                if ended_sessions < maximum_sessions =>
            {
                ListenerDecision::AcceptSuccessor
            }
            SessionEnd::PeerCompleted | SessionEnd::FrameLimit => ListenerDecision::Complete,
            SessionEnd::PeerLost => ListenerDecision::ReconnectCapacityExhausted,
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AcceptFailureDisposition {
        RejectAndContinue,
        Fatal,
    }

    pub async fn run(args: &HostArgs) -> Result<(), Box<dyn Error>> {
        // Validate and load all authentication material before creating the
        // network endpoint. A partial or malformed identity never results in
        // a listening socket.
        let (identity_cert, identity_key, peer_cert) = secure_identity_paths(args)?;
        let identity = TlsIdentity::load_der(identity_cert, identity_key)?;
        let peer_certificate = load_certificate_der(peer_cert)?;
        let server_config = mtls_server_config(&identity, &peer_certificate)?;
        let endpoint = bind_server(server_config, args.listen_addr)?;
        let mut stamp_allocator = ProductStampAllocator::new();

        println!("=== LatencyDesk Host ===");
        println!("Mode: TLS 1.3 mutual authentication over QUIC");
        println!("Host certificate: {}", hex(&identity.fingerprint()));
        println!(
            "Expected client certificate: {}",
            hex(&certificate_fingerprint(&peer_certificate))
        );
        println!("Listening securely on {}", endpoint.local_addr()?);
        println!(
            "listener: accepting up to {} secure session(s)",
            args.max_sessions
        );

        let mut ended_sessions = 0_u32;
        loop {
            let pairing_deadline =
                tokio::time::Instant::now() + Duration::from_secs(args.pairing_timeout_secs);
            let mut rejected_connections = 0_u64;
            // Deliberately sequential: only one application-level TLS
            // authentication attempt is alive at a time. The inner timeout starts
            // after Quinn yields an Incoming, while this outer timeout enforces the
            // total pairing deadline including time spent waiting for Initials.
            let connection = loop {
                let now = tokio::time::Instant::now();
                if now >= pairing_deadline {
                    close_endpoint!(endpoint, false, b"peer authentication timed out");
                    return Err(pairing_timeout_error(args, rejected_connections).into());
                }

                match tokio::time::timeout(
                    pairing_deadline.saturating_duration_since(now),
                    accept_exact_peer_with_timeout(
                        &endpoint,
                        &peer_certificate,
                        AUTHENTICATION_ATTEMPT_TIMEOUT,
                    ),
                )
                .await
                {
                    Ok(Ok(connection)) => break connection,
                    Ok(Err(error))
                        if classify_accept_failure(&error) == AcceptFailureDisposition::Fatal =>
                    {
                        close_endpoint!(endpoint, false, b"QUIC listener failed");
                        return Err(format!(
                        "secure QUIC listener failed after rejecting {rejected_connections} unauthenticated connection(s): {error}"
                    )
                    .into());
                    }
                    Ok(Err(error)) => {
                        rejected_connections = rejected_connections.saturating_add(1);
                        if should_log_rejection(rejected_connections) {
                            eprintln!(
                            "mTLS: rejected unauthenticated connection #{rejected_connections}: {error}"
                        );
                        }
                    }
                    Err(_) => {
                        close_endpoint!(endpoint, false, b"peer authentication timed out");
                        return Err(pairing_timeout_error(args, rejected_connections).into());
                    }
                }
            };
            println!(
            "mTLS: exact client certificate authenticated (rejected {rejected_connections} unauthenticated connection(s))"
        );

            // X11 capture and XTEST input are intentionally opened only after the
            // remote certificate has passed exact-byte verification.
            let mut desktop = match X11DesktopSession::open() {
                Ok(desktop) => desktop,
                Err(error) => {
                    close_endpoint!(endpoint, false, b"capture provider initialization failed");
                    return Err(error.into());
                }
            };
            let session_stamp = match stamp_allocator.allocate() {
                Ok(stamp) => stamp,
                Err(error) => {
                    close_endpoint!(endpoint, false, b"session id allocation failed");
                    return Err(error.into());
                }
            };
            let session = match ProductSession::host_with_stamp(connection, session_stamp).await {
                Ok(session) => session,
                Err(error) => {
                    close_endpoint!(endpoint, false, b"product session activation failed");
                    return Err(error.into());
                }
            };
            println!("session: active session_id={}", session_stamp.session_id);
            println!(
            "session-lifecycle: generation={} authorization_epoch={} display_epoch={} codec_epoch={}",
            session_stamp.generation,
            session_stamp.authorization_epoch,
            session_stamp.display_epoch,
            session_stamp.codec_epoch
        );
            let negotiation_result = async {
            let mut control_receiver = tokio::time::timeout(
                AUTHENTICATION_ATTEMPT_TIMEOUT,
                session.accept_control_receiver(),
            )
            .await
            .map_err(|_| "timed out waiting for client codec capabilities")??;
            let capabilities_message = tokio::time::timeout(
                AUTHENTICATION_ATTEMPT_TIMEOUT,
                control_receiver.next_control(),
            )
            .await
            .map_err(|_| "timed out waiting for client codec capabilities")??;
            if capabilities_message.kind != ControlKind::Capabilities {
                return Err(format!(
                    "expected codec capabilities, received {:?}",
                    capabilities_message.kind
                )
                .into());
            }
            let capabilities = VideoCodecCapabilities::decode(&capabilities_message.payload)?;
            let (codec, profile) = select_host_codec(capabilities, true, true)?;
            let max_width = args.max_width.min(capabilities.max_width) & !1;
            let max_height = args.max_height.min(capabilities.max_height) & !1;
            let fps = args.fps.min(capabilities.max_fps);
            let (screen_width, screen_height) = desktop.screen_size();
            let geometry =
                letterbox_geom(screen_width, screen_height, max_width, max_height)?;
            let raw_bitrate_bps = u32::try_from(
                u64::from(geometry.out_width)
                    .saturating_mul(u64::from(geometry.out_height))
                    .saturating_mul(12)
                    .saturating_mul(u64::from(fps)),
            )
            .unwrap_or(u32::MAX)
            .max(1);
            let mut selected_codec = codec;
            let mut selected_profile = profile;
            let mut encoder = None;
            if selected_codec == VideoCodec::H264 {
                match SoftwareH264Encoder::new(
                    geometry.out_width,
                    geometry.out_height,
                    fps,
                    8_000_000,
                    session.stamp().codec_epoch,
                    LowDelayPolicy::baseline(fps.saturating_mul(2)).validate()?,
                ) {
                    Ok(software) => encoder = Some(software),
                    Err(error) if capabilities.offers_nv12() => {
                        eprintln!(
                            "software H.264 encoder unavailable ({error}); falling back to raw NV12"
                        );
                        selected_codec = VideoCodec::RawNv12;
                        selected_profile = VideoProfile::RawNv12;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let target_bitrate_bps = if selected_codec == VideoCodec::H264 {
                8_000_000
            } else {
                raw_bitrate_bps
            };
            let config = VideoStreamConfig {
                contract_version: VIDEO_CODEC_CONTRACT_VERSION,
                codec: selected_codec,
                profile: selected_profile,
                pixel_format: u32::from_le_bytes(*b"NV12"),
                stream_id: 1,
                codec_epoch: session.stamp().codec_epoch,
                width: geometry.out_width,
                height: geometry.out_height,
                fps,
                target_bitrate_bps,
                flags: 0,
            };
            session
                .send_control(ControlKind::ConfigureStream, &config.encode()?)
                .await?;
            println!(
                "codec: negotiated contract v{VIDEO_CODEC_CONTRACT_VERSION} {:?}/{:?} {}x{}@{} target={target_bitrate_bps}bps",
                config.codec, config.profile, config.width, config.height, config.fps
            );
            let capture_plan = CapturePlan {
                stream: config,
                max_width,
                max_height,
            };
            Ok::<_, Box<dyn Error>>((control_receiver, capture_plan, encoder))
        }
        .await;
            let (_control_receiver, capture_plan, mut encoder) = match negotiation_result {
                Ok(negotiated) => negotiated,
                Err(error) => {
                    close_endpoint!(endpoint, false, b"codec negotiation failed");
                    return Err(error);
                }
            };

            let (status_tx, mut status_rx) = mpsc::channel(INPUT_STATUS_CAPACITY);
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let input_session = session.clone();
            let input_epoch = session.stamp().authorization_epoch;
            let input_task = tokio::spawn(async move {
                tokio::pin!(stop_rx);
                let mut input_desktop = match X11DesktopSession::open() {
                    Ok(desktop) => desktop,
                    Err(error) => {
                        let failure = super::InputLaneFailure::new(format!(
                            "input provider initialization failed: {error}"
                        ));
                        let _ = status_tx.try_send(InputWorkerStatus::Failed(failure.clone()));
                        return Err(failure);
                    }
                };
                let mut reconciler = InputReconciler::default();
                let work_result = async {
                    let accepted = tokio::select! {
                        biased;
                        _ = &mut stop_rx => return Ok(()),
                        result = input_session.accept_input_receiver() => result,
                    };
                    let mut receiver = match accepted {
                        Ok(receiver) => receiver,
                        Err(error) if is_clean_session_close(&error) => return Ok(()),
                        Err(error) if error.is_retryable_connection_loss() => {
                            return Err(super::InputLaneFailure::peer_connection_lost(format!(
                                "reliable input lane lost before establishment: {error}"
                            )))
                        }
                        Err(error) => {
                            return Err(super::InputLaneFailure::new(format!(
                                "failed to establish the reliable input lane: {error}"
                            )))
                        }
                    };

                    loop {
                        let next = tokio::select! {
                            biased;
                            _ = &mut stop_rx => return Ok(()),
                            result = receiver.next_input() => result,
                        };
                        match next {
                            Ok(payload) => apply_input(
                                &payload,
                                input_epoch,
                                &mut reconciler,
                                &mut input_desktop,
                            )
                            .map_err(|error| super::InputLaneFailure::new(error.to_string()))?,
                            Err(error) if is_clean_session_close(&error) => return Ok(()),
                            Err(error) if error.is_retryable_connection_loss() => {
                                return Err(super::InputLaneFailure::peer_connection_lost(format!(
                                    "reliable input lane lost its authenticated peer: {error}"
                                )))
                            }
                            Err(error) => {
                                return Err(super::InputLaneFailure::new(format!(
                                    "reliable input lane disconnected: {error}"
                                )))
                            }
                        }
                    }
                }
                .await;

                // Cleanup is deliberately outside every receive/error branch. Once
                // the provider has admitted any state, every terminal path reaches
                // ReleaseAll before a lifecycle status is published.
                let cleanup_result = release_all(&mut reconciler, &mut input_desktop)
                    .map_err(|error| super::InputLaneFailure::new(error.to_string()));
                let final_result = merge_input_worker_results(work_result, cleanup_result);
                let status = match &final_result {
                    Ok(()) => InputWorkerStatus::Completed,
                    Err(error) => InputWorkerStatus::Failed(error.clone()),
                };
                let _ = status_tx.try_send(status);
                final_result
            });
            let stream_result = stream_desktop(
                args,
                &session,
                &mut status_rx,
                &mut desktop,
                capture_plan,
                encoder.as_mut(),
            )
            .await;

            let _ = stop_tx.send(());
            let stream_end = stream_result.as_ref().ok().copied();
            let input_task_result = match input_task.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error))
                    if error.was_observed() || input_failure_is_redundant(stream_end, &error) =>
                {
                    Ok(())
                }
                Ok(Err(error)) => Err(error.into()),
                Err(error) if error.is_cancelled() => {
                    Err("input worker cancelled before cleanup".into())
                }
                Err(error) => Err(format!("reliable input task failed: {error}").into()),
            };
            let shutdown_result = input_task_result;
            let final_result = merge_results(
                stream_result,
                shutdown_result,
                "session shutdown also failed",
            );
            let session_end = match final_result {
                Ok(session_end) => session_end,
                Err(error) => {
                    close_endpoint!(endpoint, false, b"host session failed");
                    return Err(error);
                }
            };
            if session_end != SessionEnd::PeerLost {
                session.close(0, b"host product session complete");
            }
            ended_sessions = ended_sessions.saturating_add(1);
            println!(
                "listener: ended secure session {ended_sessions}/{} ({session_end:?})",
                args.max_sessions
            );
            match listener_decision(session_end, ended_sessions, args.max_sessions) {
                ListenerDecision::AcceptSuccessor => {
                    println!("listener: waiting for authenticated successor session");
                }
                ListenerDecision::Complete => {
                    close_endpoint!(endpoint, true, b"host session sequence ended");
                    return Ok(());
                }
                ListenerDecision::ReconnectCapacityExhausted => {
                    close_endpoint!(endpoint, false, b"reconnect capacity exhausted");
                    return Err(format!(
                        "authenticated peer transport was lost after consuming all {} allowed session(s)",
                        args.max_sessions
                    )
                    .into());
                }
            }
        }
    }

    async fn stream_desktop(
        args: &HostArgs,
        session: &ProductSession,
        status_rx: &mut mpsc::Receiver<InputWorkerStatus>,
        desktop: &mut X11DesktopSession,
        capture_plan: CapturePlan,
        mut encoder: Option<&mut SoftwareH264Encoder>,
    ) -> Result<SessionEnd, Box<dyn Error>> {
        let stream_config = capture_plan.stream;
        let frame_period =
            frame_period(stream_config.fps).ok_or("fps must be positive and nonzero")?;
        let mut ticker = tokio::time::interval(frame_period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);

        let mut frame_id = 0_u64;
        let mut announced_stream = false;
        let mut media_drop_log = MediaDropLog::default();
        let mut raw_access_unit = Vec::with_capacity(
            8_usize.saturating_add(nv12_len(stream_config.width, stream_config.height)),
        );

        loop {
            // Input payloads are serviced by an independent worker. This loop
            // prioritizes its terminal lifecycle signal over the next media
            // tick so peer completion and failures remain prompt as well.
            let work = tokio::select! {
                biased;
                signal_result = &mut shutdown => ScheduledWork::Shutdown(signal_result),
                status = status_rx.recv() => ScheduledWork::Input(status),
                _ = ticker.tick() => ScheduledWork::Media,
            };

            match work {
                ScheduledWork::Shutdown(signal_result) => {
                    signal_result?;
                    println!("shutdown: Ctrl-C requested");
                    return Ok(SessionEnd::HostShutdown);
                }
                ScheduledWork::Input(Some(InputWorkerStatus::Completed)) => {
                    println!("session: peer completed normally");
                    return Ok(SessionEnd::PeerCompleted);
                }
                ScheduledWork::Input(Some(InputWorkerStatus::Failed(error))) => {
                    error.mark_observed();
                    if error.is_retryable_connection_loss() {
                        println!("session: authenticated peer transport lost after ReleaseAll");
                        return Ok(SessionEnd::PeerLost);
                    }
                    return Err(error.into());
                }
                ScheduledWork::Input(None) => {
                    return Err("input worker terminated without lifecycle status".into());
                }
                ScheduledWork::Media => {
                    // Preserve the constraints used during negotiation. Feeding
                    // the even-rounded output dimensions back in as new bounds
                    // can round a second time (for example 224x180 -> 224x178).
                    let (width, height, nv12) =
                        desktop.capture_nv12(capture_plan.max_width, capture_plan.max_height)?;
                    if (width, height) != (stream_config.width, stream_config.height) {
                        return Err(format!(
                            "capture geometry changed from negotiated {}x{} to {width}x{height}",
                            stream_config.width, stream_config.height
                        )
                        .into());
                    }
                    let capture_timestamp_ns = frame_period
                        .as_nanos()
                        .saturating_mul(u128::from(frame_id.saturating_add(1)))
                        as u64;
                    let (frame, is_keyframe, dependency, encoded_frame_id) =
                        if let Some(encoder) = encoder.as_mut() {
                            match encoder.encode_nv12(nv12, capture_timestamp_ns) {
                                Ok(unit) => (
                                    Cow::Owned(unit.bytes),
                                    unit.meta.recovery_point,
                                    unit.meta.dependency_frame_id,
                                    unit.meta.frame_id,
                                ),
                                Err(H264Error::RecoveryPointRequired) => {
                                    encoder.request_idr();
                                    continue;
                                }
                                Err(error) => return Err(error.into()),
                            }
                        } else {
                            frame_id = frame_id.checked_add(1).ok_or("frame id exhausted")?;
                            let keyframe_interval =
                                u64::from(stream_config.fps).saturating_mul(2).max(1);
                            let is_keyframe = frame_id == 1 || frame_id % keyframe_interval == 0;
                            pack_nv12_access_unit_into(width, height, nv12, &mut raw_access_unit);
                            (
                                Cow::Borrowed(raw_access_unit.as_slice()),
                                is_keyframe,
                                (!is_keyframe).then_some(frame_id - 1),
                                frame_id,
                            )
                        };
                    frame_id = encoded_frame_id;
                    let report = match session.send_media_frame(
                        FragmentSpec {
                            kind: MediaKind::Video,
                            flags: if is_keyframe {
                                media_flags::KEYFRAME
                            } else {
                                0
                            },
                            stream_id: stream_config.stream_id,
                            codec_epoch: stream_config.codec_epoch,
                            frame_id,
                            dependency_frame_id: dependency,
                        },
                        &frame,
                        frame_period,
                    ) {
                        Ok(report) => report,
                        Err(error) if is_clean_session_close(&error) => {
                            println!("session: peer completed normally");
                            return Ok(SessionEnd::PeerCompleted);
                        }
                        Err(error) if error.is_retryable_connection_loss() => {
                            println!("session: authenticated peer transport lost");
                            return Ok(SessionEnd::PeerLost);
                        }
                        Err(error) if is_transient_media_send(&error) => {
                            if let Some(encoder) = encoder.as_mut() {
                                encoder.request_idr();
                            }
                            if let Some(dropped) = media_drop_log.record(frame_id) {
                                eprintln!(
                                    "media: dropped {dropped} frame(s) through frame {frame_id}: {error}"
                                );
                            }
                            if args.max_frames.is_some_and(|maximum| frame_id >= maximum) {
                                return Ok(SessionEnd::FrameLimit);
                            }
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };

                    if !announced_stream {
                        let label = if stream_config.codec == VideoCodec::H264 {
                            "H.264 4:2:0"
                        } else {
                            "explicit Raw NV12"
                        };
                        println!("stream: {label} {width}x{height} over QUIC DATAGRAM");
                        announced_stream = true;
                    }
                    if let Some(dropped) = media_drop_log.take_if_due(frame_id) {
                        eprintln!("media: dropped {dropped} frame(s) through frame {frame_id}");
                    }
                    if frame_log_due(frame_id) {
                        println!(
                            "streaming: frame {frame_id} bytes={} fragments={} path_datagram_limit={}",
                            frame.len(),
                            report.fragments_sent,
                            report.path_max_datagram_bytes
                        );
                    }

                    if args.max_frames.is_some_and(|maximum| frame_id >= maximum) {
                        return Ok(SessionEnd::FrameLimit);
                    }
                }
            }
        }
    }

    fn apply_input(
        payload: &[u8],
        expected_input_epoch: u32,
        reconciler: &mut InputReconciler,
        desktop: &mut X11DesktopSession,
    ) -> Result<(), Box<dyn Error>> {
        let message = InputMessage::decode(payload)?;
        if message.session_epoch != expected_input_epoch {
            return Err(format!(
                "input epoch {} does not match authenticated session epoch {expected_input_epoch}",
                message.session_epoch
            )
            .into());
        }

        match reconciler.apply(message)? {
            ReconcileOutcome::Applied(actions) => {
                if let Err((failed_actions, first_error)) =
                    attempt_all_injections(actions, |action| desktop.inject(action))
                {
                    return Err(format!(
                        "input attempted every action but {failed_actions} injections failed; first error: {first_error}"
                    )
                    .into());
                }
            }
            ReconcileOutcome::IgnoredStaleSequence | ReconcileOutcome::IgnoredStaleEpoch => {}
        }
        Ok(())
    }

    fn release_all(
        reconciler: &mut InputReconciler,
        desktop: &mut X11DesktopSession,
    ) -> Result<(), Box<dyn Error>> {
        let actions = reconciler.disconnect_release_plan();
        if let Err((failed_actions, first_error)) =
            attempt_all_injections(actions, |action| desktop.inject(action))
        {
            return Err(format!(
                "ReleaseAll attempted every held input but {failed_actions} injections failed; first error: {first_error}"
            )
            .into());
        }
        println!("input: ReleaseAll applied");
        Ok(())
    }

    fn merge_input_worker_results(
        work: Result<(), super::InputLaneFailure>,
        cleanup: Result<(), super::InputLaneFailure>,
    ) -> Result<(), super::InputLaneFailure> {
        match (work, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(work_error), Err(cleanup_error)) => Err(super::InputLaneFailure::new(format!(
                "{work_error}; input cleanup also failed: {cleanup_error}"
            ))),
        }
    }

    fn input_failure_is_redundant(
        stream_end: Option<SessionEnd>,
        input_error: &super::InputLaneFailure,
    ) -> bool {
        stream_end == Some(SessionEnd::PeerLost) && input_error.is_retryable_connection_loss()
    }

    fn attempt_all_injections<A, E: ToString>(
        actions: impl IntoIterator<Item = A>,
        mut inject: impl FnMut(A) -> Result<(), E>,
    ) -> Result<(), (usize, String)> {
        let mut failed_actions = 0_usize;
        let mut first_error = None;
        for action in actions {
            if let Err(error) = inject(action) {
                failed_actions += 1;
                if first_error.is_none() {
                    first_error = Some(error.to_string());
                }
            }
        }
        match failed_actions {
            0 => Ok(()),
            _ => Err((
                failed_actions,
                first_error.unwrap_or_else(|| "unknown injection error".to_owned()),
            )),
        }
    }

    fn merge_results<T>(
        primary: Result<T, Box<dyn Error>>,
        secondary: Result<(), Box<dyn Error>>,
        secondary_context: &str,
    ) -> Result<T, Box<dyn Error>> {
        match (primary, secondary) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(primary), Err(secondary)) => {
                Err(format!("{primary}; {secondary_context}: {secondary}").into())
            }
        }
    }

    fn classify_accept_failure(error: &IdentityError) -> AcceptFailureDisposition {
        match error {
            IdentityError::QuicTransport(
                QuicTransportError::Connection(_)
                | QuicTransportError::HandshakeTimeout
                | QuicTransportError::MissingPeerIdentity
                | QuicTransportError::UnexpectedPeerIdentity,
            )
            | IdentityError::MissingPeerCertificate
            | IdentityError::PeerCertificateMismatch => AcceptFailureDisposition::RejectAndContinue,
            IdentityError::QuicTransport(
                QuicTransportError::EndpointClosed
                | QuicTransportError::Io(_)
                | QuicTransportError::Connect(_)
                | QuicTransportError::Read(_)
                | QuicTransportError::Write(_)
                | QuicTransportError::ExpiryMismatch { .. }
                | QuicTransportError::Protocol(_)
                | QuicTransportError::DuplicateInboundLane(_)
                | QuicTransportError::StreamKindChanged { .. },
            )
            | IdentityError::InvalidDisplayName(_)
            | IdentityError::Generation(_)
            | IdentityError::InvalidIdentity(_)
            | IdentityError::InvalidPeerCertificate(_)
            | IdentityError::ClientVerifier(_)
            | IdentityError::QuicCrypto(_)
            | IdentityError::FileTooLarge { .. }
            | IdentityError::IdentityPathsMustDiffer
            | IdentityError::NoConnectionCandidates
            | IdentityError::TooManyConnectionCandidates { .. }
            | IdentityError::InvalidConnectionCandidate(_)
            | IdentityError::InvalidConnectionAttemptTimeout
            | IdentityError::ConnectionCandidatesExhausted { .. }
            | IdentityError::ConnectionAttemptTaskFailed
            | IdentityError::InsecurePrivateKeyPermissions { .. }
            | IdentityError::Io { .. } => AcceptFailureDisposition::Fatal,
        }
    }

    fn is_clean_session_close(error: &ProductSessionError) -> bool {
        matches!(
            error,
            ProductSessionError::Quic(transport) if transport.is_clean_application_close()
        )
    }

    fn is_transient_media_send(error: &ProductSessionError) -> bool {
        matches!(
            error,
            ProductSessionError::MediaSendAborted { .. }
                | ProductSessionError::MediaDeadlineOverflow
        )
    }

    const fn should_log_rejection(rejected_connections: u64) -> bool {
        rejected_connections <= 3
    }

    fn pairing_timeout_error(args: &HostArgs, rejected_connections: u64) -> String {
        format!(
            "timed out after {} seconds waiting for the exact pinned client certificate; rejected {rejected_connections} unauthenticated connection(s)",
            args.pairing_timeout_secs
        )
    }

    fn secure_identity_paths(args: &HostArgs) -> Result<(&Path, &Path, &Path), Box<dyn Error>> {
        let mut missing = Vec::new();
        if args.identity_cert.is_none() {
            missing.push("--identity-cert");
        }
        if args.identity_key.is_none() {
            missing.push("--identity-key");
        }
        if args.peer_cert.is_none() {
            missing.push("--peer-cert");
        }
        if !missing.is_empty() {
            return Err(format!(
                "secure QUIC mode requires {}; generate an identity with `latencydesk-identity generate`, exchange only certificates, and pass all three paths",
                missing.join(", ")
            )
            .into());
        }

        Ok((
            args.identity_cert.as_deref().expect("checked above"),
            args.identity_key.as_deref().expect("checked above"),
            args.peer_cert.as_deref().expect("checked above"),
        ))
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn secure_mode_lists_every_missing_identity_path() {
            let error = secure_identity_paths(&HostArgs::default()).expect_err("must fail closed");
            let message = error.to_string();
            assert!(message.contains("--identity-cert"));
            assert!(message.contains("--identity-key"));
            assert!(message.contains("--peer-cert"));
        }

        #[test]
        fn only_the_first_three_rejections_are_logged() {
            assert!(should_log_rejection(1));
            assert!(should_log_rejection(2));
            assert!(should_log_rejection(3));
            assert!(!should_log_rejection(4));
            assert!(!should_log_rejection(u64::MAX));
        }

        #[test]
        fn endpoint_closure_is_fatal_but_peer_identity_failure_is_retryable() {
            let closed = IdentityError::QuicTransport(QuicTransportError::EndpointClosed);
            assert_eq!(
                classify_accept_failure(&closed),
                AcceptFailureDisposition::Fatal
            );
            assert_eq!(
                classify_accept_failure(&IdentityError::MissingPeerCertificate),
                AcceptFailureDisposition::RejectAndContinue
            );
            assert_eq!(
                classify_accept_failure(&IdentityError::PeerCertificateMismatch),
                AcceptFailureDisposition::RejectAndContinue
            );
            assert_eq!(
                classify_accept_failure(&IdentityError::QuicTransport(
                    QuicTransportError::HandshakeTimeout
                )),
                AcceptFailureDisposition::RejectAndContinue
            );
        }

        #[test]
        fn authentication_attempt_timeout_is_shorter_than_total_pairing_limit() {
            assert!(!AUTHENTICATION_ATTEMPT_TIMEOUT.is_zero());
            assert!(AUTHENTICATION_ATTEMPT_TIMEOUT <= Duration::from_secs(3));
            assert!(AUTHENTICATION_ATTEMPT_TIMEOUT < Duration::from_secs(3_600));
        }

        #[test]
        fn input_worker_status_channel_is_bounded() {
            let (sender, _receiver) = mpsc::channel(INPUT_STATUS_CAPACITY);
            assert_eq!(sender.capacity(), INPUT_STATUS_CAPACITY);
            sender
                .try_send(InputWorkerStatus::Completed)
                .expect("one terminal status fits");
            assert!(sender.try_send(InputWorkerStatus::Completed).is_err());
        }

        #[test]
        fn input_worker_cleanup_failure_is_never_hidden() {
            let work = Err(super::super::InputLaneFailure::new("input failed".into()));
            let cleanup = Err(super::super::InputLaneFailure::new("release failed".into()));
            let error = merge_input_worker_results(work, cleanup).expect_err("both fail");
            assert!(error.to_string().contains("input failed"));
            assert!(error.to_string().contains("release failed"));
        }

        #[test]
        fn listener_only_retries_peer_loss_while_capacity_remains() {
            assert_eq!(
                listener_decision(SessionEnd::PeerLost, 1, 2),
                ListenerDecision::AcceptSuccessor
            );
            assert_eq!(
                listener_decision(SessionEnd::PeerLost, 2, 2),
                ListenerDecision::ReconnectCapacityExhausted
            );
            assert_eq!(
                listener_decision(SessionEnd::PeerCompleted, 1, 2),
                ListenerDecision::AcceptSuccessor
            );
            assert_eq!(
                listener_decision(SessionEnd::FrameLimit, 2, 2),
                ListenerDecision::Complete
            );
            assert_eq!(
                listener_decision(SessionEnd::HostShutdown, 1, 2),
                ListenerDecision::Complete
            );
        }

        #[test]
        fn concurrent_media_and_input_peer_loss_is_one_recoverable_terminal_event() {
            let peer_loss = super::super::InputLaneFailure::peer_connection_lost(
                "same timed-out connection".into(),
            );
            let fatal = super::super::InputLaneFailure::new("provider failed".into());

            assert!(input_failure_is_redundant(
                Some(SessionEnd::PeerLost),
                &peer_loss
            ));
            assert!(!input_failure_is_redundant(
                Some(SessionEnd::PeerCompleted),
                &peer_loss
            ));
            assert!(!input_failure_is_redundant(
                Some(SessionEnd::PeerLost),
                &fatal
            ));
        }

        #[test]
        fn media_max_age_is_the_ceiling_of_the_runtime_frame_period() {
            assert_eq!(frame_period(60), Some(Duration::from_nanos(16_666_667)));
            assert_eq!(frame_period(120), Some(Duration::from_nanos(8_333_334)));
            assert_eq!(frame_period(0), None);
        }

        #[test]
        fn media_drop_logging_accumulates_until_the_frame_log_cadence() {
            let mut log = MediaDropLog::default();
            for frame_id in 2..LOG_FRAME_INTERVAL {
                assert_eq!(log.record(frame_id), None);
            }
            assert_eq!(log.record(LOG_FRAME_INTERVAL), Some(LOG_FRAME_INTERVAL - 1));
            assert_eq!(log.record(LOG_FRAME_INTERVAL + 1), None);
            assert_eq!(log.take_if_due(LOG_FRAME_INTERVAL * 2), Some(1));
        }

        #[test]
        fn media_send_abort_does_not_count_as_session_close() {
            use latencydesk_socket_transport::quic::MediaSendOutcome;

            let aborted = ProductSessionError::MediaSendAborted {
                outcome: MediaSendOutcome::DroppedExpired,
                fragments_sent: 1,
                fragments_total: 4,
            };
            assert!(is_transient_media_send(&aborted));
            assert!(!is_clean_session_close(&aborted));
            assert!(is_transient_media_send(
                &ProductSessionError::MediaDeadlineOverflow
            ));
            assert!(!is_transient_media_send(
                &ProductSessionError::InvalidMediaMaxAge
            ));
        }

        #[test]
        fn attempt_all_injections_reports_failures_after_trying_every_action() {
            let mut attempted = Vec::new();
            let result = attempt_all_injections([10, 20, 30], |action| {
                attempted.push(action);
                if action == 10 {
                    Err("lost")
                } else {
                    Ok(())
                }
            });
            assert_eq!(attempted, vec![10, 20, 30]);
            assert_eq!(result, Err((1, "lost".to_owned())));
        }

        #[test]
        fn timeout_error_reports_rejected_connection_count() {
            let args = HostArgs {
                pairing_timeout_secs: 7,
                ..HostArgs::default()
            };
            let message = pairing_timeout_error(&args, 12);
            assert!(message.contains("7 seconds"));
            assert!(message.contains("12 unauthenticated"));
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(windows)]
mod windows {
    use super::HostArgs;
    use bytes::Bytes;
    use latencydesk_h264::LowDelayPolicy;
    use latencydesk_input::{InputMessage, InputReconciler, ReconcileOutcome};
    use latencydesk_platform_windows::{WindowsDdaH264Encoder, WindowsDesktopSession};
    use latencydesk_protocol::{
        media_flags, video_capability_flags, CongestionFeedbackMessage, ControlKind, MediaKind,
        RateUpdateMessage, RecoveryRequest, VideoCodec, VideoCodecCapabilities, VideoProfile,
        VideoStreamConfig, VIDEO_CODEC_CONTRACT_VERSION,
    };
    use latencydesk_session::lifecycle::ProductStampAllocator;
    use latencydesk_socket_transport::identity::{
        accept_exact_peer_with_timeout, certificate_fingerprint, load_certificate_der,
        mtls_server_config, IdentityError, TlsIdentity,
    };
    use latencydesk_socket_transport::product::{ProductSession, ProductSessionError};
    use latencydesk_socket_transport::quic::{bind_server, QuicTransportError};
    use latencydesk_transport::{
        AdaptiveCongestionConfig, AdaptiveCongestionController, FragmentSpec,
    };
    use std::error::Error;
    use std::num::NonZeroU64;
    use std::path::Path;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::MissedTickBehavior;

    const INPUT_CHANNEL_CAPACITY: usize = 64;
    const INPUT_BUDGET_PER_TURN: usize = 8;
    const LOG_FRAME_INTERVAL: u64 = 60;
    const AUTHENTICATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

    const CONTROL_CHANNEL_CAPACITY: usize = 16;
    const INITIAL_VIDEO_BITRATE_BPS: u32 = 15_000_000;
    const LAN_QUALITY_FLOOR_BPS: u32 = 15_000_000;
    const MAX_VIDEO_BITRATE_BPS: u32 = 60_000_000;
    const STREAM_ID: u32 = 1;
    const ENCODER_OUTPUT_POLL: Duration = Duration::from_micros(250);
    fn frame_period(fps: u32) -> Option<Duration> {
        let fps = NonZeroU64::new(u64::from(fps))?;
        Some(Duration::from_nanos(1_000_000_000_u64.div_ceil(fps.get())))
    }

    const fn frame_log_due(frame_id: u64) -> bool {
        frame_id == 1 || frame_id % LOG_FRAME_INTERVAL == 0
    }

    #[derive(Default)]
    struct MediaDropLog {
        pending: u64,
    }

    impl MediaDropLog {
        fn record(&mut self, frame_id: u64) -> Option<u64> {
            self.pending = self.pending.saturating_add(1);
            self.take_if_due(frame_id)
        }

        fn take_if_due(&mut self, frame_id: u64) -> Option<u64> {
            if self.pending == 0 || !frame_log_due(frame_id) {
                return None;
            }
            Some(std::mem::take(&mut self.pending))
        }
    }

    macro_rules! close_endpoint {
        ($endpoint:expr, $succeeded:expr, $reason:expr) => {{
            $endpoint.close(
                super::host_application_close_code($succeeded).into(),
                $reason,
            );
            $endpoint.wait_idle().await;
        }};
    }

    enum InputLaneEvent {
        Payload(Bytes),
        Completed,
        Failed(super::InputLaneFailure),
    }

    enum ControlLaneEvent {
        Recovery(RecoveryRequest),
        Feedback(CongestionFeedbackMessage),
        Completed,
        Failed(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum WorkPriority {
        Media,
        Input,
    }

    impl WorkPriority {
        const fn after_media() -> Self {
            Self::Input
        }

        const fn after_input() -> Self {
            Self::Media
        }
    }

    enum ScheduledWork {
        Shutdown(std::io::Result<()>),
        Media,
        EncoderOutput,
        Input(Option<InputLaneEvent>),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum InputBatchOutcome {
        Continue,
        PeerCompleted,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AcceptFailureDisposition {
        RejectAndContinue,
        Fatal,
    }

    pub async fn run(args: &HostArgs) -> Result<(), Box<dyn Error>> {
        if args.max_sessions != 1 {
            return Err(
                "--max-sessions greater than 1 is currently supported only by the Linux X11 secure Host"
                    .into(),
            );
        }
        let (identity_cert, identity_key, peer_cert) = secure_identity_paths(args)?;
        let identity = TlsIdentity::load_der(identity_cert, identity_key)?;
        let peer_certificate = load_certificate_der(peer_cert)?;
        let server_config = mtls_server_config(&identity, &peer_certificate)?;
        let endpoint = bind_server(server_config, args.listen_addr)?;
        let mut stamp_allocator = ProductStampAllocator::new();

        println!("=== LatencyDesk Host ===");
        println!("Mode: TLS 1.3 mutual authentication over QUIC");
        println!("Host certificate: {}", hex(&identity.fingerprint()));
        println!(
            "Expected client certificate: {}",
            hex(&certificate_fingerprint(&peer_certificate))
        );
        println!("Listening securely on {}", endpoint.local_addr()?);

        let pairing_deadline =
            tokio::time::Instant::now() + Duration::from_secs(args.pairing_timeout_secs);
        let mut rejected_connections = 0_u64;
        let connection = loop {
            let now = tokio::time::Instant::now();
            if now >= pairing_deadline {
                close_endpoint!(endpoint, false, b"peer authentication timed out");
                return Err(pairing_timeout_error(args, rejected_connections).into());
            }

            match tokio::time::timeout(
                pairing_deadline.saturating_duration_since(now),
                accept_exact_peer_with_timeout(
                    &endpoint,
                    &peer_certificate,
                    AUTHENTICATION_ATTEMPT_TIMEOUT,
                ),
            )
            .await
            {
                Ok(Ok(connection)) => break connection,
                Ok(Err(error))
                    if classify_accept_failure(&error) == AcceptFailureDisposition::Fatal =>
                {
                    close_endpoint!(endpoint, false, b"QUIC listener failed");
                    return Err(format!(
                        "secure QUIC listener failed after rejecting {rejected_connections} unauthenticated connection(s): {error}"
                    )
                    .into());
                }
                Ok(Err(error)) => {
                    rejected_connections = rejected_connections.saturating_add(1);
                    if should_log_rejection(rejected_connections) {
                        eprintln!(
                            "mTLS: rejected unauthenticated connection #{rejected_connections}: {error}"
                        );
                    }
                }
                Err(_) => {
                    close_endpoint!(endpoint, false, b"peer authentication timed out");
                    return Err(pairing_timeout_error(args, rejected_connections).into());
                }
            }
        };
        println!(
            "mTLS: exact client certificate authenticated (rejected {rejected_connections} unauthenticated connection(s))"
        );

        let mut desktop = match WindowsDesktopSession::open() {
            Ok(desktop) => desktop,
            Err(error) => {
                close_endpoint!(endpoint, false, b"capture provider initialization failed");
                return Err(error.into());
            }
        };
        let session_stamp = match stamp_allocator.allocate() {
            Ok(stamp) => stamp,
            Err(error) => {
                close_endpoint!(endpoint, false, b"session id allocation failed");
                return Err(error.into());
            }
        };
        let session = match ProductSession::host_with_stamp(connection, session_stamp).await {
            Ok(session) => session,
            Err(error) => {
                close_endpoint!(endpoint, false, b"product session activation failed");
                return Err(error.into());
            }
        };
        println!("session: active session_id={}", session_stamp.session_id);
        println!(
            "session-lifecycle: generation={} authorization_epoch={} display_epoch={} codec_epoch={}",
            session_stamp.generation,
            session_stamp.authorization_epoch,
            session_stamp.display_epoch,
            session_stamp.codec_epoch
        );
        let negotiation_result = async {
            let mut control_receiver = tokio::time::timeout(
                AUTHENTICATION_ATTEMPT_TIMEOUT,
                session.accept_control_receiver(),
            )
            .await
            .map_err(|_| "timed out waiting for client codec capabilities")??;
            let capabilities_message = tokio::time::timeout(
                AUTHENTICATION_ATTEMPT_TIMEOUT,
                control_receiver.next_control(),
            )
            .await
            .map_err(|_| "timed out waiting for client codec capabilities")??;
            if capabilities_message.kind != ControlKind::Capabilities {
                return Err(format!(
                    "expected codec capabilities, received {:?}",
                    capabilities_message.kind
                )
                .into());
            }
            let capabilities = VideoCodecCapabilities::decode(&capabilities_message.payload)?;
            if capabilities.flags & video_capability_flags::H264_HIGH_420 == 0 {
                return Err(
                    "client does not declare H.264 High 4:2:0 hardware decode support".into(),
                );
            }
            let width = args.max_width.min(capabilities.max_width) & !1;
            let height = args.max_height.min(capabilities.max_height) & !1;
            let fps = args.fps.min(capabilities.max_fps);
            let policy = LowDelayPolicy::baseline(fps.saturating_mul(2)).validate()?;
            let video = WindowsDdaH264Encoder::new(
                width,
                height,
                fps,
                INITIAL_VIDEO_BITRATE_BPS,
                session.stamp().codec_epoch,
                policy,
            )
            .map_err(|error| {
                format!(
                    "Windows secure video requires DDA plus a Media Foundation hardware H.264 encoder: {error}"
                )
            })?;
            let stream_config = VideoStreamConfig {
                contract_version: VIDEO_CODEC_CONTRACT_VERSION,
                codec: VideoCodec::H264,
                profile: VideoProfile::H264High420,
                pixel_format: u32::from_le_bytes(*b"NV12"),
                stream_id: STREAM_ID,
                codec_epoch: session.stamp().codec_epoch,
                width,
                height,
                fps,
                target_bitrate_bps: INITIAL_VIDEO_BITRATE_BPS,
                flags: 0,
            };
            session
                .send_control(ControlKind::ConfigureStream, &stream_config.encode()?)
                .await?;
            println!(
                "codec: negotiated contract v{VIDEO_CODEC_CONTRACT_VERSION} H.264 High 4:2:0 {width}x{height}@{fps} target={INITIAL_VIDEO_BITRATE_BPS}bps"
            );
            Ok::<_, Box<dyn Error>>((control_receiver, video))
        }
        .await;
        let (mut control_receiver, mut video) = match negotiation_result {
            Ok(negotiated) => negotiated,
            Err(error) => {
                close_endpoint!(endpoint, false, b"codec negotiation failed");
                return Err(error);
            }
        };

        let (control_tx, mut control_rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let control_task = tokio::spawn(async move {
            loop {
                let event = match control_receiver.next_control().await {
                    Ok(message) if message.kind == ControlKind::RecoveryRequest => {
                        RecoveryRequest::decode(&message.payload)
                            .map(ControlLaneEvent::Recovery)
                            .map_err(|error| error.to_string())
                    }
                    Ok(message) if message.kind == ControlKind::CongestionFeedback => {
                        CongestionFeedbackMessage::decode(&message.payload)
                            .map(ControlLaneEvent::Feedback)
                            .map_err(|error| error.to_string())
                    }
                    Ok(message) => Err(format!(
                        "unexpected client control message {:?}",
                        message.kind
                    )),
                    Err(error) if is_clean_session_close(&error) => {
                        let _ = control_tx.send(ControlLaneEvent::Completed).await;
                        return;
                    }
                    Err(error) => Err(error.to_string()),
                };
                match event {
                    Ok(event) => {
                        if control_tx.send(event).await.is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = control_tx.send(ControlLaneEvent::Failed(error)).await;
                        return;
                    }
                }
            }
        });

        let (input_tx, mut input_rx) = mpsc::channel(INPUT_CHANNEL_CAPACITY);
        let input_session = session.clone();
        let input_task = tokio::spawn(async move {
            let mut receiver = match input_session.accept_input_receiver().await {
                Ok(receiver) => receiver,
                Err(error) if is_clean_session_close(&error) => {
                    let _ = input_tx.send(InputLaneEvent::Completed).await;
                    return Ok(());
                }
                Err(error) => {
                    let failure = super::InputLaneFailure::new(format!(
                        "failed to establish the reliable input lane: {error}"
                    ));
                    let _ = input_tx.try_send(InputLaneEvent::Failed(failure.clone()));
                    return Err(failure);
                }
            };

            loop {
                match receiver.next_input().await {
                    Ok(payload) => {
                        if input_tx
                            .send(InputLaneEvent::Payload(payload))
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    Err(error) if is_clean_session_close(&error) => {
                        let _ = input_tx.send(InputLaneEvent::Completed).await;
                        return Ok(());
                    }
                    Err(error) => {
                        let failure = super::InputLaneFailure::new(format!(
                            "reliable input lane disconnected: {error}"
                        ));
                        let _ = input_tx.try_send(InputLaneEvent::Failed(failure.clone()));
                        return Err(failure);
                    }
                }
            }
        });

        let mut reconciler = InputReconciler::default();
        let stream_result = stream_desktop(
            args,
            &session,
            &mut input_rx,
            &mut control_rx,
            &mut reconciler,
            &mut desktop,
            &mut video,
        )
        .await;
        control_task.abort();

        input_task.abort();
        let input_task_result = match input_task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.was_observed() => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(format!("reliable input task failed: {error}").into()),
        };
        let release_result = release_all(&mut reconciler, &mut desktop);
        let shutdown_result = merge_results(
            input_task_result,
            release_result,
            "input cleanup also failed",
        );
        let final_result = merge_results(
            stream_result,
            shutdown_result,
            "session shutdown also failed",
        );
        let succeeded = final_result.is_ok();
        let close_reason: &[u8] = if succeeded {
            b"host session ended"
        } else {
            b"host session failed"
        };
        close_endpoint!(endpoint, succeeded, close_reason);
        final_result
    }

    async fn stream_desktop(
        args: &HostArgs,
        session: &ProductSession,
        input_rx: &mut mpsc::Receiver<InputLaneEvent>,
        control_rx: &mut mpsc::Receiver<ControlLaneEvent>,
        reconciler: &mut InputReconciler,
        desktop: &mut WindowsDesktopSession,
        video: &mut WindowsDdaH264Encoder,
    ) -> Result<(), Box<dyn Error>> {
        let frame_period = frame_period(args.fps).ok_or("fps must be positive and nonzero")?;
        let mut ticker = tokio::time::interval(frame_period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);

        let mut congestion = AdaptiveCongestionController::new(AdaptiveCongestionConfig {
            min_bitrate_bps: LAN_QUALITY_FLOOR_BPS,
            max_bitrate_bps: MAX_VIDEO_BITRATE_BPS,
            initial_bitrate_bps: INITIAL_VIDEO_BITRATE_BPS,
            min_fps: 15,
            max_fps: 120,
            initial_fps: args.fps.clamp(15, 120),
            ..AdaptiveCongestionConfig::default()
        })?;
        let feedback_clock = std::time::Instant::now();
        let expected_input_epoch = session.stamp().authorization_epoch;
        let mut announced_stream = false;
        let mut priority = WorkPriority::Input;
        let mut media_drop_log = MediaDropLog::default();

        loop {
            while let Ok(event) = control_rx.try_recv() {
                match event {
                    ControlLaneEvent::Recovery(request)
                        if request.stream_id == STREAM_ID
                            && request.codec_epoch == session.stamp().codec_epoch =>
                    {
                        video.request_idr()?;
                        println!(
                            "recovery: force IDR after missing frame {} (last_good={})",
                            request.first_missing_frame_id, request.last_good_frame_id
                        );
                    }
                    ControlLaneEvent::Recovery(request) => {
                        return Err(format!(
                            "recovery request targets stale stream/epoch stream={} epoch={}",
                            request.stream_id, request.codec_epoch
                        )
                        .into());
                    }
                    ControlLaneEvent::Feedback(feedback) => {
                        let decision = congestion.on_sample(
                            u64::from(feedback.rtt_ns),
                            feedback.loss_per_million,
                            u64::from(feedback.jitter_ns),
                            u64::try_from(feedback_clock.elapsed().as_nanos()).unwrap_or(u64::MAX),
                        );
                        video.update_bitrate(decision.target_bitrate_bps)?;
                        if decision.force_keyframe {
                            video.request_idr()?;
                        }
                        if decision.requires_codec_reconfigure || decision.force_keyframe {
                            let update = RateUpdateMessage {
                                stream_id: STREAM_ID,
                                codec_epoch: session.stamp().codec_epoch,
                                target_bitrate_bps: decision.target_bitrate_bps,
                                max_bitrate_bps: decision.max_bitrate_bps,
                                target_fps: decision.target_fps,
                                flags: if decision.force_keyframe {
                                    latencydesk_protocol::rate_flags::FORCE_KEYFRAME
                                } else {
                                    0
                                },
                            };
                            session
                                .send_control(ControlKind::RateUpdate, &update.encode())
                                .await?;
                            println!(
                                "adaptation: bitrate={}bps rtt={}ns loss_ppm={} force_idr={}",
                                decision.target_bitrate_bps,
                                decision.smoothed_rtt_ns,
                                decision.smoothed_loss_million,
                                decision.force_keyframe
                            );
                        }
                    }
                    ControlLaneEvent::Completed => {
                        println!("session: peer completed normally");
                        return Ok(());
                    }
                    ControlLaneEvent::Failed(error) => {
                        return Err(format!("reliable control lane failed: {error}").into());
                    }
                }
            }

            let work = match priority {
                WorkPriority::Media => tokio::select! {
                    biased;
                    signal_result = &mut shutdown => ScheduledWork::Shutdown(signal_result),
                    _ = ticker.tick() => ScheduledWork::Media,
                    _ = tokio::time::sleep(ENCODER_OUTPUT_POLL), if video.has_pending_output() => ScheduledWork::EncoderOutput,
                    input = input_rx.recv() => ScheduledWork::Input(input),
                },
                WorkPriority::Input => tokio::select! {
                    biased;
                    signal_result = &mut shutdown => ScheduledWork::Shutdown(signal_result),
                    input = input_rx.recv() => ScheduledWork::Input(input),
                    _ = tokio::time::sleep(ENCODER_OUTPUT_POLL), if video.has_pending_output() => ScheduledWork::EncoderOutput,
                    _ = ticker.tick() => ScheduledWork::Media,
                },
            };

            match work {
                ScheduledWork::Shutdown(signal_result) => {
                    signal_result?;
                    println!("shutdown: Ctrl-C requested");
                    return Ok(());
                }
                ScheduledWork::Input(Some(first)) => {
                    match service_input_batch(
                        first,
                        input_rx,
                        expected_input_epoch,
                        reconciler,
                        desktop,
                    )
                    .await?
                    {
                        InputBatchOutcome::Continue => {
                            priority = WorkPriority::after_input();
                        }
                        InputBatchOutcome::PeerCompleted => {
                            println!("session: peer completed normally");
                            return Ok(());
                        }
                    }
                }
                ScheduledWork::Input(None) => {
                    return Err("reliable input lane task terminated unexpectedly".into());
                }
                ScheduledWork::Media | ScheduledWork::EncoderOutput => {
                    let frame = match work {
                        ScheduledWork::Media => video.poll_access_unit()?,
                        ScheduledWork::EncoderOutput => video.poll_pending_access_unit()?,
                        _ => unreachable!("media arm accepts only media work"),
                    };
                    if frame.is_none() && video.has_pending_output() {
                        // Media Foundation completes asynchronous transforms on
                        // a provider thread. Yield this OS time slice after a
                        // miss so aggressive low-latency polling cannot starve
                        // the very worker that produces the output.
                        std::thread::yield_now();
                    }
                    let Some(frame) = frame else {
                        let recovery_drops = video.take_recovery_output_drops();
                        if recovery_drops != 0 {
                            eprintln!(
                                "media: dropped {recovery_drops} dependent encoded AU(s) while awaiting forced IDR"
                            );
                        }
                        priority = WorkPriority::after_media();
                        continue;
                    };
                    let frame_id = frame.meta.frame_id;
                    let report = match session.send_media_frame(
                        FragmentSpec {
                            kind: MediaKind::Video,
                            flags: if frame.meta.recovery_point {
                                media_flags::KEYFRAME
                            } else {
                                0
                            },
                            stream_id: STREAM_ID,
                            codec_epoch: frame.meta.codec_epoch,
                            frame_id,
                            dependency_frame_id: frame.meta.dependency_frame_id,
                        },
                        &frame.bytes,
                        frame_period,
                    ) {
                        Ok(report) => report,
                        Err(error) if is_clean_session_close(&error) => {
                            println!("session: peer completed normally");
                            return Ok(());
                        }
                        Err(error) if is_transient_media_send(&error) => {
                            video.note_encoded_but_unsent()?;
                            if let Some(dropped) = media_drop_log.record(frame_id) {
                                eprintln!(
                                    "media: dropped {dropped} H.264 AU(s) through frame {frame_id}; next output forced IDR: {error}"
                                );
                            }
                            if args.max_frames.is_some_and(|maximum| frame_id >= maximum) {
                                return Ok(());
                            }
                            priority = WorkPriority::after_media();
                            continue;
                        }
                        Err(error) => {
                            video.note_encoded_but_unsent()?;
                            return Err(error.into());
                        }
                    };

                    if !announced_stream {
                        println!(
                            "stream: H.264 High 4:2:0 {}x{} over QUIC DATAGRAM (raw NV12 disabled)",
                            frame.width, frame.height
                        );
                        announced_stream = true;
                    }
                    if let Some(dropped) = media_drop_log.take_if_due(frame_id) {
                        eprintln!("media: dropped {dropped} H.264 AU(s) through frame {frame_id}");
                    }
                    if frame_log_due(frame_id) {
                        println!(
                            "streaming: H.264 AU frame={frame_id} bytes={} keyframe={} dependency={:?} capture_sequence={} encode_submit_to_collect_us={} encode_output_poll_misses={} fragments={} path_datagram_limit={}",
                            frame.bytes.len(),
                            frame.meta.recovery_point,
                            frame.meta.dependency_frame_id,
                            frame.capture_sequence,
                            frame.encode_submit_to_collect_ns / 1_000,
                            frame.encode_output_poll_misses,
                            report.fragments_sent,
                            report.path_max_datagram_bytes
                        );
                    }

                    if args.max_frames.is_some_and(|maximum| frame_id >= maximum) {
                        return Ok(());
                    }
                    priority = WorkPriority::after_media();
                }
            }
        }
    }

    async fn service_input_batch(
        first: InputLaneEvent,
        input_rx: &mut mpsc::Receiver<InputLaneEvent>,
        expected_input_epoch: u32,
        reconciler: &mut InputReconciler,
        desktop: &mut WindowsDesktopSession,
    ) -> Result<InputBatchOutcome, Box<dyn Error>> {
        let (events, disconnected) = take_ready_input_batch(first, input_rx);
        for event in events {
            match event {
                InputLaneEvent::Payload(payload) => {
                    apply_input(&payload, expected_input_epoch, reconciler, desktop)?;
                }
                InputLaneEvent::Completed => return Ok(InputBatchOutcome::PeerCompleted),
                InputLaneEvent::Failed(error) => {
                    error.mark_observed();
                    return Err(error.into());
                }
            }
        }
        if disconnected {
            return Err("reliable input lane task terminated unexpectedly".into());
        }
        tokio::task::yield_now().await;
        Ok(InputBatchOutcome::Continue)
    }

    fn take_ready_input_batch(
        first: InputLaneEvent,
        input_rx: &mut mpsc::Receiver<InputLaneEvent>,
    ) -> (Vec<InputLaneEvent>, bool) {
        let mut events = Vec::with_capacity(INPUT_BUDGET_PER_TURN);
        events.push(first);
        let mut disconnected = false;
        while events.len() < INPUT_BUDGET_PER_TURN {
            match input_rx.try_recv() {
                Ok(event) => events.push(event),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        (events, disconnected)
    }

    fn apply_input(
        payload: &[u8],
        expected_input_epoch: u32,
        reconciler: &mut InputReconciler,
        desktop: &mut WindowsDesktopSession,
    ) -> Result<(), Box<dyn Error>> {
        let message = InputMessage::decode(payload)?;
        if message.session_epoch != expected_input_epoch {
            return Err(format!(
                "input epoch {} does not match authenticated session epoch {expected_input_epoch}",
                message.session_epoch
            )
            .into());
        }

        match reconciler.apply(message)? {
            ReconcileOutcome::Applied(actions) => {
                if let Err((failed_actions, first_error)) =
                    attempt_all_injections(actions, |action| desktop.inject(action))
                {
                    return Err(format!(
                        "input attempted every action but {failed_actions} injections failed; first error: {first_error}"
                    )
                    .into());
                }
            }
            ReconcileOutcome::IgnoredStaleSequence | ReconcileOutcome::IgnoredStaleEpoch => {}
        }
        Ok(())
    }

    fn release_all(
        reconciler: &mut InputReconciler,
        desktop: &mut WindowsDesktopSession,
    ) -> Result<(), Box<dyn Error>> {
        let actions = reconciler.disconnect_release_plan();
        if let Err((failed_actions, first_error)) =
            attempt_all_injections(actions, |action| desktop.inject(action))
        {
            return Err(format!(
                "ReleaseAll attempted every held input but {failed_actions} injections failed; first error: {first_error}"
            )
            .into());
        }
        println!("input: ReleaseAll applied");
        Ok(())
    }

    fn attempt_all_injections<A, E: ToString>(
        actions: impl IntoIterator<Item = A>,
        mut inject: impl FnMut(A) -> Result<(), E>,
    ) -> Result<(), (usize, String)> {
        let mut failed_actions = 0_usize;
        let mut first_error = None;
        for action in actions {
            if let Err(error) = inject(action) {
                failed_actions += 1;
                if first_error.is_none() {
                    first_error = Some(error.to_string());
                }
            }
        }
        match failed_actions {
            0 => Ok(()),
            _ => Err((
                failed_actions,
                first_error.unwrap_or_else(|| "unknown injection error".to_owned()),
            )),
        }
    }

    fn merge_results(
        primary: Result<(), Box<dyn Error>>,
        secondary: Result<(), Box<dyn Error>>,
        secondary_context: &str,
    ) -> Result<(), Box<dyn Error>> {
        match (primary, secondary) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(primary), Err(secondary)) => {
                Err(format!("{primary}; {secondary_context}: {secondary}").into())
            }
        }
    }

    fn classify_accept_failure(error: &IdentityError) -> AcceptFailureDisposition {
        match error {
            IdentityError::QuicTransport(
                QuicTransportError::Connection(_)
                | QuicTransportError::HandshakeTimeout
                | QuicTransportError::MissingPeerIdentity
                | QuicTransportError::UnexpectedPeerIdentity,
            )
            | IdentityError::MissingPeerCertificate
            | IdentityError::PeerCertificateMismatch => AcceptFailureDisposition::RejectAndContinue,
            IdentityError::QuicTransport(
                QuicTransportError::EndpointClosed
                | QuicTransportError::Io(_)
                | QuicTransportError::Connect(_)
                | QuicTransportError::Read(_)
                | QuicTransportError::Write(_)
                | QuicTransportError::ExpiryMismatch { .. }
                | QuicTransportError::Protocol(_)
                | QuicTransportError::DuplicateInboundLane(_)
                | QuicTransportError::StreamKindChanged { .. },
            )
            | IdentityError::InvalidDisplayName(_)
            | IdentityError::Generation(_)
            | IdentityError::InvalidIdentity(_)
            | IdentityError::InvalidPeerCertificate(_)
            | IdentityError::ClientVerifier(_)
            | IdentityError::QuicCrypto(_)
            | IdentityError::FileTooLarge { .. }
            | IdentityError::IdentityPathsMustDiffer
            | IdentityError::NoConnectionCandidates
            | IdentityError::TooManyConnectionCandidates { .. }
            | IdentityError::InvalidConnectionCandidate(_)
            | IdentityError::InvalidConnectionAttemptTimeout
            | IdentityError::ConnectionCandidatesExhausted { .. }
            | IdentityError::ConnectionAttemptTaskFailed
            | IdentityError::InsecureWindowsPrivateKeyAcl { .. }
            | IdentityError::WindowsAclCommandFailed { .. }
            | IdentityError::Io { .. } => AcceptFailureDisposition::Fatal,
        }
    }

    fn is_clean_session_close(error: &ProductSessionError) -> bool {
        matches!(
            error,
            ProductSessionError::Quic(transport) if transport.is_clean_application_close()
        )
    }

    fn is_transient_media_send(error: &ProductSessionError) -> bool {
        matches!(
            error,
            ProductSessionError::MediaSendAborted { .. }
                | ProductSessionError::MediaDeadlineOverflow
        )
    }

    const fn should_log_rejection(rejected_connections: u64) -> bool {
        rejected_connections <= 3
    }

    fn pairing_timeout_error(args: &HostArgs, rejected_connections: u64) -> String {
        format!(
            "timed out after {} seconds waiting for the exact pinned client certificate; rejected {rejected_connections} unauthenticated connection(s)",
            args.pairing_timeout_secs
        )
    }

    fn secure_identity_paths(args: &HostArgs) -> Result<(&Path, &Path, &Path), Box<dyn Error>> {
        let mut missing = Vec::new();
        if args.identity_cert.is_none() {
            missing.push("--identity-cert");
        }
        if args.identity_key.is_none() {
            missing.push("--identity-key");
        }
        if args.peer_cert.is_none() {
            missing.push("--peer-cert");
        }
        if !missing.is_empty() {
            return Err(format!(
                "secure QUIC mode requires {}; generate an identity with `latencydesk-identity generate`, exchange only certificates, and pass all three paths",
                missing.join(", ")
            )
            .into());
        }

        Ok((
            args.identity_cert.as_deref().expect("checked above"),
            args.identity_key.as_deref().expect("checked above"),
            args.peer_cert.as_deref().expect("checked above"),
        ))
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn secure_mode_lists_every_missing_identity_path() {
            let error = secure_identity_paths(&HostArgs::default()).expect_err("must fail closed");
            let message = error.to_string();
            assert!(message.contains("--identity-cert"));
            assert!(message.contains("--identity-key"));
            assert!(message.contains("--peer-cert"));
        }

        #[tokio::test]
        async fn secure_mode_rejects_missing_identity_before_useful_work() {
            let error = run(&HostArgs::default())
                .await
                .expect_err("missing identity must fail closed");
            let message = error.to_string();
            assert!(message.contains("--identity-cert"));
            assert!(message.contains("--identity-key"));
            assert!(message.contains("--peer-cert"));
            assert!(!message.contains("before opening a socket"));
            assert!(!message.to_ascii_lowercase().contains("gdi"));
        }

        #[test]
        fn only_the_first_three_rejections_are_logged() {
            assert!(should_log_rejection(1));
            assert!(should_log_rejection(2));
            assert!(should_log_rejection(3));
            assert!(!should_log_rejection(4));
            assert!(!should_log_rejection(u64::MAX));
        }

        #[test]
        fn endpoint_closure_is_fatal_but_peer_identity_failure_is_retryable() {
            let closed = IdentityError::QuicTransport(QuicTransportError::EndpointClosed);
            assert_eq!(
                classify_accept_failure(&closed),
                AcceptFailureDisposition::Fatal
            );
            assert_eq!(
                classify_accept_failure(&IdentityError::MissingPeerCertificate),
                AcceptFailureDisposition::RejectAndContinue
            );
            assert_eq!(
                classify_accept_failure(&IdentityError::PeerCertificateMismatch),
                AcceptFailureDisposition::RejectAndContinue
            );
            assert_eq!(
                classify_accept_failure(&IdentityError::QuicTransport(
                    QuicTransportError::HandshakeTimeout
                )),
                AcceptFailureDisposition::RejectAndContinue
            );
        }

        #[test]
        fn authentication_attempt_timeout_is_shorter_than_total_pairing_limit() {
            assert!(!AUTHENTICATION_ATTEMPT_TIMEOUT.is_zero());
            assert!(AUTHENTICATION_ATTEMPT_TIMEOUT <= Duration::from_secs(3));
            assert!(AUTHENTICATION_ATTEMPT_TIMEOUT < Duration::from_secs(3_600));
        }

        #[tokio::test]
        async fn ready_input_batch_never_exceeds_budget() {
            let (sender, mut receiver) = mpsc::channel(INPUT_CHANNEL_CAPACITY);
            for sequence in 0..(INPUT_BUDGET_PER_TURN + 3) {
                sender
                    .send(InputLaneEvent::Payload(Bytes::from(vec![sequence as u8])))
                    .await
                    .expect("queue input");
            }

            let first = receiver.recv().await.expect("first input");
            let (batch, disconnected) = take_ready_input_batch(first, &mut receiver);
            assert_eq!(batch.len(), INPUT_BUDGET_PER_TURN);
            assert!(!disconnected);
            assert_eq!(receiver.len(), 3);
        }

        #[test]
        fn ready_work_priority_alternates_deterministically() {
            assert_eq!(WorkPriority::after_input(), WorkPriority::Media);
            assert_eq!(WorkPriority::after_media(), WorkPriority::Input);
        }

        #[test]
        fn media_max_age_is_the_ceiling_of_the_runtime_frame_period() {
            assert_eq!(frame_period(60), Some(Duration::from_nanos(16_666_667)));
            assert_eq!(frame_period(120), Some(Duration::from_nanos(8_333_334)));
            assert_eq!(frame_period(0), None);
        }

        #[test]
        fn media_drop_logging_accumulates_until_the_frame_log_cadence() {
            let mut log = MediaDropLog::default();
            for frame_id in 2..LOG_FRAME_INTERVAL {
                assert_eq!(log.record(frame_id), None);
            }
            assert_eq!(log.record(LOG_FRAME_INTERVAL), Some(LOG_FRAME_INTERVAL - 1));
            assert_eq!(log.record(LOG_FRAME_INTERVAL + 1), None);
            assert_eq!(log.take_if_due(LOG_FRAME_INTERVAL * 2), Some(1));
        }

        #[test]
        fn media_send_abort_does_not_count_as_session_close() {
            use latencydesk_socket_transport::quic::MediaSendOutcome;

            let aborted = ProductSessionError::MediaSendAborted {
                outcome: MediaSendOutcome::DroppedExpired,
                fragments_sent: 1,
                fragments_total: 4,
            };
            assert!(is_transient_media_send(&aborted));
            assert!(!is_clean_session_close(&aborted));
            assert!(is_transient_media_send(
                &ProductSessionError::MediaDeadlineOverflow
            ));
            assert!(!is_transient_media_send(
                &ProductSessionError::InvalidMediaMaxAge
            ));
        }

        #[test]
        fn first_inject_failure_still_attempts_remaining_actions() {
            let mut attempted = Vec::new();
            let result = attempt_all_injections([10, 20, 30], |action| {
                attempted.push(action);
                if action == 10 {
                    Err("lost")
                } else {
                    Ok(())
                }
            });
            assert_eq!(attempted, vec![10, 20, 30]);
            assert_eq!(result, Err((1, "lost".to_owned())));
        }

        #[test]
        fn timeout_error_reports_rejected_connection_count() {
            let args = HostArgs {
                pairing_timeout_secs: 7,
                ..HostArgs::default()
            };
            let message = pairing_timeout_error(&args, 12);
            assert!(message.contains("7 seconds"));
            assert!(message.contains("12 unauthenticated"));
        }
    }
}

#[cfg(windows)]
pub use windows::run;

#[cfg(all(test, not(any(target_os = "linux", windows))))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn secure_mode_rejects_unsupported_platform_before_configuration() {
        let error = run(&HostArgs::default())
            .await
            .expect_err("unsupported platform must fail closed");
        assert!(error.to_string().contains("before opening a socket"));
    }
}
