//! Fail-closed product host path over exact-certificate mutual TLS and QUIC.

use super::HostArgs;
#[cfg(not(target_os = "linux"))]
use std::error::Error;

#[cfg(not(target_os = "linux"))]
const UNSUPPORTED_PLATFORM: &str = "secure hosting is currently supported only on Linux X11; Windows and other platforms are rejected before opening a socket because their product capture/input providers are not implemented (use --unsafe-udp-lab only for isolated compatibility testing)";

/// Runs the secure product path. Unsupported platforms fail before loading
/// credentials, creating a socket, or opening a capture/input provider.
#[cfg(not(target_os = "linux"))]
pub async fn run(_args: &HostArgs) -> Result<(), Box<dyn Error>> {
    Err(UNSUPPORTED_PLATFORM.into())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::HostArgs;
    use bytes::Bytes;
    use latencydesk_input::{InputMessage, InputReconciler, ReconcileOutcome};
    use latencydesk_platform_linux::{pack_nv12_access_unit, X11DesktopSession};
    use latencydesk_protocol::{media_flags, MediaKind};
    use latencydesk_socket_transport::identity::{
        accept_exact_peer_with_timeout, certificate_fingerprint, load_certificate_der,
        mtls_server_config, IdentityError, TlsIdentity,
    };
    use latencydesk_socket_transport::product::{ProductSession, ProductSessionError};
    use latencydesk_socket_transport::quic::{bind_server, QuicTransportError};
    use latencydesk_transport::FragmentSpec;
    use std::error::Error;
    use std::num::NonZeroU64;
    use std::path::Path;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::MissedTickBehavior;

    const MEDIA_MAX_AGE: Duration = Duration::from_millis(250);
    const INPUT_CHANNEL_CAPACITY: usize = 64;
    const INPUT_BUDGET_PER_TURN: usize = 8;
    const LOG_FRAME_INTERVAL: u64 = 60;
    const AUTHENTICATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

    macro_rules! close_endpoint {
        ($endpoint:expr, $reason:expr) => {{
            $endpoint.close(0_u32.into(), $reason);
            $endpoint.wait_idle().await;
        }};
    }

    enum InputLaneEvent {
        Payload(Bytes),
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
        // Validate and load all authentication material before creating the
        // network endpoint. A partial or malformed identity never results in
        // a listening socket.
        let (identity_cert, identity_key, peer_cert) = secure_identity_paths(args)?;
        let identity = TlsIdentity::load_der(identity_cert, identity_key)?;
        let peer_certificate = load_certificate_der(peer_cert)?;
        let server_config = mtls_server_config(&identity, &peer_certificate)?;
        let endpoint = bind_server(server_config, args.listen_addr)?;

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
        // Deliberately sequential: only one application-level TLS
        // authentication attempt is alive at a time. The inner timeout starts
        // after Quinn yields an Incoming, while this outer timeout enforces the
        // total pairing deadline including time spent waiting for Initials.
        let connection = loop {
            let now = tokio::time::Instant::now();
            if now >= pairing_deadline {
                close_endpoint!(endpoint, b"peer authentication timed out");
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
                    close_endpoint!(endpoint, b"QUIC listener failed");
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
                    close_endpoint!(endpoint, b"peer authentication timed out");
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
                close_endpoint!(endpoint, b"capture provider initialization failed");
                return Err(error.into());
            }
        };
        let session_id = match NonZeroU64::new(super::super::assign_session_id()) {
            Some(session_id) => session_id,
            None => {
                close_endpoint!(endpoint, b"session id allocation failed");
                return Err("failed to allocate a nonzero session id".into());
            }
        };
        let session = match ProductSession::host(connection, session_id).await {
            Ok(session) => session,
            Err(error) => {
                close_endpoint!(endpoint, b"product session activation failed");
                return Err(error.into());
            }
        };
        println!("session: active session_id={session_id}");

        let (input_tx, mut input_rx) = mpsc::channel(INPUT_CHANNEL_CAPACITY);
        let input_session = session.clone();
        let input_task = tokio::spawn(async move {
            let mut receiver = match input_session.accept_input_receiver().await {
                Ok(receiver) => receiver,
                Err(error) if is_clean_session_close(&error) => {
                    let _ = input_tx.send(InputLaneEvent::Completed).await;
                    return;
                }
                Err(error) => {
                    let _ = input_tx
                        .send(InputLaneEvent::Failed(format!(
                            "failed to establish the reliable input lane: {error}"
                        )))
                        .await;
                    return;
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
                            return;
                        }
                    }
                    Err(error) if is_clean_session_close(&error) => {
                        let _ = input_tx.send(InputLaneEvent::Completed).await;
                        return;
                    }
                    Err(error) => {
                        let _ = input_tx
                            .send(InputLaneEvent::Failed(format!(
                                "reliable input lane disconnected: {error}"
                            )))
                            .await;
                        return;
                    }
                }
            }
        });

        let mut reconciler = InputReconciler::default();
        let stream_result =
            stream_desktop(args, &session, &mut input_rx, &mut reconciler, &mut desktop).await;

        input_task.abort();
        let input_task_result = match input_task.await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(format!("reliable input task failed: {error}").into()),
        };
        let release_result = release_all(&mut reconciler, &mut desktop);
        close_endpoint!(endpoint, b"host session ended");

        let shutdown_result = merge_results(
            input_task_result,
            release_result,
            "input cleanup also failed",
        );
        merge_results(
            stream_result,
            shutdown_result,
            "session shutdown also failed",
        )
    }

    async fn stream_desktop(
        args: &HostArgs,
        session: &ProductSession,
        input_rx: &mut mpsc::Receiver<InputLaneEvent>,
        reconciler: &mut InputReconciler,
        desktop: &mut X11DesktopSession,
    ) -> Result<(), Box<dyn Error>> {
        let frame_period = Duration::from_nanos(
            1_000_000_000_u64
                .checked_div(u64::from(args.fps))
                .ok_or("fps must be positive and nonzero")?,
        );
        let mut ticker = tokio::time::interval(frame_period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);

        let expected_input_epoch = session.stamp().authorization_epoch;
        let mut frame_id = 0_u64;
        let mut announced_stream = false;
        let mut priority = WorkPriority::Input;

        loop {
            // Shutdown is first in both biased selections. When media and
            // input are simultaneously ready, alternate their priority so a
            // permanently full input channel cannot starve video and an
            // overloaded capture path cannot starve input completion.
            let work = match priority {
                WorkPriority::Media => tokio::select! {
                    biased;
                    signal_result = &mut shutdown => ScheduledWork::Shutdown(signal_result),
                    _ = ticker.tick() => ScheduledWork::Media,
                    input = input_rx.recv() => ScheduledWork::Input(input),
                },
                WorkPriority::Input => tokio::select! {
                    biased;
                    signal_result = &mut shutdown => ScheduledWork::Shutdown(signal_result),
                    input = input_rx.recv() => ScheduledWork::Input(input),
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
                ScheduledWork::Media => {
                    frame_id = frame_id.checked_add(1).ok_or("frame id exhausted")?;
                    let keyframe_interval = u64::from(args.fps).saturating_mul(2).max(1);
                    let is_keyframe = frame_id == 1 || frame_id % keyframe_interval == 0;
                    let (width, height, nv12) =
                        desktop.capture_nv12(args.max_width, args.max_height)?;
                    let frame = pack_nv12_access_unit(width, height, &nv12);
                    let report = match session.send_media_frame(
                        FragmentSpec {
                            kind: MediaKind::Video,
                            flags: if is_keyframe {
                                media_flags::KEYFRAME
                            } else {
                                0
                            },
                            stream_id: 1,
                            codec_epoch: session.stamp().codec_epoch,
                            frame_id,
                            dependency_frame_id: (!is_keyframe).then_some(frame_id - 1),
                        },
                        &frame,
                        MEDIA_MAX_AGE,
                    ) {
                        Ok(report) => report,
                        Err(error) if is_clean_session_close(&error) => {
                            println!("session: peer completed normally");
                            return Ok(());
                        }
                        Err(error) => return Err(error.into()),
                    };

                    if !announced_stream {
                        println!("stream: NV12 {width}x{height} over QUIC DATAGRAM");
                        announced_stream = true;
                    }
                    if frame_id == 1 || frame_id % LOG_FRAME_INTERVAL == 0 {
                        println!(
                            "streaming: frame {frame_id} bytes={} fragments={} path_datagram_limit={}",
                            frame.len(),
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
        desktop: &mut X11DesktopSession,
    ) -> Result<InputBatchOutcome, Box<dyn Error>> {
        let (events, disconnected) = take_ready_input_batch(first, input_rx);
        for event in events {
            match event {
                InputLaneEvent::Payload(payload) => {
                    apply_input(&payload, expected_input_epoch, reconciler, desktop)?;
                }
                InputLaneEvent::Completed => return Ok(InputBatchOutcome::PeerCompleted),
                InputLaneEvent::Failed(error) => return Err(error.into()),
            }
        }
        if disconnected {
            return Err("reliable input lane task terminated unexpectedly".into());
        }

        // Give the signal driver, QUIC driver, and timer wheel an explicit
        // scheduling point after every bounded input batch.
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
                for action in actions {
                    desktop.inject(action)?;
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
        let mut failed_actions = 0_usize;
        let mut first_error = None;
        for action in actions {
            if let Err(error) = desktop.inject(action) {
                failed_actions += 1;
                if first_error.is_none() {
                    first_error = Some(error.to_string());
                }
            }
        }
        if failed_actions != 0 {
            return Err(format!(
                "ReleaseAll attempted every held input but {failed_actions} injections failed; first error: {}",
                first_error.as_deref().unwrap_or("unknown X11 injection error")
            )
            .into());
        }
        println!("input: ReleaseAll applied");
        Ok(())
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

#[cfg(all(test, not(target_os = "linux")))]
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
