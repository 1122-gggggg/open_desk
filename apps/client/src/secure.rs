//! Fail-closed product client path over exact-certificate mutual TLS and QUIC.

use super::ClientArgs;
use latencydesk_input::{InputEvent, InputMessage};
use latencydesk_protocol::quic::SessionStamp;
use latencydesk_session::lifecycle::ReconnectPolicy;
#[cfg(test)]
use latencydesk_socket_transport::identity::connect_exact_peer;
use latencydesk_socket_transport::identity::{
    connect_exact_peer_candidates, load_certificate_der, mtls_client_config, IdentityError,
    TlsIdentity,
};
use latencydesk_socket_transport::product::ProductSessionError;
use latencydesk_socket_transport::product::{ControlReceiver, ProductSession};
use latencydesk_socket_transport::quic::bind_client;
#[cfg(any(windows, test))]
use std::collections::VecDeque;
use std::error::Error;
#[cfg(any(windows, test))]
use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CLIENT_RELIABLE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_CANDIDATE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_RECONNECT_TOTAL_BUDGET: Duration = Duration::from_secs(15);
#[cfg(any(windows, test))]
const CLIENT_CLEANUP_SCHEDULER_ALLOWANCE: Duration = Duration::from_millis(250);
#[cfg(any(windows, test))]
const SNAPSHOT_CADENCE: Duration = Duration::from_millis(500);
#[cfg(any(windows, test))]
const RECOVERY_REQUEST_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(any(windows, test))]
const MAX_QUEUED_ACCESS_UNITS: usize = 2;
#[cfg(windows)]
const VIEWER_IDLE_PARK: Duration = Duration::ZERO;

#[derive(Debug)]
enum SessionEstablishError {
    Candidate(IdentityError),
    Handshake(ProductSessionError),
    Deadline(Duration),
}

impl SessionEstablishError {
    fn is_retryable_connection_attempt(&self) -> bool {
        match self {
            Self::Candidate(error) => error.is_retryable_connection_attempt(),
            Self::Handshake(error) => error.is_retryable_connection_loss(),
            Self::Deadline(_) => true,
        }
    }
}

impl std::fmt::Display for SessionEstablishError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Candidate(error) => write!(formatter, "exact-peer mTLS connection failed: {error}"),
            Self::Handshake(error) => write!(formatter, "secure product handshake failed: {error}"),
            Self::Deadline(timeout) => write!(
                formatter,
                "secure connection timed out after {} seconds; verify address, firewall, and exchanged certificates",
                timeout.as_secs()
            ),
        }
    }
}

impl Error for SessionEstablishError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Candidate(error) => Some(error),
            Self::Handshake(error) => Some(error),
            Self::Deadline(_) => None,
        }
    }
}

async fn establish_product_session(
    endpoint: &quinn::Endpoint,
    candidates: &[SocketAddr],
    exact_peer_certificate: &[u8],
    operation_timeout: Duration,
    previous: Option<SessionStamp>,
) -> Result<(ProductSession, SocketAddr, usize), SessionEstablishError> {
    let candidate_timeout = operation_timeout.min(CLIENT_CANDIDATE_ATTEMPT_TIMEOUT);
    tokio::time::timeout(operation_timeout, async {
        let connected = connect_exact_peer_candidates(
            endpoint,
            candidates,
            exact_peer_certificate,
            candidate_timeout,
        )
        .await
        .map_err(SessionEstablishError::Candidate)?;
        let selected_remote = connected.remote;
        let attempts_started = connected.attempts_started;
        let session = match previous {
            Some(previous) => {
                ProductSession::client_successor(connected.connection, previous).await
            }
            None => ProductSession::client(connected.connection).await,
        }
        .map_err(SessionEstablishError::Handshake)?;
        Ok::<_, SessionEstablishError>((session, selected_remote, attempts_started))
    })
    .await
    .map_err(|_| SessionEstablishError::Deadline(operation_timeout))?
}

fn is_retryable_session_run_error(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(candidate) = current {
        if candidate
            .downcast_ref::<ProductSessionError>()
            .is_some_and(ProductSessionError::is_retryable_connection_loss)
        {
            return true;
        }
        current = candidate.source();
    }
    false
}

fn claim_reconnect_delay(
    policy: ReconnectPolicy,
    attempts_used: &mut u32,
    prior_session_id: u64,
) -> Option<Duration> {
    let attempt = attempts_used.checked_add(1)?;
    let delay = policy.delay_for(attempt, prior_session_id)?;
    *attempts_used = attempt;
    Some(delay)
}

fn wait_for_reconnect_delay(runtime: &tokio::runtime::Runtime, delay: Duration) {
    runtime.block_on(async { tokio::time::sleep(delay).await });
}

fn log_active_session(session: &ProductSession, remote: SocketAddr, attempts_started: usize) {
    let stamp = session.stamp();
    println!("mTLS: exact host certificate authenticated");
    println!("route: authenticated {remote} after racing {attempts_started} candidate(s)");
    println!("handshake: active session_id={}", stamp.session_id);
    println!(
        "handshake-lifecycle: generation={} authorization_epoch={} display_epoch={} codec_epoch={}",
        stamp.generation, stamp.authorization_epoch, stamp.display_epoch, stamp.codec_epoch
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum VideoCodecPreference {
    #[cfg_attr(not(windows), allow(dead_code))]
    H264High420,
    #[cfg_attr(windows, allow(dead_code))]
    RawNv12,
}

#[cfg_attr(not(test), allow(dead_code))]
impl VideoCodecPreference {
    const fn capability_flag(self) -> u16 {
        match self {
            Self::H264High420 => latencydesk_protocol::video_capability_flags::H264_HIGH_420,
            Self::RawNv12 => latencydesk_protocol::video_capability_flags::RAW_NV12,
        }
    }

    const fn expected_pair(
        self,
    ) -> (
        latencydesk_protocol::VideoCodec,
        latencydesk_protocol::VideoProfile,
    ) {
        match self {
            Self::H264High420 => (
                latencydesk_protocol::VideoCodec::H264,
                latencydesk_protocol::VideoProfile::H264High420,
            ),
            Self::RawNv12 => (
                latencydesk_protocol::VideoCodec::RawNv12,
                latencydesk_protocol::VideoProfile::RawNv12,
            ),
        }
    }
}

const fn platform_capability_flags() -> u16 {
    latencydesk_protocol::video_capability_flags::H264_HIGH_420
        | latencydesk_protocol::video_capability_flags::RAW_NV12
}

fn stream_config_is_offered(config: latencydesk_protocol::VideoStreamConfig, flags: u16) -> bool {
    match (config.codec, config.profile) {
        (
            latencydesk_protocol::VideoCodec::H264,
            latencydesk_protocol::VideoProfile::H264High420,
        ) => flags & latencydesk_protocol::video_capability_flags::H264_HIGH_420 != 0,
        (
            latencydesk_protocol::VideoCodec::RawNv12,
            latencydesk_protocol::VideoProfile::RawNv12,
        ) => flags & latencydesk_protocol::video_capability_flags::RAW_NV12 != 0,
        _ => false,
    }
}
pub(crate) async fn negotiate_video_stream(
    session: &ProductSession,
    timeout: Duration,
) -> Result<(latencydesk_protocol::VideoStreamConfig, ControlReceiver), Box<dyn Error>> {
    use latencydesk_protocol::{
        ControlKind, VideoCodecCapabilities, VideoStreamConfig, VIDEO_CODEC_CONTRACT_VERSION,
    };

    tokio::time::timeout(timeout, async {
        let flags = platform_capability_flags();
        let capabilities = VideoCodecCapabilities {
            contract_version: VIDEO_CODEC_CONTRACT_VERSION,
            flags,
            max_width: 16_384,
            max_height: 16_384,
            max_fps: 240,
        };
        session
            .send_control(ControlKind::Capabilities, &capabilities.encode()?)
            .await?;
        let mut receiver = session.accept_control_receiver().await?;
        let selected = receiver.next_control().await?;
        if selected.kind != ControlKind::ConfigureStream {
            return Err(format!(
                "expected ConfigureStream after capabilities, received {:?}",
                selected.kind
            )
            .into());
        }
        let config = VideoStreamConfig::decode(&selected.payload)?;
        if !stream_config_is_offered(config, flags) {
            return Err(format!(
                "host selected unsupported codec/profile {:?}/{:?}",
                config.codec, config.profile
            )
            .into());
        }
        Ok::<_, Box<dyn Error>>((config, receiver))
    })
    .await
    .map_err(|_| format!("codec negotiation timed out after {timeout:?}"))?
}

pub fn run(args: &ClientArgs) -> Result<(), Box<dyn Error>> {
    let identity_certificate = args
        .identity_cert
        .as_deref()
        .ok_or("secure mode is missing --identity-cert")?;
    let identity_key = args
        .identity_key
        .as_deref()
        .ok_or("secure mode is missing --identity-key")?;
    let peer_certificate = args
        .peer_cert
        .as_deref()
        .ok_or("secure mode is missing --peer-cert")?;

    // Load and validate every credential before creating a socket or attempting
    // a network connection. Private key bytes never leave `TlsIdentity`.
    let identity = TlsIdentity::load_der(identity_certificate, identity_key)?;
    let exact_peer_certificate = load_certificate_der(peer_certificate)?;
    let client_configuration = mtls_client_config(&identity, &exact_peer_certificate)?;
    let operation_timeout = Duration::from_secs(args.pairing_timeout_secs);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("latencydesk-client-quic")
        .build()?;
    // Quinn discovers Tokio through the currently-entered runtime context even
    // though endpoint construction itself is synchronous. Keep that invariant
    // in one helper so process startup cannot regress to "no async runtime".
    let endpoint = in_runtime_context(&runtime, || {
        bind_client(client_configuration, args.bind_addr)
    })?;

    println!("=== LatencyDesk Client (secure QUIC) ===");
    println!("Target Host Address: {}", args.connect_addr);
    println!("Local Binding Address: {}", endpoint.local_addr()?);
    println!(
        "client-certificate-sha256: {}",
        encode_hex(&identity.fingerprint())
    );
    println!("transport: QUIC v1 / TLS 1.3 / exact-certificate mTLS");

    let candidates = super::connection_candidates(args);
    let (session, selected_remote, attempts_started) =
        runtime.block_on(establish_product_session(
            &endpoint,
            &candidates,
            &exact_peer_certificate,
            operation_timeout,
            None,
        ))?;

    log_active_session(&session, selected_remote, attempts_started);

    let reconnect_policy = ReconnectPolicy::new(args.reconnect_attempts)?;
    let result = if args.session_count > 1 || args.reconnect_attempts > 0 {
        run_headless_successor_sequence(
            SuccessorSequenceContext {
                runtime: &runtime,
                endpoint: &endpoint,
                candidates: &candidates,
                exact_peer_certificate: &exact_peer_certificate,
                operation_timeout,
            },
            session,
            args.max_frames.expect("parser requires frames"),
            args.session_count,
            reconnect_policy,
        )
    } else if args.inject_probe {
        run_probe(
            &runtime,
            &session,
            args.width,
            args.height,
            operation_timeout,
        )
    } else if let Some(needed) = args.max_frames {
        #[cfg(windows)]
        {
            run_headless_windows_h264(&runtime, &session, needed, operation_timeout)
        }
        #[cfg(not(windows))]
        {
            run_headless(&runtime, &session, needed, operation_timeout)
        }
    } else {
        #[cfg(windows)]
        {
            run_windows_viewer(&runtime, session, operation_timeout)
        }
        #[cfg(not(windows))]
        {
            crate::software_viewer::run(&runtime, session, operation_timeout)
        }
    };

    endpoint.close(0_u32.into(), b"client session complete");
    let cleanup_result = runtime.block_on(async {
        tokio::time::timeout(CLIENT_CLEANUP_TIMEOUT, endpoint.wait_idle())
            .await
            .map_err(|_| {
                format!("QUIC endpoint cleanup timed out after {CLIENT_CLEANUP_TIMEOUT:?}")
            })
    });
    merge_cleanup_result(result, cleanup_result)
}

struct SuccessorSequenceContext<'a> {
    runtime: &'a tokio::runtime::Runtime,
    endpoint: &'a quinn::Endpoint,
    candidates: &'a [SocketAddr],
    exact_peer_certificate: &'a [u8],
    operation_timeout: Duration,
}

fn run_headless_successor_sequence(
    context: SuccessorSequenceContext<'_>,
    first_session: ProductSession,
    needed_frames: u64,
    session_count: u32,
    reconnect_policy: ReconnectPolicy,
) -> Result<(), Box<dyn Error>> {
    let mut session = first_session;
    let mut completed_sessions = 0_u32;
    let mut reconnect_attempts_used = 0_u32;
    let mut reconnect_deadline = None;
    loop {
        let run_result = {
            #[cfg(windows)]
            {
                run_headless_windows_h264(
                    context.runtime,
                    &session,
                    needed_frames,
                    context.operation_timeout,
                )
            }
            #[cfg(not(windows))]
            {
                run_headless(
                    context.runtime,
                    &session,
                    needed_frames,
                    context.operation_timeout,
                )
            }
        };
        let previous = session.stamp();
        match run_result {
            Ok(()) => {
                session.close(0, b"client headless session complete");
                completed_sessions = completed_sessions.saturating_add(1);
                if completed_sessions >= session_count {
                    return Ok(());
                }

                println!(
                    "reconnect: starting authenticated successor {}/{}",
                    completed_sessions + 1,
                    session_count
                );
                let (successor, remote, attempts_started) =
                    context.runtime.block_on(establish_product_session(
                        context.endpoint,
                        context.candidates,
                        context.exact_peer_certificate,
                        context.operation_timeout,
                        Some(previous),
                    ))?;
                log_active_session(&successor, remote, attempts_started);
                session = successor;
            }
            Err(error) if is_retryable_session_run_error(error.as_ref()) => {
                session.close(1, b"client transport recovery required");
                let deadline = *reconnect_deadline.get_or_insert_with(|| {
                    Instant::now() + context.operation_timeout.min(CLIENT_RECONNECT_TOTAL_BUDGET)
                });
                let mut last_failure = error.to_string();
                loop {
                    let Some(delay) = claim_reconnect_delay(
                        reconnect_policy,
                        &mut reconnect_attempts_used,
                        previous.session_id,
                    ) else {
                        return Err(format!(
                            "recoverable transport loss exhausted {} reconnect attempt(s): {last_failure}",
                            reconnect_policy.maximum_attempts()
                        )
                        .into());
                    };
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining <= delay {
                        return Err(format!(
                            "recoverable transport loss exhausted the {:?} reconnect deadline after {} attempt(s): {last_failure}",
                            context
                                .operation_timeout
                                .min(CLIENT_RECONNECT_TOTAL_BUDGET),
                            reconnect_attempts_used.saturating_sub(1)
                        )
                        .into());
                    }
                    println!(
                        "reconnect: recoverable transport loss, attempt {}/{} after {delay:?}",
                        reconnect_attempts_used,
                        reconnect_policy.maximum_attempts()
                    );
                    wait_for_reconnect_delay(context.runtime, delay);
                    let attempt_timeout = context
                        .operation_timeout
                        .min(deadline.saturating_duration_since(Instant::now()));
                    match context.runtime.block_on(establish_product_session(
                        context.endpoint,
                        context.candidates,
                        context.exact_peer_certificate,
                        attempt_timeout,
                        Some(previous),
                    )) {
                        Ok((successor, remote, attempts_started)) => {
                            println!(
                                "reconnect: recovered authenticated session after {reconnect_attempts_used} attempt(s)"
                            );
                            log_active_session(&successor, remote, attempts_started);
                            session = successor;
                            break;
                        }
                        Err(connect_error) if connect_error.is_retryable_connection_attempt() => {
                            last_failure = connect_error.to_string();
                        }
                        Err(connect_error) => return Err(connect_error.into()),
                    }
                }
            }
            Err(error) => {
                session.close(1, b"client headless session failed");
                return Err(error);
            }
        }
    }
}

#[cfg(windows)]
fn run_headless_windows_h264(
    runtime: &tokio::runtime::Runtime,
    session: &ProductSession,
    needed: u64,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    use latencydesk_media::{ContinuityAction, DecoderContinuity};
    use latencydesk_protocol::{CongestionFeedbackMessage, ControlKind};

    use latencydesk_h264::LowDelayPolicy;
    use latencydesk_platform_windows::{
        D3D11WindowRenderer, WindowsBackendError, WindowsH264Decoder,
    };
    let (received, last_input_sequence, release_all_sent) = runtime.block_on(async {
        tokio::time::timeout(timeout, async {
            let (config, control) = negotiate_video_stream(session, timeout).await?;
            let policy =
                LowDelayPolicy::baseline(config.fps.saturating_mul(2)).validate()?;
            let mut window = D3D11WindowRenderer::new(config.width, config.height)?;
            let mut decoder = WindowsH264Decoder::new(
                &mut window,
                config.width,
                config.height,
                config.fps,
                policy,
            )?;
            let mut hardware_decode_logged = false;
            let feedback_clock = std::time::Instant::now();
            let initial_network_stats = session.network_stats();
            let mut last_sent_packets = initial_network_stats.sent_packets;
            let mut last_lost_packets = initial_network_stats.lost_packets;
            let mut feedback_sequence = 0_u64;
            let mut received_bytes = 0_u64;

            let mut continuity = DecoderContinuity::default();
            let mut count = 0_u64;
            let mut last_good = 0_u64;
            let mut last_recovery_sent = None;
            let mut input_sequence = 0_u64;
            let mut release_all_sent = false;
            let mut motion_ticks = tokio::time::interval(Duration::from_secs(1));
            motion_ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            while count < needed {
                tokio::select! {
                    biased;
                    received_frame = session.receive_media_frame() => {
                        let frame = EncodedH264Frame::decode(received_frame?, config)?;
                        match continuity.classify(frame.meta) {
                            ContinuityAction::ResetAndDecode | ContinuityAction::Decode => {
                                if count == 0 && !frame.meta.recovery_point {
                                    return Err("headless secure smoke did not join on an IDR".into());
                                }
                                if frame.meta.recovery_point && count != 0 {
                                    decoder.flush()?;
                                }
                                loop {
                                    match decoder.submit(&frame.bytes, frame.meta.frame_id, 0) {
                                        Ok(()) => break,
                                        Err(WindowsBackendError::QueueFull) => {
                                            tokio::time::sleep(Duration::from_millis(1)).await;
                                        }
                                        Err(error) => {
                                            continuity.note_loss();
                                            request_recovery(
                                                session,
                                                config,
                                                last_good,
                                                frame.meta.frame_id,
                                                &mut last_recovery_sent,
                                            )
                                            .await?;
                                            return Err(error.into());
                                        }
                                    }
                                }
                                let decoded = loop {
                                    match decoder.poll_output() {
                                        Ok(Some(decoded)) => break decoded,
                                        Ok(None) => {
                                            tokio::time::sleep(Duration::from_millis(1)).await;
                                        }
                                        Err(error) => {
                                            continuity.note_loss();
                                            request_recovery(
                                                session,
                                                config,
                                                last_good,
                                                frame.meta.frame_id,
                                                &mut last_recovery_sent,
                                            )
                                            .await?;
                                            return Err(error.into());
                                        }
                                    }
                                };
                                if decoded.frame_id != frame.meta.frame_id {
                                    continuity.note_loss();
                                    request_recovery(
                                        session,
                                        config,
                                        last_good,
                                        frame.meta.frame_id,
                                        &mut last_recovery_sent,
                                    )
                                    .await?;
                                    continue;
                                }
                                continuity
                                    .commit_decoded(frame.meta)
                                    .map_err(|error| format!("decoded continuity commit failed: {error:?}"))?;
                                if !decoder.is_hardware_accelerated() {
                                    return Err(
                                        "inbox H.264 decoder returned a CPU/non-DXGI output buffer".into(),
                                    );
                                }
                                if !hardware_decode_logged {
                                    println!(
                                        "decoder: provider=windows_inbox_h264_dxva hardware_accelerated=true output=D3D11_NV12"
                                    );
                                    hardware_decode_logged = true;
                                }
                                received_bytes = received_bytes.saturating_add(
                                    u64::try_from(frame.bytes.len()).unwrap_or(u64::MAX),
                                );
                                window.present_decoded(&decoded)?;
                                count = count.saturating_add(1);
                                last_good =
                                    continuity.last_decoded_frame_id().unwrap_or(last_good);
                                println!(
                                    "smoke: H.264 AU frame={} bytes={} keyframe={} dependency={:?}",
                                    frame.meta.frame_id,
                                    frame.bytes.len(),
                                    frame.meta.recovery_point,
                                    frame.meta.dependency_frame_id
                                );
                                if count % 3 == 0 && count < needed {
                                    let stats = session.network_stats();
                                    let sent_delta =
                                        stats.sent_packets.saturating_sub(last_sent_packets);
                                    let lost_delta =
                                        stats.lost_packets.saturating_sub(last_lost_packets);
                                    last_sent_packets = stats.sent_packets;
                                    last_lost_packets = stats.lost_packets;
                                    let loss_per_million = if sent_delta == 0 {
                                        0
                                    } else {
                                        u32::try_from(
                                            lost_delta.saturating_mul(1_000_000) / sent_delta,
                                        )
                                        .unwrap_or(u32::MAX)
                                    };
                                    feedback_sequence = feedback_sequence.saturating_add(1);
                                    let elapsed_ns = u64::try_from(
                                        feedback_clock.elapsed().as_nanos(),
                                    )
                                    .unwrap_or(u64::MAX)
                                    .max(1);
                                    let received_bitrate_bps = u32::try_from(
                                        received_bytes
                                            .saturating_mul(8)
                                            .saturating_mul(1_000_000_000)
                                            / elapsed_ns,
                                    )
                                    .unwrap_or(u32::MAX);
                                    let feedback = CongestionFeedbackMessage {
                                        feedback_sequence,
                                        echo_timestamp_ns: 0,
                                        rtt_ns: u32::try_from(stats.rtt.as_nanos())
                                            .unwrap_or(u32::MAX),
                                        loss_per_million,
                                        jitter_ns: 0,
                                        received_bitrate_bps,
                                    };
                                    session
                                        .send_control(
                                            ControlKind::CongestionFeedback,
                                            &feedback.encode(),
                                        )
                                        .await?;
                                }
                                if !release_all_sent
                                    && count >= needed.saturating_sub(1)
                                {
                                    input_sequence = input_sequence.saturating_add(1);
                                    send_input_event(
                                        session,
                                        input_sequence,
                                        InputEvent::ReleaseAll,
                                        reliable_operation_timeout(timeout),
                                    )
                                    .await?;
                                    release_all_sent = true;
                                }
                            }
                            ContinuityAction::DropAndRequestRecovery => {
                                request_recovery(
                                    session,
                                    config,
                                    last_good,
                                    last_good.saturating_add(1),
                                    &mut last_recovery_sent,
                                )
                                .await?;
                            }
                        }
                    }
                    _ = motion_ticks.tick() => {
                        if release_all_sent {
                            continue;
                        }
                        input_sequence = input_sequence.saturating_add(1);
                        let x = if input_sequence % 2 == 0 {
                            config.width / 3
                        } else {
                            config.width.saturating_mul(2) / 3
                        };
                        send_input_event(
                            session,
                            input_sequence,
                            InputEvent::PointerMotionAbsolute {
                                x,
                                y: config.height / 2,
                                width: config.width,
                                height: config.height,
                            },
                            reliable_operation_timeout(timeout),
                        )
                        .await?;
                    }
                }
            }
            drop(control);
            Ok::<(u64, u64, bool), Box<dyn Error>>((
                count,
                input_sequence,
                release_all_sent,
            ))
        })
        .await
        .map_err(|_| format!("timed out after {timeout:?} waiting for {needed} H.264 frames"))?
    })?;
    if !release_all_sent {
        let release_result = runtime.block_on(send_input_event(
            session,
            last_input_sequence.saturating_add(1),
            InputEvent::ReleaseAll,
            reliable_operation_timeout(timeout),
        ));
        if let Err(error) = release_result {
            if !is_clean_peer_close(error.as_ref()) {
                return Err(error);
            }
        }
    }
    println!(
        "received: session_id={} H.264_frames={received}",
        session.stamp().session_id
    );
    Ok(())
}

#[cfg(not(windows))]
fn run_headless(
    runtime: &tokio::runtime::Runtime,
    session: &ProductSession,
    needed: u64,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let (config, _control_receiver) = runtime.block_on(negotiate_video_stream(session, timeout))?;
    let received = runtime.block_on(receive_frames_with_timeout(
        session, needed, timeout, config,
    ))?;
    runtime.block_on(send_input_event(
        session,
        1,
        InputEvent::ReleaseAll,
        reliable_operation_timeout(timeout),
    ))?;
    println!(
        "received: session_id={} frames={received}",
        session.stamp().session_id
    );
    Ok(())
}

fn run_probe(
    runtime: &tokio::runtime::Runtime,
    session: &ProductSession,
    width: u32,
    height: u32,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let (config, _control_receiver) = runtime.block_on(negotiate_video_stream(session, timeout))?;
    runtime.block_on(async {
        send_input_event(
            session,
            1,
            InputEvent::PointerMotionAbsolute {
                x: 10,
                y: 10,
                width,
                height,
            },
            reliable_operation_timeout(timeout),
        )
        .await?;
        send_input_event(
            session,
            2,
            InputEvent::ReleaseAll,
            reliable_operation_timeout(timeout),
        )
        .await
    })?;
    let received = runtime.block_on(receive_frames_with_timeout(session, 3, timeout, config))?;
    println!("inject-probe: sent over reliable QUIC input lane");
    println!(
        "received: session_id={} frames={received}",
        session.stamp().session_id
    );
    Ok(())
}

async fn receive_frames_with_timeout(
    session: &ProductSession,
    needed: u64,
    timeout: Duration,
    config: latencydesk_protocol::VideoStreamConfig,
) -> Result<u64, Box<dyn Error>> {
    tokio::time::timeout(timeout, async {
        let mut received = 0_u64;
        while received < needed {
            let frame = session.receive_media_frame().await?;
            match config.codec {
                latencydesk_protocol::VideoCodec::H264 => {
                    latencydesk_h264::inspect_annex_b(&frame.bytes)?;
                }
                latencydesk_protocol::VideoCodec::RawNv12 => {
                    if frame.header.stream_id != config.stream_id
                        || frame.header.codec_epoch != config.codec_epoch
                    {
                        return Err("raw NV12 frame does not match negotiated stream".into());
                    }
                    let (width, height, _) = crate::parse_nv12_access_unit(&frame.bytes)
                        .ok_or("invalid explicitly negotiated raw NV12 access unit")?;
                    if (width, height) != (config.width, config.height) {
                        return Err(format!(
                            "raw NV12 dimensions {width}x{height} differ from negotiated {}x{}",
                            config.width, config.height
                        )
                        .into());
                    }
                }
            }
            received = received.saturating_add(1);
        }
        Ok::<u64, Box<dyn Error>>(received)
    })
    .await
    .map_err(|_| {
        format!(
            "timed out after {} seconds with fewer than {needed} completed frames",
            timeout.as_secs()
        )
    })?
}

pub(crate) async fn send_input_event(
    session: &ProductSession,
    sequence: u64,
    event: InputEvent,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let payload = InputMessage {
        session_epoch: session.stamp().authorization_epoch,
        sequence,
        event,
    }
    .encode()?;
    session.send_input_with_timeout(&payload, timeout).await?;
    Ok(())
}

fn reliable_operation_timeout(session_timeout: Duration) -> Duration {
    session_timeout.min(CLIENT_RELIABLE_OPERATION_TIMEOUT)
}

#[cfg(any(windows, test))]
fn viewer_network_cleanup_timeout(reliable_timeout: Duration) -> Duration {
    let cleanup_policy_cap = CLIENT_RELIABLE_OPERATION_TIMEOUT
        .checked_mul(2)
        .and_then(|duration| duration.checked_add(CLIENT_CLEANUP_TIMEOUT))
        .unwrap_or(Duration::MAX);
    reliable_timeout
        .checked_mul(2)
        .and_then(|duration| duration.checked_add(CLIENT_CLEANUP_SCHEDULER_ALLOWANCE))
        .unwrap_or(cleanup_policy_cap)
        .min(cleanup_policy_cap)
}

fn merge_cleanup_result(
    primary: Result<(), Box<dyn Error>>,
    cleanup: Result<(), String>,
) -> Result<(), Box<dyn Error>> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup)) => Err(cleanup.into()),
        (Err(primary), Err(cleanup)) => {
            Err(format!("{primary}; cleanup also failed: {cleanup}").into())
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn in_runtime_context<T, E>(
    runtime: &tokio::runtime::Runtime,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let _runtime_guard = runtime.enter();
    operation()
}

#[cfg(any(windows, test))]
#[derive(Debug)]
struct EncodedH264Frame {
    meta: latencydesk_media::EncodedFrameMeta,
    bytes: Vec<u8>,
}

#[cfg(windows)]
impl EncodedH264Frame {
    fn decode(
        frame: latencydesk_transport::ReassembledFrame,
        config: latencydesk_protocol::VideoStreamConfig,
    ) -> Result<Self, String> {
        use latencydesk_protocol::{
            media_flags, MediaKind, VideoCodec, VideoProfile, NO_DEPENDENCY,
        };

        if config.codec != VideoCodec::H264
            || config.profile != VideoProfile::H264High420
            || frame.header.kind != MediaKind::Video
            || frame.header.stream_id != config.stream_id
            || frame.header.codec_epoch != config.codec_epoch
        {
            return Err(format!(
                "media frame {} does not match negotiated H.264 stream {}/epoch {}",
                frame.header.frame_id, config.stream_id, config.codec_epoch
            ));
        }
        let summary = latencydesk_h264::inspect_annex_b(&frame.bytes)
            .and_then(latencydesk_h264::AnnexBSummary::validate_low_delay)
            .map_err(|error| {
                format!(
                    "media frame {} is not a valid low-delay Annex-B H.264 AU: {error}",
                    frame.header.frame_id
                )
            })?;
        let recovery_point = frame.header.flags & media_flags::KEYFRAME != 0;
        if !summary.contains_picture() || summary.has_idr_slice != recovery_point {
            return Err(format!(
                "media frame {} keyframe metadata disagrees with its Annex-B slices",
                frame.header.frame_id
            ));
        }
        let dependency_frame_id = (frame.header.dependency_frame_id != NO_DEPENDENCY)
            .then_some(frame.header.dependency_frame_id);
        Ok(Self {
            meta: latencydesk_media::EncodedFrameMeta {
                codec_epoch: frame.header.codec_epoch,
                frame_id: frame.header.frame_id,
                dependency_frame_id,
                recovery_point,
            },
            bytes: frame.bytes,
        })
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LatestFrameSlotDecision {
    Queued,
    ReplacedWithRecovery,
    DroppedDependent,
}

#[cfg(any(windows, test))]
fn enqueue_latest_frame(
    queue: &mut VecDeque<EncodedH264Frame>,
    frame: EncodedH264Frame,
) -> LatestFrameSlotDecision {
    if frame.meta.recovery_point {
        let replaced = !queue.is_empty();
        queue.clear();
        queue.push_back(frame);
        return if replaced {
            LatestFrameSlotDecision::ReplacedWithRecovery
        } else {
            LatestFrameSlotDecision::Queued
        };
    }
    if queue.len() < MAX_QUEUED_ACCESS_UNITS {
        queue.push_back(frame);
        LatestFrameSlotDecision::Queued
    } else {
        LatestFrameSlotDecision::DroppedDependent
    }
}

#[cfg(windows)]
#[derive(Debug)]
enum NetworkCommand {
    Input(InputEvent),
    Decoded(latencydesk_media::EncodedFrameMeta),
    RecoveryNeeded { first_missing_frame_id: u64 },
}

#[cfg(windows)]
fn run_windows_nv12_viewer(
    runtime: &tokio::runtime::Runtime,
    session: ProductSession,
    timeout: Duration,
    config: latencydesk_protocol::VideoStreamConfig,
) -> Result<(), Box<dyn Error>> {
    use latencydesk_platform_windows::D3D11WindowRenderer;
    use std::sync::{Arc, Mutex};

    let first = runtime
        .block_on(async { tokio::time::timeout(timeout, session.receive_media_frame()).await })
        .map_err(|_| "timed out waiting for the first packed NV12 frame")??;
    let (_, _, nv12) =
        crate::parse_nv12_access_unit(&first.bytes).ok_or("invalid packed NV12 access unit")?;
    let mut window = D3D11WindowRenderer::new(config.width, config.height)
        .map_err(|error| format!("failed to create D3D11 renderer: {error:?}"))?;
    window.present_nv12(nv12)?;
    println!(
        "Client Connected. Packed NV12 -> D3D11 window open ({}x{}@{}).",
        config.width, config.height, config.fps
    );

    let latest = Arc::new(Mutex::new(None::<Vec<u8>>));
    let network_latest = Arc::clone(&latest);
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<InputEvent>(128);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let network_session = session.clone();
    let reliable_timeout = reliable_operation_timeout(timeout);
    let network_task = runtime.spawn(async move {
        let mut sequence = 0_u64;
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                event = input_rx.recv() => {
                    let Some(event) = event else { break };
                    sequence = sequence.saturating_add(1);
                    if send_input_event(&network_session, sequence, event, reliable_timeout).await.is_err() {
                        break;
                    }
                }
                frame = network_session.receive_media_frame() => {
                    match frame {
                        Ok(frame) => {
                            if let Ok(mut slot) = network_latest.lock() {
                                *slot = Some(frame.bytes);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let _ = send_input_event(
            &network_session,
            sequence.saturating_add(1),
            InputEvent::ReleaseAll,
            reliable_timeout,
        )
        .await;
    });

    while window.pump_messages() {
        for event in window.poll_inputs(32) {
            if let Some(input) = super::window_event_to_input(event, config.width, config.height) {
                let _ = input_tx.try_send(input);
            }
        }
        if let Some(bytes) = latest.lock().ok().and_then(|mut slot| slot.take()) {
            if let Some((_, _, nv12)) = crate::parse_nv12_access_unit(&bytes) {
                let _ = window.present_nv12(nv12);
            }
        }
    }
    let _ = shutdown_tx.send(());
    network_task.abort();
    window.close();
    Ok(())
}

#[cfg(windows)]
fn run_windows_viewer(
    runtime: &tokio::runtime::Runtime,
    session: ProductSession,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    use latencydesk_h264::LowDelayPolicy;
    use latencydesk_platform_windows::{
        D3D11WindowRenderer, WindowsBackendError, WindowsH264Decoder,
    };
    use std::collections::VecDeque;
    use std::sync::{mpsc, Arc, Mutex};

    let (config, control_receiver) = runtime.block_on(negotiate_video_stream(&session, timeout))?;
    if config.codec == latencydesk_protocol::VideoCodec::RawNv12 {
        return run_windows_nv12_viewer(runtime, session, timeout, config);
    }
    let first = runtime
        .block_on(async { tokio::time::timeout(timeout, session.receive_media_frame()).await })
        .map_err(|_| "timed out waiting for the first secure H.264 media frame")??;
    let first = EncodedH264Frame::decode(first, config)?;
    if !first.meta.recovery_point {
        return Err(format!(
            "join frame {} is dependent; host must force IDR on join",
            first.meta.frame_id
        )
        .into());
    }
    let first_meta = first.meta;
    let reliable_timeout = reliable_operation_timeout(timeout);
    let cleanup_timeout = viewer_network_cleanup_timeout(reliable_timeout);
    let mut window = D3D11WindowRenderer::new(config.width, config.height)
        .map_err(|error| format!("failed to create D3D11 renderer: {error:?}"))?;
    let policy = LowDelayPolicy::baseline(config.fps.saturating_mul(2)).validate()?;
    let mut decoder = WindowsH264Decoder::new(
        &mut window,
        config.width,
        config.height,
        config.fps,
        policy,
    )
    .map_err(|error| {
        format!(
            "Media Foundation hardware H.264 decode to D3D11 NV12 is required; no CPU decode/upload fallback is permitted: {error}"
        )
    })?;
    let first_decode_deadline = std::time::Instant::now() + timeout;
    loop {
        match decoder.submit(&first.bytes, first.meta.frame_id, 0) {
            Ok(()) => break,
            Err(WindowsBackendError::QueueFull)
                if std::time::Instant::now() < first_decode_deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => {
                return Err(format!(
                    "failed to submit first Annex-B H.264 AU to the hardware decoder: {error}"
                )
                .into());
            }
        }
    }
    let first_decoded = loop {
        match decoder.poll_output() {
            Ok(Some(decoded)) => break decoded,
            Ok(None) if std::time::Instant::now() < first_decode_deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(None) => return Err("timed out waiting for first MF decoder output".into()),
            Err(error) => return Err(error.into()),
        }
    };
    if first_decoded.frame_id != first_meta.frame_id {
        return Err("first MF decoder output does not match the submitted IDR".into());
    }
    if !decoder.is_hardware_accelerated() {
        return Err("decoder returned a non-D3D11/CPU output buffer".into());
    }
    println!("decoder: hardware_accelerated=true output=D3D11_NV12");
    window.present_decoded(&first_decoded)?;
    let mut rendered_frames = 1_u64;
    let mut hardware_decode_logged = true;

    println!(
        "Client Connected. Secure MF hardware H.264 -> D3D11 NV12 presentation window open ({}x{}@{}).",
        config.width, config.height, config.fps
    );
    println!("codec: contract v1 H.264 High 4:2:0; raw NV12 compatibility disabled");
    println!("Close the window to disconnect safely.");

    let latest_frame = Arc::new(Mutex::new(VecDeque::<EncodedH264Frame>::with_capacity(
        MAX_QUEUED_ACCESS_UNITS,
    )));
    let network_latest = Arc::clone(&latest_frame);
    let (command_tx, command_rx) = tokio::sync::mpsc::channel::<NetworkCommand>(128);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (termination_tx, termination_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let network_session = session.clone();
    let mut network_task = runtime.spawn(async move {
        let result = viewer_network_loop(
            network_session,
            control_receiver,
            command_rx,
            shutdown_rx,
            network_latest,
            config,
            first_meta,
            reliable_timeout,
        )
        .await;
        let _ = termination_tx.send(result.clone());
        result
    });

    let mut ui_error = None;
    let mut network_terminated = false;
    let mut submitted_frames =
        VecDeque::<(latencydesk_media::EncodedFrameMeta, usize)>::with_capacity(2);
    'ui: while window.pump_messages() {
        match termination_rx.try_recv() {
            Ok(Err(error)) => {
                network_terminated = true;
                ui_error = Some(format!("secure transport terminated: {error}"));
                break;
            }
            Ok(Ok(())) => {
                network_terminated = true;
                break;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                network_terminated = true;
                ui_error = Some("secure transport task ended without a status".to_owned());
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        let input_events = window.poll_inputs(32);
        let had_input = !input_events.is_empty();
        for event in input_events {
            if event.kind == latencydesk_platform_windows::INPUT_KIND_OVERFLOW {
                ui_error = Some(
                    "native input queue overflowed; disconnecting to prevent a stuck key or button"
                        .to_owned(),
                );
                break 'ui;
            }
            if let Some(input) = super::window_event_to_input(event, config.width, config.height) {
                if let Err(error) = command_tx.try_send(NetworkCommand::Input(input)) {
                    ui_error = Some(match error {
                        tokio::sync::mpsc::error::TrySendError::Full(_) => {
                            "bounded input queue saturated; disconnecting to avoid losing a key/button transition"
                                .to_owned()
                        }
                        tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                            "secure input lane closed".to_owned()
                        }
                    });
                    break 'ui;
                }
            }
        }

        let queued_frames = match latest_frame.lock() {
            Ok(mut slot) => slot.drain(..).collect::<Vec<_>>(),
            Err(_) => {
                ui_error = Some("latest-frame queue lock was poisoned".to_owned());
                break;
            }
        };
        let had_frame = !queued_frames.is_empty();
        for frame in queued_frames {
            if frame.meta.recovery_point {
                if let Err(error) = decoder.flush() {
                    let _ = command_tx.try_send(NetworkCommand::RecoveryNeeded {
                        first_missing_frame_id: frame.meta.frame_id,
                    });
                    ui_error = Some(format!("hardware decoder IDR reset failed: {error}"));
                    break;
                }
                submitted_frames.clear();
            }
            let submit_result = if frame.meta.recovery_point {
                let deadline = std::time::Instant::now() + RECOVERY_REQUEST_INTERVAL;
                loop {
                    let result = decoder.submit(&frame.bytes, frame.meta.frame_id, 0);
                    if !matches!(result, Err(WindowsBackendError::QueueFull))
                        || std::time::Instant::now() >= deadline
                    {
                        break result;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            } else {
                decoder.submit(&frame.bytes, frame.meta.frame_id, 0)
            };
            match submit_result {
                Ok(()) => submitted_frames.push_back((frame.meta, frame.bytes.len())),
                Err(WindowsBackendError::QueueFull) => {
                    if command_tx
                        .try_send(NetworkCommand::RecoveryNeeded {
                            first_missing_frame_id: frame.meta.frame_id,
                        })
                        .is_err()
                    {
                        ui_error =
                            Some("failed to queue recovery after decoder pressure".to_owned());
                        break;
                    }
                }
                Err(error) => {
                    let _ = command_tx.try_send(NetworkCommand::RecoveryNeeded {
                        first_missing_frame_id: frame.meta.frame_id,
                    });
                    ui_error = Some(format!(
                        "MF hardware H.264 decoder rejected frame {}: {error}",
                        frame.meta.frame_id
                    ));
                    break;
                }
            }
        }

        let mut newest_decoded = None;
        loop {
            match decoder.poll_output() {
                Ok(Some(decoded)) => {
                    let Some((meta, au_bytes)) = submitted_frames.pop_front() else {
                        ui_error =
                            Some("MF decoder produced output without a submitted frame".to_owned());
                        break 'ui;
                    };
                    if decoded.frame_id != meta.frame_id {
                        let _ = command_tx.try_send(NetworkCommand::RecoveryNeeded {
                            first_missing_frame_id: meta.frame_id,
                        });
                        ui_error = Some(format!(
                            "MF decoder output frame {} does not match submitted frame {}",
                            decoded.frame_id, meta.frame_id
                        ));
                        break 'ui;
                    }
                    match command_tx.try_send(NetworkCommand::Decoded(meta)) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            ui_error = Some("decoded-frame commit queue saturated".to_owned());
                            break 'ui;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // The clean peer-close path can win after output is
                            // already present-ready. No future dependency can
                            // consume this commit once the network task ended.
                        }
                    }
                    newest_decoded = Some((decoded, meta, au_bytes));
                }
                Ok(None) => break,
                Err(error) => {
                    let first_missing_frame_id = submitted_frames
                        .front()
                        .map_or(1, |(meta, _)| meta.frame_id);
                    let _ = command_tx.try_send(NetworkCommand::RecoveryNeeded {
                        first_missing_frame_id,
                    });
                    ui_error = Some(format!("MF hardware decoder output failed: {error}"));
                    break 'ui;
                }
            }
        }
        let had_decoded = newest_decoded.is_some();
        if let Some((decoded, meta, au_bytes)) = newest_decoded {
            if !hardware_decode_logged {
                if !decoder.is_hardware_accelerated() {
                    ui_error = Some("decoder returned a non-D3D11/CPU output buffer".to_owned());
                    break;
                }
                println!("decoder: hardware_accelerated=true output=D3D11_NV12");
                hardware_decode_logged = true;
            }
            if let Err(error) = window.present_decoded(&decoded) {
                ui_error = Some(format!("D3D11 GPU presentation failed: {error}"));
                break;
            }
            rendered_frames = rendered_frames.saturating_add(1);
            if rendered_frames % 60 == 0 {
                println!(
                    ">>> Secure H.264 streaming active: rendered frame #{} (AU {} bytes)",
                    meta.frame_id, au_bytes
                );
            }
        }
        park_viewer_if_idle(had_frame || had_decoded, had_input);
    }

    if !network_terminated && !network_task.is_finished() {
        let _ = shutdown_tx.send(());
    }
    let network_result = match runtime
        .block_on(async { tokio::time::timeout(cleanup_timeout, &mut network_task).await })
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(format!("secure transport task failed: {error}")),
        Err(_) => {
            network_task.abort();
            let _ = runtime.block_on(async {
                tokio::time::timeout(CLIENT_CLEANUP_TIMEOUT, &mut network_task).await
            });
            Err(format!(
                "secure transport cleanup timed out after {cleanup_timeout:?}; network task cancelled"
            ))
        }
    };
    window.close();

    match (ui_error, network_result) {
        (None, Ok(())) => Ok(()),
        (Some(error), Ok(())) | (None, Err(error)) => Err(error.into()),
        (Some(ui), Err(network)) if ui.contains(&network) => Err(ui.into()),
        (Some(ui), Err(network)) => {
            Err(format!("{ui}; transport cleanup also failed: {network}").into())
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum NetworkWork<C, T, M> {
    Shutdown,
    Command(C),
    Snapshot,
    Control(T),
    Media(M),
}

#[cfg(any(windows, test))]
async fn select_network_work<X, C, S, T, M>(
    shutdown: X,
    command: C,
    snapshot: S,
    control: T,
    media: M,
) -> NetworkWork<C::Output, T::Output, M::Output>
where
    X: Future,
    C: Future,
    S: Future,
    T: Future,
    M: Future,
{
    tokio::select! {
        biased;
        _ = shutdown => NetworkWork::Shutdown,
        command = command => NetworkWork::Command(command),
        _ = snapshot => NetworkWork::Snapshot,
        control = control => NetworkWork::Control(control),
        media = media => NetworkWork::Media(media),
    }
}

pub(crate) fn is_clean_peer_close(error: &(dyn Error + 'static)) -> bool {
    matches!(
        error.downcast_ref::<ProductSessionError>(),
        Some(ProductSessionError::Quic(transport)) if transport.is_clean_application_close()
    )
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
async fn viewer_network_loop(
    session: ProductSession,
    mut control: latencydesk_socket_transport::product::ControlReceiver,
    mut commands: tokio::sync::mpsc::Receiver<NetworkCommand>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    latest_frame: std::sync::Arc<std::sync::Mutex<VecDeque<EncodedH264Frame>>>,
    config: latencydesk_protocol::VideoStreamConfig,
    first_meta: latencydesk_media::EncodedFrameMeta,
    reliable_timeout: Duration,
) -> Result<(), String> {
    use latencydesk_media::{ContinuityAction, DecoderContinuity};
    use latencydesk_protocol::{CongestionFeedbackMessage, ControlKind, RateUpdateMessage};

    let mut sequence = 0_u64;
    let mut last_accepted_frame_id = first_meta.frame_id;
    let mut continuity = DecoderContinuity::default();
    continuity
        .commit_decoded(first_meta)
        .map_err(|error| format!("first decoded continuity commit failed: {error:?}"))?;
    let mut held_input = latencydesk_input::InputState::default();
    let mut snapshot_ticks = tokio::time::interval_at(
        tokio::time::Instant::now() + SNAPSHOT_CADENCE,
        SNAPSHOT_CADENCE,
    );
    snapshot_ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_recovery_sent = None;
    let mut feedback_sequence = 0_u64;
    let initial_stats = session.network_stats();
    let mut last_sent_packets = initial_stats.sent_packets;
    let mut last_lost_packets = initial_stats.lost_packets;
    let mut received_bytes = 0_u64;

    let result = loop {
        match select_network_work(
            &mut shutdown,
            commands.recv(),
            snapshot_ticks.tick(),
            control.next_control(),
            session.receive_media_frame(),
        )
        .await
        {
            NetworkWork::Shutdown => break Ok(()),
            NetworkWork::Command(command) => match command {
                Some(NetworkCommand::Input(event)) => {
                    apply_held_input(&mut held_input, &event);
                    sequence = sequence.saturating_add(1);
                    if let Err(error) =
                        send_input_event(&session, sequence, event, reliable_timeout).await
                    {
                        if is_clean_peer_close(error.as_ref()) {
                            return Ok(());
                        }
                        break Err(format!("reliable input send failed: {error}"));
                    }
                }
                Some(NetworkCommand::Decoded(meta)) => {
                    if continuity.commit_decoded(meta).is_err() {
                        continuity.note_loss();
                        let last_good = continuity.last_decoded_frame_id().unwrap_or(0);
                        request_recovery(
                            &session,
                            config,
                            last_good,
                            meta.frame_id,
                            &mut last_recovery_sent,
                        )
                        .await?;
                    }
                }
                Some(NetworkCommand::RecoveryNeeded {
                    first_missing_frame_id,
                }) => {
                    continuity.note_loss();
                    let last_good = continuity.last_decoded_frame_id().unwrap_or(0);
                    request_recovery(
                        &session,
                        config,
                        last_good,
                        first_missing_frame_id,
                        &mut last_recovery_sent,
                    )
                    .await?;
                }
                None => break Ok(()),
            },
            NetworkWork::Snapshot => {
                sequence = sequence.saturating_add(1);
                if let Err(error) = send_input_event(
                    &session,
                    sequence,
                    InputEvent::Snapshot(held_input.clone()),
                    reliable_timeout,
                )
                .await
                {
                    if is_clean_peer_close(error.as_ref()) {
                        return Ok(());
                    }
                    break Err(format!("reliable snapshot send failed: {error}"));
                }

                let stats = session.network_stats();
                let sent_delta = stats.sent_packets.saturating_sub(last_sent_packets);
                let lost_delta = stats.lost_packets.saturating_sub(last_lost_packets);
                last_sent_packets = stats.sent_packets;
                last_lost_packets = stats.lost_packets;
                let loss_per_million = if sent_delta == 0 {
                    0
                } else {
                    u32::try_from(lost_delta.saturating_mul(1_000_000) / sent_delta)
                        .unwrap_or(u32::MAX)
                };
                feedback_sequence = feedback_sequence.saturating_add(1);
                let feedback = CongestionFeedbackMessage {
                    feedback_sequence,
                    echo_timestamp_ns: 0,
                    rtt_ns: u32::try_from(stats.rtt.as_nanos()).unwrap_or(u32::MAX),
                    loss_per_million,
                    jitter_ns: 0,
                    received_bitrate_bps: u32::try_from(received_bytes.saturating_mul(16))
                        .unwrap_or(u32::MAX),
                };
                received_bytes = 0;
                if let Err(error) = session
                    .send_control(ControlKind::CongestionFeedback, &feedback.encode())
                    .await
                {
                    if is_clean_peer_close(&error) {
                        return Ok(());
                    }
                    break Err(format!("congestion feedback send failed: {error}"));
                }
            }
            NetworkWork::Control(message) => {
                let message = match message {
                    Ok(message) => message,
                    Err(error) if is_clean_peer_close(&error) => return Ok(()),
                    Err(error) => break Err(format!("secure control lane disconnected: {error}")),
                };
                if message.kind != ControlKind::RateUpdate {
                    break Err(format!(
                        "unexpected host control message after negotiation: {:?}",
                        message.kind
                    ));
                }
                let update = RateUpdateMessage::decode(&message.payload)
                    .map_err(|error| format!("invalid rate update: {error}"))?;
                if update.stream_id != config.stream_id || update.codec_epoch != config.codec_epoch
                {
                    break Err("rate update targeted a stale stream or codec epoch".to_owned());
                }
            }
            NetworkWork::Media(frame) => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) if is_clean_peer_close(&error) => return Ok(()),
                    Err(error) => {
                        break Err(format!("secure media transport disconnected: {error}"))
                    }
                };
                let frame = EncodedH264Frame::decode(frame, config)?;
                if let Err(error) =
                    advance_viewer_frame_id(&mut last_accepted_frame_id, frame.meta.frame_id)
                {
                    break Err(error);
                }
                received_bytes = received_bytes
                    .saturating_add(u64::try_from(frame.bytes.len()).unwrap_or(u64::MAX));

                let action = continuity.classify(frame.meta);
                if action == ContinuityAction::DropAndRequestRecovery {
                    continuity.note_loss();
                    let last_good = continuity.last_decoded_frame_id().unwrap_or(0);
                    request_recovery(
                        &session,
                        config,
                        last_good,
                        frame.meta.frame_id,
                        &mut last_recovery_sent,
                    )
                    .await?;
                    continue;
                }

                let frame_id = frame.meta.frame_id;
                let slot_decision = {
                    let mut slot = latest_frame
                        .lock()
                        .map_err(|_| "latest-frame queue lock was poisoned".to_owned())?;
                    enqueue_latest_frame(&mut slot, frame)
                };
                if slot_decision == LatestFrameSlotDecision::DroppedDependent {
                    continuity.note_loss();
                    let last_good = continuity.last_decoded_frame_id().unwrap_or(0);
                    request_recovery(
                        &session,
                        config,
                        last_good,
                        frame_id,
                        &mut last_recovery_sent,
                    )
                    .await?;
                }
            }
        }
    };

    sequence = sequence.saturating_add(1);
    let release_result = match send_input_event(
        &session,
        sequence,
        InputEvent::ReleaseAll,
        reliable_timeout,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(error) if is_clean_peer_close(error.as_ref()) => Ok(()),
        Err(error) => Err(format!("ReleaseAll shutdown send failed: {error}")),
    };
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(release)) => Err(release),
        (Err(primary), Err(release)) => Err(format!("{primary}; {release}")),
    }
}

#[cfg(any(windows, test))]
fn recovery_request_due(
    last_sent: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> bool {
    last_sent.is_none_or(|sent| now.duration_since(sent) >= RECOVERY_REQUEST_INTERVAL)
}
#[cfg(windows)]
async fn request_recovery(
    session: &ProductSession,
    config: latencydesk_protocol::VideoStreamConfig,
    last_good_frame_id: u64,
    first_missing_frame_id: u64,
    last_sent: &mut Option<tokio::time::Instant>,
) -> Result<(), String> {
    let now = tokio::time::Instant::now();
    if !recovery_request_due(*last_sent, now) {
        return Ok(());
    }
    let request = latencydesk_protocol::RecoveryRequest {
        stream_id: config.stream_id,
        codec_epoch: config.codec_epoch,
        last_good_frame_id,
        first_missing_frame_id,
    };
    session
        .send_control(
            latencydesk_protocol::ControlKind::RecoveryRequest,
            &request.encode(),
        )
        .await
        .map_err(|error| format!("recovery request send failed: {error}"))?;
    *last_sent = Some(now);
    println!(
        "recovery: requested IDR last_good={last_good_frame_id} first_missing={first_missing_frame_id}"
    );
    Ok(())
}

#[cfg(windows)]
fn advance_viewer_frame_id(last_accepted: &mut u64, next: u64) -> Result<(), String> {
    if next <= *last_accepted {
        return Err(format!(
            "refusing non-monotonic media frame {next}; last accepted frame was {last_accepted}"
        ));
    }
    *last_accepted = next;
    Ok(())
}

#[cfg(windows)]
fn park_viewer_if_idle(had_frame: bool, had_input: bool) {
    if !had_frame && !had_input {
        std::thread::park_timeout(VIEWER_IDLE_PARK);
    }
}

#[cfg(windows)]
fn apply_held_input(state: &mut latencydesk_input::InputState, event: &InputEvent) {
    match event {
        InputEvent::Key { code, pressed } => {
            let _ = state.set_key(*code, *pressed);
        }
        InputEvent::PointerButton { button, pressed } => {
            let _ = state.set_button(*button, *pressed);
        }
        InputEvent::ReleaseAll => *state = latencydesk_input::InputState::default(),
        InputEvent::Snapshot(snapshot) => *state = snapshot.clone(),
        InputEvent::PointerMotionRelative { .. }
        | InputEvent::PointerMotionAbsolute { .. }
        | InputEvent::Wheel { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_socket_transport::identity::{
        accept_exact_peer, mtls_client_config, mtls_server_config,
    };
    use latencydesk_socket_transport::quic::bind_server;
    use std::net::SocketAddr;
    use std::num::NonZeroU64;

    #[test]
    fn hex_encoding_is_fixed_width_and_lowercase() {
        assert_eq!(encode_hex(&[0, 1, 0xab, 0xff]), "0001abff");
    }

    #[test]
    fn codec_preferences_are_explicit_and_disjoint() {
        assert_eq!(
            VideoCodecPreference::H264High420.capability_flag(),
            latencydesk_protocol::video_capability_flags::H264_HIGH_420
        );
        assert_eq!(
            VideoCodecPreference::H264High420.expected_pair(),
            (
                latencydesk_protocol::VideoCodec::H264,
                latencydesk_protocol::VideoProfile::H264High420
            )
        );
        assert_eq!(
            VideoCodecPreference::RawNv12.capability_flag(),
            latencydesk_protocol::video_capability_flags::RAW_NV12
        );
        assert_eq!(
            VideoCodecPreference::RawNv12.expected_pair(),
            (
                latencydesk_protocol::VideoCodec::RawNv12,
                latencydesk_protocol::VideoProfile::RawNv12
            )
        );
    }

    #[test]
    fn reconnect_classification_never_retries_identity_or_protocol_failures() {
        let candidate_timeout = SessionEstablishError::Candidate(
            latencydesk_socket_transport::identity::IdentityError::QuicTransport(
                latencydesk_socket_transport::quic::QuicTransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "candidate timeout",
                )),
            ),
        );
        let certificate_mismatch = SessionEstablishError::Candidate(
            latencydesk_socket_transport::identity::IdentityError::PeerCertificateMismatch,
        );
        let handshake_protocol = SessionEstablishError::Handshake(ProductSessionError::Protocol(
            latencydesk_protocol::ProtocolError::InvalidSessionStamp,
        ));

        assert!(candidate_timeout.is_retryable_connection_attempt());
        assert!(SessionEstablishError::Deadline(Duration::from_secs(1))
            .is_retryable_connection_attempt());
        assert!(!certificate_mismatch.is_retryable_connection_attempt());
        assert!(!handshake_protocol.is_retryable_connection_attempt());
    }

    #[test]
    fn session_run_retryability_survives_error_erasure() {
        let timeout = ProductSessionError::Quic(
            latencydesk_socket_transport::quic::QuicTransportError::Connection(
                quinn::ConnectionError::TimedOut,
            ),
        );
        let protocol =
            ProductSessionError::Protocol(latencydesk_protocol::ProtocolError::InvalidSessionStamp);

        assert!(is_retryable_session_run_error(&timeout));
        assert!(!is_retryable_session_run_error(&protocol));
    }

    #[test]
    fn reconnect_attempt_claims_are_global_and_never_exceed_policy() {
        let policy = latencydesk_session::lifecycle::ReconnectPolicy::new(3)
            .expect("bounded reconnect policy");
        let mut used = 0;
        for expected in 1..=3 {
            assert!(claim_reconnect_delay(policy, &mut used, 41).is_some());
            assert_eq!(used, expected);
        }
        assert_eq!(claim_reconnect_delay(policy, &mut used, 41), None);
        assert_eq!(used, 3);
    }

    #[test]
    fn reconnect_delay_timer_is_constructed_inside_the_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        wait_for_reconnect_delay(&runtime, Duration::ZERO);
    }

    #[test]
    fn quinn_endpoint_is_composed_inside_the_runtime_context() {
        let client = TlsIdentity::generate("client-test").expect("client identity");
        let host = TlsIdentity::generate("host-test").expect("host identity");
        let configuration = mtls_client_config(&client, host.certificate_der())
            .expect("mutually authenticated client config");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let bind_address: SocketAddr = "127.0.0.1:0".parse().expect("bind address");

        let endpoint = in_runtime_context(&runtime, || bind_client(configuration, bind_address))
            .expect("Quinn endpoint requires an entered Tokio runtime");
        assert!(endpoint.local_addr().expect("local address").port() > 0);
        endpoint.close(0_u32.into(), b"test complete");
        runtime.block_on(endpoint.wait_idle());
    }

    #[test]
    fn reliable_input_bound_never_exceeds_session_or_cleanup_policy() {
        assert_eq!(
            reliable_operation_timeout(Duration::from_secs(1)),
            Duration::from_secs(1)
        );
        assert_eq!(
            reliable_operation_timeout(Duration::from_secs(60)),
            CLIENT_RELIABLE_OPERATION_TIMEOUT
        );
    }

    #[test]
    fn viewer_cleanup_budget_covers_two_reliable_operations_and_scheduler_allowance() {
        assert_eq!(
            viewer_network_cleanup_timeout(CLIENT_RELIABLE_OPERATION_TIMEOUT),
            Duration::from_millis(10_250)
        );
        assert_eq!(
            viewer_network_cleanup_timeout(Duration::from_secs(1)),
            Duration::from_millis(2_250)
        );
    }

    #[test]
    fn viewer_cleanup_budget_is_bounded_when_duration_arithmetic_overflows() {
        assert_eq!(
            viewer_network_cleanup_timeout(Duration::MAX),
            Duration::from_secs(15)
        );
    }

    #[test]
    fn snapshot_cadence_is_half_second_on_the_reliable_lane() {
        assert_eq!(SNAPSHOT_CADENCE, Duration::from_millis(500));
        assert!(SNAPSHOT_CADENCE < CLIENT_RELIABLE_OPERATION_TIMEOUT);
    }

    #[derive(Clone, Copy)]
    enum CleanCloseObservation {
        Media,
        Input,
        Snapshot,
    }

    async fn observe_host_close(
        operation: CleanCloseObservation,
        application_code: u32,
    ) -> Box<dyn Error> {
        let client_identity = TlsIdentity::generate("client-clean-close").expect("client identity");
        let host_identity = TlsIdentity::generate("host-clean-close").expect("host identity");
        let server_configuration =
            mtls_server_config(&host_identity, client_identity.certificate_der())
                .expect("server configuration");
        let client_configuration =
            mtls_client_config(&client_identity, host_identity.certificate_der())
                .expect("client configuration");
        let server_endpoint = bind_server(
            server_configuration,
            "127.0.0.1:0".parse().expect("server bind address"),
        )
        .expect("server endpoint");
        let client_endpoint = bind_client(
            client_configuration,
            "127.0.0.1:0".parse().expect("client bind address"),
        )
        .expect("client endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");
        let (server_connection, client_connection) = tokio::join!(
            accept_exact_peer(&server_endpoint, client_identity.certificate_der()),
            connect_exact_peer(
                &client_endpoint,
                server_address,
                host_identity.certificate_der()
            ),
        );
        let (host_session, client_session) = tokio::join!(
            ProductSession::host(
                server_connection.expect("server connection"),
                NonZeroU64::new(1).expect("nonzero session id"),
            ),
            ProductSession::client(client_connection.expect("client connection")),
        );
        let _host_session = host_session.expect("host session");
        let client_session = client_session.expect("client session");

        server_endpoint.close(application_code.into(), b"host session complete");
        if !matches!(operation, CleanCloseObservation::Media) {
            let error =
                tokio::time::timeout(Duration::from_secs(5), client_session.receive_media_frame())
                    .await
                    .expect("client observes host close before reliable send")
                    .expect_err("closed host cannot provide media");
            assert!(is_clean_peer_close(&error));
        }
        match operation {
            CleanCloseObservation::Media => {
                let error = tokio::time::timeout(
                    Duration::from_secs(5),
                    client_session.receive_media_frame(),
                )
                .await
                .expect("media receive observes host close")
                .expect_err("closed host cannot provide media");
                Box::new(error)
            }
            CleanCloseObservation::Input => tokio::time::timeout(
                Duration::from_secs(5),
                send_input_event(
                    &client_session,
                    1,
                    InputEvent::Key {
                        code: 4,
                        pressed: true,
                    },
                    Duration::from_secs(1),
                ),
            )
            .await
            .expect("input send observes host close")
            .expect_err("closed host cannot accept input"),
            CleanCloseObservation::Snapshot => tokio::time::timeout(
                Duration::from_secs(5),
                send_input_event(
                    &client_session,
                    1,
                    InputEvent::Snapshot(latencydesk_input::InputState::default()),
                    Duration::from_secs(1),
                ),
            )
            .await
            .expect("snapshot send observes host close")
            .expect_err("closed host cannot accept a snapshot"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn media_clean_peer_close_has_success_disposition() {
        let error = observe_host_close(CleanCloseObservation::Media, 0).await;
        assert!(is_clean_peer_close(error.as_ref()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn command_send_clean_peer_close_has_success_disposition() {
        let error = observe_host_close(CleanCloseObservation::Input, 0).await;
        assert!(is_clean_peer_close(error.as_ref()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_send_clean_peer_close_has_success_disposition() {
        let error = observe_host_close(CleanCloseObservation::Snapshot, 0).await;
        assert!(is_clean_peer_close(error.as_ref()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nonzero_host_application_close_remains_an_error() {
        let error = observe_host_close(CleanCloseObservation::Media, 1).await;
        assert!(!is_clean_peer_close(error.as_ref()));
    }

    #[test]
    fn non_transport_session_and_encoding_failures_are_not_clean_peer_closes() {
        assert!(!is_clean_peer_close(
            &ProductSessionError::MediaDeadlineOverflow
        ));
        assert!(!is_clean_peer_close(&std::io::Error::other(
            "input encoding failed"
        )));
    }

    #[test]
    fn slot_pressure_queues_two_dependent_frames_then_drops() {
        let mut slot = VecDeque::new();
        let first = enqueue_latest_frame(
            &mut slot,
            EncodedH264Frame {
                meta: latencydesk_media::EncodedFrameMeta {
                    codec_epoch: 1,
                    frame_id: 10,
                    dependency_frame_id: Some(9),
                    recovery_point: false,
                },
                bytes: vec![10],
            },
        );
        assert_eq!(first, LatestFrameSlotDecision::Queued);
        let second = enqueue_latest_frame(
            &mut slot,
            EncodedH264Frame {
                meta: latencydesk_media::EncodedFrameMeta {
                    codec_epoch: 1,
                    frame_id: 11,
                    dependency_frame_id: Some(10),
                    recovery_point: false,
                },
                bytes: vec![11],
            },
        );
        assert_eq!(second, LatestFrameSlotDecision::Queued);
        let third = enqueue_latest_frame(
            &mut slot,
            EncodedH264Frame {
                meta: latencydesk_media::EncodedFrameMeta {
                    codec_epoch: 1,
                    frame_id: 12,
                    dependency_frame_id: Some(11),
                    recovery_point: false,
                },
                bytes: vec![12],
            },
        );
        assert_eq!(third, LatestFrameSlotDecision::DroppedDependent);
        assert_eq!(
            slot.iter()
                .map(|frame| frame.meta.frame_id)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );
    }

    #[test]
    fn recovery_point_replaces_queued_dependent_frame() {
        let mut slot = VecDeque::from([EncodedH264Frame {
            meta: latencydesk_media::EncodedFrameMeta {
                codec_epoch: 1,
                frame_id: 10,
                dependency_frame_id: Some(9),
                recovery_point: false,
            },
            bytes: vec![10],
        }]);
        let decision = enqueue_latest_frame(
            &mut slot,
            EncodedH264Frame {
                meta: latencydesk_media::EncodedFrameMeta {
                    codec_epoch: 2,
                    frame_id: 20,
                    dependency_frame_id: None,
                    recovery_point: true,
                },
                bytes: vec![20],
            },
        );
        assert_eq!(decision, LatestFrameSlotDecision::ReplacedWithRecovery);
        assert_eq!(slot.len(), 1);
        assert_eq!(slot[0].meta.frame_id, 20);
        assert_eq!(slot[0].bytes.as_slice(), &[20]);
    }

    #[tokio::test]
    async fn network_work_prioritizes_shutdown_then_input_then_snapshot() {
        use std::future::{pending, ready};

        assert_eq!(
            select_network_work(
                ready(()),
                ready("input"),
                ready(()),
                pending::<()>(),
                ready("media"),
            )
            .await,
            NetworkWork::Shutdown
        );
        assert_eq!(
            select_network_work(
                pending::<()>(),
                ready("input"),
                ready(()),
                pending::<()>(),
                ready("media"),
            )
            .await,
            NetworkWork::Command("input")
        );
        assert_eq!(
            select_network_work(
                pending::<()>(),
                pending::<()>(),
                ready(()),
                pending::<()>(),
                ready("media"),
            )
            .await,
            NetworkWork::Snapshot
        );
    }

    #[test]
    fn recovery_requests_are_rate_limited_after_the_first_request() {
        let now = tokio::time::Instant::now();
        assert!(recovery_request_due(None, now));
        assert!(!recovery_request_due(
            Some(now - RECOVERY_REQUEST_INTERVAL / 2),
            now
        ));
        assert!(recovery_request_due(
            Some(now - RECOVERY_REQUEST_INTERVAL),
            now
        ));
    }

    #[cfg(windows)]
    #[test]
    fn viewer_idle_park_is_zero_timeout_not_a_fixed_sleep() {
        assert!(VIEWER_IDLE_PARK.is_zero());
    }

    #[cfg(windows)]
    #[test]
    fn held_input_tracks_keys_and_clears_on_release_all() {
        let mut state = latencydesk_input::InputState::default();
        apply_held_input(
            &mut state,
            &InputEvent::Key {
                code: 4,
                pressed: true,
            },
        );
        apply_held_input(
            &mut state,
            &InputEvent::PointerButton {
                button: 1,
                pressed: true,
            },
        );
        assert!(state.key_pressed(4));
        assert!(state.button_pressed(1));
        apply_held_input(&mut state, &InputEvent::ReleaseAll);
        assert!(state.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn viewer_frame_gate_rejects_replay_and_rollback() {
        let mut last = 10_u64;
        assert!(advance_viewer_frame_id(&mut last, 11).is_ok());
        assert_eq!(last, 11);
        assert!(advance_viewer_frame_id(&mut last, 11).is_err());
        assert!(advance_viewer_frame_id(&mut last, 9).is_err());
        assert_eq!(last, 11);
    }
}
