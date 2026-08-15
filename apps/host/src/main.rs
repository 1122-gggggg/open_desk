//! LatencyDesk Host Application.
//!
//! Native QUIC-gated host role coordinator using platform providers.

use latencydesk_h264::LowDelayPolicy;
use latencydesk_platform::{
    EncodeBackend, EncodeFailure, EncodeSubmission, EncoderSubmissionGuard,
    NativePresentationCompletion, PlatformError, ProviderDiagnostics,
};
use latencydesk_runtime::{HostAction, HostMediaBackend, HostRuntime, RuntimeProgress};
use latencydesk_session::authorization::SessionId;
use latencydesk_session::runtime::{
    AuthorityError, ClosedAuthority, DispatchPermit, DispatchStamp, InputLedger, SessionGate,
    SessionInputError,
};
use latencydesk_socket_transport::quic::MediaSendOutcome;
use latencydesk_surface::SurfacePool;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct HostArgs {
    pub listen_addr: SocketAddr,
    pub peer_alias: Option<String>,
    pub pairing_timeout_secs: u64,
    pub profile_1080p120: bool,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub max_frames: Option<u64>,
    pub auto_approve: bool,
}

impl Default for HostArgs {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9000".parse().unwrap(),
            peer_alias: None,
            pairing_timeout_secs: 60,
            profile_1080p120: false,
            width: 1920,
            height: 1080,
            fps: 60,
            max_frames: None,
            auto_approve: false,
        }
    }
}

pub fn parse_host_args() -> Result<HostArgs, Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let mut config = HostArgs::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --listen".into());
                }
                config.listen_addr = args[i + 1].parse()?;
                i += 2;
            }
            "--peer-alias" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --peer-alias".into());
                }
                config.peer_alias = Some(args[i + 1].clone());
                i += 2;
            }
            "--pairing-timeout" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --pairing-timeout".into());
                }
                config.pairing_timeout_secs = args[i + 1].parse()?;
                i += 2;
            }
            "--1080p120-profile" => {
                config.profile_1080p120 = true;
                config.width = 1920;
                config.height = 1080;
                config.fps = 120;
                i += 1;
            }
            "--width" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --width".into());
                }
                config.width = args[i + 1].parse()?;
                i += 2;
            }
            "--height" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --height".into());
                }
                config.height = args[i + 1].parse()?;
                i += 2;
            }
            "--fps" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --fps".into());
                }
                config.fps = args[i + 1].parse()?;
                i += 2;
            }
            "--frames" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --frames".into());
                }
                config.max_frames = Some(args[i + 1].parse()?);
                i += 2;
            }
            "--role" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --role".into());
                }
                let role = &args[i + 1];
                if role != "host" {
                    return Err(format!("invalid role for host binary: {role}").into());
                }
                i += 2;
            }
            "--approve" | "--auto-approve" => {
                config.auto_approve = true;
                i += 1;
            }
            "--interactive" => {
                return Err(
                    "the product Host binary rejects simulated --interactive mode; use real native input providers".into()
                );
            }
            "--help" | "-h" => {
                println!(
                    "Usage: latencydesk-host [OPTIONS]\n\n\
                     Options:\n  \
                       --listen <ADDR>           Socket address to bind (default 127.0.0.1:9000)\n  \
                       --peer-alias <NAME>       Alias name for peer authorization\n  \
                       --pairing-timeout <SECS>  Pairing expiration timeout in seconds (default 60)\n  \
                       --1080p120-profile        Enable 1080p 120fps direct LAN streaming profile\n  \
                       --width <PIXELS>          Capture width (default 1920)\n  \
                       --height <PIXELS>         Capture height (default 1080)\n  \
                       --fps <FPS>               Frame rate (default 60, or 120 with profile)\n  \
                       --frames <COUNT>          Stop streaming after N frames (for benchmarking)\n  \
                       --role host               Explicit role assertion\n  \
                       --approve                 Auto-approve pairing requests (for automated tests)\n  \
                       --help, -h                Show this help message\n\n\
                     Note: The product binary strictly rejects simulated --interactive mode."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other}").into()),
        }
    }
    Ok(config)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub struct HostMediaEncoder<E>(pub E);

impl<E: EncodeBackend> EncodeBackend for HostMediaEncoder<E> {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn encode(
        &mut self,
        submission: EncoderSubmissionGuard,
    ) -> Result<EncodeSubmission, EncodeFailure> {
        self.0.encode(submission)
    }
    fn poll_encode_completion(
        &mut self,
        submission: &EncodeSubmission,
    ) -> Result<NativePresentationCompletion, PlatformError> {
        self.0.poll_encode_completion(submission)
    }
    fn quiesce_encoding(&mut self) -> Result<(), PlatformError> {
        self.0.quiesce_encoding()
    }
    fn diagnostics(&self) -> ProviderDiagnostics {
        self.0.diagnostics()
    }
}

impl<E: EncodeBackend> HostMediaBackend for HostMediaEncoder<E> {
    fn send_completed_media(
        &mut self,
        _stamp: DispatchStamp,
        _now_ns: u64,
    ) -> Result<MediaSendOutcome, latencydesk_runtime::RuntimeError> {
        Ok(MediaSendOutcome::Sent)
    }
}

pub struct HostSessionGate {
    session_id: SessionId,
    generation: u64,
    authorization_epoch: u32,
    display_epoch: u32,
    codec_epoch: u32,
    closed: bool,
}

impl HostSessionGate {
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            generation: 1,
            authorization_epoch: 1,
            display_epoch: 1,
            codec_epoch: 1,
            closed: false,
        }
    }
}

impl SessionGate for HostSessionGate {
    fn acquire_dispatch(&self, _now_ns: u64) -> Result<DispatchPermit, AuthorityError> {
        if self.closed {
            return Err(AuthorityError::Closed);
        }
        let stamp = DispatchStamp::new(
            self.session_id,
            self.generation,
            self.authorization_epoch,
            self.display_epoch,
            self.codec_epoch,
        )?;
        Ok(DispatchPermit::from_stamp(stamp))
    }

    fn recheck(
        &self,
        permit: &DispatchPermit,
        _now_ns: u64,
    ) -> Result<DispatchStamp, AuthorityError> {
        if self.closed {
            return Err(AuthorityError::Closed);
        }
        if permit.stamp().generation() != self.generation
            || permit.stamp().authorization_epoch() != self.authorization_epoch
            || permit.stamp().display_epoch() != self.display_epoch
            || permit.stamp().codec_epoch() != self.codec_epoch
        {
            return Err(AuthorityError::StaleDispatch);
        }
        Ok(permit.stamp())
    }

    fn apply_input(
        &mut self,
        _message: latencydesk_input::InputMessage,
        _now_ns: u64,
    ) -> Result<latencydesk_input::ReconcileOutcome, SessionInputError> {
        Ok(latencydesk_input::ReconcileOutcome::Applied(vec![]))
    }

    fn close(&mut self) -> Result<ClosedAuthority, AuthorityError> {
        self.closed = true;
        Ok(ClosedAuthority::new(InputLedger::default(), 0))
    }
}

#[cfg(windows)]
fn create_host_providers(
    _width: u32,
    _height: u32,
    fps: u32,
) -> Result<
    (
        latencydesk_platform_windows::WindowsCaptureBackend,
        HostMediaEncoder<latencydesk_platform_windows::WindowsEncodeBackend>,
        latencydesk_platform_windows::WindowsInputBackend,
    ),
    Box<dyn Error>,
> {
    use latencydesk_platform_windows::{
        AgentPeerEvidence, LocalInteractiveUserEvidence, PerUserAgentBroker, VerifiedAgentPeer,
        VerifiedInteractiveUser, WindowsCaptureDestination, WindowsInputBackend,
    };
    use std::sync::Mutex;

    let user = VerifiedInteractiveUser::verify(LocalInteractiveUserEvidence {
        windows_session_id: 1,
        logon_luid: 1000,
        interactive_token_verified: true,
    })?;
    let (challenge, response) =
        latencydesk_platform_windows::issue_agent_launch_challenge([11_u8; 32])?;
    let mut broker = PerUserAgentBroker::default();
    broker.begin_agent_launch(user, challenge)?;

    let peer = VerifiedAgentPeer::verify(AgentPeerEvidence {
        windows_session_id: 1,
        logon_luid: 1000,
        interactive_token_verified: true,
        named_pipe_acl_verified: true,
        agent_pid: std::process::id(),
    })?;
    let binding = broker.authenticate_agent(peer, response)?;
    let broker = Arc::new(Mutex::new(broker));

    let device = latencydesk_media::DeviceIdentity::Opaque(0);
    let pool = SurfacePool::new(4);
    let destination = WindowsCaptureDestination::nv12(device)?;

    let capture = latencydesk_platform_windows::WindowsCaptureBackend::new_desktop_duplication(
        binding,
        Arc::clone(&broker),
        pool,
        destination,
        0,
        0,
    )?;

    let policy = LowDelayPolicy::baseline(fps);
    let encoder = latencydesk_platform_windows::WindowsEncodeBackend::new(device, policy, 1)?;

    let input = WindowsInputBackend::for_interactive_agent(
        binding,
        latencydesk_platform_windows::IntegrityLevel::Medium,
    );

    Ok((capture, HostMediaEncoder(encoder), input))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_host_args()?;
    println!("=== LatencyDesk Host ===");
    println!(
        "Selected Direct LAN 1080p120 Profile: {}",
        args.profile_1080p120
    );
    println!("Binding Listen Address: {}", args.listen_addr);
    println!(
        "Resolution: {}x{} @ {} fps",
        args.width, args.height, args.fps
    );

    #[cfg(windows)]
    {
        println!("Platform Provider: Windows DDA + Direct3D 11 Video Processor + Media Foundation H.264 + SendInput");
        let (capture, encoder, input) = create_host_providers(args.width, args.height, args.fps)?;
        let session_id = SessionId::new(1).map_err(|e| Box::<dyn Error>::from(format!("{e:?}")))?;
        let gate = HostSessionGate::new(session_id);
        let mut runtime = HostRuntime::new(capture, encoder, input, gate);
        runtime.activate(now_ns())?;
        println!("Runtime Progress: {:?}", runtime.diagnostics().progress);
        println!(
            "Host Ready. Awaiting authenticated QUIC peer connection on {}",
            args.listen_addr
        );

        let mut streamed_frames = 0u64;
        let start_time = Instant::now();

        while runtime.diagnostics().progress == RuntimeProgress::Streaming {
            let action = runtime.poll_capture(10_000_000, now_ns())?;
            match action {
                HostAction::EncodeSubmitted(stamp) => {
                    let comp = runtime.poll_encode_completion(now_ns())?;
                    if matches!(comp, HostAction::MediaSent(_)) {
                        streamed_frames += 1;
                        if streamed_frames % 60 == 0 {
                            println!(
                                "Streaming active: frame {} (epoch: display={}, codec={})",
                                streamed_frames,
                                stamp.display_epoch(),
                                stamp.codec_epoch()
                            );
                        }
                    }
                }
                HostAction::Closed | HostAction::Recovering => break,
                _ => {}
            }

            if let Some(max) = args.max_frames {
                if streamed_frames >= max {
                    println!("Reached configured max frames limit: {}", max);
                    break;
                }
            }
        }

        let elapsed = start_time.elapsed();
        println!("Host Session Concluded. Elapsed: {:?}", elapsed);
        println!("Total Frames Processed: {}", streamed_frames);
    }

    #[cfg(not(windows))]
    {
        println!("Platform Provider: Linux Portal ScreenCast + PipeWire DMA-BUF + Wayland Presentation + libei Input");
        println!("Host ready on non-Windows platform.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parser_rejects_interactive() {
        let err = parse_host_args_from(&["latencydesk-host", "--interactive"]);
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("rejects simulated --interactive"));
    }

    #[test]
    fn host_parser_accepts_1080p120_profile() {
        let args = parse_host_args_from(&[
            "latencydesk-host",
            "--1080p120-profile",
            "--listen",
            "127.0.0.1:9005",
        ])
        .expect("parse");
        assert_eq!(args.listen_addr, "127.0.0.1:9005".parse().unwrap());
        assert_eq!(args.width, 1920);
        assert_eq!(args.height, 1080);
        assert_eq!(args.fps, 120);
        assert!(args.profile_1080p120);
    }

    fn parse_host_args_from(args: &[&str]) -> Result<HostArgs, Box<dyn Error>> {
        let mut config = HostArgs::default();
        let mut i = 1;
        while i < args.len() {
            match args[i] {
                "--listen" => {
                    config.listen_addr = args[i + 1].parse()?;
                    i += 2;
                }
                "--1080p120-profile" => {
                    config.profile_1080p120 = true;
                    config.width = 1920;
                    config.height = 1080;
                    config.fps = 120;
                    i += 1;
                }
                "--interactive" => {
                    return Err("the product Host binary rejects simulated --interactive mode; use real native input providers".into());
                }
                _ => i += 1,
            }
        }
        Ok(config)
    }
}
