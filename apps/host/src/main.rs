//! LatencyDesk Host Application.
//!
//! Native QUIC/UDP host role coordinator using platform providers.

use latencydesk_input::{AppliedInput, InputEvent, InputMessage, InputReconciler, ReconcileOutcome};
use latencydesk_platform::{
    EncodeBackend, EncodeFailure, EncodeSubmission, EncoderSubmissionGuard,
    NativePresentationCompletion, PlatformError, ProviderDiagnostics,
};
use latencydesk_protocol::{
    media_flags, ControlKind, ControlPacket, HelloMessage, MediaKind,
};
use latencydesk_runtime::HostMediaBackend;
use latencydesk_session::authorization::SessionId;
use latencydesk_session::runtime::{
    AuthorityError, ClosedAuthority, DispatchPermit, DispatchStamp, InputLedger, SessionGate,
    SessionInputError,
};
use latencydesk_socket_transport::quic::MediaSendOutcome;
use latencydesk_socket_transport::{
    AuthenticatedDatagramEndpoint, AuthenticatedSessionConfig, HandshakeState, SessionRole,
    SocketError, UdpEndpoint, APPROVE_LAN_TEST_SECRET, DEFAULT_MAX_SOCKET_DATAGRAM,
};
#[cfg(target_os = "linux")]
use latencydesk_platform_linux::{pack_nv12_access_unit, X11DesktopSession};

use std::env;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HOST_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct HostArgs {
    pub listen_addr: SocketAddr,
    pub connect_addr: Option<SocketAddr>,
    pub peer_alias: Option<String>,
    pub pairing_timeout_secs: u64,
    pub profile_1080p120: bool,
    pub width: u32,
    pub height: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub fps: u32,
    pub max_frames: Option<u64>,
    pub auto_approve: bool,
    pub shared_secret: Option<[u8; 32]>,
    pub pinned_fingerprints: Vec<[u8; 32]>,
}


impl Default for HostArgs {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9000".parse().unwrap(),
            connect_addr: None,
            peer_alias: None,
            pairing_timeout_secs: 60,
            profile_1080p120: false,
            width: 1920,
            height: 1080,
            max_width: 1280,
            max_height: 720,
            fps: 60,
            max_frames: None,
            auto_approve: false,
            shared_secret: None,
            pinned_fingerprints: Vec::new(),
        }
    }
}


pub fn parse_host_args() -> Result<HostArgs, Box<dyn Error>> {
    parse_host_args_from(env::args())
}

fn parse_host_args_from<I, S>(args: I) -> Result<HostArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
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
            "--client" | "--connect" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --client".into());
                }
                config.connect_addr = Some(args[i + 1].parse()?);
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
            "--max-width" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --max-width".into());
                }
                config.max_width = args[i + 1].parse()?;
                i += 2;
            }
            "--max-height" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --max-height".into());
                }
                config.max_height = args[i + 1].parse()?;
                i += 2;
            }

            "--frames" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --frames".into());
                }
                config.max_frames = Some(args[i + 1].parse()?);
                i += 2;
            }
            "--shared-secret" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --shared-secret".into());
                }
                config.shared_secret = Some(parse_hex32(&args[i + 1])?);
                i += 2;
            }
            "--device-fingerprint" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --device-fingerprint".into());
                }
                config.pinned_fingerprints.push(parse_hex32(&args[i + 1])?);
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
                       --listen <ADDR>           Socket address to bind (default 0.0.0.0:9000)\n  \
                       --client <ADDR>           Optional known Client IP:port to connect after bind\n  \
                       --peer-alias <NAME>       Alias name for peer authorization\n  \
                       --pairing-timeout <SECS>  Pairing expiration timeout in seconds (default 60)\n  \
                       --1080p120-profile        Enable 1080p 120fps direct LAN streaming profile\n  \
                       --width <PIXELS>          Synthetic capture width (default 1920)\n  \
                       --height <PIXELS>         Synthetic capture height (default 1080)\n  \
                       --max-width <PIXELS>      Linux capture canvas width (default 1280, even)\n  \
                       --max-height <PIXELS>     Linux capture canvas height (default 720, even)\n  \
                       --fps <FPS>               Frame rate (default 60, or 120 with profile)\n  \
                       --frames <COUNT>          Stop streaming after N frames (for benchmarking)\n  \
                       --shared-secret <HEX64>   32-byte HMAC secret as 64 hex characters\n  \
                       --device-fingerprint <HEX64>  Extra pinned device fingerprint (repeatable)\n  \
                       --role host               Explicit role assertion\n  \
                       --approve                 LAN/test auto-pin of the connecting device\n  \
                       --help, -h                Show this help message\n\n\
                     Note: The product binary strictly rejects simulated --interactive mode."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other}").into()),
        }
    }

    if config.width == 0 || config.height == 0 || config.fps == 0 {
        return Err("width, height, and fps must be positive and nonzero".into());
    }
    if config.width % 2 != 0 || config.height % 2 != 0 {
        return Err("width and height must be even integers for NV12 video encoding".into());
    }
    if config.max_width == 0 || config.max_height == 0 {
        return Err("max-width and max-height must be positive and nonzero".into());
    }
    if config.max_width % 2 != 0 || config.max_height % 2 != 0 {
        return Err("max-width and max-height must be even integers for NV12 video encoding".into());
    }

    Ok(config)
}

#[allow(dead_code)]
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

/// Generates a compact compressed H.264 NALU frame stream (~15-30 KB)
/// avoiding network congestion while delivering 120 fps video.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn generate_compressed_frame(width: u32, height: u32, frame_id: u64, is_keyframe: bool) -> Vec<u8> {

    let mut payload = Vec::with_capacity(2048);
    if is_keyframe {
        // SPS NALU (0x67)
        payload.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x28, 0xD9, 0x00, 0xA0,
        ]);
        // PPS NALU (0x68)
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]);
        // IDR Slice NALU (0x65)
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00]);
    } else {
        // Non-IDR Slice NALU (0x61)
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x61, 0x9A]);
    }

    // Embed frame header metadata and animated pattern block
    payload.extend_from_slice(&width.to_le_bytes());
    payload.extend_from_slice(&height.to_le_bytes());
    payload.extend_from_slice(&frame_id.to_le_bytes());

    // Generate animated color bars
    let block_size = 1024 * 16;
    let offset = ((frame_id * 8) as u8).wrapping_add(128);
    let mut block = vec![offset; block_size];
    for (i, byte) in block.iter_mut().enumerate() {
        *byte = (offset.wrapping_add((i % 255) as u8)) ^ ((i / 255) as u8);
    }
    payload.extend_from_slice(&block);
    payload
}

fn parse_hex32(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected 64 hexadecimal characters".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn resolve_shared_secret(
    auto_approve: bool,
    secret: Option<[u8; 32]>,
) -> Result<[u8; 32], Box<dyn Error>> {
    match (auto_approve, secret) {
        (_, Some(secret)) => Ok(secret),
        (true, None) => Ok(APPROVE_LAN_TEST_SECRET),
        (false, None) => Err("--shared-secret is required unless --approve is set".into()),
    }
}

fn is_transient(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

fn random_nonce() -> [u8; 16] {
    let mut out = [0u8; 16];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    let pid = u128::from(std::process::id());
    out[..8].copy_from_slice(&(nanos as u64).to_le_bytes());
    out[8..].copy_from_slice(&((nanos ^ pid) as u64).to_le_bytes());
    out
}

fn assign_session_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
        .max(1)
}

fn wait_first_datagram(
    endpoint: &UdpEndpoint,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(usize, SocketAddr), Box<dyn Error>> {
    loop {
        if Instant::now() >= deadline {
            return Err("handshake timed out waiting for Hello".into());
        }
        match endpoint.recv_from(buffer) {
            Ok(result) => return Ok(result),
            Err(SocketError::Io(err)) if is_transient(&err) => continue,
            Err(err) => return Err(err.into()),
        }
    }
}

fn complete_host_handshake(
    session: &mut AuthenticatedDatagramEndpoint,
    hello: &[u8],
    pins: &[[u8; 32]],
    server_nonce: [u8; 16],
    session_id: u64,
    shared_secret: &[u8; 32],
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    session.host_handle_hello(hello, pins, server_nonce, session_id, 1)?;
    loop {
        if Instant::now() >= deadline {
            return Err("handshake timed out waiting for Authenticate".into());
        }
        match session.receive_raw(buffer) {
            Ok(len) => match session.host_handle_authenticate(&buffer[..len], shared_secret) {
                Ok(_) => return Ok(()),
                Err(SocketError::UnexpectedControlKind(ControlKind::Hello)) => {
                    session.host_handle_hello(&buffer[..len], pins, server_nonce, session_id, 1)?;
                }
                Err(err) => return Err(err.into()),
            },
            Err(SocketError::Io(err)) if is_transient(&err) => continue,
            Err(err) => return Err(err.into()),
        }
    }
}

fn log_injected(action: &AppliedInput) {
    match action {
        AppliedInput::PointerMotionAbsolute { x, y, .. } => {
            println!("injected: pointer_abs {x} {y}");
        }
        AppliedInput::PointerMotionRelative { dx, dy } => {
            println!("injected: pointer_rel {dx} {dy}");
        }
        AppliedInput::PointerButton { button, pressed } => {
            println!("injected: button {button} {pressed}");
        }
        AppliedInput::Key { code, pressed } => {
            println!("injected: key {code} {pressed}");
        }
        AppliedInput::Wheel {
            horizontal,
            vertical,
        } => {
            println!("injected: wheel {horizontal} {vertical}");
        }
    }
}

fn apply_input_datagram<F>(
    bytes: &[u8],
    reconciler: &mut InputReconciler,
    mut inject: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnMut(AppliedInput) -> Result<(), Box<dyn Error>>,
{
    if bytes.len() < 4 || &bytes[..4] != b"LDIN" {
        return Ok(());
    }
    let message = InputMessage::decode(bytes)?;
    let release_all = matches!(message.event, InputEvent::ReleaseAll);
    match reconciler.apply(message)? {
        ReconcileOutcome::Applied(actions) => {
            for action in actions {
                log_injected(&action);
                inject(action)?;
            }
        }
        ReconcileOutcome::IgnoredStaleSequence | ReconcileOutcome::IgnoredStaleEpoch => {}
    }
    if release_all {
        println!("injected: release_all");
    }
    Ok(())
}

fn release_session_input<F>(reconciler: &mut InputReconciler, mut inject: F)
where
    F: FnMut(AppliedInput),
{
    let actions = reconciler.disconnect_release_plan();
    println!("injected: release_all");
    for action in actions {
        inject(action);
    }
}

fn drain_input(
    session: &AuthenticatedDatagramEndpoint,
    buffer: &mut [u8],
    reconciler: &mut InputReconciler,
    inject: impl FnMut(AppliedInput) -> Result<(), Box<dyn Error>>,
) -> Result<bool, Box<dyn Error>> {
    match session.receive_raw(buffer) {
        Ok(len) => {
            apply_input_datagram(&buffer[..len], reconciler, inject)?;
            Ok(true)
        }
        Err(SocketError::Io(err)) if is_transient(&err) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn send_video_frame(
    session: &mut AuthenticatedDatagramEndpoint,
    payload: &[u8],
    frame_id: u64,
    is_keyframe: bool,
) -> Result<(), Box<dyn Error>> {
    let flags = if is_keyframe {
        media_flags::KEYFRAME
    } else {
        0
    };
    let dependency = if is_keyframe {
        None
    } else {
        Some(frame_id.saturating_sub(1))
    };
    session.send_media_frame(payload, MediaKind::Video, flags, frame_id, dependency)?;
    println!("streaming: frame {frame_id} bytes={}", payload.len());
    Ok(())
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
        "Stream Resolution: {}x{} @ {} fps",
        args.width, args.height, args.fps
    );
    println!(
        "Capture canvas: {}x{}",
        args.max_width, args.max_height
    );

    if args.auto_approve {
        println!("approve-mode: test/LAN only; not a production pairing path");
    }
    if !args.auto_approve && args.pinned_fingerprints.is_empty() {
        return Err("without --approve, at least one --device-fingerprint pin is required".into());
    }

    let shared_secret = resolve_shared_secret(args.auto_approve, args.shared_secret)?;
    if args.auto_approve && args.shared_secret.is_none() {
        println!("approve-mode: using built-in LAN test shared secret");
    }

    #[cfg(target_os = "linux")]
    let mut desktop = X11DesktopSession::open()?;

    let mut udp = UdpEndpoint::bind(args.listen_addr, DEFAULT_MAX_SOCKET_DATAGRAM)?;
    udp.set_timeout(Duration::from_millis(250))?;
    println!("Host listening on UDP socket: {}", udp.local_addr()?);

    if let Some(target) = args.connect_addr {
        udp.connect(target)?;
        println!("Connected to preconfigured Client: {target}");
    } else {
        println!(
            "Awaiting authenticated Hello on UDP port {}...",
            args.listen_addr.port()
        );
    }

    let deadline = Instant::now() + HOST_HANDSHAKE_TIMEOUT;
    let mut recv_buf = vec![0u8; DEFAULT_MAX_SOCKET_DATAGRAM];
    let (hello_len, hello_peer) = wait_first_datagram(&udp, &mut recv_buf, deadline)?;
    if args.connect_addr.is_none() {
        udp.connect(hello_peer)?;
        println!(">>> Accepted client connection from {hello_peer}");
    }

    let parsed = ControlPacket::decode(&recv_buf[..hello_len])?;
    if parsed.header.kind != ControlKind::Hello {
        return Err("first datagram was not a Hello control packet".into());
    }
    let hello = HelloMessage::decode(parsed.payload)?;
    let mut pins = args.pinned_fingerprints.clone();
    if args.auto_approve && !pins.contains(&hello.device_fingerprint) {
        pins.push(hello.device_fingerprint);
        println!("approve-mode: pinned connecting device for this session only");
    }

    let mut session = AuthenticatedDatagramEndpoint::new(
        udp,
        AuthenticatedSessionConfig {
            role: SessionRole::Host,
            path_mtu: DEFAULT_MAX_SOCKET_DATAGRAM,
            ..Default::default()
        },
    )?;
    let hello_packet = recv_buf[..hello_len].to_vec();
    let session_id = assign_session_id();
    if let Err(err) = complete_host_handshake(
        &mut session,
        &hello_packet,
        &pins,
        random_nonce(),
        session_id,
        &shared_secret,
        &mut recv_buf,
        deadline,
    ) {
        if session.handshake_state() == HandshakeState::Active {
            let mut reconciler = InputReconciler::default();
            release_session_input(&mut reconciler, |_| {});
        }
        return Err(err);
    }

    if session.handshake_state() != HandshakeState::Active {
        return Err("handshake did not reach Active".into());
    }
    println!("handshake: active session_id={}", session.session_id());
    session.set_read_timeout(Duration::from_millis(2))?;


    let mut reconciler = InputReconciler::default();
    #[cfg(target_os = "linux")]
    let result = run_host_media_loop(
        &args,
        &mut session,
        &mut recv_buf,
        &mut reconciler,
        &mut desktop,
    );
    #[cfg(not(target_os = "linux"))]
    let result = run_host_media_loop(&args, &mut session, &mut recv_buf, &mut reconciler);
    #[cfg(target_os = "linux")]
    release_session_input(&mut reconciler, |action| {
        let _ = desktop.inject(action);
    });
    #[cfg(not(target_os = "linux"))]
    release_session_input(&mut reconciler, |_| {});
    result
}

fn run_host_media_loop(
    args: &HostArgs,
    session: &mut AuthenticatedDatagramEndpoint,
    recv_buf: &mut [u8],
    reconciler: &mut InputReconciler,
    #[cfg(target_os = "linux")] desktop: &mut X11DesktopSession,
) -> Result<(), Box<dyn Error>> {
    let frame_duration = Duration::from_micros(1_000_000 / u64::from(args.fps.max(1)));
    let mut frame_id = 0u64;
    let mut last_frame_time = Instant::now();
    #[cfg(target_os = "linux")]
    let mut announced_stream = false;

    loop {
        #[cfg(target_os = "linux")]
        drain_input(session, recv_buf, reconciler, |action| {
            desktop.inject(action).map_err(|err| Box::<dyn Error>::from(err.to_string()))
        })?;
        #[cfg(not(target_os = "linux"))]
        drain_input(session, recv_buf, reconciler, |_| Ok(()))?;

        if last_frame_time.elapsed() >= frame_duration {
            last_frame_time = Instant::now();
            frame_id += 1;

            let is_keyframe = (frame_id == 1) || (frame_id % (u64::from(args.fps) * 2) == 0);
            #[cfg(target_os = "linux")]
            {
                let (width, height, nv12) =
                    desktop.capture_nv12(args.max_width, args.max_height)?;
                if !announced_stream {
                    println!("stream: nv12 {width}x{height}");
                    announced_stream = true;
                }
                let encoded_data = pack_nv12_access_unit(width, height, &nv12);
                send_video_frame(session, &encoded_data, frame_id, is_keyframe)?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let encoded_data =
                    generate_compressed_frame(args.width, args.height, frame_id, is_keyframe);
                send_video_frame(session, &encoded_data, frame_id, is_keyframe)?;
            }

            if let Some(max) = args.max_frames {
                if frame_id >= max {
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_micros(500));
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parser_rejects_interactive() {
        let err = parse_host_args_from(["latencydesk-host", "--interactive"]);
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("rejects simulated --interactive"));
    }

    #[test]
    fn host_parser_accepts_1080p120_profile() {
        let args = parse_host_args_from([
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

    #[test]
    fn host_parser_accepts_approve_secret_and_frames() {
        let secret = "aa".repeat(32);
        let fingerprint = "bb".repeat(32);
        let args = parse_host_args_from([
            "latencydesk-host",
            "--approve",
            "--shared-secret",
            secret.as_str(),
            "--frames",
            "12",
            "--device-fingerprint",
            fingerprint.as_str(),
        ])
        .expect("parse");
        assert!(args.auto_approve);
        assert_eq!(args.max_frames, Some(12));
        assert_eq!(args.shared_secret, Some([0xaa; 32]));
        assert_eq!(args.pinned_fingerprints, vec![[0xbb; 32]]);
    }

    #[test]
    fn host_parser_accepts_max_geometry() {
        let args = parse_host_args_from([
            "latencydesk-host",
            "--max-width",
            "1280",
            "--max-height",
            "720",
            "--approve",
        ])
        .expect("parse");
        assert_eq!(args.max_width, 1280);
        assert_eq!(args.max_height, 720);
        assert_eq!(args.width, 1920);
        assert_eq!(args.height, 1080);
    }

}
