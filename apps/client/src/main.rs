//! LatencyDesk Client Application.
//!
//! Native QUIC/UDP client role coordinator using platform providers.

use latencydesk_input::{InputEvent, InputMessage};
use latencydesk_media::ContinuityAction;
use latencydesk_platform::{CursorMode, PlatformError, PresentableFrame, ProviderDiagnostics};
use latencydesk_runtime::{ClientRuntime, DecodeBackend, LocalInputBackend};
use latencydesk_session::authorization::SessionId;
use latencydesk_session::runtime::{
    AuthorityError, ClosedAuthority, DispatchPermit, DispatchStamp, InputLedger, SessionGate,
    SessionInputError,
};
use latencydesk_socket_transport::{
    AuthenticatedDatagramEndpoint, AuthenticatedSessionConfig, HandshakeState, SessionRole,
    SocketError, UdpEndpoint, APPROVE_LAN_TEST_SECRET, DEFAULT_MAX_SOCKET_DATAGRAM,
};
use latencydesk_transport::{IngestOutcome, ReassembledFrame, ReassemblyConfig};

use std::env;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CLIENT_SESSION_TIMEOUT: Duration = Duration::from_secs(20);
#[derive(Debug, Clone)]
pub struct ClientArgs {

    pub connect_addr: SocketAddr,
    pub bind_addr: SocketAddr,
    pub peer_alias: Option<String>,
    pub pairing_timeout_secs: u64,
    pub profile_1080p120: bool,
    pub max_frames: Option<u64>,
    pub width: u32,
    pub height: u32,
    pub auto_approve: bool,
    pub shared_secret: Option<[u8; 32]>,
    pub inject_probe: bool,
}

impl Default for ClientArgs {
    fn default() -> Self {
        Self {
            connect_addr: "127.0.0.1:9000".parse().unwrap(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            peer_alias: None,
            pairing_timeout_secs: 60,
            profile_1080p120: false,
            max_frames: None,
            width: 1280,
            height: 720,
            auto_approve: false,
            shared_secret: None,
            inject_probe: false,
        }
    }
}


pub fn parse_client_args() -> Result<ClientArgs, Box<dyn Error>> {
    parse_client_args_from(env::args())
}

fn parse_client_args_from<I, S>(args: I) -> Result<ClientArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut config = ClientArgs::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--connect" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --connect".into());
                }
                config.connect_addr = args[i + 1].parse()?;
                i += 2;
            }
            "--bind" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --bind".into());
                }
                config.bind_addr = args[i + 1].parse()?;
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
                i += 1;
            }
            "--frames" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --frames".into());
                }
                config.max_frames = Some(args[i + 1].parse()?);
                i += 2;
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
            "--inject-probe" => {
                config.inject_probe = true;
                i += 1;
            }

            "--shared-secret" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --shared-secret".into());
                }
                config.shared_secret = Some(parse_hex32(&args[i + 1])?);
                i += 2;
            }
            "--role" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --role".into());
                }
                let role = &args[i + 1];
                if role != "client" {
                    return Err(format!("invalid role for client binary: {role}").into());
                }
                i += 2;
            }
            "--approve" | "--auto-approve" => {
                config.auto_approve = true;
                i += 1;
            }
            "--interactive" => {
                return Err(
                    "the product Client binary rejects simulated --interactive mode; use real native input providers".into()
                );
            }
            "--help" | "-h" => {
                println!(
                    "Usage: latencydesk-client [OPTIONS]\n\n\
                     Options:\n  \
                       --connect <ADDR>          Host address to connect to (default 127.0.0.1:9000)\n  \
                       --bind <ADDR>             Local socket address to bind (default 0.0.0.0:0)\n  \
                       --peer-alias <NAME>       Alias name used to derive a stable device fingerprint\n  \
                       --pairing-timeout <SECS>  Pairing expiration timeout in seconds (default 60)\n  \
                       --1080p120-profile        Request 1080p 120fps direct LAN streaming profile\n  \
                       --width <PIXELS>          Presentation width (default 1280)\n  \
                       --height <PIXELS>         Presentation height (default 720)\n  \
                       --frames <COUNT>          Receive N completed frames then exit (headless)\n  \
                       --inject-probe            Send one pointer move and ReleaseAll, wait 3 frames, exit\n  \
                       --shared-secret <HEX64>   32-byte HMAC secret as 64 hex characters\n  \
                       --role client             Explicit role assertion\n  \
                       --approve                 LAN/test mode using the built-in default secret\n  \
                       --help, -h                Show this help message\n\n\
                     Note: The product binary strictly rejects simulated --interactive mode."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other}").into()),
        }
    }
    if config.width == 0 || config.height == 0 {
        return Err("width and height must be positive and nonzero".into());
    }
    if config.width % 2 != 0 || config.height % 2 != 0 {
        return Err("width and height must be even integers for NV12 presentation".into());
    }
    Ok(config)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[derive(Debug)]
struct PassthroughDecoder {
    diagnostics: ProviderDiagnostics,
}

impl PassthroughDecoder {
    fn new() -> Self {
        Self {
            diagnostics: ProviderDiagnostics::idle("client_decoder"),
        }
    }
}

impl DecodeBackend for PassthroughDecoder {
    fn decode(
        &mut self,
        _frame: ReassembledFrame,
        _continuity: ContinuityAction,
        _stamp: DispatchStamp,
        _now_ns: u64,
    ) -> Result<PresentableFrame, latencydesk_runtime::RuntimeError> {
        Err(latencydesk_runtime::RuntimeError::Platform(
            PlatformError::Unsupported,
        ))
    }

    fn quiesce_decoding(&mut self) -> Result<(), latencydesk_runtime::RuntimeError> {
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

#[derive(Debug)]
struct NativeLocalInput {
    diagnostics: ProviderDiagnostics,
}

impl NativeLocalInput {
    fn new() -> Self {
        Self {
            diagnostics: ProviderDiagnostics::idle("client_local_input"),
        }
    }
}

impl LocalInputBackend for NativeLocalInput {
    fn release_all(
        &mut self,
        _actions: &[latencydesk_input::AppliedInput],
    ) -> Result<(), latencydesk_runtime::RuntimeError> {
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

pub struct ClientSessionGate {
    session_id: SessionId,
    generation: u64,
    authorization_epoch: u32,
    display_epoch: u32,
    codec_epoch: u32,
    closed: bool,
}

impl ClientSessionGate {
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

impl SessionGate for ClientSessionGate {
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

fn reconstruct_frame_nv12(width: usize, height: usize, frame_bytes: &[u8]) -> Vec<u8> {
    let luma_size = width * height;
    let chroma_size = luma_size / 2;
    let total_size = luma_size + chroma_size;
    let mut nv12 = vec![128u8; total_size];

    // Read animated pattern or slice payload to render onto screen
    let pattern_offset = frame_bytes
        .iter()
        .fold(0usize, |acc, &b| acc.wrapping_add(b as usize));
    for y in 0..height {
        let row_val = ((y * 255) / height.max(1)) as u8;
        for x in 0..width {
            let col_val = ((x * 255) / width.max(1)) as u8;
            nv12[y * width + x] = row_val ^ col_val ^ (pattern_offset as u8);
        }
    }
    // Chroma UV gradient
    for uv in 0..chroma_size {
        nv12[luma_size + uv] = ((uv * 255) / chroma_size.max(1)) as u8;
    }
    nv12
}

const MAX_FRAMES_PER_PUMP: usize = 4;

fn take_latest_frame<T>(receiver: &mpsc::Receiver<T>) -> Option<T> {
    let mut latest = None;
    for _ in 0..MAX_FRAMES_PER_PUMP {
        match receiver.try_recv() {
            Ok(frame) => latest = Some(frame),
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => break,
        }
    }
    latest
}

fn parse_nv12_access_unit(bytes: &[u8]) -> Option<(u32, u32, &[u8])> {
    if bytes.len() < 8 {
        return None;
    }
    let width = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let height = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if width < 2 || height < 2 || width % 2 != 0 || height % 2 != 0 {
        return None;
    }
    let expected = (width as usize)
        .checked_mul(height as usize)?
        .checked_mul(3)?
        / 2;
    if bytes.len() != 8 + expected {
        return None;
    }
    Some((width, height, &bytes[8..]))
}

fn encode_input(sequence: u64, event: InputEvent) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(InputMessage {
        session_epoch: 1,
        sequence,
        event,
    }
    .encode()?)
}

fn send_input_event(
    session: &AuthenticatedDatagramEndpoint,
    sequence: &mut u64,
    event: InputEvent,
) -> Result<(), Box<dyn Error>> {
    *sequence = sequence.saturating_add(1);
    let bytes = encode_input(*sequence, event)?;
    session.send_raw(&bytes)?;
    Ok(())
}

fn pixels_for_frame(width: u32, height: u32, bytes: &[u8]) -> Vec<u8> {
    if let Some((w, h, nv12)) = parse_nv12_access_unit(bytes) {
        if w == width && h == height {
            return nv12.to_vec();
        }
    }
    reconstruct_frame_nv12(width as usize, height as usize, bytes)
}

fn run_inject_probe(
    session: &mut AuthenticatedDatagramEndpoint,
    width: u32,
    height: u32,
) -> Result<(), Box<dyn Error>> {
    session.set_read_timeout(Duration::from_millis(2))?;

    let mut sequence = 0u64;
    send_input_event(
        session,
        &mut sequence,
        InputEvent::PointerMotionAbsolute {
            x: 10,
            y: 10,
            width,
            height,
        },
    )?;
    send_input_event(session, &mut sequence, InputEvent::ReleaseAll)?;
    let received = receive_completed_frames_for(session, 3, Duration::from_secs(30))?;
    println!("inject-probe: sent");
    println!("received: frames={received}");
    Ok(())
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

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fingerprint_from_alias(alias: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = alias.as_bytes();
    if bytes.is_empty() {
        return out;
    }
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = bytes[i % bytes.len()] ^ (i as u8).wrapping_mul(0x1d);
    }
    for round in 0..4 {
        for i in 0..32 {
            let prev = out[(i + 31) % 32];
            out[i] = out[i].wrapping_add(prev).rotate_left(3) ^ (round as u8);
        }
    }
    out
}

fn process_fingerprint() -> [u8; 32] {
    let mut out = [0u8; 32];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    let pid = u128::from(std::process::id());
    let mixed = nanos ^ pid.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let value = (mixed as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(i as u64);
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    out
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

fn establish_client_session(
    args: &ClientArgs,
) -> Result<AuthenticatedDatagramEndpoint, Box<dyn Error>> {
    let shared_secret = resolve_shared_secret(args.auto_approve, args.shared_secret)?;
    if args.auto_approve {
        println!("approve-mode: test/LAN only; not a production pairing path");
        if args.shared_secret.is_none() {
            println!("approve-mode: using built-in LAN test shared secret");
        }
    }

    let mut udp = UdpEndpoint::bind(args.bind_addr, DEFAULT_MAX_SOCKET_DATAGRAM)?;
    udp.set_timeout(Duration::from_millis(250))?;
    udp.connect(args.connect_addr)?;
    println!("Client bound on: {}", udp.local_addr()?);
    println!(
        "Initiating authenticated handshake to Host at {}...",
        args.connect_addr
    );

    let mut session = AuthenticatedDatagramEndpoint::new(
        udp,
        AuthenticatedSessionConfig {
            role: SessionRole::Client,
            path_mtu: DEFAULT_MAX_SOCKET_DATAGRAM,
            reassembly: ReassemblyConfig {
                max_frame_age_ns: 2_000_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )?;


    let fingerprint = match &args.peer_alias {
        Some(alias) => fingerprint_from_alias(alias),
        None => {
            let fingerprint = process_fingerprint();
            println!("device-fingerprint: {}", hex32(&fingerprint));
            fingerprint
        }
    };
    let client_nonce = random_nonce();
    let deadline = Instant::now() + CLIENT_SESSION_TIMEOUT;
    let mut buf = vec![0u8; DEFAULT_MAX_SOCKET_DATAGRAM];

    session.client_initiate_handshake(fingerprint, client_nonce)?;
    loop {
        if Instant::now() >= deadline {
            return Err("handshake timed out waiting for HelloAck".into());
        }
        match session.receive_raw(&mut buf) {
            Ok(len) => {
                session.client_handle_hello_ack(&buf[..len], &shared_secret)?;
                break;
            }
            Err(SocketError::Io(err)) if is_transient(&err) => {
                session.client_initiate_handshake(fingerprint, client_nonce)?;
            }
            Err(err) => return Err(err.into()),
        }
    }

    loop {
        if Instant::now() >= deadline {
            return Err("handshake timed out waiting for HandshakeCompleted".into());
        }
        match session.receive_raw(&mut buf) {
            Ok(len) => {
                session.client_handle_handshake_completed(&buf[..len])?;
                break;
            }
            Err(SocketError::Io(err)) if is_transient(&err) => continue,
            Err(err) => return Err(err.into()),
        }
    }

    if session.handshake_state() != HandshakeState::Active {
        return Err("handshake did not reach Active".into());
    }
    println!("handshake: active session_id={}", session.session_id());
    Ok(session)
}

fn receive_completed_frames(
    session: &mut AuthenticatedDatagramEndpoint,
    needed: u64,
) -> Result<u64, Box<dyn Error>> {
    receive_completed_frames_for(session, needed, CLIENT_SESSION_TIMEOUT)
}

fn receive_completed_frames_for(
    session: &mut AuthenticatedDatagramEndpoint,
    needed: u64,
    timeout: Duration,
) -> Result<u64, Box<dyn Error>>
{
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; DEFAULT_MAX_SOCKET_DATAGRAM];
    let mut completed = 0u64;
    while completed < needed {
        if Instant::now() >= deadline {
            return Err(format!("receive timed out after {completed} frames").into());
        }
        match session.receive_media_datagram(&mut buf, now_ns()) {
            Ok(IngestOutcome::Complete(_)) => completed += 1,
            Ok(_) => {}
            Err(SocketError::Io(err)) if is_transient(&err) => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(completed)
}


fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_client_args()?;
    println!("=== LatencyDesk Client ===");
    println!("Target Host Address: {}", args.connect_addr);
    println!("Local Binding Address: {}", args.bind_addr);
    println!(
        "Direct LAN 1080p120 Profile Requested: {}",
        args.profile_1080p120
    );

    let mut session = establish_client_session(&args)?;

    if args.inject_probe {
        return run_inject_probe(&mut session, args.width, args.height);
    }

    if let Some(max_frames) = args.max_frames {
        let received = receive_completed_frames(&mut session, max_frames)?;
        println!("received: frames={received}");
        return Ok(());
    }

    #[cfg(windows)]
    {
        use latencydesk_platform_windows::D3D11WindowRenderer;


        session.set_read_timeout(Duration::from_millis(2))?;

        let first = wait_first_completed_frame(&mut session)?;
        let (width, height, real_nv12) = match parse_nv12_access_unit(&first.bytes) {
            Some((w, h, _)) => (w, h, true),
            None => (args.width, args.height, false),
        };
        let mut window = D3D11WindowRenderer::new(width, height)
            .map_err(|e| Box::<dyn Error>::from(format!("{e:?}")))?;
        let first_pixels = pixels_for_frame(width, height, &first.bytes);
        let _ = window.present_nv12(&first_pixels);
        println!(
            "Client Connected. Native Direct3D 11 presentation window open ({}x{}, {}).",
            width,
            height,
            if real_nv12 { "nv12" } else { "synthetic" }
        );
        println!("Press Ctrl+C in terminal or close window to disconnect.");

        enum NetCmd {
            Send(Vec<u8>),
            Stop,
        }
        let (frame_tx, frame_rx) = mpsc::sync_channel::<ReassembledFrame>(MAX_FRAMES_PER_PUMP);
        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<NetCmd>(32);
        let running = Arc::new(AtomicBool::new(true));
        let r_clone = Arc::clone(&running);
        let network_thread = std::thread::spawn(move || {
            let mut recv_buf = vec![0u8; DEFAULT_MAX_SOCKET_DATAGRAM];
            while r_clone.load(Ordering::Relaxed) {
                while let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        NetCmd::Send(bytes) => {
                            let _ = session.send_raw(&bytes);
                        }
                        NetCmd::Stop => return,
                    }
                }
                match session.receive_media_datagram(&mut recv_buf, now_ns()) {
                    Ok(IngestOutcome::Complete(frame)) => {
                        let _ = frame_tx.try_send(frame);
                    }
                    Ok(_) => {}
                    Err(SocketError::Io(err)) if is_transient(&err) => {}
                    Err(_) => break,
                }
            }
        });

        let mut rendered_frames = 1u64;
        let mut input_seq = 0u64;

        while window.pump_messages() {
            for event in window.poll_inputs(32) {
                if let Some(input) = window_event_to_input(event, width, height) {
                    input_seq = input_seq.saturating_add(1);
                    if let Ok(bytes) = encode_input(input_seq, input) {
                        let _ = cmd_tx.try_send(NetCmd::Send(bytes));
                    }
                }
            }
            if let Some(frame) = take_latest_frame(&frame_rx) {
                rendered_frames += 1;
                let nv12_pixels = pixels_for_frame(width, height, &frame.bytes);
                let _ = window.present_nv12(&nv12_pixels);
                if rendered_frames % 60 == 0 {
                    println!(
                        ">>> Streaming active: rendered frame #{} ({} bytes payload)",
                        frame.header.frame_id,
                        frame.bytes.len()
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        input_seq = input_seq.saturating_add(1);
        if let Ok(bytes) = encode_input(input_seq, InputEvent::ReleaseAll) {
            let _ = cmd_tx.try_send(NetCmd::Send(bytes));
        }
        let _ = cmd_tx.try_send(NetCmd::Stop);
        running.store(false, Ordering::Relaxed);
        let _ = network_thread.join();
        window.close();
        println!("Presentation window closed. Disconnected cleanly.");
    }


    #[cfg(not(windows))]
    {
        let _ = session;
        println!("Client ready on non-Windows platform.");
    }

    Ok(())
}

fn wait_first_completed_frame(
    session: &mut AuthenticatedDatagramEndpoint,
) -> Result<ReassembledFrame, Box<dyn Error>> {
    let deadline = Instant::now() + CLIENT_SESSION_TIMEOUT;
    let mut buf = vec![0u8; DEFAULT_MAX_SOCKET_DATAGRAM];
    loop {
        if Instant::now() >= deadline {
            return Err("timed out waiting for the first media frame".into());
        }
        match session.receive_media_datagram(&mut buf, now_ns()) {
            Ok(IngestOutcome::Complete(frame)) => return Ok(frame),
            Ok(_) => {}
            Err(SocketError::Io(err)) if is_transient(&err) => {}
            Err(err) => return Err(err.into()),
        }
    }
}

#[cfg(windows)]
fn window_event_to_input(
    event: latencydesk_platform_windows::WindowInputEvent,
    stream_w: u32,
    stream_h: u32,
) -> Option<InputEvent> {
    use latencydesk_platform_windows::{
        win32_vk_to_hid_usage, INPUT_KIND_BUTTON, INPUT_KIND_KEY, INPUT_KIND_MOUSE_MOVE,
        INPUT_KIND_WHEEL,
    };
    match event.kind {
        INPUT_KIND_MOUSE_MOVE => {
            let max_x = stream_w.saturating_sub(1);
            let max_y = stream_h.saturating_sub(1);
            let x = event.x.clamp(0, max_x as i32) as u32;
            let y = event.y.clamp(0, max_y as i32) as u32;
            Some(InputEvent::PointerMotionAbsolute {
                x,
                y,
                width: stream_w,
                height: stream_h,
            })
        }
        INPUT_KIND_BUTTON => Some(InputEvent::PointerButton {
            button: event.button,
            pressed: event.pressed,
        }),
        INPUT_KIND_KEY => {
            let code = win32_vk_to_hid_usage(event.vk as u16)?;
            Some(InputEvent::Key {
                code,
                pressed: event.pressed,
            })
        }
        INPUT_KIND_WHEEL => Some(InputEvent::Wheel {
            horizontal: 0,
            vertical: event.wheel.clamp(i16::MIN as i32, i16::MAX as i32) as i16,
        }),
        _ => None,
    }
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_parser_rejects_interactive() {
        let err = parse_client_args_from(["latencydesk-client", "--interactive"]);
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("rejects simulated --interactive"));
    }

    #[test]
    fn client_parser_accepts_1080p120_profile() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--1080p120-profile",
            "--connect",
            "127.0.0.1:9000",
        ])
        .expect("parse");
        assert_eq!(args.connect_addr, "127.0.0.1:9000".parse().unwrap());
        assert!(args.profile_1080p120);
    }

    #[test]
    fn client_parser_accepts_approve_secret_and_frames() {
        let secret = "cc".repeat(32);
        let args = parse_client_args_from([
            "latencydesk-client",
            "--approve",
            "--shared-secret",
            secret.as_str(),
            "--frames",
            "8",
            "--bind",
            "127.0.0.1:0",
        ])
        .expect("parse");
        assert!(args.auto_approve);
        assert_eq!(args.max_frames, Some(8));
        assert_eq!(args.shared_secret, Some([0xcc; 32]));
        assert_eq!(args.bind_addr, "127.0.0.1:0".parse().unwrap());
    }

    #[test]
    fn bounded_latest_frame_drain_leaves_frames_arriving_during_render_for_next_pump() {
        let (sender, receiver) = mpsc::sync_channel(5);
        for frame in 1_u8..=5 {
            sender.send(frame).expect("queue accepts test frame");
        }

        assert_eq!(take_latest_frame(&receiver), Some(4));
        assert_eq!(receiver.try_recv().ok(), Some(5));
    }

    #[test]
    fn client_parser_accepts_geometry_and_inject_probe() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--width",
            "1280",
            "--height",
            "720",
            "--inject-probe",
        ])
        .expect("parse");
        assert_eq!(args.width, 1280);
        assert_eq!(args.height, 720);
        assert!(args.inject_probe);
    }

    #[test]
    fn nv12_prefix_detects_real_access_unit() {
        let body = vec![9u8; 6];

        let mut packed = Vec::new();
        packed.extend_from_slice(&2u32.to_le_bytes());
        packed.extend_from_slice(&2u32.to_le_bytes());
        packed.extend_from_slice(&body);
        let (w, h, pixels) = parse_nv12_access_unit(&packed).expect("nv12");
        assert_eq!((w, h), (2, 2));
        assert_eq!(pixels, body.as_slice());
        assert!(parse_nv12_access_unit(&[0, 0, 0, 1, 0x67, 1, 2, 3]).is_none());
    }

}
