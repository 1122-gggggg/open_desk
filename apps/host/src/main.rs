//! LatencyDesk Host Application.
//!
//! Native QUIC/UDP host role coordinator using platform providers.

mod secure;

use latencydesk_input::{
    AppliedInput, InputEvent, InputMessage, InputReconciler, ReconcileOutcome,
};
use latencydesk_platform::{
    EncodeBackend, EncodeFailure, EncodeSubmission, EncoderSubmissionGuard,
    NativePresentationCompletion, PlatformError, ProviderDiagnostics,
};
#[cfg(target_os = "linux")]
use latencydesk_platform_linux::{nv12_len, pack_nv12_access_unit_into, X11DesktopSession};
use latencydesk_protocol::{media_flags, ControlKind, ControlPacket, HelloMessage, MediaKind};
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

use std::env;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LEGACY_MODE_ERROR: &str = "--client/--connect, --peer-alias, --approve/--auto-approve, --shared-secret, --device-fingerprint, --1080p120-profile, --width, and --height are legacy plaintext options; add --unsafe-udp-lab only in an isolated trusted lab, or use the secure certificate and capture options";
const MAX_SECURE_SESSIONS: u32 = 16;

const HOST_HELP: &str = "Usage: latencydesk-host [OPTIONS]\n\n\
Options:\n  \
  --listen <ADDR>           QUIC address to bind (default 0.0.0.0:9000)\n  \
  --identity-cert <PATH>    Host public certificate (DER; required securely)\n  \
  --identity-key <PATH>     Host private key (PKCS#8 DER; required securely)\n  \
  --peer-cert <PATH>        Exact trusted client certificate (DER; required securely)\n  \
  --pairing-timeout <SECS>  TLS connection timeout, 1..=3600 (default 60)\n  \
  --max-width <PIXELS>      Secure Linux X11 / Windows capture canvas width (default 1280, even)\n  \
  --max-height <PIXELS>     Secure Linux X11 / Windows capture canvas height (default 720, even)\n  \
  --fps <FPS>               Secure capture frame rate, 1..=240 (default 60)\n  \
  --frames <COUNT>          Stop streaming after N frames\n  \
  --max-sessions <COUNT>    Accept 1..=16 sequential secure sessions (Linux X11; default 1)\n  \
  --role host               Explicit role assertion\n  \
  --unsafe-udp-lab          Opt in to unauthenticated-server, plaintext legacy UDP\n  \
  --version, -V             Show the host version\n  \
  --client/--connect <ADDR> Legacy UDP peer (requires --unsafe-udp-lab)\n  \
  --peer-alias <NAME>       Legacy alias (requires --unsafe-udp-lab)\n  \
  --shared-secret <HEX64>   Legacy 32-byte secret (requires --unsafe-udp-lab)\n  \
  --device-fingerprint <HEX64>  Legacy pin (repeatable; requires --unsafe-udp-lab)\n  \
  --approve/--auto-approve  Legacy built-in test secret (requires --unsafe-udp-lab)\n  \
  --1080p120-profile        Legacy synthetic profile (requires --unsafe-udp-lab)\n  \
  --width <PIXELS>          Legacy synthetic width (requires --unsafe-udp-lab)\n  \
  --height <PIXELS>         Legacy synthetic height (requires --unsafe-udp-lab)\n  \
  --help, -h                Show this help message\n\n\
Generate identities with `latencydesk-identity generate`, exchange only the\n\
certificate files, and keep private keys on their originating machines.\n\
Secure hosting requires Linux X11 or Windows GDI capture. --unsafe-udp-lab is plaintext\n\
compatibility mode and must never be exposed to an untrusted network.";

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
    pub max_sessions: u32,
    pub auto_approve: bool,
    pub shared_secret: Option<[u8; 32]>,
    pub pinned_fingerprints: Vec<[u8; 32]>,
    pub identity_cert: Option<PathBuf>,
    pub identity_key: Option<PathBuf>,
    pub peer_cert: Option<PathBuf>,
    pub unsafe_udp_lab: bool,
    pub show_version: bool,
    synthetic_geometry_explicit: bool,
    max_sessions_explicit: bool,
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
            max_sessions: 1,
            auto_approve: false,
            shared_secret: None,
            pinned_fingerprints: Vec::new(),
            identity_cert: None,
            identity_key: None,
            peer_cert: None,
            unsafe_udp_lab: false,
            show_version: false,
            synthetic_geometry_explicit: false,
            max_sessions_explicit: false,
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
                config.synthetic_geometry_explicit = true;
                i += 2;
            }
            "--height" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --height".into());
                }
                config.height = args[i + 1].parse()?;
                config.synthetic_geometry_explicit = true;
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
            "--max-sessions" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --max-sessions".into());
                }
                config.max_sessions = args[i + 1].parse()?;
                config.max_sessions_explicit = true;
                i += 2;
            }
            "--identity-cert" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --identity-cert".into());
                }
                config.identity_cert = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--identity-key" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --identity-key".into());
                }
                config.identity_key = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--peer-cert" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --peer-cert".into());
                }
                config.peer_cert = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--unsafe-udp-lab" => {
                config.unsafe_udp_lab = true;
                i += 1;
            }
            "--version" | "-V" => {
                config.show_version = true;
                i += 1;
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
                println!("{HOST_HELP}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other}").into()),
        }
    }

    if config.width == 0 || config.height == 0 {
        return Err("width and height must be positive and nonzero".into());
    }
    if config.width % 2 != 0 || config.height % 2 != 0 {
        return Err("width and height must be even integers for NV12 video encoding".into());
    }
    if config.max_width == 0 || config.max_height == 0 {
        return Err("max-width and max-height must be positive and nonzero".into());
    }
    if config.max_width % 2 != 0 || config.max_height % 2 != 0 {
        return Err(
            "max-width and max-height must be even integers for NV12 video encoding".into(),
        );
    }
    if !(1..=240).contains(&config.fps) {
        return Err("fps must be between 1 and 240".into());
    }
    if !(1..=3_600).contains(&config.pairing_timeout_secs) {
        return Err("pairing-timeout must be between 1 and 3600 seconds".into());
    }
    if config.max_frames == Some(0) {
        return Err("frames must be positive and nonzero".into());
    }
    if !(1..=MAX_SECURE_SESSIONS).contains(&config.max_sessions) {
        return Err(format!("max-sessions must be between 1 and {MAX_SECURE_SESSIONS}").into());
    }
    if config.unsafe_udp_lab && config.max_sessions_explicit {
        return Err("--max-sessions is available only for secure Host mode".into());
    }

    let has_identity_flag = config.identity_cert.is_some()
        || config.identity_key.is_some()
        || config.peer_cert.is_some();
    if config.unsafe_udp_lab && has_identity_flag {
        return Err(
            "--identity-cert, --identity-key, and --peer-cert cannot be combined with --unsafe-udp-lab"
                .into(),
        );
    }

    let has_legacy_only_option = config.connect_addr.is_some()
        || config.peer_alias.is_some()
        || config.auto_approve
        || config.shared_secret.is_some()
        || !config.pinned_fingerprints.is_empty()
        || config.profile_1080p120
        || config.synthetic_geometry_explicit;
    if !config.unsafe_udp_lab && has_legacy_only_option {
        return Err(LEGACY_MODE_ERROR.into());
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
        if permit.stamp().session_id() != self.session_id
            || permit.stamp().generation() != self.generation
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

struct HostHandshake<'a> {
    hello: &'a [u8],
    pins: &'a [[u8; 32]],
    server_nonce: [u8; 16],
    session_id: u64,
    shared_secret: &'a [u8; 32],
    deadline: Instant,
}

fn complete_host_handshake(
    session: &mut AuthenticatedDatagramEndpoint,
    buffer: &mut [u8],
    handshake: HostHandshake<'_>,
) -> Result<(), Box<dyn Error>> {
    session.host_handle_hello(
        handshake.hello,
        handshake.pins,
        handshake.server_nonce,
        handshake.session_id,
        1,
    )?;
    loop {
        if Instant::now() >= handshake.deadline {
            return Err("handshake timed out waiting for Authenticate".into());
        }
        match session.receive_raw(buffer) {
            Ok(len) => {
                match session.host_handle_authenticate(&buffer[..len], handshake.shared_secret) {
                    Ok(_) => return Ok(()),
                    Err(SocketError::UnexpectedControlKind(ControlKind::Hello)) => {
                        session.host_handle_hello(
                            &buffer[..len],
                            handshake.pins,
                            handshake.server_nonce,
                            handshake.session_id,
                            1,
                        )?;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
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
    Ok(())
}

// Two workers keep blocking media/provider work isolated from the input/network
// path without multiplying one worker per machine CPU in every Host process.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_host_args()?;
    if args.show_version {
        println!("{}", version_text());
        return Ok(());
    }
    if args.unsafe_udp_lab {
        eprintln!(
            "!!! UNSAFE UDP LAB MODE: traffic after the legacy handshake is plaintext, the server is not authenticated, and the built-in approve secret is public. Never expose this mode to an untrusted network. !!!"
        );
        run_unsafe_udp_lab(args)
    } else {
        secure::run(&args).await
    }
}

fn version_text() -> String {
    format!("latencydesk-host {}", env!("CARGO_PKG_VERSION"))
}

fn run_unsafe_udp_lab(args: HostArgs) -> Result<(), Box<dyn Error>> {
    println!("=== LatencyDesk Host ===");
    println!("Mode: UNSAFE legacy UDP lab compatibility");
    println!(
        "Selected Direct LAN 1080p120 Profile: {}",
        args.profile_1080p120
    );
    println!("Binding Listen Address: {}", args.listen_addr);
    println!(
        "Stream Resolution: {}x{} @ {} fps",
        args.width, args.height, args.fps
    );
    println!("Capture canvas: {}x{}", args.max_width, args.max_height);

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

    let deadline = Instant::now() + Duration::from_secs(args.pairing_timeout_secs);
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
        &mut recv_buf,
        HostHandshake {
            hello: &hello_packet,
            pins: &pins,
            server_nonce: random_nonce(),
            session_id,
            shared_secret: &shared_secret,
            deadline,
        },
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
    #[cfg(target_os = "linux")]
    let mut encoded_data =
        Vec::with_capacity(8_usize.saturating_add(nv12_len(args.max_width, args.max_height)));

    loop {
        #[cfg(target_os = "linux")]
        drain_input(session, recv_buf, reconciler, |action| {
            desktop
                .inject(action)
                .map_err(|err| Box::<dyn Error>::from(err.to_string()))
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
                pack_nv12_access_unit_into(width, height, nv12, &mut encoded_data);
                send_video_frame(session, &encoded_data, frame_id, is_keyframe)?;
                if frame_id == 1 || frame_id % 60 == 0 {
                    println!("streaming: frame {frame_id} bytes={}", encoded_data.len());
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let encoded_data =
                    generate_compressed_frame(args.width, args.height, frame_id, is_keyframe);
                send_video_frame(session, &encoded_data, frame_id, is_keyframe)?;
                if frame_id == 1 || frame_id % 60 == 0 {
                    println!("streaming: frame {frame_id} bytes={}", encoded_data.len());
                }
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
            "--unsafe-udp-lab",
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
    fn secure_mode_rejects_every_synthetic_legacy_option_even_at_default_values() {
        let cases: [&[&str]; 3] = [
            &["latencydesk-host", "--1080p120-profile"],
            &["latencydesk-host", "--width", "1920"],
            &["latencydesk-host", "--height", "1080"],
        ];
        for arguments in cases {
            let error = parse_host_args_from(arguments.iter().copied())
                .expect_err("synthetic option must require explicit lab mode");
            assert_eq!(error.to_string(), LEGACY_MODE_ERROR);
        }
    }

    #[test]
    fn lab_mode_accepts_synthetic_profile_and_geometry() {
        let args = parse_host_args_from([
            "latencydesk-host",
            "--unsafe-udp-lab",
            "--1080p120-profile",
            "--width",
            "1280",
            "--height",
            "720",
        ])
        .expect("explicit lab mode accepts synthetic options");
        assert!(args.profile_1080p120);
        assert_eq!(args.width, 1280);
        assert_eq!(args.height, 720);
        assert_eq!(args.fps, 120);
    }

    #[test]
    fn help_and_mode_error_label_every_legacy_option_consistently() {
        for option in [
            "--client",
            "--connect",
            "--peer-alias",
            "--approve",
            "--auto-approve",
            "--shared-secret",
            "--device-fingerprint",
            "--1080p120-profile",
            "--width",
            "--height",
        ] {
            assert!(HOST_HELP.contains(option), "help omitted {option}");
            assert!(LEGACY_MODE_ERROR.contains(option), "error omitted {option}");
        }
        for line in HOST_HELP.lines().filter(|line| line.contains("Legacy")) {
            assert!(
                line.contains("requires --unsafe-udp-lab"),
                "legacy help line is not fail-closed: {line}"
            );
        }
        assert!(HOST_HELP.contains("--max-width <PIXELS>      Secure Linux X11 / Windows capture"));
        assert!(HOST_HELP.contains("--fps <FPS>               Secure capture frame rate"));
        assert!(HOST_HELP.contains("Windows GDI capture"));
    }

    #[test]
    fn help_text_mentions_windows_capture() {
        assert!(HOST_HELP.contains("Windows GDI capture"));
        assert!(HOST_HELP.contains("Windows capture canvas"));
    }

    #[test]
    fn host_parser_accepts_approve_secret_and_frames() {
        let secret = "aa".repeat(32);
        let fingerprint = "bb".repeat(32);
        let args = parse_host_args_from([
            "latencydesk-host",
            "--unsafe-udp-lab",
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
            "--unsafe-udp-lab",
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

    #[test]
    fn host_defaults_to_secure_mode() {
        let args = parse_host_args_from(["latencydesk-host"]).expect("secure defaults parse");
        assert!(!args.unsafe_udp_lab);
        assert!(args.identity_cert.is_none());
        assert!(args.identity_key.is_none());
        assert!(args.peer_cert.is_none());
    }

    #[test]
    fn legacy_credentials_require_explicit_lab_mode() {
        let error = parse_host_args_from(["latencydesk-host", "--approve"])
            .expect_err("legacy option must fail closed");
        let message = error.to_string();
        assert!(message.contains("--unsafe-udp-lab"));
        assert!(message.contains("legacy plaintext"));
    }

    #[test]
    fn secure_identity_and_unsafe_lab_modes_are_mutually_exclusive() {
        let error = parse_host_args_from([
            "latencydesk-host",
            "--unsafe-udp-lab",
            "--identity-cert",
            "host.der",
        ])
        .expect_err("mixed security modes must be rejected");
        assert!(error.to_string().contains("cannot be combined"));
    }

    #[test]
    fn host_parser_accepts_complete_secure_identity_paths() {
        let args = parse_host_args_from([
            "latencydesk-host",
            "--identity-cert",
            "host.der",
            "--identity-key",
            "host-key.der",
            "--peer-cert",
            "client.der",
        ])
        .expect("secure identity flags parse");
        assert_eq!(args.identity_cert, Some(PathBuf::from("host.der")));
        assert_eq!(args.identity_key, Some(PathBuf::from("host-key.der")));
        assert_eq!(args.peer_cert, Some(PathBuf::from("client.der")));
        assert!(!args.unsafe_udp_lab);
    }

    #[test]
    fn host_parser_accepts_a_bounded_secure_session_count() {
        let args = parse_host_args_from([
            "latencydesk-host",
            "--identity-cert",
            "host.der",
            "--identity-key",
            "host-key.der",
            "--peer-cert",
            "client.der",
            "--max-sessions",
            "2",
        ])
        .expect("bounded persistent listener");
        assert_eq!(args.max_sessions, 2);
        assert_eq!(HostArgs::default().max_sessions, 1);

        for invalid in ["0", "17"] {
            assert!(parse_host_args_from(["latencydesk-host", "--max-sessions", invalid]).is_err());
        }
        assert!(parse_host_args_from([
            "latencydesk-host",
            "--unsafe-udp-lab",
            "--approve",
            "--max-sessions",
            "2",
        ])
        .is_err());
    }

    #[test]
    fn host_session_gate_rejects_a_foreign_session_permit() {
        let gate = HostSessionGate::new(SessionId::new(7).expect("session"));
        let foreign = DispatchPermit::from_stamp(
            DispatchStamp::new(SessionId::new(8).expect("foreign"), 1, 1, 1, 1)
                .expect("foreign stamp"),
        );
        assert_eq!(
            gate.recheck(&foreign, 0),
            Err(AuthorityError::StaleDispatch)
        );
    }

    #[test]
    fn host_version_is_a_stable_cli_action() {
        let args =
            parse_host_args_from(["latencydesk-host", "--version"]).expect("version option parses");
        assert!(args.show_version);
        assert_eq!(
            version_text(),
            format!("latencydesk-host {}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn pairing_timeout_enforces_bounded_range() {
        for invalid in ["0", "3601"] {
            let error = parse_host_args_from(["latencydesk-host", "--pairing-timeout", invalid])
                .expect_err("out-of-range timeout must fail");
            assert!(error.to_string().contains("between 1 and 3600"));
        }

        let minimum = parse_host_args_from(["latencydesk-host", "--pairing-timeout", "1"])
            .expect("minimum timeout");
        assert_eq!(minimum.pairing_timeout_secs, 1);

        let maximum = parse_host_args_from(["latencydesk-host", "--pairing-timeout", "3600"])
            .expect("maximum timeout");
        assert_eq!(maximum.pairing_timeout_secs, 3_600);
    }

    #[test]
    fn fps_enforces_safe_interval_range() {
        for invalid in ["0", "241", "4294967295"] {
            let error = parse_host_args_from(["latencydesk-host", "--fps", invalid])
                .expect_err("out-of-range fps must fail before interval construction");
            assert!(error.to_string().contains("between 1 and 240"));
        }

        let maximum = parse_host_args_from(["latencydesk-host", "--fps", "240"])
            .expect("maximum fps remains valid");
        assert_eq!(maximum.fps, 240);

        let legacy_profile =
            parse_host_args_from(["latencydesk-host", "--unsafe-udp-lab", "--1080p120-profile"])
                .expect("legacy 120 fps profile remains valid in explicit lab mode");
        assert_eq!(legacy_profile.fps, 120);
    }
}
