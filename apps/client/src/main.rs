//! LatencyDesk Client Application.
//!
//! Native QUIC/UDP client role coordinator using platform providers.

use latencydesk_input::{InputEvent, InputMessage};
use latencydesk_session::lifecycle::MAX_RECONNECT_ATTEMPTS;
use latencydesk_socket_transport::identity::MAX_PARALLEL_CONNECT_CANDIDATES;
use latencydesk_socket_transport::{
    AuthenticatedDatagramEndpoint, AuthenticatedSessionConfig, HandshakeState, SessionRole,
    SocketError, UdpEndpoint, APPROVE_LAN_TEST_SECRET, DEFAULT_MAX_SOCKET_DATAGRAM,
};
#[cfg(windows)]
use latencydesk_transport::ReassembledFrame;
use latencydesk_transport::{IngestOutcome, ReassemblyConfig};

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(windows, test))]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod secure;
#[cfg(not(windows))]
mod software_viewer;

const MAX_PAIRING_TIMEOUT_SECS: u64 = 3_600;
const MAX_CONCURRENT_TARGETS: usize = 16;
const MAX_FALLBACK_ADDRESS_ARGUMENTS: usize = 16;
const MAX_CLIENT_SESSIONS: u32 = 16;
const MAX_INPUT_LATENCY_PROBES: u32 = 1_024;

#[derive(Debug)]
struct TargetChildPlan {
    target: SocketAddr,
    args: Vec<OsString>,
}

#[derive(Debug)]
struct TargetChild {
    target: SocketAddr,
    process: Child,
    output_threads: Vec<JoinHandle<io::Result<()>>>,
}

#[derive(Debug, Clone)]
pub struct ClientArgs {
    pub connect_addr: SocketAddr,
    pub fallback_addresses: Vec<SocketAddr>,
    pub targets: Vec<(SocketAddr, PathBuf)>,
    pub bind_addr: SocketAddr,
    pub peer_alias: Option<String>,
    pub pairing_timeout_secs: u64,
    pub profile_1080p120: bool,
    pub max_frames: Option<u64>,
    pub session_count: u32,
    pub reconnect_attempts: u32,
    pub input_latency_probes: u32,
    pub width: u32,
    pub height: u32,
    pub auto_approve: bool,
    pub shared_secret: Option<[u8; 32]>,
    pub inject_probe: bool,
    pub identity_cert: Option<PathBuf>,
    pub identity_key: Option<PathBuf>,
    pub peer_cert: Option<PathBuf>,
    pub unsafe_udp_lab: bool,
    pub show_version: bool,
}

impl Default for ClientArgs {
    fn default() -> Self {
        Self {
            connect_addr: "127.0.0.1:9000".parse().unwrap(),
            fallback_addresses: Vec::new(),
            targets: Vec::new(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            peer_alias: None,
            pairing_timeout_secs: 60,
            profile_1080p120: false,
            max_frames: None,
            session_count: 1,
            reconnect_attempts: 0,
            input_latency_probes: 0,
            width: 1280,
            height: 720,
            auto_approve: false,
            shared_secret: None,
            inject_probe: false,
            identity_cert: None,
            identity_key: None,
            peer_cert: None,
            unsafe_udp_lab: false,
            show_version: false,
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
            "--target" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --target".into());
                }
                let value = &args[i + 1];
                let (addr, cert) = value
                    .split_once(',')
                    .ok_or("--target must be <ADDR>,<PEER_CERT_PATH>")?;
                if addr.is_empty() || cert.is_empty() || cert.contains(',') {
                    return Err("--target must be <ADDR>,<PEER_CERT_PATH>".into());
                }
                config.targets.push((addr.parse()?, PathBuf::from(cert)));
                i += 2;
            }
            "--connect" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --connect".into());
                }
                config.connect_addr = args[i + 1].parse()?;
                i += 2;
            }
            "--fallback-address" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --fallback-address".into());
                }
                config.fallback_addresses.push(args[i + 1].parse()?);
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
            "--session-count" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --session-count".into());
                }
                config.session_count = args[i + 1].parse()?;
                i += 2;
            }
            "--reconnect-attempts" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --reconnect-attempts".into());
                }
                config.reconnect_attempts = args[i + 1].parse()?;
                i += 2;
            }
            "--input-latency-probes" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --input-latency-probes".into());
                }
                let probes = args[i + 1].parse()?;
                if !(1..=MAX_INPUT_LATENCY_PROBES).contains(&probes) {
                    return Err(format!(
                        "--input-latency-probes must be between 1 and {MAX_INPUT_LATENCY_PROBES}"
                    )
                    .into());
                }
                config.input_latency_probes = probes;
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
                     Secure QUIC options (default and required):\n  \
                       --connect <ADDR>          Host address to connect to (default 127.0.0.1:9000)\n  \
                       --fallback-address <ADDR> Alternate address for the same exact-pinned Host (repeatable, max 3)\n  \
                       --target <ADDR>,<CERT>    Connect to up to 16 exact-pinned Hosts concurrently (repeatable)\n  \
                       --bind <ADDR>             Local socket address to bind (default 0.0.0.0:0)\n  \
                       --identity-cert <PATH>    Client identity certificate in DER format\n  \
                       --identity-key <PATH>     Client PKCS#8 private key in DER format\n  \
                       --peer-cert <PATH>        Exact Host certificate to pin in DER format\n  \
                       --pairing-timeout <SECS>  Connect/media timeout, 1..3600 (default 60)\n  \
                       --width <PIXELS>          Probe coordinate width (--inject-probe only; default 1280)\n  \
                       --height <PIXELS>         Probe coordinate height (--inject-probe only; default 720)\n  \
                       --frames <COUNT>          Receive N completed frames then exit (headless)\n  \
                       --session-count <COUNT>   Run 1..=16 clean sequential headless sessions (default 1)\n  \
                       --reconnect-attempts <N>  Retry 0..=8 recoverable headless path losses (default 0)\n  \
                       --input-latency-probes <N> Measure 1..=1024 ACK RTTs per secure target (Linux Host)\n  \
                       --inject-probe            Send one pointer move and ReleaseAll, wait 3 frames, exit\n  \
                       --role client             Explicit role assertion\n  \
                       --version, -V             Show version information\n  \
                       --help, -h                Show this help message\n\n\
                     Unsafe legacy UDP lab mode (plaintext; never expose to a network):\n  \
                       --unsafe-udp-lab          Explicitly opt into the legacy plaintext transport\n  \
                       --shared-secret <HEX64>   Legacy 32-byte handshake secret\n  \
                       --approve                 Legacy built-in lab secret\n  \
                       --peer-alias <NAME>       Legacy fingerprint alias\n  \
                       --1080p120-profile        Legacy LAN profile request\n\n\
                     Secure identity flags and --unsafe-udp-lab are mutually exclusive."
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
    if config.max_frames == Some(0) {
        return Err("--frames must be greater than zero".into());
    }
    if config.inject_probe && config.max_frames.is_some() {
        return Err("--inject-probe and --frames are mutually exclusive".into());
    }
    if !(1..=MAX_CLIENT_SESSIONS).contains(&config.session_count) {
        return Err(format!("--session-count must be between 1 and {MAX_CLIENT_SESSIONS}").into());
    }
    if config.reconnect_attempts > MAX_RECONNECT_ATTEMPTS {
        return Err(
            format!("--reconnect-attempts must be between 0 and {MAX_RECONNECT_ATTEMPTS}").into(),
        );
    }
    if config.pairing_timeout_secs == 0 || config.pairing_timeout_secs > MAX_PAIRING_TIMEOUT_SECS {
        return Err(format!(
            "--pairing-timeout must be between 1 and {MAX_PAIRING_TIMEOUT_SECS} seconds"
        )
        .into());
    }
    if config.fallback_addresses.len() > MAX_FALLBACK_ADDRESS_ARGUMENTS {
        return Err(format!(
            "--fallback-address accepts at most {MAX_FALLBACK_ADDRESS_ARGUMENTS} entries"
        )
        .into());
    }
    let mut seen_fallbacks = std::collections::HashSet::new();
    config
        .fallback_addresses
        .retain(|address| *address != config.connect_addr && seen_fallbacks.insert(*address));
    if config.fallback_addresses.len() + 1 > MAX_PARALLEL_CONNECT_CANDIDATES {
        return Err(format!(
            "--fallback-address accepts at most {} alternate addresses",
            MAX_PARALLEL_CONNECT_CANDIDATES - 1
        )
        .into());
    }
    if !config.fallback_addresses.is_empty() {
        if !config.targets.is_empty() {
            return Err("--fallback-address cannot be combined with --target".into());
        }
        if config.unsafe_udp_lab {
            return Err("--fallback-address is available only for secure QUIC mode".into());
        }
    }
    if config.bind_addr.is_ipv4()
        && connection_candidates(&config)
            .iter()
            .any(SocketAddr::is_ipv6)
    {
        return Err("IPv6 connection candidates require an IPv6 bind such as --bind [::]:0".into());
    }
    if config.targets.len() > MAX_CONCURRENT_TARGETS {
        return Err(format!("--target supports at most {MAX_CONCURRENT_TARGETS} targets").into());
    }
    let mut seen = std::collections::HashSet::new();
    config.targets.retain(|t| seen.insert((t.0, t.1.clone())));
    if !config.targets.is_empty() {
        if args.iter().any(|a| a == "--connect") || args.iter().any(|a| a == "--peer-cert") {
            return Err("--target cannot be combined with --connect or --peer-cert".into());
        }
        if args.iter().any(|a| a == "--width" || a == "--height") {
            return Err(
                "--target cannot be combined with --width or --height; probe geometry is only valid with --inject-probe"
                    .into(),
            );
        }
        if config.unsafe_udp_lab || config.inject_probe || config.bind_addr.port() != 0 {
            return Err(
                "--target requires secure mode, no probe, and an ephemeral bind port".into(),
            );
        }
        if config.targets.len() == 1 {
            config.connect_addr = config.targets[0].0;
            config.peer_cert = Some(config.targets[0].1.clone());
        }
    }
    if config.session_count > 1 {
        if config.max_frames.is_none() {
            return Err("--session-count greater than 1 currently requires --frames".into());
        }
        if config.unsafe_udp_lab || config.inject_probe || !config.targets.is_empty() {
            return Err(
                "--session-count greater than 1 requires secure headless --frames mode and is incompatible with --target, --inject-probe, and --unsafe-udp-lab"
                    .into(),
            );
        }
    }
    if config.reconnect_attempts > 0 {
        if config.max_frames.is_none() {
            return Err("--reconnect-attempts currently requires --frames".into());
        }
        if config.unsafe_udp_lab || config.inject_probe || !config.targets.is_empty() {
            return Err(
                "--reconnect-attempts requires secure headless --frames mode and is incompatible with --target, --inject-probe, and --unsafe-udp-lab"
                    .into(),
            );
        }
    }
    if config.input_latency_probes > 0
        && (config.max_frames.is_some()
            || config.session_count > 1
            || config.reconnect_attempts > 0
            || config.unsafe_udp_lab
            || config.inject_probe)
    {
        return Err(
            "--input-latency-probes supports secure --connect/--peer-cert or secure --target entries and is incompatible with --frames, --session-count, --reconnect-attempts, --inject-probe, and --unsafe-udp-lab"
                .into(),
        );
    }
    if config.show_version {
        return Ok(config);
    }

    let has_identity = config.identity_cert.is_some()
        || config.identity_key.is_some()
        || config.peer_cert.is_some();
    let has_legacy_option = config.peer_alias.is_some()
        || config.auto_approve
        || config.shared_secret.is_some()
        || config.profile_1080p120;
    if config.unsafe_udp_lab {
        if has_identity {
            return Err(
                "secure identity flags cannot be combined with --unsafe-udp-lab; remove one mode"
                    .into(),
            );
        }
        if !config.auto_approve && config.shared_secret.is_none() {
            return Err(
                "--unsafe-udp-lab requires --shared-secret <HEX64> or explicit --approve".into(),
            );
        }
    } else {
        if has_legacy_option {
            return Err(
                "legacy UDP options require explicit --unsafe-udp-lab; secure mode uses identity certificates"
                    .into(),
            );
        }
        let mut missing = Vec::new();
        if config.identity_cert.is_none() {
            missing.push("--identity-cert <PATH>");
        }
        if config.identity_key.is_none() {
            missing.push("--identity-key <PATH>");
        }
        if config.peer_cert.is_none() && config.targets.is_empty() {
            missing.push("--peer-cert <PATH>");
        }
        if !missing.is_empty() {
            return Err(format!(
                "secure QUIC mode requires {}; generate an identity and exchange only certificate files",
                missing.join(", ")
            )
            .into());
        }
    }
    Ok(config)
}

fn connection_candidates(args: &ClientArgs) -> Vec<SocketAddr> {
    let mut candidates = Vec::with_capacity(1 + args.fallback_addresses.len());
    candidates.push(args.connect_addr);
    candidates.extend(args.fallback_addresses.iter().copied());
    candidates
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(windows)]
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

#[cfg(any(windows, test))]
const MAX_FRAMES_PER_PUMP: usize = 4;

#[cfg(any(windows, test))]
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

#[cfg(windows)]
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
    timeout: Duration,
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
    let received = receive_completed_frames_for(session, 3, timeout)?;
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
    let deadline = Instant::now() + Duration::from_secs(args.pairing_timeout_secs);
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

fn receive_completed_frames_for(
    session: &mut AuthenticatedDatagramEndpoint,
    needed: u64,
    timeout: Duration,
) -> Result<u64, Box<dyn Error>> {
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

fn plan_target_child_args(args: &ClientArgs) -> Result<Vec<TargetChildPlan>, Box<dyn Error>> {
    if args.targets.len() < 2 {
        return Err("multi-target planning requires at least two targets".into());
    }
    let identity_cert = args
        .identity_cert
        .as_ref()
        .ok_or("multi-target mode requires --identity-cert")?;
    let identity_key = args
        .identity_key
        .as_ref()
        .ok_or("multi-target mode requires --identity-key")?;

    Ok(args
        .targets
        .iter()
        .map(|(addr, cert)| {
            let mut child_args = vec![
                OsString::from("--connect"),
                OsString::from(addr.to_string()),
                OsString::from("--peer-cert"),
                cert.as_os_str().to_owned(),
                OsString::from("--identity-cert"),
                identity_cert.as_os_str().to_owned(),
                OsString::from("--identity-key"),
                identity_key.as_os_str().to_owned(),
                OsString::from("--bind"),
                OsString::from(args.bind_addr.to_string()),
                OsString::from("--pairing-timeout"),
                OsString::from(args.pairing_timeout_secs.to_string()),
            ];
            if let Some(frames) = args.max_frames {
                child_args.push(OsString::from("--frames"));
                child_args.push(OsString::from(frames.to_string()));
            }
            if args.input_latency_probes > 0 {
                child_args.push(OsString::from("--input-latency-probes"));
                child_args.push(OsString::from(args.input_latency_probes.to_string()));
            }
            TargetChildPlan {
                target: *addr,
                args: child_args,
            }
        })
        .collect())
}

fn terminate_and_reap(children: &mut [TargetChild]) {
    for child in children.iter_mut() {
        let _ = child.process.kill();
    }
    for child in children.iter_mut() {
        let _ = child.process.wait();
        join_output_forwarders(child);
    }
}

fn spawn_output_forwarder<R, W>(reader: R, output: Arc<Mutex<W>>) -> JoinHandle<io::Result<()>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                return Ok(());
            }
            let mut output = output
                .lock()
                .map_err(|_| io::Error::other("child output forwarding lock was poisoned"))?;
            output.write_all(&line)?;
            output.flush()?;
        }
    })
}

fn attach_output_forwarders<W>(
    process: &mut Child,
    output: Arc<Mutex<W>>,
) -> io::Result<Vec<JoinHandle<io::Result<()>>>>
where
    W: Write + Send + 'static,
{
    let stdout = process
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("captured child stdout is unavailable"))?;
    let stderr = process
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("captured child stderr is unavailable"))?;
    Ok(vec![
        spawn_output_forwarder(stdout, Arc::clone(&output)),
        spawn_output_forwarder(stderr, output),
    ])
}

fn join_output_forwarders(child: &mut TargetChild) -> Vec<String> {
    std::mem::take(&mut child.output_threads)
        .into_iter()
        .filter_map(|thread| match thread.join() {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(format!("output forwarding failed: {error}")),
            Err(_) => Some("output forwarding thread panicked".to_owned()),
        })
        .collect()
}

fn run_multi_target(args: &ClientArgs) -> Result<(), Box<dyn Error>> {
    let plans = plan_target_child_args(args)?;
    let exe = env::current_exe()?;
    let capture_output = args.input_latency_probes > 0;
    let forwarded_output = Arc::new(Mutex::new(io::stdout()));
    let mut children = Vec::<TargetChild>::with_capacity(plans.len());
    for plan in plans {
        let mut command = Command::new(&exe);
        command.args(&plan.args);
        if capture_output {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        match command.spawn() {
            Ok(mut process) => {
                let output_threads = if capture_output {
                    match attach_output_forwarders(&mut process, Arc::clone(&forwarded_output)) {
                        Ok(threads) => threads,
                        Err(error) => {
                            let _ = process.kill();
                            let _ = process.wait();
                            terminate_and_reap(&mut children);
                            return Err(format!(
                                "failed to capture isolated client output for {}: {error}",
                                plan.target
                            )
                            .into());
                        }
                    }
                } else {
                    Vec::new()
                };
                children.push(TargetChild {
                    target: plan.target,
                    process,
                    output_threads,
                });
            }
            Err(error) => {
                terminate_and_reap(&mut children);
                return Err(format!(
                    "failed to spawn isolated client for {}: {error}",
                    plan.target
                )
                .into());
            }
        }
    }

    let mut failures = Vec::new();
    for child in &mut children {
        match child.process.wait() {
            Ok(status) if status.success() => {}
            Ok(status) => failures.push(format!("{} exited with {status}", child.target)),
            Err(error) => {
                failures.push(format!("{} could not be waited: {error}", child.target));
                let _ = child.process.kill();
                let _ = child.process.wait();
            }
        }
        failures.extend(
            join_output_forwarders(child)
                .into_iter()
                .map(|error| format!("{} {error}", child.target)),
        );
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("target children failed: {}", failures.join(", ")).into())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_client_args()?;
    if args.show_version {
        println!("latencydesk-client {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.targets.len() > 1 {
        return run_multi_target(&args);
    }
    if args.unsafe_udp_lab {
        eprintln!(
            "WARNING: --unsafe-udp-lab uses unauthenticated plaintext media/input UDP. \
             It is only for isolated localhost/lab testing and must never be exposed to a LAN or WAN."
        );
        run_unsafe_udp_lab(&args)
    } else {
        secure::run(&args)
    }
}

fn run_unsafe_udp_lab(args: &ClientArgs) -> Result<(), Box<dyn Error>> {
    println!("=== LatencyDesk Client ===");
    println!("Target Host Address: {}", args.connect_addr);
    println!("Local Binding Address: {}", args.bind_addr);
    println!(
        "Direct LAN 1080p120 Profile Requested: {}",
        args.profile_1080p120
    );

    let mut session = establish_client_session(args)?;
    let timeout = Duration::from_secs(args.pairing_timeout_secs);

    if args.inject_probe {
        return run_inject_probe(&mut session, args.width, args.height, timeout);
    }

    if let Some(max_frames) = args.max_frames {
        let received = receive_completed_frames_for(&mut session, max_frames, timeout)?;
        println!("received: frames={received}");
        return Ok(());
    }

    #[cfg(windows)]
    {
        use latencydesk_platform_windows::D3D11WindowRenderer;

        session.set_read_timeout(Duration::from_millis(2))?;

        let first = wait_first_completed_frame(&mut session, timeout)?;
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

        'viewer: while window.pump_messages() {
            for event in window.poll_inputs(32) {
                if window_input_overflowed(&event) {
                    eprintln!(
                        "native input queue overflowed; disconnecting to prevent a stuck key or button"
                    );
                    break 'viewer;
                }
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

#[cfg(windows)]
fn wait_first_completed_frame(
    session: &mut AuthenticatedDatagramEndpoint,
    timeout: Duration,
) -> Result<ReassembledFrame, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
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
        INPUT_KIND_RELEASE_ALL, INPUT_KIND_WHEEL,
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
        INPUT_KIND_RELEASE_ALL => Some(InputEvent::ReleaseAll),
        _ => None,
    }
}

#[cfg(windows)]
fn window_input_overflowed(event: &latencydesk_platform_windows::WindowInputEvent) -> bool {
    event.kind == latencydesk_platform_windows::INPUT_KIND_OVERFLOW
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
            "--unsafe-udp-lab",
            "--approve",
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
            "--unsafe-udp-lab",
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
            "--identity-cert",
            "client-cert.der",
            "--identity-key",
            "client-key.der",
            "--peer-cert",
            "host-cert.der",
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
    fn client_mode_defaults_to_secure() {
        let args = ClientArgs::default();
        assert!(!args.unsafe_udp_lab);
    }

    #[test]
    fn client_parser_accepts_complete_secure_identity() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client-cert.der",
            "--identity-key",
            "client-key.der",
            "--peer-cert",
            "host-cert.der",
            "--pairing-timeout",
            "12",
            "--frames",
            "2",
        ])
        .expect("secure args");
        assert!(!args.unsafe_udp_lab);
        assert_eq!(args.identity_cert, Some(PathBuf::from("client-cert.der")));
        assert_eq!(args.identity_key, Some(PathBuf::from("client-key.der")));
        assert_eq!(args.peer_cert, Some(PathBuf::from("host-cert.der")));
        assert_eq!(args.max_frames, Some(2));
        assert_eq!(args.pairing_timeout_secs, 12);
    }

    #[test]
    fn client_parser_builds_a_deduplicated_bounded_endpoint_race() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--peer-cert",
            "host.der",
            "--connect",
            "127.0.0.1:9000",
            "--fallback-address",
            "127.0.0.1:9001",
            "--fallback-address",
            "127.0.0.1:9001",
            "--fallback-address",
            "127.0.0.1:9002",
        ])
        .expect("bounded alternatives");
        assert_eq!(
            connection_candidates(&args),
            vec![
                "127.0.0.1:9000".parse().unwrap(),
                "127.0.0.1:9001".parse().unwrap(),
                "127.0.0.1:9002".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn client_parser_rejects_unbounded_or_incompatible_endpoint_races() {
        let too_many = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--peer-cert",
            "host.der",
            "--fallback-address",
            "127.0.0.1:9001",
            "--fallback-address",
            "127.0.0.1:9002",
            "--fallback-address",
            "127.0.0.1:9003",
            "--fallback-address",
            "127.0.0.1:9004",
        ])
        .expect_err("candidate race must be bounded");
        assert!(too_many.to_string().contains("at most"));

        let wrong_family = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--peer-cert",
            "host.der",
            "--fallback-address",
            "[::1]:9001",
        ])
        .expect_err("an IPv4-bound endpoint cannot race IPv6");
        assert!(wrong_family.to_string().contains("IPv6 bind"));

        let mixed_target = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--target",
            "127.0.0.1:9000,host-a.der",
            "--target",
            "127.0.0.1:9001,host-b.der",
            "--fallback-address",
            "127.0.0.1:9010",
        ])
        .expect_err("one fallback address cannot be shared across distinct hosts");
        assert!(mixed_target.to_string().contains("cannot be combined"));
    }

    #[test]
    fn client_parser_deduplicates_fallbacks_before_enforcing_the_race_limit() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--peer-cert",
            "host.der",
            "--fallback-address",
            "127.0.0.1:9001",
            "--fallback-address",
            "127.0.0.1:9001",
            "--fallback-address",
            "127.0.0.1:9001",
            "--fallback-address",
            "127.0.0.1:9001",
            "--fallback-address",
            "127.0.0.1:9002",
        ])
        .expect("duplicate fallback flags do not consume connection fan-out");
        assert_eq!(connection_candidates(&args).len(), 3);
    }

    #[test]
    fn client_parser_accepts_repeated_secure_targets_and_plans_isolated_children() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--target",
            "127.0.0.1:9001,host-a.der",
            "--target",
            "127.0.0.1:9002,host-b.der",
            "--bind",
            "127.0.0.1:0",
            "--pairing-timeout",
            "12",
            "--frames",
            "3",
        ])
        .expect("targets");
        assert_eq!(args.targets.len(), 2);
        let plan = plan_target_child_args(&args).expect("plan");
        let first = plan[0]
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(plan[0].target, "127.0.0.1:9001".parse().unwrap());
        assert_eq!(
            first,
            vec![
                "--connect",
                "127.0.0.1:9001",
                "--peer-cert",
                "host-a.der",
                "--identity-cert",
                "client.der",
                "--identity-key",
                "key.der",
                "--bind",
                "127.0.0.1:0",
                "--pairing-timeout",
                "12",
                "--frames",
                "3",
            ]
        );
        assert!(!first.iter().any(|arg| arg == "--target"));
    }

    #[test]
    fn client_parser_forwards_bounded_input_probes_to_every_target() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--target",
            "127.0.0.1:9001,host-a.der",
            "--target",
            "127.0.0.1:9002,host-b.der",
            "--input-latency-probes",
            "128",
        ])
        .expect("bounded probes are valid for isolated target children");

        let plans = plan_target_child_args(&args).expect("multi-target probe plan");
        assert_eq!(plans.len(), 2);
        for plan in plans {
            let child_args = plan
                .args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(child_args
                .windows(2)
                .any(|pair| pair == ["--input-latency-probes", "128"]));
            assert!(!child_args.iter().any(|arg| arg == "--target"));
        }
    }

    #[test]
    fn child_output_forwarding_preserves_complete_lines_under_concurrency() {
        use std::io::Cursor;
        use std::sync::{Arc, Mutex};

        let first_line = format!("first:{}\n", "a".repeat(8_192));
        let second_line = format!("second:{}\n", "b".repeat(8_192));
        let output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let first = spawn_output_forwarder(
            Cursor::new(first_line.clone().into_bytes()),
            Arc::clone(&output),
        );
        let second = spawn_output_forwarder(
            Cursor::new(second_line.clone().into_bytes()),
            Arc::clone(&output),
        );
        first.join().expect("first forwarder").expect("first copy");
        second
            .join()
            .expect("second forwarder")
            .expect("second copy");

        let forwarded =
            String::from_utf8(output.lock().expect("output").clone()).expect("UTF-8 output");
        let lines = forwarded.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&first_line.trim_end()));
        assert!(lines.contains(&second_line.trim_end()));
    }

    #[test]
    fn client_parser_rejects_malformed_or_unsafe_targets() {
        assert!(parse_client_args_from(["latencydesk-client", "--target", "bad"]).is_err());
        assert!(parse_client_args_from([
            "latencydesk-client",
            "--unsafe-udp-lab",
            "--approve",
            "--target",
            "127.0.0.1:1,host.der"
        ])
        .is_err());
    }

    #[test]
    fn client_parser_deduplicates_targets_and_rejects_conflicting_single_target_flags() {
        let deduplicated = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--target",
            "127.0.0.1:9001,host-a.der",
            "--target",
            "127.0.0.1:9001,host-a.der",
            "--target",
            "127.0.0.1:9002,host-b.der",
        ])
        .expect("duplicate targets are harmless");
        assert_eq!(deduplicated.targets.len(), 2);

        let mixed = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--connect",
            "127.0.0.1:9000",
            "--target",
            "127.0.0.1:9001,host-a.der",
        ])
        .expect_err("target mode cannot silently override an explicit connect address");
        assert!(mixed.to_string().contains("cannot be combined"));
    }

    #[test]
    fn client_parser_rejects_non_ephemeral_multi_target_bind() {
        let error = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--bind",
            "127.0.0.1:4000",
            "--target",
            "127.0.0.1:9001,host-a.der",
            "--target",
            "127.0.0.1:9002,host-b.der",
        ])
        .expect_err("children cannot share a fixed local UDP port");
        assert!(error.to_string().contains("ephemeral bind port"));
    }

    #[test]
    fn client_parser_rejects_probe_geometry_in_multi_target_mode() {
        let error = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--width",
            "1280",
            "--target",
            "127.0.0.1:9001,host-a.der",
            "--target",
            "127.0.0.1:9002,host-b.der",
        ])
        .expect_err("probe geometry has no multi-target meaning");
        assert!(error.to_string().contains("probe geometry"));
    }

    #[test]
    fn client_parser_accepts_only_bounded_headless_successor_sessions() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--peer-cert",
            "host.der",
            "--frames",
            "3",
            "--session-count",
            "2",
        ])
        .expect("bounded headless reconnect sequence");
        assert_eq!(args.session_count, 2);
        assert_eq!(ClientArgs::default().session_count, 1);

        for arguments in [
            vec!["latencydesk-client", "--session-count", "0"],
            vec!["latencydesk-client", "--session-count", "17"],
            vec!["latencydesk-client", "--session-count", "2"],
            vec![
                "latencydesk-client",
                "--unsafe-udp-lab",
                "--approve",
                "--frames",
                "1",
                "--session-count",
                "2",
            ],
        ] {
            assert!(parse_client_args_from(arguments).is_err());
        }
    }

    #[test]
    fn client_parser_bounds_recoverable_headless_reconnect_attempts() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--peer-cert",
            "host.der",
            "--frames",
            "3",
            "--reconnect-attempts",
            "3",
        ])
        .expect("bounded recoverable reconnect policy");
        assert_eq!(args.reconnect_attempts, 3);
        assert_eq!(ClientArgs::default().reconnect_attempts, 0);

        for arguments in [
            vec![
                "latencydesk-client",
                "--frames",
                "1",
                "--reconnect-attempts",
                "9",
            ],
            vec!["latencydesk-client", "--reconnect-attempts", "1"],
            vec![
                "latencydesk-client",
                "--unsafe-udp-lab",
                "--approve",
                "--frames",
                "1",
                "--reconnect-attempts",
                "1",
            ],
        ] {
            assert!(parse_client_args_from(arguments).is_err());
        }
    }

    #[test]
    fn client_parser_bounds_secure_input_latency_probes() {
        let args = parse_client_args_from([
            "latencydesk-client",
            "--identity-cert",
            "client.der",
            "--identity-key",
            "key.der",
            "--peer-cert",
            "host.der",
            "--input-latency-probes",
            "128",
        ])
        .expect("bounded secure input probe");
        assert_eq!(args.input_latency_probes, 128);
        assert_eq!(ClientArgs::default().input_latency_probes, 0);

        for arguments in [
            vec!["latencydesk-client", "--input-latency-probes", "0"],
            vec!["latencydesk-client", "--input-latency-probes", "1025"],
            vec![
                "latencydesk-client",
                "--input-latency-probes",
                "2",
                "--frames",
                "1",
            ],
            vec![
                "latencydesk-client",
                "--unsafe-udp-lab",
                "--approve",
                "--input-latency-probes",
                "2",
            ],
        ] {
            assert!(parse_client_args_from(arguments).is_err());
        }
    }

    #[test]
    fn client_parser_requires_explicit_lab_opt_in_for_legacy_flags() {
        let error = parse_client_args_from(["latencydesk-client", "--approve"])
            .expect_err("approve cannot silently downgrade transport");
        assert!(error.to_string().contains("--unsafe-udp-lab"));
    }

    #[test]
    fn client_parser_rejects_mixed_secure_and_lab_modes() {
        let error = parse_client_args_from([
            "latencydesk-client",
            "--unsafe-udp-lab",
            "--approve",
            "--identity-cert",
            "client-cert.der",
        ])
        .expect_err("identity and plaintext modes must not mix");
        assert!(error.to_string().contains("cannot be combined"));
    }

    #[test]
    fn client_parser_rejects_incomplete_secure_identity() {
        let error =
            parse_client_args_from(["latencydesk-client", "--identity-cert", "client-cert.der"])
                .expect_err("all three secure identity files are required");
        let message = error.to_string();
        assert!(message.contains("--identity-key"));
        assert!(message.contains("--peer-cert"));
    }

    #[test]
    fn client_parser_accepts_version_without_identity_files() {
        let args = parse_client_args_from(["latencydesk-client", "--version"])
            .expect("version is an offline action");
        assert!(args.show_version);
    }

    #[test]
    fn client_parser_rejects_out_of_range_timeout() {
        for timeout in ["0", "3601"] {
            let error = parse_client_args_from([
                "latencydesk-client",
                "--identity-cert",
                "client-cert.der",
                "--identity-key",
                "client-key.der",
                "--peer-cert",
                "host-cert.der",
                "--pairing-timeout",
                timeout,
            ])
            .expect_err("timeout must be bounded");
            assert!(error.to_string().contains("between 1 and 3600"));
        }
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

    #[cfg(windows)]
    #[test]
    fn window_safety_events_release_or_fail_closed() {
        use latencydesk_platform_windows::{
            WindowInputEvent, INPUT_KIND_OVERFLOW, INPUT_KIND_RELEASE_ALL,
        };

        let event = |kind| WindowInputEvent {
            kind,
            button: 0,
            pressed: false,
            x: 0,
            y: 0,
            wheel: 0,
            vk: 0,
        };
        assert_eq!(
            window_event_to_input(event(INPUT_KIND_RELEASE_ALL), 640, 360),
            Some(InputEvent::ReleaseAll)
        );
        assert!(window_input_overflowed(&event(INPUT_KIND_OVERFLOW)));
        assert!(window_event_to_input(event(INPUT_KIND_OVERFLOW), 640, 360).is_none());
    }
}
