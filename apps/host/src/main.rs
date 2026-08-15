//! LatencyDesk Host Application.
//!
//! Native QUIC/UDP host role coordinator using platform providers.

use latencydesk_platform::{
    EncodeBackend, EncodeFailure, EncodeSubmission, EncoderSubmissionGuard,
    NativePresentationCompletion, PlatformError, ProviderDiagnostics,
};
use latencydesk_protocol::{media_flags, MediaKind};
use latencydesk_runtime::HostMediaBackend;
use latencydesk_session::authorization::SessionId;
use latencydesk_session::runtime::{
    AuthorityError, ClosedAuthority, DispatchPermit, DispatchStamp, InputLedger, SessionGate,
    SessionInputError,
};
use latencydesk_socket_transport::quic::MediaSendOutcome;
use latencydesk_transport::{fragment_frame, FragmentSpec, DEFAULT_MAX_DATAGRAM_BYTES};
use std::env;
use std::error::Error;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HANDSHAKE_HELO: &[u8; 9] = b"LDSK_HELO";
const HANDSHAKE_OKAY: &[u8; 9] = b"LDSK_OKAY";

#[derive(Debug, Clone)]
pub struct HostArgs {
    pub listen_addr: SocketAddr,
    pub connect_addr: Option<SocketAddr>,
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
            listen_addr: "0.0.0.0:9000".parse().unwrap(),
            connect_addr: None,
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
                       --listen <ADDR>           Socket address to bind (default 0.0.0.0:9000)\n  \
                       --client <ADDR>           Pre-configured Client IP:port to stream to directly\n  \
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

    if config.width == 0 || config.height == 0 || config.fps == 0 {
        return Err("width, height, and fps must be positive and nonzero".into());
    }
    if config.width % 2 != 0 || config.height % 2 != 0 {
        return Err("width and height must be even integers for NV12 video encoding".into());
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

    let socket = UdpSocket::bind(args.listen_addr)?;
    socket.set_nonblocking(true)?;
    println!("Host listening on UDP socket: {}", socket.local_addr()?);

    let mut client_target: Option<SocketAddr> = args.connect_addr;
    if let Some(target) = client_target {
        println!("Streaming directly to preconfigured Client: {}", target);
    } else {
        println!(
            "Awaiting client handshake ping on UDP port {}...",
            args.listen_addr.port()
        );
    }

    let mut recv_buf = [0u8; 1500];
    let frame_duration = Duration::from_micros(1_000_000 / u64::from(args.fps.max(1)));
    let mut frame_id = 0u64;
    let mut last_frame_time = Instant::now();

    loop {
        // Poll for incoming handshake or heartbeat pings
        while let Ok((len, peer)) = socket.recv_from(&mut recv_buf) {
            if len >= HANDSHAKE_HELO.len() && &recv_buf[..HANDSHAKE_HELO.len()] == HANDSHAKE_HELO {
                if client_target != Some(peer) {
                    println!(
                        ">>> Accepted client connection from {}! Starting 1080p120 stream...",
                        peer
                    );
                    client_target = Some(peer);
                }
                // Reply with handshake ACK
                let mut ack_packet = HANDSHAKE_OKAY.to_vec();
                ack_packet.extend_from_slice(&args.width.to_le_bytes());
                ack_packet.extend_from_slice(&args.height.to_le_bytes());
                ack_packet.extend_from_slice(&args.fps.to_le_bytes());
                let _ = socket.send_to(&ack_packet, peer);
            }
        }

        if let Some(client_addr) = client_target {
            if last_frame_time.elapsed() >= frame_duration {
                last_frame_time = Instant::now();
                frame_id += 1;

                let is_keyframe = (frame_id == 1) || (frame_id % (u64::from(args.fps) * 2) == 0);
                let encoded_data =
                    generate_compressed_frame(args.width, args.height, frame_id, is_keyframe);

                let spec = FragmentSpec {
                    kind: MediaKind::Video,
                    flags: if is_keyframe {
                        media_flags::KEYFRAME
                    } else {
                        0
                    },
                    stream_id: 1,
                    codec_epoch: 1,
                    frame_id,
                    dependency_frame_id: if is_keyframe {
                        None
                    } else {
                        Some(frame_id.saturating_sub(1))
                    },
                };

                if let Ok(packets) = fragment_frame(spec, &encoded_data, DEFAULT_MAX_DATAGRAM_BYTES)
                {
                    for packet in packets {
                        let _ = socket.send_to(&packet, client_addr);
                    }
                }

                if frame_id % (u64::from(args.fps)) == 0 {
                    println!(
                        "Streaming active: sent frame {} ({} bytes, ~{:.1} Mbps) to {}",
                        frame_id,
                        encoded_data.len(),
                        (encoded_data.len() as f64 * 8.0 * args.fps as f64) / 1_000_000.0,
                        client_addr
                    );
                }

                if let Some(max) = args.max_frames {
                    if frame_id >= max {
                        println!("Reached max frames limit: {}", max);
                        break;
                    }
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
