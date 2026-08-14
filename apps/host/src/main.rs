use latencydesk_frame::{FakeCapture, FakeCaptureConfig, Pattern, PixelFormat};
use latencydesk_input::{AppliedInput, InputMessage, InputReconciler};
use latencydesk_protocol::{media_flags, MediaKind, NO_DEPENDENCY};
use latencydesk_session::{SessionEvent, SessionMachine};
use latencydesk_socket_transport::{UdpEndpoint, DEFAULT_MAX_SOCKET_DATAGRAM};
use latencydesk_test_codec::ExactTestCodec;
use latencydesk_transport::{fragment_frame, FragmentSpec};
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct HostConfig {
    bind_addr: SocketAddr,
    client_addr: Option<SocketAddr>,
    width: u32,
    height: u32,
    fps: u32,
    frames: Option<u64>,
    pattern: Pattern,
    seed: u64,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9000".parse().expect("valid address"),
            client_addr: None,
            width: 320,
            height: 240,
            fps: 60,
            frames: None,
            pattern: Pattern::MovingBox,
            seed: 12345,
        }
    }
}

fn parse_args() -> Result<HostConfig, Box<dyn Error>> {
    let mut config = HostConfig::default();
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                config.bind_addr = args.get(i).ok_or("missing value for --bind")?.parse()?;
            }
            "--client" => {
                i += 1;
                config.client_addr =
                    Some(args.get(i).ok_or("missing value for --client")?.parse()?);
            }
            "--width" => {
                i += 1;
                config.width = args.get(i).ok_or("missing value for --width")?.parse()?;
            }
            "--height" => {
                i += 1;
                config.height = args.get(i).ok_or("missing value for --height")?.parse()?;
            }
            "--fps" => {
                i += 1;
                config.fps = args.get(i).ok_or("missing value for --fps")?.parse()?;
            }
            "--frames" => {
                i += 1;
                config.frames = Some(args.get(i).ok_or("missing value for --frames")?.parse()?);
            }
            "--pattern" => {
                i += 1;
                match args.get(i).ok_or("missing value for --pattern")?.as_str() {
                    "moving-box" => config.pattern = Pattern::MovingBox,
                    "gradient" => config.pattern = Pattern::Gradient,
                    "text-like" => config.pattern = Pattern::TextLike,
                    other => return Err(format!("unknown pattern: {other}").into()),
                }
            }
            "--help" | "-h" => {
                println!(concat!(
                    "LatencyDesk Host Server\n",
                    "Usage: latencydesk-host [OPTIONS]\n\n",
                    "Options:\n",
                    "  --bind <ADDR:PORT>    Bind address (default: 127.0.0.1:9000)\n",
                    "  --client <ADDR:PORT>  Optional initial client address\n",
                    "  --width <PIXELS>      Stream width (default: 320)\n",
                    "  --height <PIXELS>     Stream height (default: 240)\n",
                    "  --fps <NUM>           Target framerate (default: 60)\n",
                    "  --frames <COUNT>      Run for N frames then stop (default: infinite)\n",
                    "  --pattern <NAME>      Pattern: moving-box, gradient, text-like\n",
                    "  --help, -h            Show this help\n"
                ));
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}").into()),
        }
        i += 1;
    }
    Ok(config)
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_args()?;
    println!("=== LatencyDesk Host ===");
    println!("Binding on: {}", config.bind_addr);
    println!(
        "Resolution: {}x{} @ {} fps",
        config.width, config.height, config.fps
    );
    let mut session = SessionMachine::default();
    session.apply(SessionEvent::Start)?;
    session.apply(SessionEvent::TransportReady)?;
    session.apply(SessionEvent::Authenticated)?;
    session.apply(SessionEvent::Negotiated)?;

    let target_client = config
        .client_addr
        .unwrap_or_else(|| SocketAddr::new(config.bind_addr.ip(), 9001));

    let endpoint =
        UdpEndpoint::bind_connected(config.bind_addr, target_client, DEFAULT_MAX_SOCKET_DATAGRAM)?;
    endpoint.set_timeout(Duration::from_millis(5))?;

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let receiver_endpoint = endpoint.try_clone()?;
    let input_thread = thread::spawn(move || {
        let mut reconciler = InputReconciler::default();
        let mut recv_buf = vec![0u8; DEFAULT_MAX_SOCKET_DATAGRAM];
        while r_clone.load(Ordering::Relaxed) {
            match receiver_endpoint.receive(&mut recv_buf) {
                Ok(len) if len >= 24 => {
                    if let Ok(msg) = InputMessage::decode(&recv_buf[..len]) {
                        if let Ok(outcome) = reconciler.apply(msg) {
                            match outcome {
                                latencydesk_input::ReconcileOutcome::Applied(actions) => {
                                    for action in actions {
                                        match action {
                                            AppliedInput::Key { code, pressed } => {
                                                println!(
                                                    "[Input] Key {} -> pressed={}",
                                                    code, pressed
                                                );
                                            }
                                            AppliedInput::PointerMotionRelative { dx, dy } => {
                                                println!(
                                                    "[Input] Mouse Move rel: ({}, {})",
                                                    dx, dy
                                                );
                                            }
                                            AppliedInput::PointerMotionAbsolute {
                                                x,
                                                y,
                                                width,
                                                height,
                                            } => {
                                                println!(
                                                    "[Input] Mouse Move abs: ({}, {}) in {}x{}",
                                                    x, y, width, height
                                                );
                                            }
                                            AppliedInput::PointerButton { button, pressed } => {
                                                println!(
                                                    "[Input] Mouse Button {} -> pressed={}",
                                                    button, pressed
                                                );
                                            }
                                            AppliedInput::Wheel {
                                                horizontal,
                                                vertical,
                                            } => {
                                                println!(
                                                    "[Input] Wheel: h={}, v={}",
                                                    horizontal, vertical
                                                );
                                            }
                                        }
                                    }
                                }
                                latencydesk_input::ReconcileOutcome::IgnoredStaleSequence => {}
                                latencydesk_input::ReconcileOutcome::IgnoredStaleEpoch => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let cleanup_actions = reconciler.disconnect();
        if !cleanup_actions.is_empty() {
            println!(
                "[Input] Released {} inputs on disconnect",
                cleanup_actions.len()
            );
        }
    });

    let mut capture = FakeCapture::new(FakeCaptureConfig {
        width: config.width,
        height: config.height,
        format: PixelFormat::Bgra8,
        pattern: config.pattern,
        seed: config.seed,
    })?;

    let frame_interval = Duration::from_micros(1_000_000 / u64::from(config.fps.max(1)));
    let mut frame_id: u64 = 0;
    let start_time = Instant::now();
    let mut last_dependency = NO_DEPENDENCY;

    println!("Host streaming started. Target client: {}", target_client);

    loop {
        if let Some(max_frames) = config.frames {
            if frame_id >= max_frames {
                break;
            }
        }

        let loop_start = Instant::now();
        let now_ns = start_time.elapsed().as_nanos() as u64;
        let raw_frame = capture.capture(now_ns)?;
        let encoded_bytes = ExactTestCodec::encode(&raw_frame)?;
        let is_keyframe = frame_id % 30 == 0;
        let flags = if is_keyframe {
            last_dependency = NO_DEPENDENCY;
            media_flags::KEYFRAME | media_flags::LOSSLESS
        } else {
            media_flags::LOSSLESS
        };

        let dependency_frame_id = if is_keyframe {
            None
        } else {
            Some(last_dependency)
        };

        let spec = FragmentSpec {
            kind: MediaKind::Video,
            flags,
            stream_id: 1,
            codec_epoch: 1,
            frame_id,
            dependency_frame_id,
        };

        last_dependency = frame_id;

        let datagrams = fragment_frame(spec, &encoded_bytes, DEFAULT_MAX_SOCKET_DATAGRAM)?;
        for datagram in datagrams {
            let _ = endpoint.send(&datagram);
        }

        frame_id += 1;
        if frame_id % 60 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let fps = frame_id as f64 / elapsed;
            println!(
                "[Host] Streamed frame {} ({} bytes, {:.1} fps)",
                frame_id,
                encoded_bytes.len(),
                fps
            );
        }

        let elapsed = loop_start.elapsed();
        if elapsed < frame_interval {
            thread::sleep(frame_interval - elapsed);
        }
    }

    running.store(false, Ordering::Relaxed);
    let _ = input_thread.join();

    let total_elapsed = start_time.elapsed();
    println!(
        "[Host] Finished streaming {} frames in {:.2}s ({:.1} fps avg)",
        frame_id,
        total_elapsed.as_secs_f64(),
        frame_id as f64 / total_elapsed.as_secs_f64()
    );

    Ok(())
}
