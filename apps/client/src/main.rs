use latencydesk_input::{InputEvent, InputMessage};
use latencydesk_session::{SessionEvent, SessionMachine};
use latencydesk_socket_transport::{UdpEndpoint, DEFAULT_MAX_SOCKET_DATAGRAM};
use latencydesk_test_codec::ExactTestCodec;
use latencydesk_transport::{IngestOutcome, Reassembler, ReassemblyConfig};
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct ClientConfig {
    bind_addr: SocketAddr,
    host_addr: SocketAddr,
    frames: Option<u64>,
    interactive: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9001".parse().expect("valid address"),
            host_addr: "127.0.0.1:9000".parse().expect("valid address"),
            frames: None,
            interactive: false,
        }
    }
}

fn parse_args() -> Result<ClientConfig, Box<dyn Error>> {
    let mut config = ClientConfig::default();
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                config.bind_addr = args.get(i).ok_or("missing value for --bind")?.parse()?;
            }
            "--connect" => {
                i += 1;
                config.host_addr = args.get(i).ok_or("missing value for --connect")?.parse()?;
            }
            "--frames" => {
                i += 1;
                config.frames = Some(args.get(i).ok_or("missing value for --frames")?.parse()?);
            }
            "--interactive" => {
                config.interactive = true;
            }
            "--help" | "-h" => {
                println!(concat!(
                    "LatencyDesk Client\n",
                    "Usage: latencydesk-client [OPTIONS]\n\n",
                    "Options:\n",
                    "  --connect <ADDR:PORT>  Host server address (default: 127.0.0.1:9000)\n",
                    "  --bind <ADDR:PORT>     Local bind address (default: 127.0.0.1:9001)\n",
                    "  --frames <COUNT>       Receive N frames then exit (default: continuous)\n",
                    "  --interactive          Send simulated pointer input (explicit test mode)\n",
                    "  --help, -h             Show this help\n"
                ));
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}").into()),
        }
        i += 1;
    }
    Ok(config)
}

#[must_use]
const fn simulated_input_enabled(interactive: bool) -> bool {
    interactive
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_args()?;
    println!("=== LatencyDesk Client ===");
    println!("Connecting to host: {}", config.host_addr);
    println!("Local listening on: {}", config.bind_addr);

    let mut session = SessionMachine::default();
    session.apply(SessionEvent::Start)?;
    session.apply(SessionEvent::TransportReady)?;
    session.apply(SessionEvent::Authenticated)?;
    session.apply(SessionEvent::Negotiated)?;
    let endpoint = UdpEndpoint::bind_connected(
        config.bind_addr,
        config.host_addr,
        DEFAULT_MAX_SOCKET_DATAGRAM,
    )?;
    endpoint.set_timeout(Duration::from_millis(50))?;

    let running = Arc::new(AtomicBool::new(true));
    let input_sender_thread = if simulated_input_enabled(config.interactive) {
        println!("[Client] Simulated pointer input test mode enabled.");
        let r_clone = Arc::clone(&running);
        let send_endpoint = endpoint.try_clone()?;
        Some(thread::spawn(move || {
            let mut seq = 1u64;
            while r_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
                let msg = InputMessage {
                    session_epoch: 1,
                    sequence: seq,
                    event: InputEvent::PointerMotionRelative { dx: 2, dy: -1 },
                };
                if let Ok(encoded) = msg.encode() {
                    let _ = send_endpoint.send(&encoded);
                    seq += 1;
                }
            }
        }))
    } else {
        None
    };

    let mut reassembler = Reassembler::new(ReassemblyConfig::default())?;
    let mut recv_buf = vec![0u8; DEFAULT_MAX_SOCKET_DATAGRAM];

    let start_time = Instant::now();
    let mut received_frames = 0u64;
    let mut total_payload_bytes = 0u64;

    println!("Client receiver loop active. Waiting for video stream...");

    while running.load(Ordering::Relaxed) {
        if let Some(max_frames) = config.frames {
            if received_frames >= max_frames {
                break;
            }
        }

        match endpoint.receive(&mut recv_buf) {
            Ok(bytes_read) => {
                let now_ns = start_time.elapsed().as_nanos() as u64;
                match reassembler.ingest(&recv_buf[..bytes_read], now_ns) {
                    Ok(IngestOutcome::Complete(frame)) => {
                        received_frames += 1;
                        total_payload_bytes += frame.bytes.len() as u64;

                        match ExactTestCodec::decode(&frame.bytes, now_ns) {
                            Ok(decoded) => {
                                if received_frames % 60 == 0 || received_frames == 1 {
                                    let elapsed = start_time.elapsed().as_secs_f64();
                                    let fps = received_frames as f64 / elapsed;
                                    let mbit_s =
                                        (total_payload_bytes * 8) as f64 / (elapsed * 1_000_000.0);
                                    println!(
                                        "[Client] Frame {} ({}x{}, seq {}, {:.1} fps, {:.2} Mbps, checksum: 0x{:016x})",
                                        received_frames,
                                        decoded.descriptor.width,
                                        decoded.descriptor.height,
                                        decoded.descriptor.capture_sequence,
                                        fps,
                                        mbit_s,
                                        decoded.checksum64()
                                    );
                                }
                            }
                            Err(err) => {
                                eprintln!(
                                    "[Client] Decode error on frame {}: {:?}",
                                    received_frames, err
                                );
                            }
                        }
                    }
                    Ok(IngestOutcome::Pending { .. }) => {}
                    Ok(IngestOutcome::Duplicate { .. }) => {}
                    Err(e) => {
                        eprintln!("[Client] Reassembly error: {:?}", e);
                    }
                }
            }
            Err(latencydesk_socket_transport::SocketError::Io(e)) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    // Timeout while waiting for packets
                } else if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.raw_os_error() == Some(111)
                {
                    println!("[Client] Host closed connection.");
                    break;
                } else {
                    eprintln!("[Client] Socket receive error: {:?}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("[Client] Socket receive error: {:?}", e);
                break;
            }
        }
    }

    running.store(false, Ordering::Relaxed);
    if let Some(input_sender_thread) = input_sender_thread {
        let _ = input_sender_thread.join();
    }

    let total_elapsed = start_time.elapsed();
    let stats = reassembler.stats();

    println!(
        concat!(
            "\n=== Client Stream Summary ===\n",
            "Frames decoded: {}\n",
            "Total data: {} bytes\n",
            "Duration: {:.2}s\n",
            "Average FPS: {:.1}\n",
            "Datagrams accepted: {}\n",
            "Conflicting fragments: {}\n",
            "Expired frames: {}"
        ),
        received_frames,
        total_payload_bytes,
        total_elapsed.as_secs_f64(),
        received_frames as f64 / total_elapsed.as_secs_f64().max(0.001),
        stats.datagrams_accepted,
        stats.conflicting_fragments,
        stats.frames_expired
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::simulated_input_enabled;

    #[test]
    fn simulated_input_requires_explicit_interactive_mode() {
        assert!(!simulated_input_enabled(false));
        assert!(simulated_input_enabled(true));
    }
}
