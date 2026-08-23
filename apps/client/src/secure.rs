//! Fail-closed product client path over exact-certificate mutual TLS and QUIC.

use super::ClientArgs;
use latencydesk_input::{InputEvent, InputMessage};
use latencydesk_socket_transport::identity::{
    connect_exact_peer, load_certificate_der, mtls_client_config, TlsIdentity,
};
use latencydesk_socket_transport::product::ProductSession;
use latencydesk_socket_transport::quic::bind_client;
use std::error::Error;
use std::time::Duration;

const CLIENT_RELIABLE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

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

    #[cfg(not(windows))]
    if args.max_frames.is_none() && !args.inject_probe {
        return Err(
            "interactive presentation is currently supported only on Windows; use --frames <COUNT> or --inject-probe on this platform"
                .into(),
        );
    }

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

    let session = runtime.block_on(async {
        tokio::time::timeout(operation_timeout, async {
            let connection = connect_exact_peer(
                &endpoint,
                args.connect_addr,
                &exact_peer_certificate,
            )
            .await
            .map_err(|error| format!("exact-peer mTLS connection failed: {error}"))?;
            ProductSession::client(connection)
                .await
                .map_err(|error| format!("secure product handshake failed: {error}"))
        })
        .await
        .map_err(|_| {
            format!(
                "secure connection timed out after {} seconds; verify address, firewall, and exchanged certificates",
                operation_timeout.as_secs()
            )
        })?
    })?;

    let session_id = session.stamp().session_id;
    println!("handshake: active session_id={session_id}");

    let result = if args.inject_probe {
        run_probe(
            &runtime,
            &session,
            args.width,
            args.height,
            operation_timeout,
        )
    } else if let Some(needed) = args.max_frames {
        run_headless(&runtime, &session, needed, operation_timeout)
    } else {
        #[cfg(windows)]
        {
            run_windows_viewer(&runtime, session, operation_timeout)
        }
        #[cfg(not(windows))]
        {
            unreachable!("non-Windows interactive mode is rejected before connecting")
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

fn run_headless(
    runtime: &tokio::runtime::Runtime,
    session: &ProductSession,
    needed: u64,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let received = runtime.block_on(receive_frames_with_timeout(session, needed, timeout))?;
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
    let received = runtime.block_on(receive_frames_with_timeout(session, 3, timeout))?;
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
) -> Result<u64, Box<dyn Error>> {
    tokio::time::timeout(timeout, async {
        let mut received = 0_u64;
        while received < needed {
            session.receive_media_frame().await.map_err(|error| {
                format!(
                    "secure media transport ended after {received}/{needed} completed frames: {error}"
                )
            })?;
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

async fn send_input_event(
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

#[cfg(windows)]
#[derive(Debug)]
struct StrictNv12Frame {
    frame_id: u64,
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

#[cfg(windows)]
impl StrictNv12Frame {
    fn decode(
        frame: latencydesk_transport::ReassembledFrame,
        expected_size: Option<(u32, u32)>,
    ) -> Result<Self, String> {
        let (width, height, pixels) =
            super::parse_nv12_access_unit(&frame.bytes).ok_or_else(|| {
                format!(
                    "media frame {} is not a valid packed NV12 access unit",
                    frame.header.frame_id
                )
            })?;
        if let Some((expected_width, expected_height)) = expected_size {
            if (width, height) != (expected_width, expected_height) {
                return Err(format!(
                    "media frame {} changed dimensions from {}x{} to {}x{} without reconfiguration",
                    frame.header.frame_id, expected_width, expected_height, width, height
                ));
            }
        }
        Ok(Self {
            frame_id: frame.header.frame_id,
            width,
            height,
            pixels: pixels.to_vec(),
        })
    }
}

#[cfg(windows)]
#[derive(Debug)]
enum NetworkCommand {
    Input(InputEvent),
    Stop,
}

#[cfg(windows)]
fn run_windows_viewer(
    runtime: &tokio::runtime::Runtime,
    session: ProductSession,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    use latencydesk_platform_windows::D3D11WindowRenderer;
    use std::sync::{mpsc, Arc, Mutex};

    let first = runtime
        .block_on(async { tokio::time::timeout(timeout, session.receive_media_frame()).await })
        .map_err(|_| "timed out waiting for the first secure media frame")??;
    let first = StrictNv12Frame::decode(first, None)?;
    let stream_size = (first.width, first.height);
    let first_frame_id = first.frame_id;
    let reliable_timeout = reliable_operation_timeout(timeout);
    let mut window = D3D11WindowRenderer::new(first.width, first.height)
        .map_err(|error| format!("failed to create D3D11 renderer: {error:?}"))?;
    window
        .present_nv12(&first.pixels)
        .map_err(|error| format!("failed to present first NV12 frame: {error:?}"))?;

    println!(
        "Client Connected. Secure Direct3D 11 NV12 presentation window open ({}x{}).",
        first.width, first.height
    );
    println!("Close the window to disconnect safely.");

    // This single replacement slot is a bounded latest-frame queue: a stalled
    // renderer retains the newest decodable frame, never an older backlog.
    let latest_frame = Arc::new(Mutex::new(None::<StrictNv12Frame>));
    let network_latest = Arc::clone(&latest_frame);
    let (command_tx, command_rx) = tokio::sync::mpsc::channel::<NetworkCommand>(128);
    let (termination_tx, termination_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let network_session = session.clone();
    let mut network_task = runtime.spawn(async move {
        let result = viewer_network_loop(
            network_session,
            command_rx,
            network_latest,
            stream_size,
            first_frame_id,
            reliable_timeout,
        )
        .await;
        let _ = termination_tx.send(result.clone());
        result
    });

    let mut rendered_frames = 1_u64;
    let mut ui_error = None;
    'ui: while window.pump_messages() {
        match termination_rx.try_recv() {
            Ok(Err(error)) => {
                ui_error = Some(format!("secure transport terminated: {error}"));
                break;
            }
            Ok(Ok(())) => {
                ui_error = Some("secure transport stopped while the viewer was open".to_owned());
                break;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                ui_error = Some("secure transport task ended without a status".to_owned());
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        for event in window.poll_inputs(32) {
            if event.kind == latencydesk_platform_windows::INPUT_KIND_OVERFLOW {
                ui_error = Some(
                    "native input queue overflowed; disconnecting to prevent a stuck key or button"
                        .to_owned(),
                );
                break 'ui;
            }
            if let Some(input) = super::window_event_to_input(event, first.width, first.height) {
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

        let next_frame = match latest_frame.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => {
                ui_error = Some("latest-frame queue lock was poisoned".to_owned());
                break;
            }
        };
        if let Some(frame) = next_frame {
            if let Err(error) = window.present_nv12(&frame.pixels) {
                ui_error = Some(format!("D3D11 presentation failed: {error:?}"));
                break;
            }
            rendered_frames = rendered_frames.saturating_add(1);
            if rendered_frames % 60 == 0 {
                println!(
                    ">>> Secure streaming active: rendered frame #{} ({} NV12 bytes)",
                    frame.frame_id,
                    frame.pixels.len()
                );
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    if !network_task.is_finished() {
        match runtime.block_on(async {
            tokio::time::timeout(
                CLIENT_CLEANUP_TIMEOUT,
                command_tx.send(NetworkCommand::Stop),
            )
            .await
        }) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if ui_error.is_none() {
                    ui_error = Some(format!(
                        "failed to request safe transport shutdown: {error}"
                    ));
                }
            }
            Err(_) => {
                if ui_error.is_none() {
                    ui_error = Some(format!(
                        "safe transport shutdown request timed out after {CLIENT_CLEANUP_TIMEOUT:?}"
                    ));
                }
            }
        }
    }
    let network_result = match runtime
        .block_on(async { tokio::time::timeout(CLIENT_CLEANUP_TIMEOUT, &mut network_task).await })
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(format!("secure transport task failed: {error}")),
        Err(_) => {
            network_task.abort();
            let _ = runtime.block_on(async {
                tokio::time::timeout(CLIENT_CLEANUP_TIMEOUT, &mut network_task).await
            });
            Err(format!(
                "secure transport cleanup timed out after {CLIENT_CLEANUP_TIMEOUT:?}; network task cancelled"
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

#[cfg(windows)]
async fn viewer_network_loop(
    session: ProductSession,
    mut commands: tokio::sync::mpsc::Receiver<NetworkCommand>,
    latest_frame: std::sync::Arc<std::sync::Mutex<Option<StrictNv12Frame>>>,
    stream_size: (u32, u32),
    first_frame_id: u64,
    reliable_timeout: Duration,
) -> Result<(), String> {
    let mut sequence = 0_u64;
    let mut last_accepted_frame_id = first_frame_id;
    let result = loop {
        tokio::select! {
            biased;
            command = commands.recv() => match command {
                Some(NetworkCommand::Input(event)) => {
                    sequence = sequence.saturating_add(1);
                    if let Err(error) = send_input_event(
                        &session,
                        sequence,
                        event,
                        reliable_timeout,
                    ).await {
                        break Err(format!("reliable input send failed: {error}"));
                    }
                }
                Some(NetworkCommand::Stop) | None => break Ok(()),
            },
            frame = session.receive_media_frame() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => break Err(format!("secure media transport disconnected: {error}")),
                };
                let frame = match StrictNv12Frame::decode(frame, Some(stream_size)) {
                    Ok(frame) => frame,
                    Err(error) => break Err(error),
                };
                if let Err(error) = advance_viewer_frame_id(
                    &mut last_accepted_frame_id,
                    frame.frame_id,
                ) {
                    break Err(error);
                }
                match latest_frame.lock() {
                    Ok(mut slot) => *slot = Some(frame),
                    Err(_) => break Err("latest-frame queue lock was poisoned".to_owned()),
                }
            }
        }
    };

    sequence = sequence.saturating_add(1);
    let release_result =
        send_input_event(&session, sequence, InputEvent::ReleaseAll, reliable_timeout)
            .await
            .map_err(|error| format!("ReleaseAll shutdown send failed: {error}"));
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(release)) => Err(release),
        (Err(primary), Err(release)) => Err(format!("{primary}; {release}")),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_socket_transport::identity::mtls_client_config;
    use std::net::SocketAddr;

    #[test]
    fn hex_encoding_is_fixed_width_and_lowercase() {
        assert_eq!(encode_hex(&[0, 1, 0xab, 0xff]), "0001abff");
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
