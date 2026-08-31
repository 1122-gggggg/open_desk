//! Bounded two-process exact-mTLS route promotion and rollback evidence.

use latencydesk_protocol::quic::SessionStamp;
use latencydesk_protocol::{
    media_flags, ControlKind, MediaKind, RouteTransitionMessage, RouteTransitionStage, WIRE_VERSION,
};
use latencydesk_socket_transport::{
    identity::{
        certificate_fingerprint, load_certificate_der, mtls_client_config, mtls_server_config,
        TlsIdentity,
    },
    product::{ProductRouteSet, ProductSession},
    quic::{bind_client, bind_server, QuicConnection},
};
use latencydesk_transport::FragmentSpec;
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

const SESSION_ID: u64 = 0x524f_5554_4550_524f;
const EPOCH2_CONTROL: &[u8] = b"epoch-2-control";
const EPOCH2_INPUT: &[u8] = b"epoch-2-input";
const EPOCH2_MEDIA: &[u8] = b"epoch-2-media";
const EPOCH3_CONTROL: &[u8] = b"epoch-3-control";
const EPOCH3_INPUT: &[u8] = b"epoch-3-input";
const EPOCH3_MEDIA: &[u8] = b"epoch-3-media";

#[derive(Debug)]
struct Args {
    role: String,
    certificate: PathBuf,
    private_key: PathBuf,
    peer_certificate: PathBuf,
    first: SocketAddr,
    second: SocketAddr,
    timeout: Duration,
    challenge: [u8; 32],
}

fn value(values: &[String], name: &str) -> Result<String, Box<dyn Error>> {
    let index = values
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing {name}"))?;
    values
        .get(index + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}").into())
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let values = env::args().skip(1).collect::<Vec<_>>();
    let role = value(&values, "--role")?;
    let first_flag = if role == "server" {
        "--listen"
    } else {
        "--host"
    };
    let second_flag = if role == "server" {
        "--listen2"
    } else {
        "--host2"
    };
    let first: SocketAddr = value(&values, first_flag)?.parse()?;
    let second: SocketAddr = value(&values, second_flag)?.parse()?;
    if role != "server" && role != "client" {
        return Err("--role must be server or client".into());
    }
    if first == second
        || first.port() == 0
        || second.port() == 0
        || !matches!(first.ip(), IpAddr::V4(ip) if ip.is_loopback())
        || !matches!(second.ip(), IpAddr::V4(ip) if ip.is_loopback())
    {
        return Err("route probe requires two distinct IPv4 loopback paths".into());
    }
    let timeout_seconds = value(&values, "--timeout")?.parse::<u64>()?;
    if !(1..=30).contains(&timeout_seconds) {
        return Err("--timeout must be in 1..=30".into());
    }
    Ok(Args {
        role,
        certificate: value(&values, "--cert")?.into(),
        private_key: value(&values, "--key")?.into(),
        peer_certificate: value(&values, "--peer-cert")?.into(),
        first,
        second,
        timeout: Duration::from_secs(timeout_seconds),
        challenge: decode_hex_32(&value(&values, "--challenge")?)?,
    })
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 {
        return Err("--challenge must be 64 lowercase hex characters".into());
    }
    let mut out = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)?;
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("--challenge must be lowercase hex".into());
        }
        out[index] = u8::from_str_radix(text, 16)?;
    }
    if out == [0; 32] {
        return Err("--challenge must be nonzero".into());
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write to string");
    }
    out
}

fn challenge_payload(label: &[u8], challenge: [u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(label.len() + 1 + 64);
    payload.extend_from_slice(label);
    payload.push(b'|');
    payload.extend_from_slice(encode_hex(&challenge).as_bytes());
    payload
}

fn peer_challenge(payload: &[u8], label: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    let prefix = [label, b"|"].concat();
    let encoded = payload
        .strip_prefix(prefix.as_slice())
        .ok_or("challenge payload label mismatch")?;
    decode_hex_32(std::str::from_utf8(encoded)?)
}

fn stamp() -> SessionStamp {
    SessionStamp {
        session_id: SESSION_ID,
        generation: 1,
        authorization_epoch: 1,
        display_epoch: 1,
        codec_epoch: 1,
        route_epoch: 1,
    }
}

fn route_material(
    label: &[u8],
    server_address: SocketAddr,
    session: SessionStamp,
    server_fingerprint: [u8; 32],
    client_fingerprint: [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut route = Sha256::new();
    route.update(b"latencydesk-route-probe-v2");
    route.update(label);
    route.update(server_address.to_string().as_bytes());
    route.update(session.session_id.to_be_bytes());
    route.update(session.generation.to_be_bytes());
    route.update(server_fingerprint);
    route.update(client_fingerprint);
    let route_digest: [u8; 32] = route.finalize().into();
    let mut transcript = Sha256::new();
    transcript.update(b"latencydesk-route-probe-exact-mtls-transcript-v2");
    transcript.update(route_digest);
    transcript.update(session.authorization_epoch.to_be_bytes());
    transcript.update(session.display_epoch.to_be_bytes());
    transcript.update(session.codec_epoch.to_be_bytes());
    let transcript_digest = transcript.finalize().into();
    (route_digest, transcript_digest)
}

fn transition(
    stage: RouteTransitionStage,
    sequence: u64,
    base_route_epoch: u64,
    binding: ([u8; 32], [u8; 32]),
) -> RouteTransitionMessage {
    RouteTransitionMessage {
        version: WIRE_VERSION,
        stage,
        sequence,
        base_route_epoch,
        next_route_epoch: base_route_epoch + 1,
        expires_at_ns: 10_000_000_000,
        route_digest: binding.0,
        transcript_digest: binding.1,
    }
}

fn media_spec(frame_id: u64) -> FragmentSpec {
    FragmentSpec {
        kind: MediaKind::Video,
        flags: media_flags::KEYFRAME,
        stream_id: 1,
        codec_epoch: 1,
        frame_id,
        dependency_frame_id: None,
    }
}

async fn server(args: &Args) -> Result<(), Box<dyn Error>> {
    let identity = TlsIdentity::load_der(&args.certificate, &args.private_key)?;
    let client_certificate = load_certificate_der(&args.peer_certificate)?;
    let server_fingerprint = certificate_fingerprint(identity.certificate_der());
    let client_fingerprint = certificate_fingerprint(&client_certificate);
    let first_endpoint = bind_server(
        mtls_server_config(&identity, &client_certificate)?,
        args.first,
    )?;
    let second_endpoint = bind_server(
        mtls_server_config(&identity, &client_certificate)?,
        args.second,
    )?;
    println!("route-probe-ready paths=2 exact_mtls=true");
    let (first_connection, second_connection) = tokio::join!(
        QuicConnection::accept(&first_endpoint),
        QuicConnection::accept(&second_endpoint),
    );
    let (active, candidate) = tokio::join!(
        ProductSession::host_with_stamp(first_connection?, stamp()),
        ProductSession::host_route_candidate(second_connection?, stamp()),
    );
    let active = active?;
    let candidate = candidate?;
    let first_material = route_material(
        b"path-0",
        args.first,
        stamp(),
        server_fingerprint,
        client_fingerprint,
    );
    let second_material = route_material(
        b"path-1",
        args.second,
        stamp(),
        server_fingerprint,
        client_fingerprint,
    );
    let active_binding = active.bind_authenticated_route(first_material.0, first_material.1)?;
    let candidate_binding =
        candidate.bind_authenticated_route(second_material.0, second_material.1)?;
    let mut routes = ProductRouteSet::new(active, active_binding, candidate, candidate_binding)?;
    println!("route-probe-connected role=server connections=2");
    tokio::time::sleep(Duration::from_millis(750)).await;
    let mut first_control;
    let mut second_control;

    let prepare = transition(RouteTransitionStage::Prepare, 1, 1, second_material);
    routes.send_route_transition(prepare).await?;
    first_control = routes.accept_control_receiver().await?;
    routes.next_route_transition(&mut first_control).await?;
    routes
        .send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..prepare
        })
        .await?;
    second_control = routes.accept_standby_control_receiver().await?;
    routes.next_route_activation(&mut second_control).await?;
    if routes.active_index() != 1 || routes.stamp().route_epoch != 2 {
        return Err("server promotion did not activate epoch 2".into());
    }
    let marker = routes.next_control(&mut second_control).await?;
    if marker.kind != ControlKind::Pong {
        return Err("client epoch-2 activation marker mismatch".into());
    }
    let observed_client_challenge = peer_challenge(&marker.payload, b"epoch-2-ready")?;
    routes
        .send_control(
            ControlKind::ConfigureStream,
            &challenge_payload(EPOCH2_CONTROL, args.challenge),
        )
        .await?;
    routes.send_media_frame(media_spec(2), EPOCH2_MEDIA, Duration::from_millis(250))?;
    let mut input = routes.accept_input_receiver().await?;
    if input.next_input().await?.as_ref() != EPOCH2_INPUT {
        return Err("epoch-2 input mismatch".into());
    }
    routes
        .send_control(ControlKind::Pong, b"epoch-2-data-acked")
        .await?;
    let failure_ready = routes.next_control(&mut second_control).await?;
    if failure_ready.kind != ControlKind::Pong
        || failure_ready.payload.as_ref() != b"epoch-2-failure-ready"
    {
        return Err("client failure barrier mismatch".into());
    }

    routes.fail_active_route(0x104, b"route probe injected candidate failure");
    println!("route-probe-phase role=server name=active-failed");
    let rollback = transition(RouteTransitionStage::Prepare, 2, 2, first_material);
    routes.send_rollback_via_retained(rollback).await?;
    println!("route-probe-phase role=server name=rollback-prepared-send");
    routes.next_route_transition(&mut first_control).await?;
    println!("route-probe-phase role=server name=rollback-prepared-received");
    routes
        .send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Commit,
            ..rollback
        })
        .await?;
    println!("route-probe-phase role=server name=rollback-commit-sent");
    routes.next_route_activation(&mut first_control).await?;
    println!("route-probe-phase role=server name=rollback-activated");
    if routes.active_index() != 0 || routes.stamp().route_epoch != 3 {
        return Err("server rollback did not activate epoch 3".into());
    }
    let marker = routes.next_control(&mut first_control).await?;
    if marker.kind != ControlKind::Pong
        || peer_challenge(&marker.payload, b"epoch-3-ready")? != observed_client_challenge
    {
        return Err("client epoch-3 activation marker mismatch".into());
    }
    routes
        .send_control(
            ControlKind::ConfigureStream,
            &challenge_payload(EPOCH3_CONTROL, args.challenge),
        )
        .await?;
    routes.send_media_frame(media_spec(3), EPOCH3_MEDIA, Duration::from_millis(250))?;
    let mut input = routes.accept_input_receiver().await?;
    if input.next_input().await?.as_ref() != EPOCH3_INPUT {
        return Err("epoch-3 input mismatch".into());
    }
    routes
        .send_control(ControlKind::Pong, b"epoch-3-data-acked")
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    println!(
        "route-probe-result role=server exact_mtls=true paths=2 promoted_epoch=2 rollback_epoch=3 active_index=0 active_failure=true input=true media=true control=true clean=true peer_challenge_sha256={}",
        encode_hex(&Sha256::digest(observed_client_challenge))
    );
    routes.close(0, b"route probe complete");
    first_endpoint.close(0_u32.into(), b"route probe complete");
    second_endpoint.close(0_u32.into(), b"route probe complete");
    Ok(())
}

async fn client(args: &Args) -> Result<(), Box<dyn Error>> {
    let identity = TlsIdentity::load_der(&args.certificate, &args.private_key)?;
    let server_certificate = load_certificate_der(&args.peer_certificate)?;
    let server_fingerprint = certificate_fingerprint(&server_certificate);
    let client_fingerprint = certificate_fingerprint(identity.certificate_der());
    let first_endpoint = bind_client(
        mtls_client_config(&identity, &server_certificate)?,
        "127.0.0.1:0".parse()?,
    )?;
    let second_endpoint = bind_client(
        mtls_client_config(&identity, &server_certificate)?,
        "127.0.0.1:0".parse()?,
    )?;
    let (first_connection, second_connection) = tokio::join!(
        QuicConnection::connect(&first_endpoint, args.first, "latencydesk.local"),
        QuicConnection::connect(&second_endpoint, args.second, "latencydesk.local"),
    );
    let (active, candidate) = tokio::join!(
        ProductSession::client(first_connection?),
        ProductSession::client_route_candidate(second_connection?, stamp()),
    );
    let active = active?;
    let candidate = candidate?;
    let first_material = route_material(
        b"path-0",
        args.first,
        stamp(),
        server_fingerprint,
        client_fingerprint,
    );
    let second_material = route_material(
        b"path-1",
        args.second,
        stamp(),
        server_fingerprint,
        client_fingerprint,
    );
    let active_binding = active.bind_authenticated_route(first_material.0, first_material.1)?;
    let candidate_binding =
        candidate.bind_authenticated_route(second_material.0, second_material.1)?;
    let mut routes = ProductRouteSet::new(active, active_binding, candidate, candidate_binding)?;
    println!("route-probe-connected role=client connections=2");
    tokio::time::sleep(Duration::from_millis(750)).await;
    let mut first_control = routes.accept_control_receiver().await?;

    let prepare = routes.next_route_transition(&mut first_control).await?;
    routes
        .send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Prepared,
            ..prepare
        })
        .await?;
    routes.next_route_transition(&mut first_control).await?;
    let mut second_control = routes.accept_control_receiver().await?;
    routes.next_route_confirmation(&mut second_control).await?;
    routes
        .send_control(
            ControlKind::Pong,
            &challenge_payload(b"epoch-2-ready", args.challenge),
        )
        .await?;
    let control = routes.next_control(&mut second_control).await?;
    if control.kind != ControlKind::ConfigureStream {
        return Err("epoch-2 control mismatch".into());
    }
    let observed_server_challenge = peer_challenge(&control.payload, EPOCH2_CONTROL)?;
    if routes.receive_media_frame().await?.bytes != EPOCH2_MEDIA {
        return Err("epoch-2 media mismatch".into());
    }
    routes.send_input(EPOCH2_INPUT).await?;
    let data_ack = routes.next_control(&mut second_control).await?;
    if data_ack.kind != ControlKind::Pong || data_ack.payload.as_ref() != b"epoch-2-data-acked" {
        return Err("epoch-2 data acknowledgement mismatch".into());
    }
    routes
        .send_control(ControlKind::Pong, b"epoch-2-failure-ready")
        .await?;

    println!("route-probe-phase role=client name=awaiting-retained-rollback");
    let rollback = routes.next_route_transition(&mut first_control).await?;
    println!("route-probe-phase role=client name=rollback-prepare-received");
    routes
        .send_route_transition(RouteTransitionMessage {
            stage: RouteTransitionStage::Prepared,
            ..rollback
        })
        .await?;
    println!("route-probe-phase role=client name=rollback-prepared-sent");
    routes.next_route_transition(&mut first_control).await?;
    println!("route-probe-phase role=client name=rollback-commit-received");
    routes.next_route_confirmation(&mut first_control).await?;
    println!("route-probe-phase role=client name=rollback-confirmed");
    routes
        .send_control(
            ControlKind::Pong,
            &challenge_payload(b"epoch-3-ready", args.challenge),
        )
        .await?;
    let control = routes.next_control(&mut first_control).await?;
    if control.kind != ControlKind::ConfigureStream
        || peer_challenge(&control.payload, EPOCH3_CONTROL)? != observed_server_challenge
    {
        return Err("epoch-3 control mismatch".into());
    }
    if routes.receive_media_frame().await?.bytes != EPOCH3_MEDIA {
        return Err("epoch-3 media mismatch".into());
    }
    routes.send_input(EPOCH3_INPUT).await?;
    let final_ack = routes.next_control(&mut first_control).await?;
    if final_ack.kind != ControlKind::Pong || final_ack.payload.as_ref() != b"epoch-3-data-acked" {
        return Err("epoch-3 data acknowledgement mismatch".into());
    }
    println!(
        "route-probe-result role=client exact_mtls=true paths=2 promoted_epoch=2 rollback_epoch=3 active_index=0 active_failure=true input=true media=true control=true clean=true peer_challenge_sha256={}",
        encode_hex(&Sha256::digest(observed_server_challenge))
    );
    routes.close(0, b"route probe complete");
    first_endpoint.close(0_u32.into(), b"route probe complete");
    second_endpoint.close(0_u32.into(), b"route probe complete");
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if env::args().nth(1).as_deref() == Some("--version") {
        println!("latencydesk-route-probe {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let result = async {
        let args = parse_args()?;
        let timeout = args.timeout;
        tokio::time::timeout(timeout, async {
            if args.role == "server" {
                server(&args).await
            } else {
                client(&args).await
            }
        })
        .await
        .map_err(|_| "route probe deadline elapsed")?
    }
    .await;
    if let Err(error) = result {
        eprintln!("route-probe failed: {error}");
        std::process::exit(1);
    }
}
