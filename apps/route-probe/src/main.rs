//! Bounded two-process exact-mTLS route promotion and rollback evidence.

use latencydesk_protocol::quic::SessionStamp;
use latencydesk_protocol::{
    compute_candidate_priority, media_flags, CandidateExchange, CandidateType, ControlKind,
    IceCandidate, MediaKind, RelayProvider, RendezvousRegistration, RendezvousRole,
    RouteTransitionMessage, RouteTransitionStage, TransportProtocol, WireIpAddr, WIRE_VERSION,
};
use latencydesk_rendezvous::DeviceId;
use latencydesk_rendezvousd::{exchange_registration, CommittedRendezvousDelivery};
use latencydesk_socket_transport::{
    ice::{IceCredentials, IceRole},
    identity::{
        certificate_fingerprint, connect_exact_peer, load_certificate_der, mtls_client_config,
        mtls_server_config, TlsIdentity,
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
    rendezvous: Option<RendezvousArgs>,
}

#[derive(Debug, Clone)]
struct RendezvousArgs {
    address: SocketAddr,
    certificate: PathBuf,
    match_id: [u8; 16],
    exchange_id: u64,
}

struct IntegratedRouteEvidence {
    _commit: CommittedRendezvousDelivery,
    rendezvous_endpoint: quinn::Endpoint,
    destinations: [SocketAddr; 2],
    initiator_sources: [SocketAddr; 2],
    route_digests: [[u8; 32]; 2],
    match_id: [u8; 16],
    generation: u32,
    exchange_id: u64,
    delivered_host_candidates: usize,
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
    parse_args_from(env::args().skip(1).collect())
}

fn parse_args_from(values: Vec<String>) -> Result<Args, Box<dyn Error>> {
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
    let rendezvous_address: Option<SocketAddr> = values
        .iter()
        .position(|v| v == "--rendezvous")
        .map(|_| value(&values, "--rendezvous"))
        .transpose()?
        .map(|v| v.parse())
        .transpose()?;
    let integrated = rendezvous_address.is_some();
    if !integrated
        && ["--rendezvous-cert", "--match-id", "--exchange-id"]
            .iter()
            .any(|flag| values.iter().any(|value| value == flag))
    {
        return Err("rendezvous route flags require --rendezvous".into());
    }
    if integrated
        && role == "client"
        && (values.iter().any(|v| v == "--host") || values.iter().any(|v| v == "--host2"))
    {
        return Err("integrated client must not provide --host/--host2".into());
    }
    let first: SocketAddr = match value(&values, first_flag) {
        Ok(v) => v.parse()?,
        Err(_) if integrated && role == "client" => "127.0.0.1:0".parse()?,
        Err(e) => return Err(e),
    };
    let second: SocketAddr = match value(&values, second_flag) {
        Ok(v) => v.parse()?,
        Err(_) if integrated && role == "client" => "127.0.0.1:0".parse()?,
        Err(e) => return Err(e),
    };
    if role != "server" && role != "client" {
        return Err("--role must be server or client".into());
    }
    if ((!integrated || role == "server")
        && (first == second || first.port() == 0 || second.port() == 0))
        || !matches!(first.ip(), IpAddr::V4(ip) if ip.is_loopback())
        || !matches!(second.ip(), IpAddr::V4(ip) if ip.is_loopback())
    {
        return Err("route probe requires two distinct IPv4 loopback paths".into());
    }
    let timeout_seconds = value(&values, "--timeout")?.parse::<u64>()?;
    if !(1..=30).contains(&timeout_seconds) {
        return Err("--timeout must be in 1..=30".into());
    }
    let rendezvous = if let Some(address) = rendezvous_address {
        if address.port() == 0 || !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback()) {
            return Err("--rendezvous must be a concrete IPv4 loopback address".into());
        }
        let match_text = value(&values, "--match-id")?;
        let match_id = parse_hex_16_lower(&match_text)?;
        let exchange_id = value(&values, "--exchange-id")?.parse::<u64>()?;
        if exchange_id == 0 {
            return Err("--exchange-id must be nonzero".into());
        }
        Some(RendezvousArgs {
            address,
            certificate: value(&values, "--rendezvous-cert")?.into(),
            match_id,
            exchange_id,
        })
    } else {
        None
    };
    Ok(Args {
        role,
        certificate: value(&values, "--cert")?.into(),
        private_key: value(&values, "--key")?.into(),
        peer_certificate: value(&values, "--peer-cert")?.into(),
        first,
        second,
        timeout: Duration::from_secs(timeout_seconds),
        challenge: decode_hex_32(&value(&values, "--challenge")?)?,
        rendezvous,
    })
}

fn parse_hex_16_lower(value: &str) -> Result<[u8; 16], Box<dyn Error>> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("--match-id must be exactly 32 lowercase hex characters".into());
    }
    let mut out = [0; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)?;
    }
    if out == [0; 16] {
        return Err("--match-id must be nonzero".into());
    }
    Ok(out)
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
) -> [u8; 32] {
    let mut route = Sha256::new();
    route.update(b"latencydesk-route-probe-v2");
    route.update(label);
    match server_address.ip() {
        IpAddr::V4(address) => {
            route.update([4]);
            route.update(address.octets());
        }
        IpAddr::V6(address) => {
            route.update([6]);
            route.update(address.octets());
        }
    }
    route.update(server_address.port().to_be_bytes());
    route.update(session.session_id.to_be_bytes());
    route.update(session.generation.to_be_bytes());
    route.update(server_fingerprint);
    route.update(client_fingerprint);
    let route_digest: [u8; 32] = route.finalize().into();
    route_digest
}

fn wire_ip(address: IpAddr) -> WireIpAddr {
    match address {
        IpAddr::V4(ip) => WireIpAddr::V4(ip.octets()),
        IpAddr::V6(ip) => WireIpAddr::V6(ip.octets()),
    }
}

fn host_candidate(address: SocketAddr, path_index: u8) -> IceCandidate {
    IceCandidate {
        foundation: [path_index.saturating_add(1); 8],
        component: 1,
        transport: TransportProtocol::Udp,
        priority: compute_candidate_priority(
            CandidateType::Host,
            u16::MAX.saturating_sub(u16::from(path_index)),
            1,
        ),
        candidate_type: CandidateType::Host,
        relay_provider: RelayProvider::None,
        ip: wire_ip(address.ip()),
        port: address.port(),
        related_address: None,
    }
}

fn committed_host_address(candidate: &IceCandidate) -> Result<SocketAddr, Box<dyn Error>> {
    candidate.validate()?;
    if candidate.component != 1
        || candidate.transport != TransportProtocol::Udp
        || candidate.candidate_type != CandidateType::Host
        || candidate.relay_provider != RelayProvider::None
        || candidate.related_address.is_some()
    {
        return Err("committed rendezvous candidate is not the direct Host profile".into());
    }
    let ip = match candidate.ip {
        WireIpAddr::V4(octets) => IpAddr::V4(octets.into()),
        WireIpAddr::V6(octets) => IpAddr::V6(octets.into()),
    };
    let address = SocketAddr::new(ip, candidate.port);
    if !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback()) || address.port() == 0 {
        return Err("committed Host candidate is outside the loopback evidence scope".into());
    }
    Ok(address)
}

fn update_registration(
    digest: &mut Sha256,
    registration: &RendezvousRegistration,
) -> Result<(), Box<dyn Error>> {
    let encoded = registration.encode()?;
    let length = u32::try_from(encoded.len())?;
    digest.update(length.to_be_bytes());
    digest.update(&encoded[..]);
    Ok(())
}

fn committed_route_digest(
    commit: &CommittedRendezvousDelivery,
    path_index: usize,
) -> Result<[u8; 32], Box<dyn Error>> {
    committed_route_digest_from_pair(
        commit.local_registration(),
        commit.local_device(),
        commit.peer_registration(),
        commit.peer_device(),
        path_index,
    )
}

fn committed_route_digest_from_pair(
    local: &RendezvousRegistration,
    local_device: DeviceId,
    peer: &RendezvousRegistration,
    peer_device: DeviceId,
    path_index: usize,
) -> Result<[u8; 32], Box<dyn Error>> {
    let (initiator, initiator_device, responder, responder_device) = match local.role {
        RendezvousRole::Initiator => (local, local_device, peer, peer_device),
        RendezvousRole::Responder => (peer, peer_device, local, local_device),
    };
    if initiator.role != RendezvousRole::Initiator || responder.role != RendezvousRole::Responder {
        return Err("committed rendezvous roles are not complementary".into());
    }
    let candidate = responder
        .candidates
        .candidates
        .get(path_index)
        .ok_or("committed responder candidate index is missing")?;
    let encoded_candidate = candidate.encode()?;
    let candidate_length = u16::try_from(encoded_candidate.len())?;
    let mut digest = Sha256::new();
    digest.update(b"latencydesk/committed-rendezvous-route/v1");
    digest.update([u8::try_from(path_index)?]);
    update_registration(&mut digest, initiator)?;
    update_registration(&mut digest, responder)?;
    digest.update(initiator_device.into_bytes());
    digest.update(responder_device.into_bytes());
    let session = stamp();
    digest.update(session.session_id.to_be_bytes());
    digest.update(session.generation.to_be_bytes());
    digest.update(session.authorization_epoch.to_be_bytes());
    digest.update(session.display_epoch.to_be_bytes());
    digest.update(session.codec_epoch.to_be_bytes());
    digest.update(session.route_epoch.to_be_bytes());
    digest.update(candidate_length.to_be_bytes());
    digest.update(encoded_candidate);
    Ok(digest.finalize().into())
}

async fn committed_route_evidence(
    args: &Args,
    identity: &TlsIdentity,
    peer_certificate: &[u8],
    local_addresses: [SocketAddr; 2],
) -> Result<Option<IntegratedRouteEvidence>, Box<dyn Error>> {
    let Some(rendezvous) = args.rendezvous.as_ref() else {
        return Ok(None);
    };
    if local_addresses[0] == local_addresses[1]
        || local_addresses.iter().any(|address| {
            address.port() == 0 || !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback())
        })
    {
        return Err("integrated product endpoints must own two loopback addresses".into());
    }
    let rendezvous_certificate = load_certificate_der(&rendezvous.certificate)?;
    let rendezvous_endpoint = bind_client(
        mtls_client_config(identity, &rendezvous_certificate)?,
        "127.0.0.1:0".parse()?,
    )?;
    let connection = tokio::time::timeout(
        args.timeout,
        connect_exact_peer(
            &rendezvous_endpoint,
            rendezvous.address,
            &rendezvous_certificate,
        ),
    )
    .await
    .map_err(|_| "rendezvous exact-mTLS connection timed out")??;
    let local_device = DeviceId::new(certificate_fingerprint(identity.certificate_der()))?;
    let peer_device = DeviceId::new(certificate_fingerprint(peer_certificate))?;
    let (role, ice_role) = if args.role == "server" {
        (RendezvousRole::Responder, IceRole::Controlled)
    } else {
        (RendezvousRole::Initiator, IceRole::Controlling)
    };
    let credentials =
        IceCredentials::generate()?.to_signaling(rendezvous.exchange_id, 1, ice_role)?;
    let registration = RendezvousRegistration {
        version: RendezvousRegistration::VERSION,
        role,
        generation: 1,
        ttl_seconds: 30,
        match_id: rendezvous.match_id,
        expected_peer_fingerprint: peer_device.into_bytes(),
        credentials,
        candidates: CandidateExchange {
            version: CandidateExchange::VERSION,
            exchange_id: rendezvous.exchange_id,
            generation: 1,
            candidates: vec![
                host_candidate(local_addresses[0], 0),
                host_candidate(local_addresses[1], 1),
            ],
        },
    };
    let commit =
        exchange_registration(connection, local_device, registration, args.timeout).await?;
    let local = commit.local_registration();
    let peer = commit.peer_registration();
    if commit.local_device() != local_device
        || commit.peer_device() != peer_device
        || local.role != role
        || peer.role == role
        || local.match_id != rendezvous.match_id
        || peer.match_id != rendezvous.match_id
        || local.generation != 1
        || peer.generation != 1
        || local.credentials.exchange_id != rendezvous.exchange_id
        || peer.credentials.exchange_id != rendezvous.exchange_id
        || local.candidates.exchange_id != rendezvous.exchange_id
        || peer.candidates.exchange_id != rendezvous.exchange_id
        || local.candidates.candidates.len() != 2
        || peer.candidates.candidates.len() != 2
    {
        return Err("committed rendezvous token failed route evidence validation".into());
    }
    let responder = if role == RendezvousRole::Responder {
        local
    } else {
        peer
    };
    let initiator = if role == RendezvousRole::Initiator {
        local
    } else {
        peer
    };
    let destinations = [
        committed_host_address(&responder.candidates.candidates[0])?,
        committed_host_address(&responder.candidates.candidates[1])?,
    ];
    let initiator_sources = [
        committed_host_address(&initiator.candidates.candidates[0])?,
        committed_host_address(&initiator.candidates.candidates[1])?,
    ];
    if destinations[0] == destinations[1] {
        return Err("committed responder candidates are duplicates".into());
    }
    if initiator_sources[0] == initiator_sources[1] {
        return Err("committed initiator candidates are duplicates".into());
    }
    let route_digests = [
        committed_route_digest(&commit, 0)?,
        committed_route_digest(&commit, 1)?,
    ];
    if route_digests[0] == [0; 32]
        || route_digests[1] == [0; 32]
        || route_digests[0] == route_digests[1]
    {
        return Err("committed rendezvous route digests are invalid".into());
    }
    println!(
        "route-rendezvous-committed role={} match_id={} generation=1 exchange_id={} delivered_host_candidates=2 product0_port={} product1_port={} rendezvous_local_port={}",
        args.role,
        encode_hex(&rendezvous.match_id),
        rendezvous.exchange_id,
        local_addresses[0].port(),
        local_addresses[1].port(),
        rendezvous_endpoint.local_addr()?.port(),
    );
    Ok(Some(IntegratedRouteEvidence {
        _commit: commit,
        rendezvous_endpoint,
        destinations,
        initiator_sources,
        route_digests,
        match_id: rendezvous.match_id,
        generation: 1,
        exchange_id: rendezvous.exchange_id,
        delivered_host_candidates: 2,
    }))
}

fn print_integrated_result(
    role: &str,
    evidence: &IntegratedRouteEvidence,
    peer_challenge: [u8; 32],
) {
    println!(
        "route-rendezvous-result role={} rendezvous_committed=true match_id={} generation={} exchange_id={} delivered_host_candidates={} path0_route_sha256={} path1_route_sha256={} candidate_sources_bound=true exact_mtls=true paths=2 promoted_epoch=2 rollback_epoch=3 active_index=0 active_failure=true input=true media=true control=true clean=true peer_challenge_sha256={}",
        role,
        encode_hex(&evidence.match_id),
        evidence.generation,
        evidence.exchange_id,
        evidence.delivered_host_candidates,
        encode_hex(&evidence.route_digests[0]),
        encode_hex(&evidence.route_digests[1]),
        encode_hex(&Sha256::digest(peer_challenge)),
    );
}

async fn close_integrated_evidence(
    evidence: Option<IntegratedRouteEvidence>,
) -> Result<(), Box<dyn Error>> {
    if let Some(evidence) = evidence {
        evidence
            .rendezvous_endpoint
            .close(0_u32.into(), b"integrated route probe complete");
        tokio::time::timeout(
            Duration::from_secs(2),
            evidence.rendezvous_endpoint.wait_idle(),
        )
        .await
        .map_err(|_| "integrated rendezvous endpoint cleanup timed out")?;
    }
    Ok(())
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
    let local_addresses = [first_endpoint.local_addr()?, second_endpoint.local_addr()?];
    println!("route-probe-ready paths=2 exact_mtls=true");
    let integrated =
        committed_route_evidence(args, &identity, &client_certificate, local_addresses).await?;
    if integrated
        .as_ref()
        .is_some_and(|evidence| evidence.destinations != local_addresses)
    {
        return Err("committed responder candidates do not match owned listeners".into());
    }
    let (first_connection, second_connection) = tokio::join!(
        QuicConnection::accept(&first_endpoint),
        QuicConnection::accept(&second_endpoint),
    );
    let first_connection = first_connection?;
    let second_connection = second_connection?;
    if integrated.as_ref().is_some_and(|evidence| {
        first_connection.remote_address() != evidence.initiator_sources[0]
            || second_connection.remote_address() != evidence.initiator_sources[1]
    }) {
        return Err(
            "product connection sources do not match committed Initiator candidates".into(),
        );
    }
    let (active, candidate) = tokio::join!(
        ProductSession::host_with_stamp(first_connection, stamp()),
        ProductSession::host_route_candidate(second_connection, stamp()),
    );
    let active = active?;
    let candidate = candidate?;
    let [first_material, second_material] = integrated.as_ref().map_or_else(
        || {
            [
                route_material(
                    b"path-0",
                    args.first,
                    stamp(),
                    server_fingerprint,
                    client_fingerprint,
                ),
                route_material(
                    b"path-1",
                    args.second,
                    stamp(),
                    server_fingerprint,
                    client_fingerprint,
                ),
            ]
        },
        |evidence| evidence.route_digests,
    );
    let active_binding = active.bind_authenticated_route(first_material)?;
    let candidate_binding = candidate.bind_authenticated_route(second_material)?;
    let candidate_transition_material = candidate_binding.transition_material();
    let active_transition_material = active_binding.transition_material();
    let mut routes = ProductRouteSet::new(active, active_binding, candidate, candidate_binding)?;
    println!("route-probe-connected role=server connections=2");
    tokio::time::sleep(Duration::from_millis(750)).await;
    let mut first_control;
    let mut second_control;

    let prepare = transition(
        RouteTransitionStage::Prepare,
        1,
        1,
        candidate_transition_material,
    );
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
    let rollback = transition(
        RouteTransitionStage::Prepare,
        2,
        2,
        active_transition_material,
    );
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
    if let Some(evidence) = integrated.as_ref() {
        print_integrated_result("server", evidence, observed_client_challenge);
    }
    routes.close(0, b"route probe complete");
    first_endpoint.close(0_u32.into(), b"route probe complete");
    second_endpoint.close(0_u32.into(), b"route probe complete");
    close_integrated_evidence(integrated).await?;
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
    let local_addresses = [first_endpoint.local_addr()?, second_endpoint.local_addr()?];
    let integrated =
        committed_route_evidence(args, &identity, &server_certificate, local_addresses).await?;
    let destinations = integrated
        .as_ref()
        .map_or([args.first, args.second], |evidence| evidence.destinations);
    let (first_connection, second_connection) = tokio::join!(
        QuicConnection::connect(&first_endpoint, destinations[0], "latencydesk.local"),
        QuicConnection::connect(&second_endpoint, destinations[1], "latencydesk.local"),
    );
    let first_connection = first_connection?;
    let second_connection = second_connection?;
    if first_connection.remote_address() != destinations[0]
        || second_connection.remote_address() != destinations[1]
    {
        return Err(
            "product connection destinations do not match committed Responder candidates".into(),
        );
    }
    let (active, candidate) = tokio::join!(
        ProductSession::client(first_connection),
        ProductSession::client_route_candidate(second_connection, stamp()),
    );
    let active = active?;
    let candidate = candidate?;
    let [first_material, second_material] = integrated.as_ref().map_or_else(
        || {
            [
                route_material(
                    b"path-0",
                    destinations[0],
                    stamp(),
                    server_fingerprint,
                    client_fingerprint,
                ),
                route_material(
                    b"path-1",
                    destinations[1],
                    stamp(),
                    server_fingerprint,
                    client_fingerprint,
                ),
            ]
        },
        |evidence| evidence.route_digests,
    );
    let active_binding = active.bind_authenticated_route(first_material)?;
    let candidate_binding = candidate.bind_authenticated_route(second_material)?;
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
    if let Some(evidence) = integrated.as_ref() {
        print_integrated_result("client", evidence, observed_server_challenge);
    }
    routes.close(0, b"route probe complete");
    first_endpoint.close(0_u32.into(), b"route probe complete");
    second_endpoint.close(0_u32.into(), b"route probe complete");
    close_integrated_evidence(integrated).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_registration(
        role: RendezvousRole,
        expected_peer: DeviceId,
        ports: [u16; 2],
    ) -> RendezvousRegistration {
        let (credential_role, ufrag, password_byte) = match role {
            RendezvousRole::Initiator => (
                latencydesk_protocol::IceCredentialRole::Controlling,
                "InitUfrag",
                "I",
            ),
            RendezvousRole::Responder => (
                latencydesk_protocol::IceCredentialRole::Controlled,
                "RespUfrag",
                "R",
            ),
        };
        RendezvousRegistration {
            version: RendezvousRegistration::VERSION,
            role,
            generation: 1,
            ttl_seconds: 30,
            match_id: [0x11; 16],
            expected_peer_fingerprint: expected_peer.into_bytes(),
            credentials: latencydesk_protocol::IceCredentialExchange::new(
                latencydesk_protocol::IceCredentialExchange::VERSION,
                7,
                1,
                credential_role,
                ufrag.into(),
                password_byte.repeat(32),
            )
            .unwrap(),
            candidates: CandidateExchange {
                version: CandidateExchange::VERSION,
                exchange_id: 7,
                generation: 1,
                candidates: vec![
                    host_candidate(SocketAddr::from(([127, 0, 0, 1], ports[0])), 0),
                    host_candidate(SocketAddr::from(([127, 0, 0, 1], ports[1])), 1),
                ],
            },
        }
    }

    fn integrated_client_args() -> Vec<String> {
        vec![
            "--role".into(),
            "client".into(),
            "--cert".into(),
            "client.der".into(),
            "--key".into(),
            "client-key.der".into(),
            "--peer-cert".into(),
            "server.der".into(),
            "--challenge".into(),
            "a".repeat(64),
            "--timeout".into(),
            "20".into(),
            "--rendezvous".into(),
            "127.0.0.1:3478".into(),
            "--rendezvous-cert".into(),
            "rendezvous.der".into(),
            "--match-id".into(),
            "b".repeat(32),
            "--exchange-id".into(),
            "7".into(),
        ]
    }

    #[test]
    fn integrated_client_accepts_no_product_destination() {
        let args = parse_args_from(integrated_client_args()).unwrap();
        assert_eq!(args.first, "127.0.0.1:0".parse().unwrap());
        assert_eq!(args.second, "127.0.0.1:0".parse().unwrap());
        let rendezvous = args.rendezvous.unwrap();
        assert_eq!(rendezvous.address, "127.0.0.1:3478".parse().unwrap());
        assert_eq!(rendezvous.exchange_id, 7);
    }

    #[test]
    fn integrated_client_rejects_cli_product_destination_and_partial_flags() {
        let mut destination = integrated_client_args();
        destination.extend(["--host".into(), "127.0.0.1:9000".into()]);
        assert!(parse_args_from(destination).is_err());

        let partial = vec![
            "--role".into(),
            "client".into(),
            "--host".into(),
            "127.0.0.1:9000".into(),
            "--host2".into(),
            "127.0.0.1:9001".into(),
            "--cert".into(),
            "client.der".into(),
            "--key".into(),
            "client-key.der".into(),
            "--peer-cert".into(),
            "server.der".into(),
            "--challenge".into(),
            "a".repeat(64),
            "--timeout".into(),
            "20".into(),
            "--match-id".into(),
            "b".repeat(32),
        ];
        assert!(parse_args_from(partial).is_err());
    }

    #[test]
    fn integrated_ids_are_lowercase_nonzero_and_bounded() {
        let mut uppercase = integrated_client_args();
        let match_index = uppercase
            .iter()
            .position(|arg| arg == "--match-id")
            .unwrap()
            + 1;
        uppercase[match_index] = "A".repeat(32);
        assert!(parse_args_from(uppercase).is_err());

        let mut zero_exchange = integrated_client_args();
        let exchange_index = zero_exchange
            .iter()
            .position(|arg| arg == "--exchange-id")
            .unwrap()
            + 1;
        zero_exchange[exchange_index] = "0".into();
        assert!(parse_args_from(zero_exchange).is_err());
    }

    #[test]
    fn committed_direct_candidate_policy_rejects_relay_metadata() {
        let address: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let mut candidate = host_candidate(address, 0);
        assert_eq!(committed_host_address(&candidate).unwrap(), address);
        candidate.candidate_type = CandidateType::Relayed;
        candidate.relay_provider = RelayProvider::Turn;
        candidate.priority = compute_candidate_priority(CandidateType::Relayed, 100, 1);
        assert!(committed_host_address(&candidate).is_err());
    }

    #[test]
    fn committed_route_digest_is_symmetric_and_matches_fixed_vector() {
        let initiator_device = DeviceId::new([0x21; 32]).unwrap();
        let responder_device = DeviceId::new([0x31; 32]).unwrap();
        let initiator =
            fixed_registration(RendezvousRole::Initiator, responder_device, [5001, 5002]);
        let responder =
            fixed_registration(RendezvousRole::Responder, initiator_device, [6001, 6002]);
        let initiator_view = committed_route_digest_from_pair(
            &initiator,
            initiator_device,
            &responder,
            responder_device,
            0,
        )
        .unwrap();
        let responder_view = committed_route_digest_from_pair(
            &responder,
            responder_device,
            &initiator,
            initiator_device,
            0,
        )
        .unwrap();
        assert_eq!(initiator_view, responder_view);
        assert_eq!(
            encode_hex(&initiator_view),
            "bd9899323ab30ba2d5bc307e94cca86185b0fef5d45aee97c5dde14515480b2b"
        );
    }
}
