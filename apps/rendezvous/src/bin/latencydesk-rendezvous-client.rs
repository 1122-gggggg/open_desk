use latencydesk_protocol::{
    compute_candidate_priority, CandidateExchange, CandidateType, IceCandidate, RelayProvider,
    RendezvousRegistration, RendezvousRole, TransportProtocol, WireIpAddr,
};
use latencydesk_rendezvous::DeviceId;
use latencydesk_rendezvousd::exchange_registration;
use latencydesk_socket_transport::ice::{IceCredentials, IceRole};
use latencydesk_socket_transport::identity::{
    certificate_fingerprint, connect_exact_peer, load_certificate_der, mtls_client_config,
    TlsIdentity,
};
use latencydesk_socket_transport::quic::bind_client;
use std::env;
use std::error::Error;
use std::net::UdpSocket;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    server: SocketAddr,
    bind: SocketAddr,
    certificate: PathBuf,
    private_key: PathBuf,
    server_certificate: PathBuf,
    expected_peer_certificate: PathBuf,
    role: RendezvousRole,
    match_id: [u8; 16],
    exchange_id: u64,
    candidate: SocketAddr,
    timeout: Duration,
}

fn parse_from<I, S>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values: Vec<String> = args
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect();
    let mut server: Option<SocketAddr> = None;
    let mut bind: Option<SocketAddr> = None;
    let mut certificate = None;
    let mut private_key = None;
    let mut server_certificate = None;
    let mut expected_peer_certificate = None;
    let mut role = None;
    let mut match_id = None;
    let mut exchange_id = None;
    let mut candidate: Option<SocketAddr> = None;
    let mut timeout = None;
    let mut index = 1;
    while index < values.len() {
        let flag = values[index].as_str();
        let value = values
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--server" => server = Some(value.parse().map_err(|_| "invalid server")?),
            "--bind" => bind = Some(value.parse().map_err(|_| "invalid bind")?),
            "--identity-cert" => certificate = Some(PathBuf::from(value)),
            "--identity-key" => private_key = Some(PathBuf::from(value)),
            "--server-cert" => server_certificate = Some(PathBuf::from(value)),
            "--expected-peer-cert" => expected_peer_certificate = Some(PathBuf::from(value)),
            "--role" => {
                role = Some(match value.as_str() {
                    "initiator" => RendezvousRole::Initiator,
                    "responder" => RendezvousRole::Responder,
                    _ => return Err("role must be initiator or responder".into()),
                });
            }
            "--match-id" => match_id = Some(parse_hex_16(value)?),
            "--exchange-id" => {
                exchange_id = Some(value.parse::<u64>().map_err(|_| "invalid exchange ID")?);
            }
            "--candidate" => candidate = Some(value.parse().map_err(|_| "invalid candidate")?),
            "--timeout" => {
                timeout = Some(value.parse::<u64>().map_err(|_| "invalid timeout")?);
            }
            other => return Err(format!("unknown option {other}")),
        }
        index += 2;
    }
    let server = server.ok_or("--server is required")?;
    let bind = bind.ok_or("--bind is required")?;
    let candidate = candidate.ok_or("--candidate is required")?;
    if !usable_unicast(server)
        || !usable_unicast(candidate)
        || bind.port() != 0
        || bind.ip().is_unspecified()
        || bind.ip().is_multicast()
        || bind.is_ipv4() != server.is_ipv4()
        || candidate.is_ipv4() != server.is_ipv4()
    {
        return Err("server/bind/candidate address policy failed".into());
    }
    let exchange_id = exchange_id.ok_or("--exchange-id is required")?;
    if exchange_id == 0 {
        return Err("--exchange-id must be nonzero".into());
    }
    let timeout = timeout.ok_or("--timeout is required")?;
    if !(1..=120).contains(&timeout) {
        return Err("--timeout must be in 1..=120".into());
    }
    Ok(Args {
        server,
        bind,
        certificate: certificate.ok_or("--identity-cert is required")?,
        private_key: private_key.ok_or("--identity-key is required")?,
        server_certificate: server_certificate.ok_or("--server-cert is required")?,
        expected_peer_certificate: expected_peer_certificate
            .ok_or("--expected-peer-cert is required")?,
        role: role.ok_or("--role is required")?,
        match_id: match_id.ok_or("--match-id is required")?,
        exchange_id,
        candidate,
        timeout: Duration::from_secs(timeout),
    })
}

fn usable_unicast(address: SocketAddr) -> bool {
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return false;
    }
    !matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
}

fn parse_hex_16(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("--match-id must be exactly 32 hexadecimal characters".into());
    }
    let mut out = [0_u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid match ID")?;
    }
    if out == [0; 16] {
        return Err("--match-id must be nonzero".into());
    }
    Ok(out)
}

fn wire_ip(address: IpAddr) -> WireIpAddr {
    match address {
        IpAddr::V4(ip) => WireIpAddr::V4(ip.octets()),
        IpAddr::V6(ip) => WireIpAddr::V6(ip.octets()),
    }
}

async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let candidate_socket = UdpSocket::bind(args.candidate)?;
    if candidate_socket.local_addr()? != args.candidate {
        return Err("candidate socket did not retain the explicit address".into());
    }
    let identity = TlsIdentity::load_der(&args.certificate, &args.private_key)?;
    let server_certificate = load_certificate_der(&args.server_certificate)?;
    let expected_peer_certificate = load_certificate_der(&args.expected_peer_certificate)?;
    let self_device = DeviceId::new(certificate_fingerprint(identity.certificate_der()))?;
    let expected_peer = DeviceId::new(certificate_fingerprint(&expected_peer_certificate))?;
    let endpoint = bind_client(
        mtls_client_config(&identity, &server_certificate)?,
        args.bind,
    )?;
    let connection = tokio::time::timeout(
        args.timeout,
        connect_exact_peer(&endpoint, args.server, &server_certificate),
    )
    .await
    .map_err(|_| "rendezvous connect timed out")??;
    let ice_role = match args.role {
        RendezvousRole::Initiator => IceRole::Controlling,
        RendezvousRole::Responder => IceRole::Controlled,
    };
    let credentials = IceCredentials::generate()?.to_signaling(args.exchange_id, 1, ice_role)?;
    let candidate = IceCandidate {
        foundation: [1; 8],
        component: 1,
        transport: TransportProtocol::Udp,
        priority: compute_candidate_priority(CandidateType::Host, 65_535, 1),
        candidate_type: CandidateType::Host,
        relay_provider: RelayProvider::None,
        ip: wire_ip(args.candidate.ip()),
        port: args.candidate.port(),
        related_address: None,
    };
    let registration = RendezvousRegistration {
        version: RendezvousRegistration::VERSION,
        role: args.role,
        generation: 1,
        ttl_seconds: 30,
        match_id: args.match_id,
        expected_peer_fingerprint: expected_peer.into_bytes(),
        credentials,
        candidates: CandidateExchange {
            version: CandidateExchange::VERSION,
            exchange_id: args.exchange_id,
            generation: 1,
            candidates: vec![candidate],
        },
    };
    let delivery =
        exchange_registration(connection, self_device, registration, args.timeout).await?;
    println!(
        "rendezvous-client: matched=true role={:?} peer_candidates={} exact_mtls=true desktop_payload=false relay=false",
        args.role,
        delivery.registration.candidates.candidates.len(),
    );
    endpoint.close(0_u32.into(), b"rendezvous client complete");
    tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
        .await
        .map_err(|_| "rendezvous client cleanup timed out")?;
    drop(candidate_socket);
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if env::args().nth(1).as_deref() == Some("--version") {
        println!(
            "latencydesk-rendezvous-client {}",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }
    let args = match parse_from(env::args()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(args).await {
        eprintln!("rendezvous client failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_id_parser_is_exact_and_nonzero() {
        assert_eq!(
            parse_hex_16("01010101010101010101010101010101").unwrap(),
            [1; 16]
        );
        for invalid in [
            "",
            "00",
            "00000000000000000000000000000000",
            "gggggggggggggggggggggggggggggggg",
        ] {
            assert!(parse_hex_16(invalid).is_err());
        }
    }
}
