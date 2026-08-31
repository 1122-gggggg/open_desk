//! Platform-neutral exact-mTLS ProductSession process probe.

use latencydesk_protocol::{media_flags, ControlKind, MediaKind};
use latencydesk_socket_transport::{
    identity::{
        accept_exact_peer_with_timeout, connect_exact_peer, load_certificate_der,
        mtls_client_config, mtls_server_config, TlsIdentity,
    },
    product::ProductSession,
    quic::{bind_client, bind_server, QuicConnection},
    turn_socket::{AuthenticatedTurnRoute, TurnRouteConfig},
};
use latencydesk_transport::FragmentSpec;
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    net::{IpAddr, SocketAddr},
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;

const CLIENT_CONTROL_LABEL: &[u8] = b"client-control";
const SERVER_CONTROL_LABEL: &[u8] = b"server-control";
const INPUT_LABEL: &[u8] = b"input";
const MEDIA_LABEL: &[u8] = b"media";
const COMPLETE_LABEL: &[u8] = b"complete";
const FINAL_ACK: &[u8] = b"product-probe-complete-acked";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Host,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TurnOptions {
    server: SocketAddr,
    username: String,
    password_file: PathBuf,
    channel: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    role: Role,
    bind: SocketAddr,
    peer: Option<SocketAddr>,
    certificate: PathBuf,
    private_key: PathBuf,
    peer_certificate: PathBuf,
    timeout: Duration,
    challenge: [u8; 32],
    turn: Option<TurnOptions>,
}

fn parse_from<I, S>(values: I) -> Result<Args, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values = values
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    let mut role = None;
    let mut bind: Option<SocketAddr> = None;
    let mut peer: Option<SocketAddr> = None;
    let mut certificate = None;
    let mut private_key = None;
    let mut peer_certificate = None;
    let mut timeout = None;
    let mut challenge = None;
    let mut turn_server: Option<SocketAddr> = None;
    let mut turn_username = None;
    let mut turn_password_file = None;
    let mut turn_channel = None;
    let mut index = 1;
    while index < values.len() {
        let flag = values[index].as_str();
        let value = values
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--role" => {
                role = Some(match value.as_str() {
                    "host" => Role::Host,
                    "client" => Role::Client,
                    _ => return Err("--role must be host or client".into()),
                });
            }
            "--bind" => bind = Some(value.parse().map_err(|_| "invalid --bind")?),
            "--peer" => peer = Some(value.parse().map_err(|_| "invalid --peer")?),
            "--cert" => certificate = Some(PathBuf::from(value)),
            "--key" => private_key = Some(PathBuf::from(value)),
            "--peer-cert" => peer_certificate = Some(PathBuf::from(value)),
            "--timeout" => timeout = Some(value.parse::<u64>().map_err(|_| "invalid --timeout")?),
            "--challenge" => challenge = Some(decode_hex_32(value)?),
            "--turn-server" => {
                turn_server = Some(value.parse().map_err(|_| "invalid --turn-server")?)
            }
            "--turn-username" => turn_username = Some(value.clone()),
            "--turn-password-file" => turn_password_file = Some(PathBuf::from(value)),
            "--turn-channel" => turn_channel = Some(parse_channel(value)?),
            _ => return Err(format!("unknown option {flag}")),
        }
        index += 2;
    }
    let role = role.ok_or("--role is required")?;
    let bind = bind.ok_or("--bind is required")?;
    if unusable(bind) || (role == Role::Host && bind.port() == 0) {
        return Err("--bind must be a usable address and Host port must be nonzero".into());
    }
    let peer = match (role, peer) {
        (Role::Client, Some(peer)) if peer.port() != 0 && !unusable(peer) => Some(peer),
        (Role::Client, _) => return Err("Client requires a usable --peer".into()),
        (Role::Host, None) => None,
        (Role::Host, Some(_)) => return Err("Host does not accept --peer".into()),
    };
    if peer.is_some_and(|peer| peer.is_ipv4() != bind.is_ipv4()) {
        return Err("bind and peer address families must match".into());
    }
    let timeout_seconds = timeout.ok_or("--timeout is required")?;
    if !(2..=120).contains(&timeout_seconds) {
        return Err("--timeout must be in 2..=120".into());
    }
    let turn_count = [
        turn_server.is_some(),
        turn_username.is_some(),
        turn_password_file.is_some(),
        turn_channel.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    let turn = match turn_count {
        0 => None,
        4 if role == Role::Client => {
            let server = turn_server.expect("count proves server");
            if server.port() == 0
                || unusable(server)
                || server.is_ipv4() != bind.is_ipv4()
                || turn_username.as_ref().is_some_and(String::is_empty)
            {
                return Err("TURN address, family, or username policy failed".into());
            }
            Some(TurnOptions {
                server,
                username: turn_username.expect("count proves username"),
                password_file: turn_password_file.expect("count proves password path"),
                channel: turn_channel.expect("count proves channel"),
            })
        }
        _ => return Err("TURN mode requires all four TURN options on Client only".into()),
    };
    Ok(Args {
        role,
        bind,
        peer,
        certificate: certificate.ok_or("--cert is required")?,
        private_key: private_key.ok_or("--key is required")?,
        peer_certificate: peer_certificate.ok_or("--peer-cert is required")?,
        timeout: Duration::from_secs(timeout_seconds),
        challenge: challenge.ok_or("--challenge is required")?,
        turn,
    })
}

fn parse_channel(value: &str) -> Result<u16, String> {
    let channel = if let Some(hex) = value.strip_prefix("0x") {
        u16::from_str_radix(hex, 16).map_err(|_| "invalid --turn-channel")?
    } else {
        value.parse().map_err(|_| "invalid --turn-channel")?
    };
    if !(0x4000..=0x4fff).contains(&channel) {
        return Err("--turn-channel must be in 0x4000..=0x4fff".into());
    }
    Ok(channel)
}

fn unusable(address: SocketAddr) -> bool {
    address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("--challenge must be 64 lowercase hexadecimal characters".into());
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid --challenge")?;
    }
    if output == [0; 32] {
        return Err("--challenge must be nonzero".into());
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write to String");
    }
    output
}

fn challenge_payload(label: &[u8], challenge: [u8; 32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(label.len() + 65);
    output.extend_from_slice(label);
    output.push(b'|');
    output.extend_from_slice(encode_hex(&challenge).as_bytes());
    output
}

fn parse_challenge(payload: &[u8], label: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    let mut prefix = Vec::with_capacity(label.len() + 1);
    prefix.extend_from_slice(label);
    prefix.push(b'|');
    let encoded = payload
        .strip_prefix(prefix.as_slice())
        .ok_or("product probe challenge label mismatch")?;
    Ok(decode_hex_32(std::str::from_utf8(encoded)?)?)
}

fn random_session_id() -> Result<NonZeroU64, Box<dyn Error>> {
    let mut bytes = [0_u8; 8];
    getrandom::getrandom(&mut bytes).map_err(|_| "session randomness failed")?;
    NonZeroU64::new(u64::from_be_bytes(bytes)).ok_or_else(|| "session randomness was zero".into())
}

fn media_spec(codec_epoch: u32) -> FragmentSpec {
    FragmentSpec {
        kind: MediaKind::Video,
        flags: media_flags::KEYFRAME,
        stream_id: 1,
        codec_epoch,
        frame_id: 1,
        dependency_frame_id: None,
    }
}

fn load_password(path: &Path) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || !(16..=512).contains(&(metadata.len() as usize)) {
        return Err("TURN password file size policy failed".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("TURN password file must be owner-only".into());
        }
    }
    let mut password = std::fs::read(path)?;
    while password
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        password.pop();
    }
    if password.len() < 16 {
        return Err("TURN password is too short".into());
    }
    Ok(Zeroizing::new(password))
}

async fn host(args: &Args) -> Result<(), Box<dyn Error>> {
    let identity = TlsIdentity::load_der(&args.certificate, &args.private_key)?;
    let client_certificate = load_certificate_der(&args.peer_certificate)?;
    let endpoint = bind_server(
        mtls_server_config(&identity, &client_certificate)?,
        args.bind,
    )?;
    println!(
        "product-probe-ready role=host listening={} exact_mtls=true",
        endpoint.local_addr()?
    );
    let accepted = tokio::time::timeout(
        args.timeout,
        accept_exact_peer_with_timeout(&endpoint, &client_certificate, args.timeout),
    )
    .await
    .map_err(|_| "product probe Host accept timed out")??;
    let peer_source = accepted.remote_address();
    println!(
        "product-probe-connected role=host route=direct peer_source={peer_source} exact_mtls=true"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let session = ProductSession::host(accepted, random_session_id()?).await?;
    let mut control = session.accept_control_receiver().await?;
    let client_control = control.next_control().await?;
    if client_control.kind != ControlKind::Ping {
        return Err("Client challenge control kind mismatch".into());
    }
    let observed_client = parse_challenge(&client_control.payload, CLIENT_CONTROL_LABEL)?;
    session
        .send_control(
            ControlKind::Pong,
            &challenge_payload(SERVER_CONTROL_LABEL, args.challenge),
        )
        .await?;

    let mut input = session.accept_input_receiver().await?;
    let input = input.next_input().await?;
    if parse_challenge(&input, INPUT_LABEL)? != observed_client {
        return Err("Client input challenge mismatch".into());
    }
    session
        .send_control(ControlKind::Pong, b"input-applied")
        .await?;
    session.send_media_frame(
        media_spec(session.stamp().codec_epoch),
        &challenge_payload(MEDIA_LABEL, args.challenge),
        Duration::from_millis(500),
    )?;
    let complete = control.next_control().await?;
    if complete.kind != ControlKind::Pong
        || parse_challenge(&complete.payload, COMPLETE_LABEL)? != observed_client
    {
        return Err("Client completion challenge mismatch".into());
    }
    session.send_control(ControlKind::Pong, FINAL_ACK).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    println!(
        "product-probe-result role=host route=direct exact_mtls=true product=true control=true input=true media=true clean=true session_id={} route_epoch={} peer_source={} peer_challenge_sha256={}",
        session.stamp().session_id,
        session.stamp().route_epoch,
        peer_source,
        encode_hex(&Sha256::digest(observed_client)),
    );
    session.close(0, b"product probe complete");
    endpoint.close(0_u32.into(), b"product probe complete");
    tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
        .await
        .map_err(|_| "Host endpoint cleanup timed out")?;
    Ok(())
}

async fn run_client_session(
    args: &Args,
    connection: QuicConnection,
    route_name: &str,
    local_route: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let session = ProductSession::client(connection).await?;
    session
        .send_control(
            ControlKind::Ping,
            &challenge_payload(CLIENT_CONTROL_LABEL, args.challenge),
        )
        .await?;
    let mut control = session.accept_control_receiver().await?;
    let server_control = control.next_control().await?;
    if server_control.kind != ControlKind::Pong {
        return Err("Host challenge control kind mismatch".into());
    }
    let observed_server = parse_challenge(&server_control.payload, SERVER_CONTROL_LABEL)?;
    session
        .send_input(&challenge_payload(INPUT_LABEL, args.challenge))
        .await?;
    let input_ack = control.next_control().await?;
    if input_ack.kind != ControlKind::Pong || input_ack.payload.as_ref() != b"input-applied" {
        return Err("Host input acknowledgement mismatch".into());
    }
    let media = session.receive_media_frame().await?;
    if parse_challenge(&media.bytes, MEDIA_LABEL)? != observed_server {
        return Err("Host media challenge mismatch".into());
    }
    session
        .send_control(
            ControlKind::Pong,
            &challenge_payload(COMPLETE_LABEL, args.challenge),
        )
        .await?;
    let final_ack = control.next_control().await?;
    if final_ack.kind != ControlKind::Pong || final_ack.payload.as_ref() != FINAL_ACK {
        return Err("Host final acknowledgement mismatch".into());
    }
    println!(
        "product-probe-result role=client route={} exact_mtls=true product=true control=true input=true media=true clean=true session_id={} route_epoch={} local_route={} peer_challenge_sha256={}",
        route_name,
        session.stamp().session_id,
        session.stamp().route_epoch,
        local_route,
        encode_hex(&Sha256::digest(observed_server)),
    );
    session.close(0, b"product probe complete");
    Ok(())
}

async fn client(args: &Args) -> Result<(), Box<dyn Error>> {
    let identity = TlsIdentity::load_der(&args.certificate, &args.private_key)?;
    let server_certificate = load_certificate_der(&args.peer_certificate)?;
    let client_config = mtls_client_config(&identity, &server_certificate)?;
    let peer = args.peer.ok_or("Client peer missing after validation")?;
    if let Some(turn) = &args.turn {
        let password = load_password(&turn.password_file)?;
        let route = Arc::new(
            AuthenticatedTurnRoute::establish(TurnRouteConfig {
                server: turn.server,
                bind: args.bind,
                username: turn.username.as_bytes().to_vec(),
                password: password.to_vec(),
                peer,
                channel: turn.channel,
                timeout: args.timeout,
            })
            .await?,
        );
        let relayed = route.local_addr()?;
        let endpoint = Arc::clone(&route)
            .into_quinn_endpoint(quinn::EndpointConfig::default(), client_config)?;
        let connection = tokio::time::timeout(
            args.timeout,
            connect_exact_peer(&endpoint, peer, &server_certificate),
        )
        .await
        .map_err(|_| "TURN exact-mTLS connection timed out")??;
        println!(
            "product-probe-connected role=client route=turn local_route={relayed} exact_mtls=true"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        run_client_session(args, connection, "turn", relayed).await?;
        endpoint.close(0_u32.into(), b"product probe complete");
        tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
            .await
            .map_err(|_| "TURN client endpoint cleanup timed out")?;
        route.shutdown().await?;
    } else {
        let endpoint = bind_client(client_config, args.bind)?;
        let local = endpoint.local_addr()?;
        let connection = tokio::time::timeout(
            args.timeout,
            connect_exact_peer(&endpoint, peer, &server_certificate),
        )
        .await
        .map_err(|_| "direct exact-mTLS connection timed out")??;
        println!(
            "product-probe-connected role=client route=direct local_route={local} exact_mtls=true"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        run_client_session(args, connection, "direct", local).await?;
        endpoint.close(0_u32.into(), b"product probe complete");
        tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
            .await
            .map_err(|_| "direct client endpoint cleanup timed out")?;
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if env::args().nth(1).as_deref() == Some("--version") {
        println!("latencydesk-product-probe {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let result = async {
        let args = parse_from(env::args()).map_err(|error| -> Box<dyn Error> { error.into() })?;
        let timeout = args.timeout;
        tokio::time::timeout(timeout, async {
            match args.role {
                Role::Host => host(&args).await,
                Role::Client => client(&args).await,
            }
        })
        .await
        .map_err(|_| "product probe total deadline elapsed")?
    }
    .await;
    if let Err(error) = result {
        eprintln!("product-probe failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_direct_and_complete_turn_modes() {
        assert!(parse_from([
            "probe",
            "--role",
            "client",
            "--bind",
            "127.0.0.1:0",
            "--peer",
            "127.0.0.1:5000",
            "--cert",
            "client.cert.der",
            "--key",
            "client.key.der",
            "--peer-cert",
            "server.cert.der",
            "--timeout",
            "10",
            "--challenge",
            "0101010101010101010101010101010101010101010101010101010101010101",
        ])
        .is_ok());

        let mut turn = vec![
            "probe",
            "--role",
            "client",
            "--bind",
            "127.0.0.1:0",
            "--peer",
            "127.0.0.1:5000",
            "--cert",
            "client.cert.der",
            "--key",
            "client.key.der",
            "--peer-cert",
            "server.cert.der",
            "--timeout",
            "10",
            "--challenge",
            "0101010101010101010101010101010101010101010101010101010101010101",
        ];
        turn.extend([
            "--turn-server",
            "127.0.0.1:3478",
            "--turn-username",
            "alice",
            "--turn-password-file",
            "turn.secret",
            "--turn-channel",
            "0x4000",
        ]);
        assert!(parse_from(turn).is_ok());
    }

    #[test]
    fn parser_rejects_partial_turn_and_unsafe_addresses() {
        let base = [
            "probe",
            "--role",
            "client",
            "--bind",
            "127.0.0.1:0",
            "--peer",
            "127.0.0.1:5000",
            "--cert",
            "client.cert.der",
            "--key",
            "client.key.der",
            "--peer-cert",
            "server.cert.der",
            "--timeout",
            "10",
            "--challenge",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--turn-server",
            "127.0.0.1:3478",
        ];
        assert!(parse_from(base).is_err());
        assert!(decode_hex_32(&"00".repeat(32)).is_err());
        assert!(parse_channel("0x3fff").is_err());
    }
}
