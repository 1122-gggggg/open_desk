use latencydesk_turn_relayd::{run_client, ClientConfig};
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Debug)]
struct Args {
    server: SocketAddr,
    bind: SocketAddr,
    username: String,
    password_file: PathBuf,
    peer: SocketAddr,
    timeout: Duration,
    channel: u16,
    allow_loopback_lab: bool,
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
    let mut server: Option<SocketAddr> = None;
    let mut bind: Option<SocketAddr> = None;
    let mut username = None;
    let mut password_file = None;
    let mut peer: Option<SocketAddr> = None;
    let mut timeout = None;
    let mut channel = None;
    let mut allow_loopback_lab = false;
    let mut index = 1;
    while index < values.len() {
        let flag = values[index].as_str();
        if flag == "--allow-loopback-lab" {
            allow_loopback_lab = true;
            index += 1;
            continue;
        }
        let value = values
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--server" => server = Some(value.parse().map_err(|_| "invalid server")?),
            "--bind" => bind = Some(value.parse().map_err(|_| "invalid bind")?),
            "--username" => username = Some(value.clone()),
            "--password-file" => password_file = Some(PathBuf::from(value)),
            "--peer" => peer = Some(value.parse().map_err(|_| "invalid peer")?),
            "--timeout" => timeout = Some(value.parse::<u64>().map_err(|_| "invalid timeout")?),
            "--channel" => {
                channel = Some(parse_channel(value)?);
            }
            _ => return Err(format!("unknown option {flag}")),
        }
        index += 2;
    }
    let server = server.ok_or("--server is required")?;
    let bind = bind.ok_or("--bind is required")?;
    let peer = peer.ok_or("--peer is required")?;
    let timeout = timeout.ok_or("--timeout is required")?;
    if server.port() == 0
        || bind.port() != 0
        || bind.ip().is_unspecified()
        || server.is_ipv4() != bind.is_ipv4()
        || server.is_ipv4() != peer.is_ipv4()
        || !(1..=120).contains(&timeout)
        || ((server.ip().is_loopback() || peer.ip().is_loopback()) && !allow_loopback_lab)
    {
        return Err("TURN client address or timeout policy failed".into());
    }
    Ok(Args {
        server,
        bind,
        username: username.ok_or("--username is required")?,
        password_file: password_file.ok_or("--password-file is required")?,
        peer,
        timeout: Duration::from_secs(timeout),
        channel: channel.ok_or("--channel is required")?,
        allow_loopback_lab,
    })
}

fn parse_channel(value: &str) -> Result<u16, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let channel = u16::from_str_radix(value, 16).map_err(|_| "invalid channel")?;
    if !(0x4000..=0x4fff).contains(&channel) {
        return Err("channel must be in 0x4000..=0x4fff".into());
    }
    Ok(channel)
}

fn load_password(path: &Path) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() < 16 || metadata.len() > 512 {
        return Err("TURN password file policy failed".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("TURN password file must be owner-only".into());
        }
    }
    let mut bytes = std::fs::read(path)?;
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        bytes.pop();
    }
    Ok(Zeroizing::new(bytes))
}

async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    debug_assert!(args.allow_loopback_lab || !args.server.ip().is_loopback());
    let password = load_password(&args.password_file)?;
    let mut send_payload = vec![0_u8; 64];
    let mut channel_payload = vec![0_u8; 64];
    getrandom::getrandom(&mut send_payload).map_err(|_| "OS randomness failed")?;
    getrandom::getrandom(&mut channel_payload).map_err(|_| "OS randomness failed")?;
    let report = run_client(ClientConfig {
        server: args.server,
        bind: args.bind,
        username: args.username.into_bytes(),
        password: password.to_vec(),
        peer: args.peer,
        timeout: args.timeout,
        channel: args.channel,
        send_payload,
        channel_payload,
    })
    .await?;
    println!(
        "turn-client: challenge_authenticated={} send_round_trip={} channel_round_trip={} deallocated={} relayed={} opaque_payload=true exact_bytes=true tcp_relay=false desktop_payload=false",
        report.challenge_authenticated,
        report.send_round_trip,
        report.channel_round_trip,
        report.deallocated,
        report.relayed_address,
    );
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args = match parse_from(env::args()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(args).await {
        eprintln!("turn-client failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_parser_uses_rfc8656_range() {
        assert_eq!(parse_channel("0x4000").unwrap(), 0x4000);
        assert_eq!(parse_channel("4fff").unwrap(), 0x4fff);
        assert!(parse_channel("5000").is_err());
    }
}
