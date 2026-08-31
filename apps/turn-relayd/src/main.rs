use latencydesk_turn_relayd::{serve, ServerConfig};
use std::env;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

const HELP: &str = "Usage: latencydesk-turn-relayd \
--listen <UNICAST:PORT> --relay-ip <UNICAST_IP> \
--realm <REALM> --username <USER> --password-file <OWNER_ONLY_FILE> \
--max-allocations <1..=256> --total-timeout <1..=3600> \
--exit-after-deallocations <0..=MAX> [--allow-loopback-lab]";

#[derive(Debug, PartialEq, Eq)]
struct Args {
    listen: SocketAddr,
    relay_ip: IpAddr,
    realm: String,
    username: String,
    password_file: PathBuf,
    max_allocations: usize,
    total_timeout: Duration,
    exit_after_deallocations: usize,
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
    let mut listen: Option<SocketAddr> = None;
    let mut relay_ip: Option<IpAddr> = None;
    let mut realm = None;
    let mut username = None;
    let mut password_file = None;
    let mut max_allocations = None;
    let mut total_timeout = None;
    let mut exit_after_deallocations = None;
    let mut allow_loopback_lab = false;
    let mut index = 1;
    while index < values.len() {
        let flag = values[index].as_str();
        if flag == "--allow-loopback-lab" {
            allow_loopback_lab = true;
            index += 1;
            continue;
        }
        if flag == "--help" || flag == "-h" {
            return Err(HELP.into());
        }
        let value = values
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--listen" => listen = Some(value.parse().map_err(|_| "invalid --listen")?),
            "--relay-ip" => relay_ip = Some(value.parse().map_err(|_| "invalid --relay-ip")?),
            "--realm" => realm = Some(value.clone()),
            "--username" => username = Some(value.clone()),
            "--password-file" => password_file = Some(PathBuf::from(value)),
            "--max-allocations" => {
                max_allocations = Some(value.parse().map_err(|_| "invalid allocation maximum")?)
            }
            "--total-timeout" => {
                total_timeout = Some(value.parse::<u64>().map_err(|_| "invalid timeout")?)
            }
            "--exit-after-deallocations" => {
                exit_after_deallocations =
                    Some(value.parse().map_err(|_| "invalid deallocation target")?)
            }
            _ => return Err(format!("unknown option {flag}")),
        }
        index += 2;
    }
    let listen = listen.ok_or("--listen is required")?;
    let relay_ip = relay_ip.ok_or("--relay-ip is required")?;
    let max_allocations = max_allocations.ok_or("--max-allocations is required")?;
    let timeout = total_timeout.ok_or("--total-timeout is required")?;
    let exit_after_deallocations =
        exit_after_deallocations.ok_or("--exit-after-deallocations is required")?;
    if !usable(listen.ip())
        || listen.port() == 0
        || !usable(relay_ip)
        || listen.is_ipv4() != relay_ip.is_ipv4()
        || !listen.ip().is_loopback()
        || !relay_ip.is_loopback()
        || !allow_loopback_lab
        || !(1..=256).contains(&max_allocations)
        || !(1..=3_600).contains(&timeout)
        || exit_after_deallocations > max_allocations
    {
        return Err("TURN address or bound policy failed".into());
    }
    Ok(Args {
        listen,
        relay_ip,
        realm: realm.ok_or("--realm is required")?,
        username: username.ok_or("--username is required")?,
        password_file: password_file.ok_or("--password-file is required")?,
        max_allocations,
        total_timeout: Duration::from_secs(timeout),
        exit_after_deallocations,
        allow_loopback_lab,
    })
}

fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast()
}

fn load_password(path: &Path) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() < 16 || metadata.len() > 512 {
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

async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let password = load_password(&args.password_file)?;
    let config = ServerConfig::new(
        args.relay_ip,
        args.realm.into_bytes(),
        args.username.into_bytes(),
        password.to_vec(),
        args.max_allocations,
        args.total_timeout,
        args.allow_loopback_lab,
        args.exit_after_deallocations,
    )?;
    let control = UdpSocket::bind(args.listen).await?;
    println!("turn-relayd: listening={}", control.local_addr()?);
    let report = serve(control, config).await?;
    println!(
        "turn-relayd: allocations={} deallocations={} rejected={} client_to_peer={} peer_to_client={} clean_shutdown={} opaque_payload=true tcp_relay=false desktop_payload=false",
        report.allocations_created,
        report.deallocations,
        report.rejected,
        report.client_to_peer_datagrams,
        report.peer_to_client_datagrams,
        report.clean_shutdown,
    );
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    if env::args().nth(1).as_deref() == Some("--version") {
        println!("latencydesk-turn-relayd {}", env!("CARGO_PKG_VERSION"));
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
        eprintln!("turn-relayd failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Vec<&'static str> {
        vec![
            "turn-relayd",
            "--listen",
            "127.0.0.1:3478",
            "--relay-ip",
            "127.0.0.1",
            "--realm",
            "turn.example",
            "--username",
            "alice",
            "--password-file",
            "turn.secret",
            "--max-allocations",
            "4",
            "--total-timeout",
            "30",
            "--exit-after-deallocations",
            "1",
            "--allow-loopback-lab",
        ]
    }

    #[test]
    fn parser_requires_explicit_bounded_loopback_lab() {
        let parsed = parse_from(valid()).unwrap();
        assert_eq!(parsed.max_allocations, 4);
        let without_opt_in = valid()
            .into_iter()
            .filter(|value| *value != "--allow-loopback-lab")
            .collect::<Vec<_>>();
        assert!(parse_from(without_opt_in).is_err());
    }

    #[test]
    fn parser_never_accepts_password_on_command_line() {
        let mut values = valid();
        values.extend(["--password", "do-not-allow"]);
        assert!(parse_from(values).is_err());
    }
}
