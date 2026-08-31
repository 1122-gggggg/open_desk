use latencydesk_rendezvousd::serve_one_match;
use latencydesk_socket_transport::identity::{
    load_certificate_der, mtls_server_config_for_exact_clients, TlsIdentity,
};
use latencydesk_socket_transport::quic::bind_server;
use std::env;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

const HELP: &str = "Usage: latencydesk-rendezvousd \
--listen <UNICAST_ADDR> \
--identity-cert <DER> --identity-key <PKCS8_DER> \
--allowed-client-cert <DER> --allowed-client-cert <DER> \
--total-timeout <1..=3600> --max-registrations 2";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    listen: SocketAddr,
    certificate: PathBuf,
    private_key: PathBuf,
    allowed_clients: Vec<PathBuf>,
    total_timeout: Duration,
    max_registrations: usize,
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
    let mut listen = None;
    let mut certificate = None;
    let mut private_key = None;
    let mut allowed_clients = Vec::new();
    let mut timeout_seconds = None;
    let mut max_registrations = None;
    let mut index = 1;
    while index < values.len() {
        let flag = values[index].as_str();
        if flag == "--help" || flag == "-h" {
            return Err(HELP.to_owned());
        }
        let value = values
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--listen" => {
                listen = Some(value.parse().map_err(|_| "invalid --listen")?);
            }
            "--identity-cert" => certificate = Some(PathBuf::from(value)),
            "--identity-key" => private_key = Some(PathBuf::from(value)),
            "--allowed-client-cert" => allowed_clients.push(PathBuf::from(value)),
            "--total-timeout" => {
                timeout_seconds = Some(value.parse::<u64>().map_err(|_| "invalid timeout")?);
            }
            "--max-registrations" => {
                max_registrations = Some(value.parse::<usize>().map_err(|_| "invalid maximum")?);
            }
            other => return Err(format!("unknown option {other}")),
        }
        index += 2;
    }
    let listen = listen.ok_or("--listen is required")?;
    if !usable_unicast(listen) {
        return Err("--listen must be a nonzero unicast address".into());
    }
    let certificate = certificate.ok_or("--identity-cert is required")?;
    let private_key = private_key.ok_or("--identity-key is required")?;
    if allowed_clients.len() != 2 || allowed_clients[0] == allowed_clients[1] {
        return Err("exactly two distinct --allowed-client-cert paths are required".into());
    }
    let timeout_seconds = timeout_seconds.ok_or("--total-timeout is required")?;
    if !(1..=3_600).contains(&timeout_seconds) {
        return Err("--total-timeout must be in 1..=3600".into());
    }
    let max_registrations = max_registrations.ok_or("--max-registrations is required")?;
    if max_registrations != 2 {
        return Err("this bounded service requires --max-registrations 2".into());
    }
    Ok(Args {
        listen,
        certificate,
        private_key,
        allowed_clients,
        total_timeout: Duration::from_secs(timeout_seconds),
        max_registrations,
    })
}

fn usable_unicast(address: SocketAddr) -> bool {
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return false;
    }
    !matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
}

fn remaining_before(deadline: tokio::time::Instant) -> Result<Duration, &'static str> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err("rendezvous total lifecycle deadline elapsed");
    }
    Ok(remaining)
}

async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    debug_assert_eq!(args.max_registrations, 2);
    let identity = TlsIdentity::load_der(&args.certificate, &args.private_key)?;
    let allowed = args
        .allowed_clients
        .iter()
        .map(load_certificate_der)
        .collect::<Result<Vec<_>, _>>()?;
    let configuration = mtls_server_config_for_exact_clients(&identity, &allowed)?;
    let endpoint = bind_server(configuration, args.listen)?;
    println!("rendezvous: listening={}", endpoint.local_addr()?);
    let deadline = tokio::time::Instant::now() + args.total_timeout;
    let service_budget = remaining_before(deadline)?;
    let result = tokio::time::timeout(
        service_budget,
        serve_one_match(&endpoint, &allowed, service_budget),
    )
    .await
    .map_err(|_| "rendezvous total lifecycle deadline elapsed");
    endpoint.close(0_u32.into(), b"rendezvous service complete");
    let cleanup_budget = remaining_before(deadline)?;
    tokio::time::timeout(cleanup_budget, endpoint.wait_idle())
        .await
        .map_err(|_| "rendezvous total lifecycle deadline elapsed")?;
    let report = result??;
    println!(
        "rendezvous: registrations={} matched={} rejected={} desktop_payload=false relay=false",
        report.registrations, report.matched, report.rejected
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
        eprintln!("rendezvous failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args() -> Vec<&'static str> {
        vec![
            "latencydesk-rendezvousd",
            "--listen",
            "127.0.0.1:9443",
            "--identity-cert",
            "server.der",
            "--identity-key",
            "server.key.der",
            "--allowed-client-cert",
            "a.der",
            "--allowed-client-cert",
            "b.der",
            "--total-timeout",
            "30",
            "--max-registrations",
            "2",
        ]
    }

    #[test]
    fn parser_requires_explicit_bounded_mtls_configuration() {
        let parsed = parse_from(valid_args()).unwrap();
        assert_eq!(parsed.listen, "127.0.0.1:9443".parse().unwrap());
        assert_eq!(parsed.allowed_clients.len(), 2);
        assert_eq!(parsed.total_timeout, Duration::from_secs(30));
        assert_eq!(parsed.max_registrations, 2);
    }

    #[test]
    fn parser_rejects_unspecified_duplicate_and_unbounded_inputs() {
        for (needle, replacement) in [
            ("127.0.0.1:9443", "0.0.0.0:9443"),
            ("127.0.0.1:9443", "127.0.0.1:0"),
            ("30", "0"),
            ("2", "3"),
        ] {
            let args = valid_args()
                .into_iter()
                .map(|value| if value == needle { replacement } else { value })
                .collect::<Vec<_>>();
            assert!(parse_from(args).is_err());
        }
        let mut duplicate = valid_args();
        let last = duplicate
            .iter()
            .rposition(|value| *value == "b.der")
            .unwrap();
        duplicate[last] = "a.der";
        assert!(parse_from(duplicate).is_err());
    }

    #[test]
    fn parser_names_the_successful_registration_cap_precisely() {
        let ambiguous = valid_args()
            .into_iter()
            .map(|value| {
                if value == "--max-registrations" {
                    "--max-connections"
                } else {
                    value
                }
            })
            .collect::<Vec<_>>();
        assert!(parse_from(valid_args()).is_ok());
        assert!(parse_from(ambiguous).is_err());
    }

    #[test]
    fn lifecycle_budget_rejects_an_expired_absolute_deadline() {
        assert!(remaining_before(tokio::time::Instant::now()).is_err());
    }
}
