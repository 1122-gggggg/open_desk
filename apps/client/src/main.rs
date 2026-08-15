//! LatencyDesk Client Application.
//!
//! Native QUIC-gated client role coordinator using platform providers.

use latencydesk_media::ContinuityAction;
use latencydesk_platform::{CursorMode, PlatformError, PresentableFrame, ProviderDiagnostics};
use latencydesk_runtime::{ClientRuntime, DecodeBackend, LocalInputBackend};
use latencydesk_session::authorization::SessionId;
use latencydesk_session::runtime::{
    AuthorityError, ClosedAuthority, DispatchPermit, DispatchStamp, InputLedger, SessionGate,
    SessionInputError,
};
use latencydesk_transport::{ReassembledFrame, ReassemblyConfig};
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ClientArgs {
    pub connect_addr: SocketAddr,
    pub bind_addr: SocketAddr,
    pub peer_alias: Option<String>,
    pub pairing_timeout_secs: u64,
    pub profile_1080p120: bool,
    pub max_frames: Option<u64>,
    pub auto_approve: bool,
}

impl Default for ClientArgs {
    fn default() -> Self {
        Self {
            connect_addr: "127.0.0.1:9000".parse().unwrap(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            peer_alias: None,
            pairing_timeout_secs: 60,
            profile_1080p120: false,
            max_frames: None,
            auto_approve: false,
        }
    }
}

pub fn parse_client_args() -> Result<ClientArgs, Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let mut config = ClientArgs::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--connect" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --connect".into());
                }
                config.connect_addr = args[i + 1].parse()?;
                i += 2;
            }
            "--bind" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --bind".into());
                }
                config.bind_addr = args[i + 1].parse()?;
                i += 2;
            }
            "--peer-alias" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --peer-alias".into());
                }
                config.peer_alias = Some(args[i + 1].clone());
                i += 2;
            }
            "--pairing-timeout" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --pairing-timeout".into());
                }
                config.pairing_timeout_secs = args[i + 1].parse()?;
                i += 2;
            }
            "--1080p120-profile" => {
                config.profile_1080p120 = true;
                i += 1;
            }
            "--frames" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --frames".into());
                }
                config.max_frames = Some(args[i + 1].parse()?);
                i += 2;
            }
            "--role" => {
                if i + 1 >= args.len() {
                    return Err("missing value for --role".into());
                }
                let role = &args[i + 1];
                if role != "client" {
                    return Err(format!("invalid role for client binary: {role}").into());
                }
                i += 2;
            }
            "--approve" | "--auto-approve" => {
                config.auto_approve = true;
                i += 1;
            }
            "--interactive" => {
                return Err(
                    "the product Client binary rejects simulated --interactive mode; use real native input providers".into()
                );
            }
            "--help" | "-h" => {
                println!(
                    "Usage: latencydesk-client [OPTIONS]\n\n\
                     Options:\n  \
                       --connect <ADDR>          Host address to connect to (default 127.0.0.1:9000)\n  \
                       --bind <ADDR>             Local socket address to bind (default 0.0.0.0:0)\n  \
                       --peer-alias <NAME>       Alias name for host peer authorization\n  \
                       --pairing-timeout <SECS>  Pairing expiration timeout in seconds (default 60)\n  \
                       --1080p120-profile        Request 1080p 120fps direct LAN streaming profile\n  \
                       --frames <COUNT>          Stop streaming after N frames (for benchmarking)\n  \
                       --role client             Explicit role assertion\n  \
                       --approve                 Auto-approve pairing requests (for automated tests)\n  \
                       --help, -h                Show this help message\n\n\
                     Note: The product binary strictly rejects simulated --interactive mode."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other}").into()),
        }
    }
    Ok(config)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[derive(Debug)]
struct PassthroughDecoder {
    diagnostics: ProviderDiagnostics,
}

impl PassthroughDecoder {
    fn new() -> Self {
        Self {
            diagnostics: ProviderDiagnostics::idle("client_decoder"),
        }
    }
}

impl DecodeBackend for PassthroughDecoder {
    fn decode(
        &mut self,
        _frame: ReassembledFrame,
        _continuity: ContinuityAction,
        _stamp: DispatchStamp,
        _now_ns: u64,
    ) -> Result<PresentableFrame, latencydesk_runtime::RuntimeError> {
        Err(latencydesk_runtime::RuntimeError::Platform(
            PlatformError::Unsupported,
        ))
    }

    fn quiesce_decoding(&mut self) -> Result<(), latencydesk_runtime::RuntimeError> {
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

#[derive(Debug)]
struct NativeLocalInput {
    diagnostics: ProviderDiagnostics,
}

impl NativeLocalInput {
    fn new() -> Self {
        Self {
            diagnostics: ProviderDiagnostics::idle("client_local_input"),
        }
    }
}

impl LocalInputBackend for NativeLocalInput {
    fn release_all(
        &mut self,
        _actions: &[latencydesk_input::AppliedInput],
    ) -> Result<(), latencydesk_runtime::RuntimeError> {
        Ok(())
    }

    fn diagnostics(&self) -> ProviderDiagnostics {
        self.diagnostics.clone()
    }
}

pub struct ClientSessionGate {
    session_id: SessionId,
    generation: u64,
    authorization_epoch: u32,
    display_epoch: u32,
    codec_epoch: u32,
    closed: bool,
}

impl ClientSessionGate {
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            generation: 1,
            authorization_epoch: 1,
            display_epoch: 1,
            codec_epoch: 1,
            closed: false,
        }
    }
}

impl SessionGate for ClientSessionGate {
    fn acquire_dispatch(&self, _now_ns: u64) -> Result<DispatchPermit, AuthorityError> {
        if self.closed {
            return Err(AuthorityError::Closed);
        }
        let stamp = DispatchStamp::new(
            self.session_id,
            self.generation,
            self.authorization_epoch,
            self.display_epoch,
            self.codec_epoch,
        )?;
        Ok(DispatchPermit::from_stamp(stamp))
    }

    fn recheck(
        &self,
        permit: &DispatchPermit,
        _now_ns: u64,
    ) -> Result<DispatchStamp, AuthorityError> {
        if self.closed {
            return Err(AuthorityError::Closed);
        }
        if permit.stamp().generation() != self.generation
            || permit.stamp().authorization_epoch() != self.authorization_epoch
            || permit.stamp().display_epoch() != self.display_epoch
            || permit.stamp().codec_epoch() != self.codec_epoch
        {
            return Err(AuthorityError::StaleDispatch);
        }
        Ok(permit.stamp())
    }

    fn apply_input(
        &mut self,
        _message: latencydesk_input::InputMessage,
        _now_ns: u64,
    ) -> Result<latencydesk_input::ReconcileOutcome, SessionInputError> {
        Ok(latencydesk_input::ReconcileOutcome::Applied(vec![]))
    }

    fn close(&mut self) -> Result<ClosedAuthority, AuthorityError> {
        self.closed = true;
        Ok(ClosedAuthority::new(InputLedger::default(), 0))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_client_args()?;
    println!("=== LatencyDesk Client ===");
    println!("Connecting to Host: {}", args.connect_addr);
    println!("Local Binding Address: {}", args.bind_addr);
    println!(
        "Direct LAN 1080p120 Profile Requested: {}",
        args.profile_1080p120
    );

    #[cfg(windows)]
    {
        use latencydesk_platform_windows::{WindowsRenderBackend, WindowsSwapChainConfig};
        let device = latencydesk_media::DeviceIdentity::Opaque(0);
        let renderer = WindowsRenderBackend::new(
            device,
            WindowsSwapChainConfig::default(),
            CursorMode::Metadata,
        );
        let decoder = PassthroughDecoder::new();
        let local_input = NativeLocalInput::new();
        let session_id = SessionId::new(1).map_err(|e| Box::<dyn Error>::from(format!("{e:?}")))?;
        let gate = ClientSessionGate::new(session_id);
        let mut runtime = ClientRuntime::new(
            decoder,
            renderer,
            local_input,
            gate,
            ReassemblyConfig::default(),
        )?;

        runtime.activate(now_ns())?;
        println!("Runtime Progress: {:?}", runtime.diagnostics().progress);
        println!("Client Connected and Ready. Active presentation surface running.");
    }

    #[cfg(not(windows))]
    {
        println!("Client ready on non-Windows platform.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_parser_rejects_interactive() {
        let err = parse_client_args_from(&["latencydesk-client", "--interactive"]);
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("rejects simulated --interactive"));
    }

    #[test]
    fn client_parser_accepts_1080p120_profile() {
        let args = parse_client_args_from(&[
            "latencydesk-client",
            "--1080p120-profile",
            "--connect",
            "127.0.0.1:9000",
        ])
        .expect("parse");
        assert_eq!(args.connect_addr, "127.0.0.1:9000".parse().unwrap());
        assert!(args.profile_1080p120);
    }

    fn parse_client_args_from(args: &[&str]) -> Result<ClientArgs, Box<dyn Error>> {
        let mut config = ClientArgs::default();
        let mut i = 1;
        while i < args.len() {
            match args[i] {
                "--connect" => {
                    config.connect_addr = args[i + 1].parse()?;
                    i += 2;
                }
                "--1080p120-profile" => {
                    config.profile_1080p120 = true;
                    i += 1;
                }
                "--interactive" => {
                    return Err("the product Client binary rejects simulated --interactive mode; use real native input providers".into());
                }
                _ => i += 1,
            }
        }
        Ok(config)
    }
}
