use latencydesk_socket_transport::identity::{
    certificate_fingerprint, load_certificate_der, IdentityError, TlsIdentity,
};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const CERTIFICATE_FILE_NAME: &str = "identity.cert.der";
const PRIVATE_KEY_FILE_NAME: &str = "identity.key.der";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Generate { name: String, out_dir: PathBuf },
    Fingerprint { certificate: PathBuf },
    Help,
    Version,
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Identity(IdentityError),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::Usage(_) => None,
        }
    }
}

impl From<IdentityError> for CliError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

#[derive(Debug)]
struct GeneratedIdentity {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    fingerprint: String,
}

fn main() {
    if let Err(error) = run(env::args_os().skip(1)) {
        eprintln!("error: {error}\n\nRun `latencydesk-identity --help` for usage.");
        std::process::exit(2);
    }
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), CliError> {
    match parse_arguments(arguments)? {
        Command::Generate { name, out_dir } => {
            let generated = generate_identity(&name, &out_dir)?;
            println!("Identity created successfully.");
            println!(
                "Certificate (share this file): {}",
                generated.certificate_path.display()
            );
            println!(
                "Private key (KEEP SECRET): {}",
                generated.private_key_path.display()
            );
            println!("SHA-256 fingerprint: {}", generated.fingerprint);
            println!();
            println!(
                "IMPORTANT: Exchange only {CERTIFICATE_FILE_NAME}. Never share {PRIVATE_KEY_FILE_NAME}."
            );
        }
        Command::Fingerprint { certificate } => {
            let certificate_der = load_certificate_der(&certificate)?;
            println!(
                "SHA-256 fingerprint: {}",
                lowercase_hex(&certificate_fingerprint(&certificate_der))
            );
        }
        Command::Help => print_help(),
        Command::Version => println!("latencydesk-identity {}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, CliError> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or_else(|| {
        CliError::Usage("missing command; expected `generate` or `fingerprint`".to_owned())
    })?;
    let command = command.to_str().ok_or_else(|| {
        CliError::Usage(
            "command name is not valid Unicode; use `generate` or `fingerprint`".to_owned(),
        )
    })?;

    match command {
        "--help" | "-h" => require_no_extra_arguments(arguments, Command::Help),
        "--version" | "-V" => require_no_extra_arguments(arguments, Command::Version),
        "generate" => parse_generate(arguments),
        "fingerprint" => parse_fingerprint(arguments),
        other => Err(CliError::Usage(format!(
            "unknown command `{other}`; expected `generate` or `fingerprint`"
        ))),
    }
}

fn require_no_extra_arguments(
    mut arguments: impl Iterator<Item = OsString>,
    command: Command,
) -> Result<Command, CliError> {
    if let Some(extra) = arguments.next() {
        return Err(CliError::Usage(format!(
            "unexpected argument `{}`",
            extra.to_string_lossy()
        )));
    }
    Ok(command)
}

fn parse_generate(mut arguments: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let mut name = None;
    let mut out_dir = None;

    while let Some(option) = arguments.next() {
        let option_text = option.to_str().ok_or_else(|| {
            CliError::Usage("generate option name is not valid Unicode".to_owned())
        })?;
        match option_text {
            "--name" => {
                reject_duplicate(&name, "--name")?;
                let value = take_value(&mut arguments, "--name")?;
                name = Some(value.into_string().map_err(|_| {
                    CliError::Usage("value for --name must be valid Unicode".to_owned())
                })?);
            }
            "--out-dir" => {
                reject_duplicate(&out_dir, "--out-dir")?;
                out_dir = Some(PathBuf::from(take_value(&mut arguments, "--out-dir")?));
            }
            "--help" | "-h" => return Ok(Command::Help),
            other => {
                return Err(CliError::Usage(format!(
                    "unknown generate option `{other}`; expected --name and --out-dir"
                )));
            }
        }
    }

    let name =
        name.ok_or_else(|| CliError::Usage("generate requires --name <DEVICE_NAME>".to_owned()))?;
    let out_dir =
        out_dir.ok_or_else(|| CliError::Usage("generate requires --out-dir <DIR>".to_owned()))?;
    Ok(Command::Generate { name, out_dir })
}

fn parse_fingerprint(mut arguments: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let mut certificate = None;

    while let Some(option) = arguments.next() {
        let option_text = option.to_str().ok_or_else(|| {
            CliError::Usage("fingerprint option name is not valid Unicode".to_owned())
        })?;
        match option_text {
            "--cert" => {
                reject_duplicate(&certificate, "--cert")?;
                certificate = Some(PathBuf::from(take_value(&mut arguments, "--cert")?));
            }
            "--help" | "-h" => return Ok(Command::Help),
            other => {
                return Err(CliError::Usage(format!(
                    "unknown fingerprint option `{other}`; expected --cert"
                )));
            }
        }
    }

    let certificate = certificate
        .ok_or_else(|| CliError::Usage("fingerprint requires --cert <PATH>".to_owned()))?;
    Ok(Command::Fingerprint { certificate })
}

fn take_value(
    arguments: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> Result<OsString, CliError> {
    arguments
        .next()
        .ok_or_else(|| CliError::Usage(format!("missing value for {option}")))
}

fn reject_duplicate<T>(value: &Option<T>, option: &str) -> Result<(), CliError> {
    if value.is_some() {
        return Err(CliError::Usage(format!(
            "{option} was provided more than once"
        )));
    }
    Ok(())
}

fn generate_identity(name: &str, out_dir: &Path) -> Result<GeneratedIdentity, CliError> {
    let identity = TlsIdentity::generate(name)?;
    create_output_directory(out_dir)?;

    let certificate_path = out_dir.join(CERTIFICATE_FILE_NAME);
    let private_key_path = out_dir.join(PRIVATE_KEY_FILE_NAME);
    identity.write_der(&certificate_path, &private_key_path)?;

    let certificate_path = canonicalize(&certificate_path)?;
    let private_key_path = canonicalize(&private_key_path)?;
    let fingerprint = lowercase_hex(&certificate_fingerprint(identity.certificate_der()));

    Ok(GeneratedIdentity {
        certificate_path,
        private_key_path,
        fingerprint,
    })
}

fn create_output_directory(path: &Path) -> Result<(), CliError> {
    let existed = path.exists();
    fs::create_dir_all(path).map_err(|source| CliError::Io {
        operation: "create output directory",
        path: path.to_owned(),
        source,
    })?;

    let metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        operation: "inspect output directory",
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CliError::Usage(format!(
            "output directory {} must not be a symbolic link",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(CliError::Usage(format!(
            "output path {} is not a directory",
            path.display()
        )));
    }

    if !existed {
        restrict_new_directory_permissions(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_new_directory_permissions(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| CliError::Io {
        operation: "restrict output directory permissions",
        path: path.to_owned(),
        source,
    })
}

#[cfg(not(unix))]
fn restrict_new_directory_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

fn canonicalize(path: &Path) -> Result<PathBuf, CliError> {
    fs::canonicalize(path).map_err(|source| CliError::Io {
        operation: "resolve absolute path for",
        path: path.to_owned(),
        source,
    })
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn print_help() {
    println!(
        "latencydesk-identity {version}\n\
         \n\
         Create and inspect a persistent LatencyDesk device identity.\n\
         \n\
         USAGE:\n\
           latencydesk-identity generate --name <DEVICE_NAME> --out-dir <DIR>\n\
           latencydesk-identity fingerprint --cert <PATH>\n\
           latencydesk-identity --help\n\
           latencydesk-identity --version\n\
         \n\
         SECURITY:\n\
           Exchange only {CERTIFICATE_FILE_NAME}. Never share {PRIVATE_KEY_FILE_NAME}.\n\
           Existing identity files are never overwritten.",
        version = env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMPORARY_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn parser_rejects_missing_and_unknown_arguments() {
        let missing = parse_arguments(Vec::<OsString>::new()).expect_err("missing command");
        assert!(missing.to_string().contains("missing command"));

        let missing_generate_options =
            parse_arguments(os_strings(["generate"])).expect_err("missing options");
        assert!(missing_generate_options
            .to_string()
            .contains("requires --name"));

        let unknown =
            parse_arguments(os_strings(["generate", "--unknown"])).expect_err("unknown option");
        assert!(unknown.to_string().contains("unknown generate option"));

        let missing_value =
            parse_arguments(os_strings(["fingerprint", "--cert"])).expect_err("missing value");
        assert!(missing_value
            .to_string()
            .contains("missing value for --cert"));
    }

    #[test]
    fn generate_uses_fixed_names_and_refuses_overwrite() {
        let directory = unique_temporary_directory();
        let first = generate_identity("test-device", &directory).expect("generate identity");
        assert_eq!(
            first.certificate_path.file_name(),
            Some(std::ffi::OsStr::new(CERTIFICATE_FILE_NAME))
        );
        assert_eq!(
            first.private_key_path.file_name(),
            Some(std::ffi::OsStr::new(PRIVATE_KEY_FILE_NAME))
        );
        assert_eq!(first.fingerprint.len(), 64);

        let fingerprint_before =
            TlsIdentity::load_der(&first.certificate_path, &first.private_key_path)
                .expect("load original identity")
                .fingerprint();

        let second = generate_identity("replacement-device", &directory);
        assert!(second.is_err(), "existing identity must not be overwritten");
        let fingerprint_after =
            TlsIdentity::load_der(&first.certificate_path, &first.private_key_path)
                .expect("reload identity after retry")
                .fingerprint();
        assert_eq!(fingerprint_after, fingerprint_before);

        fs::remove_dir_all(&directory).expect("remove owned temporary directory");
    }

    fn os_strings<const N: usize>(values: [&str; N]) -> Vec<OsString> {
        values.into_iter().map(OsString::from).collect()
    }

    fn unique_temporary_directory() -> PathBuf {
        let sequence = NEXT_TEMPORARY_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "latencydesk-identity-test-{}-{sequence}",
            std::process::id()
        ))
    }
}
