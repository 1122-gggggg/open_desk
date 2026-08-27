//! Persistent TLS identities and mutually authenticated QUIC configuration.
//!
//! Each generated identity is a self-signed end-entity certificate. TLS configs
//! start from an empty trust store containing one caller-supplied certificate,
//! and the connection wrappers independently require exact peer-leaf equality.

use crate::quic::{QuicConnection, QuicTransportError};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// DNS subject alternative name present in every generated identity.
pub const TLS_SERVER_NAME: &str = "latencydesk.local";
/// ALPN identifier used by the LatencyDesk QUIC protocol.
pub const TLS_ALPN_PROTOCOL: &[u8] = b"latencydesk/1";
/// Maximum number of Unicode scalar values accepted in a certificate display name.
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
/// Maximum DER certificate size accepted from disk or callers.
pub const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
/// Maximum PKCS#8 private-key size accepted from disk or callers.
pub const MAX_PRIVATE_KEY_DER_BYTES: usize = 64 * 1024;

/// Maximum simultaneously open incoming bidirectional QUIC streams.
pub const MAX_QUIC_BIDIRECTIONAL_STREAMS: u32 = 8;
/// Maximum simultaneously open incoming unidirectional QUIC streams.
pub const MAX_QUIC_UNIDIRECTIONAL_STREAMS: u32 = 8;
/// Per-stream receive flow-control window.
pub const QUIC_STREAM_RECEIVE_WINDOW_BYTES: u32 = 2 * 1024 * 1024;
/// Aggregate receive flow-control window.
pub const QUIC_RECEIVE_WINDOW_BYTES: u32 = 8 * 1024 * 1024;
/// Aggregate unacknowledged send-data limit.
pub const QUIC_SEND_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum queued incoming QUIC DATAGRAM bytes.
pub const QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES: usize = 2 * 1024 * 1024;
/// Maximum queued outgoing QUIC DATAGRAM bytes.
pub const QUIC_DATAGRAM_SEND_BUFFER_BYTES: usize = 2 * 1024 * 1024;

const QUIC_CRYPTO_BUFFER_BYTES: usize = 64 * 1024;
const QUIC_IDLE_TIMEOUT_MILLIS: u32 = 30_000;
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const QUIC_INITIAL_RTT: Duration = Duration::from_millis(5);
const QUIC_MAX_ACK_DELAY: Duration = Duration::from_millis(1);
const QUIC_MINIMUM_MTU: u16 = 1_200;
const QUIC_MAXIMUM_MTU: u16 = 1_452;
const PEER_IDENTITY_ERROR_CODE: u32 = 0x101;
const PEER_IDENTITY_ERROR_REASON: &[u8] = b"peer certificate mismatch";

/// Why a requested certificate display name was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayNameError {
    /// The name was empty.
    Empty,
    /// Leading or trailing whitespace was present.
    SurroundingWhitespace,
    /// The name exceeded [`MAX_DISPLAY_NAME_CHARS`].
    TooLong {
        /// Number of Unicode scalar values supplied by the caller.
        actual: usize,
    },
    /// A character outside the conservative device-name alphabet was present.
    InvalidCharacter {
        /// Zero-based Unicode scalar index of the invalid character.
        index: usize,
    },
}

impl fmt::Display for DisplayNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("display name is empty"),
            Self::SurroundingWhitespace => {
                formatter.write_str("display name has leading or trailing whitespace")
            }
            Self::TooLong { actual } => write!(
                formatter,
                "display name has {actual} characters; maximum is {MAX_DISPLAY_NAME_CHARS}"
            ),
            Self::InvalidCharacter { index } => {
                write!(
                    formatter,
                    "display name has an invalid character at index {index}"
                )
            }
        }
    }
}

/// Failures while creating, loading, persisting, or configuring an identity.
#[derive(Debug)]
pub enum IdentityError {
    /// The human-readable device name did not meet the certificate policy.
    InvalidDisplayName(DisplayNameError),
    /// rcgen could not create the key pair or certificate.
    Generation(rcgen::Error),
    /// The local certificate/private-key pair was malformed or mismatched.
    InvalidIdentity(rustls::Error),
    /// The exact peer certificate could not be used as a trust anchor.
    InvalidPeerCertificate(rustls::Error),
    /// rustls could not construct a mandatory client-certificate verifier.
    ClientVerifier(rustls::server::VerifierBuilderError),
    /// The selected rustls provider was not usable by QUIC.
    QuicCrypto(quinn::crypto::rustls::NoInitialCipherSuite),
    /// QUIC did not complete a fully authenticated connection.
    QuicTransport(QuicTransportError),
    /// The verified certificate chain did not contain a leaf certificate.
    MissingPeerCertificate,
    /// The authenticated leaf did not exactly equal the expected DER certificate.
    PeerCertificateMismatch,
    /// An identity file exceeded its fixed input limit.
    FileTooLarge {
        /// Non-secret description of the file's role.
        kind: &'static str,
        /// Path supplied by the caller.
        path: PathBuf,
        /// Maximum accepted size.
        max_bytes: usize,
    },
    /// Certificate and key paths referred to the same path.
    IdentityPathsMustDiffer,
    /// A private-key file is accessible by Unix group or other users.
    #[cfg(unix)]
    InsecurePrivateKeyPermissions {
        /// Path supplied by the caller.
        path: PathBuf,
        /// Permission bits observed on disk.
        mode: u32,
    },
    /// Windows DACL grants Everyone, Users, or Authenticated Users access.
    #[cfg(windows)]
    InsecureWindowsPrivateKeyAcl {
        /// Path supplied by the caller.
        path: PathBuf,
    },
    /// `icacls` could not inspect or restrict a private-key ACL.
    #[cfg(windows)]
    WindowsAclCommandFailed {
        /// Operation being attempted.
        operation: &'static str,
        /// Path supplied by the caller.
        path: PathBuf,
        /// `icacls` exit status or spawn failure, without file contents.
        details: String,
    },
    /// Filesystem work failed. No file contents are included in this error.
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Path supplied by the caller.
        path: PathBuf,
        /// Operating-system error.
        source: io::Error,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDisplayName(error) => write!(formatter, "invalid display name: {error}"),
            Self::Generation(error) => write!(formatter, "TLS identity generation failed: {error}"),
            Self::InvalidIdentity(error) => write!(formatter, "invalid TLS identity: {error}"),
            Self::InvalidPeerCertificate(error) => {
                write!(formatter, "invalid exact peer certificate: {error}")
            }
            Self::ClientVerifier(error) => {
                write!(
                    formatter,
                    "client-certificate verifier setup failed: {error}"
                )
            }
            Self::QuicCrypto(error) => write!(formatter, "QUIC TLS setup failed: {error}"),
            Self::QuicTransport(error) => {
                write!(formatter, "QUIC authentication failed: {error}")
            }
            Self::MissingPeerCertificate => {
                formatter.write_str("authenticated peer certificate chain was empty")
            }
            Self::PeerCertificateMismatch => {
                formatter.write_str("authenticated peer leaf did not match the exact certificate")
            }
            Self::FileTooLarge {
                kind,
                path,
                max_bytes,
            } => write!(
                formatter,
                "{kind} at {} exceeds the {max_bytes}-byte limit",
                path.display()
            ),
            Self::IdentityPathsMustDiffer => {
                formatter.write_str("certificate and private-key paths must differ")
            }
            #[cfg(unix)]
            Self::InsecurePrivateKeyPermissions { path, mode } => write!(
                formatter,
                "private key at {} has insecure mode {mode:04o}; expected no group/other permissions (0600 recommended)",
                path.display()
            ),
            #[cfg(windows)]
            Self::InsecureWindowsPrivateKeyAcl { path } => write!(
                formatter,
                "private key at {} has an insecure Windows ACL; Everyone, Users, and Authenticated Users must not have access",
                path.display()
            ),
            #[cfg(windows)]
            Self::WindowsAclCommandFailed {
                operation,
                path,
                details,
            } => write!(
                formatter,
                "failed to {operation} {}: {details}",
                path.display()
            ),
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

impl Error for IdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Generation(error) => Some(error),
            Self::InvalidIdentity(error) | Self::InvalidPeerCertificate(error) => Some(error),
            Self::ClientVerifier(error) => Some(error),
            Self::QuicCrypto(error) => Some(error),
            Self::QuicTransport(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::InvalidDisplayName(_)
            | Self::FileTooLarge { .. }
            | Self::IdentityPathsMustDiffer
            | Self::MissingPeerCertificate
            | Self::PeerCertificateMismatch => None,
            #[cfg(unix)]
            Self::InsecurePrivateKeyPermissions { .. } => None,
            #[cfg(windows)]
            Self::InsecureWindowsPrivateKeyAcl { .. } | Self::WindowsAclCommandFailed { .. } => {
                None
            }
        }
    }
}

/// A validated X.509 certificate and matching PKCS#8 private key.
pub struct TlsIdentity {
    certificate: CertificateDer<'static>,
    private_key: PrivatePkcs8KeyDer<'static>,
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsIdentity")
            .field("certificate_bytes", &self.certificate.as_ref().len())
            .field("fingerprint", &self.fingerprint())
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl TlsIdentity {
    /// Generates an ECDSA self-signed identity with a fixed
    /// `latencydesk.local` DNS SAN and the validated display name as its CN.
    pub fn generate(display_name: &str) -> Result<Self, IdentityError> {
        validate_display_name(display_name).map_err(IdentityError::InvalidDisplayName)?;

        let key_pair = KeyPair::generate().map_err(IdentityError::Generation)?;
        let mut parameters = CertificateParams::new(vec![TLS_SERVER_NAME.to_owned()])
            .map_err(IdentityError::Generation)?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, display_name.to_owned());
        parameters.distinguished_name = distinguished_name;
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = parameters
            .self_signed(&key_pair)
            .map_err(IdentityError::Generation)?;

        Self::from_der(
            certificate.der().as_ref().to_vec(),
            key_pair.serialize_der(),
        )
    }

    /// Validates and owns one DER certificate and one DER PKCS#8 private key.
    pub fn from_der(
        certificate_der: Vec<u8>,
        private_key_pkcs8_der: Vec<u8>,
    ) -> Result<Self, IdentityError> {
        check_size(
            "certificate",
            None,
            certificate_der.len(),
            MAX_CERTIFICATE_DER_BYTES,
        )?;
        check_size(
            "private key",
            None,
            private_key_pkcs8_der.len(),
            MAX_PRIVATE_KEY_DER_BYTES,
        )?;

        let certificate = CertificateDer::from(certificate_der);
        let private_key = PrivatePkcs8KeyDer::from(private_key_pkcs8_der);
        validate_identity_pair(&certificate, &private_key)?;

        Ok(Self {
            certificate,
            private_key,
        })
    }

    /// Loads and validates raw DER certificate and PKCS#8 key files.
    pub fn load_der(
        certificate_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
    ) -> Result<Self, IdentityError> {
        let certificate_path = certificate_path.as_ref();
        let private_key_path = private_key_path.as_ref();
        verify_private_key_permissions(private_key_path)?;
        let certificate_der =
            read_bounded(certificate_path, "certificate", MAX_CERTIFICATE_DER_BYTES)?;
        let private_key_der =
            read_bounded(private_key_path, "private key", MAX_PRIVATE_KEY_DER_BYTES)?;
        Self::from_der(certificate_der, private_key_der)
    }

    /// Persists raw DER files without overwriting either destination.
    ///
    /// The private-key file is created first with `create_new`. On Unix its
    /// permissions are set to exactly `0600` before key bytes are written. On
    /// Windows its DACL is restricted with `icacls` so only the current user
    /// can read/write; a failed restriction deletes the new file. If
    /// certificate creation fails, the newly created private-key file is
    /// removed so callers never observe a successful half-write.
    pub fn write_der(
        &self,
        certificate_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
    ) -> Result<(), IdentityError> {
        let certificate_path = certificate_path.as_ref();
        let private_key_path = private_key_path.as_ref();
        if certificate_path == private_key_path {
            return Err(IdentityError::IdentityPathsMustDiffer);
        }

        write_new_file(private_key_path, self.private_key.secret_pkcs8_der(), true)?;
        if let Err(error) = write_new_file(certificate_path, self.certificate.as_ref(), false) {
            let _ = fs::remove_file(private_key_path);
            return Err(error);
        }
        Ok(())
    }

    /// Returns the public DER-encoded end-entity certificate.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    /// Returns the SHA-256 fingerprint of the exact DER certificate bytes.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        certificate_fingerprint(self.certificate.as_ref())
    }

    fn certificate_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.certificate.clone()]
    }

    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.private_key.clone_key())
    }
}

#[cfg(unix)]
fn verify_private_key_permissions(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|source| IdentityError::Io {
        operation: "inspect private-key permissions for",
        path: path.to_owned(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::InsecurePrivateKeyPermissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

#[cfg(windows)]
fn verify_private_key_permissions(path: &Path) -> Result<(), IdentityError> {
    let listing = run_icacls(path, &[], "inspect private-key ACL for")?;
    if windows_acl_grants_world_access(&listing) {
        return Err(IdentityError::InsecureWindowsPrivateKeyAcl {
            path: path.to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_private_key_permissions(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

#[cfg(windows)]
fn restrict_windows_owner_only_acl(path: &Path) -> Result<(), IdentityError> {
    let user =
        current_windows_account().map_err(|source| IdentityError::WindowsAclCommandFailed {
            operation: "determine current Windows account for",
            path: path.to_owned(),
            details: source.to_string(),
        })?;
    let grant = format!("{user}:(R,W)");
    run_icacls(
        path,
        &["/grant:r", grant.as_str()],
        "restrict private-key ACL for",
    )?;
    run_icacls(
        path,
        &["/inheritance:r"],
        "disable private-key ACL inheritance for",
    )?;
    Ok(())
}

#[cfg(windows)]
fn current_windows_account() -> io::Result<String> {
    let output = Command::new(system32_tool("whoami.exe")).output()?;
    if output.status.success() {
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !name.is_empty() {
            return Ok(name);
        }
    }
    match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(domain), Ok(user)) if !user.is_empty() => {
            if domain.is_empty() {
                Ok(user)
            } else {
                Ok(format!("{domain}\\{user}"))
            }
        }
        (_, Ok(user)) if !user.is_empty() => Ok(user),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "current Windows account is unavailable",
        )),
    }
}

#[cfg(windows)]
fn system32_tool(name: &str) -> PathBuf {
    match std::env::var_os("SystemRoot") {
        Some(root) => PathBuf::from(root).join("System32").join(name),
        None => PathBuf::from(name),
    }
}

#[cfg(windows)]
fn run_icacls(
    path: &Path,
    extra_args: &[&str],
    operation: &'static str,
) -> Result<String, IdentityError> {
    let mut command = Command::new(system32_tool("icacls.exe"));
    command.arg(path);
    for arg in extra_args {
        command.arg(arg);
    }
    let output = command
        .output()
        .map_err(|source| IdentityError::WindowsAclCommandFailed {
            operation,
            path: path.to_owned(),
            details: source.to_string(),
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let details = if stderr.trim().is_empty() {
            format!("icacls exited with {}", output.status)
        } else {
            format!("icacls exited with {}: {}", output.status, stderr.trim())
        };
        return Err(IdentityError::WindowsAclCommandFailed {
            operation,
            path: path.to_owned(),
            details,
        });
    }
    Ok(stdout)
}

#[cfg(windows)]
fn windows_acl_grants_world_access(listing: &str) -> bool {
    let lower = listing.to_ascii_lowercase().replace('/', "\\");
    const MARKERS: [&str; 7] = [
        "everyone:(",
        "authenticated users:(",
        "builtin\\users:(",
        "nt authority\\authenticated users:(",
        "s-1-1-0:(",
        "s-1-5-11:(",
        "s-1-5-32-545:(",
    ];
    if MARKERS.iter().any(|marker| lower.contains(marker)) {
        return true;
    }
    for line in lower.lines() {
        let Some((left, _)) = line.split_once(":(") else {
            continue;
        };
        let name = left
            .rsplit('\\')
            .next()
            .unwrap_or(left)
            .trim()
            .rsplit(' ')
            .next()
            .unwrap_or("")
            .trim();
        if matches!(
            name,
            "users" | "everyone" | "s-1-1-0" | "s-1-5-11" | "s-1-5-32-545"
        ) {
            return true;
        }
    }
    false
}

/// Computes the SHA-256 fingerprint of exact DER certificate bytes.
#[must_use]
pub fn certificate_fingerprint(certificate_der: &[u8]) -> [u8; 32] {
    Sha256::digest(certificate_der).into()
}

/// Reads one peer certificate with the same fixed size bound used by identity
/// loading, and validates that rustls can use it as a trust anchor.
pub fn load_certificate_der(path: impl AsRef<Path>) -> Result<Vec<u8>, IdentityError> {
    let certificate_der =
        read_bounded(path.as_ref(), "peer certificate", MAX_CERTIFICATE_DER_BYTES)?;
    exact_root_store(&certificate_der)?;
    Ok(certificate_der)
}

/// Builds a TLS 1.3-only Quinn server config that requires the exact client
/// certificate supplied as its sole trust root.
pub fn mtls_server_config(
    identity: &TlsIdentity,
    exact_client_certificate_der: &[u8],
) -> Result<quinn::ServerConfig, IdentityError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_roots = exact_root_store(exact_client_certificate_der)?;
    let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        provider.clone(),
    )
    .build()
    .map_err(IdentityError::ClientVerifier)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(IdentityError::InvalidIdentity)?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(identity.certificate_chain(), identity.private_key())
        .map_err(IdentityError::InvalidIdentity)?;
    tls.alpn_protocols = vec![TLS_ALPN_PROTOCOL.to_vec()];
    tls.max_early_data_size = 0;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
        .map_err(IdentityError::QuicCrypto)?;
    let mut configuration = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    configuration.transport = Arc::new(bounded_transport_config());
    Ok(configuration)
}

/// Builds a TLS 1.3-only Quinn client config that presents its certificate and
/// trusts the exact server certificate supplied as its sole root.
pub fn mtls_client_config(
    identity: &TlsIdentity,
    exact_server_certificate_der: &[u8],
) -> Result<quinn::ClientConfig, IdentityError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_roots = exact_root_store(exact_server_certificate_der)?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(IdentityError::InvalidIdentity)?
        .with_root_certificates(server_roots)
        .with_client_auth_cert(identity.certificate_chain(), identity.private_key())
        .map_err(IdentityError::InvalidIdentity)?;
    tls.alpn_protocols = vec![TLS_ALPN_PROTOCOL.to_vec()];
    tls.enable_early_data = false;

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(IdentityError::QuicCrypto)?;
    let mut configuration = quinn::ClientConfig::new(Arc::new(crypto));
    configuration.transport_config(Arc::new(bounded_transport_config()));
    Ok(configuration)
}

/// Connects, completes TLS 1.3 authentication, and checks the authenticated
/// server leaf byte-for-byte before returning an application connection.
///
/// This equality gate is intentionally separate from web-PKI path validation:
/// a caller-supplied certificate that happens to be a CA could otherwise
/// authorize a different leaf signed by that CA.
pub async fn connect_exact_peer(
    endpoint: &quinn::Endpoint,
    remote: SocketAddr,
    exact_server_certificate_der: &[u8],
) -> Result<QuicConnection, IdentityError> {
    exact_root_store(exact_server_certificate_der)?;
    let connection = QuicConnection::connect(endpoint, remote, TLS_SERVER_NAME)
        .await
        .map_err(IdentityError::QuicTransport)?;
    verify_exact_peer(&connection, exact_server_certificate_der)?;
    Ok(connection)
}

/// Accepts, completes mandatory client-certificate authentication, and checks
/// the authenticated client leaf byte-for-byte before returning it to the app.
pub async fn accept_exact_peer(
    endpoint: &quinn::Endpoint,
    exact_client_certificate_der: &[u8],
) -> Result<QuicConnection, IdentityError> {
    exact_root_store(exact_client_certificate_der)?;
    let connection = QuicConnection::accept(endpoint)
        .await
        .map_err(IdentityError::QuicTransport)?;
    verify_exact_peer(&connection, exact_client_certificate_der)?;
    Ok(connection)
}

/// Accepts one incoming connection with a bounded post-Initial TLS handshake,
/// then applies the same mandatory exact-leaf check as [`accept_exact_peer`].
/// Waiting for an Initial is not charged to `handshake_timeout`; callers remain
/// responsible for a separate total listener/pairing deadline.
pub async fn accept_exact_peer_with_timeout(
    endpoint: &quinn::Endpoint,
    exact_client_certificate_der: &[u8],
    handshake_timeout: Duration,
) -> Result<QuicConnection, IdentityError> {
    exact_root_store(exact_client_certificate_der)?;
    let connection = QuicConnection::accept_with_handshake_timeout(endpoint, handshake_timeout)
        .await
        .map_err(IdentityError::QuicTransport)?;
    verify_exact_peer(&connection, exact_client_certificate_der)?;
    Ok(connection)
}

/// Returns the product QUIC transport policy with explicit flow-control,
/// stream-count, crypto, MTU, and DATAGRAM buffer limits.
#[must_use]
pub fn bounded_transport_config() -> quinn::TransportConfig {
    let mut mtu_discovery = quinn::MtuDiscoveryConfig::default();
    mtu_discovery.upper_bound(QUIC_MAXIMUM_MTU);

    let mut ack_frequency = quinn::AckFrequencyConfig::default();
    ack_frequency.max_ack_delay(Some(QUIC_MAX_ACK_DELAY));

    let mut configuration = quinn::TransportConfig::default();
    configuration
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_QUIC_BIDIRECTIONAL_STREAMS))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_QUIC_UNIDIRECTIONAL_STREAMS))
        .max_idle_timeout(Some(
            quinn::VarInt::from_u32(QUIC_IDLE_TIMEOUT_MILLIS).into(),
        ))
        .stream_receive_window(quinn::VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW_BYTES))
        .receive_window(quinn::VarInt::from_u32(QUIC_RECEIVE_WINDOW_BYTES))
        .send_window(QUIC_SEND_WINDOW_BYTES)
        .initial_mtu(QUIC_MINIMUM_MTU)
        .min_mtu(QUIC_MINIMUM_MTU)
        .mtu_discovery_config(Some(mtu_discovery))
        .keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL))
        .crypto_buffer_size(QUIC_CRYPTO_BUFFER_BYTES)
        .allow_spin(false)
        .initial_rtt(QUIC_INITIAL_RTT)
        .ack_frequency_config(Some(ack_frequency))
        .datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES))
        .datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_BYTES);
    configuration
}

fn validate_display_name(display_name: &str) -> Result<(), DisplayNameError> {
    if display_name.is_empty() {
        return Err(DisplayNameError::Empty);
    }
    if display_name.trim() != display_name {
        return Err(DisplayNameError::SurroundingWhitespace);
    }
    let character_count = display_name.chars().count();
    if character_count > MAX_DISPLAY_NAME_CHARS {
        return Err(DisplayNameError::TooLong {
            actual: character_count,
        });
    }
    if let Some((index, _)) = display_name.chars().enumerate().find(|(_, character)| {
        !(character.is_alphanumeric() || matches!(character, ' ' | '-' | '_' | '.'))
    }) {
        return Err(DisplayNameError::InvalidCharacter { index });
    }
    Ok(())
}

fn validate_identity_pair(
    certificate: &CertificateDer<'static>,
    private_key: &PrivatePkcs8KeyDer<'static>,
) -> Result<(), IdentityError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(IdentityError::InvalidIdentity)?
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivateKeyDer::Pkcs8(private_key.clone_key()),
        )
        .map_err(IdentityError::InvalidIdentity)?;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificate.clone())
        .map_err(IdentityError::InvalidIdentity)
}

fn exact_root_store(certificate_der: &[u8]) -> Result<rustls::RootCertStore, IdentityError> {
    check_size(
        "peer certificate",
        None,
        certificate_der.len(),
        MAX_CERTIFICATE_DER_BYTES,
    )?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der.to_vec()))
        .map_err(IdentityError::InvalidPeerCertificate)?;
    Ok(roots)
}

fn verify_exact_peer(
    connection: &QuicConnection,
    expected_certificate_der: &[u8],
) -> Result<(), IdentityError> {
    let chain = match connection.peer_certificate_chain() {
        Ok(chain) => chain,
        Err(error) => {
            connection.close(PEER_IDENTITY_ERROR_CODE, PEER_IDENTITY_ERROR_REASON);
            return Err(IdentityError::QuicTransport(error));
        }
    };
    let Some(actual_certificate_der) = chain.first() else {
        connection.close(PEER_IDENTITY_ERROR_CODE, PEER_IDENTITY_ERROR_REASON);
        return Err(IdentityError::MissingPeerCertificate);
    };
    let fingerprints_match = certificate_fingerprint(actual_certificate_der)
        == certificate_fingerprint(expected_certificate_der);
    if !fingerprints_match || actual_certificate_der.as_slice() != expected_certificate_der {
        connection.close(PEER_IDENTITY_ERROR_CODE, PEER_IDENTITY_ERROR_REASON);
        return Err(IdentityError::PeerCertificateMismatch);
    }
    Ok(())
}

fn read_bounded(
    path: &Path,
    kind: &'static str,
    max_bytes: usize,
) -> Result<Vec<u8>, IdentityError> {
    let file = File::open(path).map_err(|source| IdentityError::Io {
        operation: "open",
        path: path.to_owned(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| IdentityError::Io {
            operation: "read",
            path: path.to_owned(),
            source,
        })?;
    check_size(kind, Some(path), bytes.len(), max_bytes)?;
    Ok(bytes)
}

fn check_size(
    kind: &'static str,
    path: Option<&Path>,
    actual: usize,
    max_bytes: usize,
) -> Result<(), IdentityError> {
    if actual > max_bytes {
        return Err(IdentityError::FileTooLarge {
            kind,
            path: path.unwrap_or_else(|| Path::new("<memory>")).to_owned(),
            max_bytes,
        });
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8], private: bool) -> Result<(), IdentityError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|source| IdentityError::Io {
        operation: if private {
            "create private key"
        } else {
            "create certificate"
        },
        path: path.to_owned(),
        source,
    })?;

    let result = (|| {
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|source| IdentityError::Io {
                    operation: "secure private key",
                    path: path.to_owned(),
                    source,
                })?;
        }
        #[cfg(windows)]
        if private {
            restrict_windows_owner_only_acl(path)?;
            verify_private_key_permissions(path)?;
        }
        file.write_all(bytes).map_err(|source| IdentityError::Io {
            operation: if private {
                "write private key"
            } else {
                "write certificate"
            },
            path: path.to_owned(),
            source,
        })?;
        file.sync_all().map_err(|source| IdentityError::Io {
            operation: if private {
                "sync private key"
            } else {
                "sync certificate"
            },
            path: path.to_owned(),
            source,
        })
    })();

    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{bind_client, bind_server, MediaSendOutcome};
    use bytes::Bytes;
    use latencydesk_protocol::quic::{MediaDatagram, SessionStamp};
    use latencydesk_protocol::{media_flags, MediaHeader, MediaKind, NO_DEPENDENCY};
    use rcgen::{BasicConstraints, IsCa};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::time::timeout;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "latencydesk-identity-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn server_identity_signed_by(
        display_name: &str,
        issuer: &rcgen::Certificate,
        issuer_key: &KeyPair,
    ) -> TlsIdentity {
        let key_pair = KeyPair::generate().expect("leaf key");
        let mut parameters =
            CertificateParams::new(vec![TLS_SERVER_NAME.to_owned()]).expect("leaf params");
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, display_name.to_owned());
        parameters.distinguished_name = distinguished_name;
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = parameters
            .signed_by(&key_pair, issuer, issuer_key)
            .expect("signed leaf");
        TlsIdentity::from_der(
            certificate.der().as_ref().to_vec(),
            key_pair.serialize_der(),
        )
        .expect("signed identity")
    }

    #[test]
    fn display_name_policy_is_explicit() {
        assert!(TlsIdentity::generate("Office PC-1_台北").is_ok());
        assert!(matches!(
            TlsIdentity::generate(""),
            Err(IdentityError::InvalidDisplayName(DisplayNameError::Empty))
        ));
        assert!(matches!(
            TlsIdentity::generate(" padded"),
            Err(IdentityError::InvalidDisplayName(
                DisplayNameError::SurroundingWhitespace
            ))
        ));
        assert!(matches!(
            TlsIdentity::generate("host/name"),
            Err(IdentityError::InvalidDisplayName(
                DisplayNameError::InvalidCharacter { .. }
            ))
        ));
        let too_long = "a".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        assert!(matches!(
            TlsIdentity::generate(&too_long),
            Err(IdentityError::InvalidDisplayName(
                DisplayNameError::TooLong { .. }
            ))
        ));
    }

    #[test]
    fn certificate_fingerprint_is_sha256() {
        assert_eq!(
            certificate_fingerprint(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn der_round_trip_refuses_overwrite_and_redacts_key_errors() {
        let directory = TestDirectory::new();
        let certificate_path = directory.path("identity.cert.der");
        let private_key_path = directory.path("identity.key.der");
        let identity = TlsIdentity::generate("Round Trip").expect("identity");
        identity
            .write_der(&certificate_path, &private_key_path)
            .expect("write identity");

        let certificate_before = fs::read(&certificate_path).expect("certificate bytes");
        let private_key_before = fs::read(&private_key_path).expect("private key bytes");
        let loaded =
            TlsIdentity::load_der(&certificate_path, &private_key_path).expect("load identity");
        assert_eq!(loaded.certificate_der(), certificate_before);
        assert_eq!(loaded.fingerprint(), identity.fingerprint());
        assert_eq!(
            load_certificate_der(&certificate_path).expect("load peer certificate"),
            certificate_before
        );

        let replacement = TlsIdentity::generate("Replacement").expect("replacement");
        let error = replacement
            .write_der(&certificate_path, &private_key_path)
            .expect_err("private key overwrite must fail");
        assert!(matches!(
            error,
            IdentityError::Io {
                source,
                ..
            } if source.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(
            fs::read(&certificate_path).expect("unchanged certificate"),
            certificate_before
        );
        assert_eq!(
            fs::read(&private_key_path).expect("unchanged private key"),
            private_key_before
        );

        let marker = b"private-key-marker-that-must-not-leak".to_vec();
        let invalid = TlsIdentity::from_der(identity.certificate_der().to_vec(), marker)
            .expect_err("invalid private key");
        let rendered = format!("{invalid:?}\n{invalid}");
        assert!(!rendered.contains("private-key-marker"));
        let identity_debug = format!("{identity:?}");
        assert!(identity_debug.contains("[redacted]"));
        assert!(!identity_debug.contains("private-key-marker"));
    }

    #[test]
    fn peer_certificate_load_is_bounded() {
        let directory = TestDirectory::new();
        let certificate_path = directory.path("oversize.cert.der");
        fs::write(&certificate_path, vec![0_u8; MAX_CERTIFICATE_DER_BYTES + 1])
            .expect("write oversized certificate");

        assert!(matches!(
            load_certificate_der(&certificate_path),
            Err(IdentityError::FileTooLarge {
                kind: "peer certificate",
                max_bytes: MAX_CERTIFICATE_DER_BYTES,
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_written_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let certificate_path = directory.path("identity.cert.der");
        let private_key_path = directory.path("identity.key.der");
        TlsIdentity::generate("Permissions")
            .expect("identity")
            .write_der(&certificate_path, &private_key_path)
            .expect("write identity");
        let mode = fs::metadata(private_key_path)
            .expect("private key metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn loading_rejects_group_or_other_accessible_private_key() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let certificate_path = directory.path("identity.cert.der");
        let private_key_path = directory.path("identity.key.der");
        TlsIdentity::generate("Insecure Permissions")
            .expect("identity")
            .write_der(&certificate_path, &private_key_path)
            .expect("write identity");
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o640))
            .expect("weaken permissions");

        assert!(matches!(
            TlsIdentity::load_der(&certificate_path, &private_key_path),
            Err(IdentityError::InsecurePrivateKeyPermissions { mode: 0o640, .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn private_key_is_written_with_owner_only_acl() {
        let directory = TestDirectory::new();
        let certificate_path = directory.path("identity.cert.der");
        let private_key_path = directory.path("identity.key.der");
        TlsIdentity::generate("Permissions")
            .expect("identity")
            .write_der(&certificate_path, &private_key_path)
            .expect("write identity");
        verify_private_key_permissions(&private_key_path)
            .expect("freshly written key ACL must be accepted");
        TlsIdentity::load_der(&certificate_path, &private_key_path).expect("load restricted key");
    }

    #[cfg(windows)]
    #[test]
    fn loading_rejects_world_readable_private_key_acl() {
        let directory = TestDirectory::new();
        let certificate_path = directory.path("identity.cert.der");
        let private_key_path = directory.path("identity.key.der");
        TlsIdentity::generate("Insecure Permissions")
            .expect("identity")
            .write_der(&certificate_path, &private_key_path)
            .expect("write identity");

        let grant = Command::new(system32_tool("icacls.exe"))
            .arg(&private_key_path)
            .arg("/grant")
            .arg("Everyone:(R)")
            .output()
            .expect("grant Everyone");
        assert!(
            grant.status.success(),
            "granting Everyone read must work without admin: {}",
            String::from_utf8_lossy(&grant.stderr)
        );

        assert!(matches!(
            TlsIdentity::load_der(&certificate_path, &private_key_path),
            Err(IdentityError::InsecureWindowsPrivateKeyAcl { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_acl_parser_rejects_world_principals() {
        assert!(windows_acl_grants_world_access(
            "C:\\k Everyone:(R)\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n"
        ));
        assert!(windows_acl_grants_world_access(
            "C:\\k NT AUTHORITY\\Authenticated Users:(R)\r\n"
        ));
        assert!(windows_acl_grants_world_access(
            "C:\\k BUILTIN\\Users:(R)\r\n"
        ));
        assert!(windows_acl_grants_world_access(
            "                                                     Users:(R)\r\n"
        ));
        assert!(!windows_acl_grants_world_access(
            "C:\\k 90607STAR\\90607:(R,W)\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n"
        ));
        assert!(!windows_acl_grants_world_access(
            "C:\\k 90607star\\CodexSandboxUsers:(I)(M)\r\n"
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtls_loopback_exposes_exact_peer_chains_and_datagrams() {
        let server_identity = TlsIdentity::generate("Loopback Server").expect("server identity");
        let client_identity = TlsIdentity::generate("Loopback Client").expect("client identity");
        let server_certificate = server_identity.certificate_der().to_vec();
        let client_certificate = client_identity.certificate_der().to_vec();
        let server_configuration =
            mtls_server_config(&server_identity, &client_certificate).expect("server config");
        let client_configuration =
            mtls_client_config(&client_identity, &server_certificate).expect("client config");
        let server_endpoint = bind_server(
            server_configuration,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("server endpoint");
        let client_endpoint = bind_client(
            client_configuration,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("client endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");

        let (server, client) = tokio::join!(
            timeout(
                Duration::from_secs(5),
                accept_exact_peer(&server_endpoint, &client_certificate)
            ),
            timeout(
                Duration::from_secs(5),
                connect_exact_peer(&client_endpoint, server_address, &server_certificate)
            ),
        );
        let server = server
            .expect("server handshake timeout")
            .expect("server mTLS");
        let client = client
            .expect("client handshake timeout")
            .expect("client mTLS");
        assert_eq!(
            client.peer_certificate_chain().expect("server chain"),
            vec![server_certificate]
        );
        assert_eq!(
            server.peer_certificate_chain().expect("client chain"),
            vec![client_certificate]
        );

        let stamp = SessionStamp {
            session_id: 1,
            generation: 1,
            authorization_epoch: 1,
            display_epoch: 1,
            codec_epoch: 1,
        };
        let header = MediaHeader {
            kind: MediaKind::Video,
            flags: media_flags::KEYFRAME,
            stream_id: 1,
            codec_epoch: 1,
            frame_id: 1,
            dependency_frame_id: NO_DEPENDENCY,
            frame_len: 4,
            fragment_offset: 0,
            fragment_len: 4,
        };
        let datagram = Bytes::from(
            MediaDatagram::encode(stamp, 100, header, b"data").expect("media datagram"),
        );
        assert_eq!(
            client
                .send_media(datagram.clone(), 1, 100)
                .expect("send media"),
            MediaSendOutcome::Sent
        );
        let received = timeout(Duration::from_secs(5), server.receive_media())
            .await
            .expect("datagram timeout")
            .expect("receive datagram");
        assert_eq!(received, datagram);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exact_server_certificate_pin_rejects_a_different_peer() {
        let issuer_key = KeyPair::generate().expect("issuer key");
        let mut issuer_parameters =
            CertificateParams::new(Vec::<String>::new()).expect("issuer params");
        let mut issuer_name = DistinguishedName::new();
        issuer_name.push(DnType::CommonName, "Loopback Test CA");
        issuer_parameters.distinguished_name = issuer_name;
        issuer_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let issuer = issuer_parameters
            .self_signed(&issuer_key)
            .expect("issuer certificate");
        let server_identity = server_identity_signed_by("Actual Server", &issuer, &issuer_key);
        let wrong_server = server_identity_signed_by("Wrong Server", &issuer, &issuer_key);
        let client_identity = TlsIdentity::generate("Client").expect("client identity");
        let server_configuration =
            mtls_server_config(&server_identity, client_identity.certificate_der())
                .expect("server config");
        let client_configuration =
            mtls_client_config(&client_identity, issuer.der().as_ref()).expect("client config");
        let server_endpoint = bind_server(
            server_configuration,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("server endpoint");
        let client_endpoint = bind_client(
            client_configuration,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("client endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");

        let (server, client) = tokio::join!(
            timeout(
                Duration::from_secs(5),
                accept_exact_peer(&server_endpoint, client_identity.certificate_der())
            ),
            timeout(
                Duration::from_secs(5),
                connect_exact_peer(
                    &client_endpoint,
                    server_address,
                    wrong_server.certificate_der()
                )
            ),
        );
        match client {
            Ok(Err(IdentityError::PeerCertificateMismatch)) => {}
            Ok(Err(error)) => panic!("unexpected exact-leaf error: {error}"),
            Ok(Ok(_)) => panic!("wrapper returned a differently pinned server certificate"),
            Err(_) => panic!("exact-leaf wrapper did not finish"),
        }
        match server {
            Ok(Ok(connection)) => {
                timeout(Duration::from_secs(5), connection.closed())
                    .await
                    .expect("server did not observe mismatch close");
            }
            Ok(Err(_)) => {}
            Err(_) => panic!("server did not finish or observe the mismatch close"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_rejects_an_unpinned_client_certificate() {
        let server_identity = TlsIdentity::generate("Server").expect("server identity");
        let expected_client = TlsIdentity::generate("Expected Client").expect("expected client");
        let actual_client = TlsIdentity::generate("Actual Client").expect("actual client");
        let server_configuration =
            mtls_server_config(&server_identity, expected_client.certificate_der())
                .expect("server config");
        let client_configuration =
            mtls_client_config(&actual_client, server_identity.certificate_der())
                .expect("client config");
        let server_endpoint = bind_server(
            server_configuration,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("server endpoint");
        let client_endpoint = bind_client(
            client_configuration,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("client endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");

        let (server, client) = tokio::join!(
            timeout(
                Duration::from_secs(5),
                accept_exact_peer(&server_endpoint, expected_client.certificate_der())
            ),
            timeout(
                Duration::from_secs(5),
                connect_exact_peer(
                    &client_endpoint,
                    server_address,
                    server_identity.certificate_der()
                )
            ),
        );
        match server {
            Ok(Err(IdentityError::QuicTransport(_))) => {}
            Ok(Err(error)) => panic!("unexpected server rejection error: {error}"),
            Ok(Ok(_)) => panic!("server returned an unpinned client connection"),
            Err(_) => panic!("server did not finish the rejected handshake"),
        }
        match client {
            Ok(Err(IdentityError::QuicTransport(_))) => {}
            Ok(Err(error)) => panic!("unexpected client rejection error: {error}"),
            Ok(Ok(connection)) => {
                let terminal = timeout(Duration::from_secs(5), connection.closed())
                    .await
                    .expect("client did not observe server's mTLS rejection");
                assert!(!matches!(
                    terminal,
                    quinn::ConnectionError::LocallyClosed | quinn::ConnectionError::TimedOut
                ));
            }
            Err(_) => panic!("client did not finish or observe terminal rejection"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejected_client_does_not_close_server_endpoint_for_next_exact_peer() {
        let server_identity = TlsIdentity::generate("Persistent Server").expect("server identity");
        let expected_client =
            TlsIdentity::generate("Expected Client").expect("expected client identity");
        let rogue_client = TlsIdentity::generate("Rogue Client").expect("rogue client identity");
        let server_certificate = server_identity.certificate_der().to_vec();
        let expected_client_certificate = expected_client.certificate_der().to_vec();

        let server_endpoint = bind_server(
            mtls_server_config(&server_identity, &expected_client_certificate)
                .expect("server config"),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("server endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");
        let rogue_endpoint = bind_client(
            mtls_client_config(&rogue_client, &server_certificate).expect("rogue client config"),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("rogue endpoint");

        let (server_rejection, rogue_attempt) = tokio::join!(
            timeout(
                Duration::from_secs(5),
                accept_exact_peer_with_timeout(
                    &server_endpoint,
                    &expected_client_certificate,
                    Duration::from_secs(3),
                )
            ),
            timeout(
                Duration::from_secs(5),
                connect_exact_peer(&rogue_endpoint, server_address, &server_certificate)
            ),
        );
        assert!(matches!(
            server_rejection,
            Ok(Err(IdentityError::QuicTransport(
                QuicTransportError::Connection(_)
            )))
        ));
        match rogue_attempt {
            Ok(Err(IdentityError::QuicTransport(_))) => {}
            Ok(Ok(connection)) => {
                timeout(Duration::from_secs(5), connection.closed())
                    .await
                    .expect("rogue connection did not observe rejection");
            }
            Ok(Err(error)) => panic!("unexpected rogue-client result: {error}"),
            Err(_) => panic!("rogue-client attempt did not finish"),
        }

        let valid_endpoint = bind_client(
            mtls_client_config(&expected_client, &server_certificate).expect("valid client config"),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("valid endpoint");
        let (server_acceptance, valid_attempt) = tokio::join!(
            timeout(
                Duration::from_secs(5),
                accept_exact_peer_with_timeout(
                    &server_endpoint,
                    &expected_client_certificate,
                    Duration::from_secs(3),
                )
            ),
            timeout(
                Duration::from_secs(5),
                connect_exact_peer(&valid_endpoint, server_address, &server_certificate)
            ),
        );
        let accepted = server_acceptance
            .expect("valid server accept timed out")
            .expect("server endpoint must remain usable after rogue rejection");
        let valid = valid_attempt
            .expect("valid client connect timed out")
            .expect("valid client must authenticate after rogue rejection");
        assert_eq!(
            accepted
                .peer_certificate_chain()
                .expect("accepted client chain"),
            vec![expected_client_certificate]
        );
        assert_eq!(
            valid.peer_certificate_chain().expect("valid server chain"),
            vec![server_certificate]
        );
    }
}
