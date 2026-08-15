//! Pinned-device pairing and explicit two-sided SAS approval.
//!
//! A successful pairing binds the selected local peer pin to the certificate
//! identity already authenticated by QUIC/TLS. The six-digit SAS is derived
//! from canonical public pairing evidence and is never retained after either
//! confirmation path has completed.

use crate::authorization::{CapabilitySet, SessionId};
use core::fmt;
use latencydesk_platform::{DeviceIdentity, DeviceIdentityStore, PeerAlias, PeerPin};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Maximum duration from pairing start to confirmation.
pub const MAX_PAIRING_TTL_NS: u64 = 5 * 60 * 1_000_000_000;
/// Number of invalid SAS confirmations before the attempt is permanently closed.
pub const DEFAULT_MAX_SAS_ATTEMPTS: u8 = 3;

const SAS_MODULUS: u32 = 1_000_000;
const SAS_DOMAIN: &[u8] = b"LatencyDesk-v1-SAS-Numeric";
const SAS_CONFIRM_DOMAIN: &[u8] = b"LatencyDesk-v1-SAS-Confirm";
const PAIRING_EVIDENCE_LEN: usize = 8 + 32 + 32 + 8 + 1;

/// Failure while pinning a TLS identity or confirming its short authentication
/// string. Errors intentionally contain no identity or SAS material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    InvalidEvidence,
    InvalidSas,
    PairingInProgress,
    Closed,
    Expired,
    PeerPinMismatch,
    SasMismatch,
    SasAttemptsExceeded,
    StoreFailure,
}

impl fmt::Display for PairingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PairingError {}

/// Canonical public evidence bound into a pairing SAS.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PairingEvidence {
    pub session_id: SessionId,
    pub local_fingerprint: [u8; 32],
    pub peer_fingerprint: [u8; 32],
    pub expires_at_ns: u64,
    pub capabilities: CapabilitySet,
}

impl PairingEvidence {
    pub fn new(
        session_id: SessionId,
        local_fingerprint: [u8; 32],
        peer_fingerprint: [u8; 32],
        expires_at_ns: u64,
        capabilities: CapabilitySet,
    ) -> Result<Self, PairingError> {
        let evidence = Self {
            session_id,
            local_fingerprint,
            peer_fingerprint,
            expires_at_ns,
            capabilities,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(self) -> Result<(), PairingError> {
        if self.local_fingerprint.iter().all(|byte| *byte == 0)
            || self.peer_fingerprint.iter().all(|byte| *byte == 0)
            || self.local_fingerprint == self.peer_fingerprint
            || self.expires_at_ns == 0
        {
            return Err(PairingError::InvalidEvidence);
        }
        Ok(())
    }

    fn canonical_bytes(self) -> [u8; PAIRING_EVIDENCE_LEN] {
        let mut encoded = [0_u8; PAIRING_EVIDENCE_LEN];
        let mut offset = 0;
        put_bytes(
            &mut encoded,
            &mut offset,
            &self.session_id.value().to_be_bytes(),
        );
        put_bytes(&mut encoded, &mut offset, &self.local_fingerprint);
        put_bytes(&mut encoded, &mut offset, &self.peer_fingerprint);
        put_bytes(&mut encoded, &mut offset, &self.expires_at_ns.to_be_bytes());
        put_bytes(&mut encoded, &mut offset, &[self.capabilities.bits()]);
        encoded
    }
}

impl fmt::Debug for PairingEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingEvidence(<redacted>)")
    }
}

fn put_bytes(destination: &mut [u8], offset: &mut usize, source: &[u8]) {
    let end = *offset + source.len();
    destination[*offset..end].copy_from_slice(source);
    *offset = end;
}

/// Six-digit SAS. Its ASCII representation is zeroized on drop and omitted
/// from diagnostics.
pub struct SasCode {
    digits: Zeroizing<[u8; 6]>,
}

impl SasCode {
    pub fn from_u32(value: u32) -> Result<Self, PairingError> {
        if value >= SAS_MODULUS {
            return Err(PairingError::InvalidSas);
        }
        Ok(Self::from_valid_value(value))
    }

    #[must_use]
    pub fn value(&self) -> u32 {
        self.digits
            .iter()
            .fold(0_u32, |value, digit| value * 10 + u32::from(*digit - b'0'))
    }

    fn from_evidence(evidence: PairingEvidence) -> Self {
        let encoded = evidence.canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(SAS_DOMAIN);
        hasher.update(encoded);
        let digest = hasher.finalize();
        let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % SAS_MODULUS;
        Self::from_valid_value(value)
    }

    fn from_valid_value(value: u32) -> Self {
        let mut remaining = value;
        let mut digits = [b'0'; 6];
        for digit in digits.iter_mut().rev() {
            *digit = b'0' + (remaining % 10) as u8;
            remaining /= 10;
        }
        Self {
            digits: Zeroizing::new(digits),
        }
    }

    fn ascii_digits(&self) -> [u8; 6] {
        let mut digits = [0_u8; 6];
        digits.copy_from_slice(&self.digits[..]);
        digits
    }
}

impl fmt::Debug for SasCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SasCode(<redacted>)")
    }
}

/// The secret-bearing display prompt. The code is returned only for the local
/// approval UI and is not persisted in pairing state.
pub struct PairingPrompt {
    evidence: PairingEvidence,
    sas: SasCode,
}

impl PairingPrompt {
    #[must_use]
    pub const fn evidence(&self) -> PairingEvidence {
        self.evidence
    }

    pub fn into_sas(self) -> SasCode {
        self.sas
    }
}

impl fmt::Debug for PairingPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingPrompt(<redacted>)")
    }
}

/// A transport admission created only after TLS pin verification and both SAS
/// confirmations. This is the only session value usable by runtime authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AcceptedSession {
    session_id: SessionId,
    local_identity: DeviceIdentity,
    peer_pin: PeerPin,
    capabilities: CapabilitySet,
}

impl AcceptedSession {
    fn from_evidence(
        evidence: PairingEvidence,
        local_identity: DeviceIdentity,
        peer_pin: PeerPin,
    ) -> Self {
        Self {
            session_id: evidence.session_id,
            local_identity,
            peer_pin,
            capabilities: evidence.capabilities,
        }
    }

    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn local_identity(self) -> DeviceIdentity {
        self.local_identity
    }

    #[must_use]
    pub const fn peer_pin(self) -> PeerPin {
        self.peer_pin
    }

    #[must_use]
    pub const fn capabilities(self) -> CapabilitySet {
        self.capabilities
    }

    #[cfg(test)]
    pub(crate) fn test_only(
        session_id: SessionId,
        local_spki_fingerprint: [u8; 32],
        peer_pin: PeerPin,
        capabilities: CapabilitySet,
    ) -> Self {
        let local_identity = DeviceIdentity::from_tls_spki_fingerprint(local_spki_fingerprint)
            .unwrap_or_else(|_| unreachable!("test identity must be valid"));
        Self {
            session_id,
            local_identity,
            peer_pin,
            capabilities,
        }
    }
}

impl fmt::Debug for AcceptedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedSession")
            .field("session_id", &self.session_id)
            .field("local_identity", &"<redacted>")
            .field("peer_pin", &"<redacted>")
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

/// Result of starting a pairing attempt.
pub enum PairingStart {
    AwaitingSas(PairingPrompt),
    Accepted(AcceptedSession),
}

impl fmt::Debug for PairingStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitingSas(_) => formatter.write_str("PairingStart::AwaitingSas(<redacted>)"),
            Self::Accepted(session) => formatter
                .debug_tuple("PairingStart::Accepted")
                .field(session)
                .finish(),
        }
    }
}

/// State after one side has submitted its confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingProgress {
    AwaitingLocalApproval,
    AwaitingPeerAcknowledgement,
    Accepted(AcceptedSession),
}

/// Non-secret pairing status suitable for telemetry and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStatus {
    Idle,
    Pending { attempts_remaining: u8 },
    Accepted,
    Closed,
}

/// Secret-free diagnostic snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingDiagnostics {
    status: PairingStatus,
}

impl PairingDiagnostics {
    #[must_use]
    pub const fn status(self) -> PairingStatus {
        self.status
    }
}

struct PendingPairing {
    alias: PeerAlias,
    evidence: PairingEvidence,
    local_identity: DeviceIdentity,
    peer_pin: PeerPin,
    expected_sas_commitment: Zeroizing<[u8; 32]>,
    local_approved: bool,
    peer_acknowledged: bool,
    attempts_remaining: u8,
}

enum PairingState {
    Idle,
    Pending(PendingPairing),
    Accepted(AcceptedSession),
    Closed,
}

/// Coordinates one non-resumable pairing attempt against a platform-owned
/// identity store. A storage failure closes the attempt rather than leaving
/// an unpinned peer usable.
pub struct PairingCoordinator<S> {
    store: S,
    state: PairingState,
}

impl<S> PairingCoordinator<S>
where
    S: DeviceIdentityStore,
{
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self {
            store,
            state: PairingState::Idle,
        }
    }

    pub fn begin(
        &mut self,
        alias: PeerAlias,
        evidence: PairingEvidence,
        tls_peer_spki_fingerprint: [u8; 32],
        now_ns: u64,
    ) -> Result<PairingStart, PairingError> {
        match self.state {
            PairingState::Idle => {}
            PairingState::Pending(_) => return Err(PairingError::PairingInProgress),
            PairingState::Accepted(_) | PairingState::Closed => return Err(PairingError::Closed),
        }
        if evidence.validate().is_err() {
            return self.close_with(PairingError::InvalidEvidence);
        }
        let local_identity = match self.store.load_or_create_identity() {
            Ok(identity) => identity,
            Err(_) => return self.close_with(PairingError::StoreFailure),
        };
        if evidence.local_fingerprint != local_identity.spki_fingerprint()
            || tls_peer_spki_fingerprint != evidence.peer_fingerprint
            || evidence.expires_at_ns <= now_ns
            || evidence.expires_at_ns - now_ns > MAX_PAIRING_TTL_NS
        {
            return self.close_with(PairingError::InvalidEvidence);
        }
        let selected_pin = match self.store.load_peer_pin(&alias) {
            Ok(pin) => pin,
            Err(_) => return self.close_with(PairingError::StoreFailure),
        };
        let peer_pin = match PeerPin::from_tls_spki_fingerprint(tls_peer_spki_fingerprint) {
            Ok(pin) => pin,
            Err(_) => return self.close_with(PairingError::InvalidEvidence),
        };

        if let Some(selected_pin) = selected_pin {
            if selected_pin != peer_pin {
                return self.close_with(PairingError::PeerPinMismatch);
            }
            let accepted = AcceptedSession::from_evidence(evidence, local_identity, peer_pin);
            self.state = PairingState::Accepted(accepted);
            return Ok(PairingStart::Accepted(accepted));
        }

        let sas = SasCode::from_evidence(evidence);
        let expected_sas_commitment = sas_commitment(&sas);
        self.state = PairingState::Pending(PendingPairing {
            alias,
            evidence,
            local_identity,
            peer_pin,
            expected_sas_commitment,
            local_approved: false,
            peer_acknowledged: false,
            attempts_remaining: DEFAULT_MAX_SAS_ATTEMPTS,
        });
        Ok(PairingStart::AwaitingSas(PairingPrompt { evidence, sas }))
    }

    pub fn confirm_local(&mut self, now_ns: u64) -> Result<PairingProgress, PairingError> {
        let pending = self.pending_mut(now_ns)?;
        pending.local_approved = true;
        self.progress_or_accept()
    }

    pub fn confirm_peer(
        &mut self,
        sas: SasCode,
        now_ns: u64,
    ) -> Result<PairingProgress, PairingError> {
        let commitment = sas_commitment(&sas);
        let result = {
            let pending = self.pending_mut(now_ns)?;
            if constant_time_equal(&commitment, &pending.expected_sas_commitment) {
                pending.peer_acknowledged = true;
                Ok(())
            } else {
                pending.attempts_remaining = pending.attempts_remaining.saturating_sub(1);
                if pending.attempts_remaining == 0 {
                    Err(PairingError::SasAttemptsExceeded)
                } else {
                    Err(PairingError::SasMismatch)
                }
            }
        };
        match result {
            Ok(()) => self.progress_or_accept(),
            Err(error) => {
                if error == PairingError::SasAttemptsExceeded {
                    self.state = PairingState::Closed;
                }
                Err(error)
            }
        }
    }

    #[must_use]
    pub fn accepted_session(&self) -> Option<AcceptedSession> {
        match self.state {
            PairingState::Accepted(session) => Some(session),
            PairingState::Idle | PairingState::Pending(_) | PairingState::Closed => None,
        }
    }

    #[must_use]
    pub fn status(&self) -> PairingStatus {
        match &self.state {
            PairingState::Idle => PairingStatus::Idle,
            PairingState::Pending(pending) => PairingStatus::Pending {
                attempts_remaining: pending.attempts_remaining,
            },
            PairingState::Accepted(_) => PairingStatus::Accepted,
            PairingState::Closed => PairingStatus::Closed,
        }
    }

    #[must_use]
    pub fn diagnostics(&self) -> PairingDiagnostics {
        PairingDiagnostics {
            status: self.status(),
        }
    }

    fn pending_mut(&mut self, now_ns: u64) -> Result<&mut PendingPairing, PairingError> {
        let expired = match &self.state {
            PairingState::Pending(pending) => pending.evidence.expires_at_ns <= now_ns,
            PairingState::Idle | PairingState::Accepted(_) | PairingState::Closed => false,
        };
        if expired {
            self.state = PairingState::Closed;
            return Err(PairingError::Expired);
        }
        match &mut self.state {
            PairingState::Pending(pending) => Ok(pending),
            PairingState::Idle => Err(PairingError::InvalidEvidence),
            PairingState::Accepted(_) | PairingState::Closed => Err(PairingError::Closed),
        }
    }

    fn progress_or_accept(&mut self) -> Result<PairingProgress, PairingError> {
        let decision = match &self.state {
            PairingState::Pending(pending) if !pending.local_approved => {
                return Ok(PairingProgress::AwaitingLocalApproval);
            }
            PairingState::Pending(pending) if !pending.peer_acknowledged => {
                return Ok(PairingProgress::AwaitingPeerAcknowledgement);
            }
            PairingState::Pending(pending) => (
                pending.alias.clone(),
                pending.evidence,
                pending.local_identity,
                pending.peer_pin,
            ),
            PairingState::Idle | PairingState::Accepted(_) | PairingState::Closed => {
                return Err(PairingError::Closed);
            }
        };
        let (alias, evidence, local_identity, peer_pin) = decision;
        if self.store.store_peer_pin(&alias, peer_pin).is_err() {
            return self.close_with(PairingError::StoreFailure);
        }
        let accepted = AcceptedSession::from_evidence(evidence, local_identity, peer_pin);
        self.state = PairingState::Accepted(accepted);
        Ok(PairingProgress::Accepted(accepted))
    }

    fn close_with<T>(&mut self, error: PairingError) -> Result<T, PairingError> {
        self.state = PairingState::Closed;
        Err(error)
    }
}

impl<S> fmt::Debug for PairingCoordinator<S>
where
    S: DeviceIdentityStore,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingCoordinator")
            .field("status", &self.status())
            .finish()
    }
}

fn sas_commitment(sas: &SasCode) -> Zeroizing<[u8; 32]> {
    let digits = sas.ascii_digits();
    let mut hasher = Sha256::new();
    hasher.update(SAS_CONFIRM_DOMAIN);
    hasher.update(digits);
    let digest = hasher.finalize();
    let mut commitment = [0_u8; 32];
    commitment.copy_from_slice(&digest);
    Zeroizing::new(commitment)
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.as_slice().ct_eq(right.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    struct RecordingIdentityStore {
        identity: DeviceIdentity,
        stored_pin: Mutex<Option<PeerPin>>,
        fail_store: AtomicBool,
    }

    impl RecordingIdentityStore {
        fn new(existing_pin: Option<PeerPin>, fail_store: bool) -> Self {
            Self {
                identity: DeviceIdentity::from_tls_spki_fingerprint([1; 32]).expect("identity"),
                stored_pin: Mutex::new(existing_pin),
                fail_store: AtomicBool::new(fail_store),
            }
        }
    }

    impl DeviceIdentityStore for RecordingIdentityStore {
        fn load_or_create_identity(
            &self,
        ) -> Result<DeviceIdentity, latencydesk_platform::PlatformError> {
            Ok(self.identity)
        }

        fn load_peer_pin(
            &self,
            _alias: &PeerAlias,
        ) -> Result<Option<PeerPin>, latencydesk_platform::PlatformError> {
            Ok(*self.stored_pin.lock().expect("pin store lock"))
        }

        fn store_peer_pin(
            &self,
            _alias: &PeerAlias,
            pin: PeerPin,
        ) -> Result<(), latencydesk_platform::PlatformError> {
            if self.fail_store.load(Ordering::Relaxed) {
                return Err(latencydesk_platform::PlatformError::DeviceLost);
            }
            *self.stored_pin.lock().expect("pin store lock") = Some(pin);
            Ok(())
        }
    }

    fn alias() -> PeerAlias {
        PeerAlias::new("host").expect("peer alias")
    }

    fn evidence() -> PairingEvidence {
        PairingEvidence::new(
            SessionId::new(7).expect("session id"),
            [1; 32],
            [2; 32],
            1_000,
            CapabilitySet::view_and_input(),
        )
        .expect("pairing evidence")
    }

    fn begin_pending<S>(coordinator: &mut PairingCoordinator<S>) -> PairingPrompt
    where
        S: DeviceIdentityStore,
    {
        match coordinator
            .begin(alias(), evidence(), [2; 32], 10)
            .expect("pairing start")
        {
            PairingStart::AwaitingSas(prompt) => prompt,
            PairingStart::Accepted(_) => panic!("new peer must require SAS"),
        }
    }

    #[test]
    fn pin_mismatch_rejects_before_sas() {
        let pinned = PeerPin::from_tls_spki_fingerprint([9; 32]).expect("peer pin");
        let mut coordinator =
            PairingCoordinator::new(RecordingIdentityStore::new(Some(pinned), false));

        assert!(matches!(
            coordinator.begin(alias(), evidence(), [2; 32], 10),
            Err(PairingError::PeerPinMismatch)
        ));
        assert_eq!(coordinator.status(), PairingStatus::Closed);
    }

    #[test]
    fn matching_tls_pin_activates_without_sas() {
        let pin = PeerPin::from_tls_spki_fingerprint([2; 32]).expect("peer pin");
        let mut coordinator =
            PairingCoordinator::new(RecordingIdentityStore::new(Some(pin), false));

        let accepted = match coordinator
            .begin(alias(), evidence(), [2; 32], 10)
            .expect("pinned peer start")
        {
            PairingStart::Accepted(session) => session,
            PairingStart::AwaitingSas(_) => panic!("matching pin must not require SAS"),
        };
        assert_eq!(accepted.peer_pin(), pin);
        assert_eq!(coordinator.accepted_session(), Some(accepted));
    }

    #[test]
    fn both_confirmations_store_tls_pin_before_activation() {
        let mut coordinator = PairingCoordinator::new(RecordingIdentityStore::new(None, false));
        let prompt = begin_pending(&mut coordinator);

        assert_eq!(
            coordinator.confirm_local(20),
            Ok(PairingProgress::AwaitingPeerAcknowledgement)
        );
        let accepted = match coordinator
            .confirm_peer(prompt.into_sas(), 20)
            .expect("peer acknowledgement")
        {
            PairingProgress::Accepted(session) => session,
            PairingProgress::AwaitingLocalApproval
            | PairingProgress::AwaitingPeerAcknowledgement => {
                panic!("both confirmations must activate")
            }
        };
        assert_eq!(accepted.peer_pin().spki_fingerprint(), [2; 32]);
        assert_eq!(coordinator.accepted_session(), Some(accepted));
    }

    #[test]
    fn either_confirmation_alone_cannot_activate_pairing() {
        let mut local_first = PairingCoordinator::new(RecordingIdentityStore::new(None, false));
        let _local_prompt = begin_pending(&mut local_first);
        assert_eq!(
            local_first.confirm_local(20),
            Ok(PairingProgress::AwaitingPeerAcknowledgement)
        );
        assert!(local_first.accepted_session().is_none());

        let mut peer_first = PairingCoordinator::new(RecordingIdentityStore::new(None, false));
        let peer_prompt = begin_pending(&mut peer_first);
        assert_eq!(
            peer_first.confirm_peer(peer_prompt.into_sas(), 20),
            Ok(PairingProgress::AwaitingLocalApproval)
        );
        assert!(peer_first.accepted_session().is_none());
    }

    #[test]
    fn three_wrong_sas_attempts_terminate_the_pairing_attempt() {
        let mut coordinator = PairingCoordinator::new(RecordingIdentityStore::new(None, false));
        let prompt = begin_pending(&mut coordinator);
        let wrong_value = (prompt.into_sas().value() + 1) % SAS_MODULUS;

        assert_eq!(
            coordinator.confirm_peer(SasCode::from_u32(wrong_value).expect("wrong SAS"), 20),
            Err(PairingError::SasMismatch)
        );
        assert_eq!(
            coordinator.confirm_peer(SasCode::from_u32(wrong_value).expect("wrong SAS"), 20),
            Err(PairingError::SasMismatch)
        );
        assert_eq!(
            coordinator.confirm_peer(SasCode::from_u32(wrong_value).expect("wrong SAS"), 20),
            Err(PairingError::SasAttemptsExceeded)
        );
        assert_eq!(coordinator.status(), PairingStatus::Closed);
    }

    #[test]
    fn out_of_range_sas_is_rejected() {
        assert!(matches!(
            SasCode::from_u32(SAS_MODULUS),
            Err(PairingError::InvalidSas)
        ));
    }

    #[test]
    fn store_failure_closes_pairing_attempt() {
        let mut coordinator = PairingCoordinator::new(RecordingIdentityStore::new(None, true));
        let prompt = begin_pending(&mut coordinator);

        assert_eq!(
            coordinator.confirm_local(20),
            Ok(PairingProgress::AwaitingPeerAcknowledgement)
        );
        assert_eq!(
            coordinator.confirm_peer(prompt.into_sas(), 20),
            Err(PairingError::StoreFailure)
        );
        assert_eq!(coordinator.status(), PairingStatus::Closed);
    }

    #[test]
    fn pairing_diagnostics_redact_identity_and_sas_material() {
        let mut coordinator = PairingCoordinator::new(RecordingIdentityStore::new(None, false));
        let prompt = begin_pending(&mut coordinator);
        let diagnostics = format!("{coordinator:?} {prompt:?}");

        assert!(diagnostics.contains("<redacted>"));
        assert!(!diagnostics.contains("1, 1, 1"));
        assert!(!diagnostics.contains("2, 2, 2"));
    }
}
