//! Secure pairing protocol with 6-digit numeric Short Authentication String (SAS)
//! and out-of-band host confirmation.

use crate::authorization::DeviceFingerprint;
use core::fmt;
use latencydesk_protocol::{PairingRequestWire, PairingResponseWire, SasCode};

/// Maximum allowable duration for a pairing session (5 minutes).
pub const MAX_PAIRING_TTL_NS: u64 = 5 * 60 * 1_000_000_000;
/// Default maximum invalid SAS confirmation attempts before brute-force lockout.
pub const DEFAULT_MAX_SAS_ATTEMPTS: u8 = 3;

/// Errors occurring during numeric SAS pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasError {
    PairingNotInProgress,
    PairingExpired,
    PairingInProgress,
    InvalidDevice,
    SasMismatch,
    MaxAttemptsExceeded,
    StaleHandle,
    AlreadyConfirmed,
    HostRejected,
}

impl fmt::Display for SasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SasError {}

/// Opaque handle returned when a client presents ephemeral parameters,
/// required for the host operator to confirm or reject the 6-digit SAS code.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SasApprovalHandle {
    pub device: DeviceFingerprint,
    pub generation: u64,
    pub nonce: [u8; 16],
}

impl fmt::Debug for SasApprovalHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SasApprovalHandle")
            .field("device", &self.device)
            .field("generation", &self.generation)
            .field("nonce", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SasState {
    Idle,
    AwaitingRequest {
        host_fingerprint: DeviceFingerprint,
        host_ephemeral: [u8; 32],
        generation: u64,
        expires_at_ns: u64,
    },
    AwaitingHostConfirmation {
        client_device: DeviceFingerprint,
        client_ephemeral: [u8; 32],
        host_ephemeral: [u8; 32],
        sas_code: SasCode,
        attempts_remaining: u8,
        generation: u64,
        expires_at_ns: u64,
        handle: SasApprovalHandle,
    },
    Confirmed {
        client_device: DeviceFingerprint,
        generation: u64,
    },
    Rejected,
}

/// Host-side manager for SAS-based device pairing.
#[derive(Debug)]
pub struct SasPairingManager {
    max_attempts: u8,
    pairing_ttl_ns: u64,
    next_generation: u64,
    state: SasState,
}

impl Default for SasPairingManager {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SAS_ATTEMPTS, MAX_PAIRING_TTL_NS)
    }
}

impl SasPairingManager {
    #[must_use]
    pub const fn new(max_attempts: u8, pairing_ttl_ns: u64) -> Self {
        Self {
            max_attempts,
            pairing_ttl_ns,
            next_generation: 1,
            state: SasState::Idle,
        }
    }

    /// Begins a new pairing session on the host side.
    pub fn begin_pairing(
        &mut self,
        host_fingerprint: DeviceFingerprint,
        host_ephemeral: [u8; 32],
        now_ns: u64,
    ) -> Result<(), SasError> {
        self.expire(now_ns);
        if !matches!(
            self.state,
            SasState::Idle | SasState::Rejected | SasState::Confirmed { .. }
        ) {
            return Err(SasError::PairingInProgress);
        }

        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        let expires_at_ns = now_ns.saturating_add(self.pairing_ttl_ns);

        self.state = SasState::AwaitingRequest {
            host_fingerprint,
            host_ephemeral,
            generation,
            expires_at_ns,
        };
        Ok(())
    }

    /// Handles a client pairing request, computes the 6-digit numeric SAS, and yields
    /// the host response and SAS approval handle for out-of-band operator verification.
    pub fn handle_client_request(
        &mut self,
        request: PairingRequestWire,
        confirmation_nonce: [u8; 16],
        now_ns: u64,
    ) -> Result<(PairingResponseWire, SasCode, SasApprovalHandle), SasError> {
        match self.state {
            SasState::AwaitingRequest {
                host_fingerprint,
                host_ephemeral,
                generation,
                expires_at_ns,
            } => {
                if now_ns >= expires_at_ns {
                    self.state = SasState::Idle;
                    return Err(SasError::PairingExpired);
                }
                let client_device = DeviceFingerprint::new(request.client_fingerprint)
                    .map_err(|_| SasError::InvalidDevice)?;
                let salt = b"LatencyDesk-v1-SAS-Numeric";
                let sas_code =
                    SasCode::compute(&host_ephemeral, &request.client_ephemeral_key, salt);

                let handle = SasApprovalHandle {
                    device: client_device,
                    generation,
                    nonce: confirmation_nonce,
                };

                let sas_commitment = PairingResponseWire::compute_commitment(
                    &host_ephemeral,
                    &request.client_ephemeral_key,
                    salt,
                );
                let response = PairingResponseWire {
                    host_fingerprint: host_fingerprint.as_bytes(),
                    host_ephemeral_key: host_ephemeral,
                    sas_commitment,
                    expires_at_ns,
                };

                self.state = SasState::AwaitingHostConfirmation {
                    client_device,
                    client_ephemeral: request.client_ephemeral_key,
                    host_ephemeral,
                    sas_code,
                    attempts_remaining: self.max_attempts,
                    generation,
                    expires_at_ns,
                    handle,
                };

                Ok((response, sas_code, handle))
            }
            SasState::AwaitingHostConfirmation { .. } => Err(SasError::PairingInProgress),
            _ => Err(SasError::PairingNotInProgress),
        }
    }

    /// Host operator out-of-band confirmation of the 6-digit numeric SAS.
    /// Fails closed on mismatch or max attempt exhaustion.
    pub fn confirm_sas(
        &mut self,
        handle: SasApprovalHandle,
        entered_code: SasCode,
        now_ns: u64,
    ) -> Result<(), SasError> {
        match &mut self.state {
            SasState::AwaitingHostConfirmation {
                client_device,
                sas_code,
                attempts_remaining,
                generation,
                expires_at_ns,
                handle: active_handle,
                ..
            } => {
                if *active_handle != handle {
                    return Err(SasError::StaleHandle);
                }
                if now_ns >= *expires_at_ns {
                    self.state = SasState::Idle;
                    return Err(SasError::PairingExpired);
                }

                if entered_code.value() == sas_code.value() {
                    let dev = *client_device;
                    let gen = *generation;
                    self.state = SasState::Confirmed {
                        client_device: dev,
                        generation: gen,
                    };
                    Ok(())
                } else {
                    *attempts_remaining = attempts_remaining.saturating_sub(1);
                    if *attempts_remaining == 0 {
                        self.state = SasState::Rejected;
                        Err(SasError::MaxAttemptsExceeded)
                    } else {
                        Err(SasError::SasMismatch)
                    }
                }
            }
            SasState::Confirmed { .. } => Err(SasError::AlreadyConfirmed),
            _ => Err(SasError::PairingNotInProgress),
        }
    }

    /// Host operator explicitly rejects the pairing request.
    pub fn reject_sas(&mut self, handle: SasApprovalHandle) -> Result<(), SasError> {
        match self.state {
            SasState::AwaitingHostConfirmation {
                handle: active_handle,
                ..
            } => {
                if active_handle != handle {
                    return Err(SasError::StaleHandle);
                }
                self.state = SasState::Rejected;
                Ok(())
            }
            _ => Err(SasError::PairingNotInProgress),
        }
    }

    /// Checks if a client device is in confirmed state.
    #[must_use]
    pub fn is_confirmed(&self, device: DeviceFingerprint) -> bool {
        match self.state {
            SasState::Confirmed { client_device, .. } => client_device == device,
            _ => false,
        }
    }

    /// Expires any active pairing attempt if timestamp passed deadline.
    pub fn expire(&mut self, now_ns: u64) {
        match self.state {
            SasState::AwaitingRequest { expires_at_ns, .. }
            | SasState::AwaitingHostConfirmation { expires_at_ns, .. }
                if now_ns >= expires_at_ns =>
            {
                self.state = SasState::Idle;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sas_commitment_is_cryptographic_hash_not_plaintext_digits() {
        let host_dev = DeviceFingerprint::new([1_u8; 32]).expect("host device");
        let client_dev = DeviceFingerprint::new([2_u8; 32]).expect("client device");
        let host_ephemeral = [3_u8; 32];
        let client_ephemeral = [4_u8; 32];
        let nonce = [8_u8; 16];

        let mut manager = SasPairingManager::default();
        manager
            .begin_pairing(host_dev, host_ephemeral, 1_000_000)
            .expect("begin");

        let req = PairingRequestWire {
            client_fingerprint: client_dev.as_bytes(),
            client_ephemeral_key: client_ephemeral,
            requested_capabilities: 0x03,
            timestamp_ns: 1_100_000,
        };

        let (resp, sas_code, _handle) = manager
            .handle_client_request(req, nonce, 1_200_000)
            .expect("handle req");

        // Verify sas_commitment is not the raw ASCII digits or confirmation nonce
        let sas_digits = sas_code.to_ascii_digits();
        assert_ne!(&resp.sas_commitment[0..6], &sas_digits[..]);
        assert_ne!(&resp.sas_commitment[6..22], &nonce[..]);

        // Verify sas_commitment is computed deterministically from ephemeral keys & salt
        let expected_commitment = PairingResponseWire::compute_commitment(
            &host_ephemeral,
            &client_ephemeral,
            b"LatencyDesk-v1-SAS-Numeric",
        );
        assert_eq!(resp.sas_commitment, expected_commitment);
        assert_ne!(resp.sas_commitment, [0_u8; 32]);
    }

    #[test]
    fn test_pairing_expiry_and_timeout() {
        let host_dev = DeviceFingerprint::new([1_u8; 32]).expect("host device");
        let host_ephemeral = [3_u8; 32];
        let mut manager = SasPairingManager::new(3, 1_000_000_000); // 1s TTL

        manager
            .begin_pairing(host_dev, host_ephemeral, 1_000)
            .expect("begin");

        let client_dev = DeviceFingerprint::new([2_u8; 32]).expect("client device");
        let req = PairingRequestWire {
            client_fingerprint: client_dev.as_bytes(),
            client_ephemeral_key: [4_u8; 32],
            requested_capabilities: 0x01,
            timestamp_ns: 2_000_000_000,
        };

        assert_eq!(
            manager.handle_client_request(req, [0_u8; 16], 2_000_000_000),
            Err(SasError::PairingExpired)
        );
    }

    #[test]
    fn test_pairing_rejection_and_stale_handle() {
        let host_dev = DeviceFingerprint::new([1_u8; 32]).expect("host device");
        let client_dev = DeviceFingerprint::new([2_u8; 32]).expect("client device");
        let mut manager = SasPairingManager::default();

        manager
            .begin_pairing(host_dev, [10_u8; 32], 1_000)
            .expect("begin");

        let req = PairingRequestWire {
            client_fingerprint: client_dev.as_bytes(),
            client_ephemeral_key: [20_u8; 32],
            requested_capabilities: 0x01,
            timestamp_ns: 2_000,
        };

        let (_resp, sas_code, handle) = manager
            .handle_client_request(req, [5_u8; 16], 3_000)
            .expect("handle");

        let stale_handle = SasApprovalHandle {
            device: client_dev,
            generation: handle.generation + 1,
            nonce: handle.nonce,
        };

        assert_eq!(
            manager.confirm_sas(stale_handle, sas_code, 4_000),
            Err(SasError::StaleHandle)
        );

        assert_eq!(manager.reject_sas(handle), Ok(()));
        assert_eq!(
            manager.confirm_sas(handle, sas_code, 5_000),
            Err(SasError::PairingNotInProgress)
        );
    }

    #[test]
    fn test_sas_approval_handle_debug_redaction() {
        let dev = DeviceFingerprint::new([7_u8; 32]).expect("device");
        let handle = SasApprovalHandle {
            device: dev,
            generation: 42,
            nonce: [0x5A; 16],
        };
        let debug_str = format!("{handle:?}");
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("90")); // 0x5A is 90
    }
}
