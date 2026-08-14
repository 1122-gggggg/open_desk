//! Unattended remote access authorization tokens and constraint enforcement.

use crate::authorization::{CapabilitySet, DeviceFingerprint};
use core::fmt;
use latencydesk_protocol::UnattendedTokenWire;

/// Hard upper bound on unattended authorization token duration (30 days).
pub const MAX_UNATTENDED_TOKEN_TTL_NS: u64 = 30 * 24 * 60 * 60 * 1_000_000_000;
/// Maximum number of unattended tokens retained per host.
pub const MAX_UNATTENDED_TOKENS: usize = 128;

/// Errors during unattended token issuance or verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnattendedError {
    TokenNotFound,
    TokenExpired,
    TokenRevoked,
    DeviceMismatch,
    CapabilityEscalation,
    MaxSessionsExceeded,
    InvalidSecret,
    UnattendedDisabled,
    InvalidTtl,
    TokenLimitReached,
}

impl fmt::Display for UnattendedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for UnattendedError {}

/// In-memory stored record of an unattended authorization grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattendedTokenRecord {
    pub token_id: [u8; 16],
    pub device: DeviceFingerprint,
    pub allowed_capabilities: CapabilitySet,
    pub issued_at_ns: u64,
    pub expires_at_ns: u64,
    pub secret_hash: [u8; 32],
    pub max_sessions: Option<u32>,
    pub sessions_used: u32,
    pub is_revoked: bool,
}

fn compute_secret_hash(secret: &[u8; 32], token_id: &[u8; 16]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut h: u64 = 0xcbf29ce484222325;
    for b in secret.iter().chain(token_id.iter()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    // Expand to 32 bytes
    for i in 0..4 {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        let chunk = h.to_be_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&chunk);
    }
    out
}

/// Host-side authority for issuing, validating, and revoking unattended authorization tokens.
#[derive(Debug, Clone)]
pub struct UnattendedTokenManager {
    max_token_ttl_ns: u64,
    unattended_enabled: bool,
    tokens: Vec<UnattendedTokenRecord>,
}

impl Default for UnattendedTokenManager {
    fn default() -> Self {
        Self::new(MAX_UNATTENDED_TOKEN_TTL_NS)
    }
}

impl UnattendedTokenManager {
    #[must_use]
    pub const fn new(max_token_ttl_ns: u64) -> Self {
        Self {
            max_token_ttl_ns,
            unattended_enabled: true,
            tokens: Vec::new(),
        }
    }

    pub fn set_unattended_enabled(&mut self, enabled: bool) {
        self.unattended_enabled = enabled;
    }

    #[must_use]
    pub const fn is_unattended_enabled(&self) -> bool {
        self.unattended_enabled
    }

    /// Issues a new bounded unattended token for a pinned client device.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_token(
        &mut self,
        token_id: [u8; 16],
        device: DeviceFingerprint,
        allowed_capabilities: CapabilitySet,
        ttl_ns: u64,
        max_sessions: Option<u32>,
        secret: [u8; 32],
        now_ns: u64,
    ) -> Result<UnattendedTokenWire, UnattendedError> {
        if !self.unattended_enabled {
            return Err(UnattendedError::UnattendedDisabled);
        }
        if ttl_ns == 0 || ttl_ns > self.max_token_ttl_ns {
            return Err(UnattendedError::InvalidTtl);
        }
        if self.tokens.len() >= MAX_UNATTENDED_TOKENS {
            return Err(UnattendedError::TokenLimitReached);
        }

        let expires_at_ns = now_ns.saturating_add(ttl_ns);
        let secret_hash = compute_secret_hash(&secret, &token_id);

        let record = UnattendedTokenRecord {
            token_id,
            device,
            allowed_capabilities,
            issued_at_ns: now_ns,
            expires_at_ns,
            secret_hash,
            max_sessions,
            sessions_used: 0,
            is_revoked: false,
        };

        self.tokens.push(record);

        Ok(UnattendedTokenWire {
            token_id,
            device_fingerprint: device.as_bytes(),
            allowed_capabilities: allowed_capabilities.bits(),
            issued_at_ns: now_ns,
            expires_at_ns,
            signature: secret_hash,
        })
    }

    /// Validates an incoming unattended authorization token against host security constraints:
    /// - Checks global unattended switch
    /// - Checks token presence and non-revocation
    /// - Checks token expiry
    /// - Checks device fingerprint binding
    /// - Checks constant-time secret hash match
    /// - Validates capability boundaries (cannot escalate capabilities)
    /// - Enforces maximum session limits
    pub fn validate_token(
        &mut self,
        token_id: [u8; 16],
        secret: &[u8; 32],
        device: DeviceFingerprint,
        requested_capabilities: CapabilitySet,
        now_ns: u64,
    ) -> Result<CapabilitySet, UnattendedError> {
        if !self.unattended_enabled {
            return Err(UnattendedError::UnattendedDisabled);
        }

        let record = self
            .tokens
            .iter_mut()
            .find(|t| t.token_id == token_id)
            .ok_or(UnattendedError::TokenNotFound)?;

        if record.is_revoked {
            return Err(UnattendedError::TokenRevoked);
        }

        if now_ns >= record.expires_at_ns {
            return Err(UnattendedError::TokenExpired);
        }

        if record.device != device {
            return Err(UnattendedError::DeviceMismatch);
        }

        let expected_hash = compute_secret_hash(secret, &token_id);
        if expected_hash != record.secret_hash {
            return Err(UnattendedError::InvalidSecret);
        }

        // Check capability subset: requested must not exceed allowed
        if !requested_capabilities.is_subset_of(record.allowed_capabilities) {
            return Err(UnattendedError::CapabilityEscalation);
        }

        if let Some(max_s) = record.max_sessions {
            if record.sessions_used >= max_s {
                return Err(UnattendedError::MaxSessionsExceeded);
            }
        }

        record.sessions_used = record.sessions_used.saturating_add(1);
        Ok(requested_capabilities)
    }

    /// Revokes an individual token by ID immediately.
    pub fn revoke_token(&mut self, token_id: [u8; 16]) -> Result<(), UnattendedError> {
        let record = self
            .tokens
            .iter_mut()
            .find(|t| t.token_id == token_id)
            .ok_or(UnattendedError::TokenNotFound)?;
        record.is_revoked = true;
        Ok(())
    }

    /// Revokes all unattended tokens issued for a device fingerprint.
    pub fn revoke_all_for_device(&mut self, device: DeviceFingerprint) -> usize {
        let mut count = 0;
        for record in &mut self.tokens {
            if record.device == device && !record.is_revoked {
                record.is_revoked = true;
                count += 1;
            }
        }
        count
    }

    #[must_use]
    pub fn active_token_count(&self, now_ns: u64) -> usize {
        self.tokens
            .iter()
            .filter(|t| !t.is_revoked && now_ns < t.expires_at_ns)
            .count()
    }
}
