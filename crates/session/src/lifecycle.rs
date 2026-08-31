//! Product-session lifecycle stamp allocation for reconnect fencing.

use core::fmt;
use latencydesk_protocol::quic::SessionStamp;
use std::time::Duration;

const MAX_ZERO_ID_RETRIES: usize = 4;
pub const MAX_RECONNECT_ATTEMPTS: u32 = 8;
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(2);
const RECONNECT_BASE_DELAY_MILLIS: [u64; 5] = [100, 200, 400, 800, 1_600];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductStampAllocationError {
    RngFailure,
    ZeroSessionId,
    EpochExhausted,
}

impl fmt::Display for ProductStampAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProductStampAllocationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectPolicyError {
    TooManyAttempts,
}

impl fmt::Display for ReconnectPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ReconnectPolicyError {}

/// Bounded exponential reconnect delay with deterministic per-session jitter.
/// The random session identity naturally desynchronizes clients without adding
/// another fallible entropy read to the recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    maximum_attempts: u32,
}

impl ReconnectPolicy {
    pub const fn new(maximum_attempts: u32) -> Result<Self, ReconnectPolicyError> {
        if maximum_attempts > MAX_RECONNECT_ATTEMPTS {
            return Err(ReconnectPolicyError::TooManyAttempts);
        }
        Ok(Self { maximum_attempts })
    }

    #[must_use]
    pub const fn maximum_attempts(self) -> u32 {
        self.maximum_attempts
    }

    #[must_use]
    pub fn delay_for(self, attempt: u32, prior_session_id: u64) -> Option<Duration> {
        if attempt == 0 || attempt > self.maximum_attempts {
            return None;
        }
        let schedule_index = usize::try_from(attempt.saturating_sub(1).min(4)).ok()?;
        let base_millis = RECONNECT_BASE_DELAY_MILLIS[schedule_index];
        let jitter_span = base_millis / 4;
        let jitter_attempt = u64::from(attempt.min(5));
        let mut mixed = prior_session_id ^ jitter_attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^= mixed >> 31;
        let jitter_millis = mixed % jitter_span.saturating_add(1);
        Some(Duration::from_millis(
            base_millis.saturating_add(jitter_millis),
        ))
    }
}

/// Allocates fresh random session IDs and strictly monotonic lifecycle epochs.
#[derive(Debug, Clone)]
pub struct ProductStampAllocator {
    next_generation: u64,
    next_authorization_epoch: u32,
    next_display_epoch: u32,
    next_codec_epoch: u32,
}

impl Default for ProductStampAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProductStampAllocator {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_generation: 1,
            next_authorization_epoch: 1,
            next_display_epoch: 1,
            next_codec_epoch: 1,
        }
    }

    pub fn allocate(&mut self) -> Result<SessionStamp, ProductStampAllocationError> {
        self.allocate_with(&mut |bytes| {
            getrandom::getrandom(bytes).map_err(|_| ProductStampAllocationError::RngFailure)
        })
    }

    fn allocate_with(
        &mut self,
        fill_random: &mut impl FnMut(&mut [u8; 8]) -> Result<(), ProductStampAllocationError>,
    ) -> Result<SessionStamp, ProductStampAllocationError> {
        let following_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ProductStampAllocationError::EpochExhausted)?;
        let following_authorization = self
            .next_authorization_epoch
            .checked_add(1)
            .ok_or(ProductStampAllocationError::EpochExhausted)?;
        let following_display = self
            .next_display_epoch
            .checked_add(1)
            .ok_or(ProductStampAllocationError::EpochExhausted)?;
        let following_codec = self
            .next_codec_epoch
            .checked_add(1)
            .ok_or(ProductStampAllocationError::EpochExhausted)?;

        let mut session_id = 0_u64;
        for _ in 0..MAX_ZERO_ID_RETRIES {
            let mut bytes = [0_u8; 8];
            fill_random(&mut bytes)?;
            session_id = u64::from_be_bytes(bytes);
            if session_id != 0 {
                break;
            }
        }
        if session_id == 0 {
            return Err(ProductStampAllocationError::ZeroSessionId);
        }

        let stamp = SessionStamp {
            session_id,
            generation: self.next_generation,
            authorization_epoch: self.next_authorization_epoch,
            display_epoch: self.next_display_epoch,
            codec_epoch: self.next_codec_epoch,
            route_epoch: 1,
        };
        self.next_generation = following_generation;
        self.next_authorization_epoch = following_authorization;
        self.next_display_epoch = following_display;
        self.next_codec_epoch = following_codec;
        Ok(stamp)
    }

    #[cfg(test)]
    const fn with_next_for_test(
        generation: u64,
        authorization_epoch: u32,
        display_epoch: u32,
        codec_epoch: u32,
    ) -> Self {
        Self {
            next_generation: generation,
            next_authorization_epoch: authorization_epoch,
            next_display_epoch: display_epoch,
            next_codec_epoch: codec_epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_issues_fresh_ids_and_strictly_new_product_epochs() {
        let mut allocator = ProductStampAllocator::new();
        let mut next_id = 40_u64;
        let mut fill = |bytes: &mut [u8; 8]| {
            next_id += 1;
            *bytes = next_id.to_be_bytes();
            Ok(())
        };

        let first = allocator.allocate_with(&mut fill).expect("first stamp");
        let second = allocator.allocate_with(&mut fill).expect("successor stamp");
        assert_eq!(first.session_id, 41);
        assert_eq!(second.session_id, 42);
        assert!(second.generation > first.generation);
        assert!(second.authorization_epoch > first.authorization_epoch);
        assert!(second.display_epoch > first.display_epoch);
        assert!(second.codec_epoch > first.codec_epoch);
        assert_eq!(first.route_epoch, 1);
        assert_eq!(second.route_epoch, 1);
    }

    #[test]
    fn allocator_retries_zero_id_and_fails_closed_on_epoch_exhaustion() {
        let mut allocator = ProductStampAllocator::new();
        let mut calls = 0;
        let stamp = allocator
            .allocate_with(&mut |bytes| {
                calls += 1;
                *bytes = if calls == 1 { 0 } else { 9_u64 }.to_be_bytes();
                Ok(())
            })
            .expect("zero id is retried");
        assert_eq!(stamp.session_id, 9);
        assert_eq!(calls, 2);

        let mut exhausted =
            ProductStampAllocator::with_next_for_test(u64::MAX, u32::MAX, u32::MAX, u32::MAX);
        assert_eq!(
            exhausted.allocate_with(&mut |bytes| {
                *bytes = 10_u64.to_be_bytes();
                Ok(())
            }),
            Err(ProductStampAllocationError::EpochExhausted)
        );
    }

    #[test]
    fn reconnect_policy_is_bounded_capped_and_session_jittered() {
        assert_eq!(
            ReconnectPolicy::new(MAX_RECONNECT_ATTEMPTS + 1),
            Err(ReconnectPolicyError::TooManyAttempts)
        );
        let disabled = ReconnectPolicy::new(0).expect("disabled policy");
        assert_eq!(disabled.delay_for(1, 41), None);

        let policy = ReconnectPolicy::new(8).expect("bounded policy");
        let delays = (1..=8)
            .map(|attempt| policy.delay_for(attempt, 41).expect("retry delay"))
            .collect::<Vec<_>>();
        assert!(delays.windows(2).all(|pair| pair[1] >= pair[0]));
        assert!(delays.iter().all(|delay| *delay <= MAX_RECONNECT_DELAY));
        assert_eq!(policy.delay_for(9, 41), None);
        assert_eq!(policy.delay_for(0, 41), None);
        assert_eq!(policy.delay_for(3, 41), policy.delay_for(3, 41));
        assert_ne!(policy.delay_for(3, 41), policy.delay_for(3, 42));
    }
}
