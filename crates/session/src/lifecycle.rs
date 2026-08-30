//! Product-session lifecycle stamp allocation for reconnect fencing.

use core::fmt;
use latencydesk_protocol::quic::SessionStamp;

const MAX_ZERO_ID_RETRIES: usize = 4;

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
}
