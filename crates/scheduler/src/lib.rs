//! Bounded, deadline-aware send scheduler.
//!
//! Optimized for the hot send path: single heap allocation at creation
//! (`Vec::with_capacity`), zero per-push/per-pop allocation, `&` borrows
//! for inspection, and `#[inline]` on tiny comparators.

use std::time::Instant;

/// Logical channel priority. Lower rank is more urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityClass {
    Input,
    Control,
    RecoveryVideo,
    RealtimeVideo,
    Audio,
    Refinement,
}

impl PriorityClass {
    #[inline]
    const fn rank(self) -> u8 {
        match self {
            Self::Input => 0,
            Self::Control => 1,
            Self::RecoveryVideo => 2,
            Self::RealtimeVideo => 3,
            Self::Audio => 4,
            Self::Refinement => 5,
        }
    }
}

/// One queued payload. Payload bytes live in the transport layer.
#[derive(Debug, Clone)]
pub struct ScheduledItem {
    pub id: u64,
    pub class: PriorityClass,
    pub deadline: Instant,
    pub payload_bytes: usize,
}

/// Result of an enqueue attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Inserted { evicted: usize },
    RejectedOversize,
    RejectedCapacity,
}

/// Queue with explicit item and byte caps.
///
/// Inline preallocation: `items` is created with `Vec::with_capacity(max_items)`
/// so the hot `push`/`pop_next` path performs no reallocation until `max_items`
/// is reached. For `max_items <= 8` this is a single heap allocation at
/// construction; if strict heap-free inline storage is ever required the field
/// can be switched to `SmallVec<[ScheduledItem; 8]>` without changing the
/// public API.
#[derive(Debug)]
pub struct DeadlineScheduler {
    max_items: usize,
    max_bytes: usize,
    queued_bytes: usize,
    items: Vec<ScheduledItem>,
}

impl DeadlineScheduler {
    /// Creates a scheduler with nonzero caps.
    ///
    /// Preallocates `max_items` slots inline so steady-state push/pop is
    /// allocation-free.
    #[must_use]
    #[inline]
    pub fn new(max_items: usize, max_bytes: usize) -> Self {
        assert!(max_items > 0, "max_items must be nonzero");
        assert!(max_bytes > 0, "max_bytes must be nonzero");
        Self {
            max_items,
            max_bytes,
            queued_bytes: 0,
            items: Vec::with_capacity(max_items),
        }
    }

    /// Inserts one item, first dropping expired items and then allowing a more
    /// urgent item to evict less urgent work. Equal-priority work is not silently
    /// evicted; callers must apply class-specific policy.
    #[inline]
    pub fn push(&mut self, item: ScheduledItem, now: Instant) -> PushOutcome {
        if item.payload_bytes > self.max_bytes {
            return PushOutcome::RejectedOversize;
        }
        let mut evicted = self.drop_expired(now);

        while self.items.len() >= self.max_items
            || self.queued_bytes.saturating_add(item.payload_bytes) > self.max_bytes
        {
            // Borrowed scan: no allocation, no `collect`. Uses `&` refs and a
            // single `max_by` over an iterator with capacity hint via `iter()`.
            let victim = self
                .items
                .iter()
                .enumerate()
                .filter(|(_, queued)| queued.class.rank() > item.class.rank())
                .max_by(|(_, a), (_, b)| {
                    a.class
                        .rank()
                        .cmp(&b.class.rank())
                        .then_with(|| a.deadline.cmp(&b.deadline))
                        .then_with(|| a.id.cmp(&b.id))
                })
                .map(|(index, _)| index);
            let Some(index) = victim else {
                return PushOutcome::RejectedCapacity;
            };
            let removed = self.items.swap_remove(index);
            self.queued_bytes -= removed.payload_bytes;
            evicted += 1;
        }

        self.queued_bytes += item.payload_bytes;
        // `reserve` is not needed because `Vec::with_capacity(max_items)` was
        // done at construction; this push is allocation-free in steady state.
        self.items.push(item);
        PushOutcome::Inserted { evicted }
    }

    /// Pops the highest-priority nonexpired item, breaking ties by deadline then id.
    #[inline]
    pub fn pop_next(&mut self, now: Instant) -> Option<ScheduledItem> {
        self.drop_expired(now);
        let index = self
            .items
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| {
                a.class
                    .rank()
                    .cmp(&b.class.rank())
                    .then_with(|| a.deadline.cmp(&b.deadline))
                    .then_with(|| a.id.cmp(&b.id))
            })
            .map(|(index, _)| index)?;
        let item = self.items.swap_remove(index);
        self.queued_bytes -= item.payload_bytes;
        Some(item)
    }

    /// Peeks the highest-priority nonexpired item by reference without cloning.
    #[inline]
    #[must_use]
    pub fn peek(&self, now: Instant) -> Option<&ScheduledItem> {
        // Non-mutating peek: caller provides `now`; we cannot mutate to drop
        // expired, so we filter expired on the fly and return a `&` borrow.
        self.items
            .iter()
            .filter(|item| item.deadline > now)
            .min_by(|a, b| {
                a.class
                    .rank()
                    .cmp(&b.class.rank())
                    .then_with(|| a.deadline.cmp(&b.deadline))
                    .then_with(|| a.id.cmp(&b.id))
            })
    }

    /// Borrows the queued items slice without cloning.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[ScheduledItem] {
        &self.items
    }

    /// Iterates queued items by `&` reference.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, ScheduledItem> {
        self.items.iter()
    }

    /// Number of queued items.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when no work is queued.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Total queued payload bytes.
    #[inline]
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Capacity hint for diagnostics: preallocated slots.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.items.capacity()
    }

    #[inline]
    fn drop_expired(&mut self, now: Instant) -> usize {
        let mut dropped = 0;
        let mut index = 0;
        // Swap-remove loop is allocation-free and cache-friendly: linear scan
        // with no `collect` and no secondary Vec.
        while index < self.items.len() {
            if self.items[index].deadline <= now {
                let removed = self.items.swap_remove(index);
                self.queued_bytes -= removed.payload_bytes;
                dropped += 1;
            } else {
                index += 1;
            }
        }
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn item(id: u64, class: PriorityClass, deadline: Instant, bytes: usize) -> ScheduledItem {
        ScheduledItem {
            id,
            class,
            deadline,
            payload_bytes: bytes,
        }
    }

    #[test]
    fn input_preempts_video_when_full() {
        let now = Instant::now();
        let mut queue = DeadlineScheduler::new(1, 1_000);
        assert_eq!(
            queue.push(
                item(
                    1,
                    PriorityClass::RealtimeVideo,
                    now + Duration::from_secs(1),
                    900
                ),
                now
            ),
            PushOutcome::Inserted { evicted: 0 }
        );
        assert_eq!(
            queue.push(
                item(2, PriorityClass::Input, now + Duration::from_millis(20), 20),
                now
            ),
            PushOutcome::Inserted { evicted: 1 }
        );
        assert_eq!(queue.pop_next(now).expect("input").id, 2);
    }

    #[test]
    fn stale_media_is_removed() {
        let now = Instant::now();
        let mut queue = DeadlineScheduler::new(4, 1_000);
        queue.push(
            item(1, PriorityClass::RealtimeVideo, now, 500),
            now - Duration::from_millis(1),
        );
        assert!(queue.pop_next(now).is_none());
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[test]
    fn equal_priority_is_not_silently_evicted() {
        let now = Instant::now();
        let mut queue = DeadlineScheduler::new(1, 100);
        queue.push(
            item(1, PriorityClass::Control, now + Duration::from_secs(1), 50),
            now,
        );
        assert_eq!(
            queue.push(
                item(
                    2,
                    PriorityClass::Control,
                    now + Duration::from_millis(1),
                    50
                ),
                now
            ),
            PushOutcome::RejectedCapacity
        );
    }

    #[test]
    fn peek_borrows_without_clone() {
        let now = Instant::now();
        let mut queue = DeadlineScheduler::new(4, 1_000);
        queue.push(
            item(1, PriorityClass::Audio, now + Duration::from_secs(1), 10),
            now,
        );
        queue.push(
            item(2, PriorityClass::Input, now + Duration::from_secs(1), 10),
            now,
        );
        let peeked = queue.peek(now).expect("peek");
        assert_eq!(peeked.id, 2);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn preallocation_avoids_realloc() {
        let queue = DeadlineScheduler::new(16, 10_000);
        assert!(queue.capacity() >= 16);
    }
}
