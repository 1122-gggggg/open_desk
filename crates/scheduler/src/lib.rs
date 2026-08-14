//! Bounded, deadline-aware send scheduler.

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
#[derive(Debug)]
pub struct DeadlineScheduler {
    max_items: usize,
    max_bytes: usize,
    queued_bytes: usize,
    items: Vec<ScheduledItem>,
}

impl DeadlineScheduler {
    /// Creates a scheduler with nonzero caps.
    #[must_use]
    pub fn new(max_items: usize, max_bytes: usize) -> Self {
        assert!(max_items > 0, "max_items must be nonzero");
        assert!(max_bytes > 0, "max_bytes must be nonzero");
        Self {
            max_items,
            max_bytes,
            queued_bytes: 0,
            items: Vec::new(),
        }
    }

    /// Inserts one item, first dropping expired items and then allowing a more
    /// urgent item to evict less urgent work. Equal-priority work is not silently
    /// evicted; callers must apply class-specific policy.
    pub fn push(&mut self, item: ScheduledItem, now: Instant) -> PushOutcome {
        if item.payload_bytes > self.max_bytes {
            return PushOutcome::RejectedOversize;
        }
        let mut evicted = self.drop_expired(now);

        while self.items.len() >= self.max_items
            || self.queued_bytes.saturating_add(item.payload_bytes) > self.max_bytes
        {
            let victim = self
                .items
                .iter()
                .enumerate()
                .filter(|(_, queued)| queued.class.rank() > item.class.rank())
                .max_by_key(|(_, queued)| (queued.class.rank(), queued.deadline, queued.id))
                .map(|(index, _)| index);
            let Some(index) = victim else {
                return PushOutcome::RejectedCapacity;
            };
            let removed = self.items.swap_remove(index);
            self.queued_bytes -= removed.payload_bytes;
            evicted += 1;
        }

        self.queued_bytes += item.payload_bytes;
        self.items.push(item);
        PushOutcome::Inserted { evicted }
    }

    /// Pops the highest-priority nonexpired item, breaking ties by deadline then id.
    pub fn pop_next(&mut self, now: Instant) -> Option<ScheduledItem> {
        self.drop_expired(now);
        let index = self
            .items
            .iter()
            .enumerate()
            .min_by_key(|(_, item)| (item.class.rank(), item.deadline, item.id))
            .map(|(index, _)| index)?;
        let item = self.items.swap_remove(index);
        self.queued_bytes -= item.payload_bytes;
        Some(item)
    }

    /// Number of queued items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when no work is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Total queued payload bytes.
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    fn drop_expired(&mut self, now: Instant) -> usize {
        let mut dropped = 0;
        let mut index = 0;
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
}
