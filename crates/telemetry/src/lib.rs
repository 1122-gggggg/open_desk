//! Per-frame latency telemetry with explicit clock-domain boundaries.
//!
//! Host and client timestamps are never subtracted from one another. Optical
//! input-to-photon measurements remain the source of truth for end-to-end latency.

use std::collections::VecDeque;
use std::fmt::Write as _;

/// Timestamps measured entirely in the host monotonic clock domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFrameTrace {
    pub frame_id: u64,
    pub capture_done_ns: u64,
    pub encode_begin_ns: u64,
    pub encode_done_ns: u64,
    pub send_ns: u64,
}

/// Validated host stage durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostDurations {
    pub capture_to_encode_ns: u64,
    pub encode_ns: u64,
    pub post_encode_queue_ns: u64,
}

impl HostFrameTrace {
    /// Computes durations only when every timestamp is monotonic.
    #[must_use]
    pub fn durations(self) -> Option<HostDurations> {
        Some(HostDurations {
            capture_to_encode_ns: self.encode_begin_ns.checked_sub(self.capture_done_ns)?,
            encode_ns: self.encode_done_ns.checked_sub(self.encode_begin_ns)?,
            post_encode_queue_ns: self.send_ns.checked_sub(self.encode_done_ns)?,
        })
    }
}

/// Timestamps measured entirely in the client monotonic clock domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFrameTrace {
    pub frame_id: u64,
    pub receive_ns: u64,
    pub decode_begin_ns: u64,
    pub decode_done_ns: u64,
    pub present_submit_ns: u64,
}

/// Validated client stage durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDurations {
    pub receive_queue_ns: u64,
    pub decode_ns: u64,
    pub post_decode_queue_ns: u64,
}

impl ClientFrameTrace {
    /// Computes durations only when every timestamp is monotonic.
    #[must_use]
    pub fn durations(self) -> Option<ClientDurations> {
        Some(ClientDurations {
            receive_queue_ns: self.decode_begin_ns.checked_sub(self.receive_ns)?,
            decode_ns: self.decode_done_ns.checked_sub(self.decode_begin_ns)?,
            post_decode_queue_ns: self.present_submit_ns.checked_sub(self.decode_done_ns)?,
        })
    }
}

/// Optional network clock model. This is an estimate, never optical ground truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockEstimate {
    pub remote_minus_local_ns: i64,
    pub uncertainty_ns: u64,
    pub sample_count: u32,
}

impl ClockEstimate {
    #[must_use]
    pub const fn is_usable(self, max_uncertainty_ns: u64, min_samples: u32) -> bool {
        self.uncertainty_ns <= max_uncertainty_ns && self.sample_count >= min_samples
    }
}

/// One complete laboratory record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTraceRecord {
    pub host: HostFrameTrace,
    pub client: ClientFrameTrace,
    pub encoded_bytes: u64,
    pub datagrams: u32,
    pub recovery_count: u32,
}

impl FrameTraceRecord {
    #[must_use]
    pub fn valid(self) -> bool {
        self.host.frame_id == self.client.frame_id
            && self.host.durations().is_some()
            && self.client.durations().is_some()
    }
}

/// Result of inserting a trace into a bounded collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracePushOutcome {
    Inserted,
    EvictedOldest,
    RejectedNonMonotonic,
}

/// Nearest-rank distribution summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Percentiles {
    pub count: usize,
    pub minimum: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub maximum: u64,
}

impl Percentiles {
    #[must_use]
    pub fn from_samples(samples: &[u64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Some(Self {
            count: sorted.len(),
            minimum: sorted[0],
            p50: percentile(&sorted, 50),
            p95: percentile(&sorted, 95),
            p99: percentile(&sorted, 99),
            maximum: sorted[sorted.len() - 1],
        })
    }
}

/// Same-clock-domain stage summaries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TraceSummary {
    pub records: usize,
    pub rejected: u64,
    pub evicted: u64,
    pub host_capture_to_encode_ns: Option<Percentiles>,
    pub host_encode_ns: Option<Percentiles>,
    pub host_post_encode_queue_ns: Option<Percentiles>,
    pub client_receive_queue_ns: Option<Percentiles>,
    pub client_decode_ns: Option<Percentiles>,
    pub client_post_decode_queue_ns: Option<Percentiles>,
}

/// Explicitly bounded trace collector with dependency-free CSV and JSON output.
#[derive(Debug, Clone)]
pub struct TraceCollector {
    max_records: usize,
    records: VecDeque<FrameTraceRecord>,
    rejected: u64,
    evicted: u64,
}

impl TraceCollector {
    #[must_use]
    pub fn new(max_records: usize) -> Self {
        assert!(max_records > 0, "max_records must be nonzero");
        Self {
            max_records,
            records: VecDeque::with_capacity(max_records.min(4_096)),
            rejected: 0,
            evicted: 0,
        }
    }

    pub fn push(&mut self, record: FrameTraceRecord) -> TracePushOutcome {
        if !record.valid() {
            self.rejected = self.rejected.saturating_add(1);
            return TracePushOutcome::RejectedNonMonotonic;
        }
        let outcome = if self.records.len() == self.max_records {
            let _ = self.records.pop_front();
            self.evicted = self.evicted.saturating_add(1);
            TracePushOutcome::EvictedOldest
        } else {
            TracePushOutcome::Inserted
        };
        self.records.push_back(record);
        outcome
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub const fn rejected(&self) -> u64 {
        self.rejected
    }

    #[must_use]
    pub const fn evicted(&self) -> u64 {
        self.evicted
    }

    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut output = String::from(
            "frame_id,host_capture_done_ns,host_encode_begin_ns,host_encode_done_ns,host_send_ns,client_receive_ns,client_decode_begin_ns,client_decode_done_ns,client_present_submit_ns,encoded_bytes,datagrams,recovery_count\n",
        );
        for record in &self.records {
            let _ = writeln!(
                output,
                "{},{},{},{},{},{},{},{},{},{},{},{}",
                record.host.frame_id,
                record.host.capture_done_ns,
                record.host.encode_begin_ns,
                record.host.encode_done_ns,
                record.host.send_ns,
                record.client.receive_ns,
                record.client.decode_begin_ns,
                record.client.decode_done_ns,
                record.client.present_submit_ns,
                record.encoded_bytes,
                record.datagrams,
                record.recovery_count,
            );
        }
        output
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        let mut output = String::from(
            "{\"schema\":1,\"clock_domains\":\"host_and_client_separate\",\"records\":[",
        );
        for (index, record) in self.records.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let _ = write!(
                output,
                concat!(
                    "{{\"frame_id\":{},",
                    "\"host\":{{\"capture_done_ns\":{},\"encode_begin_ns\":{},",
                    "\"encode_done_ns\":{},\"send_ns\":{}}},",
                    "\"client\":{{\"receive_ns\":{},\"decode_begin_ns\":{},",
                    "\"decode_done_ns\":{},\"present_submit_ns\":{}}},",
                    "\"encoded_bytes\":{},\"datagrams\":{},\"recovery_count\":{}}}"
                ),
                record.host.frame_id,
                record.host.capture_done_ns,
                record.host.encode_begin_ns,
                record.host.encode_done_ns,
                record.host.send_ns,
                record.client.receive_ns,
                record.client.decode_begin_ns,
                record.client.decode_done_ns,
                record.client.present_submit_ns,
                record.encoded_bytes,
                record.datagrams,
                record.recovery_count,
            );
        }
        let _ = write!(
            output,
            "],\"rejected\":{},\"evicted\":{}}}",
            self.rejected, self.evicted
        );
        output
    }

    #[must_use]
    pub fn summary(&self) -> TraceSummary {
        let mut host_capture_to_encode = Vec::with_capacity(self.records.len());
        let mut host_encode = Vec::with_capacity(self.records.len());
        let mut host_post_encode_queue = Vec::with_capacity(self.records.len());
        let mut client_receive_queue = Vec::with_capacity(self.records.len());
        let mut client_decode = Vec::with_capacity(self.records.len());
        let mut client_post_decode_queue = Vec::with_capacity(self.records.len());
        for record in &self.records {
            let host = record.host.durations().expect("validated before insertion");
            let client = record
                .client
                .durations()
                .expect("validated before insertion");
            host_capture_to_encode.push(host.capture_to_encode_ns);
            host_encode.push(host.encode_ns);
            host_post_encode_queue.push(host.post_encode_queue_ns);
            client_receive_queue.push(client.receive_queue_ns);
            client_decode.push(client.decode_ns);
            client_post_decode_queue.push(client.post_decode_queue_ns);
        }
        TraceSummary {
            records: self.records.len(),
            rejected: self.rejected,
            evicted: self.evicted,
            host_capture_to_encode_ns: Percentiles::from_samples(&host_capture_to_encode),
            host_encode_ns: Percentiles::from_samples(&host_encode),
            host_post_encode_queue_ns: Percentiles::from_samples(&host_post_encode_queue),
            client_receive_queue_ns: Percentiles::from_samples(&client_receive_queue),
            client_decode_ns: Percentiles::from_samples(&client_decode),
            client_post_decode_queue_ns: Percentiles::from_samples(&client_post_decode_queue),
        }
    }
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let numerator = sorted.len().saturating_mul(percentile);
    let rank = numerator
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(0)
        .saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(frame_id: u64) -> FrameTraceRecord {
        FrameTraceRecord {
            host: HostFrameTrace {
                frame_id,
                capture_done_ns: 10,
                encode_begin_ns: 12,
                encode_done_ns: 20,
                send_ns: 21,
            },
            client: ClientFrameTrace {
                frame_id,
                receive_ns: 30,
                decode_begin_ns: 31,
                decode_done_ns: 36,
                present_submit_ns: 38,
            },
            encoded_bytes: 100,
            datagrams: 2,
            recovery_count: 0,
        }
    }

    #[test]
    fn nearest_rank_percentiles_are_stable() {
        let samples: Vec<u64> = (1..=100).collect();
        let summary = Percentiles::from_samples(&samples).expect("nonempty");
        assert_eq!(summary.p50, 50);
        assert_eq!(summary.p95, 95);
        assert_eq!(summary.p99, 99);
    }

    #[test]
    fn collector_evicts_oldest_and_exports_clock_domains() {
        let mut collector = TraceCollector::new(2);
        assert_eq!(collector.push(record(1)), TracePushOutcome::Inserted);
        assert_eq!(collector.push(record(2)), TracePushOutcome::Inserted);
        assert_eq!(collector.push(record(3)), TracePushOutcome::EvictedOldest);
        let csv = collector.to_csv();
        assert!(!csv.lines().any(|line| line.starts_with("1,")));
        assert!(csv.lines().any(|line| line.starts_with("3,")));
        let json = collector.to_json();
        assert!(json.contains("host_and_client_separate"));
        assert_eq!(collector.evicted(), 1);
    }

    #[test]
    fn non_monotonic_record_is_rejected() {
        let mut invalid = record(1);
        invalid.host.encode_done_ns = 1;
        let mut collector = TraceCollector::new(1);
        assert_eq!(
            collector.push(invalid),
            TracePushOutcome::RejectedNonMonotonic
        );
        assert!(collector.is_empty());
    }
}
