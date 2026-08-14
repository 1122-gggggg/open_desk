//! Deterministic end-to-end laboratory shared by CLI, CI, and stress tests.

use latencydesk_frame::{FakeCapture, FakeCaptureConfig, FrameError, Pattern, PixelFormat};
use latencydesk_input::{InputEvent, InputMessage, InputReconciler, InputState, ReconcileOutcome};
use latencydesk_protocol::{media_flags, MediaKind, ProtocolError};
use latencydesk_telemetry::{
    ClientFrameTrace, FrameTraceRecord, HostFrameTrace, TraceCollector, TraceSummary,
};
use latencydesk_test_codec::{CodecError as TestCodecError, ExactTestCodec};
use latencydesk_transport::{
    fragment_frame, FragmentSpec, IngestOutcome, NetworkLane, NetworkProfile, NetworkSimulator,
    Reassembler, ReassemblyConfig, SimPacket, TransportError, DEFAULT_MAX_DATAGRAM_BYTES,
};
use std::fmt;
use std::time::Instant;

/// Reproducible laboratory configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabConfig {
    pub frames: u64,
    pub width: u32,
    pub height: u32,
    pub max_datagram_bytes: usize,
    pub frame_interval_ns: u64,
    pub frame_deadline_ns: u64,
    pub network: NetworkProfile,
    pub seed: u64,
}

impl Default for LabConfig {
    fn default() -> Self {
        Self {
            frames: 120,
            width: 320,
            height: 180,
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
            frame_interval_ns: 16_666_667,
            frame_deadline_ns: 250_000_000,
            network: NetworkProfile::default(),
            seed: 0x4c44_534b_0000_0001,
        }
    }
}

impl LabConfig {
    pub fn validate(self) -> Result<(), LabError> {
        if self.frames == 0
            || self.width == 0
            || self.height == 0
            || self.frame_interval_ns == 0
            || self.frame_deadline_ns <= self.frame_interval_ns
        {
            return Err(LabError::InvalidConfig);
        }
        self.network.validate().map_err(LabError::Transport)?;
        Ok(())
    }
}

/// Observable laboratory result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabReport {
    pub submitted_frames: u64,
    pub completed_frames: u64,
    pub incomplete_frames: u64,
    pub corrupt_or_malformed_datagrams: u64,
    pub exact_mismatches: u64,
    pub input_reconciliation_passed: bool,
    pub network_submitted: u64,
    pub network_delivered: u64,
    pub network_lost: u64,
    pub network_expired: u64,
    pub network_corrupted: u64,
    pub reassembly_completed: u64,
    pub reassembly_expired: u64,
    pub trace_records: usize,
}

impl LabReport {
    #[must_use]
    pub fn lossless_passed(self) -> bool {
        self.completed_frames == self.submitted_frames
            && self.incomplete_frames == 0
            && self.exact_mismatches == 0
            && self.input_reconciliation_passed
    }
}

/// Runs capture → exact encode → fragment → hostile link → reassemble → exact decode.
pub fn run_lab(config: LabConfig) -> Result<(LabReport, TraceCollector), LabError> {
    config.validate()?;
    let mut capture = FakeCapture::new(FakeCaptureConfig {
        width: config.width,
        height: config.height,
        format: PixelFormat::Bgra8,
        pattern: Pattern::TextLike,
        seed: config.seed,
    })
    .map_err(LabError::Frame)?;
    let mut network = NetworkSimulator::new(config.network, config.seed ^ 0xa5a5_5a5a)
        .map_err(LabError::Transport)?;
    let mut reassembler =
        Reassembler::new(ReassemblyConfig::default()).map_err(LabError::Transport)?;
    let mut traces = TraceCollector::new(config.frames.min(100_000) as usize);
    let origin = Instant::now();
    let mut completed_frames = 0_u64;
    let mut incomplete_frames = 0_u64;
    let mut corrupt_or_malformed_datagrams = 0_u64;
    let mut exact_mismatches = 0_u64;

    for frame_id in 0..config.frames {
        let capture_timestamp_ns = frame_id.saturating_mul(config.frame_interval_ns);
        let frame = capture
            .capture(capture_timestamp_ns)
            .map_err(LabError::Frame)?;
        let capture_done_ns = elapsed_ns(origin);
        let encode_begin_ns = elapsed_ns(origin);
        let encoded = ExactTestCodec::encode(&frame).map_err(LabError::Codec)?;
        let encode_done_ns = elapsed_ns(origin);
        let datagrams = fragment_frame(
            FragmentSpec {
                kind: MediaKind::Video,
                flags: media_flags::KEYFRAME | media_flags::LOSSLESS,
                stream_id: 1,
                codec_epoch: 1,
                frame_id,
                dependency_frame_id: None,
            },
            &encoded,
            config.max_datagram_bytes,
        )
        .map_err(LabError::Transport)?;

        let send_time_ns = frame_id.saturating_mul(config.frame_interval_ns);
        let deadline_ns = send_time_ns.saturating_add(config.frame_deadline_ns);
        for (fragment_index, datagram) in datagrams.iter().enumerate() {
            let packet_id = frame_id
                .checked_mul(1_000_000)
                .and_then(|base| base.checked_add(fragment_index as u64))
                .ok_or(LabError::Arithmetic)?;
            let _submission = network
                .submit(SimPacket {
                    id: packet_id,
                    lane: NetworkLane::RealtimeMedia,
                    send_ns: send_time_ns,
                    deadline_ns,
                    bytes: datagram.clone(),
                })
                .map_err(LabError::Transport)?;
        }
        let send_ns = elapsed_ns(origin);

        let poll_until_ns = deadline_ns.saturating_add(config.network.base_delay_ns);
        let mut reconstructed = None;
        for packet in network.poll(poll_until_ns) {
            match reassembler.ingest(&packet.packet.bytes, packet.delivery_ns) {
                Ok(IngestOutcome::Complete(frame)) if frame.header.frame_id == frame_id => {
                    reconstructed = Some(frame.bytes);
                }
                Ok(
                    IngestOutcome::Complete(_)
                    | IngestOutcome::Pending { .. }
                    | IngestOutcome::Duplicate { .. },
                ) => {}
                Err(_) => {
                    corrupt_or_malformed_datagrams =
                        corrupt_or_malformed_datagrams.saturating_add(1);
                }
            }
        }

        if let Some(access_unit) = reconstructed {
            let receive_ns = elapsed_ns(origin);
            let decode_begin_ns = elapsed_ns(origin);
            match ExactTestCodec::decode(&access_unit, receive_ns) {
                Ok(decoded) => {
                    let decode_done_ns = elapsed_ns(origin);
                    if decoded.data != frame.data || decoded.checksum64() != frame.checksum64() {
                        exact_mismatches = exact_mismatches.saturating_add(1);
                    } else {
                        completed_frames = completed_frames.saturating_add(1);
                    }
                    let present_submit_ns = elapsed_ns(origin);
                    let _ = traces.push(FrameTraceRecord {
                        host: HostFrameTrace {
                            frame_id,
                            capture_done_ns,
                            encode_begin_ns,
                            encode_done_ns,
                            send_ns,
                        },
                        client: ClientFrameTrace {
                            frame_id,
                            receive_ns,
                            decode_begin_ns,
                            decode_done_ns,
                            present_submit_ns,
                        },
                        encoded_bytes: encoded.len() as u64,
                        datagrams: datagrams.len() as u32,
                        recovery_count: 0,
                    });
                }
                Err(_) => {
                    exact_mismatches = exact_mismatches.saturating_add(1);
                }
            }
        } else {
            incomplete_frames = incomplete_frames.saturating_add(1);
        }
    }

    let final_time = config
        .frames
        .saturating_mul(config.frame_interval_ns)
        .saturating_add(config.frame_deadline_ns)
        .saturating_add(1);
    let _ = reassembler.expire(final_time);
    let network_stats = network.stats();
    let reassembly_stats = reassembler.stats();
    let report = LabReport {
        submitted_frames: config.frames,
        completed_frames,
        incomplete_frames,
        corrupt_or_malformed_datagrams,
        exact_mismatches,
        input_reconciliation_passed: input_reconciliation_probe()?,
        network_submitted: network_stats.submitted,
        network_delivered: network_stats.delivered,
        network_lost: network_stats.lost,
        network_expired: network_stats.expired,
        network_corrupted: network_stats.corrupted,
        reassembly_completed: reassembly_stats.frames_completed,
        reassembly_expired: reassembly_stats.frames_expired,
        trace_records: traces.len(),
    };
    Ok((report, traces))
}

/// Verifies that a lost key-up is repaired by the periodic state snapshot.
pub fn input_reconciliation_probe() -> Result<bool, LabError> {
    let mut reconciler = InputReconciler::default();
    let down = InputMessage {
        session_epoch: 7,
        sequence: 1,
        event: InputEvent::Key {
            code: 26,
            pressed: true,
        },
    };
    let encoded = down.encode().map_err(LabError::Input)?;
    let decoded = InputMessage::decode(&encoded).map_err(LabError::Input)?;
    let _ = reconciler.apply(decoded).map_err(LabError::Input)?;
    if !reconciler.state().key_pressed(26) {
        return Ok(false);
    }
    let snapshot = InputMessage {
        session_epoch: 7,
        sequence: 3,
        event: InputEvent::Snapshot(InputState::default()),
    };
    let outcome = reconciler.apply(snapshot).map_err(LabError::Input)?;
    Ok(matches!(outcome, ReconcileOutcome::Applied(_)) && reconciler.state().is_empty())
}

fn elapsed_ns(origin: Instant) -> u64 {
    origin.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

#[derive(Debug)]
pub enum LabError {
    InvalidConfig,
    Arithmetic,
    Frame(FrameError),
    Codec(TestCodecError),
    Protocol(ProtocolError),
    Transport(TransportError),
    Input(latencydesk_input::InputError),
}

impl fmt::Display for LabError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LabError {}

/// Reproducible run manifest containing configuration, outcome, and source revision.
#[must_use]
pub fn report_json(
    config: LabConfig,
    report: LabReport,
    summary: TraceSummary,
    commit: Option<&str>,
) -> String {
    let commit = commit.unwrap_or("unknown");
    format!(
        concat!(
            "{{\"schema\":1,\"commit\":\"{}\",",
            "\"config\":{{\"frames\":{},\"width\":{},\"height\":{},",
            "\"max_datagram_bytes\":{},\"frame_interval_ns\":{},",
            "\"frame_deadline_ns\":{},\"seed\":{},",
            "\"network\":{{\"base_delay_ns\":{},\"jitter_ns\":{},",
            "\"bandwidth_bps\":{},\"loss_per_million\":{},",
            "\"duplicate_per_million\":{},\"reorder_per_million\":{},",
            "\"corrupt_per_million\":{}}}}},",
            "\"result\":{}}}"
        ),
        json_escape(commit),
        config.frames,
        config.width,
        config.height,
        config.max_datagram_bytes,
        config.frame_interval_ns,
        config.frame_deadline_ns,
        config.seed,
        config.network.base_delay_ns,
        config.network.jitter_ns,
        config.network.bandwidth_bps,
        config.network.loss_per_million,
        config.network.duplicate_per_million,
        config.network.reorder_per_million,
        config.network.corrupt_per_million,
        summary_json(report, summary),
    )
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => escaped.push('?'),
            character => escaped.push(character),
        }
    }
    escaped
}

/// Convenience summary for CLI output.
#[must_use]
pub fn summary_json(report: LabReport, summary: TraceSummary) -> String {
    format!(
        concat!(
            "{{\"submitted_frames\":{},\"completed_frames\":{},",
            "\"incomplete_frames\":{},\"exact_mismatches\":{},",
            "\"malformed_datagrams\":{},\"input_reconciliation_passed\":{},",
            "\"network\":{{\"submitted\":{},\"delivered\":{},\"lost\":{},",
            "\"expired\":{},\"corrupted\":{}}},",
            "\"reassembly\":{{\"completed\":{},\"expired\":{}}},",
            "\"trace_records\":{},\"trace_rejected\":{},\"trace_evicted\":{}}}"
        ),
        report.submitted_frames,
        report.completed_frames,
        report.incomplete_frames,
        report.exact_mismatches,
        report.corrupt_or_malformed_datagrams,
        report.input_reconciliation_passed,
        report.network_submitted,
        report.network_delivered,
        report.network_lost,
        report.network_expired,
        report.network_corrupted,
        report.reassembly_completed,
        report.reassembly_expired,
        summary.records,
        summary.rejected,
        summary.evicted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossless_profile_reconstructs_every_frame() {
        let config = LabConfig {
            frames: 12,
            width: 96,
            height: 64,
            network: NetworkProfile {
                duplicate_per_million: 200_000,
                reorder_per_million: 300_000,
                ..NetworkProfile::default()
            },
            ..LabConfig::default()
        };
        let (report, _) = run_lab(config).expect("lab");
        assert!(report.lossless_passed());
    }

    #[test]
    fn lossy_profile_finishes_without_unbounded_state() {
        let config = LabConfig {
            frames: 30,
            width: 64,
            height: 48,
            network: NetworkProfile {
                loss_per_million: 50_000,
                corrupt_per_million: 10_000,
                ..NetworkProfile::default()
            },
            ..LabConfig::default()
        };
        let (report, _) = run_lab(config).expect("lab");
        assert_eq!(report.submitted_frames, 30);
        assert_eq!(
            report.completed_frames + report.incomplete_frames + report.exact_mismatches,
            30
        );
    }

    #[test]
    fn report_manifest_records_seed_and_commit() {
        let config = LabConfig {
            frames: 1,
            width: 32,
            height: 24,
            seed: 77,
            ..LabConfig::default()
        };
        let report = LabReport {
            submitted_frames: 1,
            completed_frames: 1,
            incomplete_frames: 0,
            corrupt_or_malformed_datagrams: 0,
            exact_mismatches: 0,
            input_reconciliation_passed: true,
            network_submitted: 1,
            network_delivered: 1,
            network_lost: 0,
            network_expired: 0,
            network_corrupted: 0,
            reassembly_completed: 1,
            reassembly_expired: 0,
            trace_records: 1,
        };
        let manifest = report_json(config, report, TraceSummary::default(), Some("abc123"));
        assert!(manifest.contains("\"commit\":\"abc123\""));
        assert!(manifest.contains("\"seed\":77"));
    }
}
