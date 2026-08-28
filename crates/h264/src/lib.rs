//! H.264 low-delay policy and bounded Annex-B access-unit inspection.
//!
//! Native providers own vendor encoder/decoder APIs. This crate validates the
//! provider policy, rejects access units that introduce decoder reordering, and
//! emits conservative frame-dependency metadata for loss recovery.

use latencydesk_codec::{CodecError, CodecId, EncodedAccessUnit};
use latencydesk_media::EncodedFrameMeta;
use std::fmt;

mod software;
pub use software::{DecodedNv12, SoftwareH264Decoder, SoftwareH264Encoder};

pub const MAX_ACCESS_UNIT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NAL_UNITS: usize = 2_048;
pub const MAX_RBSP_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H264Profile {
    Baseline,
    Main,
    High,
    High444Predictive,
}

/// Provider-neutral low-delay policy. It describes intent; encoded output is
/// still inspected because vendor APIs may ignore unsupported properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowDelayPolicy {
    pub profile: H264Profile,
    pub b_frames: u8,
    pub lookahead_frames: u16,
    pub max_provider_queue: u8,
    pub intra_period_frames: u32,
    pub repeat_parameter_sets: bool,
}

/// Public compatibility name used by provider manifests.
pub type LowDelayH264Config = LowDelayPolicy;

impl LowDelayPolicy {
    #[must_use]
    pub const fn baseline(intra_period_frames: u32) -> Self {
        Self {
            profile: H264Profile::High,
            b_frames: 0,
            lookahead_frames: 0,
            // A second queued surface is a hidden frame of latency. The
            // product path drops/catches up at frame boundaries instead of
            // allowing an encoder or decoder backlog to form.
            max_provider_queue: 1,
            intra_period_frames,
            repeat_parameter_sets: true,
        }
    }

    pub fn validate(self) -> Result<Self, H264Error> {
        if self.b_frames != 0 {
            return Err(H264Error::BFrameForbidden);
        }
        if self.lookahead_frames != 0 {
            return Err(H264Error::LookaheadForbidden);
        }
        if self.max_provider_queue == 0 || self.max_provider_queue > 4 {
            return Err(H264Error::ProviderQueue);
        }
        if self.intra_period_frames == 0 || self.intra_period_frames > 100_000 {
            return Err(H264Error::IntraPeriod);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceClass {
    P,
    B,
    I,
    Sp,
    Si,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnnexBSummary {
    pub nal_units: u16,
    pub has_sps: bool,
    pub has_pps: bool,
    pub has_idr_slice: bool,
    pub has_non_idr_slice: bool,
    pub has_aud: bool,
    pub has_b_slice: bool,
}

impl AnnexBSummary {
    #[must_use]
    pub const fn contains_picture(self) -> bool {
        self.has_idr_slice || self.has_non_idr_slice
    }

    pub fn validate_low_delay(self) -> Result<Self, H264Error> {
        if self.has_b_slice {
            Err(H264Error::BFrameDetected)
        } else {
            Ok(self)
        }
    }

    pub fn continuity_meta(
        self,
        codec_epoch: u32,
        frame_id: u64,
        previous_frame_id: Option<u64>,
    ) -> Result<EncodedFrameMeta, H264Error> {
        self.validate_low_delay()?;
        if self.has_idr_slice {
            Ok(EncodedFrameMeta {
                codec_epoch,
                frame_id,
                dependency_frame_id: None,
                recovery_point: true,
            })
        } else {
            let dependency = previous_frame_id.ok_or(H264Error::RecoveryPointRequired)?;
            if dependency >= frame_id {
                return Err(H264Error::InvalidDependency);
            }
            Ok(EncodedFrameMeta {
                codec_epoch,
                frame_id,
                dependency_frame_id: Some(dependency),
                recovery_point: false,
            })
        }
    }
}

/// Inspects one complete Annex-B access unit with fixed global bounds.
pub fn inspect_annex_b(bytes: &[u8]) -> Result<AnnexBSummary, H264Error> {
    if bytes.is_empty() || bytes.len() > MAX_ACCESS_UNIT_BYTES {
        return Err(H264Error::AccessUnitSize(bytes.len()));
    }
    let starts = find_start_codes(bytes)?;
    let Some(&(first, _)) = starts.first() else {
        return Err(H264Error::MissingStartCode);
    };
    if bytes[..first].iter().any(|byte| *byte != 0) {
        return Err(H264Error::LeadingGarbage);
    }

    let mut summary = AnnexBSummary::default();
    for (index, &(start, prefix_len)) in starts.iter().enumerate() {
        let nal_start = start.checked_add(prefix_len).ok_or(H264Error::Malformed)?;
        let nal_end = starts.get(index + 1).map_or(bytes.len(), |(next, _)| *next);
        if nal_start >= nal_end {
            return Err(H264Error::Malformed);
        }
        let nal = &bytes[nal_start..nal_end];
        let header = nal[0];
        if header & 0x80 != 0 {
            return Err(H264Error::ForbiddenZeroBit);
        }
        let nal_type = header & 0x1f;
        summary.nal_units = summary
            .nal_units
            .checked_add(1)
            .ok_or(H264Error::TooManyNalUnits)?;
        match nal_type {
            1 | 5 => {
                let slice_class = parse_slice_class(&nal[1..])?;
                summary.has_b_slice |= slice_class == SliceClass::B;
                summary.has_non_idr_slice |= nal_type == 1;
                summary.has_idr_slice |= nal_type == 5;
            }
            2..=4 => return Err(H264Error::DataPartitionUnsupported),
            7 => summary.has_sps = true,
            8 => summary.has_pps = true,
            9 => summary.has_aud = true,
            0 | 24..=31 => return Err(H264Error::UnsupportedNalType(nal_type)),
            _ => {}
        }
    }
    if !summary.contains_picture() {
        return Err(H264Error::NoPicture);
    }
    if summary.has_idr_slice && summary.has_non_idr_slice {
        return Err(H264Error::MixedPictureTypes);
    }
    summary.validate_low_delay()
}

fn find_start_codes(bytes: &[u8]) -> Result<Vec<(usize, usize)>, H264Error> {
    let mut starts = Vec::new();
    let mut cursor = 0usize;
    while cursor + 3 <= bytes.len() {
        let prefix = if cursor + 4 <= bytes.len() && bytes[cursor..cursor + 4] == [0, 0, 0, 1] {
            Some(4)
        } else if bytes[cursor..cursor + 3] == [0, 0, 1] {
            Some(3)
        } else {
            None
        };
        if let Some(prefix) = prefix {
            if starts.len() == MAX_NAL_UNITS {
                return Err(H264Error::TooManyNalUnits);
            }
            starts.push((cursor, prefix));
            cursor = cursor.checked_add(prefix).ok_or(H264Error::Malformed)?;
        } else {
            cursor = cursor.checked_add(1).ok_or(H264Error::Malformed)?;
        }
    }
    Ok(starts)
}

fn parse_slice_class(ebsp: &[u8]) -> Result<SliceClass, H264Error> {
    let payload_len = ebsp
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    if payload_len == 0 {
        return Err(H264Error::TruncatedSlice);
    }
    let rbsp = unescape_rbsp_prefix(&ebsp[..payload_len], 64)?;
    let mut bits = BitReader::new(&rbsp);
    let _first_macroblock = bits.read_ue()?;
    let slice_type = bits.read_ue()?;
    match slice_type % 5 {
        0 => Ok(SliceClass::P),
        1 => Ok(SliceClass::B),
        2 => Ok(SliceClass::I),
        3 => Ok(SliceClass::Sp),
        4 => Ok(SliceClass::Si),
        _ => Err(H264Error::Malformed),
    }
}

fn unescape_rbsp_prefix(ebsp: &[u8], output_limit: usize) -> Result<Vec<u8>, H264Error> {
    if output_limit == 0
        || output_limit > MAX_RBSP_BYTES
        || ebsp.len() > MAX_RBSP_BYTES.saturating_add(MAX_RBSP_BYTES / 2)
    {
        return Err(H264Error::RbspLimit(ebsp.len()));
    }
    let mut rbsp = Vec::with_capacity(ebsp.len().min(output_limit));
    let mut zero_count = 0u8;
    let mut cursor = 0usize;
    while cursor < ebsp.len() && rbsp.len() < output_limit {
        let byte = ebsp[cursor];
        if zero_count >= 2 && byte <= 3 {
            if byte != 3 {
                return Err(H264Error::MalformedEscape(cursor, byte));
            }
            let next = ebsp
                .get(cursor + 1)
                .copied()
                .ok_or(H264Error::MalformedEscape(cursor, 0xff))?;
            if next > 3 {
                return Err(H264Error::MalformedEscape(cursor, next));
            }
            zero_count = 0;
            cursor += 1;
            continue;
        }
        rbsp.push(byte);
        zero_count = if byte == 0 {
            zero_count.saturating_add(1)
        } else {
            0
        };
        cursor += 1;
    }
    Ok(rbsp)
}

#[cfg(test)]
fn unescape_rbsp(ebsp: &[u8]) -> Result<Vec<u8>, H264Error> {
    unescape_rbsp_prefix(ebsp, MAX_RBSP_BYTES)
}

struct BitReader<'a> {
    bytes: &'a [u8],
    bit_offset: usize,
}

impl<'a> BitReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            bit_offset: 0,
        }
    }

    fn read_bit(&mut self) -> Result<u8, H264Error> {
        let byte = *self
            .bytes
            .get(self.bit_offset / 8)
            .ok_or(H264Error::TruncatedSlice)?;
        let bit = (byte >> (7 - self.bit_offset % 8)) & 1;
        self.bit_offset = self
            .bit_offset
            .checked_add(1)
            .ok_or(H264Error::ExpGolombOverflow)?;
        Ok(bit)
    }

    fn read_ue(&mut self) -> Result<u32, H264Error> {
        let mut leading = 0u32;
        while self.read_bit()? == 0 {
            leading = leading.checked_add(1).ok_or(H264Error::ExpGolombOverflow)?;
            if leading > 31 {
                return Err(H264Error::ExpGolombOverflow);
            }
        }
        let mut suffix = 0u32;
        for _ in 0..leading {
            suffix = suffix.checked_shl(1).ok_or(H264Error::ExpGolombOverflow)?
                | u32::from(self.read_bit()?);
        }
        let base = 1u32
            .checked_shl(leading)
            .ok_or(H264Error::ExpGolombOverflow)?
            .saturating_sub(1);
        base.checked_add(suffix).ok_or(H264Error::ExpGolombOverflow)
    }
}

/// Generates conservative application-level dependency metadata and blocks
/// dependent output after any known loss until a validated IDR arrives.
#[derive(Debug, Clone)]
pub struct ContinuityPlanner {
    codec_epoch: u32,
    next_frame_id: u64,
    last_transmitted: Option<u64>,
    recovery_requested: bool,
}

impl ContinuityPlanner {
    #[must_use]
    pub fn new(codec_epoch: u32, first_frame_id: u64) -> Self {
        assert!(codec_epoch > 0, "codec epoch must be nonzero");
        Self {
            codec_epoch,
            next_frame_id: first_frame_id,
            last_transmitted: None,
            recovery_requested: true,
        }
    }

    pub fn note_output_drop(&mut self) {
        self.recovery_requested = true;
    }

    #[must_use]
    pub const fn recovery_requested(&self) -> bool {
        self.recovery_requested
    }

    pub fn accept(&mut self, bytes: &[u8]) -> Result<EncodedFrameMeta, H264Error> {
        let summary = inspect_annex_b(bytes)?;
        let frame_id = self.next_frame_id;
        self.next_frame_id = self
            .next_frame_id
            .checked_add(1)
            .ok_or(H264Error::FrameIdExhausted)?;
        if summary.has_idr_slice {
            self.last_transmitted = Some(frame_id);
            self.recovery_requested = false;
            return summary.continuity_meta(self.codec_epoch, frame_id, None);
        }
        if self.recovery_requested {
            return Err(H264Error::RecoveryPointRequired);
        }
        let dependency = self
            .last_transmitted
            .ok_or(H264Error::RecoveryPointRequired)?;
        let metadata = summary.continuity_meta(self.codec_epoch, frame_id, Some(dependency))?;
        self.last_transmitted = Some(frame_id);
        Ok(metadata)
    }

    pub fn reconfigure(&mut self, codec_epoch: u32) -> Result<(), H264Error> {
        if codec_epoch <= self.codec_epoch {
            return Err(H264Error::NonMonotonicEpoch);
        }
        self.codec_epoch = codec_epoch;
        self.last_transmitted = None;
        self.recovery_requested = true;
        Ok(())
    }
}

/// Wraps a validated Annex-B access unit with conservative continuity metadata.
pub fn wrap_access_unit(
    planner: &mut ContinuityPlanner,
    bytes: &[u8],
    capture_sequence: u64,
    capture_timestamp_ns: u64,
) -> Result<EncodedAccessUnit, H264Error> {
    let meta = planner.accept(bytes)?;
    let unit = EncodedAccessUnit {
        codec: CodecId::H264,
        stream_id: 1,
        capture_sequence,
        capture_timestamp_ns,
        meta,
        bytes: bytes.to_vec(),
    };
    unit.validate().map_err(|err| match err {
        CodecError::EncodedSize(len) => H264Error::AccessUnitSize(len),
        CodecError::ForwardDependency | CodecError::RecoveryPointHasDependency => {
            H264Error::InvalidDependency
        }
        _ => H264Error::Malformed,
    })?;
    Ok(unit)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H264Error {
    AccessUnitSize(usize),
    MissingStartCode,
    LeadingGarbage,
    Malformed,
    ForbiddenZeroBit,
    TooManyNalUnits,
    UnsupportedNalType(u8),
    DataPartitionUnsupported,
    NoPicture,
    MixedPictureTypes,
    BFrameForbidden,
    BFrameDetected,
    LookaheadForbidden,
    ProviderQueue,
    IntraPeriod,
    RbspLimit(usize),
    MalformedEscape(usize, u8),
    TruncatedSlice,
    ExpGolombOverflow,
    RecoveryPointRequired,
    InvalidDependency,
    FrameIdExhausted,
    NonMonotonicEpoch,
    SoftwareEncode,
    SoftwareDecode,
    InvalidNv12,
}

impl fmt::Display for H264Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for H264Error {}

#[cfg(test)]
mod tests {
    use super::*;

    const IDR: &[u8] = &[0, 0, 0, 1, 0x67, 1, 0, 0, 1, 0x68, 2, 0, 0, 1, 0x65, 0xb8];
    const P: &[u8] = &[0, 0, 1, 0x41, 0xe0];
    const B: &[u8] = &[0, 0, 1, 0x01, 0xa8];

    #[test]
    fn detects_idr_and_parameter_sets() {
        let summary = inspect_annex_b(IDR).expect("valid");
        assert!(summary.has_sps && summary.has_pps && summary.has_idr_slice);
        assert_eq!(summary.nal_units, 3);
    }

    #[test]
    fn detects_and_rejects_b_slice_output() {
        assert_eq!(inspect_annex_b(B), Err(H264Error::BFrameDetected));
    }

    #[test]
    fn continuity_requires_idr_after_drop() {
        let mut planner = ContinuityPlanner::new(1, 10);
        assert!(planner.accept(IDR).expect("idr").recovery_point);
        assert_eq!(planner.accept(P).expect("p").dependency_frame_id, Some(10));
        planner.note_output_drop();
        assert_eq!(planner.accept(P), Err(H264Error::RecoveryPointRequired));
        assert!(planner.accept(IDR).expect("recovery").recovery_point);
    }

    #[test]
    fn policy_forbids_hidden_latency() {
        let policy = LowDelayPolicy::baseline(120);
        assert_eq!(policy.validate(), Ok(policy));
        assert_eq!(policy.max_provider_queue, 1);
        let invalid = LowDelayPolicy {
            b_frames: 1,
            ..policy
        };
        assert_eq!(invalid.validate(), Err(H264Error::BFrameForbidden));
    }

    #[test]
    fn wrap_access_unit_validates_idr_p_and_rejects_b() {
        let mut planner = ContinuityPlanner::new(1, 10);
        let idr = wrap_access_unit(&mut planner, IDR, 7, 1_000).expect("idr");
        assert_eq!(idr.codec, CodecId::H264);
        assert_eq!(idr.stream_id, 1);
        assert_eq!(idr.capture_sequence, 7);
        assert_eq!(idr.capture_timestamp_ns, 1_000);
        assert_eq!(idr.bytes, IDR);
        assert!(idr.meta.recovery_point);
        assert_eq!(idr.meta.dependency_frame_id, None);
        idr.validate().expect("validated idr");
        assert!(!planner.recovery_requested());

        let p = wrap_access_unit(&mut planner, P, 8, 2_000).expect("p");
        assert_eq!(p.codec, CodecId::H264);
        assert_eq!(p.meta.dependency_frame_id, Some(10));
        assert!(!p.meta.recovery_point);
        p.validate().expect("validated p");

        planner.note_output_drop();
        planner.note_output_drop();
        assert!(planner.recovery_requested());
        assert_eq!(
            wrap_access_unit(&mut planner, P, 9, 3_000),
            Err(H264Error::RecoveryPointRequired)
        );

        let recovered = wrap_access_unit(&mut planner, IDR, 10, 4_000).expect("recovery");
        assert!(recovered.meta.recovery_point);
        recovered.validate().expect("validated recovery");
        assert!(!planner.recovery_requested());

        assert_eq!(
            wrap_access_unit(&mut planner, B, 11, 5_000),
            Err(H264Error::BFrameDetected)
        );
    }

    #[test]
    fn emulation_prevention_allows_literal_three_after_escape() {
        assert_eq!(unescape_rbsp(&[0, 0, 3, 3, 0x80]), Ok(vec![0, 0, 3, 0x80]));
    }

    #[test]
    fn slice_parser_ignores_annex_b_trailing_zero_bytes() {
        assert_eq!(parse_slice_class(&[0xe0, 0, 0, 0]), Ok(SliceClass::P));
    }

    #[test]
    fn repeated_emulation_prevention_groups_decode_consecutive_zeros() {
        assert_eq!(
            unescape_rbsp(&[0, 0, 3, 0, 0, 3, 0]),
            Ok(vec![0, 0, 0, 0, 0])
        );
    }
}
