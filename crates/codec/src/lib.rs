//! Provider-neutral codec contracts.
//!
//! Production backends (NVENC, Media Foundation, VA-API, oneVPL, AMF) must
//! implement these contracts without leaking vendor-owned surface lifetimes into
//! the shared core. The deterministic laboratory uses a separate exact codec.

use latencydesk_frame::{PixelFormat, RawFrame};
use latencydesk_media::{EncodedFrameMeta, ImportPath};
use std::fmt;

/// Wire-level codec identifier negotiated per stream epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CodecId {
    /// Deterministic exact codec used only by tests and CI.
    ExactTest = 0,
    H264 = 1,
    H265 = 2,
    Av1 = 3,
}

/// Chroma and sample layout expected by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChromaMode {
    Yuv420EightBit,
    Yuv444EightBit,
    Yuv420TenBit,
    RgbExact,
}

/// Intended provider operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyMode {
    /// Minimize latency and queueing; quality may fluctuate.
    UltraLowLatency,
    /// Keep low latency while allowing a small bounded quality buffer.
    Interactive,
    /// Background exact refinement; never blocks the realtime stream.
    Refinement,
}

/// Codec configuration. Every field is bounded before a backend is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecConfig {
    pub codec: CodecId,
    pub width: u32,
    pub height: u32,
    pub fps_num: u32,
    pub fps_den: u32,
    pub target_bitrate_bps: u32,
    pub max_bitrate_bps: u32,
    pub keyframe_interval_frames: u32,
    pub chroma: ChromaMode,
    pub latency_mode: LatencyMode,
}

impl CodecConfig {
    /// Rejects configurations that would create unbounded provider allocations.
    pub fn validate(self) -> Result<(), CodecError> {
        const MAX_DIMENSION: u32 = 16_384;
        const MAX_PIXELS: u64 = 134_217_728;
        const MAX_BITRATE: u32 = 1_000_000_000;
        if self.width == 0
            || self.height == 0
            || self.width > MAX_DIMENSION
            || self.height > MAX_DIMENSION
            || u64::from(self.width) * u64::from(self.height) > MAX_PIXELS
        {
            return Err(CodecError::InvalidDimensions);
        }
        if self.fps_num == 0 || self.fps_den == 0 || self.fps_num / self.fps_den > 1_000 {
            return Err(CodecError::InvalidFrameRate);
        }
        if self.target_bitrate_bps == 0
            || self.target_bitrate_bps > self.max_bitrate_bps
            || self.max_bitrate_bps > MAX_BITRATE
        {
            return Err(CodecError::InvalidBitrate);
        }
        if self.keyframe_interval_frames == 0 || self.keyframe_interval_frames > 100_000 {
            return Err(CodecError::InvalidKeyframeInterval);
        }
        Ok(())
    }
}

/// Capabilities returned by probing a concrete provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecCapabilities {
    pub provider_name: String,
    pub codecs: Vec<CodecId>,
    pub input_formats: Vec<PixelFormat>,
    pub chroma_modes: Vec<ChromaMode>,
    pub max_width: u32,
    pub max_height: u32,
    pub supports_dynamic_bitrate: bool,
    pub supports_forced_recovery_point: bool,
    /// Paths observed during probe; runtime may still downgrade after import.
    pub import_paths: Vec<ImportPath>,
}

impl CodecCapabilities {
    #[must_use]
    pub fn supports(&self, config: CodecConfig) -> bool {
        self.codecs.contains(&config.codec)
            && self.chroma_modes.contains(&config.chroma)
            && config.width <= self.max_width
            && config.height <= self.max_height
    }
}

/// One complete encoded access unit with conservative dependency metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAccessUnit {
    pub codec: CodecId,
    pub stream_id: u32,
    pub capture_sequence: u64,
    pub capture_timestamp_ns: u64,
    pub meta: EncodedFrameMeta,
    pub bytes: Vec<u8>,
}

impl EncodedAccessUnit {
    pub const MAX_BYTES: usize = 16 * 1024 * 1024;

    pub fn validate(&self) -> Result<(), CodecError> {
        if self.bytes.is_empty() || self.bytes.len() > Self::MAX_BYTES {
            return Err(CodecError::EncodedSize(self.bytes.len()));
        }
        if self.meta.recovery_point && self.meta.dependency_frame_id.is_some() {
            return Err(CodecError::RecoveryPointHasDependency);
        }
        if self
            .meta
            .dependency_frame_id
            .is_some_and(|dependency| dependency >= self.meta.frame_id)
        {
            return Err(CodecError::ForwardDependency);
        }
        Ok(())
    }
}

/// Encoder reconfiguration that is safe without changing dimensions/format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateUpdate {
    pub target_bitrate_bps: u32,
    pub max_bitrate_bps: u32,
}

/// Provider-neutral encoder interface.
///
/// Implementations must keep their internal submission queue bounded and must
/// report dependency metadata conservatively. Returning from `encode` transfers
/// an owned access unit to the caller; no vendor surface may be borrowed by it.
pub trait FrameEncoder {
    fn capabilities(&self) -> &CodecCapabilities;
    fn config(&self) -> CodecConfig;
    fn encode(&mut self, frame: &RawFrame) -> Result<EncodedAccessUnit, CodecError>;
    fn request_recovery_point(&mut self) -> Result<(), CodecError>;
    fn update_rate(&mut self, update: RateUpdate) -> Result<(), CodecError>;
    fn drain(&mut self) -> Result<Vec<EncodedAccessUnit>, CodecError>;
}

/// Provider-neutral decoder interface.
pub trait FrameDecoder {
    fn configure(&mut self, config: CodecConfig, codec_epoch: u32) -> Result<(), CodecError>;
    fn decode(&mut self, unit: &EncodedAccessUnit) -> Result<Option<RawFrame>, CodecError>;
    fn reset(&mut self) -> Result<(), CodecError>;
}

/// Codec provider failure. Native providers should preserve vendor details in
/// logs while mapping them into these stable recovery classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    InvalidDimensions,
    InvalidFrameRate,
    InvalidBitrate,
    InvalidKeyframeInterval,
    UnsupportedConfiguration,
    UnsupportedImportPath,
    EncodedSize(usize),
    RecoveryPointHasDependency,
    ForwardDependency,
    QueueFull,
    DeviceLost,
    PermissionRevoked,
    InvalidBitstream,
    Backend(String),
}

impl CodecError {
    /// Whether rebuilding the provider/device may recover the session.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::QueueFull | Self::DeviceLost | Self::PermissionRevoked
        )
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> CodecConfig {
        CodecConfig {
            codec: CodecId::H264,
            width: 1_920,
            height: 1_080,
            fps_num: 60,
            fps_den: 1,
            target_bitrate_bps: 20_000_000,
            max_bitrate_bps: 30_000_000,
            keyframe_interval_frames: 120,
            chroma: ChromaMode::Yuv420EightBit,
            latency_mode: LatencyMode::UltraLowLatency,
        }
    }

    #[test]
    fn config_is_bounded() {
        assert!(valid_config().validate().is_ok());
        let mut invalid = valid_config();
        invalid.width = 100_000;
        assert_eq!(invalid.validate(), Err(CodecError::InvalidDimensions));
    }

    #[test]
    fn dependency_must_point_backward() {
        let unit = EncodedAccessUnit {
            codec: CodecId::H264,
            stream_id: 1,
            capture_sequence: 10,
            capture_timestamp_ns: 0,
            meta: EncodedFrameMeta {
                codec_epoch: 1,
                frame_id: 10,
                dependency_frame_id: Some(10),
                recovery_point: false,
            },
            bytes: vec![1],
        };
        assert_eq!(unit.validate(), Err(CodecError::ForwardDependency));
    }
}
