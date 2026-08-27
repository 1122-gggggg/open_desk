//! Raw-frame ownership, validation, deterministic capture sources, tile-based
//! differential analysis, bounded tile refinement cache, and idle refinement policy.

use latencydesk_media::{
    FrameDescriptor, IdleRefinementStatus, MemoryDomain, TileCacheStats, TileCoord,
    TileRefinementMeta,
};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Maximum raw frame allocation accepted by the deterministic laboratory.
pub const MAX_RAW_FRAME_BYTES: usize = 256 * 1024 * 1024;

/// Pixel formats supported by the exact test path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PixelFormat {
    /// Four bytes per pixel in blue, green, red, alpha order.
    Bgra8 = 1,
    /// 8-bit Y plane followed by an interleaved, half-resolution UV plane.
    Nv12 = 2,
}

impl TryFrom<u8> for PixelFormat {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Bgra8),
            2 => Ok(Self::Nv12),
            other => Err(FrameError::UnsupportedPixelFormat(other)),
        }
    }
}

impl PixelFormat {
    /// FourCC-like identifier used in provider-neutral descriptors.
    #[must_use]
    pub const fn fourcc(self) -> u32 {
        match self {
            Self::Bgra8 => u32::from_le_bytes(*b"BGRA"),
            Self::Nv12 => u32::from_le_bytes(*b"NV12"),
        }
    }
}

/// An owned raw frame. Native capture leases must be imported or copied into an
/// equivalent owned object before the capture callback returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub descriptor: FrameDescriptor,
    pub format: PixelFormat,
    /// Bytes between adjacent rows in the primary plane.
    pub stride: u32,
    pub data: Vec<u8>,
}

impl RawFrame {
    /// Builds and validates an owned raw frame.
    pub fn new(
        width: u32,
        height: u32,
        format: PixelFormat,
        stride: u32,
        capture_sequence: u64,
        capture_timestamp_ns: u64,
        data: Vec<u8>,
    ) -> Result<Self, FrameError> {
        let descriptor = FrameDescriptor {
            width,
            height,
            format_fourcc: format.fourcc(),
            memory_domain: MemoryDomain::Cpu,
            capture_sequence,
            capture_timestamp_ns,
        };
        descriptor.validate().map_err(|_| FrameError::Dimensions)?;
        let expected = expected_len(width, height, format, stride)?;
        if expected != data.len() {
            return Err(FrameError::DataLength {
                expected,
                actual: data.len(),
            });
        }
        Ok(Self {
            descriptor,
            format,
            stride,
            data,
        })
    }

    /// Stable, dependency-free FNV-1a checksum for exact reconstruction tests.
    #[must_use]
    pub fn checksum64(&self) -> u64 {
        checksum64(&self.data)
    }
}

/// Returns the exact byte count for a supported raw frame.
pub fn expected_len(
    width: u32,
    height: u32,
    format: PixelFormat,
    stride: u32,
) -> Result<usize, FrameError> {
    if width == 0 || height == 0 || stride == 0 {
        return Err(FrameError::Dimensions);
    }
    let width = usize::try_from(width).map_err(|_| FrameError::Overflow)?;
    let height = usize::try_from(height).map_err(|_| FrameError::Overflow)?;
    let stride = usize::try_from(stride).map_err(|_| FrameError::Overflow)?;
    let len = match format {
        PixelFormat::Bgra8 => {
            let minimum = width.checked_mul(4).ok_or(FrameError::Overflow)?;
            if stride < minimum {
                return Err(FrameError::Stride);
            }
            stride.checked_mul(height).ok_or(FrameError::Overflow)?
        }
        PixelFormat::Nv12 => {
            if width % 2 != 0 || height % 2 != 0 || stride < width {
                return Err(FrameError::Stride);
            }
            let y = stride.checked_mul(height).ok_or(FrameError::Overflow)?;
            let uv = stride.checked_mul(height / 2).ok_or(FrameError::Overflow)?;
            y.checked_add(uv).ok_or(FrameError::Overflow)?
        }
    };
    if len > MAX_RAW_FRAME_BYTES {
        return Err(FrameError::AllocationLimit(len));
    }
    Ok(len)
}

/// Deterministic pattern emitted by [`FakeCapture`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// Static spatial gradient with a sequence marker.
    Gradient,
    /// Moving high-contrast rectangle over a stable background.
    MovingBox,
    /// Dense UI-like rows with a blinking caret.
    TextLike,
}

/// Validated fake-capture configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeCaptureConfig {
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    pub pattern: Pattern,
    pub seed: u64,
}

impl FakeCaptureConfig {
    /// Checks dimensions and allocation limits before capture starts.
    pub fn validate(self) -> Result<(), FrameError> {
        let stride = default_stride(self.width, self.format)?;
        expected_len(self.width, self.height, self.format, stride).map(|_| ())
    }
}

/// Deterministic capture source for transport and codec tests.
#[derive(Debug, Clone)]
pub struct FakeCapture {
    config: FakeCaptureConfig,
    next_sequence: u64,
}

impl FakeCapture {
    pub fn new(config: FakeCaptureConfig) -> Result<Self, FrameError> {
        config.validate()?;
        Ok(Self {
            config,
            next_sequence: 0,
        })
    }

    /// Produces one frame using the supplied host-local monotonic timestamp.
    pub fn capture(&mut self, timestamp_ns: u64) -> Result<RawFrame, FrameError> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let stride = default_stride(self.config.width, self.config.format)?;
        let len = expected_len(
            self.config.width,
            self.config.height,
            self.config.format,
            stride,
        )?;
        let mut data = vec![0_u8; len];
        match self.config.format {
            PixelFormat::Bgra8 => self.fill_bgra(sequence, stride, &mut data),
            PixelFormat::Nv12 => self.fill_nv12(sequence, stride, &mut data),
        }
        RawFrame::new(
            self.config.width,
            self.config.height,
            self.config.format,
            stride,
            sequence,
            timestamp_ns,
            data,
        )
    }

    fn fill_bgra(&self, sequence: u64, stride: u32, data: &mut [u8]) {
        let width = self.config.width as usize;
        let height = self.config.height as usize;
        let stride = stride as usize;
        for y in 0..height {
            for x in 0..width {
                let offset = y * stride + x * 4;
                let (b, g, r) = self.pixel_rgb(x, y, sequence);
                data[offset] = b;
                data[offset + 1] = g;
                data[offset + 2] = r;
                data[offset + 3] = 255;
            }
        }
    }

    fn fill_nv12(&self, sequence: u64, stride: u32, data: &mut [u8]) {
        let width = self.config.width as usize;
        let height = self.config.height as usize;
        let stride = stride as usize;
        for y in 0..height {
            for x in 0..width {
                let (_, g, r) = self.pixel_rgb(x, y, sequence);
                data[y * stride + x] = luma(r, g, self.pixel_rgb(x, y, sequence).0);
            }
        }
        let uv_start = stride * height;
        for y in 0..(height / 2) {
            for x in (0..width).step_by(2) {
                let phase = ((x / 2 + y + sequence as usize) & 31) as u8;
                data[uv_start + y * stride + x] = 112_u8.saturating_add(phase / 2);
                data[uv_start + y * stride + x + 1] = 144_u8.saturating_sub(phase / 2);
            }
        }
    }

    fn pixel_rgb(&self, x: usize, y: usize, sequence: u64) -> (u8, u8, u8) {
        let seed = self.config.seed as usize;
        match self.config.pattern {
            Pattern::Gradient => (
                ((x + seed) & 255) as u8,
                ((y * 3 + seed) & 255) as u8,
                (((x ^ y) + sequence as usize) & 255) as u8,
            ),
            Pattern::MovingBox => {
                let box_width = (self.config.width as usize / 6).max(8);
                let box_height = (self.config.height as usize / 6).max(8);
                let span_x = (self.config.width as usize)
                    .saturating_sub(box_width)
                    .max(1);
                let span_y = (self.config.height as usize)
                    .saturating_sub(box_height)
                    .max(1);
                let left = (sequence as usize * 7 + seed) % span_x;
                let top = (sequence as usize * 3 + seed) % span_y;
                if x >= left && x < left + box_width && y >= top && y < top + box_height {
                    (245, 245, 245)
                } else {
                    (24, 28, 34)
                }
            }
            Pattern::TextLike => {
                let row = y / 12;
                let stroke = y % 12;
                let glyph = (x / 7 + row + seed) % 11;
                let caret_x = (sequence as usize * 5) % (self.config.width as usize).max(1);
                if x >= caret_x && x < caret_x + 2 && stroke > 1 && stroke < 11 {
                    (255, 255, 255)
                } else if stroke == 3 || stroke == 8 || glyph == 0 {
                    (210, 220, 225)
                } else {
                    (20, 23, 27)
                }
            }
        }
    }
}

fn default_stride(width: u32, format: PixelFormat) -> Result<u32, FrameError> {
    match format {
        PixelFormat::Bgra8 => width.checked_mul(4).ok_or(FrameError::Overflow),
        PixelFormat::Nv12 => Ok(width),
    }
}

fn luma(r: u8, g: u8, b: u8) -> u8 {
    let value = 77_u32 * u32::from(r) + 150_u32 * u32::from(g) + 29_u32 * u32::from(b);
    (value >> 8) as u8
}

/// Dependency-free checksum shared by the test codec and tile cache.
#[must_use]
pub fn checksum64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    Dimensions,
    Stride,
    Overflow,
    AllocationLimit(usize),
    DataLength { expected: usize, actual: usize },
    UnsupportedPixelFormat(u8),
    InvalidTileGrid,
    InvalidTileCoord(u32, u32),
    TileHashMismatch { expected: u64, actual: u64 },
    CorruptedTilePayload,
    StaleEpoch { expected: u32, actual: u32 },
    TileCacheLimitExceeded,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for FrameError {}

/// Portable NV12 preview helpers shared by host capture paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvertError {
    InvalidDimensions,
    BufferTooSmall { required: usize, actual: usize },
}

impl fmt::Display for ConvertError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDimensions => {
                write!(formatter, "width and height must be positive even integers")
            }
            Self::BufferTooSmall { required, actual } => {
                write!(
                    formatter,
                    "pixel buffer too small: required {required}, actual {actual}"
                )
            }
        }
    }
}

impl std::error::Error for ConvertError {}

#[must_use]
pub fn even_dimension(value: u32) -> u32 {
    value & !1
}

#[must_use]
pub fn nv12_len(width: u32, height: u32) -> usize {
    let width = width as usize;
    let height = height as usize;
    width * height + width * height / 2
}

#[must_use]
pub fn pack_nv12_access_unit(width: u32, height: u32, nv12: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + nv12.len());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(nv12);
    out
}

pub fn parse_nv12_access_unit(bytes: &[u8]) -> Option<(u32, u32, &[u8])> {
    if bytes.len() < 8 {
        return None;
    }
    let width = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let height = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if width < 2 || height < 2 || width % 2 != 0 || height % 2 != 0 {
        return None;
    }
    let expected = nv12_len(width, height);
    if bytes.len() != 8 + expected {
        return None;
    }
    Some((width, height, &bytes[8..]))
}

/// BT.601 limited-range integer conversion used by the desktop capture path.
#[must_use]
pub fn rgb_to_yuv_bt601_limited(r: u8, g: u8, b: u8) -> (u8, u8, u8) {
    let r = i32::from(r);
    let g = i32::from(g);
    let b = i32::from(b);
    let y = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
    let u = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
    let v = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
    (
        y.clamp(16, 235) as u8,
        u.clamp(16, 240) as u8,
        v.clamp(16, 240) as u8,
    )
}

pub fn bgra_to_nv12_bt601_limited(
    width: u32,
    height: u32,
    bgra: &[u8],
    src_stride: usize,
) -> Result<Vec<u8>, ConvertError> {
    let mut nv12 = Vec::new();
    bgra_to_nv12_bt601_limited_into(width, height, bgra, src_stride, &mut nv12)?;
    Ok(nv12)
}

pub fn bgra_to_nv12_bt601_limited_into(
    width: u32,
    height: u32,
    bgra: &[u8],
    src_stride: usize,
    nv12: &mut Vec<u8>,
) -> Result<(), ConvertError> {
    if width < 2 || height < 2 || width % 2 != 0 || height % 2 != 0 {
        return Err(ConvertError::InvalidDimensions);
    }
    let width_us = width as usize;
    let height_us = height as usize;
    let min_stride = width_us.saturating_mul(4);
    if src_stride < min_stride {
        return Err(ConvertError::BufferTooSmall {
            required: min_stride,
            actual: src_stride,
        });
    }
    let required = src_stride.saturating_mul(height_us);
    if bgra.len() < required {
        return Err(ConvertError::BufferTooSmall {
            required,
            actual: bgra.len(),
        });
    }

    let len = nv12_len(width, height);
    nv12.clear();
    nv12.resize(len, 128);
    let luma = width_us * height_us;
    for y in 0..height_us {
        for x in 0..width_us {
            let px = y * src_stride + x * 4;
            let b = bgra[px];
            let g = bgra[px + 1];
            let r = bgra[px + 2];
            let (yp, u, v) = rgb_to_yuv_bt601_limited(r, g, b);
            nv12[y * width_us + x] = yp;
            if y % 2 == 0 && x % 2 == 0 {
                let uv = luma + (y / 2) * width_us + (x / 2) * 2;
                nv12[uv] = u;
                nv12[uv + 1] = v;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LetterboxGeom {
    pub out_width: u32,
    pub out_height: u32,
    pub content_width: u32,
    pub content_height: u32,
    pub offset_x: u32,
    pub offset_y: u32,
}

#[must_use]
pub fn letterbox_identity_geom(width: u32, height: u32) -> LetterboxGeom {
    LetterboxGeom {
        out_width: width,
        out_height: height,
        content_width: width,
        content_height: height,
        offset_x: 0,
        offset_y: 0,
    }
}

#[must_use]
pub fn letterbox_can_skip_scale(
    src_width: u32,
    src_height: u32,
    max_width: u32,
    max_height: u32,
) -> bool {
    src_width >= 2
        && src_height >= 2
        && src_width % 2 == 0
        && src_height % 2 == 0
        && src_width <= max_width
        && src_height <= max_height
}

fn validate_bgra_buffer(
    src: &[u8],
    src_width: u32,
    src_height: u32,
    src_stride: usize,
) -> Result<(usize, usize, usize), ConvertError> {
    let src_w = src_width as usize;
    let src_h = src_height as usize;
    let min_stride = src_w.saturating_mul(4);
    if src_stride < min_stride {
        return Err(ConvertError::BufferTooSmall {
            required: min_stride,
            actual: src_stride,
        });
    }
    let required = src_stride.saturating_mul(src_h);
    if src.len() < required {
        return Err(ConvertError::BufferTooSmall {
            required,
            actual: src.len(),
        });
    }
    Ok((src_w, src_h, min_stride))
}

pub fn letterbox_geom(
    src_width: u32,
    src_height: u32,
    max_width: u32,
    max_height: u32,
) -> Result<LetterboxGeom, ConvertError> {
    let out_width = even_dimension(max_width);
    let out_height = even_dimension(max_height);
    if src_width == 0 || src_height == 0 || out_width < 2 || out_height < 2 {
        return Err(ConvertError::InvalidDimensions);
    }
    if letterbox_can_skip_scale(src_width, src_height, max_width, max_height) {
        return Ok(letterbox_identity_geom(src_width, src_height));
    }
    let scale_num = u64::from(out_width).min(
        (u64::from(out_width) * u64::from(src_height))
            .min(u64::from(out_height) * u64::from(src_width)),
    );
    let mut content_width = even_dimension(
        ((u64::from(src_width) * u64::from(out_height)) / u64::from(src_height))
            .min(u64::from(out_width)) as u32,
    );
    let mut content_height = even_dimension(
        ((u64::from(src_height) * u64::from(out_width)) / u64::from(src_width))
            .min(u64::from(out_height)) as u32,
    );
    if content_width == 0 {
        content_width = 2;
    }
    if content_height == 0 {
        content_height = 2;
    }
    if content_width > out_width {
        content_width = out_width;
    }
    if content_height > out_height {
        content_height = out_height;
    }
    let _ = scale_num;
    let offset_x = even_dimension((out_width - content_width) / 2);
    let offset_y = even_dimension((out_height - content_height) / 2);
    Ok(LetterboxGeom {
        out_width,
        out_height,
        content_width,
        content_height,
        offset_x,
        offset_y,
    })
}

pub fn letterbox_scale_bgra<'a>(
    src: &'a [u8],
    src_width: u32,
    src_height: u32,
    src_stride: usize,
    max_width: u32,
    max_height: u32,
) -> Result<(LetterboxGeom, Cow<'a, [u8]>), ConvertError> {
    let (_src_w, src_h, min_stride) = validate_bgra_buffer(src, src_width, src_height, src_stride)?;
    let required = src_stride.saturating_mul(src_h);
    if letterbox_can_skip_scale(src_width, src_height, max_width, max_height) {
        let geom = letterbox_identity_geom(src_width, src_height);
        if src_stride == min_stride {
            return Ok((geom, Cow::Borrowed(&src[..required])));
        }
        let mut packed = vec![0u8; min_stride.saturating_mul(src_h)];
        for y in 0..src_h {
            let dst = y * min_stride;
            let src_row = y * src_stride;
            packed[dst..dst + min_stride].copy_from_slice(&src[src_row..src_row + min_stride]);
        }
        return Ok((geom, Cow::Owned(packed)));
    }

    let mut out = Vec::new();
    let geom = letterbox_scale_bgra_into(
        src, src_width, src_height, src_stride, max_width, max_height, &mut out,
    )?;
    Ok((geom, Cow::Owned(out)))
}

pub fn letterbox_scale_bgra_into(
    src: &[u8],
    src_width: u32,
    src_height: u32,
    src_stride: usize,
    max_width: u32,
    max_height: u32,
    out: &mut Vec<u8>,
) -> Result<LetterboxGeom, ConvertError> {
    let (src_w, src_h, _min_stride) = validate_bgra_buffer(src, src_width, src_height, src_stride)?;
    if letterbox_can_skip_scale(src_width, src_height, max_width, max_height) {
        return Ok(letterbox_identity_geom(src_width, src_height));
    }
    let geom = letterbox_geom(src_width, src_height, max_width, max_height)?;
    let out_w = geom.out_width as usize;
    let out_h = geom.out_height as usize;
    let needed = out_w.saturating_mul(out_h).saturating_mul(4);
    out.clear();
    out.resize(needed, 0);
    let content_w = geom.content_width.max(1) as usize;
    let content_h = geom.content_height.max(1) as usize;
    let off_x = geom.offset_x as usize;
    let off_y = geom.offset_y as usize;

    for y in 0..out_h {
        for x in 0..out_w {
            let dst = (y * out_w + x) * 4;
            if x < off_x || y < off_y || x >= off_x + content_w || y >= off_y + content_h {
                continue;
            }
            let sx = ((x - off_x) * src_w) / content_w;
            let sy = ((y - off_y) * src_h) / content_h;
            let sx = sx.min(src_w - 1);
            let sy = sy.min(src_h - 1);
            let src_px = sy * src_stride + sx * 4;
            out[dst..dst + 4].copy_from_slice(&src[src_px..src_px + 4]);
        }
    }
    Ok(geom)
}

pub fn map_letterboxed_pointer(
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    geom: LetterboxGeom,
    screen_width: u32,
    screen_height: u32,
) -> (u32, u32) {
    if width == 0 || height == 0 || screen_width == 0 || screen_height == 0 {
        return (0, 0);
    }
    let scale_x = |value: u32, from: u32, to: u32| -> u32 {
        if from <= 1 {
            0
        } else {
            ((u64::from(value) * u64::from(to.saturating_sub(1)))
                / u64::from(from.saturating_sub(1))) as u32
        }
    };
    let px = scale_x(x.min(width.saturating_sub(1)), width, geom.out_width);
    let py = scale_x(y.min(height.saturating_sub(1)), height, geom.out_height);
    let content_x = px
        .saturating_sub(geom.offset_x)
        .min(geom.content_width.saturating_sub(1));
    let content_y = py
        .saturating_sub(geom.offset_y)
        .min(geom.content_height.saturating_sub(1));
    let sx = scale_x(content_x, geom.content_width, screen_width);
    let sy = scale_x(content_y, geom.content_height, screen_height);
    (
        sx.min(screen_width.saturating_sub(1)),
        sy.min(screen_height.saturating_sub(1)),
    )
}

/// Default tile dimension in pixels (64x64).
pub const DEFAULT_TILE_SIZE: u32 = 64;

/// Default maximum memory allocated to client tile refinement cache (128 MB).
pub const DEFAULT_MAX_CACHE_BYTES: usize = 128 * 1024 * 1024;

/// Idle duration threshold before lossless tile refinement triggers (100 ms).
pub const DEFAULT_IDLE_REFINEMENT_THRESHOLD_NS: u64 = 100_000_000;

const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

#[inline]
fn round64(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

#[inline]
fn merge_round64(acc: u64, val: u64) -> u64 {
    (acc ^ round64(0, val))
        .wrapping_mul(PRIME64_1)
        .wrapping_add(PRIME64_4)
}

/// Streaming, dependency-free xxHash64 implementation for fast tile hashing.
#[derive(Debug, Clone)]
pub struct XxHash64 {
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    total_len: u64,
    seed: u64,
    buffer: [u8; 32],
    buffer_len: usize,
}

impl XxHash64 {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            v1: seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2),
            v2: seed.wrapping_add(PRIME64_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME64_1),
            total_len: 0,
            seed,
            buffer: [0_u8; 32],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);

        if self.buffer_len > 0 {
            let needed = 32 - self.buffer_len;
            if input.len() < needed {
                self.buffer[self.buffer_len..self.buffer_len + input.len()].copy_from_slice(input);
                self.buffer_len += input.len();
                return;
            }
            self.buffer[self.buffer_len..32].copy_from_slice(&input[..needed]);
            input = &input[needed..];
            let k1 = u64::from_le_bytes(self.buffer[0..8].try_into().unwrap());
            let k2 = u64::from_le_bytes(self.buffer[8..16].try_into().unwrap());
            let k3 = u64::from_le_bytes(self.buffer[16..24].try_into().unwrap());
            let k4 = u64::from_le_bytes(self.buffer[24..32].try_into().unwrap());
            self.v1 = round64(self.v1, k1);
            self.v2 = round64(self.v2, k2);
            self.v3 = round64(self.v3, k3);
            self.v4 = round64(self.v4, k4);
            self.buffer_len = 0;
        }

        while input.len() >= 32 {
            let k1 = u64::from_le_bytes(input[0..8].try_into().unwrap());
            let k2 = u64::from_le_bytes(input[8..16].try_into().unwrap());
            let k3 = u64::from_le_bytes(input[16..24].try_into().unwrap());
            let k4 = u64::from_le_bytes(input[24..32].try_into().unwrap());
            self.v1 = round64(self.v1, k1);
            self.v2 = round64(self.v2, k2);
            self.v3 = round64(self.v3, k3);
            self.v4 = round64(self.v4, k4);
            input = &input[32..];
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    #[must_use]
    pub fn finish(&self) -> u64 {
        let mut h64 = if self.total_len >= 32 {
            let mut acc = self
                .v1
                .rotate_left(1)
                .wrapping_add(self.v2.rotate_left(7))
                .wrapping_add(self.v3.rotate_left(12))
                .wrapping_add(self.v4.rotate_left(18));
            acc = merge_round64(acc, self.v1);
            acc = merge_round64(acc, self.v2);
            acc = merge_round64(acc, self.v3);
            acc = merge_round64(acc, self.v4);
            acc
        } else {
            self.seed.wrapping_add(PRIME64_5)
        };

        h64 = h64.wrapping_add(self.total_len);

        let mut remaining = &self.buffer[..self.buffer_len];
        while remaining.len() >= 8 {
            let k1 = u64::from_le_bytes(remaining[0..8].try_into().unwrap());
            h64 = (h64 ^ round64(0, k1))
                .rotate_left(27)
                .wrapping_mul(PRIME64_1)
                .wrapping_add(PRIME64_4);
            remaining = &remaining[8..];
        }

        if remaining.len() >= 4 {
            let k1 = u32::from_le_bytes(remaining[0..4].try_into().unwrap());
            h64 = (h64 ^ (u64::from(k1).wrapping_mul(PRIME64_1)))
                .rotate_left(23)
                .wrapping_mul(PRIME64_2)
                .wrapping_add(PRIME64_3);
            remaining = &remaining[4..];
        }

        for &byte in remaining {
            h64 = (h64 ^ (u64::from(byte).wrapping_mul(PRIME64_5)))
                .rotate_left(11)
                .wrapping_mul(PRIME64_1);
        }

        h64 ^= h64 >> 33;
        h64 = h64.wrapping_mul(PRIME64_2);
        h64 ^= h64 >> 29;
        h64 = h64.wrapping_mul(PRIME64_3);
        h64 ^= h64 >> 32;

        h64
    }

    #[must_use]
    pub fn oneshot(bytes: &[u8]) -> u64 {
        let mut hasher = Self::new(0);
        hasher.update(bytes);
        hasher.finish()
    }
}

/// Computes the xxHash64 of bytes with default seed 0.
#[must_use]
pub fn xxhash64(bytes: &[u8]) -> u64 {
    XxHash64::oneshot(bytes)
}

/// Discrete grid partitioning a display surface into square or border-clamped tiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TileGrid {
    pub width: u32,
    pub height: u32,
    pub tile_size: u32,
    pub tiles_x: u32,
    pub tiles_y: u32,
}

impl TileGrid {
    pub fn new(width: u32, height: u32, tile_size: u32) -> Result<Self, FrameError> {
        if width == 0 || height == 0 || tile_size == 0 {
            return Err(FrameError::Dimensions);
        }
        let tiles_x = width
            .checked_add(tile_size - 1)
            .ok_or(FrameError::Overflow)?
            / tile_size;
        let tiles_y = height
            .checked_add(tile_size - 1)
            .ok_or(FrameError::Overflow)?
            / tile_size;
        Ok(Self {
            width,
            height,
            tile_size,
            tiles_x,
            tiles_y,
        })
    }

    #[must_use]
    pub fn total_tiles(&self) -> usize {
        (self.tiles_x as usize) * (self.tiles_y as usize)
    }

    pub fn tile_bounds(&self, coord: TileCoord) -> Result<(u32, u32, u32, u32), FrameError> {
        if coord.x >= self.tiles_x || coord.y >= self.tiles_y {
            return Err(FrameError::InvalidTileCoord(coord.x, coord.y));
        }
        let x = coord.x * self.tile_size;
        let y = coord.y * self.tile_size;
        let w = (self.width - x).min(self.tile_size);
        let h = (self.height - y).min(self.tile_size);
        Ok((x, y, w, h))
    }

    pub fn tile_index(&self, coord: TileCoord) -> Result<usize, FrameError> {
        if coord.x >= self.tiles_x || coord.y >= self.tiles_y {
            return Err(FrameError::InvalidTileCoord(coord.x, coord.y));
        }
        Ok((coord.y as usize) * (self.tiles_x as usize) + (coord.x as usize))
    }

    pub fn tile_coord(&self, index: usize) -> Result<TileCoord, FrameError> {
        let total = self.total_tiles();
        if index >= total {
            return Err(FrameError::Overflow);
        }
        let x = (index % (self.tiles_x as usize)) as u32;
        let y = (index / (self.tiles_x as usize)) as u32;
        Ok(TileCoord::new(x, y))
    }
}

/// Axis-aligned pixel rectangle enclosing all detected dirty regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirtyRect {
    pub min_x: u32,
    pub min_y: u32,
    pub max_x: u32,
    pub max_y: u32,
}

/// Output of differential tile analysis for one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TileDiffResult {
    pub display_epoch: u32,
    pub capture_sequence: u64,
    pub dirty_tiles: Vec<TileCoord>,
    pub static_tiles: Vec<TileCoord>,
    pub dirty_rect: Option<DirtyRect>,
    pub total_tiles: usize,
}

impl TileDiffResult {
    #[must_use]
    pub fn has_motion(&self) -> bool {
        !self.dirty_tiles.is_empty()
    }

    #[must_use]
    pub fn is_fully_static(&self) -> bool {
        self.dirty_tiles.is_empty()
    }

    #[must_use]
    pub fn dirty_ratio(&self) -> f32 {
        if self.total_tiles == 0 {
            0.0
        } else {
            self.dirty_tiles.len() as f32 / self.total_tiles as f32
        }
    }
}

/// High-throughput differential tile change detector using fast 64-bit hashing.
#[derive(Debug, Clone)]
pub struct TileChangeDetector {
    grid: TileGrid,
    previous_hashes: Vec<u64>,
    display_epoch: u32,
    initialized: bool,
}

impl TileChangeDetector {
    #[must_use]
    pub fn new(grid: TileGrid, display_epoch: u32) -> Self {
        let total = grid.total_tiles();
        Self {
            grid,
            previous_hashes: vec![0_u64; total],
            display_epoch,
            initialized: false,
        }
    }

    #[must_use]
    pub const fn grid(&self) -> TileGrid {
        self.grid
    }

    #[must_use]
    pub const fn display_epoch(&self) -> u32 {
        self.display_epoch
    }

    pub fn reset(&mut self, grid: TileGrid, display_epoch: u32) {
        self.grid = grid;
        self.display_epoch = display_epoch;
        self.previous_hashes = vec![0_u64; grid.total_tiles()];
        self.initialized = false;
    }

    pub fn detect_changes(&mut self, frame: &RawFrame) -> Result<TileDiffResult, FrameError> {
        if frame.descriptor.width != self.grid.width || frame.descriptor.height != self.grid.height
        {
            return Err(FrameError::Dimensions);
        }

        let mut dirty_tiles = Vec::new();
        let mut static_tiles = Vec::new();
        let mut min_x = u32::MAX;
        let mut min_y = u32::MAX;
        let mut max_x = 0_u32;
        let mut max_y = 0_u32;

        let total = self.grid.total_tiles();
        let mut new_hashes = Vec::with_capacity(total);

        for ty in 0..self.grid.tiles_y {
            for tx in 0..self.grid.tiles_x {
                let coord = TileCoord::new(tx, ty);
                let (x, y, w, h) = self.grid.tile_bounds(coord)?;
                let hash = compute_tile_hash(frame, x, y, w, h)?;
                new_hashes.push(hash);

                let idx = (ty as usize) * (self.grid.tiles_x as usize) + (tx as usize);
                let is_dirty = !self.initialized || hash != self.previous_hashes[idx];

                if is_dirty {
                    dirty_tiles.push(coord);
                    min_x = min_x.min(x);
                    min_y = min_y.min(y);
                    max_x = max_x.max(x + w);
                    max_y = max_y.max(y + h);
                } else {
                    static_tiles.push(coord);
                }
            }
        }

        self.previous_hashes = new_hashes;
        self.initialized = true;

        let dirty_rect = if dirty_tiles.is_empty() {
            None
        } else {
            Some(DirtyRect {
                min_x,
                min_y,
                max_x,
                max_y,
            })
        };

        Ok(TileDiffResult {
            display_epoch: self.display_epoch,
            capture_sequence: frame.descriptor.capture_sequence,
            dirty_tiles,
            static_tiles,
            dirty_rect,
            total_tiles: total,
        })
    }
}

/// Hashes the tile region in a raw frame without memory allocations.
fn compute_tile_hash(frame: &RawFrame, x: u32, y: u32, w: u32, h: u32) -> Result<u64, FrameError> {
    let stride = frame.stride as usize;
    let mut hasher = XxHash64::new(0);

    match frame.format {
        PixelFormat::Bgra8 => {
            let row_bytes = (w as usize) * 4;
            for row in 0..h {
                let row_offset = ((y + row) as usize) * stride + (x as usize) * 4;
                if row_offset + row_bytes > frame.data.len() {
                    return Err(FrameError::Overflow);
                }
                hasher.update(&frame.data[row_offset..row_offset + row_bytes]);
            }
        }
        PixelFormat::Nv12 => {
            let row_bytes = w as usize;
            for row in 0..h {
                let row_offset = ((y + row) as usize) * stride + (x as usize);
                if row_offset + row_bytes > frame.data.len() {
                    return Err(FrameError::Overflow);
                }
                hasher.update(&frame.data[row_offset..row_offset + row_bytes]);
            }
            let uv_start = stride * (frame.descriptor.height as usize);
            let uv_w = w.div_ceil(2) * 2;
            let uv_h = h.div_ceil(2);
            let uv_x = (x / 2) * 2;
            let uv_y = y / 2;
            let uv_row_bytes = uv_w as usize;
            for row in 0..uv_h {
                let row_offset = uv_start + ((uv_y + row) as usize) * stride + (uv_x as usize);
                if row_offset + uv_row_bytes > frame.data.len() {
                    return Err(FrameError::Overflow);
                }
                hasher.update(&frame.data[row_offset..row_offset + uv_row_bytes]);
            }
        }
    }

    Ok(hasher.finish())
}

/// Extracts tightly-packed pixel bytes for one tile from a raw frame.
pub fn extract_tile_pixels(
    frame: &RawFrame,
    grid: &TileGrid,
    coord: TileCoord,
) -> Result<Vec<u8>, FrameError> {
    let (x, y, w, h) = grid.tile_bounds(coord)?;
    let stride = frame.stride as usize;

    match frame.format {
        PixelFormat::Bgra8 => {
            let row_bytes = (w as usize) * 4;
            let total_len = row_bytes * (h as usize);
            let mut pixels = Vec::with_capacity(total_len);
            for row in 0..h {
                let row_offset = ((y + row) as usize) * stride + (x as usize) * 4;
                if row_offset + row_bytes > frame.data.len() {
                    return Err(FrameError::Overflow);
                }
                pixels.extend_from_slice(&frame.data[row_offset..row_offset + row_bytes]);
            }
            Ok(pixels)
        }
        PixelFormat::Nv12 => {
            let y_row_bytes = w as usize;
            let y_len = y_row_bytes * (h as usize);
            let uv_w = w.div_ceil(2) * 2;
            let uv_h = h.div_ceil(2);
            let uv_len = (uv_w as usize) * (uv_h as usize);
            let mut pixels = Vec::with_capacity(y_len + uv_len);

            for row in 0..h {
                let row_offset = ((y + row) as usize) * stride + (x as usize);
                if row_offset + y_row_bytes > frame.data.len() {
                    return Err(FrameError::Overflow);
                }
                pixels.extend_from_slice(&frame.data[row_offset..row_offset + y_row_bytes]);
            }

            let uv_start = stride * (frame.descriptor.height as usize);
            let uv_x = (x / 2) * 2;
            let uv_y = y / 2;
            let uv_row_bytes = uv_w as usize;
            for row in 0..uv_h {
                let row_offset = uv_start + ((uv_y + row) as usize) * stride + (uv_x as usize);
                if row_offset + uv_row_bytes > frame.data.len() {
                    return Err(FrameError::Overflow);
                }
                pixels.extend_from_slice(&frame.data[row_offset..row_offset + uv_row_bytes]);
            }
            Ok(pixels)
        }
    }
}

/// Applies tightly-packed tile pixel bytes to a destination raw frame at the tile coordinates.
pub fn apply_tile_pixels(
    frame: &mut RawFrame,
    grid: &TileGrid,
    coord: TileCoord,
    pixels: &[u8],
) -> Result<(), FrameError> {
    let (x, y, w, h) = grid.tile_bounds(coord)?;
    let stride = frame.stride as usize;

    match frame.format {
        PixelFormat::Bgra8 => {
            let row_bytes = (w as usize) * 4;
            let expected_len = row_bytes * (h as usize);
            if pixels.len() != expected_len {
                return Err(FrameError::DataLength {
                    expected: expected_len,
                    actual: pixels.len(),
                });
            }
            for row in 0..h {
                let row_offset = ((y + row) as usize) * stride + (x as usize) * 4;
                let src_offset = (row as usize) * row_bytes;
                frame.data[row_offset..row_offset + row_bytes]
                    .copy_from_slice(&pixels[src_offset..src_offset + row_bytes]);
            }
        }
        PixelFormat::Nv12 => {
            let y_row_bytes = w as usize;
            let y_len = y_row_bytes * (h as usize);
            let uv_w = w.div_ceil(2) * 2;
            let uv_h = h.div_ceil(2);
            let uv_row_bytes = uv_w as usize;
            let uv_len = uv_row_bytes * (uv_h as usize);
            let expected_len = y_len + uv_len;
            if pixels.len() != expected_len {
                return Err(FrameError::DataLength {
                    expected: expected_len,
                    actual: pixels.len(),
                });
            }

            for row in 0..h {
                let row_offset = ((y + row) as usize) * stride + (x as usize);
                let src_offset = (row as usize) * y_row_bytes;
                frame.data[row_offset..row_offset + y_row_bytes]
                    .copy_from_slice(&pixels[src_offset..src_offset + y_row_bytes]);
            }

            let uv_start = stride * (frame.descriptor.height as usize);
            let uv_x = (x / 2) * 2;
            let uv_y = y / 2;
            for row in 0..uv_h {
                let row_offset = uv_start + ((uv_y + row) as usize) * stride + (uv_x as usize);
                let src_offset = y_len + (row as usize) * uv_row_bytes;
                frame.data[row_offset..row_offset + uv_row_bytes]
                    .copy_from_slice(&pixels[src_offset..src_offset + uv_row_bytes]);
            }
        }
    }

    Ok(())
}

/// Bounded PackBits compression for lossless tile payloads.
pub fn compress_packbits(input: &[u8]) -> Result<Vec<u8>, FrameError> {
    let mut output = Vec::with_capacity(input.len() + input.len() / 64 + 16);
    let mut cursor = 0;
    while cursor < input.len() {
        let run = repeated_run(input, cursor);
        if run >= 3 {
            let count = run.min(128);
            let header = (257 - count) as u8;
            output.push(header);
            output.push(input[cursor]);
            cursor += count;
        } else {
            let lit_len = literal_run(input, cursor);
            let count = lit_len.min(128);
            let header = (count - 1) as u8;
            output.push(header);
            output.extend_from_slice(&input[cursor..cursor + count]);
            cursor += count;
        }
    }
    Ok(output)
}

fn repeated_run(input: &[u8], start: usize) -> usize {
    let target = input[start];
    let mut count = 0;
    while start + count < input.len() && input[start + count] == target && count < 128 {
        count += 1;
    }
    count
}

fn literal_run(input: &[u8], start: usize) -> usize {
    let mut count = 0;
    while start + count < input.len() && count < 128 {
        if repeated_run(input, start + count) >= 3 {
            break;
        }
        count += 1;
    }
    if count == 0 && start < input.len() {
        1
    } else {
        count
    }
}

/// Bounded PackBits decompression for lossless tile payloads.
pub fn decompress_packbits(payload: &[u8], expected_len: usize) -> Result<Vec<u8>, FrameError> {
    if expected_len > MAX_RAW_FRAME_BYTES {
        return Err(FrameError::AllocationLimit(expected_len));
    }
    let mut output = Vec::with_capacity(expected_len);
    let mut cursor = 0;
    while cursor < payload.len() {
        let header = payload[cursor];
        cursor += 1;
        if header <= 127 {
            let count = (header as usize) + 1;
            if cursor + count > payload.len() || output.len() + count > expected_len {
                return Err(FrameError::CorruptedTilePayload);
            }
            output.extend_from_slice(&payload[cursor..cursor + count]);
            cursor += count;
        } else if header >= 129 {
            let count = 257 - (header as usize);
            if cursor >= payload.len() || output.len() + count > expected_len {
                return Err(FrameError::CorruptedTilePayload);
            }
            let byte = payload[cursor];
            cursor += 1;
            output.resize(output.len() + count, byte);
        }
    }
    if output.len() != expected_len {
        return Err(FrameError::DataLength {
            expected: expected_len,
            actual: output.len(),
        });
    }
    Ok(output)
}

const TILE_MAGIC: [u8; 4] = *b"LDTR";
pub const TILE_HEADER_LEN: usize = 48;

/// Wire-encodable lossless tile refinement packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TileRefinementPacket {
    pub meta: TileRefinementMeta,
    pub format: PixelFormat,
    pub raw_len: u32,
    pub compressed: bool,
    pub payload: Vec<u8>,
}

impl TileRefinementPacket {
    pub fn from_frame(
        frame: &RawFrame,
        grid: &TileGrid,
        coord: TileCoord,
        display_epoch: u32,
        generation: u64,
        compress: bool,
    ) -> Result<Self, FrameError> {
        let (_, _, w, h) = grid.tile_bounds(coord)?;
        let raw_pixels = extract_tile_pixels(frame, grid, coord)?;
        let hash = xxhash64(&raw_pixels);
        let raw_len = raw_pixels.len() as u32;

        let (compressed, payload) = if compress {
            let compressed_data = compress_packbits(&raw_pixels)?;
            if compressed_data.len() < raw_pixels.len() {
                (true, compressed_data)
            } else {
                (false, raw_pixels)
            }
        } else {
            (false, raw_pixels)
        };

        let meta = TileRefinementMeta {
            display_epoch,
            generation,
            coord,
            width: w,
            height: h,
            hash,
        };

        Ok(Self {
            meta,
            format: frame.format,
            raw_len,
            compressed,
            payload,
        })
    }

    pub fn decompress_data(&self) -> Result<Vec<u8>, FrameError> {
        if self.compressed {
            decompress_packbits(&self.payload, self.raw_len as usize)
        } else {
            if self.payload.len() != self.raw_len as usize {
                return Err(FrameError::DataLength {
                    expected: self.raw_len as usize,
                    actual: self.payload.len(),
                });
            }
            Ok(self.payload.clone())
        }
    }

    pub fn validate(&self) -> Result<(), FrameError> {
        let data = self.decompress_data()?;
        let computed_hash = xxhash64(&data);
        if computed_hash != self.meta.hash {
            return Err(FrameError::TileHashMismatch {
                expected: self.meta.hash,
                actual: computed_hash,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TILE_HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&TILE_MAGIC);
        buf.push(1_u8); // Version
        buf.push(self.format as u8);
        buf.extend_from_slice(&(self.compressed as u16).to_be_bytes());
        buf.extend_from_slice(&self.meta.display_epoch.to_be_bytes());
        buf.extend_from_slice(&self.meta.generation.to_be_bytes());
        buf.extend_from_slice(&self.meta.coord.x.to_be_bytes());
        buf.extend_from_slice(&self.meta.coord.y.to_be_bytes());
        buf.extend_from_slice(&(self.meta.width as u16).to_be_bytes());
        buf.extend_from_slice(&(self.meta.height as u16).to_be_bytes());
        buf.extend_from_slice(&self.raw_len.to_be_bytes());
        buf.extend_from_slice(&self.meta.hash.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < TILE_HEADER_LEN {
            return Err(FrameError::CorruptedTilePayload);
        }
        if bytes[0..4] != TILE_MAGIC {
            return Err(FrameError::CorruptedTilePayload);
        }
        let format = PixelFormat::try_from(bytes[5])?;
        let compressed = u16::from_be_bytes(bytes[6..8].try_into().unwrap()) != 0;
        let display_epoch = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let generation = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        let x = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let y = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        let width = u16::from_be_bytes(bytes[28..30].try_into().unwrap()) as u32;
        let height = u16::from_be_bytes(bytes[30..32].try_into().unwrap()) as u32;
        let raw_len = u32::from_be_bytes(bytes[32..36].try_into().unwrap());
        let hash = u64::from_be_bytes(bytes[36..44].try_into().unwrap());
        let payload_len = u32::from_be_bytes(bytes[44..48].try_into().unwrap()) as usize;

        if bytes.len() != TILE_HEADER_LEN + payload_len {
            return Err(FrameError::CorruptedTilePayload);
        }
        let payload = bytes[TILE_HEADER_LEN..TILE_HEADER_LEN + payload_len].to_vec();

        let meta = TileRefinementMeta {
            display_epoch,
            generation,
            coord: TileCoord::new(x, y),
            width,
            height,
            hash,
        };

        let packet = Self {
            meta,
            format,
            raw_len,
            compressed,
            payload,
        };
        packet.validate()?;
        Ok(packet)
    }
}

#[derive(Debug, Clone)]
struct CachedTileEntry {
    meta: TileRefinementMeta,
    #[allow(dead_code)]
    format: PixelFormat,
    raw_pixels: Vec<u8>,
    last_accessed: u64,
}

/// Memory-bounded client-side tile cache with LRU eviction and epoch validation.
#[derive(Debug, Clone)]
pub struct TileRefinementCache {
    max_bytes: usize,
    current_bytes: usize,
    display_epoch: u32,
    grid: Option<TileGrid>,
    entries: HashMap<TileCoord, CachedTileEntry>,
    access_counter: u64,
    stats: TileCacheStats,
}

impl TileRefinementCache {
    #[must_use]
    pub fn new(max_bytes: usize, display_epoch: u32, grid: Option<TileGrid>) -> Self {
        Self {
            max_bytes,
            current_bytes: 0,
            display_epoch,
            grid,
            entries: HashMap::new(),
            access_counter: 0,
            stats: TileCacheStats {
                cached_tiles: 0,
                memory_bytes: 0,
                max_memory_bytes: max_bytes,
                hits: 0,
                misses: 0,
                evictions: 0,
                stale_rejections: 0,
            },
        }
    }

    #[must_use]
    pub fn with_default_limit(display_epoch: u32, grid: Option<TileGrid>) -> Self {
        Self::new(DEFAULT_MAX_CACHE_BYTES, display_epoch, grid)
    }

    #[must_use]
    pub const fn display_epoch(&self) -> u32 {
        self.display_epoch
    }

    #[must_use]
    pub const fn stats(&self) -> TileCacheStats {
        self.stats
    }

    #[must_use]
    pub fn cached_tile_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn memory_bytes(&self) -> usize {
        self.current_bytes
    }

    pub fn invalidate_epoch(&mut self, new_epoch: u32, new_grid: Option<TileGrid>) {
        self.entries.clear();
        self.current_bytes = 0;
        self.display_epoch = new_epoch;
        self.grid = new_grid;
        self.stats.cached_tiles = 0;
        self.stats.memory_bytes = 0;
    }

    pub fn put(&mut self, packet: &TileRefinementPacket) -> Result<bool, FrameError> {
        if packet.meta.display_epoch != self.display_epoch {
            self.stats.stale_rejections += 1;
            return Ok(false);
        }

        if let Some(grid) = &self.grid {
            if packet.meta.coord.x >= grid.tiles_x || packet.meta.coord.y >= grid.tiles_y {
                return Err(FrameError::InvalidTileCoord(
                    packet.meta.coord.x,
                    packet.meta.coord.y,
                ));
            }
        }

        packet.validate()?;
        let raw_pixels = packet.decompress_data()?;
        let coord = packet.meta.coord;
        self.access_counter = self.access_counter.wrapping_add(1);

        let entry_size = raw_pixels.len() + std::mem::size_of::<CachedTileEntry>() + 32;
        if entry_size > self.max_bytes {
            return Err(FrameError::TileCacheLimitExceeded);
        }

        if let Some(existing) = self.entries.get_mut(&coord) {
            if existing.meta.hash == packet.meta.hash {
                existing.last_accessed = self.access_counter;
                self.stats.hits += 1;
                return Ok(true);
            }
            let old_size = existing.raw_pixels.len() + std::mem::size_of::<CachedTileEntry>() + 32;
            self.current_bytes = self.current_bytes.saturating_sub(old_size);
        }

        while self.current_bytes + entry_size > self.max_bytes && !self.entries.is_empty() {
            let oldest_coord = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(c, _)| *c);

            if let Some(to_evict) = oldest_coord {
                if let Some(evicted) = self.entries.remove(&to_evict) {
                    let evicted_size =
                        evicted.raw_pixels.len() + std::mem::size_of::<CachedTileEntry>() + 32;
                    self.current_bytes = self.current_bytes.saturating_sub(evicted_size);
                    self.stats.evictions += 1;
                }
            } else {
                break;
            }
        }

        self.entries.insert(
            coord,
            CachedTileEntry {
                meta: packet.meta,
                format: packet.format,
                raw_pixels,
                last_accessed: self.access_counter,
            },
        );
        self.current_bytes += entry_size;
        self.stats.cached_tiles = self.entries.len();
        self.stats.memory_bytes = self.current_bytes;

        Ok(true)
    }

    pub fn get(&mut self, coord: TileCoord) -> Option<&[u8]> {
        self.access_counter = self.access_counter.wrapping_add(1);
        let counter = self.access_counter;
        if let Some(entry) = self.entries.get_mut(&coord) {
            entry.last_accessed = counter;
            self.stats.hits += 1;
            Some(&entry.raw_pixels)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    pub fn apply_tile_to_frame(
        &mut self,
        coord: TileCoord,
        frame: &mut RawFrame,
    ) -> Result<bool, FrameError> {
        let grid = self.grid.unwrap_or(TileGrid::new(
            frame.descriptor.width,
            frame.descriptor.height,
            DEFAULT_TILE_SIZE,
        )?);

        if let Some(pixels) = self.get(coord) {
            apply_tile_pixels(frame, &grid, coord, pixels)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn apply_all_to_frame(&mut self, frame: &mut RawFrame) -> Result<usize, FrameError> {
        let grid = self.grid.unwrap_or(TileGrid::new(
            frame.descriptor.width,
            frame.descriptor.height,
            DEFAULT_TILE_SIZE,
        )?);

        let mut count = 0;
        let coords: Vec<TileCoord> = self.entries.keys().copied().collect();
        for coord in coords {
            if let Some(entry) = self.entries.get(&coord) {
                apply_tile_pixels(frame, &grid, coord, &entry.raw_pixels)?;
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Host-side idle refinement policy emitting lossless tiles when display remains static > 100ms.
#[derive(Debug, Clone)]
pub struct IdleRefinementPolicy {
    display_epoch: u32,
    grid: TileGrid,
    idle_threshold_ns: u64,
    max_tiles_per_burst: usize,
    last_motion_timestamp_ns: u64,
    compress_tiles: bool,
    generation: u64,
    refined_tiles: HashSet<TileCoord>,
    lossy_candidates: Vec<TileCoord>,
    status: IdleRefinementStatus,
}

impl IdleRefinementPolicy {
    #[must_use]
    pub fn new(display_epoch: u32, grid: TileGrid) -> Self {
        Self {
            display_epoch,
            grid,
            idle_threshold_ns: DEFAULT_IDLE_REFINEMENT_THRESHOLD_NS,
            max_tiles_per_burst: 32,
            last_motion_timestamp_ns: 0,
            compress_tiles: true,
            generation: 0,
            refined_tiles: HashSet::new(),
            lossy_candidates: Vec::new(),
            status: IdleRefinementStatus::ActiveMotion,
        }
    }

    #[must_use]
    pub fn with_config(
        display_epoch: u32,
        grid: TileGrid,
        idle_threshold_ns: u64,
        max_tiles_per_burst: usize,
        compress_tiles: bool,
    ) -> Self {
        Self {
            display_epoch,
            grid,
            idle_threshold_ns,
            max_tiles_per_burst,
            last_motion_timestamp_ns: 0,
            compress_tiles,
            generation: 0,
            refined_tiles: HashSet::new(),
            lossy_candidates: Vec::new(),
            status: IdleRefinementStatus::ActiveMotion,
        }
    }

    #[must_use]
    pub const fn status(&self) -> IdleRefinementStatus {
        self.status
    }

    #[must_use]
    pub const fn display_epoch(&self) -> u32 {
        self.display_epoch
    }

    pub fn reset_epoch(&mut self, new_epoch: u32, new_grid: TileGrid) {
        self.display_epoch = new_epoch;
        self.grid = new_grid;
        self.last_motion_timestamp_ns = 0;
        self.generation = 0;
        self.refined_tiles.clear();
        self.lossy_candidates.clear();
        self.status = IdleRefinementStatus::ActiveMotion;
    }

    pub fn on_frame(
        &mut self,
        frame: &RawFrame,
        diff: &TileDiffResult,
        timestamp_ns: u64,
    ) -> Result<Vec<TileRefinementPacket>, FrameError> {
        if diff.has_motion() {
            self.last_motion_timestamp_ns = timestamp_ns;
            self.status = IdleRefinementStatus::ActiveMotion;

            for dirty in &diff.dirty_tiles {
                self.refined_tiles.remove(dirty);
                if !self.lossy_candidates.contains(dirty) {
                    self.lossy_candidates.push(*dirty);
                }
            }
            return Ok(Vec::new());
        }

        let idle_duration = timestamp_ns.saturating_sub(self.last_motion_timestamp_ns);
        if idle_duration < self.idle_threshold_ns {
            self.status = IdleRefinementStatus::StaticPending {
                idle_duration_ns: idle_duration,
            };
            return Ok(Vec::new());
        }

        if self.lossy_candidates.is_empty() && self.refined_tiles.len() < self.grid.total_tiles() {
            for ty in 0..self.grid.tiles_y {
                for tx in 0..self.grid.tiles_x {
                    let coord = TileCoord::new(tx, ty);
                    if !self.refined_tiles.contains(&coord) {
                        self.lossy_candidates.push(coord);
                    }
                }
            }
        }

        if self.lossy_candidates.is_empty() && self.refined_tiles.len() == self.grid.total_tiles() {
            self.status = IdleRefinementStatus::FullyRefined {
                idle_duration_ns: idle_duration,
            };
            return Ok(Vec::new());
        }

        let batch_size = self.max_tiles_per_burst.min(self.lossy_candidates.len());
        let mut packets = Vec::with_capacity(batch_size);
        let to_process: Vec<TileCoord> = self.lossy_candidates.drain(..batch_size).collect();

        for coord in to_process {
            let packet = TileRefinementPacket::from_frame(
                frame,
                &self.grid,
                coord,
                self.display_epoch,
                self.generation,
                self.compress_tiles,
            )?;
            self.refined_tiles.insert(coord);
            packets.push(packet);
        }

        self.generation += 1;
        self.status = IdleRefinementStatus::Refining {
            idle_duration_ns: idle_duration,
            remaining_tiles: self.lossy_candidates.len(),
        };

        Ok(packets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_capture_repeats_with_same_seed() {
        let config = FakeCaptureConfig {
            width: 64,
            height: 48,
            format: PixelFormat::Bgra8,
            pattern: Pattern::MovingBox,
            seed: 42,
        };
        let mut first = FakeCapture::new(config).expect("capture");
        let mut second = FakeCapture::new(config).expect("capture");
        for timestamp in [0, 16_666_667, 33_333_334] {
            assert_eq!(
                first.capture(timestamp).expect("frame"),
                second.capture(timestamp).expect("frame")
            );
        }
    }

    #[test]
    fn nv12_requires_even_dimensions() {
        assert!(FakeCapture::new(FakeCaptureConfig {
            width: 63,
            height: 48,
            format: PixelFormat::Nv12,
            pattern: Pattern::Gradient,
            seed: 0,
        })
        .is_err());
    }

    #[test]
    fn allocation_is_bounded() {
        assert!(expected_len(16_384, 16_384, PixelFormat::Bgra8, 65_536).is_err());
    }

    #[test]
    fn xxhash64_deterministic_and_streaming() {
        let data = b"LatencyDesk desktop tile differential refinement 2026";
        let hash1 = xxhash64(data);
        let hash2 = xxhash64(data);
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, 0);

        let mut streaming = XxHash64::new(0);
        streaming.update(&data[..10]);
        streaming.update(&data[10..]);
        assert_eq!(streaming.finish(), hash1);

        let mutated = b"LatencyDesk desktop tile differential refinement 2027";
        assert_ne!(xxhash64(mutated), hash1);
    }

    #[test]
    fn tile_grid_geometry_and_boundaries() {
        let grid = TileGrid::new(1920, 1080, 64).expect("grid");
        assert_eq!(grid.tiles_x, 30);
        assert_eq!(grid.tiles_y, 17);
        assert_eq!(grid.total_tiles(), 510);

        // Normal interior tile
        let (x, y, w, h) = grid.tile_bounds(TileCoord::new(0, 0)).expect("bounds");
        assert_eq!((x, y, w, h), (0, 0, 64, 64));

        // Right-edge tile (1920 is exact multiple: 30 * 64 = 1920)
        let (x, y, w, h) = grid.tile_bounds(TileCoord::new(29, 0)).expect("bounds");
        assert_eq!((x, y, w, h), (1856, 0, 64, 64));

        // Bottom-edge tile (1080 % 64 = 56)
        let (x, y, w, h) = grid.tile_bounds(TileCoord::new(0, 16)).expect("bounds");
        assert_eq!((x, y, w, h), (0, 1024, 64, 56));

        // Non-aligned grid
        let uneven = TileGrid::new(100, 100, 64).expect("uneven grid");
        assert_eq!(uneven.tiles_x, 2);
        assert_eq!(uneven.tiles_y, 2);
        let (x, y, w, h) = uneven.tile_bounds(TileCoord::new(1, 1)).expect("bounds");
        assert_eq!((x, y, w, h), (64, 64, 36, 36));
    }

    #[test]
    fn tile_change_detector_distinguishes_motion_and_static() {
        let config = FakeCaptureConfig {
            width: 128,
            height: 128,
            format: PixelFormat::Bgra8,
            pattern: Pattern::MovingBox,
            seed: 10,
        };
        let mut capture = FakeCapture::new(config).expect("capture");
        let grid = TileGrid::new(128, 128, 64).expect("grid");
        let mut detector = TileChangeDetector::new(grid, 1);

        let frame0 = capture.capture(0).expect("frame0");
        let diff0 = detector.detect_changes(&frame0).expect("diff0");
        assert_eq!(diff0.dirty_tiles.len(), 4); // First frame initializes all dirty

        // Same frame content -> static
        let diff_static = detector.detect_changes(&frame0).expect("diff_static");
        assert!(diff_static.is_fully_static());
        assert_eq!(diff_static.dirty_tiles.len(), 0);
        assert_eq!(diff_static.static_tiles.len(), 4);
        assert!(diff_static.dirty_rect.is_none());

        // Moving frame -> dirty
        let frame1 = capture.capture(16_666_667).expect("frame1");
        let diff1 = detector.detect_changes(&frame1).expect("diff1");
        assert!(diff1.has_motion());
        assert!(diff1.dirty_rect.is_some());
    }

    #[test]
    fn packbits_lossless_round_trip() {
        let original = vec![255_u8; 1024];
        let compressed = compress_packbits(&original).expect("compress");
        assert!(compressed.len() < original.len()); // Highly compressible
        let decompressed = decompress_packbits(&compressed, original.len()).expect("decompress");
        assert_eq!(decompressed, original);

        // Mixed literal and repeated data
        let mut mixed = vec![1, 2, 3, 4, 5];
        mixed.extend_from_slice(&[42; 200]);
        mixed.extend_from_slice(&[10, 20, 30]);
        let comp_mixed = compress_packbits(&mixed).expect("compress");
        let decomp_mixed = decompress_packbits(&comp_mixed, mixed.len()).expect("decompress");
        assert_eq!(decomp_mixed, mixed);
    }

    #[test]
    fn tile_refinement_packet_encode_decode_round_trip() {
        let config = FakeCaptureConfig {
            width: 128,
            height: 128,
            format: PixelFormat::Bgra8,
            pattern: Pattern::TextLike,
            seed: 7,
        };
        let mut capture = FakeCapture::new(config).expect("capture");
        let frame = capture.capture(0).expect("frame");
        let grid = TileGrid::new(128, 128, 64).expect("grid");
        let coord = TileCoord::new(0, 0);

        let packet =
            TileRefinementPacket::from_frame(&frame, &grid, coord, 1, 42, true).expect("packet");
        assert_eq!(packet.meta.display_epoch, 1);
        assert_eq!(packet.meta.generation, 42);
        assert_eq!(packet.meta.coord, coord);
        assert_eq!(packet.meta.width, 64);
        assert_eq!(packet.meta.height, 64);

        let encoded = packet.encode();
        assert_eq!(encoded.len(), TILE_HEADER_LEN + packet.payload.len());
        let decoded = TileRefinementPacket::decode(&encoded).expect("decode");
        assert_eq!(packet, decoded);

        let decompressed = decoded.decompress_data().expect("decompressed");
        assert_eq!(xxhash64(&decompressed), packet.meta.hash);
    }

    #[test]
    fn tile_refinement_packet_header_len_and_truncation_rejections() {
        assert_eq!(TILE_HEADER_LEN, 48);

        for len in 0..TILE_HEADER_LEN {
            let truncated = vec![0u8; len];
            let res = TileRefinementPacket::decode(&truncated);
            assert_eq!(res, Err(FrameError::CorruptedTilePayload));
        }

        let config = FakeCaptureConfig {
            width: 64,
            height: 64,
            format: PixelFormat::Bgra8,
            pattern: Pattern::Gradient,
            seed: 12,
        };
        let mut capture = FakeCapture::new(config).expect("capture");
        let frame = capture.capture(0).expect("frame");
        let grid = TileGrid::new(64, 64, 64).expect("grid");
        let packet =
            TileRefinementPacket::from_frame(&frame, &grid, TileCoord::new(0, 0), 1, 1, false)
                .expect("packet");
        let encoded = packet.encode();
        assert!(encoded.len() > TILE_HEADER_LEN);

        let header_only = &encoded[..TILE_HEADER_LEN];
        assert_eq!(
            TileRefinementPacket::decode(header_only),
            Err(FrameError::CorruptedTilePayload)
        );

        let partial_payload = &encoded[..TILE_HEADER_LEN + 5];
        assert_eq!(
            TileRefinementPacket::decode(partial_payload),
            Err(FrameError::CorruptedTilePayload)
        );
    }

    #[test]
    fn tile_refinement_cache_bounds_memory_and_evicts_lru() {
        let grid = TileGrid::new(256, 256, 64).expect("grid");
        // 4x4 = 16 tiles. Each 64x64 BGRA tile is 16384 bytes (~16 KB).
        // Limit cache to 40 KB (room for ~2 tiles).
        let mut cache = TileRefinementCache::new(40 * 1024, 1, Some(grid));

        let config = FakeCaptureConfig {
            width: 256,
            height: 256,
            format: PixelFormat::Bgra8,
            pattern: Pattern::Gradient,
            seed: 1,
        };
        let mut capture = FakeCapture::new(config).expect("capture");
        let frame = capture.capture(0).expect("frame");

        let p0 = TileRefinementPacket::from_frame(&frame, &grid, TileCoord::new(0, 0), 1, 1, false)
            .expect("p0");
        let p1 = TileRefinementPacket::from_frame(&frame, &grid, TileCoord::new(1, 0), 1, 1, false)
            .expect("p1");
        let p2 = TileRefinementPacket::from_frame(&frame, &grid, TileCoord::new(2, 0), 1, 1, false)
            .expect("p2");

        assert!(cache.put(&p0).expect("put p0"));
        assert_eq!(cache.cached_tile_count(), 1);

        assert!(cache.put(&p1).expect("put p1"));
        assert_eq!(cache.cached_tile_count(), 2);

        // Putting 3rd tile must evict LRU tile to stay within 40 KB limit
        assert!(cache.put(&p2).expect("put p2"));
        assert!(cache.memory_bytes() <= 40 * 1024);
        assert_eq!(cache.stats().evictions, 1);

        // Stale epoch packet is rejected
        let p_stale =
            TileRefinementPacket::from_frame(&frame, &grid, TileCoord::new(3, 0), 999, 1, false)
                .expect("stale");
        assert!(!cache.put(&p_stale).expect("stale put"));
        assert_eq!(cache.stats().stale_rejections, 1);
    }

    #[test]
    fn tile_refinement_cache_applies_lossless_tiles_to_frame() {
        let grid = TileGrid::new(128, 128, 64).expect("grid");
        let mut cache = TileRefinementCache::new(DEFAULT_MAX_CACHE_BYTES, 1, Some(grid));

        let config = FakeCaptureConfig {
            width: 128,
            height: 128,
            format: PixelFormat::Bgra8,
            pattern: Pattern::TextLike,
            seed: 99,
        };
        let mut capture = FakeCapture::new(config).expect("capture");
        let original_frame = capture.capture(0).expect("original");

        // Cache tile (0, 0)
        let p0 = TileRefinementPacket::from_frame(
            &original_frame,
            &grid,
            TileCoord::new(0, 0),
            1,
            1,
            false,
        )
        .expect("p0");
        cache.put(&p0).expect("put");

        // Create a corrupted/lossy frame buffer
        let mut corrupted_frame = original_frame.clone();
        corrupted_frame.data[0..100].fill(0x00);
        assert_ne!(corrupted_frame.checksum64(), original_frame.checksum64());

        // Apply cached lossless tile back to corrupted frame
        let applied = cache
            .apply_tile_to_frame(TileCoord::new(0, 0), &mut corrupted_frame)
            .expect("apply");
        assert!(applied);
        assert_eq!(corrupted_frame.checksum64(), original_frame.checksum64());
    }

    #[test]
    fn idle_refinement_policy_triggers_after_100ms() {
        let grid = TileGrid::new(128, 128, 64).expect("grid"); // 4 tiles
        let mut policy = IdleRefinementPolicy::new(1, grid);

        let config = FakeCaptureConfig {
            width: 128,
            height: 128,
            format: PixelFormat::Bgra8,
            pattern: Pattern::TextLike,
            seed: 123,
        };
        let mut capture = FakeCapture::new(config).expect("capture");
        let mut detector = TileChangeDetector::new(grid, 1);

        let frame = capture.capture(0).expect("frame");

        // 1. Initial frame with motion -> emits 0 refinement packets
        let diff_motion = detector.detect_changes(&frame).expect("diff");
        let packets_motion = policy
            .on_frame(&frame, &diff_motion, 0)
            .expect("on_frame motion");
        assert_eq!(packets_motion.len(), 0);
        assert_eq!(policy.status(), IdleRefinementStatus::ActiveMotion);

        // 2. Static frame at 50ms (< 100ms) -> emits 0 refinement packets
        let diff_static = detector.detect_changes(&frame).expect("diff static");
        let packets_50ms = policy
            .on_frame(&frame, &diff_static, 50_000_000)
            .expect("on_frame 50ms");
        assert_eq!(packets_50ms.len(), 0);
        assert_eq!(
            policy.status(),
            IdleRefinementStatus::StaticPending {
                idle_duration_ns: 50_000_000
            }
        );

        // 3. Static frame at 120ms (> 100ms threshold) -> emits lossless refinement packets!
        let packets_120ms = policy
            .on_frame(&frame, &diff_static, 120_000_000)
            .expect("on_frame 120ms");
        assert!(!packets_120ms.is_empty());
        assert_eq!(packets_120ms.len(), 4); // All 4 tiles refined

        // 4. Subsequent frame at 200ms -> all tiles already refined, status is FullyRefined
        let packets_200ms = policy
            .on_frame(&frame, &diff_static, 200_000_000)
            .expect("on_frame 200ms");
        assert_eq!(packets_200ms.len(), 0);
        assert_eq!(
            policy.status(),
            IdleRefinementStatus::FullyRefined {
                idle_duration_ns: 200_000_000
            }
        );
    }

    #[test]
    fn red_pixel_matches_bt601_limited() {
        let (y, u, v) = rgb_to_yuv_bt601_limited(255, 0, 0);
        assert_eq!((y, u, v), (82, 90, 240));
    }

    #[test]
    fn bgra_two_by_two_encodes_nv12_bt601_red() {
        let mut bgra = vec![0u8; 2 * 2 * 4];
        for px in bgra.chunks_mut(4) {
            px[0] = 0;
            px[1] = 0;
            px[2] = 255;
            px[3] = 255;
        }
        let nv12 = bgra_to_nv12_bt601_limited(2, 2, &bgra, 8).expect("convert");
        assert_eq!(nv12.len(), nv12_len(2, 2));
        assert_eq!(nv12[0], 82);
        assert_eq!(nv12[4], 90);
        assert_eq!(nv12[5], 240);
    }

    #[test]
    fn pack_and_parse_nv12_access_unit_round_trip() {
        let payload = vec![1u8, 2, 3, 4, 5, 6];
        let packed = pack_nv12_access_unit(2, 2, &payload);
        let (w, h, body) = parse_nv12_access_unit(&packed).expect("parse");
        assert_eq!((w, h), (2, 2));
        assert_eq!(body, payload.as_slice());
        assert!(parse_nv12_access_unit(&[0, 0, 0, 3, 0, 0, 0, 2, 1]).is_none());
    }

    #[test]
    fn letterbox_skip_gates() {
        assert!(letterbox_can_skip_scale(1920, 1080, 1920, 1080));
        assert!(letterbox_can_skip_scale(1280, 720, 1920, 1080));
        assert!(!letterbox_can_skip_scale(1920, 1080, 1280, 720));
        assert!(!letterbox_can_skip_scale(1919, 1080, 1920, 1080));
        assert!(!letterbox_can_skip_scale(1920, 1079, 1920, 1080));
        assert!(!letterbox_can_skip_scale(2, 1, 1920, 1080));
        assert!(!letterbox_can_skip_scale(0, 1080, 1920, 1080));
    }

    #[test]
    fn letterbox_identity_skip_is_bit_identical() {
        let width = 8_u32;
        let height = 6_u32;
        let mut src = vec![0u8; (width * height * 4) as usize];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let (geom, out) =
            letterbox_scale_bgra(&src, width, height, (width * 4) as usize, 1920, 1080)
                .expect("skip");
        assert_eq!(geom, letterbox_identity_geom(width, height));
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), src.as_slice());
    }

    #[test]
    fn letterbox_1080p_skip_borrows_source_without_canvas() {
        let width = 1920_u32;
        let height = 1080_u32;
        let src = vec![0x5A_u8; (width * height * 4) as usize];
        let (geom, out) =
            letterbox_scale_bgra(&src, width, height, (width * 4) as usize, width, height)
                .expect("1080p skip");
        assert!(letterbox_can_skip_scale(width, height, width, height));
        assert_eq!(geom, letterbox_identity_geom(width, height));
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), src.as_slice());
    }

    #[test]
    fn letterbox_scale_preserves_aspect_no_stretch() {
        let geom = letterbox_geom(1920, 1200, 640, 360).expect("geom");
        assert_eq!(geom.content_width % 2, 0);
        assert_eq!(geom.content_height % 2, 0);
        assert!(geom.content_width <= 640);
        assert!(geom.content_height <= 360);
        assert!(geom.out_width <= 640);
        assert!(geom.out_height <= 360);
        let src_w = 8_u32;
        let src_h = 4_u32;
        let mut src = vec![0u8; (src_w * src_h * 4) as usize];
        for y in 0..src_h {
            for x in 0..src_w {
                let index = ((y * src_w + x) * 4) as usize;
                if x < src_w / 2 {
                    src[index..index + 4].copy_from_slice(&[255, 255, 255, 255]);
                }
            }
        }
        let (geom, out) =
            letterbox_scale_bgra(&src, src_w, src_h, (src_w * 4) as usize, 4, 2).expect("scale");
        assert!(!letterbox_can_skip_scale(src_w, src_h, 4, 2));
        assert_eq!((geom.out_width, geom.out_height), (4, 2));
        assert!(matches!(out, Cow::Owned(_)));
        assert_eq!(out.len(), 4 * 2 * 4);
        let content_x0 = geom.offset_x as usize;
        let left = (content_x0) * 4;
        assert!(out[left] > 200);
        let right_x = (geom.offset_x + geom.content_width.saturating_sub(1)) as usize;
        let right = right_x * 4;
        assert!(out[right] < 40);
    }
}
