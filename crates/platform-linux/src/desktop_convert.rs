//! CPU conversion helpers for the X11 desktop capture path.
//!
//! These stay free of X11 so they can be tested on every host.

use std::borrow::Cow;
use std::fmt;

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
    pack_nv12_access_unit_into(width, height, nv12, &mut out);
    out
}

/// Packs one raw NV12 access unit into caller-owned storage.
///
/// Reusing the same output across frames avoids a full-frame allocation in the
/// raw preview path while preserving the exact wire representation produced by
/// [`pack_nv12_access_unit`].
pub fn pack_nv12_access_unit_into(width: u32, height: u32, nv12: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(8_usize.saturating_add(nv12.len()));
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(nv12);
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

#[must_use]
pub fn yuv_to_rgb_bt601_limited(y: u8, u: u8, v: u8) -> (u8, u8, u8) {
    let y = i32::from(y) - 16;
    let u = i32::from(u) - 128;
    let v = i32::from(v) - 128;
    let r = (298 * y + 409 * v + 128) >> 8;
    let g = (298 * y - 100 * u - 208 * v + 128) >> 8;
    let b = (298 * y + 516 * u + 128) >> 8;
    (
        r.clamp(0, 255) as u8,
        g.clamp(0, 255) as u8,
        b.clamp(0, 255) as u8,
    )
}

pub fn nv12_to_argb_u32(
    width: u32,
    height: u32,
    nv12: &[u8],
    out: &mut Vec<u32>,
) -> Result<(), ConvertError> {
    if width < 2 || height < 2 || width % 2 != 0 || height % 2 != 0 {
        return Err(ConvertError::InvalidDimensions);
    }
    let required = nv12_len(width, height);
    if nv12.len() < required {
        return Err(ConvertError::BufferTooSmall {
            required,
            actual: nv12.len(),
        });
    }
    let width = width as usize;
    let height = height as usize;
    let y_plane = &nv12[..width * height];
    let uv = &nv12[width * height..required];
    out.clear();
    out.resize(width * height, 0);
    for row in 0..height {
        let uv_row = (row / 2) * width;
        for col in 0..width {
            let y = y_plane[row * width + col];
            let uv_index = uv_row + (col & !1);
            let u = uv[uv_index];
            let v = uv[uv_index + 1];
            let (r, g, b) = yuv_to_rgb_bt601_limited(y, u, v);
            out[row * width + col] = (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b);
        }
    }
    Ok(())
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
    let max_w = even_dimension(max_width);
    let max_h = even_dimension(max_height);
    if src_width == 0 || src_height == 0 || max_w < 2 || max_h < 2 {
        return Err(ConvertError::InvalidDimensions);
    }
    if letterbox_can_skip_scale(src_width, src_height, max_width, max_height) {
        return Ok(letterbox_identity_geom(src_width, src_height));
    }
    let src_w = u64::from(src_width);
    let src_h = u64::from(src_height);
    let max_w64 = u64::from(max_w);
    let max_h64 = u64::from(max_h);
    let (out_width, out_height) = if src_w * max_h64 >= src_h * max_w64 {
        let height = even_dimension(((src_h * max_w64) / src_w) as u32)
            .max(2)
            .min(max_h);
        (max_w, height)
    } else {
        let width = even_dimension(((src_w * max_h64) / src_h) as u32)
            .max(2)
            .min(max_w);
        (width, max_h)
    };
    Ok(LetterboxGeom {
        out_width,
        out_height,
        content_width: out_width,
        content_height: out_height,
        offset_x: 0,
        offset_y: 0,
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
    if out_w == 0 || out_h == 0 {
        return Ok(geom);
    }
    for y in 0..out_h {
        let y0 = (y * src_h) / out_h;
        let y1 = ((y + 1) * src_h) / out_h;
        let y1 = y1.max(y0 + 1).min(src_h);
        for x in 0..out_w {
            let x0 = (x * src_w) / out_w;
            let x1 = ((x + 1) * src_w) / out_w;
            let x1 = x1.max(x0 + 1).min(src_w);
            let mut blue = 0_u32;
            let mut green = 0_u32;
            let mut red = 0_u32;
            let mut alpha = 0_u32;
            let mut count = 0_u32;
            for sy in y0..y1 {
                let row = sy * src_stride;
                for sx in x0..x1 {
                    let src_px = row + sx * 4;
                    blue += u32::from(src[src_px]);
                    green += u32::from(src[src_px + 1]);
                    red += u32::from(src[src_px + 2]);
                    alpha += u32::from(src[src_px + 3]);
                    count += 1;
                }
            }
            let dst = (y * out_w + x) * 4;
            if count == 0 {
                continue;
            }
            out[dst] = (blue / count) as u8;
            out[dst + 1] = (green / count) as u8;
            out[dst + 2] = (red / count) as u8;
            out[dst + 3] = (alpha / count) as u8;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn even_dimension_clears_low_bit() {
        assert_eq!(even_dimension(1280), 1280);
        assert_eq!(even_dimension(1279), 1278);
    }

    #[test]
    fn red_pixel_matches_bt601_limited() {
        let (y, u, v) = rgb_to_yuv_bt601_limited(255, 0, 0);
        assert_eq!((y, u, v), (82, 90, 240));
    }

    #[test]
    fn nv12_argb_round_trip_keeps_red_channel_dominant() {
        let mut nv12 = vec![0_u8; nv12_len(2, 2)];
        nv12[0] = 82;
        nv12[1] = 82;
        nv12[2] = 82;
        nv12[3] = 82;
        nv12[4] = 90;
        nv12[5] = 240;
        let mut argb = Vec::new();
        nv12_to_argb_u32(2, 2, &nv12, &mut argb).expect("convert");
        assert_eq!(argb.len(), 4);
        let r = (argb[0] >> 16) & 0xff;
        let g = (argb[0] >> 8) & 0xff;
        let b = argb[0] & 0xff;
        assert!(r > g && r > b, "red={r} green={g} blue={b}");
    }
    #[test]
    fn bgra_two_by_two_encodes_nv12_size() {
        let mut bgra = vec![0u8; 2 * 2 * 4];
        // solid red
        for px in bgra.chunks_mut(4) {
            px[0] = 0;
            px[1] = 0;
            px[2] = 255;
            px[3] = 255;
        }
        let nv12 = bgra_to_nv12_bt601_limited(2, 2, &bgra, 8).expect("convert");
        assert_eq!(nv12.len(), 6);
        assert_eq!(nv12[0], 82);
        assert_eq!(nv12[4], 90);
        assert_eq!(nv12[5], 240);
    }

    #[test]
    fn pack_and_parse_round_trip() {
        let payload = vec![1u8, 2, 3, 4, 5, 6];
        let packed = pack_nv12_access_unit(2, 2, &payload);
        let (w, h, body) = parse_nv12_access_unit(&packed).expect("parse");
        assert_eq!((w, h), (2, 2));
        assert_eq!(body, payload.as_slice());
    }

    #[test]
    fn pack_into_reuses_reserved_output_storage() {
        let payload = vec![1u8, 2, 3, 4, 5, 6];
        let mut packed = Vec::with_capacity(64);
        let allocation = packed.as_ptr();

        pack_nv12_access_unit_into(2, 2, &payload, &mut packed);

        assert_eq!(packed.as_ptr(), allocation);
        let (w, h, body) = parse_nv12_access_unit(&packed).expect("parse");
        assert_eq!((w, h), (2, 2));
        assert_eq!(body, payload.as_slice());
    }

    #[test]
    fn letterbox_fits_inside_even_canvas() {
        let geom = letterbox_geom(1920, 1080, 1280, 720).expect("geom");
        assert_eq!((geom.out_width, geom.out_height), (1280, 720));
        assert_eq!(geom.content_width % 2, 0);
        assert_eq!(geom.content_height % 2, 0);
        assert!(geom.content_width <= 1280);
        assert!(geom.content_height <= 720);
    }

    #[test]
    fn letterbox_preserves_sixteen_by_ten() {
        let geom = letterbox_geom(1920, 1200, 640, 360).expect("geom");
        assert_eq!((geom.out_width, geom.out_height), (576, 360));
        assert_eq!(geom.offset_x, 0);
        assert_eq!(geom.offset_y, 0);
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
    fn letterbox_scale_preserves_aspect_pixels() {
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
        assert_eq!((geom.offset_x, geom.offset_y), (0, 0));
        assert!(matches!(out, Cow::Owned(_)));
        assert_eq!(out.len(), 4 * 2 * 4);
        assert!(out[0] > 200);
        assert!(out[2] > 200);
        let right = 28;
        assert!(out[right] < 40);
    }
}
