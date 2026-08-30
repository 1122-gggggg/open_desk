//! Portable OpenH264 encode/decode for platforms without a hardware MFT.
//!
//! OpenH264 emits constrained-baseline 4:2:0 without B-frames. Product peers
//! still advertise `H264High420` as the 8-bit 4:2:0 low-delay compatibility
//! floor; Media Foundation decoders accept this bitstream.

use crate::{wrap_access_unit, ContinuityPlanner, H264Error, LowDelayPolicy};
use latencydesk_codec::EncodedAccessUnit;
use openh264::decoder::Decoder;
use openh264::encoder::{BitRate, Encoder, EncoderConfig, FrameRate};
use openh264::formats::{YUVSlices, YUVSource};

pub struct SoftwareH264Encoder {
    encoder: Encoder,
    planner: ContinuityPlanner,
    width: u32,
    height: u32,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
    force_idr: bool,
    capture_sequence: u64,
}
pub struct SoftwareH264Decoder {
    decoder: Decoder,
    width: u32,
    height: u32,
}

pub struct DecodedNv12 {
    pub width: u32,
    pub height: u32,
    pub nv12: Vec<u8>,
}

impl SoftwareH264Encoder {
    pub fn new(
        width: u32,
        height: u32,
        fps: u32,
        target_bitrate_bps: u32,
        codec_epoch: u32,
        policy: LowDelayPolicy,
    ) -> Result<Self, H264Error> {
        let _policy = policy.validate()?;
        if width == 0 || height == 0 || width % 2 != 0 || height % 2 != 0 || fps == 0 {
            return Err(H264Error::InvalidNv12);
        }
        let y_len = (width as usize).saturating_mul(height as usize);
        let uv_len = y_len / 4;
        let config = EncoderConfig::new()
            .bitrate(BitRate::from_bps(target_bitrate_bps.max(64_000)))
            .max_frame_rate(FrameRate::from_hz(fps as f32))
            .skip_frames(false)
            .num_threads(1);
        let encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)
            .map_err(|_| H264Error::SoftwareEncode)?;
        Ok(Self {
            encoder,
            planner: ContinuityPlanner::new(codec_epoch, 1),
            width,
            height,
            y: vec![0; y_len],
            u: vec![0; uv_len],
            v: vec![0; uv_len],
            force_idr: true,
            capture_sequence: 0,
        })
    }

    pub fn request_idr(&mut self) {
        self.force_idr = true;
        self.planner.note_output_drop();
        self.encoder.force_intra_frame();
    }

    pub fn encode_nv12(
        &mut self,
        nv12: &[u8],
        capture_timestamp_ns: u64,
    ) -> Result<EncodedAccessUnit, H264Error> {
        split_nv12_into_i420(
            self.width,
            self.height,
            nv12,
            &mut self.y,
            &mut self.u,
            &mut self.v,
        )?;
        if self.force_idr {
            self.encoder.force_intra_frame();
        }
        let source = YUVSlices::new(
            (&self.y, &self.u, &self.v),
            (self.width as usize, self.height as usize),
            (
                self.width as usize,
                (self.width / 2) as usize,
                (self.width / 2) as usize,
            ),
        );
        let bitstream = self
            .encoder
            .encode(&source)
            .map_err(|_| H264Error::SoftwareEncode)?;
        let bytes = bitstream.to_vec();
        if bytes.is_empty() {
            return Err(H264Error::SoftwareEncode);
        }
        self.capture_sequence = self.capture_sequence.saturating_add(1);
        match wrap_access_unit(
            &mut self.planner,
            &bytes,
            self.capture_sequence,
            capture_timestamp_ns,
        ) {
            Ok(unit) => {
                self.force_idr = false;
                Ok(unit)
            }
            Err(H264Error::RecoveryPointRequired) => {
                self.encoder.force_intra_frame();
                self.force_idr = true;
                Err(H264Error::RecoveryPointRequired)
            }
            Err(error) => Err(error),
        }
    }
}

impl SoftwareH264Decoder {
    pub fn new(width: u32, height: u32) -> Result<Self, H264Error> {
        if width == 0 || height == 0 || width % 2 != 0 || height % 2 != 0 {
            return Err(H264Error::InvalidNv12);
        }
        let decoder = Decoder::new().map_err(|_| H264Error::SoftwareDecode)?;
        Ok(Self {
            decoder,
            width,
            height,
        })
    }

    pub fn decode_annex_b(&mut self, annex_b: &[u8]) -> Result<Option<DecodedNv12>, H264Error> {
        let decoded = self
            .decoder
            .decode(annex_b)
            .map_err(|_| H264Error::SoftwareDecode)?;
        let Some(yuv) = decoded else {
            return Ok(None);
        };
        let (width, height) = yuv.dimensions();
        let width = u32::try_from(width).map_err(|_| H264Error::InvalidNv12)?;
        let height = u32::try_from(height).map_err(|_| H264Error::InvalidNv12)?;
        if width != self.width || height != self.height {
            return Err(H264Error::InvalidNv12);
        }
        Ok(Some(DecodedNv12 {
            width,
            height,
            nv12: i420_to_nv12(width, height, yuv.y(), yuv.u(), yuv.v(), yuv.strides())?,
        }))
    }
}

fn split_nv12_into_i420(
    width: u32,
    height: u32,
    nv12: &[u8],
    y: &mut [u8],
    u: &mut [u8],
    v: &mut [u8],
) -> Result<(), H264Error> {
    let width = width as usize;
    let height = height as usize;
    let y_len = width.saturating_mul(height);
    let uv_len = y_len / 4;
    if nv12.len() < y_len + y_len / 2 || y.len() != y_len || u.len() != uv_len || v.len() != uv_len
    {
        return Err(H264Error::InvalidNv12);
    }
    y.copy_from_slice(&nv12[..y_len]);
    let chroma = &nv12[y_len..y_len + y_len / 2];
    for (index, pair) in chroma.chunks_exact(2).enumerate() {
        u[index] = pair[0];
        v[index] = pair[1];
    }
    Ok(())
}

fn i420_to_nv12(
    width: u32,
    height: u32,
    y: &[u8],
    u: &[u8],
    v: &[u8],
    strides: (usize, usize, usize),
) -> Result<Vec<u8>, H264Error> {
    let width = width as usize;
    let height = height as usize;
    let y_len = width.saturating_mul(height);
    let mut nv12 = vec![0_u8; y_len + y_len / 2];
    let (y_stride, u_stride, v_stride) = strides;
    if y_stride < width {
        return Err(H264Error::InvalidNv12);
    }
    for row in 0..height {
        let src = row.saturating_mul(y_stride);
        let dst = row.saturating_mul(width);
        let row_bytes = y.get(src..src + width).ok_or(H264Error::InvalidNv12)?;
        nv12[dst..dst + width].copy_from_slice(row_bytes);
    }
    let chroma_height = height / 2;
    let chroma_width = width / 2;
    let mut chroma = y_len;
    for row in 0..chroma_height {
        let u_row = row.saturating_mul(u_stride);
        let v_row = row.saturating_mul(v_stride);
        for col in 0..chroma_width {
            nv12[chroma] = *u.get(u_row + col).ok_or(H264Error::InvalidNv12)?;
            nv12[chroma + 1] = *v.get(v_row + col).ok_or(H264Error::InvalidNv12)?;
            chroma += 2;
        }
    }
    Ok(nv12)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LowDelayPolicy;

    #[test]
    fn nv12_round_trip_planes_match() {
        let width = 16_u32;
        let height = 8_u32;
        let y_len = (width * height) as usize;
        let mut nv12 = vec![0_u8; y_len + y_len / 2];
        for (index, byte) in nv12.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let mut y = vec![0; y_len];
        let mut u = vec![0; y_len / 4];
        let mut v = vec![0; y_len / 4];
        split_nv12_into_i420(width, height, &nv12, &mut y, &mut u, &mut v).expect("split");
        let restored = i420_to_nv12(
            width,
            height,
            &y,
            &u,
            &v,
            (width as usize, width as usize / 2, width as usize / 2),
        )
        .expect("merge");
        assert_eq!(restored, nv12);
    }

    #[test]
    fn software_encoder_emits_low_delay_idr_then_p() {
        let mut encoder =
            SoftwareH264Encoder::new(16, 16, 30, 200_000, 1, LowDelayPolicy::baseline(60))
                .expect("encoder");
        let nv12 = vec![128_u8; 16 * 16 + 16 * 16 / 2];
        let first = encoder.encode_nv12(&nv12, 1_000).expect("idr");
        assert!(first.meta.recovery_point);
        let second = encoder.encode_nv12(&nv12, 2_000).expect("p");
        assert!(!second.meta.recovery_point);
        assert_eq!(second.meta.dependency_frame_id, Some(first.meta.frame_id));
    }
}
