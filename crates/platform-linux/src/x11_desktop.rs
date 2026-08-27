//! X11 root capture and XTEST injection for the first remote-control slice.

use crate::desktop_convert::{
    bgra_to_nv12_bt601_limited_into, letterbox_can_skip_scale, letterbox_geom,
    letterbox_identity_geom, letterbox_scale_bgra_into, map_letterboxed_pointer, LetterboxGeom,
};
use crate::hid_to_evdev;
use latencydesk_input::AppliedInput;
use std::env;
use std::fmt;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{self, ConnectionExt as XprotoExt, ImageFormat, Screen, Visualtype};
use x11rb::protocol::xtest::ConnectionExt as XtestExt;
use x11rb::rust_connection::RustConnection;

const X_KEY_PRESS: u8 = 2;
const X_KEY_RELEASE: u8 = 3;
const X_BUTTON_PRESS: u8 = 4;
const X_BUTTON_RELEASE: u8 = 5;
const X_MOTION_NOTIFY: u8 = 6;

#[derive(Debug)]
pub enum X11DesktopError {
    DisplayMissing,
    Connect(String),
    Protocol(String),
    InvalidDimensions,
    Convert(crate::desktop_convert::ConvertError),
}

impl fmt::Display for X11DesktopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DisplayMissing => write!(
                formatter,
                "DISPLAY is not set; X11 desktop capture requires an X session (e.g. export DISPLAY=:0). This slice does not use portal/PipeWire."
            ),
            Self::Connect(message) => write!(formatter, "failed to connect to X11 display: {message}"),
            Self::Protocol(message) => write!(formatter, "X11 protocol error: {message}"),
            Self::InvalidDimensions => write!(formatter, "X11 root or capture size is invalid"),
            Self::Convert(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for X11DesktopError {}

impl From<crate::desktop_convert::ConvertError> for X11DesktopError {
    fn from(error: crate::desktop_convert::ConvertError) -> Self {
        Self::Convert(error)
    }
}

pub struct X11DesktopSession {
    conn: RustConnection,
    root: xproto::Window,
    screen_width: u32,
    screen_height: u32,
    bits_per_pixel: u8,
    image_lsb_first: bool,
    red_mask: u32,
    green_mask: u32,
    blue_mask: u32,
    last_geom: Option<LetterboxGeom>,
    bgra_scratch: Vec<u8>,
    nv12_scratch: Vec<u8>,
    scaled_scratch: Vec<u8>,
}

#[derive(Clone, Copy)]
struct ZPixmapFormat {
    bits_per_pixel: u8,
    lsb_first: bool,
    red_mask: u32,
    green_mask: u32,
    blue_mask: u32,
}

impl X11DesktopSession {
    pub fn open() -> Result<Self, X11DesktopError> {
        match env::var_os("DISPLAY") {
            None => return Err(X11DesktopError::DisplayMissing),
            Some(value) if value.is_empty() => return Err(X11DesktopError::DisplayMissing),
            Some(_) => {}
        }

        let (conn, screen_num) = RustConnection::connect(None)
            .map_err(|error| X11DesktopError::Connect(error.to_string()))?;
        let setup = conn.setup();
        let screen: &Screen = setup
            .roots
            .get(screen_num)
            .ok_or(X11DesktopError::InvalidDimensions)?;
        let visual = find_visual(setup, screen.root_visual)
            .ok_or_else(|| X11DesktopError::Protocol("root visual not found".into()))?;
        let bits_per_pixel = setup
            .pixmap_formats
            .iter()
            .find(|format| format.depth == screen.root_depth)
            .map(|format| format.bits_per_pixel)
            .unwrap_or(32);
        if bits_per_pixel != 24 && bits_per_pixel != 32 {
            return Err(X11DesktopError::Protocol(format!(
                "unsupported root depth {bits_per_pixel} bpp"
            )));
        }

        conn.xtest_get_version(2, 1)
            .map_err(protocol)?
            .reply()
            .map_err(protocol)?;

        let geometry = conn
            .get_geometry(screen.root)
            .map_err(protocol)?
            .reply()
            .map_err(protocol)?;
        let screen_width = u32::from(geometry.width).max(2);
        let screen_height = u32::from(geometry.height).max(2);

        Ok(Self {
            root: screen.root,
            screen_width,
            screen_height,
            bits_per_pixel,
            image_lsb_first: setup.image_byte_order == xproto::ImageOrder::LSB_FIRST,
            red_mask: visual.red_mask,
            green_mask: visual.green_mask,
            blue_mask: visual.blue_mask,
            last_geom: None,
            bgra_scratch: Vec::new(),
            nv12_scratch: Vec::new(),
            scaled_scratch: Vec::new(),
            conn,
        })
    }

    #[must_use]
    pub const fn screen_size(&self) -> (u32, u32) {
        (self.screen_width, self.screen_height)
    }

    pub fn capture_nv12(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<(u32, u32, Vec<u8>), X11DesktopError> {
        self.capture_root_bgra()?;
        let src_w = self.screen_width;
        let src_h = self.screen_height;
        if src_w < 2 || src_h < 2 {
            return Err(X11DesktopError::InvalidDimensions);
        }
        let src_stride = src_w as usize * 4;
        let bgra_needed = src_stride.saturating_mul(src_h as usize);
        if self.bgra_scratch.len() < bgra_needed {
            return Err(X11DesktopError::InvalidDimensions);
        }
        if letterbox_can_skip_scale(src_w, src_h, max_width, max_height) {
            let geom = letterbox_identity_geom(src_w, src_h);
            self.last_geom = Some(geom);
            bgra_to_nv12_bt601_limited_into(
                src_w,
                src_h,
                &self.bgra_scratch,
                src_stride,
                &mut self.nv12_scratch,
            )?;
            return Ok((src_w, src_h, self.nv12_scratch.clone()));
        }
        let geom = letterbox_scale_bgra_into(
            &self.bgra_scratch,
            src_w,
            src_h,
            src_stride,
            max_width,
            max_height,
            &mut self.scaled_scratch,
        )?;
        self.last_geom = Some(geom);
        bgra_to_nv12_bt601_limited_into(
            geom.out_width,
            geom.out_height,
            &self.scaled_scratch,
            geom.out_width as usize * 4,
            &mut self.nv12_scratch,
        )?;
        Ok((geom.out_width, geom.out_height, self.nv12_scratch.clone()))
    }

    pub fn inject(&mut self, action: AppliedInput) -> Result<(), X11DesktopError> {
        match action {
            AppliedInput::Key { code, pressed } => {
                let keycode = hid_to_evdev(code).saturating_add(8);
                if keycode == 0 || keycode > 255 {
                    return Ok(());
                }
                let kind = if pressed { X_KEY_PRESS } else { X_KEY_RELEASE };
                self.conn
                    .xtest_fake_input(kind, keycode as u8, 0, x11rb::NONE, 0, 0, 0)
                    .map_err(protocol)?;
            }
            AppliedInput::PointerButton { button, pressed } => {
                let Some(x_button) = pointer_button_to_x11(button) else {
                    return Ok(());
                };
                let kind = if pressed {
                    X_BUTTON_PRESS
                } else {
                    X_BUTTON_RELEASE
                };
                self.conn
                    .xtest_fake_input(kind, x_button, 0, x11rb::NONE, 0, 0, 0)
                    .map_err(protocol)?;
            }
            AppliedInput::PointerMotionRelative { dx, dy } => {
                let pointer = self
                    .conn
                    .query_pointer(self.root)
                    .map_err(protocol)?
                    .reply()
                    .map_err(protocol)?;
                let x = relative_pointer_coordinate(pointer.root_x, dx, self.screen_width);
                let y = relative_pointer_coordinate(pointer.root_y, dy, self.screen_height);
                self.warp(x, y)?;
            }
            AppliedInput::PointerMotionAbsolute {
                x,
                y,
                width,
                height,
            } => {
                let geom = match self.last_geom {
                    Some(geom)
                        if geom.out_width == width.max(1) && geom.out_height == height.max(1) =>
                    {
                        geom
                    }
                    _ => letterbox_geom(self.screen_width, self.screen_height, width, height)
                        .unwrap_or(LetterboxGeom {
                            out_width: width.max(2),
                            out_height: height.max(2),
                            content_width: width.max(2),
                            content_height: height.max(2),
                            offset_x: 0,
                            offset_y: 0,
                        }),
                };
                let (sx, sy) = map_letterboxed_pointer(
                    x,
                    y,
                    width,
                    height,
                    geom,
                    self.screen_width,
                    self.screen_height,
                );
                self.warp(
                    absolute_pointer_coordinate(sx, self.screen_width),
                    absolute_pointer_coordinate(sy, self.screen_height),
                )?;
            }
            AppliedInput::Wheel {
                vertical,
                horizontal: _,
            } => {
                if vertical == 0 {
                    return Ok(());
                }
                let button = if vertical > 0 { 4 } else { 5 };
                let clicks = vertical.unsigned_abs().clamp(1, 8);
                for _ in 0..clicks {
                    self.conn
                        .xtest_fake_input(X_BUTTON_PRESS, button, 0, x11rb::NONE, 0, 0, 0)
                        .map_err(protocol)?;
                    self.conn
                        .xtest_fake_input(X_BUTTON_RELEASE, button, 0, x11rb::NONE, 0, 0, 0)
                        .map_err(protocol)?;
                }
            }
        }
        self.conn.flush().map_err(protocol)?;
        Ok(())
    }

    fn warp(&self, x: i16, y: i16) -> Result<(), X11DesktopError> {
        self.conn
            .xtest_fake_input(X_MOTION_NOTIFY, 0, 0, self.root, x, y, 0)
            .map_err(protocol)?;
        Ok(())
    }

    fn refresh_root_geometry(&mut self) -> Result<bool, X11DesktopError> {
        let geometry = self
            .conn
            .get_geometry(self.root)
            .map_err(protocol)?
            .reply()
            .map_err(protocol)?;
        let width = u32::from(geometry.width).max(2);
        let height = u32::from(geometry.height).max(2);
        let changed = width != self.screen_width || height != self.screen_height;
        if changed {
            self.screen_width = width;
            self.screen_height = height;
            self.last_geom = None;
        }
        Ok(changed)
    }

    fn get_image_unpacked(&mut self) -> Result<(), X11DesktopError> {
        let width = self.screen_width.min(u32::from(u16::MAX));
        let height = self.screen_height.min(u32::from(u16::MAX));
        let reply = self
            .conn
            .get_image(
                ImageFormat::Z_PIXMAP,
                self.root,
                0,
                0,
                width as u16,
                height as u16,
                !0,
            )
            .map_err(protocol)?
            .reply()
            .map_err(protocol)?;
        let needed = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(4);
        if self.bgra_scratch.len() < needed {
            self.bgra_scratch.resize(needed, 0);
        }
        unpack_zpixmap_bgra(
            &reply.data,
            width,
            height,
            ZPixmapFormat {
                bits_per_pixel: self.bits_per_pixel,
                lsb_first: self.image_lsb_first,
                red_mask: self.red_mask,
                green_mask: self.green_mask,
                blue_mask: self.blue_mask,
            },
            &mut self.bgra_scratch,
        )?;
        Ok(())
    }

    fn capture_root_bgra(&mut self) -> Result<(), X11DesktopError> {
        self.refresh_root_geometry()?;
        match self.get_image_unpacked() {
            Ok(()) => Ok(()),
            Err(_) => {
                self.refresh_root_geometry()?;
                self.get_image_unpacked()
            }
        }
    }
}

fn pointer_button_to_x11(button: u8) -> Option<u8> {
    match button {
        0 => Some(1),
        1 => Some(3),
        2 => Some(2),
        3 => Some(8),
        4 => Some(9),
        _ => None,
    }
}

fn protocol<E: fmt::Display>(error: E) -> X11DesktopError {
    X11DesktopError::Protocol(error.to_string())
}

fn absolute_pointer_coordinate(value: u32, screen_extent: u32) -> i16 {
    let maximum = screen_extent.saturating_sub(1).min(i16::MAX as u32);
    value.min(maximum) as i16
}

fn relative_pointer_coordinate(current: i16, delta: i32, screen_extent: u32) -> i16 {
    let maximum = screen_extent.saturating_sub(1).min(i16::MAX as u32) as i32;
    i32::from(current).saturating_add(delta).clamp(0, maximum) as i16
}

fn find_visual(setup: &xproto::Setup, visual_id: xproto::Visualid) -> Option<&Visualtype> {
    setup.roots.iter().find_map(|screen| {
        screen.allowed_depths.iter().find_map(|depth| {
            depth
                .visuals
                .iter()
                .find(|visual| visual.visual_id == visual_id)
        })
    })
}

fn unpack_zpixmap_bgra(
    data: &[u8],
    width: u32,
    height: u32,
    format: ZPixmapFormat,
    out: &mut [u8],
) -> Result<(), X11DesktopError> {
    let width = width as usize;
    let height = height as usize;
    let src_bpp = if format.bits_per_pixel == 24 { 3 } else { 4 };
    let required = width * height * src_bpp;
    if data.len() < required {
        return Err(X11DesktopError::Protocol(format!(
            "GetImage returned {} bytes, expected at least {required}",
            data.len()
        )));
    }
    let needed = width * height * 4;
    if out.len() < needed {
        return Err(X11DesktopError::InvalidDimensions);
    }
    for y in 0..height {
        for x in 0..width {
            let src = (y * width + x) * src_bpp;
            let pixel = if src_bpp == 4 {
                let bytes = [data[src], data[src + 1], data[src + 2], data[src + 3]];
                if format.lsb_first {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes(bytes)
                }
            } else {
                let bytes = [data[src], data[src + 1], data[src + 2], 0];
                if format.lsb_first {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
                }
            };
            let r = extract_channel(pixel, format.red_mask);
            let g = extract_channel(pixel, format.green_mask);
            let b = extract_channel(pixel, format.blue_mask);
            let dst = (y * width + x) * 4;
            out[dst] = b;
            out[dst + 1] = g;
            out[dst + 2] = r;
            out[dst + 3] = 255;
        }
    }
    Ok(())
}

fn extract_channel(pixel: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let bits = mask.count_ones();
    let value = (pixel & mask) >> shift;
    if bits >= 8 {
        (value >> (bits - 8)) as u8
    } else {
        let max = (1u32 << bits) - 1;
        ((value * 255) / max) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::{absolute_pointer_coordinate, pointer_button_to_x11, relative_pointer_coordinate};

    #[test]
    fn producer_pointer_buttons_map_to_x11_buttons() {
        assert_eq!(pointer_button_to_x11(0), Some(1));
        assert_eq!(pointer_button_to_x11(1), Some(3));
        assert_eq!(pointer_button_to_x11(2), Some(2));
        assert_eq!(pointer_button_to_x11(3), Some(8));
        assert_eq!(pointer_button_to_x11(4), Some(9));
        assert_eq!(pointer_button_to_x11(5), None);
    }

    #[test]
    fn relative_pointer_extremes_saturate_without_overflow() {
        assert_eq!(relative_pointer_coordinate(100, i32::MAX, 1_920), 1_919);
        assert_eq!(relative_pointer_coordinate(100, i32::MIN, 1_920), 0);
        assert_eq!(relative_pointer_coordinate(100, 25, 1_920), 125);
        assert_eq!(relative_pointer_coordinate(100, -25, 1_920), 75);
    }

    #[test]
    fn pointer_coordinates_respect_x11_signed_wire_range() {
        assert_eq!(
            relative_pointer_coordinate(i16::MAX, i32::MAX, u32::MAX),
            i16::MAX
        );
        assert_eq!(absolute_pointer_coordinate(u32::MAX, u32::MAX), i16::MAX);
        assert_eq!(absolute_pointer_coordinate(500, 1), 0);
    }
}
