//! X11 root capture and XTEST injection for the first remote-control slice.

use crate::desktop_convert::{
    bgra_to_nv12_bt601_limited, letterbox_geom, letterbox_scale_bgra, map_letterboxed_pointer,
    LetterboxGeom,
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
                "unsupported root depth {} bpp",
                bits_per_pixel
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
        let bgra = self.capture_root_bgra()?;
        let src_w = self.screen_width;
        let src_h = self.screen_height;
        if src_w == 0 || src_h == 0 {
            return Err(X11DesktopError::InvalidDimensions);
        }
        let (geom, scaled) =
            letterbox_scale_bgra(&bgra, src_w, src_h, src_w as usize * 4, max_width, max_height)?;
        self.last_geom = Some(geom);
        let nv12 = bgra_to_nv12_bt601_limited(
            geom.out_width,
            geom.out_height,
            &scaled,
            geom.out_width as usize * 4,
        )?;
        Ok((geom.out_width, geom.out_height, nv12))
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
                let x_button = match button {
                    1 => 1,
                    2 => 3,
                    3 => 2,
                    4 => 4,
                    5 => 5,
                    _ => return Ok(()),
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
                let x = (i32::from(pointer.root_x) + dx)
                    .clamp(0, self.screen_width.saturating_sub(1) as i32);
                let y = (i32::from(pointer.root_y) + dy)
                    .clamp(0, self.screen_height.saturating_sub(1) as i32);
                self.warp(x as i16, y as i16)?;
            }
            AppliedInput::PointerMotionAbsolute {
                x,
                y,
                width,
                height,
            } => {
                let geom = self.last_geom.unwrap_or_else(|| {
                    letterbox_geom(self.screen_width, self.screen_height, width, height).unwrap_or(
                        LetterboxGeom {
                            out_width: width.max(2),
                            out_height: height.max(2),
                            content_width: width.max(2),
                            content_height: height.max(2),
                            offset_x: 0,
                            offset_y: 0,
                        },
                    )
                });
                let (sx, sy) = map_letterboxed_pointer(
                    x,
                    y,
                    width,
                    height,
                    geom,
                    self.screen_width,
                    self.screen_height,
                );
                self.warp(sx as i16, sy as i16)?;
            }
            AppliedInput::Wheel {
                vertical,
                horizontal: _,
            } => {
                if vertical == 0 {
                    return Ok(());
                }
                let button = if vertical > 0 { 4 } else { 5 };
                let clicks = vertical.unsigned_abs().min(8).max(1);
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

    fn capture_root_bgra(&mut self) -> Result<Vec<u8>, X11DesktopError> {
        let geometry = self
            .conn
            .get_geometry(self.root)
            .map_err(protocol)?
            .reply()
            .map_err(protocol)?;
        self.screen_width = u32::from(geometry.width).max(2);
        self.screen_height = u32::from(geometry.height).max(2);
        let width = self.screen_width.min(u32::from(u16::MAX));
        let height = self.screen_height.min(u32::from(u16::MAX));
        let depth = geometry.depth;
        let pixmap = self.conn.generate_id().map_err(protocol)?;
        self.conn
            .create_pixmap(depth, pixmap, self.root, width as u16, height as u16)
            .map_err(protocol)?;
        let gc = self.conn.generate_id().map_err(protocol)?;
        self.conn
            .create_gc(gc, self.root, &xproto::CreateGCAux::new())
            .map_err(protocol)?;
        let copy = self.conn.copy_area(
            self.root,
            pixmap,
            gc,
            0,
            0,
            0,
            0,
            width as u16,
            height as u16,
        );
        let image = self.conn.get_image(
            ImageFormat::Z_PIXMAP,
            pixmap,
            0,
            0,
            width as u16,
            height as u16,
            !0,
        );
        let result = (|| {
            copy.map_err(protocol)?;
            let reply = image.map_err(protocol)?.reply().map_err(protocol)?;
            let mut bgra = vec![0u8; width as usize * height as usize * 4];
            unpack_zpixmap_bgra(
                &reply.data,
                width,
                height,
                self.bits_per_pixel,
                self.image_lsb_first,
                self.red_mask,
                self.green_mask,
                self.blue_mask,
                &mut bgra,
            )?;
            Ok(bgra)
        })();
        let _ = self.conn.free_gc(gc);
        let _ = self.conn.free_pixmap(pixmap);
        result
    }


}

fn protocol<E: fmt::Display>(error: E) -> X11DesktopError {
    X11DesktopError::Protocol(error.to_string())
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
    bits_per_pixel: u8,
    lsb_first: bool,
    red_mask: u32,
    green_mask: u32,
    blue_mask: u32,
    out: &mut [u8],
) -> Result<(), X11DesktopError> {
    let width = width as usize;
    let height = height as usize;
    let src_bpp = if bits_per_pixel == 24 { 3 } else { 4 };
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
                if lsb_first {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes(bytes)
                }
            } else {
                let bytes = [data[src], data[src + 1], data[src + 2], 0];
                if lsb_first {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
                }
            };
            let r = extract_channel(pixel, red_mask);
            let g = extract_channel(pixel, green_mask);
            let b = extract_channel(pixel, blue_mask);
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
