//! Windows GDI desktop capture and SendInput injection for the secure host.

#[cfg(windows)]
use crate::applied_input_to_win32;
#[cfg(windows)]
use crate::win32_input_consts::{INPUT_KEYBOARD, INPUT_MOUSE};
#[cfg(windows)]
use crate::Win32Input;
use latencydesk_frame::ConvertError;
#[cfg(windows)]
use latencydesk_frame::{
    bgra_to_nv12_bt601_limited_into, letterbox_can_skip_scale, letterbox_identity_geom,
    letterbox_scale_bgra_into,
};
use latencydesk_input::AppliedInput;
use latencydesk_platform::PlatformError;
use std::fmt;

#[derive(Debug)]
pub enum WindowsDesktopError {
    Unsupported,
    Capture(String),
    Inject(String),
    InvalidDimensions,
    Convert(ConvertError),
    Mapping(PlatformError),
}

impl fmt::Display for WindowsDesktopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(
                formatter,
                "Windows desktop capture requires a Windows target"
            ),
            Self::Capture(message) => write!(formatter, "GDI desktop capture failed: {message}"),
            Self::Inject(message) => write!(formatter, "SendInput failed: {message}"),
            Self::InvalidDimensions => {
                write!(formatter, "Windows desktop or capture size is invalid")
            }
            Self::Convert(error) => write!(formatter, "{error}"),
            Self::Mapping(error) => write!(formatter, "input mapping failed: {error}"),
        }
    }
}

impl std::error::Error for WindowsDesktopError {}

impl From<ConvertError> for WindowsDesktopError {
    fn from(error: ConvertError) -> Self {
        Self::Convert(error)
    }
}

pub struct WindowsDesktopSession {
    screen_width: u32,
    screen_height: u32,
    #[cfg(windows)]
    bgra_scratch: Vec<u8>,
    #[cfg(windows)]
    nv12_scratch: Vec<u8>,
    #[cfg(windows)]
    scaled_scratch: Vec<u8>,
}

impl WindowsDesktopSession {
    pub fn open() -> Result<Self, WindowsDesktopError> {
        #[cfg(not(windows))]
        {
            return Err(WindowsDesktopError::Unsupported);
        }
        #[cfg(windows)]
        {
            let (width, height, _, _) = desktop_metrics()?;
            if width < 2 || height < 2 {
                return Err(WindowsDesktopError::InvalidDimensions);
            }
            Ok(Self {
                screen_width: width,
                screen_height: height,
                bgra_scratch: Vec::new(),
                nv12_scratch: Vec::new(),
                scaled_scratch: Vec::new(),
            })
        }
    }

    #[must_use]
    pub const fn screen_size(&self) -> (u32, u32) {
        (self.screen_width, self.screen_height)
    }

    pub fn capture_nv12(
        &mut self,
        max_width: u32,
        max_height: u32,
    ) -> Result<(u32, u32, Vec<u8>), WindowsDesktopError> {
        #[cfg(not(windows))]
        {
            let _ = (max_width, max_height);
            return Err(WindowsDesktopError::Unsupported);
        }
        #[cfg(windows)]
        {
            let (src_w, src_h, src_stride) = capture_desktop_bgra(&mut self.bgra_scratch)?;
            self.screen_width = src_w;
            self.screen_height = src_h;
            if src_w < 2 || src_h < 2 {
                return Err(WindowsDesktopError::InvalidDimensions);
            }
            if letterbox_can_skip_scale(src_w, src_h, max_width, max_height) {
                let geom = letterbox_identity_geom(src_w, src_h);
                bgra_to_nv12_bt601_limited_into(
                    geom.out_width,
                    geom.out_height,
                    &self.bgra_scratch,
                    src_stride,
                    &mut self.nv12_scratch,
                )?;
                return Ok((geom.out_width, geom.out_height, self.nv12_scratch.clone()));
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
            bgra_to_nv12_bt601_limited_into(
                geom.out_width,
                geom.out_height,
                &self.scaled_scratch,
                geom.out_width as usize * 4,
                &mut self.nv12_scratch,
            )?;
            Ok((geom.out_width, geom.out_height, self.nv12_scratch.clone()))
        }
    }

    pub fn inject(&mut self, action: AppliedInput) -> Result<(), WindowsDesktopError> {
        #[cfg(not(windows))]
        {
            let _ = action;
            return Err(WindowsDesktopError::Unsupported);
        }
        #[cfg(windows)]
        {
            let inputs = applied_input_to_win32(action).map_err(WindowsDesktopError::Mapping)?;
            for input in inputs {
                send_one(input)?;
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
fn desktop_metrics() -> Result<(u32, u32, i32, i32), WindowsDesktopError> {
    let mut width = 0_u32;
    let mut height = 0_u32;
    let mut origin_x = 0_i32;
    let mut origin_y = 0_i32;
    let status = crate::native::ffi::gdi_desktop_metrics(
        &mut width,
        &mut height,
        &mut origin_x,
        &mut origin_y,
    );
    if status != crate::native::STATUS_OK {
        return Err(WindowsDesktopError::Capture(format!(
            "desktop metrics status {status}"
        )));
    }
    Ok((width, height, origin_x, origin_y))
}

#[cfg(windows)]
fn capture_desktop_bgra(pixels: &mut Vec<u8>) -> Result<(u32, u32, usize), WindowsDesktopError> {
    let (mut width, mut height, _, _) = desktop_metrics()?;
    if width < 2 || height < 2 {
        return Err(WindowsDesktopError::InvalidDimensions);
    }
    let mut needed = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(4);
    if pixels.len() < needed {
        pixels.resize(needed, 0);
    }
    let mut stride = 0_u32;
    let mut status =
        crate::native::ffi::gdi_capture_desktop_bgra(pixels, &mut width, &mut height, &mut stride);
    if status == crate::native::STATUS_INVALID_ARGUMENT && width >= 2 && height >= 2 {
        needed = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(4);
        if pixels.len() < needed {
            pixels.resize(needed, 0);
        }
        status = crate::native::ffi::gdi_capture_desktop_bgra(
            pixels,
            &mut width,
            &mut height,
            &mut stride,
        );
    }
    if status != crate::native::STATUS_OK {
        return Err(WindowsDesktopError::Capture(format!(
            "BitBlt status {status}"
        )));
    }
    if width < 2 || height < 2 || stride < width.saturating_mul(4) {
        return Err(WindowsDesktopError::InvalidDimensions);
    }
    let needed = (stride as usize).saturating_mul(height as usize);
    if pixels.len() < needed {
        return Err(WindowsDesktopError::Capture(format!(
            "pixel buffer too small: required {needed}, actual {}",
            pixels.len()
        )));
    }
    Ok((width, height, stride as usize))
}

#[cfg(windows)]
fn send_one(input: Win32Input) -> Result<(), WindowsDesktopError> {
    let status = match input {
        Win32Input::Mouse(mouse) => crate::native::ffi::send_win32_input(
            INPUT_MOUSE,
            mouse.dx,
            mouse.dy,
            mouse.mouse_data,
            mouse.flags,
            0,
            0,
            mouse.time,
            mouse.extra_info as u64,
        ),
        Win32Input::Keyboard(key) => crate::native::ffi::send_win32_input(
            INPUT_KEYBOARD,
            0,
            0,
            0,
            key.flags,
            key.vk_code,
            key.scan_code,
            key.time,
            key.extra_info as u64,
        ),
        Win32Input::Hardware(_) => {
            return Err(WindowsDesktopError::Inject(
                "hardware INPUT is not used by the product path".into(),
            ));
        }
    };
    if status != crate::native::STATUS_OK {
        return Err(WindowsDesktopError::Inject(format!(
            "native status {status} (no UAC/secure-desktop bypass)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_actionable() {
        let message = WindowsDesktopError::InvalidDimensions.to_string();
        assert!(message.contains("invalid"));
    }

    #[cfg(not(windows))]
    #[test]
    fn open_fails_closed_off_windows() {
        let error = WindowsDesktopSession::open().expect_err("non-Windows must fail closed");
        assert!(matches!(error, WindowsDesktopError::Unsupported));
    }
}
