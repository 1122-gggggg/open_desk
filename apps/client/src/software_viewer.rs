//! Portable interactive viewer for non-Windows clients.
//!
//! Decodes negotiated H.264 with OpenH264 or presents packed NV12, then shows
//! RGB through minifb so Linux and macOS can drive a real window and input.

use crate::secure::{is_clean_peer_close, negotiate_video_stream, send_input_event};
use latencydesk_h264::SoftwareH264Decoder;
use latencydesk_input::{InputEvent, InputState};
use latencydesk_platform_linux::nv12_to_argb_u32;
use latencydesk_protocol::VideoCodec;
use latencydesk_socket_transport::product::ProductSession;
use minifb::{Key, MouseButton, MouseMode, Window, WindowOptions};
use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const SNAPSHOT_CADENCE: Duration = Duration::from_millis(500);
const MAX_VIEWER_FPS: u32 = 120;
const MAX_PENDING_RELIABLE_INPUT: usize = 256;

fn viewer_fps(negotiated: u32) -> usize {
    negotiated.clamp(1, MAX_VIEWER_FPS) as usize
}

#[derive(Default)]
struct PointerPosition(Option<(u32, u32)>);

impl PointerPosition {
    fn changed(&mut self, position: (u32, u32)) -> bool {
        if self.0 == Some(position) {
            false
        } else {
            self.0 = Some(position);
            true
        }
    }
}

fn flush_pending_motion(
    input_tx: &tokio::sync::mpsc::Sender<InputEvent>,
    pending: &mut Option<InputEvent>,
) -> Result<(), &'static str> {
    let Some(event) = pending.take() else {
        return Ok(());
    };
    match input_tx.try_send(event) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
            *pending = Some(event);
            Ok(())
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err("input lane closed"),
    }
}

struct PendingReliableInput {
    events: VecDeque<InputEvent>,
    max_events: usize,
}

impl PendingReliableInput {
    fn new(max_events: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(max_events.max(1)),
            max_events: max_events.max(1),
        }
    }

    /// Returns true when discrete events had to be coalesced into the latest
    /// complete input state to preserve a hard memory bound.
    fn push(&mut self, event: InputEvent, held: &InputState) -> bool {
        if self.events.len() < self.max_events {
            self.events.push_back(event);
            return false;
        }
        self.events.clear();
        self.events.push_back(InputEvent::Snapshot(held.clone()));
        true
    }

    fn flush(
        &mut self,
        input_tx: &tokio::sync::mpsc::Sender<InputEvent>,
    ) -> Result<(), &'static str> {
        while let Some(event) = self.events.pop_front() {
            match input_tx.try_send(event) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                    self.events.push_front(event);
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    return Err("input lane closed")
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.events.len()
    }

    #[cfg(test)]
    fn front(&self) -> Option<&InputEvent> {
        self.events.front()
    }
}

pub fn run(
    runtime: &tokio::runtime::Runtime,
    session: ProductSession,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let (config, _control) = runtime.block_on(negotiate_video_stream(&session, timeout))?;
    let width = config.width as usize;
    let height = config.height as usize;
    let mut decoder = if config.codec == VideoCodec::H264 {
        Some(SoftwareH264Decoder::new(config.width, config.height)?)
    } else {
        None
    };

    let first = runtime
        .block_on(async { tokio::time::timeout(timeout, session.receive_media_frame()).await })
        .map_err(|_| "timed out waiting for the first media frame")??;
    if first.header.stream_id != config.stream_id || first.header.codec_epoch != config.codec_epoch
    {
        return Err("first media frame does not match negotiated stream".into());
    }
    let mut pixels = Vec::with_capacity(width.saturating_mul(height));
    present_payload(
        config.codec,
        config.width,
        config.height,
        &first.bytes,
        decoder.as_mut(),
        &mut pixels,
    )?;

    let mut window = Window::new(
        "LatencyDesk",
        width,
        height,
        WindowOptions {
            resize: false,
            ..WindowOptions::default()
        },
    )?;
    window.set_target_fps(viewer_fps(config.fps));
    window.update_with_buffer(&pixels, width, height)?;

    println!(
        "Client Connected. Software {} -> RGB window open ({}x{}@{}).",
        if config.codec == VideoCodec::H264 {
            "H.264"
        } else {
            "raw NV12"
        },
        config.width,
        config.height,
        config.fps
    );
    println!("Close the window to disconnect safely.");

    let latest = Arc::new(Mutex::new(None::<Vec<u8>>));
    let network_latest = Arc::clone(&latest);
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<InputEvent>(128);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let network_session = session.clone();
    let reliable_timeout = timeout.min(Duration::from_secs(5));
    let mut network_task = runtime.spawn(async move {
        let result = network_loop(
            network_session,
            config,
            network_latest,
            &mut input_rx,
            &mut shutdown_rx,
            reliable_timeout,
        )
        .await;
        let _ = done_tx.send(result.clone());
        result
    });

    let mut held = InputState::default();
    let mut prev_keys = HashSet::<Key>::new();
    let mut prev_buttons = [false; 3];
    let mut pointer_position = PointerPosition::default();
    let mut pending_motion = None;
    let mut pending_reliable = PendingReliableInput::new(MAX_PENDING_RELIABLE_INPUT);
    let mut ui_error = None;
    'viewer: while window.is_open() && !window.is_key_down(Key::Escape) {
        match done_rx.try_recv() {
            Ok(Err(error)) => {
                ui_error = Some(error);
                break;
            }
            Ok(Ok(())) | Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        let latest_bytes = match latest.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => {
                ui_error = Some("latest-frame slot lock was poisoned".to_owned());
                break;
            }
        };
        if let Some(bytes) = latest_bytes {
            if let Err(error) = present_payload(
                config.codec,
                config.width,
                config.height,
                &bytes,
                decoder.as_mut(),
                &mut pixels,
            ) {
                ui_error = Some(error.to_string());
                break;
            }
            if let Err(error) = window.update_with_buffer(&pixels, width, height) {
                ui_error = Some(format!("window presentation failed: {error}"));
                break;
            }
        } else {
            window.update();
        }

        if let Err(error) = pending_reliable.flush(&input_tx) {
            ui_error = Some(error.to_owned());
            break;
        }
        if let Err(error) = flush_pending_motion(&input_tx, &mut pending_motion) {
            ui_error = Some(error.to_owned());
            break;
        }

        if let Some((x, y)) = window.get_mouse_pos(MouseMode::Clamp) {
            let position = (x as u32, y as u32);
            if pointer_position.changed(position) {
                let event = InputEvent::PointerMotionAbsolute {
                    x: position.0,
                    y: position.1,
                    width: config.width,
                    height: config.height,
                };
                apply_held(&mut held, &event);
                pending_motion = Some(event);
                if let Err(error) = flush_pending_motion(&input_tx, &mut pending_motion) {
                    ui_error = Some(error.to_owned());
                    break 'viewer;
                }
            }
        }
        for (index, button) in [MouseButton::Left, MouseButton::Right, MouseButton::Middle]
            .into_iter()
            .enumerate()
        {
            let pressed = window.get_mouse_down(button);
            if pressed != prev_buttons[index] {
                prev_buttons[index] = pressed;
                let event = InputEvent::PointerButton {
                    button: index as u8,
                    pressed,
                };
                apply_held(&mut held, &event);
                if pending_reliable.push(event, &held) {
                    eprintln!(
                        "input: reliable queue saturated; coalesced to the latest state snapshot"
                    );
                }
                if let Err(error) = pending_reliable.flush(&input_tx) {
                    ui_error = Some(error.to_owned());
                    break 'viewer;
                }
            }
        }
        let keys: HashSet<Key> = window.get_keys().into_iter().collect();
        for key in keys.difference(&prev_keys) {
            if let Some(code) = hid_usage(*key) {
                let event = InputEvent::Key {
                    code,
                    pressed: true,
                };
                apply_held(&mut held, &event);
                if pending_reliable.push(event, &held) {
                    eprintln!(
                        "input: reliable queue saturated; coalesced to the latest state snapshot"
                    );
                }
                if let Err(error) = pending_reliable.flush(&input_tx) {
                    ui_error = Some(error.to_owned());
                    break 'viewer;
                }
            }
        }
        for key in prev_keys.difference(&keys) {
            if let Some(code) = hid_usage(*key) {
                let event = InputEvent::Key {
                    code,
                    pressed: false,
                };
                apply_held(&mut held, &event);
                if pending_reliable.push(event, &held) {
                    eprintln!(
                        "input: reliable queue saturated; coalesced to the latest state snapshot"
                    );
                }
                if let Err(error) = pending_reliable.flush(&input_tx) {
                    ui_error = Some(error.to_owned());
                    break 'viewer;
                }
            }
        }
        prev_keys = keys;
    }

    let _ = shutdown_tx.send(());
    // The network loop owns ReleaseAll and sends it after observing shutdown.
    let network_result = match runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), &mut network_task).await })
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(format!("secure transport task failed: {error}")),
        Err(_) => {
            network_task.abort();
            Err("secure transport cleanup timed out".to_owned())
        }
    };
    match (ui_error, network_result) {
        (None, Ok(())) => Ok(()),
        (Some(error), Ok(())) | (None, Err(error)) => Err(error.into()),
        (Some(ui), Err(network)) => Err(format!("{ui}; {network}").into()),
    }
}

fn present_payload(
    codec: VideoCodec,
    width: u32,
    height: u32,
    bytes: &[u8],
    decoder: Option<&mut SoftwareH264Decoder>,
    pixels: &mut Vec<u32>,
) -> Result<(), Box<dyn Error>> {
    match codec {
        VideoCodec::H264 => {
            let decoder = decoder.ok_or("H.264 decoder missing")?;
            let frame = match decoder.decode_annex_b(bytes)? {
                Some(frame) => frame,
                None => return Ok(()),
            };
            nv12_to_argb_u32(width, height, &frame.nv12, pixels)?;
        }
        VideoCodec::RawNv12 => {
            let (parsed_w, parsed_h, nv12) =
                crate::parse_nv12_access_unit(bytes).ok_or("invalid packed NV12 access unit")?;
            if (parsed_w, parsed_h) != (width, height) {
                return Err("NV12 geometry does not match negotiated stream".into());
            }
            nv12_to_argb_u32(width, height, nv12, pixels)?;
        }
    }
    Ok(())
}

async fn network_loop(
    session: ProductSession,
    config: latencydesk_protocol::VideoStreamConfig,
    latest: Arc<Mutex<Option<Vec<u8>>>>,
    input_rx: &mut tokio::sync::mpsc::Receiver<InputEvent>,
    shutdown: &mut tokio::sync::oneshot::Receiver<()>,
    timeout: Duration,
) -> Result<(), String> {
    let mut sequence = 0_u64;
    let mut snapshot = tokio::time::interval(SNAPSHOT_CADENCE);
    snapshot.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut held = InputState::default();
    loop {
        tokio::select! {
            _ = &mut *shutdown => break,
            event = input_rx.recv() => {
                let Some(event) = event else { break };
                apply_held(&mut held, &event);
                sequence = sequence.saturating_add(1);
                if let Err(error) = send_input_event(&session, sequence, event, timeout).await {
                    if is_clean_peer_close(error.as_ref()) {
                        break;
                    }
                    return Err(error.to_string());
                }
            }
            _ = snapshot.tick() => {
                sequence = sequence.saturating_add(1);
                if let Err(error) = send_input_event(
                    &session,
                    sequence,
                    InputEvent::Snapshot(held.clone()),
                    timeout,
                )
                .await {
                    if is_clean_peer_close(error.as_ref()) {
                        break;
                    }
                    return Err(error.to_string());
                }
            }
            frame = session.receive_media_frame() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) if is_clean_peer_close(&error) => break,
                    Err(error) => return Err(error.to_string()),
                };
                if frame.header.stream_id != config.stream_id
                    || frame.header.codec_epoch != config.codec_epoch
                {
                    return Err("media frame does not match negotiated stream".to_owned());
                }
                let mut slot = latest
                    .lock()
                    .map_err(|_| "latest-frame slot lock was poisoned".to_owned())?;
                *slot = Some(frame.bytes);
            }
        }
    }
    sequence = sequence.saturating_add(1);
    match send_input_event(&session, sequence, InputEvent::ReleaseAll, timeout).await {
        Ok(()) => Ok(()),
        Err(error) if is_clean_peer_close(error.as_ref()) => Ok(()),
        Err(error) => Err(format!("failed to release input state: {error}")),
    }
}

fn apply_held(state: &mut InputState, event: &InputEvent) {
    match event {
        InputEvent::Key { code, pressed } => {
            let _ = state.set_key(*code, *pressed);
        }
        InputEvent::PointerButton { button, pressed } => {
            let _ = state.set_button(*button, *pressed);
        }
        InputEvent::ReleaseAll => *state = InputState::default(),
        InputEvent::Snapshot(snapshot) => *state = snapshot.clone(),
        _ => {}
    }
}

fn hid_usage(key: Key) -> Option<u16> {
    Some(match key {
        Key::A => 0x04,
        Key::B => 0x05,
        Key::C => 0x06,
        Key::D => 0x07,
        Key::E => 0x08,
        Key::F => 0x09,
        Key::G => 0x0a,
        Key::H => 0x0b,
        Key::I => 0x0c,
        Key::J => 0x0d,
        Key::K => 0x0e,
        Key::L => 0x0f,
        Key::M => 0x10,
        Key::N => 0x11,
        Key::O => 0x12,
        Key::P => 0x13,
        Key::Q => 0x14,
        Key::R => 0x15,
        Key::S => 0x16,
        Key::T => 0x17,
        Key::U => 0x18,
        Key::V => 0x19,
        Key::W => 0x1a,
        Key::X => 0x1b,
        Key::Y => 0x1c,
        Key::Z => 0x1d,
        Key::Key1 => 0x1e,
        Key::Key2 => 0x1f,
        Key::Key3 => 0x20,
        Key::Key4 => 0x21,
        Key::Key5 => 0x22,
        Key::Key6 => 0x23,
        Key::Key7 => 0x24,
        Key::Key8 => 0x25,
        Key::Key9 => 0x26,
        Key::Key0 => 0x27,
        Key::Enter => 0x28,
        Key::Escape => 0x29,
        Key::Backspace => 0x2a,
        Key::Tab => 0x2b,
        Key::Space => 0x2c,
        Key::Right => 0x4f,
        Key::Left => 0x50,
        Key::Down => 0x51,
        Key::Up => 0x52,
        Key::LeftCtrl => 0xe0,
        Key::LeftShift => 0xe1,
        Key::LeftAlt => 0xe2,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacing_is_bounded_and_never_zero() {
        assert_eq!(viewer_fps(0), 1);
        assert_eq!(viewer_fps(60), 60);
        assert_eq!(viewer_fps(u32::MAX), MAX_VIEWER_FPS as usize);
    }

    #[test]
    fn pointer_motion_only_emits_when_position_changes() {
        let mut pointer = PointerPosition::default();
        assert!(pointer.changed((1, 2)));
        assert!(!pointer.changed((1, 2)));
        assert!(pointer.changed((2, 2)));
    }

    #[test]
    fn pointer_motion_keeps_the_latest_position_while_the_queue_is_full() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender.try_send(InputEvent::ReleaseAll).expect("fill queue");
        let mut pending = Some(InputEvent::PointerMotionAbsolute {
            x: 10,
            y: 20,
            width: 640,
            height: 360,
        });

        flush_pending_motion(&sender, &mut pending).expect("full queue is not fatal");
        pending = Some(InputEvent::PointerMotionAbsolute {
            x: 30,
            y: 40,
            width: 640,
            height: 360,
        });
        assert!(matches!(receiver.try_recv(), Ok(InputEvent::ReleaseAll)));
        flush_pending_motion(&sender, &mut pending).expect("flush latest");

        assert!(pending.is_none());
        assert!(matches!(
            receiver.try_recv(),
            Ok(InputEvent::PointerMotionAbsolute { x: 30, y: 40, .. })
        ));
    }

    #[test]
    fn reliable_input_overflow_coalesces_to_the_latest_state_snapshot() {
        let mut queue = PendingReliableInput::new(2);
        let mut held = InputState::default();
        held.set_key(4, true).expect("hold A");
        assert!(!queue.push(
            InputEvent::Key {
                code: 4,
                pressed: true,
            },
            &held,
        ));
        held.set_key(5, true).expect("hold B");
        assert!(!queue.push(
            InputEvent::Key {
                code: 5,
                pressed: true,
            },
            &held,
        ));
        held.set_button(0, true).expect("hold button");
        assert!(queue.push(
            InputEvent::PointerButton {
                button: 0,
                pressed: true,
            },
            &held,
        ));

        assert_eq!(queue.len(), 1);
        assert!(matches!(
            queue.front(),
            Some(InputEvent::Snapshot(snapshot))
                if snapshot.key_pressed(4)
                    && snapshot.key_pressed(5)
                    && snapshot.button_pressed(0)
        ));
    }
}
