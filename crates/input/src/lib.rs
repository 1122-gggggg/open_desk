//! Bounded input wire model with duplicate suppression and state reconciliation.

use std::fmt;

const MAGIC: [u8; 4] = *b"LDIN";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 24;
const MAX_MESSAGE_BYTES: usize = 256;
const MAX_KEY_CODE: u16 = 511;
const KEY_WORDS: usize = 8;

/// Monotonic input envelope. `session_epoch` changes on reconnect so stale
/// datagrams from an old transport cannot affect a new desktop session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputMessage {
    pub session_epoch: u32,
    pub sequence: u64,
    pub event: InputEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputEvent {
    Key {
        code: u16,
        pressed: bool,
    },
    PointerButton {
        button: u8,
        pressed: bool,
    },
    PointerMotionRelative {
        dx: i32,
        dy: i32,
    },
    PointerMotionAbsolute {
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    },
    Wheel {
        horizontal: i16,
        vertical: i16,
    },
    /// Complete idempotent state, sent periodically and after reconnect.
    Snapshot(InputState),
    /// Explicit sender-side focus loss. Receivers release every active input.
    ReleaseAll,
}

/// Complete keyboard/button state. Key codes are provider-neutral USB-HID-like
/// usages in the range 0..=511; platform translation occurs after reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputState {
    key_words: [u64; KEY_WORDS],
    buttons: u16,
}

impl Default for InputState {
    fn default() -> Self {
        Self {
            key_words: [0; KEY_WORDS],
            buttons: 0,
        }
    }
}

impl InputState {
    pub fn set_key(&mut self, code: u16, pressed: bool) -> Result<(), InputError> {
        validate_key(code)?;
        let word = usize::from(code / 64);
        let bit = code % 64;
        if pressed {
            self.key_words[word] |= 1_u64 << bit;
        } else {
            self.key_words[word] &= !(1_u64 << bit);
        }
        Ok(())
    }

    #[must_use]
    pub fn key_pressed(&self, code: u16) -> bool {
        if code > MAX_KEY_CODE {
            return false;
        }
        let word = usize::from(code / 64);
        let bit = code % 64;
        self.key_words[word] & (1_u64 << bit) != 0
    }

    pub fn set_button(&mut self, button: u8, pressed: bool) -> Result<(), InputError> {
        if button >= 16 {
            return Err(InputError::Button(button));
        }
        if pressed {
            self.buttons |= 1_u16 << button;
        } else {
            self.buttons &= !(1_u16 << button);
        }
        Ok(())
    }

    #[must_use]
    pub fn button_pressed(&self, button: u8) -> bool {
        button < 16 && self.buttons & (1_u16 << button) != 0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buttons == 0 && self.key_words.iter().all(|word| *word == 0)
    }

    fn encode_into(&self, output: &mut Vec<u8>) {
        for word in self.key_words {
            output.extend_from_slice(&word.to_be_bytes());
        }
        output.extend_from_slice(&self.buttons.to_be_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, InputError> {
        let expected = KEY_WORDS * 8 + 2;
        if bytes.len() != expected {
            return Err(InputError::PayloadLength);
        }
        let mut key_words = [0_u64; KEY_WORDS];
        for (index, word) in key_words.iter_mut().enumerate() {
            *word = read_u64(bytes, index * 8);
        }
        Ok(Self {
            key_words,
            buttons: read_u16(bytes, KEY_WORDS * 8),
        })
    }
}

impl InputMessage {
    pub fn encode(&self) -> Result<Vec<u8>, InputError> {
        let (kind, mut payload) = encode_event(&self.event)?;
        if payload.len() > MAX_MESSAGE_BYTES - HEADER_LEN {
            return Err(InputError::PayloadLength);
        }
        let payload_len = u16::try_from(payload.len()).map_err(|_| InputError::PayloadLength)?;
        let mut output = Vec::with_capacity(HEADER_LEN + payload.len());
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.push(kind);
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(&self.session_epoch.to_be_bytes());
        output.extend_from_slice(&self.sequence.to_be_bytes());
        output.extend_from_slice(&0_u32.to_be_bytes());
        output.append(&mut payload);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, InputError> {
        if bytes.len() < HEADER_LEN || bytes.len() > MAX_MESSAGE_BYTES {
            return Err(InputError::PayloadLength);
        }
        if bytes[0..4] != MAGIC {
            return Err(InputError::Magic);
        }
        if bytes[4] != VERSION {
            return Err(InputError::Version(bytes[4]));
        }
        let kind = bytes[5];
        let payload_len = usize::from(read_u16(bytes, 6));
        if bytes[20..24] != [0, 0, 0, 0] {
            return Err(InputError::Reserved);
        }
        if HEADER_LEN.checked_add(payload_len) != Some(bytes.len()) {
            return Err(InputError::PayloadLength);
        }
        Ok(Self {
            session_epoch: read_u32(bytes, 8),
            sequence: read_u64(bytes, 12),
            event: decode_event(kind, &bytes[HEADER_LEN..])?,
        })
    }
}

fn encode_event(event: &InputEvent) -> Result<(u8, Vec<u8>), InputError> {
    let mut payload = Vec::new();
    let kind = match event {
        InputEvent::Key { code, pressed } => {
            validate_key(*code)?;
            payload.extend_from_slice(&code.to_be_bytes());
            payload.push(u8::from(*pressed));
            1
        }
        InputEvent::PointerButton { button, pressed } => {
            if *button >= 16 {
                return Err(InputError::Button(*button));
            }
            payload.push(*button);
            payload.push(u8::from(*pressed));
            2
        }
        InputEvent::PointerMotionRelative { dx, dy } => {
            payload.extend_from_slice(&dx.to_be_bytes());
            payload.extend_from_slice(&dy.to_be_bytes());
            3
        }
        InputEvent::PointerMotionAbsolute {
            x,
            y,
            width,
            height,
        } => {
            if *width == 0 || *height == 0 || *x >= *width || *y >= *height {
                return Err(InputError::Coordinate);
            }
            payload.extend_from_slice(&x.to_be_bytes());
            payload.extend_from_slice(&y.to_be_bytes());
            payload.extend_from_slice(&width.to_be_bytes());
            payload.extend_from_slice(&height.to_be_bytes());
            4
        }
        InputEvent::Wheel {
            horizontal,
            vertical,
        } => {
            payload.extend_from_slice(&horizontal.to_be_bytes());
            payload.extend_from_slice(&vertical.to_be_bytes());
            5
        }
        InputEvent::Snapshot(state) => {
            state.encode_into(&mut payload);
            6
        }
        InputEvent::ReleaseAll => 7,
    };
    Ok((kind, payload))
}

fn decode_event(kind: u8, payload: &[u8]) -> Result<InputEvent, InputError> {
    match kind {
        1 if payload.len() == 3 => {
            let code = read_u16(payload, 0);
            validate_key(code)?;
            Ok(InputEvent::Key {
                code,
                pressed: decode_bool(payload[2])?,
            })
        }
        2 if payload.len() == 2 => {
            if payload[0] >= 16 {
                return Err(InputError::Button(payload[0]));
            }
            Ok(InputEvent::PointerButton {
                button: payload[0],
                pressed: decode_bool(payload[1])?,
            })
        }
        3 if payload.len() == 8 => Ok(InputEvent::PointerMotionRelative {
            dx: read_i32(payload, 0),
            dy: read_i32(payload, 4),
        }),
        4 if payload.len() == 16 => {
            let event = InputEvent::PointerMotionAbsolute {
                x: read_u32(payload, 0),
                y: read_u32(payload, 4),
                width: read_u32(payload, 8),
                height: read_u32(payload, 12),
            };
            encode_event(&event)?;
            Ok(event)
        }
        5 if payload.len() == 4 => Ok(InputEvent::Wheel {
            horizontal: read_i16(payload, 0),
            vertical: read_i16(payload, 2),
        }),
        6 => Ok(InputEvent::Snapshot(InputState::decode(payload)?)),
        7 if payload.is_empty() => Ok(InputEvent::ReleaseAll),
        other => Err(InputError::EventKind(other)),
    }
}

fn decode_bool(value: u8) -> Result<bool, InputError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(InputError::Boolean(value)),
    }
}

fn validate_key(code: u16) -> Result<(), InputError> {
    if code > MAX_KEY_CODE {
        Err(InputError::Key(code))
    } else {
        Ok(())
    }
}

/// Platform action emitted after duplicate suppression and reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppliedInput {
    Key {
        code: u16,
        pressed: bool,
    },
    PointerButton {
        button: u8,
        pressed: bool,
    },
    PointerMotionRelative {
        dx: i32,
        dy: i32,
    },
    PointerMotionAbsolute {
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    },
    Wheel {
        horizontal: i16,
        vertical: i16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    Applied(Vec<AppliedInput>),
    /// Message belongs to the active epoch but its sequence was already applied.
    IgnoredStaleSequence,
    /// Message belongs to an older connection/session epoch.
    IgnoredStaleEpoch,
}

/// Receiver-side input state. Disconnecting or switching epochs produces
/// explicit release actions for all held keys and buttons. A disconnected
/// epoch remains retired so delayed records cannot reactivate it; only a
/// strictly newer epoch may resume input on the same reconciler.
#[derive(Debug, Default, Clone)]
pub struct InputReconciler {
    epoch: Option<u32>,
    epoch_retired: bool,
    last_sequence: Option<u64>,
    state: InputState,
}

impl InputReconciler {
    pub fn apply(&mut self, message: InputMessage) -> Result<ReconcileOutcome, InputError> {
        if self.epoch_retired {
            if self
                .epoch
                .is_some_and(|retired| message.session_epoch <= retired)
            {
                return Ok(ReconcileOutcome::IgnoredStaleEpoch);
            }
            self.epoch_retired = false;
        }
        match self.epoch {
            Some(epoch) if message.session_epoch < epoch => {
                return Ok(ReconcileOutcome::IgnoredStaleEpoch)
            }
            Some(epoch) if message.session_epoch > epoch => {
                let mut actions = self.release_all();
                self.epoch = Some(message.session_epoch);
                self.epoch_retired = false;
                self.last_sequence = None;
                actions.extend(self.apply_fresh(message.event)?);
                self.last_sequence = Some(message.sequence);
                return Ok(ReconcileOutcome::Applied(actions));
            }
            None => {
                self.epoch = Some(message.session_epoch);
                self.epoch_retired = false;
            }
            _ => {}
        }
        if self
            .last_sequence
            .is_some_and(|sequence| message.sequence <= sequence)
        {
            return Ok(ReconcileOutcome::IgnoredStaleSequence);
        }
        let actions = self.apply_fresh(message.event)?;
        self.last_sequence = Some(message.sequence);
        Ok(ReconcileOutcome::Applied(actions))
    }

    /// Releases every active key/button and permanently retires the current
    /// epoch. Call on disconnect, portal revocation, or before replacing a
    /// platform input backend. Use an explicit `ReleaseAll` event for a
    /// nonterminal focus loss within the same epoch.
    pub fn disconnect_release_plan(&mut self) -> Vec<AppliedInput> {
        let actions = self.release_all();
        self.epoch_retired = self.epoch.is_some();
        self.last_sequence = None;
        actions
    }

    /// Releases all held state without retiring the active epoch or resetting
    /// its sequence. This is for a temporary focus loss where the same
    /// authenticated session may resume with a later sequence number.
    pub fn release_all_plan(&mut self) -> Vec<AppliedInput> {
        self.release_all()
    }

    /// Backward-compatible alias for [`Self::disconnect_release_plan`].
    pub fn disconnect(&mut self) -> Vec<AppliedInput> {
        self.disconnect_release_plan()
    }

    #[must_use]
    pub const fn state(&self) -> &InputState {
        &self.state
    }

    fn apply_fresh(&mut self, event: InputEvent) -> Result<Vec<AppliedInput>, InputError> {
        match event {
            InputEvent::Key { code, pressed } => {
                if self.state.key_pressed(code) == pressed {
                    return Ok(Vec::new());
                }
                self.state.set_key(code, pressed)?;
                Ok(vec![AppliedInput::Key { code, pressed }])
            }
            InputEvent::PointerButton { button, pressed } => {
                if self.state.button_pressed(button) == pressed {
                    return Ok(Vec::new());
                }
                self.state.set_button(button, pressed)?;
                Ok(vec![AppliedInput::PointerButton { button, pressed }])
            }
            InputEvent::PointerMotionRelative { dx, dy } => {
                Ok(vec![AppliedInput::PointerMotionRelative { dx, dy }])
            }
            InputEvent::PointerMotionAbsolute {
                x,
                y,
                width,
                height,
            } => Ok(vec![AppliedInput::PointerMotionAbsolute {
                x,
                y,
                width,
                height,
            }]),
            InputEvent::Wheel {
                horizontal,
                vertical,
            } => Ok(vec![AppliedInput::Wheel {
                horizontal,
                vertical,
            }]),
            InputEvent::Snapshot(snapshot) => Ok(self.reconcile_snapshot(snapshot)),
            InputEvent::ReleaseAll => Ok(self.release_all()),
        }
    }

    fn reconcile_snapshot(&mut self, snapshot: InputState) -> Vec<AppliedInput> {
        let mut actions = Vec::new();
        for code in 0..=MAX_KEY_CODE {
            let current = self.state.key_pressed(code);
            let desired = snapshot.key_pressed(code);
            if current != desired {
                actions.push(AppliedInput::Key {
                    code,
                    pressed: desired,
                });
            }
        }
        for button in 0..16 {
            let current = self.state.button_pressed(button);
            let desired = snapshot.button_pressed(button);
            if current != desired {
                actions.push(AppliedInput::PointerButton {
                    button,
                    pressed: desired,
                });
            }
        }
        self.state = snapshot;
        actions
    }

    fn release_all(&mut self) -> Vec<AppliedInput> {
        let empty = InputState::default();
        self.reconcile_snapshot(empty)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_i16(bytes: &[u8], offset: usize) -> i16 {
    i16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    Magic,
    Version(u8),
    Reserved,
    PayloadLength,
    EventKind(u8),
    Boolean(u8),
    Key(u16),
    Button(u8),
    Coordinate,
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for InputError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(sequence: u64, event: InputEvent) -> InputMessage {
        epoch_message(3, sequence, event)
    }

    fn epoch_message(session_epoch: u32, sequence: u64, event: InputEvent) -> InputMessage {
        InputMessage {
            session_epoch,
            sequence,
            event,
        }
    }

    #[test]
    fn wire_round_trip_for_all_event_classes() {
        let mut snapshot = InputState::default();
        snapshot.set_key(44, true).expect("key");
        snapshot.set_button(1, true).expect("button");
        let events = [
            InputEvent::Key {
                code: 4,
                pressed: true,
            },
            InputEvent::PointerButton {
                button: 1,
                pressed: false,
            },
            InputEvent::PointerMotionRelative { dx: -5, dy: 7 },
            InputEvent::PointerMotionAbsolute {
                x: 10,
                y: 20,
                width: 100,
                height: 80,
            },
            InputEvent::Wheel {
                horizontal: -1,
                vertical: 3,
            },
            InputEvent::Snapshot(snapshot),
            InputEvent::ReleaseAll,
        ];
        for (sequence, event) in events.into_iter().enumerate() {
            let value = message(sequence as u64, event);
            let encoded = value.encode().expect("encode");
            assert_eq!(InputMessage::decode(&encoded).expect("decode"), value);
        }
    }

    #[test]
    fn lost_key_up_is_corrected_by_snapshot() {
        let mut reconciler = InputReconciler::default();
        reconciler
            .apply(message(
                1,
                InputEvent::Key {
                    code: 26,
                    pressed: true,
                },
            ))
            .expect("down");
        assert!(reconciler.state().key_pressed(26));
        let outcome = reconciler
            .apply(message(3, InputEvent::Snapshot(InputState::default())))
            .expect("snapshot");
        assert_eq!(
            outcome,
            ReconcileOutcome::Applied(vec![AppliedInput::Key {
                code: 26,
                pressed: false,
            }])
        );
        assert!(reconciler.state().is_empty());
    }

    #[test]
    fn disconnect_releases_everything() {
        let mut reconciler = InputReconciler::default();
        reconciler
            .apply(message(
                1,
                InputEvent::Key {
                    code: 4,
                    pressed: true,
                },
            ))
            .expect("key");
        reconciler
            .apply(message(
                2,
                InputEvent::PointerButton {
                    button: 0,
                    pressed: true,
                },
            ))
            .expect("button");
        let actions = reconciler.disconnect();
        assert!(actions.contains(&AppliedInput::Key {
            code: 4,
            pressed: false
        }));
        assert!(actions.contains(&AppliedInput::PointerButton {
            button: 0,
            pressed: false
        }));
        assert!(reconciler.state().is_empty());
    }

    #[test]
    fn disconnect_retires_the_epoch_and_cleanup_is_idempotent() {
        let mut reconciler = InputReconciler::default();
        for (sequence, event) in [
            InputEvent::Key {
                code: 4,
                pressed: true,
            },
            InputEvent::Key {
                code: 5,
                pressed: true,
            },
            InputEvent::PointerButton {
                button: 1,
                pressed: true,
            },
        ]
        .into_iter()
        .enumerate()
        {
            reconciler
                .apply(epoch_message(10, sequence as u64 + 1, event))
                .expect("held input");
        }

        let releases = reconciler.disconnect_release_plan();
        assert_eq!(releases.len(), 3);
        assert!(releases.iter().all(|action| matches!(
            action,
            AppliedInput::Key { pressed: false, .. }
                | AppliedInput::PointerButton { pressed: false, .. }
        )));
        assert!(reconciler.disconnect_release_plan().is_empty());

        assert_eq!(
            reconciler
                .apply(epoch_message(
                    10,
                    99,
                    InputEvent::Key {
                        code: 4,
                        pressed: true,
                    },
                ))
                .expect("late retired input"),
            ReconcileOutcome::IgnoredStaleEpoch
        );
        assert!(reconciler.state().is_empty());

        assert!(matches!(
            reconciler
                .apply(epoch_message(
                    11,
                    1,
                    InputEvent::Key {
                        code: 6,
                        pressed: true,
                    },
                ))
                .expect("fresh successor input"),
            ReconcileOutcome::Applied(_)
        ));
        assert!(reconciler.state().key_pressed(6));
    }

    #[test]
    fn temporary_release_preserves_the_active_epoch_and_sequence_floor() {
        let mut reconciler = InputReconciler::default();
        reconciler
            .apply(epoch_message(
                10,
                1,
                InputEvent::Key {
                    code: 4,
                    pressed: true,
                },
            ))
            .expect("key down");
        assert_eq!(
            reconciler.release_all_plan(),
            vec![AppliedInput::Key {
                code: 4,
                pressed: false,
            }]
        );
        assert_eq!(
            reconciler
                .apply(epoch_message(
                    10,
                    1,
                    InputEvent::Key {
                        code: 5,
                        pressed: true,
                    },
                ))
                .expect("old sequence"),
            ReconcileOutcome::IgnoredStaleSequence
        );
        assert!(matches!(
            reconciler
                .apply(epoch_message(
                    10,
                    2,
                    InputEvent::Key {
                        code: 5,
                        pressed: true,
                    },
                ))
                .expect("same epoch resumes"),
            ReconcileOutcome::Applied(_)
        ));
    }

    #[test]
    fn successor_epoch_rejects_every_delayed_old_state_event() {
        let mut reconciler = InputReconciler::default();
        reconciler
            .apply(epoch_message(
                10,
                1,
                InputEvent::Key {
                    code: 4,
                    pressed: true,
                },
            ))
            .expect("old key down");
        reconciler
            .apply(epoch_message(
                11,
                1,
                InputEvent::Snapshot(InputState::default()),
            ))
            .expect("successor snapshot");
        assert!(reconciler.state().is_empty());

        let mut stale_snapshot = InputState::default();
        stale_snapshot.set_key(7, true).expect("stale key");
        stale_snapshot.set_button(2, true).expect("stale button");
        for event in [
            InputEvent::Key {
                code: 4,
                pressed: true,
            },
            InputEvent::PointerButton {
                button: 1,
                pressed: true,
            },
            InputEvent::Snapshot(stale_snapshot),
            InputEvent::ReleaseAll,
        ] {
            assert_eq!(
                reconciler
                    .apply(epoch_message(10, u64::MAX, event))
                    .expect("stale input is nonfatal"),
                ReconcileOutcome::IgnoredStaleEpoch
            );
            assert!(reconciler.state().is_empty());
        }
    }

    #[test]
    fn duplicates_are_idempotent() {
        let mut reconciler = InputReconciler::default();
        let input = message(
            7,
            InputEvent::Key {
                code: 5,
                pressed: true,
            },
        );
        reconciler.apply(input.clone()).expect("first");
        assert_eq!(
            reconciler.apply(input).expect("duplicate"),
            ReconcileOutcome::IgnoredStaleSequence
        );
    }
}
