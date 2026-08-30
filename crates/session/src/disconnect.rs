//! Safe session termination lifecycle, buffer draining, and fail-closed security gates.

use core::fmt;
use latencydesk_protocol::{DisconnectReason, DisconnectWire};

/// Errors occurring during disconnection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectError {
    AlreadyClosed,
    DrainTimeout,
    InvalidWireMessage,
    SessionMismatch,
    AuthorizationEpochMismatch,
}

impl fmt::Display for DisconnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DisconnectError {}

/// Disconnect lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectState {
    Connected,
    Closing {
        reason: DisconnectReason,
        initiated_by_local: bool,
        deadline_ns: u64,
    },
    Closed {
        reason: DisconnectReason,
        timestamp_ns: u64,
    },
}

/// Controller for managing graceful and fail-closed disconnection procedures.
#[derive(Debug, Clone)]
pub struct SafeDisconnectController {
    session_id: u64,
    authorization_epoch: u32,
    state: DisconnectState,
    default_drain_timeout_ns: u64,
}

impl SafeDisconnectController {
    #[must_use]
    pub const fn new(
        session_id: u64,
        authorization_epoch: u32,
        default_drain_timeout_ns: u64,
    ) -> Self {
        Self {
            session_id,
            authorization_epoch,
            state: DisconnectState::Connected,
            default_drain_timeout_ns,
        }
    }

    #[must_use]
    pub const fn state(&self) -> DisconnectState {
        self.state
    }

    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, DisconnectState::Closed { .. })
    }

    #[must_use]
    pub const fn can_process_traffic(&self) -> bool {
        matches!(self.state, DisconnectState::Connected)
    }

    #[must_use]
    pub const fn disconnect_reason(&self) -> Option<DisconnectReason> {
        match self.state {
            DisconnectState::Closing { reason, .. } | DisconnectState::Closed { reason, .. } => {
                Some(reason)
            }
            DisconnectState::Connected => None,
        }
    }

    /// Initiates graceful local disconnection.
    pub fn initiate_disconnect(
        &mut self,
        reason: DisconnectReason,
        message: &'static str,
        now_ns: u64,
    ) -> DisconnectWire<'static> {
        let deadline_ns = now_ns.saturating_add(self.default_drain_timeout_ns);
        self.state = DisconnectState::Closing {
            reason,
            initiated_by_local: true,
            deadline_ns,
        };

        DisconnectWire {
            reason,
            session_id: self.session_id,
            authorization_epoch: self.authorization_epoch,
            message,
        }
    }

    /// Handles a disconnection message received from the remote peer.
    pub fn handle_remote_disconnect(
        &mut self,
        wire: &DisconnectWire<'_>,
        now_ns: u64,
    ) -> Result<(), DisconnectError> {
        if wire.session_id != self.session_id {
            return Err(DisconnectError::SessionMismatch);
        }
        if wire.authorization_epoch != self.authorization_epoch {
            return Err(DisconnectError::AuthorizationEpochMismatch);
        }
        if self.is_closed() {
            return Err(DisconnectError::AlreadyClosed);
        }
        self.state = DisconnectState::Closed {
            reason: wire.reason,
            timestamp_ns: now_ns,
        };
        Ok(())
    }

    /// Checks whether pending outbound buffers have drained. If drained or timed out,
    /// advances state to `Closed`.
    pub fn check_drain(&mut self, pending_bytes: usize, now_ns: u64) -> bool {
        match self.state {
            DisconnectState::Closing {
                reason,
                deadline_ns,
                ..
            } => {
                if pending_bytes == 0 || now_ns >= deadline_ns {
                    self.state = DisconnectState::Closed {
                        reason,
                        timestamp_ns: now_ns,
                    };
                    true
                } else {
                    false
                }
            }
            DisconnectState::Closed { .. } => true,
            DisconnectState::Connected => false,
        }
    }

    /// Immediately forces the session to fail closed.
    pub fn force_close(&mut self, reason: DisconnectReason, now_ns: u64) {
        self.state = DisconnectState::Closed {
            reason,
            timestamp_ns: now_ns,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_disconnect_rejects_stale_session_and_epoch_without_closing_successor() {
        let mut controller = SafeDisconnectController::new(42, 7, 1_000);
        let wrong_session = DisconnectWire {
            reason: DisconnectReason::UserInitiated,
            session_id: 41,
            authorization_epoch: 7,
            message: "stale session",
        };
        assert_eq!(
            controller.handle_remote_disconnect(&wrong_session, 100),
            Err(DisconnectError::SessionMismatch)
        );
        assert_eq!(controller.state(), DisconnectState::Connected);

        let wrong_epoch = DisconnectWire {
            reason: DisconnectReason::UserInitiated,
            session_id: 42,
            authorization_epoch: 6,
            message: "stale epoch",
        };
        assert_eq!(
            controller.handle_remote_disconnect(&wrong_epoch, 101),
            Err(DisconnectError::AuthorizationEpochMismatch)
        );
        assert_eq!(controller.state(), DisconnectState::Connected);
    }
}
