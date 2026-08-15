//! Runtime session authority and input-release ownership.
//!
//! Native work receives an opaque permit and must call [`SessionAuthority::recheck`]
//! immediately before touching a platform provider. Closing an authority moves its
//! input ledger to an explicit release path with a separate deadline.

use crate::authorization::{Capability, SessionId};
use crate::pairing::AcceptedSession;
use core::fmt;
use latencydesk_input::{
    AppliedInput, InputError, InputMessage, InputReconciler, ReconcileOutcome,
};

/// Complete authorization/display/codec generation snapshot attached to every
/// provider dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DispatchStamp {
    session_id: SessionId,
    generation: u64,
    authorization_epoch: u32,
    display_epoch: u32,
    codec_epoch: u32,
}

impl DispatchStamp {
    pub fn new(
        session_id: SessionId,
        generation: u64,
        authorization_epoch: u32,
        display_epoch: u32,
        codec_epoch: u32,
    ) -> Result<Self, AuthorityError> {
        if generation == 0 || authorization_epoch == 0 || display_epoch == 0 || codec_epoch == 0 {
            return Err(AuthorityError::InvalidDispatchStamp);
        }
        Ok(Self {
            session_id,
            generation,
            authorization_epoch,
            display_epoch,
            codec_epoch,
        })
    }

    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn authorization_epoch(self) -> u32 {
        self.authorization_epoch
    }

    #[must_use]
    pub const fn display_epoch(self) -> u32 {
        self.display_epoch
    }

    #[must_use]
    pub const fn codec_epoch(self) -> u32 {
        self.codec_epoch
    }
}

/// Non-forgeable-by-construction capability returned by `acquire_dispatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchPermit {
    stamp: DispatchStamp,
}

impl DispatchPermit {
    #[must_use]
    pub const fn from_stamp(stamp: DispatchStamp) -> Self {
        Self { stamp }
    }

    #[must_use]
    pub const fn stamp(self) -> DispatchStamp {
        self.stamp
    }
}

/// State reconciler owned by one active authority. It is returned only while
/// closing that authority so every held key/button can be released.
#[derive(Debug, Default)]
pub struct InputLedger {
    reconciler: InputReconciler,
}

impl InputLedger {
    pub fn apply(&mut self, message: InputMessage) -> Result<ReconcileOutcome, InputError> {
        self.reconciler.apply(message)
    }

    /// Emits releases for every held key or pointer button and clears the
    /// reconciliation state. The caller must execute this plan by the release
    /// deadline returned from `SessionAuthority::close`.
    #[must_use]
    pub fn release_plan(&mut self) -> Vec<AppliedInput> {
        self.reconciler.disconnect_release_plan()
    }
}

/// Failure of authority acquisition, validation, or closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    InvalidDispatchStamp,
    SessionMismatch,
    InvalidDeadline,
    ViewNotGranted,
    InputNotGranted,
    Expired,
    StaleDispatch,
    Closed,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AuthorityError {}

/// Failure while applying a protocol-validated input message through an active
/// session authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionInputError {
    Authority(AuthorityError),
    Input(InputError),
}

impl fmt::Display for SessionInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(formatter, "authority rejected input: {error}"),
            Self::Input(error) => write!(formatter, "input reconciliation failed: {error}"),
        }
    }
}

impl std::error::Error for SessionInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Input(error) => Some(error),
        }
    }
}

/// Result of closing a session authority. The independent release deadline is
/// deliberately not constrained by the session-dispatch deadline.
pub struct ClosedAuthority {
    input_ledger: InputLedger,
    release_deadline_ns: u64,
}

impl ClosedAuthority {
    #[must_use]
    pub fn new(input_ledger: InputLedger, release_deadline_ns: u64) -> Self {
        Self {
            input_ledger,
            release_deadline_ns,
        }
    }

    #[must_use]
    pub const fn release_deadline_ns(&self) -> u64 {
        self.release_deadline_ns
    }

    #[must_use]
    pub fn into_input_ledger(self) -> InputLedger {
        self.input_ledger
    }
}

impl fmt::Debug for ClosedAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedAuthority")
            .field("release_deadline_ns", &self.release_deadline_ns)
            .finish_non_exhaustive()
    }
}

/// Authority operations required by a role runtime.
///
/// The runtime receives no direct access to the input ledger or authenticated
/// session material. It can only acquire and recheck a dispatch permit, route a
/// validated input message, and close through this interface.
pub trait SessionGate {
    fn acquire_dispatch(&self, now_ns: u64) -> Result<DispatchPermit, AuthorityError>;
    fn recheck(
        &self,
        permit: &DispatchPermit,
        now_ns: u64,
    ) -> Result<DispatchStamp, AuthorityError>;
    fn apply_input(
        &mut self,
        message: InputMessage,
        now_ns: u64,
    ) -> Result<ReconcileOutcome, SessionInputError>;
    fn close(&mut self) -> Result<ClosedAuthority, AuthorityError>;
}

/// Per-session gate around an accepted TLS-pinned pairing and an owned input
/// ledger. An epoch mutation must close this authority before creating its
/// replacement, so permits from the prior authority fail `recheck`.
pub struct SessionAuthority {
    accepted: AcceptedSession,
    stamp: DispatchStamp,
    input_ledger: Option<InputLedger>,
    session_deadline_ns: u64,
    release_deadline_ns: u64,
}

impl SessionAuthority {
    pub fn new(
        accepted: AcceptedSession,
        stamp: DispatchStamp,
        input_ledger: InputLedger,
        session_deadline_ns: u64,
        release_deadline_ns: u64,
    ) -> Result<Self, AuthorityError> {
        if accepted.session_id() != stamp.session_id() {
            return Err(AuthorityError::SessionMismatch);
        }
        if session_deadline_ns == 0 || release_deadline_ns == 0 {
            return Err(AuthorityError::InvalidDeadline);
        }
        Ok(Self {
            accepted,
            stamp,
            input_ledger: Some(input_ledger),
            session_deadline_ns,
            release_deadline_ns,
        })
    }

    /// Acquires a dispatch permit. Native providers must not use this permit
    /// without a final `recheck` immediately before native work.
    pub fn acquire_dispatch(&self, now_ns: u64) -> Result<DispatchPermit, AuthorityError> {
        self.ensure_dispatchable(now_ns)?;
        Ok(DispatchPermit { stamp: self.stamp })
    }

    /// Revalidates a permit against all authority epochs and expiration.
    pub fn recheck(
        &self,
        permit: &DispatchPermit,
        now_ns: u64,
    ) -> Result<DispatchStamp, AuthorityError> {
        self.ensure_dispatchable(now_ns)?;
        if permit.stamp != self.stamp {
            return Err(AuthorityError::StaleDispatch);
        }
        Ok(self.stamp)
    }

    /// Reconciles a validated remote input message while this authority is
    /// dispatchable. Native injection remains the runtime's responsibility and
    /// must follow a final permit recheck.
    pub fn apply_input(
        &mut self,
        message: InputMessage,
        now_ns: u64,
    ) -> Result<ReconcileOutcome, SessionInputError> {
        self.ensure_dispatchable(now_ns)
            .map_err(SessionInputError::Authority)?;
        if !self.accepted.capabilities().contains(Capability::Input) {
            return Err(SessionInputError::Authority(
                AuthorityError::InputNotGranted,
            ));
        }
        self.input_ledger
            .as_mut()
            .ok_or(SessionInputError::Authority(AuthorityError::Closed))?
            .apply(message)
            .map_err(SessionInputError::Input)
    }

    /// Closes dispatch access and transfers the current key/button state to an
    /// independent, deadline-bound release action.
    pub fn close(&mut self) -> Result<ClosedAuthority, AuthorityError> {
        let input_ledger = self.input_ledger.take().ok_or(AuthorityError::Closed)?;
        Ok(ClosedAuthority {
            input_ledger,
            release_deadline_ns: self.release_deadline_ns,
        })
    }

    #[must_use]
    pub const fn accepted_session(&self) -> AcceptedSession {
        self.accepted
    }

    #[must_use]
    pub const fn stamp(&self) -> DispatchStamp {
        self.stamp
    }

    fn ensure_dispatchable(&self, now_ns: u64) -> Result<(), AuthorityError> {
        if self.input_ledger.is_none() {
            return Err(AuthorityError::Closed);
        }
        if now_ns >= self.session_deadline_ns {
            return Err(AuthorityError::Expired);
        }
        if !self.accepted.capabilities().contains(Capability::View) {
            return Err(AuthorityError::ViewNotGranted);
        }
        Ok(())
    }
}

impl SessionGate for SessionAuthority {
    fn acquire_dispatch(&self, now_ns: u64) -> Result<DispatchPermit, AuthorityError> {
        Self::acquire_dispatch(self, now_ns)
    }

    fn recheck(
        &self,
        permit: &DispatchPermit,
        now_ns: u64,
    ) -> Result<DispatchStamp, AuthorityError> {
        Self::recheck(self, permit, now_ns)
    }

    fn apply_input(
        &mut self,
        message: InputMessage,
        now_ns: u64,
    ) -> Result<ReconcileOutcome, SessionInputError> {
        Self::apply_input(self, message, now_ns)
    }

    fn close(&mut self) -> Result<ClosedAuthority, AuthorityError> {
        Self::close(self)
    }
}

impl fmt::Debug for SessionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionAuthority")
            .field("accepted", &self.accepted)
            .field("stamp", &self.stamp)
            .field("session_deadline_ns", &self.session_deadline_ns)
            .field("release_deadline_ns", &self.release_deadline_ns)
            .field("closed", &self.input_ledger.is_none())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{CapabilitySet, SessionId};
    use latencydesk_input::{AppliedInput, InputEvent};
    use latencydesk_platform::PeerPin;

    #[test]
    fn authority_rechecks_exact_epochs_and_close_returns_ledger_with_independent_deadline() {
        let session_id = SessionId::new(7).expect("session id");
        let accepted = AcceptedSession::test_only(
            session_id,
            [1; 32],
            PeerPin::from_tls_spki_fingerprint([2; 32]).expect("peer pin"),
            CapabilitySet::view_and_input(),
        );
        let stamp = DispatchStamp::new(session_id, 3, 4, 5, 6).expect("stamp");
        let ledger = InputLedger::default();

        let mut authority =
            SessionAuthority::new(accepted, stamp, ledger, 900, 800).expect("authority");
        assert_eq!(
            authority
                .apply_input(
                    InputMessage {
                        session_epoch: 6,
                        sequence: 1,
                        event: InputEvent::Key {
                            code: 42,
                            pressed: true,
                        },
                    },
                    700,
                )
                .expect("authority routes input"),
            ReconcileOutcome::Applied(vec![AppliedInput::Key {
                code: 42,
                pressed: true,
            }])
        );
        let permit = authority.acquire_dispatch(700).expect("dispatch permit");
        assert_eq!(authority.recheck(&permit, 700), Ok(stamp));
        assert_eq!(permit.stamp(), stamp);

        let closed = authority.close().expect("close returns ledger");
        assert_eq!(closed.release_deadline_ns(), 800);
        assert_eq!(authority.recheck(&permit, 700), Err(AuthorityError::Closed));

        let mut old_ledger = closed.into_input_ledger();
        assert_eq!(
            old_ledger.release_plan(),
            vec![AppliedInput::Key {
                code: 42,
                pressed: false,
            }]
        );
    }

    #[test]
    fn view_only_authority_dispatches_media_but_rejects_input() {
        let session_id = SessionId::new(7).expect("session id");
        let accepted = AcceptedSession::test_only(
            session_id,
            [1; 32],
            PeerPin::from_tls_spki_fingerprint([2; 32]).expect("peer pin"),
            CapabilitySet::view_only(),
        );
        let stamp = DispatchStamp::new(session_id, 3, 4, 5, 6).expect("stamp");
        let mut authority =
            SessionAuthority::new(accepted, stamp, InputLedger::default(), 900, 800)
                .expect("authority");

        let permit = authority.acquire_dispatch(700).expect("view dispatch");
        assert_eq!(authority.recheck(&permit, 700), Ok(stamp));
        assert_eq!(
            authority.apply_input(
                InputMessage {
                    session_epoch: 6,
                    sequence: 1,
                    event: InputEvent::Key {
                        code: 42,
                        pressed: true,
                    },
                },
                700,
            ),
            Err(SessionInputError::Authority(
                AuthorityError::InputNotGranted
            ))
        );
    }

    #[test]
    fn dispatch_stamp_rejects_missing_epoch() {
        let session_id = SessionId::new(7).expect("session id");
        assert_eq!(
            DispatchStamp::new(session_id, 1, 0, 1, 1),
            Err(AuthorityError::InvalidDispatchStamp)
        );
    }
}
