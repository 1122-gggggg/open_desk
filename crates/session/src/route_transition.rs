//! Two-phase authenticated route promotion with bounded rollback retention.

use crate::nat::ConnectionPath;
use latencydesk_protocol::{
    quic::SessionStamp, RelayProvider, RouteTransitionMessage, RouteTransitionStage, WireIpAddr,
    WIRE_VERSION,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteProof {
    pub ice_nominated: bool,
    pub exact_mtls: bool,
    pub transcript_bound: bool,
    pub consent_fresh: bool,
    pub transcript_digest: [u8; 32],
}

impl RouteProof {
    fn is_complete(self) -> bool {
        self.ice_nominated
            && self.exact_mtls
            && self.transcript_bound
            && self.consent_fresh
            && self.transcript_digest != [0; 32]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromotionToken {
    pub sequence: u64,
    pub base_route_epoch: u64,
    pub stamp: SessionStamp,
    pub route: ConnectionPath,
    pub route_digest: [u8; 32],
    pub transcript_digest: [u8; 32],
    pub expires_at_ns: u64,
}

impl PromotionToken {
    pub fn wire_message(
        self,
        stage: RouteTransitionStage,
    ) -> Result<RouteTransitionMessage, RouteTransitionError> {
        let next_route_epoch = self
            .base_route_epoch
            .checked_add(1)
            .ok_or(RouteTransitionError::RouteEpochExhausted)?;
        Ok(RouteTransitionMessage {
            version: WIRE_VERSION,
            stage,
            sequence: self.sequence,
            base_route_epoch: self.base_route_epoch,
            next_route_epoch,
            expires_at_ns: self.expires_at_ns,
            route_digest: self.route_digest,
            transcript_digest: self.transcript_digest,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSwitch {
    pub sequence: u64,
    pub route_epoch: u64,
    pub stamp: SessionStamp,
    pub from: ConnectionPath,
    pub to: ConnectionPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteHealthAction {
    NoChange,
    Stable,
    RollbackRequired(PromotionToken),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTransitionError {
    InvalidConfig,
    InvalidRoute,
    SameRoute,
    UnverifiedRoute,
    TransitionInProgress,
    TokenMismatch,
    InvalidState,
    Expired,
    NoVerifiedRoute,
    SequenceExhausted,
    RouteEpochExhausted,
    TimeOverflow,
}

impl std::fmt::Display for RouteTransitionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RouteTransitionError {}

#[derive(Debug, Clone, Copy)]
enum TransitionState {
    Stable,
    Probing {
        token: PromotionToken,
        previous: ConnectionPath,
    },
    Prepared {
        token: PromotionToken,
        previous: ConnectionPath,
    },
    Committed {
        token: PromotionToken,
        previous: ConnectionPath,
        previous_transcript_digest: [u8; 32],
        stable_at_ns: u64,
    },
}

#[derive(Debug, Clone)]
pub struct RouteTransitionController {
    stamp: SessionStamp,
    active: ConnectionPath,
    active_transcript_digest: [u8; 32],
    prepare_timeout_ns: u64,
    stability_window_ns: u64,
    next_sequence: u64,
    active_authority: bool,
    state: TransitionState,
}

impl RouteTransitionController {
    pub fn new(
        stamp: SessionStamp,
        active: ConnectionPath,
        active_proof: RouteProof,
        prepare_timeout_ns: u64,
        stability_window_ns: u64,
    ) -> Result<Self, RouteTransitionError> {
        if stamp.validate_pending().is_err()
            || stamp.authorization_epoch == 0
            || stamp.display_epoch == 0
            || stamp.codec_epoch == 0
            || !active_proof.is_complete()
            || prepare_timeout_ns == 0
            || stability_window_ns == 0
        {
            return Err(RouteTransitionError::InvalidConfig);
        }
        if !valid_path(active) {
            return Err(RouteTransitionError::InvalidRoute);
        }
        Ok(Self {
            stamp,
            active,
            active_transcript_digest: active_proof.transcript_digest,
            prepare_timeout_ns,
            stability_window_ns,
            next_sequence: 0,
            active_authority: true,
            state: TransitionState::Stable,
        })
    }

    #[must_use]
    pub const fn stamp(&self) -> SessionStamp {
        self.stamp
    }

    #[must_use]
    pub const fn active_route(&self) -> ConnectionPath {
        self.active
    }

    #[must_use]
    pub const fn route_epoch(&self) -> u64 {
        self.stamp.route_epoch
    }

    #[must_use]
    pub fn accepts_application_route(&self, route_epoch: u64, route: ConnectionPath) -> bool {
        self.active_authority && route_epoch == self.stamp.route_epoch && route == self.active
    }

    /// Fail-closed receiver gate for packets carrying a route epoch.
    ///
    /// The session stamp is checked alongside the route epoch so a packet
    /// captured from a different session cannot become valid merely by using
    /// the current route number. Call this at every reliable, media, and
    /// input dispatch boundary before decoding or injecting the payload.
    #[must_use]
    pub fn accepts_packet(&self, stamp: SessionStamp, route: ConnectionPath) -> bool {
        self.stamp == stamp && self.accepts_application_route(stamp.route_epoch, route)
    }

    #[must_use]
    pub const fn rollback_route(&self) -> Option<ConnectionPath> {
        match self.state {
            TransitionState::Committed { previous, .. } => Some(previous),
            _ => None,
        }
    }

    pub fn begin(
        &mut self,
        candidate: ConnectionPath,
        proof: RouteProof,
        now_ns: u64,
    ) -> Result<PromotionToken, RouteTransitionError> {
        if !self.active_authority {
            return Err(RouteTransitionError::NoVerifiedRoute);
        }
        if !matches!(self.state, TransitionState::Stable) {
            return Err(RouteTransitionError::TransitionInProgress);
        }
        if candidate == self.active {
            return Err(RouteTransitionError::SameRoute);
        }
        if !valid_path(candidate) {
            return Err(RouteTransitionError::InvalidRoute);
        }
        if !proof.is_complete() {
            return Err(RouteTransitionError::UnverifiedRoute);
        }
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(RouteTransitionError::SequenceExhausted)?;
        let expires_at_ns = now_ns
            .checked_add(self.prepare_timeout_ns)
            .ok_or(RouteTransitionError::TimeOverflow)?;
        let token = PromotionToken {
            sequence,
            base_route_epoch: self.stamp.route_epoch,
            stamp: self.stamp,
            route: candidate,
            route_digest: connection_path_digest(candidate),
            transcript_digest: proof.transcript_digest,
            expires_at_ns,
        };
        self.next_sequence = sequence;
        self.state = TransitionState::Probing {
            token,
            previous: self.active,
        };
        Ok(token)
    }

    pub fn peer_prepared(
        &mut self,
        token: PromotionToken,
        now_ns: u64,
    ) -> Result<(), RouteTransitionError> {
        let TransitionState::Probing {
            token: expected,
            previous,
        } = self.state
        else {
            return Err(RouteTransitionError::InvalidState);
        };
        if token != expected {
            return Err(RouteTransitionError::TokenMismatch);
        }
        if now_ns >= token.expires_at_ns {
            self.state = TransitionState::Stable;
            return Err(RouteTransitionError::Expired);
        }
        self.state = TransitionState::Prepared { token, previous };
        Ok(())
    }

    pub fn commit(
        &mut self,
        token: PromotionToken,
        now_ns: u64,
    ) -> Result<RouteSwitch, RouteTransitionError> {
        let TransitionState::Prepared {
            token: expected,
            previous,
        } = self.state
        else {
            return Err(RouteTransitionError::InvalidState);
        };
        if token != expected {
            return Err(RouteTransitionError::TokenMismatch);
        }
        if now_ns >= token.expires_at_ns {
            self.state = TransitionState::Stable;
            return Err(RouteTransitionError::Expired);
        }
        let stable_at_ns = now_ns
            .checked_add(self.stability_window_ns)
            .ok_or(RouteTransitionError::TimeOverflow)?;
        let route_epoch = self
            .stamp
            .route_epoch
            .checked_add(1)
            .ok_or(RouteTransitionError::RouteEpochExhausted)?;
        let previous_transcript_digest = self.active_transcript_digest;
        self.stamp.route_epoch = route_epoch;
        self.active_transcript_digest = token.transcript_digest;
        let switch = RouteSwitch {
            sequence: token.sequence,
            route_epoch,
            stamp: self.stamp,
            from: previous,
            to: token.route,
        };
        self.active = token.route;
        self.active_authority = true;
        self.state = TransitionState::Committed {
            token,
            previous,
            previous_transcript_digest,
            stable_at_ns,
        };
        Ok(switch)
    }

    pub fn note_healthy(
        &mut self,
        sequence: u64,
        now_ns: u64,
        candidate_proof: RouteProof,
        previous_proof: RouteProof,
    ) -> Result<RouteHealthAction, RouteTransitionError> {
        let TransitionState::Committed {
            token,
            stable_at_ns,
            ..
        } = self.state
        else {
            return Err(RouteTransitionError::InvalidState);
        };
        if sequence != token.sequence {
            return Err(RouteTransitionError::TokenMismatch);
        }
        if now_ns >= stable_at_ns {
            return self.settle_committed(now_ns, candidate_proof, previous_proof);
        }
        if !candidate_proof.is_complete()
            || candidate_proof.transcript_digest != token.transcript_digest
        {
            return Err(RouteTransitionError::UnverifiedRoute);
        }
        Ok(RouteHealthAction::NoChange)
    }

    pub fn note_unhealthy(
        &mut self,
        sequence: u64,
        now_ns: u64,
        previous_proof: RouteProof,
    ) -> Result<PromotionToken, RouteTransitionError> {
        let TransitionState::Committed {
            token,
            previous,
            previous_transcript_digest,
            ..
        } = self.state
        else {
            return Err(RouteTransitionError::InvalidState);
        };
        if sequence != token.sequence {
            return Err(RouteTransitionError::TokenMismatch);
        }
        if !previous_proof.is_complete()
            || previous_proof.transcript_digest != previous_transcript_digest
        {
            self.active_authority = false;
            self.state = TransitionState::Stable;
            return Err(RouteTransitionError::NoVerifiedRoute);
        }
        self.begin_verified_rollback(previous, previous_transcript_digest, now_ns)
    }

    pub fn tick(
        &mut self,
        now_ns: u64,
        candidate_proof: RouteProof,
        previous_proof: RouteProof,
    ) -> Result<RouteHealthAction, RouteTransitionError> {
        match self.state {
            TransitionState::Probing { token, .. } | TransitionState::Prepared { token, .. }
                if now_ns >= token.expires_at_ns =>
            {
                self.state = TransitionState::Stable;
                Ok(RouteHealthAction::NoChange)
            }
            TransitionState::Committed { stable_at_ns, .. } if now_ns >= stable_at_ns => {
                self.settle_committed(now_ns, candidate_proof, previous_proof)
            }
            _ => Ok(RouteHealthAction::NoChange),
        }
    }

    fn settle_committed(
        &mut self,
        now_ns: u64,
        candidate_proof: RouteProof,
        previous_proof: RouteProof,
    ) -> Result<RouteHealthAction, RouteTransitionError> {
        let TransitionState::Committed {
            token,
            previous,
            previous_transcript_digest,
            ..
        } = self.state
        else {
            return Err(RouteTransitionError::InvalidState);
        };
        if candidate_proof.is_complete()
            && candidate_proof.transcript_digest == token.transcript_digest
        {
            self.active_authority = true;
            self.state = TransitionState::Stable;
            return Ok(RouteHealthAction::Stable);
        }
        if previous_proof.is_complete()
            && previous_proof.transcript_digest == previous_transcript_digest
        {
            let rollback =
                self.begin_verified_rollback(previous, previous_transcript_digest, now_ns)?;
            return Ok(RouteHealthAction::RollbackRequired(rollback));
        }
        self.active_authority = false;
        self.state = TransitionState::Stable;
        Err(RouteTransitionError::NoVerifiedRoute)
    }

    fn begin_verified_rollback(
        &mut self,
        previous: ConnectionPath,
        transcript_digest: [u8; 32],
        now_ns: u64,
    ) -> Result<PromotionToken, RouteTransitionError> {
        if self.stamp.route_epoch.checked_add(1).is_none() {
            self.active_authority = false;
            self.state = TransitionState::Stable;
            return Err(RouteTransitionError::RouteEpochExhausted);
        }
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(RouteTransitionError::SequenceExhausted)?;
        let expires_at_ns = now_ns
            .checked_add(self.prepare_timeout_ns)
            .ok_or(RouteTransitionError::TimeOverflow)?;
        let token = PromotionToken {
            sequence,
            base_route_epoch: self.stamp.route_epoch,
            stamp: self.stamp,
            route: previous,
            route_digest: connection_path_digest(previous),
            transcript_digest,
            expires_at_ns,
        };
        let current = self.active;
        self.next_sequence = sequence;
        self.active_authority = false;
        self.state = TransitionState::Probing {
            token,
            previous: current,
        };
        Ok(token)
    }
}

fn valid_path(path: ConnectionPath) -> bool {
    match path {
        ConnectionPath::Direct {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            pair_priority,
        } => {
            local_port != 0
                && remote_port != 0
                && pair_priority != 0
                && valid_ip(local_ip)
                && valid_ip(remote_ip)
                && matches!(
                    (local_ip, remote_ip),
                    (WireIpAddr::V4(_), WireIpAddr::V4(_)) | (WireIpAddr::V6(_), WireIpAddr::V6(_))
                )
        }
        ConnectionPath::Relay {
            relay_session_id,
            provider,
            remote_peer_id,
        } => relay_session_id != 0 && provider != RelayProvider::None && remote_peer_id != [0; 16],
    }
}

#[must_use]
pub fn connection_path_digest(path: ConnectionPath) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"latencydesk-route-v1");
    match path {
        ConnectionPath::Direct {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            pair_priority,
        } => {
            digest.update([1]);
            update_ip_digest(&mut digest, local_ip);
            digest.update(local_port.to_be_bytes());
            update_ip_digest(&mut digest, remote_ip);
            digest.update(remote_port.to_be_bytes());
            digest.update(pair_priority.to_be_bytes());
        }
        ConnectionPath::Relay {
            relay_session_id,
            provider,
            remote_peer_id,
        } => {
            digest.update([2]);
            digest.update(relay_session_id.to_be_bytes());
            digest.update([provider as u8]);
            digest.update(remote_peer_id);
        }
    }
    digest.finalize().into()
}

fn update_ip_digest(digest: &mut Sha256, address: WireIpAddr) {
    match address {
        WireIpAddr::V4(bytes) => {
            digest.update([4]);
            digest.update(bytes);
        }
        WireIpAddr::V6(bytes) => {
            digest.update([6]);
            digest.update(bytes);
        }
    }
}

fn valid_ip(ip: WireIpAddr) -> bool {
    match ip {
        WireIpAddr::V4(bytes) => {
            bytes != [0; 4] && bytes != [255; 4] && !(224..=239).contains(&bytes[0])
        }
        WireIpAddr::V6(bytes) => bytes != [0; 16] && bytes[0] != 0xff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::ConnectionPath;
    use latencydesk_protocol::{quic::SessionStamp, RelayProvider, WireIpAddr};

    fn stamp() -> SessionStamp {
        SessionStamp {
            session_id: 7,
            generation: 2,
            authorization_epoch: 3,
            display_epoch: 4,
            codec_epoch: 5,
            route_epoch: 1,
        }
    }

    fn stamp_with_session(session_id: u64) -> SessionStamp {
        SessionStamp {
            session_id,
            ..stamp()
        }
    }

    fn relay() -> ConnectionPath {
        ConnectionPath::Relay {
            relay_session_id: 9,
            provider: RelayProvider::Turn,
            remote_peer_id: [8; 16],
        }
    }

    fn direct(port: u16) -> ConnectionPath {
        ConnectionPath::Direct {
            local_ip: WireIpAddr::V4([10, 0, 0, 1]),
            local_port: port,
            remote_ip: WireIpAddr::V4([10, 0, 0, 2]),
            remote_port: port + 1,
            pair_priority: u64::from(port),
        }
    }

    fn proof() -> RouteProof {
        RouteProof {
            ice_nominated: true,
            exact_mtls: true,
            transcript_bound: true,
            consent_fresh: true,
            transcript_digest: [0xA5; 32],
        }
    }

    fn candidate_proof() -> RouteProof {
        RouteProof {
            transcript_digest: [0xB6; 32],
            ..proof()
        }
    }

    #[test]
    fn promotion_is_two_phase_and_keeps_old_route_until_stable() {
        let mut controller =
            RouteTransitionController::new(stamp(), relay(), proof(), 1_000, 5_000).unwrap();
        let token = controller
            .begin(direct(5000), candidate_proof(), 10)
            .unwrap();
        let prepare = token.wire_message(RouteTransitionStage::Prepare).unwrap();
        assert_eq!(prepare.base_route_epoch, 1);
        assert_eq!(prepare.next_route_epoch, 2);
        assert_eq!(prepare.route_digest, connection_path_digest(direct(5000)));
        assert_eq!(
            prepare.transcript_digest,
            candidate_proof().transcript_digest
        );
        assert_eq!(controller.route_epoch(), 1);
        assert!(controller.accepts_application_route(1, relay()));
        assert_eq!(controller.active_route(), relay());
        controller.peer_prepared(token, 20).unwrap();
        assert_eq!(
            token
                .wire_message(RouteTransitionStage::Prepared)
                .unwrap()
                .stage,
            RouteTransitionStage::Prepared
        );
        assert_eq!(controller.active_route(), relay());
        let switch = controller.commit(token, 30).unwrap();
        assert_eq!(switch.from, relay());
        assert_eq!(switch.to, direct(5000));
        assert_eq!(switch.route_epoch, 2);
        assert_eq!(switch.stamp.route_epoch, 2);
        assert_eq!(controller.active_route(), direct(5000));
        assert!(controller.accepts_application_route(2, direct(5000)));
        assert!(!controller.accepts_application_route(1, relay()));
        assert_eq!(controller.rollback_route(), Some(relay()));
        assert_eq!(controller.stamp().route_epoch, 2);
        assert_eq!(switch.stamp, controller.stamp());
        assert_eq!(
            controller
                .note_healthy(token.sequence, 5_031, candidate_proof(), proof())
                .unwrap(),
            RouteHealthAction::Stable
        );
        assert_eq!(controller.active_route(), direct(5000));
        assert_eq!(controller.rollback_route(), None);
    }

    #[test]
    fn missing_proof_wrong_stamp_and_stale_ack_never_mutate_route() {
        let mut controller =
            RouteTransitionController::new(stamp(), relay(), proof(), 1_000, 5_000).unwrap();
        let mut incomplete = proof();
        incomplete.exact_mtls = false;
        assert!(matches!(
            controller.begin(direct(5000), incomplete, 10),
            Err(RouteTransitionError::UnverifiedRoute)
        ));
        assert_eq!(controller.active_route(), relay());

        let mut digestless = proof();
        digestless.transcript_digest = [0; 32];
        assert!(matches!(
            controller.begin(direct(5000), digestless, 10),
            Err(RouteTransitionError::UnverifiedRoute)
        ));

        let token = controller
            .begin(direct(5000), candidate_proof(), 10)
            .unwrap();
        assert!(matches!(
            controller.peer_prepared(
                PromotionToken {
                    stamp: SessionStamp {
                        generation: 1,
                        ..stamp()
                    },
                    ..token
                },
                20,
            ),
            Err(RouteTransitionError::TokenMismatch)
        ));
        assert_eq!(controller.active_route(), relay());
        controller.peer_prepared(token, 20).unwrap();
        controller.commit(token, 30).unwrap();
        assert!(matches!(
            controller.peer_prepared(token, 40),
            Err(RouteTransitionError::InvalidState)
        ));
    }

    #[test]
    fn unhealthy_or_expired_candidate_rolls_back_without_epoch_drift() {
        let mut controller =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 5_000).unwrap();
        let token = controller
            .begin(direct(5000), candidate_proof(), 10)
            .unwrap();
        controller.peer_prepared(token, 20).unwrap();
        controller.commit(token, 30).unwrap();
        let rollback_token = controller
            .note_unhealthy(token.sequence, 40, proof())
            .unwrap();
        assert_eq!(rollback_token.route, relay());
        assert_eq!(rollback_token.base_route_epoch, 2);
        assert_eq!(controller.active_route(), direct(5000));
        assert!(!controller.accepts_application_route(2, direct(5000)));
        controller.peer_prepared(rollback_token, 41).unwrap();
        let rollback = controller.commit(rollback_token, 42).unwrap();
        assert_eq!(rollback.from, direct(5000));
        assert_eq!(rollback.to, relay());
        assert_eq!(rollback.route_epoch, 3);
        assert!(controller.accepts_application_route(3, relay()));
        assert_eq!(rollback.stamp, controller.stamp());
        assert_eq!(
            controller
                .note_healthy(rollback.sequence, 5_043, proof(), candidate_proof())
                .unwrap(),
            RouteHealthAction::Stable
        );

        let token = controller
            .begin(direct(6000), candidate_proof(), 50)
            .unwrap();
        assert_eq!(
            controller.tick(151, proof(), proof()).unwrap(),
            RouteHealthAction::NoChange
        );
        assert_eq!(controller.active_route(), relay());
        assert_eq!(controller.route_epoch(), 3);
        assert!(matches!(
            controller.commit(token, 152),
            Err(RouteTransitionError::InvalidState | RouteTransitionError::TokenMismatch)
        ));

        let mut no_health =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 50).unwrap();
        let token = no_health.begin(direct(7000), candidate_proof(), 1).unwrap();
        no_health.peer_prepared(token, 2).unwrap();
        no_health.commit(token, 3).unwrap();
        assert!(matches!(
            no_health.tick(
                53,
                RouteProof {
                    ice_nominated: false,
                    ..proof()
                },
                RouteProof {
                    ice_nominated: false,
                    ..proof()
                },
            ),
            Err(RouteTransitionError::NoVerifiedRoute)
        ));
        assert!(!no_health.accepts_application_route(2, direct(7000)));
        assert!(!no_health.accepts_application_route(1, relay()));

        let mut observed =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 50).unwrap();
        let token = observed.begin(direct(8000), candidate_proof(), 1).unwrap();
        observed.peer_prepared(token, 2).unwrap();
        observed.commit(token, 3).unwrap();
        observed
            .note_healthy(token.sequence, 20, candidate_proof(), proof())
            .unwrap();
        assert_eq!(
            observed.tick(53, candidate_proof(), proof()).unwrap(),
            RouteHealthAction::Stable
        );
        assert_eq!(observed.active_route(), direct(8000));
        assert_eq!(observed.rollback_route(), None);
    }

    #[test]
    fn concurrent_or_same_route_promotions_are_rejected() {
        let mut controller =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 5_000).unwrap();
        assert!(matches!(
            controller.begin(relay(), proof(), 1),
            Err(RouteTransitionError::SameRoute)
        ));
        controller
            .begin(direct(5000), candidate_proof(), 2)
            .unwrap();
        assert!(matches!(
            controller.begin(direct(6000), candidate_proof(), 3),
            Err(RouteTransitionError::TransitionInProgress)
        ));
    }

    #[test]
    fn prepare_and_commit_reject_the_exact_expiry_boundary() {
        let mut preparing =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 5_000).unwrap();
        let token = preparing
            .begin(direct(5000), candidate_proof(), 10)
            .unwrap();
        assert!(matches!(
            preparing.peer_prepared(token, 110),
            Err(RouteTransitionError::Expired)
        ));
        assert_eq!(preparing.active_route(), relay());

        let mut committing =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 5_000).unwrap();
        let token = committing
            .begin(direct(5000), candidate_proof(), 10)
            .unwrap();
        committing.peer_prepared(token, 109).unwrap();
        assert!(matches!(
            committing.commit(token, 110),
            Err(RouteTransitionError::Expired)
        ));
        assert_eq!(committing.active_route(), relay());
    }

    #[test]
    fn healthy_after_stability_deadline_cannot_retain_candidate() {
        let mut controller =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 50).unwrap();
        let token = controller
            .begin(direct(5000), candidate_proof(), 1)
            .unwrap();
        controller.peer_prepared(token, 2).unwrap();
        controller.commit(token, 3).unwrap();
        let mut stale = proof();
        stale.consent_fresh = false;
        assert!(matches!(
            controller.note_healthy(token.sequence, 53, stale, stale),
            Err(RouteTransitionError::NoVerifiedRoute)
        ));
        assert!(!controller.accepts_application_route(2, direct(5000)));
        assert!(!controller.accepts_application_route(1, relay()));
    }

    #[test]
    fn rollback_requires_fresh_proof_for_previous_route() {
        let mut controller =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 50).unwrap();
        let token = controller
            .begin(direct(5000), candidate_proof(), 1)
            .unwrap();
        controller.peer_prepared(token, 2).unwrap();
        controller.commit(token, 3).unwrap();
        let mut incomplete = proof();
        incomplete.consent_fresh = false;
        assert!(matches!(
            controller.note_unhealthy(token.sequence, 4, incomplete),
            Err(RouteTransitionError::NoVerifiedRoute)
        ));
        assert!(!controller.accepts_application_route(2, direct(5000)));
        assert!(!controller.accepts_application_route(1, relay()));
        assert!(matches!(
            controller.begin(direct(6000), candidate_proof(), 5),
            Err(RouteTransitionError::NoVerifiedRoute)
        ));
    }

    #[test]
    fn health_proofs_must_match_the_candidate_and_previous_transcripts() {
        let mut controller =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 50).unwrap();
        let token = controller
            .begin(direct(5000), candidate_proof(), 1)
            .unwrap();
        controller.peer_prepared(token, 2).unwrap();
        controller.commit(token, 3).unwrap();
        assert!(matches!(
            controller.note_healthy(token.sequence, 4, proof(), proof()),
            Err(RouteTransitionError::UnverifiedRoute)
        ));
        let mut wrong_previous = proof();
        wrong_previous.transcript_digest = [0xCC; 32];
        assert!(matches!(
            controller.note_unhealthy(token.sequence, 5, wrong_previous),
            Err(RouteTransitionError::NoVerifiedRoute)
        ));
        assert!(!controller.accepts_application_route(2, direct(5000)));
    }

    #[test]
    fn equal_timestamp_tick_and_health_are_deterministic_and_fail_closed() {
        let mut via_tick =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 50).unwrap();
        let token = via_tick.begin(direct(5000), candidate_proof(), 1).unwrap();
        via_tick.peer_prepared(token, 2).unwrap();
        via_tick.commit(token, 3).unwrap();
        let mut via_health = via_tick.clone();
        let stale_candidate = RouteProof {
            ice_nominated: false,
            ..proof()
        };
        let tick_action = via_tick.tick(53, stale_candidate, proof()).unwrap();
        let health_action = via_health
            .note_healthy(token.sequence, 53, stale_candidate, proof())
            .unwrap();
        assert_eq!(tick_action, health_action);
        let RouteHealthAction::RollbackRequired(tick_token) = tick_action else {
            panic!("stale candidate must require authenticated rollback");
        };
        assert_eq!(tick_token.route, relay());
        assert_eq!(via_tick.active_route(), direct(5000));
        assert_eq!(via_health.active_route(), direct(5000));
        assert!(!via_tick.accepts_application_route(2, direct(5000)));
    }

    #[test]
    fn rollback_epoch_exhaustion_revokes_all_route_authority() {
        let mut controller =
            RouteTransitionController::new(stamp(), relay(), proof(), 100, 50).unwrap();
        let token = controller
            .begin(direct(5000), candidate_proof(), 1)
            .unwrap();
        controller.peer_prepared(token, 2).unwrap();
        controller.commit(token, 3).unwrap();
        controller.stamp.route_epoch = u64::MAX;
        assert!(matches!(
            controller.note_unhealthy(token.sequence, 4, proof()),
            Err(RouteTransitionError::RouteEpochExhausted)
        ));
        assert!(!controller.accepts_application_route(u64::MAX, direct(5000)));
        assert!(!controller.accepts_application_route(1, relay()));
        assert!(matches!(
            controller.begin(direct(6000), candidate_proof(), 5),
            Err(RouteTransitionError::NoVerifiedRoute)
        ));
    }

    #[test]
    fn packet_gate_rejects_stale_epoch_and_foreign_stamp_after_promotion_and_rollback() {
        let active_stamp = stamp();
        let mut controller =
            RouteTransitionController::new(active_stamp, relay(), proof(), 100, 50).unwrap();
        assert!(controller.accepts_packet(active_stamp, relay()));
        let token = controller
            .begin(direct(5000), candidate_proof(), 1)
            .unwrap();
        controller.peer_prepared(token, 2).unwrap();
        let switch = controller.commit(token, 3).unwrap();
        assert!(controller.accepts_packet(switch.stamp, direct(5000)));
        assert!(!controller.accepts_packet(active_stamp, relay()));
        assert!(!controller.accepts_packet(stamp_with_session(99), direct(5000)));
        let rollback_token = controller
            .note_unhealthy(token.sequence, 4, proof())
            .unwrap();
        assert!(!controller.accepts_packet(switch.stamp, direct(5000)));
        controller.peer_prepared(rollback_token, 5).unwrap();
        let rollback = controller.commit(rollback_token, 6).unwrap();
        assert!(controller.accepts_packet(rollback.stamp, relay()));
        assert!(!controller.accepts_packet(switch.stamp, direct(5000)));
    }
}
