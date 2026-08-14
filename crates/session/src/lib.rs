//! Explicit session state machine. Invalid transitions fail closed.

use core::fmt;

pub mod authorization;
pub mod disconnect;
pub mod nat;
pub mod pairing;
pub mod unattended;

/// High-level lifecycle of one remote desktop session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No transport or authorization state exists.
    Idle,
    /// A transport connection is being established.
    Connecting,
    /// Peer identity and user authorization are being verified.
    Authenticating,
    /// Capture, input, codec, display, and protocol capabilities are negotiated.
    Negotiating,
    /// Media and input are active.
    Streaming,
    /// Decoder continuity is lost and a recovery point is required.
    Recovering,
    /// Local shutdown has begun.
    Closing,
    /// Transport is closed cleanly.
    Closed,
    /// A terminal failure occurred.
    Failed,
}

/// Events accepted by [`SessionMachine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Start,
    TransportReady,
    Authenticated,
    Negotiated,
    ContinuityLost,
    RecoveryFrameAccepted,
    Stop,
    TransportClosed,
    Fail,
}

/// Small deterministic session state machine.
#[derive(Debug, Clone)]
pub struct SessionMachine {
    state: SessionState,
}

impl Default for SessionMachine {
    fn default() -> Self {
        Self {
            state: SessionState::Idle,
        }
    }
}

impl SessionMachine {
    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Applies one event. Invalid transitions do not mutate state.
    pub fn apply(&mut self, event: SessionEvent) -> Result<SessionState, TransitionError> {
        use SessionEvent as E;
        use SessionState as S;

        let next = match (self.state, event) {
            (S::Idle, E::Start) => S::Connecting,
            (S::Connecting, E::TransportReady) => S::Authenticating,
            (S::Authenticating, E::Authenticated) => S::Negotiating,
            (S::Negotiating, E::Negotiated) => S::Streaming,
            (S::Streaming, E::ContinuityLost) => S::Recovering,
            (S::Recovering, E::RecoveryFrameAccepted) => S::Streaming,
            (
                S::Idle
                | S::Connecting
                | S::Authenticating
                | S::Negotiating
                | S::Streaming
                | S::Recovering,
                E::Stop,
            ) => S::Closing,
            (S::Closing, E::TransportClosed) => S::Closed,
            (
                S::Idle
                | S::Connecting
                | S::Authenticating
                | S::Negotiating
                | S::Streaming
                | S::Recovering
                | S::Closing,
                E::Fail,
            ) => S::Failed,
            _ => {
                return Err(TransitionError {
                    state: self.state,
                    event,
                });
            }
        };
        self.state = next;
        Ok(next)
    }
}

/// Invalid state/event pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError {
    pub state: SessionState,
    pub event: SessionEvent,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid session transition: {:?} + {:?}",
            self.state, self.event
        )
    }
}

impl std::error::Error for TransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nominal_lifecycle() {
        let mut machine = SessionMachine::default();
        for event in [
            SessionEvent::Start,
            SessionEvent::TransportReady,
            SessionEvent::Authenticated,
            SessionEvent::Negotiated,
        ] {
            machine.apply(event).expect("valid transition");
        }
        assert_eq!(machine.state(), SessionState::Streaming);
        machine.apply(SessionEvent::Stop).expect("stop");
        machine
            .apply(SessionEvent::TransportClosed)
            .expect("closed");
        assert_eq!(machine.state(), SessionState::Closed);
    }

    #[test]
    fn recovery_is_explicit() {
        let mut machine = SessionMachine {
            state: SessionState::Streaming,
        };
        assert_eq!(
            machine
                .apply(SessionEvent::ContinuityLost)
                .expect("recover"),
            SessionState::Recovering
        );
        assert_eq!(
            machine
                .apply(SessionEvent::RecoveryFrameAccepted)
                .expect("resume"),
            SessionState::Streaming
        );
    }

    #[test]
    fn invalid_transition_does_not_mutate() {
        let mut machine = SessionMachine::default();
        assert!(machine.apply(SessionEvent::Negotiated).is_err());
        assert_eq!(machine.state(), SessionState::Idle);
    }

    #[test]
    fn nat_candidate_gathering_and_priority() {
        use crate::nat::{CandidateGatherer, WireIpAddr};
        use latencydesk_protocol::{CandidateType, RelayProvider};

        let mut gatherer = CandidateGatherer::new();
        let host = gatherer
            .add_host_candidate(WireIpAddr::V4([192, 168, 1, 10]), 5000, 1, 100)
            .expect("host");
        let srflx = gatherer
            .add_srflx_candidate(
                WireIpAddr::V4([203, 0, 113, 5]),
                6000,
                WireIpAddr::V4([192, 168, 1, 10]),
                5000,
                1,
                50,
            )
            .expect("srflx");
        let relay = gatherer
            .add_relay_candidate(
                WireIpAddr::V4([198, 51, 100, 1]),
                7000,
                RelayProvider::Turn,
                1,
                10,
            )
            .expect("relay");

        assert_eq!(host.candidate_type, CandidateType::Host);
        assert_eq!(srflx.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(relay.candidate_type, CandidateType::Relayed);

        let sorted = gatherer.finish_gathering();
        assert_eq!(sorted.len(), 3);
        // Priority ordering must strictly be Host > Srflx > Relay
        assert_eq!(sorted[0].candidate_type, CandidateType::Host);
        assert_eq!(sorted[1].candidate_type, CandidateType::ServerReflexive);
        assert_eq!(sorted[2].candidate_type, CandidateType::Relayed);
    }

    #[test]
    fn router_direct_priority_and_seamless_relay_fallback() {
        use crate::nat::{CandidateGatherer, ConnectionPath, ConnectionRouter, WireIpAddr};
        use latencydesk_protocol::RelayProvider;

        let mut local_gatherer = CandidateGatherer::new();
        local_gatherer
            .add_host_candidate(WireIpAddr::V4([192, 168, 1, 10]), 5000, 1, 100)
            .unwrap();
        local_gatherer
            .add_relay_candidate(
                WireIpAddr::V4([198, 51, 100, 1]),
                7000,
                RelayProvider::Turn,
                1,
                10,
            )
            .unwrap();
        let local = local_gatherer.finish_gathering();

        let mut remote_gatherer = CandidateGatherer::new();
        remote_gatherer
            .add_host_candidate(WireIpAddr::V4([192, 168, 1, 20]), 5000, 1, 100)
            .unwrap();
        remote_gatherer
            .add_relay_candidate(
                WireIpAddr::V4([198, 51, 100, 1]),
                7000,
                RelayProvider::Turn,
                1,
                10,
            )
            .unwrap();
        let remote = remote_gatherer.finish_gathering();

        let mut router = ConnectionRouter::new(true, 1_000_000_000); // 1s direct timeout
        router.set_candidates(local, remote, 0x1234, [9_u8; 16]);

        // Within 1s window, router probes direct path
        let initial_path = router
            .select_initial_path(100_000_000)
            .expect("initial path");
        assert!(matches!(initial_path, ConnectionPath::Direct { .. }));

        // If direct checks time out at 1.5s -> seamless fallback to Relay!
        let mut timeout_router = ConnectionRouter::new(true, 1_000_000_000);
        timeout_router.set_candidates(
            local_gatherer.finish_gathering(),
            remote_gatherer.finish_gathering(),
            0x5678,
            [9_u8; 16],
        );
        let fallback_path = timeout_router
            .select_initial_path(1_500_000_000)
            .expect("fallback path");
        assert!(matches!(fallback_path, ConnectionPath::Relay { .. }));
        assert!(timeout_router.is_using_relay());
    }

    #[test]
    fn router_seamless_direct_upgrade_and_downgrade() {
        use crate::nat::{CandidateGatherer, ConnectionPath, ConnectionRouter, WireIpAddr};
        use latencydesk_protocol::RelayProvider;

        let mut local_gatherer = CandidateGatherer::new();
        local_gatherer
            .add_host_candidate(WireIpAddr::V4([10, 0, 0, 1]), 5000, 1, 100)
            .unwrap();
        local_gatherer
            .add_relay_candidate(
                WireIpAddr::V4([198, 51, 100, 1]),
                7000,
                RelayProvider::Derp,
                1,
                10,
            )
            .unwrap();

        let mut remote_gatherer = CandidateGatherer::new();
        remote_gatherer
            .add_host_candidate(WireIpAddr::V4([10, 0, 0, 2]), 5000, 1, 100)
            .unwrap();
        remote_gatherer
            .add_relay_candidate(
                WireIpAddr::V4([198, 51, 100, 1]),
                7000,
                RelayProvider::Derp,
                1,
                10,
            )
            .unwrap();

        let mut router = ConnectionRouter::new(true, 500_000_000);
        router.set_candidates(
            local_gatherer.finish_gathering(),
            remote_gatherer.finish_gathering(),
            0x9999,
            [7_u8; 16],
        );

        // Start on relay fallback after direct timeout
        let path = router.select_initial_path(1_000_000_000).expect("path");
        assert!(matches!(path, ConnectionPath::Relay { .. }));
        assert!(router.is_using_relay());

        // Background probing triggers on relay fallback
        let probe_pair = router
            .tick_background_probing(1_600_000_000)
            .expect("probe pair");
        assert!(probe_pair.is_direct());

        // Direct probe succeeds -> SEAMLESS UPGRADE TO DIRECT PATH!
        let direct_idx = router
            .pairs()
            .iter()
            .position(|p| p.is_direct())
            .expect("direct idx");
        let upgraded = router
            .record_check_result(direct_idx, true, 15_000_000, 1_700_000_000)
            .expect("upgraded");
        assert!(matches!(upgraded, ConnectionPath::Direct { .. }));
        assert!(!router.is_using_relay());
        assert_eq!(router.stats().direct_upgrades, 1);

        // If direct path fails later -> SEAMLESS DOWNGRADE BACK TO RELAY!
        let downgraded = router
            .record_check_result(direct_idx, false, 0, 2_000_000_000)
            .expect("downgraded");
        assert!(matches!(downgraded, ConnectionPath::Relay { .. }));
        assert!(router.is_using_relay());
        assert_eq!(router.stats().relay_downgrades, 1);
    }

    #[test]
    fn sas_pairing_workflow_and_lockout() {
        use crate::authorization::DeviceFingerprint;
        use crate::pairing::{SasError, SasPairingManager};
        use latencydesk_protocol::{PairingRequestWire, PairingResponseWire, SasCode};
        let host_dev = DeviceFingerprint::new([1_u8; 32]).expect("host device");
        let client_dev = DeviceFingerprint::new([2_u8; 32]).expect("client device");
        let host_ephemeral = [3_u8; 32];
        let client_ephemeral = [4_u8; 32];

        let mut manager = SasPairingManager::new(3, 300_000_000_000);
        manager
            .begin_pairing(host_dev, host_ephemeral, 1_000_000)
            .expect("begin");

        let req = PairingRequestWire {
            client_fingerprint: client_dev.as_bytes(),
            client_ephemeral_key: client_ephemeral,
            requested_capabilities: 0x03,
            timestamp_ns: 1_100_000,
        };

        let (resp, sas_code, handle) = manager
            .handle_client_request(req, [8_u8; 16], 1_200_000)
            .expect("handle req");

        // Verify wire sas_commitment is cryptographic commitment and not plaintext SAS digits
        assert_eq!(
            resp.sas_commitment,
            PairingResponseWire::compute_commitment(
                &host_ephemeral,
                &client_ephemeral,
                b"LatencyDesk-v1-SAS-Numeric"
            )
        );
        assert_ne!(&resp.sas_commitment[0..6], &sas_code.to_ascii_digits());

        // Wrong SAS code attempts decrement counter
        let wrong_sas = SasCode::from_u32((sas_code.value() + 1) % 1_000_000).unwrap();
        assert_eq!(
            manager.confirm_sas(handle, wrong_sas, 1_300_000),
            Err(SasError::SasMismatch)
        );
        assert_eq!(
            manager.confirm_sas(handle, wrong_sas, 1_400_000),
            Err(SasError::SasMismatch)
        );
        // 3rd attempt exceeds max attempts and permanently locks out
        assert_eq!(
            manager.confirm_sas(handle, wrong_sas, 1_500_000),
            Err(SasError::MaxAttemptsExceeded)
        );
        assert!(!manager.is_confirmed(client_dev));

        // New session with correct SAS confirms successfully
        let mut valid_manager = SasPairingManager::new(3, 300_000_000_000);
        valid_manager
            .begin_pairing(host_dev, host_ephemeral, 2_000_000)
            .expect("begin");
        let (_resp2, sas_code2, handle2) = valid_manager
            .handle_client_request(req, [9_u8; 16], 2_100_000)
            .expect("req");
        assert_eq!(
            valid_manager.confirm_sas(handle2, sas_code2, 2_200_000),
            Ok(())
        );
        assert!(valid_manager.is_confirmed(client_dev));
    }

    #[test]
    fn unattended_token_constraints_and_revocation() {
        use crate::authorization::{CapabilitySet, DeviceFingerprint};
        use crate::unattended::{UnattendedError, UnattendedTokenManager};

        let mut manager = UnattendedTokenManager::default();
        let device = DeviceFingerprint::new([5_u8; 32]).expect("device");
        let other_device = DeviceFingerprint::new([6_u8; 32]).expect("other device");
        let secret = [0x55; 32];
        let token_id = [0xAA; 16];

        let allowed = CapabilitySet::view_only();
        let token_wire = manager
            .issue_token(
                token_id,
                device,
                allowed,
                86_400_000_000_000, // 24h
                Some(2),            // max 2 sessions
                secret,
                1_000_000,
            )
            .expect("issue");

        assert_eq!(token_wire.token_id, token_id);

        // 1. Valid authentication
        let validated = manager
            .validate_token(token_id, &secret, device, allowed, 1_100_000)
            .expect("validate 1");
        assert_eq!(validated, allowed);

        // 2. Capability escalation rejected: token only permits View, requesting View+Input fails!
        let escalated = CapabilitySet::view_and_input();
        assert_eq!(
            manager.validate_token(token_id, &secret, device, escalated, 1_200_000),
            Err(UnattendedError::CapabilityEscalation)
        );

        // 3. Device mismatch rejected
        assert_eq!(
            manager.validate_token(token_id, &secret, other_device, allowed, 1_300_000),
            Err(UnattendedError::DeviceMismatch)
        );

        // 4. Invalid secret rejected
        let bad_secret = [0x00; 32];
        assert_eq!(
            manager.validate_token(token_id, &bad_secret, device, allowed, 1_400_000),
            Err(UnattendedError::InvalidSecret)
        );

        // 5. 2nd valid session reaches max sessions limit
        assert!(manager
            .validate_token(token_id, &secret, device, allowed, 1_500_000)
            .is_ok());
        assert_eq!(
            manager.validate_token(token_id, &secret, device, allowed, 1_600_000),
            Err(UnattendedError::MaxSessionsExceeded)
        );

        // 6. Instantaneous device-wide revocation
        let token_id2 = [0xBB; 16];
        manager
            .issue_token(
                token_id2,
                device,
                allowed,
                86_400_000_000_000,
                None,
                secret,
                2_000_000,
            )
            .expect("issue 2");
        assert_eq!(manager.revoke_all_for_device(device), 2);
        assert_eq!(
            manager.validate_token(token_id2, &secret, device, allowed, 2_100_000),
            Err(UnattendedError::TokenRevoked)
        );
    }

    #[test]
    fn safe_disconnect_lifecycle_and_fail_closed() {
        use crate::disconnect::{DisconnectState, SafeDisconnectController};
        use latencydesk_protocol::DisconnectReason;

        let mut controller = SafeDisconnectController::new(0x1234, 1, 2_000_000_000);
        assert_eq!(controller.state(), DisconnectState::Connected);
        assert!(controller.can_process_traffic());

        // Initiate graceful disconnect
        let wire = controller.initiate_disconnect(
            DisconnectReason::UserInitiated,
            "User clicked disconnect",
            1_000_000_000,
        );
        assert_eq!(wire.reason, DisconnectReason::UserInitiated);
        assert!(!controller.can_process_traffic()); // Fails closed immediately

        // Buffer drain in progress
        assert!(!controller.check_drain(1024, 1_500_000_000));
        // Buffer drain completed -> Closed
        assert!(controller.check_drain(0, 1_600_000_000));
        assert!(controller.is_closed());
        assert_eq!(
            controller.disconnect_reason(),
            Some(DisconnectReason::UserInitiated)
        );
    }
}
