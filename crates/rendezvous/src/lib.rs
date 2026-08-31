//! Authenticated, bounded rendezvous state. Transport-level mTLS supplies the
//! caller's [`DeviceId`]; payload claims never choose that identity.

use latencydesk_protocol::{ProtocolError, RendezvousRegistration};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    pub fn new(fingerprint: [u8; 32]) -> Result<Self, RendezvousError> {
        if fingerprint == [0; 32] {
            return Err(RendezvousError::InvalidDeviceId);
        }
        Ok(Self(fingerprint))
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DeviceId")
            .field(&"<certificate-fingerprint>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RendezvousLimits {
    pub max_pending: usize,
    pub max_pending_per_device: usize,
}

impl Default for RendezvousLimits {
    fn default() -> Self {
        Self {
            max_pending: 1_024,
            max_pending_per_device: 4,
        }
    }
}

impl RendezvousLimits {
    fn validate(self) -> Result<Self, RendezvousError> {
        if !(1..=4_096).contains(&self.max_pending)
            || !(1..=16).contains(&self.max_pending_per_device)
            || self.max_pending_per_device > self.max_pending
        {
            return Err(RendezvousError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug)]
pub enum RendezvousError {
    InvalidLimits,
    InvalidDeviceId,
    InvalidRegistration(ProtocolError),
    SelfMatch,
    Replay,
    PeerMismatch,
    RoleMismatch,
    GenerationMismatch,
    Capacity,
    DeviceCapacity,
    TimeOverflow,
    DeliveryUnavailable,
}

impl fmt::Display for RendezvousError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RendezvousError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRegistration(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ProtocolError> for RendezvousError {
    fn from(error: ProtocolError) -> Self {
        Self::InvalidRegistration(error)
    }
}

#[derive(Debug)]
pub struct RendezvousDelivery {
    pub peer: DeviceId,
    pub registration: RendezvousRegistration,
}

#[derive(Debug)]
pub enum RegisterOutcome {
    Waiting { expires_at: u64 },
    Matched(RendezvousDelivery),
}

#[derive(Debug)]
struct PendingRegistration {
    device: DeviceId,
    registration: RendezvousRegistration,
    expires_at: u64,
}

#[derive(Debug)]
struct StoredDelivery {
    delivery: RendezvousDelivery,
    expires_at: u64,
}

#[derive(Debug)]
pub struct RendezvousBroker {
    limits: RendezvousLimits,
    pending: HashMap<[u8; 16], PendingRegistration>,
    deliveries: HashMap<(DeviceId, [u8; 16]), StoredDelivery>,
    completed: HashMap<[u8; 16], u64>,
}

impl RendezvousBroker {
    pub fn new(limits: RendezvousLimits) -> Result<Self, RendezvousError> {
        Ok(Self {
            limits: limits.validate()?,
            pending: HashMap::new(),
            deliveries: HashMap::new(),
            completed: HashMap::new(),
        })
    }

    pub fn register(
        &mut self,
        authenticated_device: DeviceId,
        registration: RendezvousRegistration,
        now: u64,
    ) -> Result<RegisterOutcome, RendezvousError> {
        self.cleanup(now);
        registration.encode()?;
        if registration.expected_peer_fingerprint == authenticated_device.into_bytes() {
            return Err(RendezvousError::SelfMatch);
        }
        let match_id = registration.match_id;
        if self.completed.contains_key(&match_id)
            || self
                .deliveries
                .contains_key(&(authenticated_device, match_id))
        {
            return Err(RendezvousError::Replay);
        }
        let expires_at = now
            .checked_add(u64::from(registration.ttl_seconds))
            .ok_or(RendezvousError::TimeOverflow)?;

        if let Some(waiting) = self.pending.get(&match_id) {
            if waiting.device == authenticated_device {
                return Err(RendezvousError::Replay);
            }
            if waiting.registration.expected_peer_fingerprint != authenticated_device.into_bytes()
                || registration.expected_peer_fingerprint != waiting.device.into_bytes()
            {
                return Err(RendezvousError::PeerMismatch);
            }
            if waiting.registration.role == registration.role {
                return Err(RendezvousError::RoleMismatch);
            }
            if waiting.registration.generation != registration.generation
                || waiting.registration.credentials.exchange_id
                    != registration.credentials.exchange_id
            {
                return Err(RendezvousError::GenerationMismatch);
            }
            let completed_limit = self.limits.max_pending.saturating_mul(4);
            if self.deliveries.len() >= self.limits.max_pending
                || self.completed.len() >= completed_limit
            {
                return Err(RendezvousError::Capacity);
            }
            let waiting = self
                .pending
                .remove(&match_id)
                .expect("waiting registration checked before removal");
            let delivery_expiry = waiting.expires_at.min(expires_at);
            let caller_delivery = RendezvousDelivery {
                peer: waiting.device,
                registration: waiting.registration,
            };
            self.deliveries.insert(
                (waiting.device, match_id),
                StoredDelivery {
                    delivery: RendezvousDelivery {
                        peer: authenticated_device,
                        registration,
                    },
                    expires_at: delivery_expiry,
                },
            );
            self.completed.insert(match_id, delivery_expiry);
            return Ok(RegisterOutcome::Matched(caller_delivery));
        }

        if self.pending.len() >= self.limits.max_pending
            || self.completed.len() >= self.limits.max_pending.saturating_mul(4)
        {
            return Err(RendezvousError::Capacity);
        }
        let device_pending = self
            .pending
            .values()
            .filter(|pending| pending.device == authenticated_device)
            .count();
        if device_pending >= self.limits.max_pending_per_device {
            return Err(RendezvousError::DeviceCapacity);
        }
        self.pending.insert(
            match_id,
            PendingRegistration {
                device: authenticated_device,
                registration,
                expires_at,
            },
        );
        Ok(RegisterOutcome::Waiting { expires_at })
    }

    pub fn take_delivery(
        &mut self,
        authenticated_device: DeviceId,
        match_id: [u8; 16],
        now: u64,
    ) -> Result<RendezvousDelivery, RendezvousError> {
        self.cleanup(now);
        self.deliveries
            .remove(&(authenticated_device, match_id))
            .map(|stored| stored.delivery)
            .ok_or(RendezvousError::DeliveryUnavailable)
    }

    pub fn cleanup(&mut self, now: u64) {
        let expired_pending: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(match_id, pending)| (pending.expires_at <= now).then_some(*match_id))
            .collect();
        for match_id in expired_pending {
            self.pending.remove(&match_id);
            self.completed.insert(
                match_id,
                now.saturating_add(u64::from(RendezvousRegistration::MAX_TTL_SECONDS)),
            );
        }
        self.deliveries
            .retain(|_, delivery| delivery.expires_at > now);
        self.completed.retain(|_, expires_at| *expires_at > now);
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_protocol::{
        CandidateExchange, CandidateType, IceCandidate, IceCredentialExchange, IceCredentialRole,
        RelayProvider, RendezvousRegistration, RendezvousRole, TransportProtocol, WireIpAddr,
    };

    fn device(byte: u8) -> DeviceId {
        DeviceId::new([byte; 32]).unwrap()
    }

    fn registration(
        role: RendezvousRole,
        expected_peer: DeviceId,
        match_id: [u8; 16],
    ) -> RendezvousRegistration {
        RendezvousRegistration {
            version: RendezvousRegistration::VERSION,
            role,
            generation: 1,
            ttl_seconds: 30,
            match_id,
            expected_peer_fingerprint: expected_peer.into_bytes(),
            credentials: IceCredentialExchange::new(
                1,
                7,
                1,
                match role {
                    RendezvousRole::Initiator => IceCredentialRole::Controlling,
                    RendezvousRole::Responder => IceCredentialRole::Controlled,
                },
                format!("ufrag{role:?}"),
                match role {
                    RendezvousRole::Initiator => "A".repeat(32),
                    RendezvousRole::Responder => "B".repeat(32),
                },
            )
            .unwrap(),
            candidates: CandidateExchange {
                version: CandidateExchange::VERSION,
                exchange_id: 7,
                generation: 1,
                candidates: vec![IceCandidate {
                    foundation: [1; 8],
                    component: 1,
                    transport: TransportProtocol::Udp,
                    priority: 1,
                    candidate_type: CandidateType::Host,
                    relay_provider: RelayProvider::None,
                    ip: WireIpAddr::V4([127, 0, 0, 1]),
                    port: if role == RendezvousRole::Initiator {
                        5001
                    } else {
                        5002
                    },
                    related_address: None,
                }],
            },
        }
    }

    #[test]
    fn reciprocal_exact_peers_match_and_each_takes_the_other_offer_once() {
        let mut broker = RendezvousBroker::new(RendezvousLimits::default()).unwrap();
        let initiator = device(1);
        let responder = device(2);
        let match_id = [9; 16];
        assert!(matches!(
            broker.register(
                initiator,
                registration(RendezvousRole::Initiator, responder, match_id),
                100,
            ),
            Ok(RegisterOutcome::Waiting { .. })
        ));
        let responder_delivery = match broker
            .register(
                responder,
                registration(RendezvousRole::Responder, initiator, match_id),
                101,
            )
            .unwrap()
        {
            RegisterOutcome::Matched(delivery) => delivery,
            RegisterOutcome::Waiting { .. } => panic!("second reciprocal peer must match"),
        };
        assert_eq!(responder_delivery.peer, initiator);
        assert_eq!(
            responder_delivery.registration.role,
            RendezvousRole::Initiator
        );
        let initiator_delivery = broker.take_delivery(initiator, match_id, 101).unwrap();
        assert_eq!(initiator_delivery.peer, responder);
        assert_eq!(
            initiator_delivery.registration.role,
            RendezvousRole::Responder
        );
        assert!(matches!(
            broker.take_delivery(initiator, match_id, 101),
            Err(RendezvousError::DeliveryUnavailable)
        ));

        let mut reverse = RendezvousBroker::new(RendezvousLimits::default()).unwrap();
        let reverse_match = [8; 16];
        reverse
            .register(
                responder,
                registration(RendezvousRole::Responder, initiator, reverse_match),
                200,
            )
            .unwrap();
        let initiator_delivery = reverse
            .register(
                initiator,
                registration(RendezvousRole::Initiator, responder, reverse_match),
                201,
            )
            .unwrap();
        assert!(matches!(initiator_delivery, RegisterOutcome::Matched(_)));
        assert!(reverse.take_delivery(responder, reverse_match, 201).is_ok());
    }

    #[test]
    fn mismatch_replay_capacity_and_expiry_fail_without_consuming_valid_waiter() {
        let limits = RendezvousLimits {
            max_pending: 1,
            max_pending_per_device: 1,
        };
        let mut broker = RendezvousBroker::new(limits).unwrap();
        let initiator = device(1);
        let responder = device(2);
        let stranger = device(3);
        let match_id = [9; 16];
        broker
            .register(
                initiator,
                registration(RendezvousRole::Initiator, responder, match_id),
                100,
            )
            .unwrap();
        assert!(matches!(
            broker.register(
                stranger,
                registration(RendezvousRole::Initiator, responder, [7; 16]),
                101,
            ),
            Err(RendezvousError::Capacity)
        ));
        assert!(matches!(
            broker.register(
                initiator,
                registration(RendezvousRole::Initiator, responder, match_id),
                101,
            ),
            Err(RendezvousError::Replay)
        ));
        assert!(matches!(
            broker.register(
                stranger,
                registration(RendezvousRole::Responder, initiator, match_id),
                101,
            ),
            Err(RendezvousError::PeerMismatch)
        ));
        let delivery = broker
            .register(
                responder,
                registration(RendezvousRole::Responder, initiator, match_id),
                102,
            )
            .unwrap();
        assert!(matches!(delivery, RegisterOutcome::Matched(_)));

        let second_match = [8; 16];
        assert!(matches!(
            broker.register(
                stranger,
                registration(RendezvousRole::Initiator, responder, second_match),
                200,
            ),
            Ok(RegisterOutcome::Waiting { .. })
        ));
        broker.cleanup(231);
        assert_eq!(broker.pending_len(), 0);
        assert!(matches!(
            broker.register(
                stranger,
                registration(RendezvousRole::Initiator, responder, second_match),
                231,
            ),
            Err(RendezvousError::Replay)
        ));

        let mut per_device = RendezvousBroker::new(RendezvousLimits {
            max_pending: 2,
            max_pending_per_device: 1,
        })
        .unwrap();
        per_device
            .register(
                initiator,
                registration(RendezvousRole::Initiator, responder, [6; 16]),
                300,
            )
            .unwrap();
        assert!(matches!(
            per_device.register(
                initiator,
                registration(RendezvousRole::Initiator, responder, [5; 16]),
                300,
            ),
            Err(RendezvousError::DeviceCapacity)
        ));
    }

    #[test]
    fn wrong_role_or_generation_does_not_consume_the_waiting_registration() {
        let mut broker = RendezvousBroker::new(RendezvousLimits::default()).unwrap();
        let initiator = device(1);
        let responder = device(2);
        let match_id = [9; 16];
        broker
            .register(
                initiator,
                registration(RendezvousRole::Initiator, responder, match_id),
                100,
            )
            .unwrap();
        assert!(matches!(
            broker.register(
                responder,
                registration(RendezvousRole::Initiator, initiator, match_id),
                101,
            ),
            Err(RendezvousError::RoleMismatch)
        ));
        let mut wrong_generation = registration(RendezvousRole::Responder, initiator, match_id);
        wrong_generation.generation = 2;
        wrong_generation.credentials.generation = 2;
        wrong_generation.candidates.generation = 2;
        assert!(matches!(
            broker.register(responder, wrong_generation, 101),
            Err(RendezvousError::GenerationMismatch)
        ));
        assert!(matches!(
            broker.register(
                responder,
                registration(RendezvousRole::Responder, initiator, match_id),
                102,
            ),
            Ok(RegisterOutcome::Matched(_))
        ));
        assert!(matches!(
            broker.take_delivery(initiator, match_id, 131),
            Err(RendezvousError::DeliveryUnavailable)
        ));
    }

    #[test]
    fn debug_and_errors_never_render_credential_sentinels() {
        assert!(matches!(
            DeviceId::new([0; 32]),
            Err(RendezvousError::InvalidDeviceId)
        ));
        assert!(matches!(
            RendezvousBroker::new(RendezvousLimits {
                max_pending: 0,
                max_pending_per_device: 1,
            }),
            Err(RendezvousError::InvalidLimits)
        ));
        let registration = registration(RendezvousRole::Initiator, device(2), [9; 16]);
        let rendered = format!("{registration:?}");
        assert!(!rendered.contains(&"A".repeat(32)));
        let delivery = RendezvousDelivery {
            peer: device(2),
            registration,
        };
        assert!(!format!("{delivery:?}").contains(&"A".repeat(32)));
    }
}
