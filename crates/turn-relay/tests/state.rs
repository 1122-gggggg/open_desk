use latencydesk_turn_relay::{
    wire::{self, Attribute, Class, Header, Message, Method},
    AllocationCredentials, AuthenticatedRequest, ChannelNumber, DeliveryRoute, PeerPolicy, Quota,
    RelayState, StateError, UdpTuple, CHANNEL_LIFETIME, DEFAULT_ALLOCATION_LIFETIME,
    PERMISSION_LIFETIME,
};
use std::net::SocketAddr;

fn tuple(port: u16) -> UdpTuple {
    UdpTuple {
        client: format!("192.0.2.10:{port}").parse().unwrap(),
        server: "198.51.100.10:3478".parse().unwrap(),
    }
}

fn relay(port: u16) -> SocketAddr {
    format!("198.51.100.10:{port}").parse().unwrap()
}

fn peer(ip: u8, port: u16) -> SocketAddr {
    format!("203.0.113.{ip}:{port}").parse().unwrap()
}

fn credentials(user: &[u8]) -> AllocationCredentials {
    let key = integrity_key(user);
    AllocationCredentials::new(
        user.to_vec(),
        b"turn.example".to_vec(),
        b"nonce-1".to_vec(),
        [user, b"-identity"].concat(),
        *key,
    )
    .unwrap()
}

fn integrity_key(user: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    wire::derive_long_term_key_sha256(user, b"turn.example", &[user, b"-password"].concat())
}

fn signed_request(
    user: &[u8],
    realm: &[u8],
    nonce: &[u8],
    method: Method,
    attributes: Vec<Attribute>,
) -> Vec<u8> {
    signed_request_with_id(
        user,
        realm,
        nonce,
        method,
        attributes,
        [method as u8 + 1; 12],
    )
}

fn signed_request_with_id(
    user: &[u8],
    realm: &[u8],
    nonce: &[u8],
    method: Method,
    mut attributes: Vec<Attribute>,
    transaction_id: [u8; 12],
) -> Vec<u8> {
    let key = integrity_key(user);
    let mut credentials = vec![
        Attribute::Username(user.to_vec()),
        Attribute::Realm(realm.to_vec()),
        Attribute::Nonce(nonce.to_vec()),
    ];
    credentials.append(&mut attributes);
    wire::encode_with_integrity(
        &Message {
            header: Header {
                class: Class::Request,
                method,
                transaction_id,
            },
            attributes: credentials,
        },
        key.as_ref(),
    )
    .unwrap()
}

fn authenticate(
    state: &mut RelayState,
    key: UdpTuple,
    user: &[u8],
    nonce: &[u8],
    method: Method,
    attributes: Vec<Attribute>,
    now: u64,
) -> AuthenticatedRequest {
    state
        .authenticate_request(
            &key,
            &signed_request(user, b"turn.example", nonce, method, attributes),
            now,
        )
        .unwrap()
}

fn assert_auth_error(state: &mut RelayState, encoded: &[u8], now: u64, expected: StateError) {
    assert!(matches!(
        state.authenticate_request(&tuple(5000), encoded, now),
        Err(error) if error == expected
    ));
}

fn quota() -> Quota {
    Quota {
        max_allocations: 4,
        max_allocations_per_user: 2,
        max_permissions_per_allocation: 2,
        max_channels_per_allocation: 2,
        max_packets_per_allocation: 4,
        max_payload_bytes_per_allocation: 16,
    }
}

fn state() -> RelayState {
    RelayState::new(quota(), PeerPolicy::default()).unwrap()
}

#[test]
fn stale_nonce_challenge_replay_cannot_rotate_state() {
    let mut state = state();
    let key = tuple(5000);
    state
        .create(key, credentials(b"alice"), relay(49000), 0, None)
        .unwrap();
    let mut invalid_bytes = signed_request(
        b"alice",
        b"turn.example",
        b"nonce-1",
        Method::Refresh,
        vec![Attribute::Lifetime(1)],
    );
    *invalid_bytes.last_mut().unwrap() ^= 0xff;
    assert!(matches!(
        state.stale_nonce_challenge(&key, &invalid_bytes, 1),
        Err(StateError::Integrity)
    ));
    let stale_bytes = signed_request(
        b"alice",
        b"turn.example",
        b"nonce-0",
        Method::Refresh,
        vec![Attribute::Lifetime(1)],
    );
    let current = authenticate(
        &mut state,
        key,
        b"alice",
        b"nonce-1",
        Method::Refresh,
        vec![],
        1,
    );
    state
        .rotate_nonce(&current, b"nonce-2".to_vec(), 1)
        .unwrap();
    let current_challenge = state.stale_nonce_challenge(&key, &stale_bytes, 1).unwrap();
    let encoded_challenge = current_challenge
        .encode_signed_438(Method::Refresh, [0x66; 12])
        .unwrap();
    let verified_challenge =
        wire::verify_integrity(&encoded_challenge, integrity_key(b"alice").as_ref()).unwrap();
    assert_eq!(
        verified_challenge
            .message()
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Realm(value) => Some(value.as_slice()),
                _ => None,
            }),
        Some(b"turn.example".as_slice())
    );
    assert_eq!(
        verified_challenge
            .message()
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Nonce(value) => Some(value.as_slice()),
                _ => None,
            }),
        Some(b"nonce-2".as_slice())
    );
    let replay = signed_request_with_id(
        b"alice",
        b"turn.example",
        b"nonce-0",
        Method::Refresh,
        vec![Attribute::Lifetime(1)],
        [0x77; 12],
    );
    let replay_challenge = state.stale_nonce_challenge(&key, &replay, 1).unwrap();
    let replay_response = replay_challenge
        .encode_signed_438(Method::Refresh, [0x77; 12])
        .unwrap();
    let replay_response =
        wire::verify_integrity(&replay_response, integrity_key(b"alice").as_ref()).unwrap();
    assert_eq!(
        replay_response
            .message()
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Nonce(value) => Some(value.as_slice()),
                _ => None,
            }),
        Some(b"nonce-2".as_slice())
    );
    assert!(matches!(
        state.authenticate_request(&key, &stale_bytes, 1),
        Err(StateError::StaleNonce)
    ));
    let fresh = signed_request(
        b"alice",
        b"turn.example",
        b"nonce-2",
        Method::Refresh,
        vec![Attribute::Lifetime(1)],
    );
    assert!(state.authenticate_request(&key, &fresh, 1).is_ok());
}

#[test]
fn quota_constructor_rejects_zero_and_unbounded_values() {
    let mut invalid = quota();
    invalid.max_allocations = 0;
    assert!(matches!(
        RelayState::new(invalid, PeerPolicy::default()),
        Err(StateError::InvalidQuota)
    ));
    invalid = quota();
    invalid.max_channels_per_allocation = 10_000;
    assert!(matches!(
        RelayState::new(invalid, PeerPolicy::default()),
        Err(StateError::InvalidQuota)
    ));
}

#[test]
fn allocation_is_five_tuple_unique_and_uses_bounded_default_lifetime() {
    let mut state = state();
    let info = state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 10, None)
        .unwrap();
    assert_eq!(info.expires_at, 10 + DEFAULT_ALLOCATION_LIFETIME);
    assert!(matches!(
        state.create(
            tuple(5000),
            credentials(b"alice"),
            relay(55001),
            11,
            Some(3_600)
        ),
        Err(StateError::DuplicateAllocation)
    ));
}

#[test]
fn expired_allocation_is_reclaimed_before_duplicate_and_quota_checks() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    state
        .create(
            tuple(5000),
            credentials(b"alice"),
            relay(55001),
            DEFAULT_ALLOCATION_LIFETIME,
            None,
        )
        .unwrap();
    assert_eq!(
        state
            .allocation_info(&tuple(5000), DEFAULT_ALLOCATION_LIFETIME)
            .unwrap()
            .relayed_address,
        relay(55001)
    );
}

#[test]
fn global_and_per_username_allocation_quotas_are_independent() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    state
        .create(tuple(5001), credentials(b"alice"), relay(55001), 0, None)
        .unwrap();
    assert!(matches!(
        state.create(tuple(5002), credentials(b"alice"), relay(55002), 0, None),
        Err(StateError::UserQuota)
    ));
    state
        .create(tuple(5002), credentials(b"bob"), relay(55002), 0, None)
        .unwrap();
}

#[test]
fn relayed_transport_address_is_globally_unique() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    assert!(matches!(
        state.create(tuple(5001), credentials(b"bob"), relay(55000), 0, None),
        Err(StateError::RelayAddressInUse)
    ));
}

#[test]
fn authentication_binds_username_realm_nonce_and_identity() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::Refresh,
        vec![],
        1,
    );
    let wrong_realm = signed_request(b"alice", b"other", b"nonce-1", Method::Refresh, vec![]);
    assert_auth_error(&mut state, &wrong_realm, 1, StateError::WrongCredentials);
    let stale = signed_request(b"alice", b"turn.example", b"old", Method::Refresh, vec![]);
    assert_auth_error(&mut state, &stale, 1, StateError::StaleNonce);
    let mut corrupted = signed_request(
        b"alice",
        b"turn.example",
        b"nonce-1",
        Method::Refresh,
        vec![],
    );
    corrupted[8] ^= 1;
    assert_auth_error(&mut state, &corrupted, 1, StateError::Integrity);
}

#[test]
fn nonce_rotation_invalidates_old_nonce_without_changing_allocation_key() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let request = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::Refresh,
        vec![],
        1,
    );
    state
        .rotate_nonce(&request, b"nonce-2".to_vec(), 1)
        .unwrap();
    let stale = signed_request(
        b"alice",
        b"turn.example",
        b"nonce-1",
        Method::Refresh,
        vec![],
    );
    assert_auth_error(&mut state, &stale, 2, StateError::StaleNonce);
    authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-2",
        Method::Refresh,
        vec![],
        2,
    );
    assert!(matches!(
        state.refresh(&request, 2),
        Err(StateError::StaleNonce)
    ));
}

#[test]
fn refresh_zero_deletes_and_expired_allocation_cannot_resurrect() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let delete = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::Refresh,
        vec![Attribute::Lifetime(0)],
        1,
    );
    assert_eq!(state.refresh(&delete, 1).unwrap(), None);
    assert!(matches!(
        state.refresh(&delete, 2),
        Err(StateError::MissingAllocation)
    ));
}

#[test]
fn old_verified_token_cannot_authorize_recreated_tuple_aba() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let old_permission = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::CreatePermission,
        vec![Attribute::XorPeerAddress(peer(1, 5000))],
        1,
    );
    let delete = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::Refresh,
        vec![Attribute::Lifetime(0)],
        1,
    );
    state.refresh(&delete, 1).unwrap();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55001), 2, None)
        .unwrap();
    assert!(matches!(
        state.create_permissions(&old_permission, 3),
        Err(StateError::StaleAuthorization)
    ));
}

#[test]
fn sealed_token_cannot_cross_relay_state_instances() {
    let mut first = state();
    first
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let token = authenticate(
        &mut first,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::CreatePermission,
        vec![Attribute::XorPeerAddress(peer(1, 5000))],
        1,
    );
    let mut second = state();
    second
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    assert!(matches!(
        second.create_permissions(&token, 2),
        Err(StateError::StaleAuthorization)
    ));
}

#[test]
fn permission_is_ip_scoped_and_expiry_reclaims_quota() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let permission = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::CreatePermission,
        vec![Attribute::XorPeerAddress(peer(1, 53))],
        1,
    );
    state.create_permissions(&permission, 1).unwrap();
    assert!(state
        .authorize_send(&tuple(5000), peer(1, 6000), 1, 2)
        .is_ok());
    assert_eq!(
        state
            .route_peer_datagram(&tuple(5000), peer(1, 53), 1, 2)
            .unwrap(),
        DeliveryRoute::DataIndication
    );
    assert!(matches!(
        state.authorize_send(&tuple(5000), peer(1, 6000), 1, 1 + PERMISSION_LIFETIME),
        Err(StateError::NotPermitted)
    ));
}

#[test]
fn channel_binding_is_bijective_and_same_binding_refreshes() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let binding = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::ChannelBind,
        vec![
            Attribute::ChannelNumber(0x4000),
            Attribute::XorPeerAddress(peer(1, 5000)),
        ],
        1,
    );
    state.bind_channel(&binding, 1).unwrap();
    state.bind_channel(&binding, 2).unwrap();
    let collision = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::ChannelBind,
        vec![
            Attribute::ChannelNumber(0x4001),
            Attribute::XorPeerAddress(peer(1, 5000)),
        ],
        3,
    );
    assert!(matches!(
        state.bind_channel(&collision, 3),
        Err(StateError::ChannelCollision)
    ));
}

#[test]
fn expired_binding_enforces_per_allocation_rebind_quarantine() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let original = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::ChannelBind,
        vec![
            Attribute::ChannelNumber(0x4000),
            Attribute::XorPeerAddress(peer(1, 5000)),
        ],
        1,
    );
    state.bind_channel(&original, 1).unwrap();
    let refresh = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::Refresh,
        vec![Attribute::Lifetime(DEFAULT_ALLOCATION_LIFETIME as u32)],
        599,
    );
    state.refresh(&refresh, 599).unwrap();
    let expired = 1 + CHANNEL_LIFETIME;
    let different = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::ChannelBind,
        vec![
            Attribute::ChannelNumber(0x4000),
            Attribute::XorPeerAddress(peer(2, 5000)),
        ],
        expired,
    );
    assert!(matches!(
        state.bind_channel(&different, expired),
        Err(StateError::ChannelQuarantined)
    ));
    state.bind_channel(&original, expired).unwrap();
}

#[test]
fn channel_bind_cannot_bypass_permission_quota() {
    let mut limited = quota();
    limited.max_permissions_per_allocation = 1;
    let mut state = RelayState::new(limited, PeerPolicy::default()).unwrap();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let permission = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::CreatePermission,
        vec![Attribute::XorPeerAddress(peer(1, 5000))],
        1,
    );
    state.create_permissions(&permission, 1).unwrap();
    let binding = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::ChannelBind,
        vec![
            Attribute::ChannelNumber(0x4000),
            Attribute::XorPeerAddress(peer(2, 5000)),
        ],
        2,
    );
    assert!(matches!(
        state.bind_channel(&binding, 2),
        Err(StateError::PermissionQuota)
    ));
}

#[test]
fn family_and_loopback_policy_fail_closed_unless_lab_opted_in() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    for invalid in ["[2001:db8::1]:5000", "127.0.0.1:5000", "224.0.0.1:5000"] {
        let request = authenticate(
            &mut state,
            tuple(5000),
            b"alice",
            b"nonce-1",
            Method::CreatePermission,
            vec![Attribute::XorPeerAddress(invalid.parse().unwrap())],
            1,
        );
        assert!(matches!(
            state.create_permissions(&request, 1),
            Err(StateError::InvalidPeer)
        ));
    }
}

#[test]
fn send_channel_and_peer_routes_require_live_permission_and_exact_binding() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let binding = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::ChannelBind,
        vec![
            Attribute::ChannelNumber(0x4000),
            Attribute::XorPeerAddress(peer(1, 5000)),
        ],
        1,
    );
    state.bind_channel(&binding, 1).unwrap();
    assert_eq!(
        state
            .authorize_channel_data(&tuple(5000), ChannelNumber(0x4000), 1, 2)
            .unwrap(),
        peer(1, 5000)
    );
    assert_eq!(
        state
            .route_peer_datagram(&tuple(5000), peer(1, 5000), 1, 2)
            .unwrap(),
        DeliveryRoute::ChannelData(ChannelNumber(0x4000))
    );
}

#[test]
fn packet_and_byte_quota_rejections_do_not_overflow_or_wrap() {
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let permission = authenticate(
        &mut state,
        tuple(5000),
        b"alice",
        b"nonce-1",
        Method::CreatePermission,
        vec![Attribute::XorPeerAddress(peer(1, 5000))],
        1,
    );
    state.create_permissions(&permission, 1).unwrap();
    assert!(state
        .authorize_send(&tuple(5000), peer(1, 5000), 16, 2)
        .is_ok());
    assert!(matches!(
        state.authorize_send(&tuple(5000), peer(1, 5000), 1, 3),
        Err(StateError::TrafficQuota)
    ));
    assert_eq!(state.counters(&tuple(5000), 3).unwrap().payload_bytes, 16);
}

#[test]
fn checked_deadlines_and_cleanup_remove_every_child_state() {
    let mut state = state();
    assert!(matches!(
        state.create(
            tuple(5000),
            credentials(b"alice"),
            relay(55000),
            u64::MAX,
            None
        ),
        Err(StateError::TimeOverflow)
    ));
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    state.cleanup(DEFAULT_ALLOCATION_LIFETIME);
    assert_eq!(state.allocation_count(), 0);
}

#[test]
fn credentials_debug_is_redacted() {
    let rendered = format!("{:?}", credentials(b"alice"));
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("alice"));
    assert!(!rendered.contains("nonce-1"));
    let request = signed_request(
        b"alice",
        b"turn.example",
        b"nonce-1",
        Method::Refresh,
        vec![],
    );
    let mut state = state();
    state
        .create(tuple(5000), credentials(b"alice"), relay(55000), 0, None)
        .unwrap();
    let verified = state
        .authenticate_request(&tuple(5000), &request, 1)
        .unwrap();
    let request_rendered = format!("{verified:?}");
    assert!(request_rendered.contains("<redacted>"));
    assert!(!request_rendered.contains("nonce-1"));
}
