use latencydesk_turn_relay::wire::{self, Attribute, Class, Header, Message, Method};
use latencydesk_turn_relayd::{serve, ServerConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

const USER: &[u8] = b"alice";
const REALM: &[u8] = b"turn.example";
const PASSWORD: &[u8] = b"alice-password-with-entropy";

fn server_config(total: Duration, exit_after: usize) -> ServerConfig {
    ServerConfig::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        REALM.to_vec(),
        USER.to_vec(),
        PASSWORD.to_vec(),
        4,
        total,
        true,
        exit_after,
    )
    .unwrap()
}

fn request_message(method: Method, tx: u8, attributes: Vec<Attribute>) -> Message {
    Message {
        header: Header {
            class: Class::Request,
            method,
            transaction_id: [tx; 12],
        },
        attributes,
    }
}

async fn transact(socket: &UdpSocket, server: SocketAddr, encoded: &[u8]) -> Vec<u8> {
    socket.send_to(encoded, server).await.unwrap();
    let mut buffer = [0_u8; 4096];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(source, server);
    buffer[..length].to_vec()
}

async fn challenge(socket: &UdpSocket, server: SocketAddr, tx: u8) -> (Vec<u8>, Vec<u8>) {
    let encoded = wire::encode(&request_message(
        Method::Allocate,
        tx,
        vec![Attribute::RequestedTransport(17)],
    ))
    .unwrap();
    let response = wire::decode(&transact(socket, server, &encoded).await).unwrap();
    assert_eq!(error_code(&response), Some(401));
    let realm = bytes(&response, true).unwrap().to_vec();
    let nonce = bytes(&response, false).unwrap().to_vec();
    (realm, nonce)
}

fn signed(
    method: Method,
    tx: u8,
    realm: &[u8],
    nonce: &[u8],
    attributes: Vec<Attribute>,
) -> Vec<u8> {
    signed_with_password(method, tx, realm, nonce, attributes, PASSWORD)
}

fn signed_with_password(
    method: Method,
    tx: u8,
    realm: &[u8],
    nonce: &[u8],
    mut attributes: Vec<Attribute>,
    password: &[u8],
) -> Vec<u8> {
    let mut credentials = vec![
        Attribute::Username(USER.to_vec()),
        Attribute::Realm(realm.to_vec()),
        Attribute::Nonce(nonce.to_vec()),
    ];
    credentials.append(&mut attributes);
    let key = wire::derive_long_term_key_sha256(USER, realm, password);
    wire::encode_with_integrity(&request_message(method, tx, credentials), key.as_ref()).unwrap()
}

fn error_code(message: &Message) -> Option<u16> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::ErrorCode { code, .. } => Some(*code),
            _ => None,
        })
}

fn bytes(message: &Message, realm: bool) -> Option<&[u8]> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match (realm, attribute) {
            (true, Attribute::Realm(value)) | (false, Attribute::Nonce(value)) => {
                Some(value.as_slice())
            }
            _ => None,
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_tcp_request_is_442_and_stale_nonce_is_438() {
    let control = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = control.local_addr().unwrap();
    let server_task = tokio::spawn(serve(control, server_config(Duration::from_secs(3), 1)));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (realm, first_nonce) = challenge(&client, server, 1).await;
    let tcp = signed(
        Method::Allocate,
        2,
        &realm,
        &first_nonce,
        vec![Attribute::RequestedTransport(6)],
    );
    let key = wire::derive_long_term_key_sha256(USER, &realm, PASSWORD);
    let tcp_response = transact(&client, server, &tcp).await;
    let tcp_verified = wire::verify_integrity(&tcp_response, key.as_ref()).unwrap();
    assert_eq!(error_code(tcp_verified.message()), Some(442));

    let other_source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cross_source = signed(
        Method::Allocate,
        5,
        &realm,
        &first_nonce,
        vec![Attribute::RequestedTransport(17)],
    );
    let cross_response =
        wire::decode(&transact(&other_source, server, &cross_source).await).unwrap();
    assert_eq!(error_code(&cross_response), Some(438));

    let (_, second_nonce) = challenge(&client, server, 3).await;
    assert_ne!(first_nonce, second_nonce);
    let stale = signed(
        Method::Allocate,
        4,
        &realm,
        b"old-stale-nonce",
        vec![Attribute::RequestedTransport(17)],
    );
    let stale_response = transact(&client, server, &stale).await;
    let stale_response = wire::verify_integrity(&stale_response, key.as_ref()).unwrap();
    assert_eq!(error_code(stale_response.message()), Some(438));
    let current_nonce = bytes(stale_response.message(), false).unwrap().to_vec();
    let replay = signed(
        Method::Allocate,
        7,
        &realm,
        b"old-stale-nonce",
        vec![Attribute::RequestedTransport(17)],
    );
    let replay = transact(&client, server, &replay).await;
    let replay = wire::verify_integrity(&replay, key.as_ref()).unwrap();
    assert_eq!(error_code(replay.message()), Some(438));
    assert_eq!(bytes(replay.message(), false).unwrap(), current_nonce);
    let allocate = signed(
        Method::Allocate,
        8,
        &realm,
        &current_nonce,
        vec![Attribute::RequestedTransport(17)],
    );
    let allocate =
        wire::verify_integrity(&transact(&client, server, &allocate).await, key.as_ref()).unwrap();
    assert_eq!(allocate.message().header.class, Class::Success);
    let delete = signed(
        Method::Refresh,
        9,
        &realm,
        &current_nonce,
        vec![Attribute::Lifetime(0)],
    );
    let delete =
        wire::verify_integrity(&transact(&client, server, &delete).await, key.as_ref()).unwrap();
    assert!(delete
        .message()
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, Attribute::Lifetime(0))));
    let report = server_task.await.unwrap().unwrap();
    assert_eq!(report.allocations_created, 1);
    assert_eq!(report.deallocations, 1);
}

fn stale_nonce_from_response(
    encoded: &[u8],
    key: &[u8],
    method: Method,
    transaction_id: [u8; 12],
) -> Vec<u8> {
    let verified = wire::verify_integrity(encoded, key).unwrap();
    assert_eq!(verified.message().header.class, Class::Error);
    assert_eq!(verified.message().header.method, method);
    assert_eq!(verified.message().header.transaction_id, transaction_id);
    assert_eq!(error_code(verified.message()), Some(438));
    bytes(verified.message(), false).unwrap().to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_allocation_replies_idempotent_signed_438_for_every_authenticated_method() {
    let control = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = control.local_addr().unwrap();
    let server_task = tokio::spawn(serve(control, server_config(Duration::from_secs(5), 1)));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_address = peer.local_addr().unwrap();
    let (realm, mut nonce) = challenge(&client, server, 21).await;
    let key = wire::derive_long_term_key_sha256(USER, &realm, PASSWORD);

    let allocate = signed(
        Method::Allocate,
        22,
        &realm,
        &nonce,
        vec![Attribute::RequestedTransport(17)],
    );
    let allocation =
        wire::verify_integrity(&transact(&client, server, &allocate).await, key.as_ref()).unwrap();
    assert_eq!(allocation.message().header.class, Class::Success);

    let permission_attributes = vec![Attribute::XorPeerAddress(peer_address)];
    let stale_permission = signed(
        Method::CreatePermission,
        23,
        &realm,
        b"stale-permission",
        permission_attributes.clone(),
    );
    let rotated = transact(&client, server, &stale_permission).await;
    nonce = stale_nonce_from_response(&rotated, key.as_ref(), Method::CreatePermission, [23; 12]);
    let replay = signed(
        Method::CreatePermission,
        30,
        &realm,
        b"stale-permission",
        vec![Attribute::XorPeerAddress(peer_address)],
    );
    let replay = transact(&client, server, &replay).await;
    let replay_nonce =
        stale_nonce_from_response(&replay, key.as_ref(), Method::CreatePermission, [30; 12]);
    assert_eq!(replay_nonce, nonce);
    let permission = signed(
        Method::CreatePermission,
        24,
        &realm,
        &nonce,
        permission_attributes,
    );
    let permission =
        wire::verify_integrity(&transact(&client, server, &permission).await, key.as_ref())
            .unwrap();
    assert_eq!(permission.message().header.class, Class::Success);

    let stale_channel = signed(
        Method::ChannelBind,
        25,
        &realm,
        b"stale-channel",
        vec![
            Attribute::ChannelNumber(0x4000),
            Attribute::XorPeerAddress(peer_address),
        ],
    );
    let rotated = transact(&client, server, &stale_channel).await;
    nonce = stale_nonce_from_response(&rotated, key.as_ref(), Method::ChannelBind, [25; 12]);
    let channel = signed(
        Method::ChannelBind,
        26,
        &realm,
        &nonce,
        vec![
            Attribute::ChannelNumber(0x4000),
            Attribute::XorPeerAddress(peer_address),
        ],
    );
    let channel =
        wire::verify_integrity(&transact(&client, server, &channel).await, key.as_ref()).unwrap();
    assert_eq!(channel.message().header.class, Class::Success);

    let stale_refresh = signed(
        Method::Refresh,
        27,
        &realm,
        b"stale-refresh",
        vec![Attribute::Lifetime(1)],
    );
    let rotated = transact(&client, server, &stale_refresh).await;
    nonce = stale_nonce_from_response(&rotated, key.as_ref(), Method::Refresh, [27; 12]);
    let refresh = signed(
        Method::Refresh,
        28,
        &realm,
        &nonce,
        vec![Attribute::Lifetime(1)],
    );
    let refresh =
        wire::verify_integrity(&transact(&client, server, &refresh).await, key.as_ref()).unwrap();
    assert_eq!(refresh.message().header.class, Class::Success);

    let delete = signed(
        Method::Refresh,
        29,
        &realm,
        &nonce,
        vec![Attribute::Lifetime(0)],
    );
    let deleted =
        wire::verify_integrity(&transact(&client, server, &delete).await, key.as_ref()).unwrap();
    assert!(deleted
        .message()
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, Attribute::Lifetime(0))));
    let report = server_task.await.unwrap().unwrap();
    assert_eq!(report.allocations_created, 1);
    assert_eq!(report.deallocations, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allocate_retransmission_is_idempotent_and_unpermitted_send_is_dropped() {
    let control = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = control.local_addr().unwrap();
    let server_task = tokio::spawn(serve(control, server_config(Duration::from_secs(3), 1)));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_address = peer.local_addr().unwrap();
    let (realm, nonce) = challenge(&client, server, 11).await;
    let allocate = signed(
        Method::Allocate,
        12,
        &realm,
        &nonce,
        vec![Attribute::RequestedTransport(17)],
    );
    let first = transact(&client, server, &allocate).await;
    let second = transact(&client, server, &allocate).await;
    assert_eq!(first, second);

    let send = wire::encode(&Message {
        header: Header {
            class: Class::Indication,
            method: Method::Send,
            transaction_id: [13; 12],
        },
        attributes: vec![
            Attribute::XorPeerAddress(peer_address),
            Attribute::Data(b"must-be-dropped".to_vec()),
        ],
    })
    .unwrap();
    client.send_to(&send, server).await.unwrap();
    let mut buffer = [0_u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), peer.recv_from(&mut buffer))
            .await
            .is_err()
    );

    let delete = signed(
        Method::Refresh,
        14,
        &realm,
        &nonce,
        vec![Attribute::Lifetime(0)],
    );
    let key = wire::derive_long_term_key_sha256(USER, &realm, PASSWORD);
    let deleted = transact(&client, server, &delete).await;
    let verified = wire::verify_integrity(&deleted, key.as_ref()).unwrap();
    assert!(verified
        .message()
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, Attribute::Lifetime(0))));
    let report = server_task.await.unwrap().unwrap();
    assert_eq!(report.allocations_created, 1);
    assert_eq!(report.deallocations, 1);
    assert_eq!(report.client_to_peer_datagrams, 0);
}
