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
    let server_task = tokio::spawn(serve(control, server_config(Duration::from_millis(500), 0)));
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
        &first_nonce,
        vec![Attribute::RequestedTransport(17)],
    );
    let stale_response = wire::decode(&transact(&client, server, &stale).await).unwrap();
    assert_eq!(error_code(&stale_response), Some(438));
    let current_nonce = bytes(&stale_response, false).unwrap().to_vec();
    let wrong_password = signed_with_password(
        Method::Allocate,
        6,
        &realm,
        &current_nonce,
        vec![Attribute::RequestedTransport(17)],
        b"definitely-the-wrong-password",
    );
    let wrong_response = wire::decode(&transact(&client, server, &wrong_password).await).unwrap();
    assert_eq!(error_code(&wrong_response), Some(401));
    let report = server_task.await.unwrap().unwrap();
    assert_eq!(report.allocations_created, 0);
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
