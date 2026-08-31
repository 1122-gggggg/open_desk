use latencydesk_turn_relayd::{run_client, serve, ClientConfig, ServerConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_allocate_permission_channel_and_bidirectional_relay() {
    let control = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = control.local_addr().unwrap();
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_address = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        for _ in 0..2 {
            let (length, source) = echo.recv_from(&mut buffer).await.unwrap();
            echo.send_to(&buffer[..length], source).await.unwrap();
        }
    });

    let server_config = ServerConfig::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        b"turn.example".to_vec(),
        b"alice".to_vec(),
        b"a-high-entropy-test-password".to_vec(),
        4,
        Duration::from_secs(5),
        true,
        1,
    )
    .unwrap();
    let server_task = tokio::spawn(serve(control, server_config));
    let report = run_client(ClientConfig {
        server: server_address,
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        username: b"alice".to_vec(),
        password: b"a-high-entropy-test-password".to_vec(),
        peer: peer_address,
        timeout: Duration::from_secs(3),
        channel: 0x4000,
        send_payload: b"opaque-send-payload".to_vec(),
        channel_payload: b"opaque-channel-payload".to_vec(),
    })
    .await
    .unwrap();
    assert!(report.challenge_authenticated);
    assert!(report.send_round_trip);
    assert!(report.channel_round_trip);
    assert!(report.deallocated);
    assert_ne!(report.relayed_address.port(), 0);

    echo_task.await.unwrap();
    let server_report = server_task.await.unwrap().unwrap();
    assert_eq!(server_report.allocations_created, 1);
    assert_eq!(server_report.deallocations, 1);
    assert_eq!(server_report.client_to_peer_datagrams, 2);
    assert_eq!(server_report.peer_to_client_datagrams, 2);
    assert!(server_report.clean_shutdown);
}
