use std::collections::HashSet;

use tokio::time::{sleep, timeout};

use super::*;
use crate::wg_packet_obfuscation::{decode_packet, encode_packet};

fn test_settings(magic_byte: Option<u8>, idle_timeout: Duration) -> WgPacketObfuscation {
    let _ = idle_timeout;
    WgPacketObfuscation::new(b"test-obfuscation-key".to_vec(), magic_byte).unwrap()
}

#[test]
fn drop_notice_is_rate_limited() {
    let mut notice = RateLimitedDropNotice::new(Duration::from_secs(30));
    let now = Instant::now();

    assert_eq!(notice.record(now), Some(0));
    assert_eq!(notice.record(now + Duration::from_secs(1)), None);
    assert_eq!(notice.record(now + Duration::from_secs(31)), Some(1));
}

#[test]
fn probe_detector_prunes_expired_states_before_inserting_new_ip() {
    let config = ProbeBlockConfig {
        threshold: 10,
        window: Duration::from_secs(1),
        block_duration: Duration::from_secs(1),
    };
    let detector = ProbeDetector::with_max_states(Some(config), 1);
    let first_ip = IpAddr::from([192, 0, 2, 1]);
    let second_ip = IpAddr::from([192, 0, 2, 2]);
    let now = Instant::now();

    assert!(!detector.record_decode_error(first_ip, now));
    assert_eq!(detector.states.len(), 1);

    assert!(!detector.record_decode_error(second_ip, now + Duration::from_secs(2)));

    assert!(!detector.states.contains_key(&first_ip));
    assert!(detector.states.contains_key(&second_ip));
}

#[test]
fn probe_detector_does_not_evict_active_state_at_budget() {
    let config = ProbeBlockConfig {
        threshold: 10,
        window: Duration::from_secs(10),
        block_duration: Duration::from_secs(10),
    };
    let detector = ProbeDetector::with_max_states(Some(config), 1);
    let first_ip = IpAddr::from([192, 0, 2, 1]);
    let second_ip = IpAddr::from([192, 0, 2, 2]);
    let now = Instant::now();

    assert!(!detector.record_decode_error(first_ip, now));
    assert!(!detector.record_decode_error(second_ip, now + Duration::from_secs(1)));

    assert!(detector.states.contains_key(&first_ip));
    assert!(!detector.states.contains_key(&second_ip));
}

#[test]
fn probe_block_duration_config_rejects_zero_values() {
    assert_eq!(
        positive_duration_or_default(None, Duration::from_secs(7)),
        Some(Duration::from_secs(7))
    );
    assert_eq!(
        positive_duration_or_default(Some(5), Duration::from_secs(7)),
        Some(Duration::from_secs(5))
    );
    assert_eq!(
        positive_duration_or_default(Some(0), Duration::from_secs(7)),
        None
    );
}

#[tokio::test]
async fn relay_forwards_plaintext_to_internal_listener_and_replies() {
    let shutdown = CancellationToken::new();
    let obfuscation = test_settings(Some(0xAA), Duration::from_secs(1));
    let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let internal_addr = internal_socket.local_addr().unwrap();
    let (public_addr, relay_task) = spawn_with_addrs(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        internal_addr,
        obfuscation.clone(),
        Duration::from_secs(1),
        shutdown.clone(),
    )
    .await
    .unwrap();

    let upstream = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"handshake-init");
        internal_socket
            .send_to(b"handshake-reply", relay_peer)
            .await
            .unwrap();
    });

    let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let encoded = encode_packet(b"handshake-init", &obfuscation).unwrap();
    client.send_to(&encoded, public_addr).await.unwrap();

    let mut buf = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let decoded = decode_packet(&buf[..len], &obfuscation).unwrap();
    assert_eq!(decoded, b"handshake-reply");

    upstream.await.unwrap();
    shutdown.cancel();
    relay_task.await.unwrap();
}

#[tokio::test]
async fn relay_uses_distinct_upstream_ports_per_client() {
    let shutdown = CancellationToken::new();
    let obfuscation = test_settings(Some(0xAA), Duration::from_secs(1));
    let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let internal_addr = internal_socket.local_addr().unwrap();
    let (public_addr, relay_task) = spawn_with_addrs(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        internal_addr,
        obfuscation.clone(),
        Duration::from_secs(1),
        shutdown.clone(),
    )
    .await
    .unwrap();

    let upstream = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut peers = Vec::new();
        for _ in 0..2 {
            let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
            peers.push(relay_peer);
            internal_socket
                .send_to(&buf[..len], relay_peer)
                .await
                .unwrap();
        }
        peers
    });

    let client_one = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let client_two = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();

    client_one
        .send_to(&encode_packet(b"peer-one", &obfuscation).unwrap(), public_addr)
        .await
        .unwrap();
    client_two
        .send_to(&encode_packet(b"peer-two", &obfuscation).unwrap(), public_addr)
        .await
        .unwrap();

    let mut buf_one = [0u8; 2048];
    let mut buf_two = [0u8; 2048];
    let (len_one, _) = timeout(Duration::from_secs(1), client_one.recv_from(&mut buf_one))
        .await
        .unwrap()
        .unwrap();
    let (len_two, _) = timeout(Duration::from_secs(1), client_two.recv_from(&mut buf_two))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_packet(&buf_one[..len_one], &obfuscation).unwrap(),
        b"peer-one"
    );
    assert_eq!(
        decode_packet(&buf_two[..len_two], &obfuscation).unwrap(),
        b"peer-two"
    );

    let peers = upstream.await.unwrap();
    let unique_peers: HashSet<_> = peers.into_iter().map(|peer| peer.port()).collect();
    assert_eq!(unique_peers.len(), 2);

    shutdown.cancel();
    relay_task.await.unwrap();
}

#[tokio::test]
async fn relay_drops_raw_direct_packets_without_magic_byte() {
    let shutdown = CancellationToken::new();
    let obfuscation = test_settings(Some(0xAA), Duration::from_secs(1));
    let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let internal_addr = internal_socket.local_addr().unwrap();
    let (public_addr, relay_task) = spawn_with_addrs(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        internal_addr,
        obfuscation,
        Duration::from_secs(1),
        shutdown.clone(),
    )
    .await
    .unwrap();

    let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    client
        .send_to(b"missing-magic-byte", public_addr)
        .await
        .unwrap();

    let mut internal_buf = [0u8; 2048];
    let mut client_buf = [0u8; 2048];
    assert!(timeout(
        Duration::from_millis(250),
        internal_socket.recv_from(&mut internal_buf)
    )
    .await
    .is_err());
    assert!(timeout(
        Duration::from_millis(250),
        client.recv_from(&mut client_buf)
    )
    .await
    .is_err());

    shutdown.cancel();
    relay_task.await.unwrap();
}

#[tokio::test]
async fn relay_evicts_idle_sessions_and_recreates_upstream_socket() {
    let shutdown = CancellationToken::new();
    let obfuscation = test_settings(Some(0xAA), Duration::from_millis(100));
    let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let internal_addr = internal_socket.local_addr().unwrap();
    let (public_addr, relay_task) = spawn_with_addrs(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        internal_addr,
        obfuscation.clone(),
        Duration::from_millis(100),
        shutdown.clone(),
    )
    .await
    .unwrap();

    let upstream = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut peers = Vec::new();
        for _ in 0..2 {
            let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
            peers.push(relay_peer);
            internal_socket
                .send_to(&buf[..len], relay_peer)
                .await
                .unwrap();
        }
        peers
    });

    let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    client
        .send_to(&encode_packet(b"first-packet", &obfuscation).unwrap(), public_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 2048];
    timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    sleep(Duration::from_millis(250)).await;

    client
        .send_to(&encode_packet(b"second-packet", &obfuscation).unwrap(), public_addr)
        .await
        .unwrap();
    timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let peers = upstream.await.unwrap();
    assert_eq!(peers.len(), 2);
    assert_ne!(peers[0].port(), peers[1].port());

    shutdown.cancel();
    relay_task.await.unwrap();
}
