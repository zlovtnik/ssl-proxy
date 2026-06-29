    use std::collections::HashSet;

    use proptest::prelude::*;
    use tokio::{
        sync::oneshot,
        time::{sleep, timeout},
    };

    use super::*;
    use crate::{
        wg_packet_obfuscation::{
            decode_packet as decode_obfuscated_packet, encode_packet, EncryptionMode,
            MagicPositionMode, PacketPadding,
        },
        wg_relay,
    };

    fn test_obfuscation(magic_byte: Option<u8>) -> WgPacketObfuscation {
        WgPacketObfuscation::new(b"test-obfuscation-key".to_vec(), magic_byte)
    }

    fn test_shim_config() -> Arc<WgObfsShimConfig> {
        Arc::new(WgObfsShimConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([127, 0, 0, 1], 1)),
            test_obfuscation(None),
            Duration::from_secs(30),
        ))
    }

    fn test_session_for_limit(id: u64, last_activity_millis: u64) -> Arc<ShimSession> {
        let (upstream_tx, _upstream_rx) = mpsc::channel(1);
        Arc::new(ShimSession::new(
            id,
            test_shim_config(),
            upstream_tx,
            0,
            last_activity_millis,
            info_span!("test_session", session_id = id),
        ))
    }

    fn test_shim_config_with_queue_capacity(capacity: usize) -> Arc<WgObfsShimConfig> {
        let mut config = WgObfsShimConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([127, 0, 0, 1], 1)),
            test_obfuscation(None),
            Duration::from_secs(30),
        );
        config.send_queue_capacity = capacity;
        Arc::new(config)
    }

    fn test_session_with_queue_capacity(capacity: usize) -> Arc<ShimSession> {
        let (upstream_tx, _upstream_rx) = mpsc::channel(capacity.max(1));
        Arc::new(ShimSession::new(
            1,
            test_shim_config_with_queue_capacity(capacity),
            upstream_tx,
            40000,
            10,
            info_span!("test_session", client_addr = "127.0.0.1:1"),
        ))
    }

    fn test_queued_packet(
        pool: &Arc<UdpBufferPool>,
        queued_at_millis: u64,
    ) -> QueuedUpstreamPacket {
        let mut lease = pool.lease().expect("lease is available");
        lease[..4].copy_from_slice(b"ping");
        QueuedUpstreamPacket {
            lease,
            len: 4,
            queued_at_millis,
            is_chaff: false,
        }
    }

    proptest! {
        #[test]
        fn session_table_never_exceeds_max_sessions(
            max_sessions in 1usize..32,
            arrivals in prop::collection::vec(any::<u16>(), 1..128),
        ) {
            let sessions = DashMap::new();
            let metrics = ShimMetrics::default();

            for (index, port) in arrivals.into_iter().enumerate() {
                let client_addr = SocketAddr::from(([127, 0, 0, 1], port.max(1)));
                if !sessions.contains_key(&client_addr) {
                    enforce_session_limit(&sessions, Some(max_sessions), &metrics, Some(client_addr)).unwrap();
                    let session = test_session_for_limit(index as u64 + 1, index as u64);
                    sessions.insert(client_addr, session);
                    metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
                }

                prop_assert!(sessions.len() <= max_sessions);
            }
        }
    }

    #[tokio::test]
    async fn session_activity_uses_atomic_epoch_millis() {
        let (upstream_tx, _upstream_rx) = mpsc::channel(1);
        let session = ShimSession::new(
            1,
            test_shim_config(),
            upstream_tx,
            40000,
            10,
            info_span!("test_session", client_addr = "127.0.0.1:1"),
        );

        assert_eq!(session.idle_for(15), Duration::from_millis(5));
        session.touch(100);
        assert_eq!(session.idle_for(125), Duration::from_millis(25));
    }

    #[test]
    fn token_bucket_limits_and_refills() {
        let mut bucket = TokenBucket::new(
            RateLimitConfig {
                packets_per_sec: 2,
                burst_packets: 2,
            },
            0,
        );

        assert!(bucket.try_take(0));
        assert!(bucket.try_take(0));
        assert!(!bucket.try_take(0));
        assert!(bucket.try_take(500));
        assert!(!bucket.try_take(500));
        assert!(bucket.try_take(1_000));
    }

    #[test]
    fn buffer_pool_returns_lease_on_drop() {
        let pool = Arc::new(UdpBufferPool::new(1, 256));
        let lease = pool.lease();
        assert!(lease.is_some());
        assert_eq!(lease.as_ref().unwrap().len(), 256);
        assert!(pool.lease().is_none());
        drop(lease);
        assert!(pool.lease().is_some());
    }

    #[test]
    fn queued_upstream_packet_owns_pooled_buffer() {
        let pool = Arc::new(UdpBufferPool::new(1, 256));
        let mut lease = pool.lease().expect("lease is available");
        lease[..4].copy_from_slice(b"ping");
        assert_eq!(pool.available(), 0);

        let packet = QueuedUpstreamPacket {
            lease,
            len: 4,
            queued_at_millis: 10,
            is_chaff: false,
        };
        assert_eq!(packet.bytes(), b"ping");
        drop(packet);

        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn buffer_pool_wait_counter_records_elapsed_millis_when_pool_empty() {
        let pool = Arc::new(UdpBufferPool::new(1, 256));
        let lease = pool.lease();
        let metrics = ShimMetrics::default();
        let wait_started = Instant::now() - Duration::from_millis(3);

        assert!(lease.is_some());
        assert!(pool.lease().is_none());
        record_buffer_pool_wait_since(&metrics, wait_started);

        assert!(
            metrics
                .buffer_pool_wait_millis_total
                .load(Ordering::Relaxed)
            >= 3
        );
    }

    #[test]
    fn send_queue_accounting_tracks_full_drops_and_wait() {
        let metrics = ShimMetrics::default();
        let pool = Arc::new(UdpBufferPool::new(2, 256));
        let session = test_session_with_queue_capacity(1);
        let (tx, mut rx) = mpsc::channel(1);
        metrics.record_send_queue_capacity_add(session.send_queue_capacity());

        let reservation = session.reserve_send_queue_slot(&metrics);
        tx.try_send(test_queued_packet(&pool, 10)).unwrap();
        session.record_send_queue_accepted(&metrics, reservation);

        assert_eq!(session.send_queue_depth(), 1);
        assert_eq!(metrics.send_queue_depth(), 1);
        assert_eq!(metrics.send_queue_capacity(), 1);

        let _reservation = session.reserve_send_queue_slot(&metrics);
        match tx.try_send(test_queued_packet(&pool, 11)) {
            Err(mpsc::error::TrySendError::Full(_packet)) => {
                session.release_send_queue_slot(&metrics);
                session.record_send_queue_full_drop(&metrics);
            }
            _ => panic!("expected full queue"),
        }

        assert_eq!(session.send_queue_depth(), 1);
        assert_eq!(metrics.send_queue_depth(), 1);
        assert_eq!(metrics.send_queue_drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .send_queue_max_session_utilization_percent
                .load(Ordering::Relaxed),
            100
        );

        let packet = rx.try_recv().expect("packet is queued");
        session.record_send_queue_dequeued(&metrics, packet.queued_at_millis, 15);
        drop(packet);

        assert_eq!(session.send_queue_depth(), 0);
        assert_eq!(metrics.send_queue_depth(), 0);
        assert_eq!(metrics.send_queue_dequeued.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .send_queue_wait_millis_total
                .load(Ordering::Relaxed),
            5
        );
    }

    #[test]
    fn queue_health_snapshot_keeps_lifetime_counters_informational() {
        let metrics = Arc::new(ShimMetrics::default());
        let sessions = Arc::new(DashMap::new());
        let session = test_session_with_queue_capacity(2);
        let client_addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        sessions.insert(client_addr, session.clone());
        metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
        metrics.record_send_queue_capacity_add(session.send_queue_capacity());

        let reservation = session.reserve_send_queue_slot(&metrics);
        session.record_send_queue_accepted(&metrics, reservation);
        session.record_send_queue_full_drop(&metrics);
        metrics.buffer_pool_exhausted.fetch_add(1, Ordering::Relaxed);

        let handle = ShimHealthHandle {
            metrics,
            sessions,
        };
        let snapshot = handle.snapshot();

        assert_eq!(snapshot.status, "ok");
        assert_eq!(snapshot.queue.depth, 1);
        assert_eq!(snapshot.queue.capacity, 2);
        assert_eq!(snapshot.queue.utilization_percent, 50);
        assert_eq!(snapshot.queue.drops_total, 1);
        assert_eq!(snapshot.queue.buffer_pool_exhausted_total, 1);
        assert!(snapshot.queue.reasons.is_empty());
    }

    #[test]
    fn queue_health_snapshot_reports_high_current_utilization() {
        let metrics = Arc::new(ShimMetrics::default());
        let sessions = Arc::new(DashMap::new());
        let session = test_session_with_queue_capacity(2);
        sessions.insert(SocketAddr::from(([127, 0, 0, 1], 12345)), session.clone());
        metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
        metrics.record_send_queue_capacity_add(session.send_queue_capacity());

        for _ in 0..2 {
            let reservation = session.reserve_send_queue_slot(&metrics);
            session.record_send_queue_accepted(&metrics, reservation);
        }

        let handle = ShimHealthHandle { metrics, sessions };
        let snapshot = handle.queue_health_snapshot();

        assert_eq!(snapshot.status, "degraded");
        assert_eq!(snapshot.depth, 2);
        assert_eq!(snapshot.capacity, 2);
        assert_eq!(snapshot.max_session_utilization_percent, 100);
        assert!(snapshot
            .reasons
            .contains(&"send_queue_utilization_high"));
    }

    #[test]
    fn rate_limited_log_notice_suppresses_until_interval() {
        let mut notice = RateLimitedLogNotice::new(Duration::from_secs(30));
        let now = Instant::now();

        assert_eq!(notice.record(now), Some(0));
        assert_eq!(notice.record(now + Duration::from_secs(1)), None);
        assert_eq!(notice.record(now + Duration::from_secs(31)), Some(1));
    }

    #[test]
    fn server_rtt_uses_explicit_known_state() {
        let (upstream_tx, _upstream_rx) = mpsc::channel(1);
        let session = ShimSession::new(
            1,
            test_shim_config(),
            upstream_tx,
            40000,
            10,
            info_span!("test_session", client_addr = "127.0.0.1:1"),
        );

        assert_eq!(session.last_server_rtt_millis(), None);
        session.record_server_reply(10);
        assert_eq!(session.last_server_rtt_millis(), None);
        session.record_upstream_send(20);
        session.record_server_reply(20);
        assert_eq!(session.last_server_rtt_millis(), Some(0));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn shim_metrics_render_openmetrics() {
        let metrics = ShimMetrics::default();
        metrics.active_sessions.store(2, Ordering::Relaxed);
        metrics.packets_client_to_server.store(3, Ordering::Relaxed);
        metrics
            .buffer_pool_wait_millis_total
            .store(4, Ordering::Relaxed);
        metrics.send_queue_depth.store(5, Ordering::Relaxed);
        metrics.send_queue_capacity.store(8, Ordering::Relaxed);
        metrics
            .send_queue_depth_high_watermark
            .store(6, Ordering::Relaxed);
        metrics
            .send_queue_max_session_utilization_percent
            .store(75, Ordering::Relaxed);
        metrics.send_queue_dequeued.store(7, Ordering::Relaxed);
        metrics
            .send_queue_wait_millis_total
            .store(9, Ordering::Relaxed);

        let rendered = metrics.render_openmetrics();

        assert!(rendered.contains("wg_obfs_shim_active_sessions 2"));
        assert!(rendered
            .contains("wg_obfs_shim_packets_forwarded_total{direction=\"client_to_server\"} 3"));
        assert!(rendered.contains("wg_obfs_shim_buffer_pool_wait_millis_total 4"));
        assert!(rendered.contains("wg_obfs_shim_send_queue_depth 5"));
        assert!(rendered.contains("wg_obfs_shim_send_queue_capacity 8"));
        assert!(rendered.contains("wg_obfs_shim_send_queue_depth_high_watermark 6"));
        assert!(rendered.contains(
            "wg_obfs_shim_send_queue_max_session_utilization_percent 75"
        ));
        assert!(rendered.contains("wg_obfs_shim_send_queue_dequeued_total 7"));
        assert!(rendered.contains("wg_obfs_shim_send_queue_wait_millis_total 9"));
        assert!(rendered.ends_with("# EOF\n"));
    }

    #[test]
    fn cleanup_interval_uses_override_when_configured() {
        let config = WgObfsShimConfig {
            cleanup_interval: Some(Duration::from_secs(17)),
            ..WgObfsShimConfig::new(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                SocketAddr::from(([127, 0, 0, 1], 1)),
                test_obfuscation(Some(0xAA)),
                Duration::from_secs(300),
            )
        };

        assert_eq!(config.cleanup_interval(), Duration::from_secs(17));
    }

    #[test]
    fn chaff_interval_rejects_excessive_packet_rate() {
        let config = WgObfsShimConfig {
            chaff_pps: MAX_CHAFF_PPS + 1,
            ..WgObfsShimConfig::new(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                SocketAddr::from(([127, 0, 0, 1], 1)),
                test_obfuscation(Some(0xAA)),
                Duration::from_secs(300),
            )
        };

        assert_eq!(config.chaff_interval(), None);
    }

    #[tokio::test]
    async fn shim_obfuscates_plaintext_and_decodes_replies() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
            let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
            assert_eq!(decoded, b"handshake-init");
            let response = encode_packet(b"handshake-reply", &obfuscation);
            server_socket.send_to(&response, shim_peer).await.unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"handshake-init", listen_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"handshake-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_uses_distinct_upstream_ports_per_local_client() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
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
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
                let response = encode_packet(&decoded, &obfuscation);
                server_socket.send_to(&response, shim_peer).await.unwrap();
            }
            peers
        });

        let client_one = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let client_two = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();

        client_one.send_to(b"peer-one", listen_addr).await.unwrap();
        client_two.send_to(b"peer-two", listen_addr).await.unwrap();

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
        assert_eq!(&buf_one[..len_one], b"peer-one");
        assert_eq!(&buf_two[..len_two], b"peer-two");

        let peers = upstream.await.unwrap();
        let unique_peers: HashSet<_> = peers.into_iter().map(|peer| peer.port()).collect();
        assert_eq!(unique_peers.len(), 2);

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_evicts_idle_sessions_and_recreates_upstream_socket() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let mut config = WgObfsShimConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_millis(100),
        );
        config.cleanup_interval = Some(Duration::from_millis(20));
        let (listen_addr, shim_task) = spawn_with_config(config, shutdown.clone()).await.unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..2 {
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
                let response = encode_packet(&decoded, &obfuscation);
                server_socket.send_to(&response, shim_peer).await.unwrap();
            }
            peers
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"first-packet", listen_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        sleep(Duration::from_millis(250)).await;

        client.send_to(b"second-packet", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let peers = upstream.await.unwrap();
        assert_eq!(peers.len(), 2);
        assert_ne!(peers[0].port(), peers[1].port());

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_max_sessions_evicts_oldest_session() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let mut config = WgObfsShimConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(30),
        );
        config.max_sessions = Some(1);
        let (listen_addr, shim_task) = spawn_with_config(config, shutdown.clone()).await.unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..3 {
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
                server_socket
                    .send_to(&encode_packet(&decoded, &obfuscation), shim_peer)
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
        let mut buf = [0u8; 2048];

        client_one.send_to(b"first", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client_one.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        client_two.send_to(b"second", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client_two.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        client_one.send_to(b"third", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client_one.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let peers = upstream.await.unwrap();
        assert_ne!(peers[0].port(), peers[1].port());
        assert_ne!(peers[1].port(), peers[2].port());

        shutdown.cancel();
        shim_task.await.unwrap();
    }
