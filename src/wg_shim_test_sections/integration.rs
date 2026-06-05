    #[tokio::test]
    async fn shim_rate_limits_upstream_sends_per_session() {
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
        config.rate_limit = RateLimitConfig::new(1, 1);
        let (listen_addr, shim_task) = spawn_with_config(config, shutdown.clone()).await.unwrap();

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"first", listen_addr).await.unwrap();
        client.send_to(b"second", listen_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), server_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap(),
            b"first"
        );
        assert!(timeout(
            Duration::from_millis(200),
            server_socket.recv_from(&mut buf)
        )
        .await
        .is_err());

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_drops_magic_byte_mismatch_replies() {
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
            assert_eq!(
                decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap(),
                b"first"
            );
            server_socket
                .send_to(b"reply-without-magic", shim_peer)
                .await
                .unwrap();

            let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(
                decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap(),
                b"second"
            );
            server_socket
                .send_to(&encode_packet(b"second-reply", &obfuscation), shim_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"first", listen_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(250), client.recv_from(&mut buf))
                .await
                .is_err()
        );

        client.send_to(b"second", listen_addr).await.unwrap();
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"second-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_creates_concurrent_sessions_for_distinct_clients() {
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

        let server_obfuscation = obfuscation.clone();
        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..50 {
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &server_obfuscation).unwrap();
                let mut response = b"reply-".to_vec();
                response.extend_from_slice(&decoded);
                server_socket
                    .send_to(&encode_packet(&response, &server_obfuscation), shim_peer)
                    .await
                    .unwrap();
            }
            peers
        });

        let mut clients = Vec::new();
        for index in 0..50 {
            let payload = format!("client-{index}").into_bytes();
            clients.push(tokio::spawn(async move {
                let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap();
                client.send_to(&payload, listen_addr).await.unwrap();
                let mut buf = [0u8; 2048];
                let (len, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                let mut expected = b"reply-".to_vec();
                expected.extend_from_slice(&payload);
                assert_eq!(&buf[..len], expected.as_slice());
            }));
        }

        for client in clients {
            client.await.unwrap();
        }
        let peers = upstream.await.unwrap();
        let unique_ports = peers
            .into_iter()
            .map(|peer| peer.port())
            .collect::<HashSet<_>>();
        assert_eq!(unique_ports.len(), 50);

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_shutdown_mid_flight_exits_cleanly() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation,
            Duration::from_secs(30),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let (received_tx, received_rx) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let _ = server_socket.recv_from(&mut buf).await.unwrap();
            let _ = received_tx.send(());
            sleep(Duration::from_millis(100)).await;
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"in-flight", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), received_rx)
            .await
            .unwrap()
            .unwrap();
        shutdown.cancel();

        timeout(Duration::from_secs(2), shim_task)
            .await
            .unwrap()
            .unwrap();
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn shim_forwards_ipv6_loopback_packets() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            "[::1]:0".parse::<SocketAddr>().unwrap(),
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
            assert_eq!(
                decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap(),
                b"ipv6"
            );
            server_socket
                .send_to(&encode_packet(b"ipv6-reply", &obfuscation), shim_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        client.send_to(b"ipv6", listen_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"ipv6-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_and_relay_round_trip_with_aead_framing() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA))
            .with_encryption_mode(EncryptionMode::Aead)
            .with_padding(PacketPadding::PowerOfTwo)
            .with_magic_position(MagicPositionMode::Randomized);

        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_server_addr, relay_task) = wg_relay::spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let (shim_listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            public_server_addr,
            obfuscation,
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"aead-handshake");
            internal_socket
                .send_to(b"aead-reply", relay_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"aead-handshake", shim_listen_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"aead-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_and_server_relay_round_trip_end_to_end() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));

        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_server_addr, relay_task) = wg_relay::spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let (shim_listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            public_server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"end-to-end-handshake");
            internal_socket
                .send_to(b"end-to-end-reply", relay_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"end-to-end-handshake", shim_listen_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"end-to-end-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
        relay_task.await.unwrap();
    }
