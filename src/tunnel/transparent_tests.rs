use super::*;
use crate::state::AppState;
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

async fn test_state() -> SharedState {
    test_state_with_config(crate::config::Config::for_tests()).await
}

async fn test_state_with_config(config: crate::config::Config) -> SharedState {
    let (stats_tx, _) = broadcast::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());
    AppState::new(client, resolver, stats_tx, events_tx, config)
}

#[tokio::test]
async fn cancelled_transparent_direction_keeps_successfully_written_bytes() {
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct CancellationIo {
        input: std::io::Cursor<Vec<u8>>,
        partial_writer: bool,
        write_started: Arc<AtomicBool>,
    }

    impl AsyncRead for CancellationIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.partial_writer {
                // The opposite copy fails only after this socket has accepted
                // part of the chunk that its write future cannot finish.
                if self.write_started.load(Ordering::Relaxed) {
                    return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut self.input).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for CancellationIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.partial_writer {
                if self.write_started.swap(true, Ordering::Relaxed) {
                    return Poll::Pending;
                }
                return Poll::Ready(Ok(bytes.len().min(3)));
            }
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    for partial_upstream in [true, false] {
        let write_started = Arc::new(AtomicBool::new(false));
        let socket = |partial_writer| CancellationIo {
            input: std::io::Cursor::new(b"outbound".to_vec()),
            partial_writer,
            write_started: Arc::clone(&write_started),
        };
        let (mut up_preview, mut down_preview) = (Vec::new(), Vec::new());
        let (up, down, result) = tokio::time::timeout(
            Duration::from_secs(1),
            copy_transparent(
                socket(!partial_upstream),
                socket(partial_upstream),
                &mut up_preview,
                &mut down_preview,
                4096,
                |_, _| {},
            ),
        )
        .await
        .expect("the opposite read error must cancel the pending write");
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert_eq!((up, down), if partial_upstream { (3, 0) } else { (0, 3) });
        assert!(up_preview.is_empty() && down_preview.is_empty());
    }
}

#[tokio::test]
async fn transparent_copy_preserves_bidirectional_observations_and_preview_limits() {
    for preview_limit in [0, 3] {
        let (client, mut client_peer) = tokio::io::duplex(64);
        let (upstream, mut upstream_peer) = tokio::io::duplex(64);
        client_peer.write_all(b"upload").await.unwrap();
        client_peer.shutdown().await.unwrap();
        upstream_peer.write_all(b"download").await.unwrap();
        upstream_peer.shutdown().await.unwrap();
        let (mut up_preview, mut down_preview) = (Vec::new(), Vec::new());
        let observations = std::cell::RefCell::new(Vec::new());
        let (up, down, result) = copy_transparent(
            client,
            upstream,
            &mut up_preview,
            &mut down_preview,
            preview_limit,
            |direction, n| observations.borrow_mut().push((direction, n)),
        )
        .await;
        result.unwrap();
        assert_eq!((up, down), (6, 8));
        let mut received = Vec::new();
        upstream_peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"upload");
        received.clear();
        client_peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"download");
        assert_eq!(up_preview, &b"upload"[..preview_limit]);
        assert_eq!(down_preview, &b"download"[..preview_limit]);
        let observations = observations.into_inner();
        assert!(observations.contains(&(PacketDirection::Upstream, 6)));
        assert!(observations.contains(&(PacketDirection::Downstream, 8)));
    }
}

#[tokio::test]
async fn blocked_tunnel_estimate_is_per_event() {
    let state = test_state().await;
    let host = "blocked.example";
    state
        .blocklist
        .store(Arc::new(HashSet::from([host.to_string()])));
    let destination = "127.0.0.1:443".parse().unwrap();
    let tls = TlsInfo {
        parse_status: "parsed",
        sni: Some(host.to_string()),
        ..TlsInfo::default()
    };

    for expected_total in [65, 130] {
        let decision = evaluate_transparent_policy(&state, destination, &tls, None).await;
        let TransparentPolicyDecision::Block(block) = decision else {
            panic!("expected blocked tunnel");
        };
        assert_eq!(block.blocked_bytes_delta_approx, 65);
        assert_eq!(block.blocked_bytes, expected_total);
    }
}

#[tokio::test]
async fn payload_audit_collects_http_preview_without_general_payload_capture() {
    let mut config = crate::config::Config::for_tests();
    config.payload_audit.enabled = true;
    config.proxy.capture_plaintext_payloads = false;
    let state = test_state_with_config(config).await;
    let mut observation = HttpTunnelObservation {
        state,
        destination: "127.0.0.1:80".parse().unwrap(),
        started: Instant::now(),
        flow: None,
        bytes_up: 0,
        bytes_down: 0,
        up_preview: Vec::new(),
        down_preview: Vec::new(),
    };
    observation.observe(b"POST / HTTP/1.1\r\n", PacketDirection::Upstream);
    observation.observe(b"HTTP/1.1 200 OK\r\n", PacketDirection::Downstream);
    assert_eq!(observation.up_preview, b"POST / HTTP/1.1\r\n");
    assert!(observation.down_preview.is_empty());
    assert_eq!(observation.bytes_down, 17);
}

#[test]
fn plaintext_authorities_are_unambiguous_and_normalized() {
    use hyper::Request;
    for (uri, hosts, expected) in [
        ("/", vec!["Blocked.Example.:80"], Some("blocked.example")),
        (
            "http://allowed.example/a",
            vec!["allowed.example:80"],
            Some("allowed.example"),
        ),
        ("http://blocked.example/a", vec!["allowed.example"], None),
        ("https://allowed.example/a", vec!["allowed.example"], None),
        ("/", vec!["user@allowed.example"], None),
        ("/", vec!["allowed.example", "blocked.example"], None),
        ("/", vec![], None),
    ] {
        let mut builder = Request::builder().uri(uri);
        for host in hosts {
            builder = builder.header("Host", host);
        }
        let request = builder.body(()).unwrap();
        assert_eq!(
            transparent_http_hostname(&request).as_deref(),
            expected,
            "{uri}"
        );
    }
}

#[tokio::test]
async fn plaintext_keepalive_checks_every_request_before_original_destination_connect() {
    use axum::{
        body::{to_bytes, Body},
        routing::any,
        Router,
    };
    use hyper::{Request, Response};
    let state = test_state().await;
    let mut events_rx = state.events_tx.subscribe();
    state
        .blocklist
        .store(Arc::new(HashSet::from(["blocked.example".to_string()])));
    let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let orig_dst = upstream.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let origin = tokio::spawn(async move {
        let router = Router::new().fallback(any(move |req: Request<Body>| {
            let tx = tx.clone();
            async move {
                let host = req.headers()["host"].clone();
                let path = req.uri().to_string();
                let body = to_bytes(req.into_body(), 4096).await.unwrap();
                tx.send((host, path, body)).unwrap();
                Response::new(Body::from("ok"))
            }
        }));
        axum::serve(upstream, router).await.unwrap();
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let handler = tokio::spawn(serve_transparent_http(
        stream,
        state.clone(),
        orig_dst,
        None,
    ));
    // A chunked body containing header-shaped text must not become a request.
    client.write_all(b"POST /allowed?q=1 HTTP/1.1\r\nHost: allowed.example\r\nTransfer-Encoding: chunked\r\n\r\n15\r\nHost: blocked.example\r\n0\r\n\r\nGET /blocked HTTP/1.1\r\nHost: BlOcKeD.Example.:80\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut responses = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut responses))
        .await
        .unwrap()
        .unwrap();
    let responses = String::from_utf8(responses).unwrap();
    assert!(responses.contains("200 OK"), "{responses}");
    assert!(responses.contains("403 Forbidden"), "{responses}");
    let (host, path, body) = rx.recv().await.unwrap();
    assert_eq!(host, "allowed.example");
    assert_eq!(path, "/allowed?q=1");
    assert_eq!(body.as_ref(), b"Host: blocked.example");
    assert!(
        rx.try_recv().is_err(),
        "blocked second request reached origin"
    );
    handler.await.unwrap();
    assert_eq!(state.active_tunnels.load(Ordering::Relaxed), 0);
    assert_eq!(state.tunnels_opened.load(Ordering::Relaxed), 1);
    assert!(state.bytes_up.load(Ordering::Relaxed) > 100);
    assert!(state.bytes_down.load(Ordering::Relaxed) > 0);
    let close = std::iter::from_fn(|| events_rx.try_recv().ok())
        .map(|raw| serde_json::from_str::<serde_json::Value>(&raw).unwrap())
        .find(|event| event["type"] == "tunnel_close")
        .expect("plaintext connection emits a close observation");
    assert_eq!(close["measurement"]["bytes_status"], "unavailable");
    assert_eq!(close["measurement"]["source"], "unavailable");
    origin.abort();
}

#[tokio::test]
async fn opaque_http_upgrades_are_rejected_and_websockets_keep_working() {
    let state = test_state().await;
    let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let destination = upstream.local_addr().unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let handler = tokio::spawn(serve_transparent_http(
        stream,
        state.clone(),
        destination,
        None,
    ));
    client.write_all(b"GET / HTTP/1.1\r\nHost: allowed.example\r\nConnection: upgrade, close\r\nUpgrade: h2c\r\n\r\n").await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.contains("400 Bad Request"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), upstream.accept())
            .await
            .is_err()
    );
    handler.await.unwrap();

    let origin = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
        let mut payload = [0; 4];
        socket.read_exact(&mut payload).await.unwrap();
        socket.write_all(&payload).await.unwrap();
    });
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let handler = tokio::spawn(serve_transparent_http(
        stream,
        state.clone(),
        destination,
        None,
    ));
    client.write_all(b"GET /ws HTTP/1.1\r\nHost: allowed.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
    let mut header = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !header.ends_with(b"\r\n\r\n") {
            header.push(client.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(String::from_utf8(header)
        .unwrap()
        .contains("101 Switching Protocols"));
    client.write_all(b"ping").await.unwrap();
    let mut payload = [0; 4];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&payload, b"ping");
    drop(client);
    origin.await.unwrap();
    handler.await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.active_tunnels.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fragmented_blocked_http_headers_never_connect_upstream() {
    let state = test_state().await;
    state
        .blocklist
        .store(Arc::new(HashSet::from(["blocked.example".to_string()])));
    let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let orig_dst = upstream.local_addr().unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let handler = tokio::spawn(serve_transparent_http(stream, state, orig_dst, None));
    client.write_all(b"GET / HTTP/1.1\r\nHo").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), upstream.accept())
            .await
            .is_err()
    );
    client
        .write_all(b"st: blocked.example\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.contains("403 Forbidden"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), upstream.accept())
            .await
            .is_err()
    );
    handler.await.unwrap();
}

#[tokio::test]
async fn blocked_non_tarpit_transparent_sessions_do_not_fall_through() {
    let state = test_state().await;
    let mut events_rx = state.events_tx.subscribe();
    let blocked_host = "blocked.example";
    let mut blocked = HashSet::new();
    blocked.insert(blocked_host.to_string());
    state.blocklist.store(Arc::new(blocked));

    let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let orig_dst = upstream_listener.local_addr().unwrap();

    let client_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_task = tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
    let (stream, _) = client_listener.accept().await.unwrap();
    let _client = client_task.await.unwrap();

    let tls = TlsInfo {
        sni: Some(blocked_host.to_string()),
        parse_status: "parsed",
        alpn: None,
        tls_ver: Some("TLS1.0".to_string()),
        offered_version: Some("TLS1.2".to_string()),
        cipher_suites_count: None,
        ja3_lite: None,
    };

    handle_transparent_inner(stream, state, orig_dst, tls).await;

    let connected =
        tokio::time::timeout(Duration::from_millis(300), upstream_listener.accept()).await;
    assert!(
        connected.is_err(),
        "blocked transparent session unexpectedly connected to upstream"
    );

    let event: serde_json::Value = serde_json::from_str(&events_rx.recv().await.unwrap())
        .expect("transparent block event should serialize");
    assert_eq!(event["reason"], POLICY_REASON_MATCHED_BLOCKLIST);
    assert_eq!(event["fingerprint"]["tls_ver"], "TLS1.0");
    assert_eq!(event["tls_evidence"]["offered_version"], "TLS1.2");
    assert_eq!(
        event["tls_evidence"]["parser_version"],
        "proxy-clienthello-v2"
    );
    assert_eq!(event["tls_evidence"]["parse_status"], "parsed");
    assert_eq!(event["tls_evidence"]["semantics"], "offered_not_negotiated");
}

#[tokio::test]
async fn no_sni_https_is_blocked_before_upstream_connect() {
    let state = test_state().await;
    let mut events_rx = state.events_tx.subscribe();

    let client_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_task = tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
    let (stream, _) = client_listener.accept().await.unwrap();
    let _client = client_task.await.unwrap();

    handle_transparent_inner(
        stream,
        state,
        SocketAddr::from(([127, 0, 0, 1], 443)),
        TlsInfo::default(),
    )
    .await;

    let event: serde_json::Value = serde_json::from_str(&events_rx.recv().await.unwrap())
        .expect("transparent no-sni event should serialize");
    assert_eq!(event["reason"], POLICY_REASON_NO_SNI_HTTPS);
    assert_eq!(event["host"], "127.0.0.1:443");
}

#[tokio::test]
async fn pinned_transparent_hosts_bypass_and_connect() {
    let state = test_state().await;
    let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let orig_dst = upstream_listener.local_addr().unwrap();

    let client_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_task = tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
    let (stream, _) = client_listener.accept().await.unwrap();

    let state_clone = state.clone();
    let handler = tokio::spawn(async move {
        handle_transparent_inner(
            stream,
            state_clone,
            orig_dst,
            TlsInfo {
                parse_status: "parsed",
                sni: Some("i.instagram.com".to_string()),
                alpn: Some("h2".to_string()),
                tls_ver: Some("TLS1.3".to_string()),
                cipher_suites_count: Some(4),
                ja3_lite: Some("771,4865-4866,0-16,29-23,0".to_string()),
                ..TlsInfo::default()
            },
        )
        .await;
    });

    let mut client = client_task.await.unwrap();
    let (mut upstream, _) =
        tokio::time::timeout(Duration::from_secs(1), upstream_listener.accept())
            .await
            .expect("bypass should connect upstream")
            .unwrap();

    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(1), upstream.read_exact(&mut buf))
        .await
        .expect("upstream should receive client bytes")
        .unwrap();
    assert_eq!(&buf, b"ping");

    drop(client);
    drop(upstream);
    handler.await.unwrap();
}
