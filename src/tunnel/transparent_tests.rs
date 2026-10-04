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
    let (stats_tx, _) = broadcast::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());
    let config = crate::config::Config::for_tests();

    AppState::new(client, resolver, stats_tx, events_tx, config)
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
        alpn: None,
        tls_ver: None,
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
                sni: Some("i.instagram.com".to_string()),
                alpn: Some("h2".to_string()),
                tls_ver: Some("TLS1.3".to_string()),
                cipher_suites_count: Some(4),
                ja3_lite: Some("771,4865-4866,0-16,29-23,0".to_string()),
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
