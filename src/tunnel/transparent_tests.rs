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
