use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use axum::{body::Body, http::Request};
use tower::ServiceExt;

use super::{
    accept_explicit_proxy_connections, admin_api_key_matches, build_explicit_proxy_router,
    build_observability_router, build_state, build_tls_acceptor, constant_time_eq,
    AdminAuthRateLimiter, TlsLoadError, ADMIN_AUTH_FAILURE_WINDOW, ADMIN_AUTH_MAX_FAILURES,
    ADMIN_AUTH_MAX_TRACKED_IPS,
};

#[tokio::test]
async fn explicit_listener_reaps_completed_connections_while_idle() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;
    use tower_http::cors::CorsLayer;

    let state = build_state(&ssl_proxy::config::Config::default()).unwrap();
    let router = build_explicit_proxy_router(state.clone(), CorsLayer::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let (live_tx, live_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        // The explicit listener also supervises a long-lived QUIC listener.
        tasks.spawn(async {
            let _ = live_rx.await;
        });
        accept_explicit_proxy_connections(
            listener, state, &token, permits, &mut tasks, router, None, None,
        )
        .await;
        tasks
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..128 {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 "));
        }
        // No more accepts are needed to reap the final completed connection.
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown.cancel();
    })
    .await
    .expect("listener processes short connections without spinning or stalling");
    let mut tasks = server.await.unwrap();
    assert_eq!(tasks.len(), 1, "only the live listener task should remain");
    live_tx.send(()).unwrap();
    assert!(tasks.join_next().await.unwrap().is_ok());
    assert!(tasks.is_empty());
}

#[tokio::test]
async fn sync_status_preserves_cumulative_topic_counts_after_history_eviction() {
    let state = build_state(&ssl_proxy::config::Config::default()).unwrap();
    for _ in 0..1024 {
        let _ = state.publisher.enqueue_message("wireless.audit", "{}");
    }
    assert!(state.publisher.published_messages().len() < 1024);
    let axum::Json(report) = ssl_proxy::dashboard::sync_status(axum::extract::State(state)).await;
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(
        value["published_topics"],
        serde_json::json!([
            {"topic": "wireless.audit", "count": 1024}
        ])
    );
}

#[test]
fn constant_time_eq_rejects_same_prefix_with_different_lengths() {
    assert!(!constant_time_eq("prefix", "prefix-suffix"));
}

#[test]
fn constant_time_eq_handles_long_inputs() {
    let a = "a".repeat(300);
    let b = "a".repeat(300);

    assert!(constant_time_eq(&a, &b));
}

#[test]
fn admin_api_key_matches_rejects_empty_keys() {
    assert!(!admin_api_key_matches("", ""));
    assert!(!admin_api_key_matches("test-key", ""));
    assert!(admin_api_key_matches("test-key", "test-key"));
}

#[test]
fn configured_unreadable_tls_material_is_rejected() {
    let directory = tempfile::tempdir().expect("create temp dir");
    let mut config = ssl_proxy::config::Config::default();
    config.proxy.explicit_enabled = true;
    config.tls.cert_path = Some(directory.path().join("missing.crt").display().to_string());
    config.tls.key_path = Some(directory.path().join("missing.key").display().to_string());

    assert!(matches!(
        build_tls_acceptor(&config),
        Err(TlsLoadError::ReadCert(_))
    ));
}

#[test]
fn cert_only_tls_config_is_rejected() {
    let directory = tempfile::tempdir().expect("create temp dir");
    let mut config = ssl_proxy::config::Config::default();
    config.proxy.explicit_enabled = true;
    config.tls.cert_path = Some(directory.path().join("cert.crt").display().to_string());
    config.tls.key_path = None;

    assert!(matches!(
        build_tls_acceptor(&config),
        Err(TlsLoadError::InvalidConfig(msg)) if msg.contains("must both be set")
    ));
}

#[test]
fn key_only_tls_config_is_rejected() {
    let directory = tempfile::tempdir().expect("create temp dir");
    let mut config = ssl_proxy::config::Config::default();
    config.proxy.explicit_enabled = true;
    config.tls.cert_path = None;
    config.tls.key_path = Some(directory.path().join("key.key").display().to_string());

    assert!(matches!(
        build_tls_acceptor(&config),
        Err(TlsLoadError::InvalidConfig(msg)) if msg.contains("must both be set")
    ));
}

#[test]
fn admin_auth_rate_limiter_evicts_expired_failures() {
    let limiter = AdminAuthRateLimiter::default();
    let now = Instant::now();
    let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let second_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

    assert_eq!(limiter.record_failure(first_ip, now), 1);
    assert_eq!(
        limiter.record_failure(
            second_ip,
            now + ADMIN_AUTH_FAILURE_WINDOW + Duration::from_millis(1),
        ),
        1
    );

    assert!(limiter.failures_by_ip.get(&first_ip).is_none());
    assert!(limiter.failures_by_ip.get(&second_ip).is_some());
}

#[test]
fn admin_auth_rate_limiter_fails_closed_when_saturated() {
    let limiter = AdminAuthRateLimiter::default();
    let now = Instant::now();

    for idx in 0..ADMIN_AUTH_MAX_TRACKED_IPS {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            ((idx >> 16) & 0xff) as u8,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        assert_eq!(limiter.record_failure(ip, now), 1);
    }

    let saturated_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    assert_eq!(
        limiter.record_failure(saturated_ip, now),
        ADMIN_AUTH_MAX_FAILURES
    );
    assert!(limiter.failures_by_ip.get(&saturated_ip).is_none());
}

#[tokio::test]
async fn observability_listener_exposes_no_admin_routes() {
    let state = build_state(&ssl_proxy::config::Config::default()).expect("build state");
    let router = build_observability_router(state);

    for path in ["/hosts", "/stats/summary", "/devices", "/dashboard"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch observability request");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}
