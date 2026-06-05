use super::*;
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::broadcast;

async fn create_test_state() -> SharedState {
    let (stats_tx, _) = broadcast::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
    AppState::new(
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(hyper_util::client::legacy::connect::HttpConnector::new()),
        resolver,
        stats_tx,
        events_tx,
        crate::config::Config::for_tests(),
    )
}

#[tokio::test]
async fn host_stats_transition_to_tarpit() {
    let state = create_test_state().await;
    let host = "test.analytics.host";

    assert!(state.record_host_block(host, 100, "analytics").is_none());

    {
        let mut stats = state.host_stats.get_mut(host).unwrap();
        stats.blocked_attempts = 100;
        stats.first_seen = Instant::now() - Duration::from_secs(10);
        stats.last_seen = Instant::now() - Duration::from_millis(100);
        stats.iat_ema_ms = Some(100);
        stats.jitter_ema_ms = Some(5);
        stats.low_jitter_streak = 3;
    }

    let verdict_change = state.record_host_block(host, 100, "analytics");
    assert_eq!(verdict_change, Some(("BLOCKED", "TARPIT")));
}

#[tokio::test]
async fn low_jitter_state_accumulates_for_regular_blocking() {
    let state = create_test_state().await;
    let host = "regular.analytics.host";

    assert!(state.record_host_block(host, 100, "analytics").is_none());
    {
        let mut stats = state.host_stats.get_mut(host).unwrap();
        stats.last_seen = Instant::now() - Duration::from_millis(100);
    }
    let _ = state.record_host_block(host, 100, "analytics");
    {
        let mut stats = state.host_stats.get_mut(host).unwrap();
        stats.last_seen = Instant::now() - Duration::from_millis(100);
    }
    let _ = state.record_host_block(host, 100, "analytics");

    let stats = state.host_stats.get(host).unwrap();
    assert!(stats.iat_ema_ms.is_some());
    assert!(stats.jitter_ema_ms.is_some());
    assert!(stats.low_jitter_streak >= 1);
}

#[tokio::test]
async fn stale_hosts_are_evicted() {
    let state = create_test_state().await;
    state.record_host_block("active.host", 100, "test");
    state.record_host_block("stale.host", 100, "test");
    {
        let mut stats = state.host_stats.get_mut("stale.host").unwrap();
        stats.last_seen = Instant::now() - Duration::from_secs(3600);
    }

    state.evict_stale_hosts(600);
    assert!(state.host_stats.contains_key("active.host"));
    assert!(!state.host_stats.contains_key("stale.host"));
}

#[tokio::test]
async fn claim_lookup_expires() {
    let state = create_test_state().await;
    let device = DeviceInfo {
        device_id: "device-1".to_string(),
        wg_pubkey: Some("pubkey-1".to_string()),
        claim_token_hash: Some("hash".to_string()),
        display_name: Some("Test Device".to_string()),
        username: None,
        hostname: None,
        os_hint: None,
        mac_hint: None,
        first_seen: crate::time::now_rfc3339(),
        last_seen: crate::time::now_rfc3339(),
        notes: None,
    };
    state.upsert_device(device);
    let claim = state
        .refresh_claim("device-1", "pubkey-1", "10.0.0.2")
        .unwrap();
    assert!(claim.active());
    assert!(state
        .find_claim(Some("pubkey-1"), Some("10.0.0.2"))
        .is_some());

    state.device_claims.insert(
        "pubkey-1|10.0.0.2".to_string(),
        DeviceClaim {
            expires_instant: Instant::now() - Duration::from_secs(1),
            ..claim
        },
    );
    assert!(state
        .find_claim(Some("pubkey-1"), Some("10.0.0.2"))
        .is_none());
}

#[tokio::test]
async fn peer_counters_are_created_and_updated_atomically() {
    let state = create_test_state().await;

    state.record_tunnel_open_for_peer(Some("pubkey-1"));
    state.record_peer_block(Some("pubkey-1"), 512);

    let counters = state.peer_counters.get("pubkey-1").unwrap();
    assert_eq!(counters.sessions_open.load(Ordering::Relaxed), 1);
    assert_eq!(counters.blocked_count.load(Ordering::Relaxed), 1);
    assert_eq!(counters.blocked_bytes_approx.load(Ordering::Relaxed), 512);
}

#[tokio::test]
async fn refresh_wg_peers_replaces_snapshot_consistently() {
    let state = create_test_state().await;
    let first = WgPeerSnapshot {
        interface: "wg0".to_string(),
        wg_pubkey: "pubkey-1".to_string(),
        peer_ip: Some("10.0.0.2".to_string()),
        allowed_ips: vec!["10.0.0.2/32".to_string()],
        rx_bytes_total: 100,
        tx_bytes_total: 200,
        ..WgPeerSnapshot::default()
    };
    let second = WgPeerSnapshot {
        interface: "wg0".to_string(),
        wg_pubkey: "pubkey-2".to_string(),
        peer_ip: Some("10.0.0.3".to_string()),
        allowed_ips: vec!["10.0.0.3/32".to_string()],
        rx_bytes_total: 300,
        tx_bytes_total: 400,
        ..WgPeerSnapshot::default()
    };

    state.refresh_wg_peers(&[first.clone()]);
    assert_eq!(
        state.resolve_wg_pubkey(Some("10.0.0.2")),
        Some("pubkey-1".to_string())
    );
    assert!(state.wg_peers_snapshot().inventory.contains_key("pubkey-1"));

    state.refresh_wg_peers(&[second.clone()]);
    let snapshot = state.wg_peers_snapshot();
    assert_eq!(snapshot.inventory.len(), 1);
    assert!(snapshot.inventory.contains_key("pubkey-2"));
    assert!(!snapshot.inventory.contains_key("pubkey-1"));
    assert_eq!(
        snapshot.pubkey_by_ip.get("10.0.0.3").map(String::as_str),
        Some("pubkey-2")
    );
    assert!(snapshot.pubkey_by_ip.get("10.0.0.2").is_none());
}

#[tokio::test]
async fn record_resolved_preserves_all_cached_ips() {
    let state = create_test_state().await;
    state.record_host_block("example.com", 42, "test");
    state.record_resolved(
        "example.com",
        vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()],
        Some("Example ASN".to_string()),
    );

    let cached = state.dns_cache.get("example.com").unwrap();
    assert_eq!(
        cached.resolved_ips,
        vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()]
    );
    drop(cached);

    let host = state.host_stats.get("example.com").unwrap();
    assert_eq!(host.resolved_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(host.asn_org.as_deref(), Some("Example ASN"));
}
