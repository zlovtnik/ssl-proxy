use hickory_resolver::TokioAsyncResolver;
use serde::ser::{Error as _, Serializer};
use std::sync::{Mutex, OnceLock};
use tokio::sync::broadcast;

use super::*;

#[test]
fn endpoint_rejects_userinfo_without_retaining_credentials() {
    for authority in [
        "user:secret@example.com:443",
        "user@example.com",
        "@example.com",
        "secret@",
    ] {
        let evidence = endpoint(authority, "connect_authority", 8443);
        assert!(evidence["authority_raw"].is_null());
        assert!(evidence["host_raw"].is_null());
        assert!(evidence["port"].is_null());
        assert_eq!(evidence["parse_status"], "invalid");
        assert_eq!(evidence["routing_port"], 8443);
        assert_eq!(evidence["authority_source"], "connect_authority");
    }
}

#[test]
fn endpoint_preserves_observed_authority_separately_from_routing() {
    for (authority, host, port) in [
        ("example.com:443", "example.com", Some(443)),
        ("example.com", "example.com", None),
        ("[2001:db8::1]:8443", "2001:db8::1", Some(8443)),
    ] {
        let evidence = endpoint(authority, "quic_authority", 443);
        assert_eq!(evidence["authority_raw"], authority);
        assert_eq!(evidence["host_raw"], host);
        assert_eq!(evidence["port"], serde_json::json!(port));
        assert_eq!(evidence["routing_port"], 443);
    }
}

#[test]
fn frozen_proxy_envelopes_preserve_replay_ids_and_scan_contract() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../sql/postgres/contracts/fixtures/proxy-events-v1.json"
    ))
    .unwrap();
    let mut ids = std::collections::HashSet::new();
    let mut kinds = std::collections::HashSet::new();
    for observation in corpus["observations"].as_array().unwrap() {
        let raw = observation["raw_json"].as_str().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
        let event = value["type"].as_str().unwrap().to_string();
        let host = value["host"].as_str().unwrap().to_string();
        let time = value["time"].as_str().unwrap().to_string();
        let id = value["event_id"].as_str().unwrap().to_string();
        assert!(crate::proxy_sync::should_publish_scan_request(&event));
        assert_eq!(
            ids.insert(id.clone()),
            observation["source_count_delta"] == 1
        );
        kinds.insert(event.clone());
        let map = value.as_object_mut().unwrap();
        for key in ["event_id", "type", "host", "time"] {
            map.remove(key);
        }
        let encoded = serde_json::to_string(&EventEnvelope {
            event_id: id,
            event: &event,
            host: &host,
            time: time.clone(),
            extra: map.clone(),
        })
        .unwrap();
        assert_eq!(encoded, raw);
        assert_eq!(
            format!("{:x}", Sha256::digest(raw.as_bytes())),
            observation["payload_sha256"]
        );
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(format!("{event}:{host}:{time}:{raw}").as_bytes())
            ),
            observation["scan_request"]["dedupe_key"]
        );
        assert!(sync_plane::parse_payload_ref(
            observation["scan_request"]["payload_ref"].as_str().unwrap()
        )
        .is_some());
    }
    assert_eq!(kinds.len(), 7);
    assert_eq!(ids.len(), 8);
}

#[tokio::test]
async fn http_failure_duration_is_not_response_header_latency() {
    let state = create_test_state().await;
    let mut rx = state.events_tx.subscribe();
    for (event_type, expected_status) in [
        ("http_error", "unavailable"),
        ("http_proxied", "header_latency"),
    ] {
        emit_serializable(
            &state,
            event_type,
            "example.com",
            None,
            None,
            None,
            None,
            None,
            None,
            0,
            0,
            None,
            false,
            None,
            serde_json::json!({"duration_ms": 123}),
        );
        let event: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(event["duration_ms"], 123);
        assert_eq!(event["measurement"]["duration_status"], expected_status);
    }
}

#[tokio::test]
async fn additive_endpoint_fields_obey_nested_hostname_privacy() {
    let _lock = env_lock();
    std::env::set_var("AUDIT_SANITIZE_HOSTNAMES", "true");
    std::env::set_var("AUDIT_HMAC_KEY", "contract-only");
    let state = create_test_state().await;
    let mut rx = state.events_tx.subscribe();
    emit_serializable(
        &state,
        "http_proxied",
        "private.example",
        None,
        None,
        None,
        None,
        None,
        None,
        0,
        0,
        None,
        false,
        None,
        serde_json::json!({"nested_arrays": [[{"authority_raw": "private.example:443"}]], "endpoint": {
            "authority_raw": "private.example:8443", "host_normalized": "private.example", "registrable_domain": "private.example"
        }}),
    );
    let raw = rx.recv().await.unwrap();
    assert!(!raw.contains("private.example"));
    let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(event["sanitization_status"], "sanitized");
    assert_eq!(event["measurement"]["bytes_status"], "unavailable");
    clear_audit_env();
}

#[tokio::test]
async fn coalescing_separates_devices_and_reasons_and_reports_rollover() {
    let state = create_test_state().await;
    assert!(state
        .coalesce_event(
            "block",
            "example.com",
            None,
            None,
            Some("a"),
            Some("policy")
        )
        .is_some());
    assert!(state
        .coalesce_event(
            "block",
            "example.com",
            None,
            None,
            Some("a"),
            Some("policy")
        )
        .is_none());
    assert!(state
        .coalesce_event(
            "block",
            "example.com",
            None,
            None,
            Some("b"),
            Some("policy")
        )
        .is_some());
    assert!(state
        .coalesce_event(
            "block",
            "example.com",
            None,
            None,
            Some("a"),
            Some("changed")
        )
        .is_some());
    tokio::time::sleep(std::time::Duration::from_millis(510)).await;
    let evidence = state
        .coalesce_event(
            "block",
            "example.com",
            None,
            None,
            Some("a"),
            Some("policy"),
        )
        .unwrap();
    assert_eq!(evidence["suppressed_previous_window"], 1);
}

struct FailingExtra;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn clear_audit_env() {
    std::env::remove_var("AUDIT_SANITIZE_HOSTNAMES");
    std::env::remove_var("AUDIT_HMAC_KEY");
}

impl Serialize for FailingExtra {
    /// Always returns a serialization error when attempting to serialize this value.
    ///
    /// # Examples
    ///
    /// ```
    /// use serde::Serialize;
    ///
    /// struct FailingExtra;
    ///
    /// impl Serialize for FailingExtra {
    ///     fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    ///     where
    ///         S: serde::Serializer,
    ///     {
    ///         Err(S::Error::custom("intentional serialization failure"))
    ///     }
    /// }
    ///
    /// let e = FailingExtra;
    /// assert!(serde_json::to_string(&e).is_err());
    /// ```
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(S::Error::custom("intentional serialization failure"))
    }
}

/// Builds a SharedState configured for tests with local broadcast channels and a system DNS resolver.
///
/// # Examples
///
/// ```
/// #[tokio::test]
/// async fn create_state_example() {
///     let state = create_test_state().await;
///     // Use `state` in test assertions or to subscribe to `events_tx`/`stats_tx`.
///     let _ = state;
/// }
/// ```
async fn create_test_state() -> SharedState {
    let (stats_tx, _) = broadcast::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let resolver =
        TokioAsyncResolver::tokio_from_system_conf().expect("system resolver should initialize");

    crate::state::AppState::new(
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(hyper_util::client::legacy::connect::HttpConnector::new()),
        resolver,
        stats_tx,
        events_tx,
        crate::config::Config::for_tests(),
    )
}

/// Verifies that no broadcast is sent when serializing the extra payload fails.
///
/// Creates a test shared state, subscribes to the events broadcast channel, calls
/// `emit_serializable` using a `Serialize` implementation that always returns an
/// error, and asserts the receiver has no available message.
///
/// # Examples
///
/// ```no_run
/// // Illustrative: the real test uses `FailingExtra` which fails serialization.
/// let state = create_test_state().await;
/// let mut rx = state.events_tx.subscribe();
/// emit_serializable(
///     &state,
///     "test_event",
///     "example.com",
///     None,
///     0,
///     0,
///     None,
///     false,
///     None,
///     FailingExtra,
/// );
/// assert!(matches!(rx.try_recv(), Err(tokio::sync::broadcast::error::TryRecvError::Empty)));
/// ```
#[tokio::test]
async fn emit_serializable_skips_broadcast_when_serialization_fails() {
    let state = create_test_state().await;
    let mut rx = state.events_tx.subscribe();
    let _guard = env_lock();
    clear_audit_env();

    emit_serializable(
        &state,
        "test_event",
        "example.com",
        None,
        None,
        None,
        None,
        None,
        None,
        0,
        0,
        None,
        false,
        None,
        FailingExtra,
    );

    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn emit_serializable_publishes_sync_request_only_for_allowed_events() {
    let state = create_test_state().await;
    let _guard = env_lock();
    clear_audit_env();

    emit_serializable(
        &state,
        "stats_live",
        "example.com",
        None,
        None,
        None,
        None,
        None,
        None,
        0,
        0,
        None,
        false,
        None,
        serde_json::json!({ "ignored": true }),
    );
    assert!(state.publisher.published_messages().is_empty());

    emit_serializable(
        &state,
        "tunnel_open",
        "example.com",
        None,
        None,
        None,
        None,
        None,
        None,
        0,
        0,
        None,
        false,
        None,
        serde_json::json!({ "kind": "connect" }),
    );

    let published = state.publisher.published_messages();
    assert_eq!(published.len(), 1);
    assert!(published[0]
        .payload
        .contains("\"payload_ref\":\"inline://json/"));
}

#[tokio::test]
async fn emit_serializable_uses_one_timestamp_and_top_level_identity_fields() {
    let state = create_test_state().await;
    let mut events = state.events_tx.subscribe();
    let _guard = env_lock();
    clear_audit_env();

    emit_serializable(
        &state,
        "tunnel_open",
        "example.com",
        Some("10.13.13.2".to_string()),
        Some("wg-pubkey".to_string()),
        Some("device-1".to_string()),
        Some("registered".to_string()),
        Some("phone.local".to_string()),
        Some("ExampleUA/1.0".to_string()),
        12,
        34,
        Some(200),
        false,
        Some("default".to_string()),
        serde_json::json!({ "kind": "connect" }),
    );

    let raw = events.try_recv().expect("event should be broadcast");
    let envelope: serde_json::Value =
        serde_json::from_str(&raw).expect("event should be valid json");
    assert_eq!(envelope["wg_pubkey"], "wg-pubkey");
    assert_eq!(envelope["device_id"], "device-1");
    assert_eq!(envelope["identity_source"], "registered");
    assert_eq!(envelope["peer_hostname"], "phone.local");
    assert_eq!(envelope["client_ua"], "ExampleUA/1.0");
    assert!(uuid::Uuid::parse_str(
        envelope["event_id"]
            .as_str()
            .expect("event_id should be a string")
    )
    .is_ok());
    assert_eq!(envelope["classification"], "unknown");

    let published = state.publisher.published_messages();
    assert_eq!(published.len(), 1);
    let request: sync_plane::ScanRequest =
        serde_json::from_str(&published[0].payload).expect("scan request should decode");
    assert_eq!(
        envelope["time"].as_str(),
        Some(request.observed_at.as_str())
    );
    assert_eq!(
        state
            .publisher
            .resolve_payload_ref_contents(&request.payload_ref)
            .expect("inline payload should resolve"),
        raw
    );
}

#[tokio::test]
async fn emit_serializable_queues_dashboard_event_when_no_subscriber() {
    let state = create_test_state().await;
    let _guard = env_lock();
    clear_audit_env();
    assert_eq!(state.dashboard_event_queue_len(), 0);

    emit_serializable(
        &state,
        "tunnel_open",
        "example.com",
        None,
        None,
        None,
        None,
        None,
        None,
        0,
        0,
        None,
        false,
        None,
        serde_json::json!({ "kind": "connect" }),
    );

    assert_eq!(state.dashboard_event_queue_len(), 1);

    let mut rx = state.events_tx.subscribe();
    state.flush_dashboard_event_queue();

    assert_eq!(state.dashboard_event_queue_len(), 0);
    let raw = rx
        .try_recv()
        .expect("queued dashboard event should be delivered");
    assert!(raw.contains("\"type\":\"tunnel_open\"") || raw.contains("\"type\": \"tunnel_open\""));
}

#[tokio::test]
async fn flush_dashboard_event_queue_drops_event_after_retry_limit() {
    let state = create_test_state().await;
    let _guard = env_lock();
    clear_audit_env();

    emit_serializable(
        &state,
        "tunnel_open",
        "example.com",
        None,
        None,
        None,
        None,
        None,
        None,
        0,
        0,
        None,
        false,
        None,
        serde_json::json!({ "kind": "connect" }),
    );

    assert_eq!(state.dashboard_event_queue_len(), 1);
    for _ in 0..crate::state::DASHBOARD_EVENT_MAX_RETRY_ATTEMPTS {
        state.flush_dashboard_event_queue();
    }

    assert_eq!(state.dashboard_event_queue_len(), 0);
}

#[tokio::test]
async fn emit_serializable_coalesces_duplicate_blocked_events() {
    let state = create_test_state().await;
    let mut rx = state.events_tx.subscribe();
    let _guard = env_lock();
    clear_audit_env();

    for _ in 0..2 {
        emit_serializable(
            &state,
            "http_blocked",
            "blocked.example",
            Some("10.13.13.2".to_string()),
            Some("wg-pubkey".to_string()),
            None,
            None,
            None,
            None,
            0,
            0,
            Some(403),
            true,
            None,
            serde_json::json!({ "path": "/" }),
        );
    }

    let _ = rx.try_recv().expect("first blocked event should emit");
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn emit_serializable_sanitizes_audit_hostnames_when_enabled() {
    let state = create_test_state().await;
    let mut rx = state.events_tx.subscribe();
    let _guard = env_lock();
    std::env::set_var("AUDIT_SANITIZE_HOSTNAMES", "true");
    std::env::set_var("AUDIT_HMAC_KEY", "audit-secret");

    emit_serializable(
        &state,
        "tunnel_open",
        "example.com",
        Some("10.13.13.2".to_string()),
        None,
        None,
        None,
        Some("phone.local".to_string()),
        None,
        0,
        0,
        None,
        false,
        None,
        serde_json::json!({ "sni": "api.example.com" }),
    );

    let raw = rx.try_recv().expect("event should emit");
    let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(event["host"].as_str().unwrap().starts_with("hmac:"));
    assert!(event["peer_hostname"]
        .as_str()
        .unwrap()
        .starts_with("hmac:"));
    assert!(event["sni"].as_str().unwrap().starts_with("hmac:"));
    assert!(!raw.contains("example.com"));
    assert!(!raw.contains("phone.local"));

    clear_audit_env();
}
