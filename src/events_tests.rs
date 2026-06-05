use hickory_resolver::TokioAsyncResolver;
use serde::ser::{Error as _, Serializer};
use tokio::sync::broadcast;

use super::*;

struct FailingExtra;

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

    let published = state.publisher.published_messages();
    assert_eq!(published.len(), 1);
    let request: crate::sync::ScanRequest =
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
