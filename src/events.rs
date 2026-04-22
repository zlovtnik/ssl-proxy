//! Shared event emission helpers for broadcast and sync-plane publishing.
//!
//! This module centralizes the common event envelope used across proxy, tunnel,
//! and QUIC paths. It does not decide when events should be emitted.

use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::error;

use crate::state::SharedState;

/// Payload fields stored alongside an emitted event.
///
/// The typed fields are carried into the broadcast payload and the derived
/// scan request metadata, while `extra` is flattened into the JSON envelope.
pub struct EmitPayload {
    pub peer_ip: Option<String>,
    pub wg_pubkey: Option<String>,
    pub device_id: Option<String>,
    pub identity_source: Option<String>,
    pub peer_hostname: Option<String>,
    pub client_ua: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub status_code: Option<u16>,
    pub blocked: bool,
    pub obfuscation_profile: Option<String>,
    pub extra: serde_json::Value,
}

#[derive(Serialize)]
struct EventEnvelope<'a> {
    #[serde(rename = "type")]
    event: &'a str,
    host: &'a str,
    time: String,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// Emit an event using the provided `EmitPayload`, serializing its fields into the event envelope.
///
/// # Examples
///
/// ```rust,no_run
/// use serde_json::json;
/// use ssl_proxy::{events::{self, EmitPayload}, state};
///
/// // `state` would be your application shared state; here it's a placeholder.
/// let state: &state::SharedState = unimplemented!();
/// let payload = EmitPayload {
///     peer_ip: Some("192.0.2.1".into()),
///     wg_pubkey: Some("wg-pubkey".into()),
///     device_id: Some("device-1".into()),
///     identity_source: Some("registered".into()),
///     peer_hostname: Some("iphone.local".into()),
///     client_ua: Some("ExampleUA/1.0".into()),
///     bytes_up: 123,
///     bytes_down: 456,
///     status_code: Some(200),
///     blocked: false,
///     obfuscation_profile: None,
///     extra: json!({"path": "/api/health", "method": "GET"}),
/// };
/// events::emit(state, "proxy.request", "example.com", payload);
/// ```
pub fn emit(state: &SharedState, event: &str, host: &str, payload: EmitPayload) {
    emit_serializable(
        state,
        event,
        host,
        payload.peer_ip,
        payload.wg_pubkey,
        payload.device_id,
        payload.identity_source,
        payload.peer_hostname,
        payload.client_ua,
        payload.bytes_up,
        payload.bytes_down,
        payload.status_code,
        payload.blocked,
        payload.obfuscation_profile,
        payload.extra,
    );
}

/// Serializes an event envelope and dispatches it to the broadcast channel and sync publisher.
///
/// This function wraps the provided `extra` payload inside an `EventEnvelope` (including `type`, `host`, and an RFC3339 UTC `time`), serializes it to JSON, sends the resulting raw JSON string to `state.events_tx`, and emits a `sync.scan.request` message only for events on the sync-plane allowlist. If serialization or payload-reference preparation fails the error is logged and the function returns without publishing downstream.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use ssl_proxy::{events::emit_serializable, state};
///
/// // `state` must be a valid `SharedState` in your application.
/// let state: state::SharedState = unimplemented!();
/// emit_serializable(
///     &state,
///     "proxy_request",
///     "example.com",
///     Some("1.2.3.4".to_string()),
///     Some("wg-pubkey".to_string()),
///     Some("device-1".to_string()),
///     Some("registered".to_string()),
///     Some("iphone.local".to_string()),
///     Some("ExampleUA/1.0".to_string()),
///     123,
///     456,
///     Some(200),
///     false,
///     None::<String>,
///     json!({ "path": "/index.html" }),
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_serializable<T>(
    state: &SharedState,
    event: &str,
    host: &str,
    peer_ip: Option<String>,
    wg_pubkey: Option<String>,
    device_id: Option<String>,
    identity_source: Option<String>,
    peer_hostname: Option<String>,
    client_ua: Option<String>,
    bytes_up: u64,
    bytes_down: u64,
    status_code: Option<u16>,
    blocked: bool,
    obfuscation_profile: Option<String>,
    extra: T,
) where
    T: Serialize,
{
    let mut extra = match serde_json::to_value(extra) {
        Ok(serde_json::Value::Object(map)) => map,
        Ok(other) => {
            let mut map = serde_json::Map::new();
            map.insert("extra".to_string(), other);
            map
        }
        Err(e) => {
            error!(%e, event_name = event, %host, "failed to serialize event payload");
            return;
        }
    };

    if let Some(value) = peer_ip {
        extra.insert("peer_ip".to_string(), serde_json::Value::String(value));
    }
    if let Some(value) = wg_pubkey {
        extra.insert("wg_pubkey".to_string(), serde_json::Value::String(value));
    }
    if let Some(value) = device_id {
        extra.insert("device_id".to_string(), serde_json::Value::String(value));
    }
    if let Some(value) = identity_source {
        extra.insert(
            "identity_source".to_string(),
            serde_json::Value::String(value),
        );
    }
    if let Some(value) = peer_hostname {
        extra.insert(
            "peer_hostname".to_string(),
            serde_json::Value::String(value),
        );
    }
    if let Some(value) = client_ua {
        extra.insert("client_ua".to_string(), serde_json::Value::String(value));
    }
    extra.insert("bytes_up".to_string(), serde_json::Value::from(bytes_up));
    extra.insert(
        "bytes_down".to_string(),
        serde_json::Value::from(bytes_down),
    );
    if let Some(value) = status_code {
        extra.insert("status_code".to_string(), serde_json::Value::from(value));
    }
    extra.insert("blocked".to_string(), serde_json::Value::Bool(blocked));
    if let Some(value) = obfuscation_profile {
        extra.insert(
            "obfuscation_profile".to_string(),
            serde_json::Value::String(value),
        );
    }

    let observed_at = chrono::Utc::now().to_rfc3339();
    let raw = match serde_json::to_string(&EventEnvelope {
        event,
        host,
        time: observed_at.clone(),
        extra,
    }) {
        Ok(raw) => raw,
        Err(e) => {
            error!(%e, event_name = event, %host, "failed to serialize event envelope");
            return;
        }
    };

    let _ = state.events_tx.send(raw.clone());

    if !crate::sync::should_publish_scan_request(event) {
        return;
    }

    let dedupe_key = format!(
        "{:x}",
        Sha256::digest(format!("{event}:{host}:{observed_at}:{raw}").as_bytes())
    );
    let payload_ref = match state.publisher.payload_ref_for_event(&raw, &observed_at) {
        Ok(payload_ref) => payload_ref,
        Err(error) => {
            error!(%error, event_name = event, %host, "failed to prepare sync payload reference");
            return;
        }
    };
    state
        .publisher
        .publish_scan_request(crate::sync::ScanRequest {
            stream_name: "proxy.events".to_string(),
            dedupe_key,
            payload_ref,
            observed_at,
        });
}

#[cfg(test)]
mod tests {
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
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .expect("system resolver should initialize");

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
}
