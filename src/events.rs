//! Shared event emission helpers for broadcast and sync-plane publishing.
//!
//! This module centralizes the common event envelope used across proxy, tunnel,
//! and QUIC paths. It does not decide when events should be emitted.

use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info};

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
/// This function wraps the provided `extra` payload inside an `EventEnvelope` (including `type`, `host`, and an Eastern-time RFC3339 `time`), serializes it to JSON, sends the resulting raw JSON string to `state.events_tx`, and emits a `sync.scan.request` message only for events on the sync-plane allowlist. If serialization or payload-reference preparation fails the error is logged and the function returns without publishing downstream.
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
    if should_dedup_event(event, blocked)
        && !state.should_emit_deduped_event(
            event,
            host,
            peer_ip.as_deref(),
            wg_pubkey.as_deref(),
            device_id.as_deref(),
        )
    {
        debug!(
            event_name = event,
            %host,
            "coalesced duplicate event inside deduplication window"
        );
        return;
    }

    let audit_sanitize = audit_sanitize_hostnames();
    let event_host = if audit_sanitize {
        sanitize_hostname(host)
    } else {
        host.to_string()
    };

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
    if audit_sanitize {
        sanitize_extra_host_fields(&mut extra);
    }

    let observed_at = crate::time::now_rfc3339();
    let raw = match serde_json::to_string(&EventEnvelope {
        event,
        host: &event_host,
        time: observed_at.clone(),
        extra,
    }) {
        Ok(raw) => raw,
        Err(e) => {
            error!(%e, event_name = event, %host, "failed to serialize event envelope");
            return;
        }
    };

    if state.events_tx.send(raw.clone()).is_err() {
        state.queue_dashboard_event(&raw, event, &event_host);
    } else {
        state.flush_dashboard_event_queue();
    }

    if !crate::proxy_sync::should_publish_scan_request(event) {
        return;
    }

    debug!(
        target: "sync",
        event_name = event,
        host = %event_host,
        "proxy event qualifies for sync plane — preparing scan request"
    );

    let dedupe_key = format!(
        "{:x}",
        Sha256::digest(format!("{event}:{event_host}:{observed_at}:{raw}").as_bytes())
    );
    let payload_ref = match state.publisher.payload_ref_for_event(&raw, &observed_at) {
        Ok(payload_ref) => payload_ref,
        Err(error) => {
            error!(%error, event_name = event, host = %event_host, "failed to prepare sync payload reference");
            return;
        }
    };
    state
        .publisher
        .publish_scan_request(sync_plane::ScanRequest {
            stream_name: "proxy.events".to_string(),
            dedupe_key,
            payload_ref,
            observed_at,
        });
    info!(
        target: "sync",
        event_name = event,
        host = %event_host,
        "published scan request to sync.scan.request for oracle ingest"
    );
}

fn should_dedup_event(event: &str, blocked: bool) -> bool {
    blocked
        || matches!(
            event,
            "http_blocked" | "block" | "session.blocked" | "tunnel_blocked"
        )
}

fn audit_sanitize_hostnames() -> bool {
    std::env::var("AUDIT_SANITIZE_HOSTNAMES")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn sanitize_extra_host_fields(extra: &mut serde_json::Map<String, serde_json::Value>) {
    for (key, value) in extra.iter_mut() {
        let key = key.to_ascii_lowercase();
        if is_hostname_field(&key) {
            sanitize_json_strings(value);
        } else {
            match value {
                serde_json::Value::Object(map) => sanitize_extra_host_fields(map),
                serde_json::Value::Array(values) => {
                    for value in values {
                        if let serde_json::Value::Object(map) = value {
                            sanitize_extra_host_fields(map);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn is_hostname_field(key: &str) -> bool {
    key == "host"
        || key == "hostname"
        || key == "sni"
        || key.ends_with("_host")
        || key.ends_with("_hostname")
        || key.contains("hostname")
}

fn sanitize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(raw) => {
            *raw = sanitize_hostname(raw);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                sanitize_json_strings(value);
            }
        }
        serde_json::Value::Object(map) => sanitize_extra_host_fields(map),
        _ => {}
    }
}

fn sanitize_hostname(host: &str) -> String {
    let key = std::env::var("AUDIT_HMAC_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(key) = key else {
        return "hmac:unconfigured".to_string();
    };
    format!("hmac:{}", hmac_sha256_first8_hex(key.as_bytes(), host))
}

fn hmac_sha256_first8_hex(key: &[u8], message: &str) -> String {
    const BLOCK_LEN: usize = 64;
    let mut key_block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for index in 0..BLOCK_LEN {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message.as_bytes());
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let digest = outer.finalize();
    hex_prefix(&digest[..8])
}

fn hex_prefix(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
