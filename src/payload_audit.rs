//! HTTP payload audit extraction and redaction for transparent plaintext flows.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::{config::PayloadAuditConfig, identity::ResolvedIdentity, state::SharedState};

#[derive(Debug, Deserialize, Serialize)]
pub struct PayloadAuditRecord {
    pub observed_at: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub query_keys: Vec<String>,
    pub body: Value,
    pub body_bytes_original: usize,
    pub truncated: bool,
    pub content_type: String,
    pub peer_ip: Option<String>,
    pub wg_pubkey: Option<String>,
    pub device_id: Option<String>,
    pub identity_source: Option<String>,
    pub peer_hostname: Option<String>,
}

pub fn try_parse_http_preview(
    preview: &[u8],
    host: &str,
    identity: &ResolvedIdentity,
    config: &PayloadAuditConfig,
) -> Option<PayloadAuditRecord> {
    let preview = std::str::from_utf8(preview).ok()?;
    let mut lines = preview.lines();
    let request_line = lines.next()?.trim_end_matches('\r');
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next()?.to_string();
    let target = request_parts.next()?;

    if !config
        .allowed_methods
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&method))
    {
        return None;
    }

    let (path, query_keys) = parse_path_and_query_keys(target);
    let mut content_type = String::new();
    let mut content_length = None;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-type") {
            content_type = value.to_string();
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<usize>().ok();
        }
    }

    if !config
        .allowed_content_types
        .iter()
        .any(|allowed| starts_with_ignore_ascii_case(&content_type, allowed))
    {
        return None;
    }

    let body_start = find_body_start(preview.as_bytes())?;
    let body_bytes_available = &preview.as_bytes()[body_start..];
    let body_bytes_original = content_length.unwrap_or(body_bytes_available.len());
    let take = body_bytes_available
        .len()
        .min(config.max_body_bytes)
        .min(body_bytes_original);
    let truncated = content_length.map_or(body_bytes_available.len() > take, |cl| cl > take);
    let body_preview = std::str::from_utf8(&body_bytes_available[..take]).ok()?;
    let mut body = serde_json::from_str::<Value>(body_preview)
        .unwrap_or_else(|_| json!({ "_raw": body_preview }));
    redact_json_value(&mut body);

    Some(PayloadAuditRecord {
        observed_at: crate::time::now_rfc3339(),
        host: host.to_string(),
        method,
        path,
        query_keys,
        body,
        body_bytes_original,
        truncated,
        content_type,
        peer_ip: identity.peer_ip.clone(),
        wg_pubkey: identity.wg_pubkey.clone(),
        device_id: identity.device_id.clone(),
        identity_source: identity.identity_source.clone(),
        peer_hostname: identity.peer_hostname.clone(),
    })
}

pub fn audit_http_preview(
    preview: &[u8],
    host: &str,
    identity: &ResolvedIdentity,
    state: &SharedState,
) -> bool {
    if !state.config.payload_audit.enabled {
        return false;
    }

    let Some(record) = try_parse_http_preview(preview, host, identity, &state.config.payload_audit)
    else {
        return false;
    };
    let json = match serde_json::to_string(&record) {
        Ok(json) => json,
        Err(error) => {
            warn!(%error, "payload audit record serialization failed");
            return false;
        }
    };

    match state
        .publisher
        .publish_payload_audit(&state.config.payload_audit.nats_subject, &json)
    {
        Ok(()) => {
            debug!(host, "payload audit record enqueued");
            true
        }
        Err(error) => {
            warn!(%error, host, "payload audit record publish failed");
            false
        }
    }
}

fn redact_json_value(value: &mut Value) {
    let keys = sensitive_keys();
    redact_json_value_with_keys(value, &keys);
}

fn redact_json_value_with_keys(value: &mut Value, sensitive_keys: &HashSet<&'static str>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if sensitive_keys.contains(key.to_ascii_lowercase().as_str()) {
                    *value = Value::String("[REDACTED]".to_string());
                } else {
                    redact_json_value_with_keys(value, sensitive_keys);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json_value_with_keys(value, sensitive_keys);
            }
        }
        _ => {}
    }
}

fn sensitive_keys() -> HashSet<&'static str> {
    [
        "password",
        "passwd",
        "pass",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "client_secret",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "ssn",
        "credit_card",
        "card_number",
        "cvv",
        "pin",
    ]
    .into_iter()
    .collect()
}

fn parse_path_and_query_keys(target: &str) -> (String, Vec<String>) {
    let Some((path, query)) = target.split_once('?') else {
        return (target.to_string(), Vec::new());
    };
    let query_keys = query
        .split('&')
        .filter_map(|part| {
            let key = part.split_once('=').map(|(key, _)| key).unwrap_or(part);
            if key.is_empty() {
                None
            } else {
                Some(key.to_string())
            }
        })
        .collect();
    (path.to_string(), query_keys)
}

fn find_body_start(preview: &[u8]) -> Option<usize> {
    preview
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            preview
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, state::AppState};
    use hickory_resolver::TokioAsyncResolver;
    use tokio::sync::broadcast;

    fn config() -> PayloadAuditConfig {
        PayloadAuditConfig {
            enabled: true,
            nats_subject: "proxy.payload_audit".to_string(),
            max_body_bytes: 65_536,
            allowed_methods: vec!["POST".to_string(), "PUT".to_string(), "PATCH".to_string()],
            allowed_content_types: vec!["application/json".to_string()],
        }
    }

    fn identity() -> ResolvedIdentity {
        ResolvedIdentity {
            peer_ip: Some("10.0.0.2".to_string()),
            wg_pubkey: Some("pubkey".to_string()),
            device_id: Some("device-1".to_string()),
            identity_source: Some("registered".to_string()),
            peer_hostname: Some("phone.local".to_string()),
            client_ua: None,
        }
    }

    fn preview(method: &str, target: &str, content_type: &str, body: &str) -> Vec<u8> {
        format!(
            "{method} {target} HTTP/1.1\r\nHost: example.com\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn redacts_password_at_any_depth() {
        let body = r#"{"user":{"password":"x"}}"#;
        let record = try_parse_http_preview(
            &preview("POST", "/login", "application/json", body),
            "example.com",
            &identity(),
            &config(),
        )
        .unwrap();

        assert_eq!(record.body["user"]["password"], "[REDACTED]");
    }

    #[test]
    fn redacts_token_case_insensitive() {
        let body = r#"{"Token":"x"}"#;
        let record = try_parse_http_preview(
            &preview("POST", "/login", "application/json", body),
            "example.com",
            &identity(),
            &config(),
        )
        .unwrap();

        assert_eq!(record.body["Token"], "[REDACTED]");
    }

    #[test]
    fn skips_non_post_methods() {
        let record = try_parse_http_preview(
            &preview("GET", "/login", "application/json", "{}"),
            "example.com",
            &identity(),
            &config(),
        );

        assert!(record.is_none());
    }

    #[test]
    fn skips_non_json_content_type() {
        let record = try_parse_http_preview(
            &preview("POST", "/login", "text/html", "{}"),
            "example.com",
            &identity(),
            &config(),
        );

        assert!(record.is_none());
    }

    #[test]
    fn truncates_oversized_body() {
        let mut config = config();
        config.max_body_bytes = 8;
        let record = try_parse_http_preview(
            &preview("POST", "/login", "application/json", r#"{"abcdef":true}"#),
            "example.com",
            &identity(),
            &config,
        )
        .unwrap();

        assert!(record.truncated);
        assert_eq!(record.body_bytes_original, 15);
    }

    #[test]
    fn handles_malformed_json_body() {
        let record = try_parse_http_preview(
            &preview("POST", "/login", "application/json", "not-json"),
            "example.com",
            &identity(),
            &config(),
        )
        .unwrap();

        assert_eq!(record.body["_raw"], "not-json");
    }

    #[test]
    fn extracts_query_keys_without_values() {
        let record = try_parse_http_preview(
            &preview("POST", "/login?foo=1&bar=2", "application/json", "{}"),
            "example.com",
            &identity(),
            &config(),
        )
        .unwrap();

        assert_eq!(record.path, "/login");
        assert_eq!(record.query_keys, vec!["foo", "bar"]);
    }

    #[tokio::test]
    async fn disabled_config_returns_false() {
        let (stats_tx, _) = broadcast::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        let mut config = Config::default();
        config.payload_audit.enabled = false;
        let state = AppState::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new()),
            resolver,
            stats_tx,
            events_tx,
            config,
        );

        assert!(!audit_http_preview(
            &preview("POST", "/login", "application/json", "{}"),
            "example.com",
            &identity(),
            &state,
        ));
    }
}
