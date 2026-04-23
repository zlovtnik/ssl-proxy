use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleLoad {
    pub job_id: String,
    pub batch_id: String,
    pub batch_no: i32,
    pub stream_name: String,
    pub payload_ref: String,
    pub cursor_start: String,
    pub cursor_end: String,
    pub attempt: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleResult {
    pub job_id: String,
    pub batch_id: String,
    pub status: String,
    pub row_count: i32,
    pub checksum: String,
    pub retryable: bool,
    pub error_class: String,
    pub error_text: String,
    pub finished_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleErrorClass {
    Retryable,
    Permanent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkTarget {
    ProxyEvents,
    WirelessAudit,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ProxyEventRow {
    #[serde(rename = "type")]
    pub event_type: String,
    pub host: String,
    pub peer_ip: Option<String>,
    pub wg_pubkey: Option<String>,
    pub device_id: Option<String>,
    pub identity_source: Option<String>,
    pub peer_hostname: Option<String>,
    pub client_ua: Option<String>,
    pub bytes_up: Option<u64>,
    pub bytes_down: Option<u64>,
    pub status_code: Option<u16>,
    pub blocked: Option<bool>,
    pub obfuscation_profile: Option<String>,
    pub time: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct WirelessAuditRow {
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: u8,
    pub bssid: Option<String>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub transmitter_mac: Option<String>,
    pub receiver_mac: Option<String>,
    pub ssid: Option<String>,
    pub frame_subtype: String,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub frequency_mhz: Option<u16>,
    pub channel_flags: Option<u16>,
    pub data_rate_kbps: Option<u32>,
    pub sequence_number: Option<u16>,
    pub duration_id: Option<u16>,
    pub retry: Option<bool>,
    pub power_save: Option<bool>,
    pub protected: Option<bool>,
    pub to_ds: Option<bool>,
    pub from_ds: Option<bool>,
    pub raw_len: usize,
    pub tags: Vec<String>,
    #[serde(default)]
    pub security_flags: u32,
    pub wps_device_name: Option<String>,
    pub wps_manufacturer: Option<String>,
    pub wps_model_name: Option<String>,
    pub device_fingerprint: Option<String>,
    #[serde(default)]
    pub handshake_captured: bool,
    pub device_id: Option<String>,
    pub username: Option<String>,
    pub identity_source: String,
}

pub fn classify_oracle_error(message: &str) -> OracleErrorClass {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("timeout")
        || normalized.contains("temporarily unavailable")
        || normalized.contains("connection reset")
        || normalized.contains("deadlock")
    {
        OracleErrorClass::Retryable
    } else {
        OracleErrorClass::Permanent
    }
}

pub fn sink_target(stream_name: &str) -> Result<SinkTarget, OracleErrorClass> {
    match stream_name {
        "proxy.events" => Ok(SinkTarget::ProxyEvents),
        "wireless.audit" => Ok(SinkTarget::WirelessAudit),
        _ => Err(OracleErrorClass::Permanent),
    }
}

pub fn resolve_payload(payload_ref: &str) -> Result<String, String> {
    if let Some(b64) = payload_ref.strip_prefix("inline://json/") {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|error| format!("base64 decode: {error}"))?;
        return String::from_utf8(bytes).map_err(|error| format!("utf8: {error}"));
    }

    if let Some(path) = payload_ref.strip_prefix("outbox://") {
        let outbox_dir =
            std::env::var("SYNC_OUTBOX_DIR").unwrap_or_else(|_| "/sync-outbox".to_string());
        let outbox_base = PathBuf::from(&outbox_dir)
            .canonicalize()
            .map_err(|error| format!("canonicalize outbox dir: {error}"))?;
        let resolved = outbox_base.join(path);
        let resolved = resolved
            .canonicalize()
            .map_err(|error| format!("resolve outbox path {}: {error}", resolved.display()))?;
        if !resolved.starts_with(&outbox_base) {
            return Err(format!(
                "invalid outbox path escapes base: {}",
                resolved.display()
            ));
        }
        return std::fs::read_to_string(&resolved)
            .map_err(|error| format!("read outbox {}: {error}", resolved.display()));
    }

    Err(format!("unsupported payload_ref scheme: {payload_ref}"))
}

pub fn handle_load(load: OracleLoad) -> OracleResult {
    let target = match sink_target(&load.stream_name) {
        Ok(target) => target,
        Err(error_class) => {
            return failure_result(
                load.job_id,
                load.batch_id,
                error_class,
                format!("unsupported stream_name {}", load.stream_name),
            );
        }
    };

    let payload = match resolve_payload(&load.payload_ref) {
        Ok(payload) => payload,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };

    let row_count = match validate_payload(target, &payload) {
        Ok(row_count) => row_count,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };

    OracleResult {
        job_id: load.job_id,
        batch_id: load.batch_id,
        status: "success".to_string(),
        row_count,
        checksum: checksum(target, &payload),
        retryable: false,
        error_class: String::new(),
        error_text: String::new(),
        finished_at: Utc::now().to_rfc3339(),
    }
}

fn validate_payload(target: SinkTarget, payload: &str) -> Result<i32, String> {
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|error| format!("decode payload json: {error}"))?;
    match value {
        serde_json::Value::Array(rows) => {
            for row in &rows {
                validate_payload_row(target, row.clone())?;
            }
            i32::try_from(rows.len()).map_err(|_| "payload row count exceeds i32 limit".to_string())
        }
        other => {
            validate_payload_row(target, other)?;
            Ok(1)
        }
    }
}

fn validate_payload_row(target: SinkTarget, row: serde_json::Value) -> Result<(), String> {
    match target {
        SinkTarget::ProxyEvents => {
            let parsed: ProxyEventRow = serde_json::from_value(row)
                .map_err(|error| format!("decode proxy.events row: {error}"))?;
            if parsed.event_type.trim().is_empty() || parsed.host.trim().is_empty() {
                return Err("proxy.events row missing event type or host".to_string());
            }
            Ok(())
        }
        SinkTarget::WirelessAudit => {
            let parsed: WirelessAuditRow = serde_json::from_value(row)
                .map_err(|error| format!("decode wireless.audit row: {error}"))?;
            if parsed.event_type.trim().is_empty()
                || parsed.sensor_id.trim().is_empty()
                || parsed.frame_subtype.trim().is_empty()
            {
                return Err("wireless.audit row missing required identity fields".to_string());
            }
            Ok(())
        }
    }
}

fn checksum(target: SinkTarget, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(target.checksum_tag().as_bytes());
    hasher.update([0]);
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl SinkTarget {
    fn checksum_tag(self) -> &'static str {
        match self {
            SinkTarget::ProxyEvents => "proxy.events",
            SinkTarget::WirelessAudit => "wireless.audit",
        }
    }
}

fn failure_result(
    job_id: String,
    batch_id: String,
    error_class: OracleErrorClass,
    error_text: String,
) -> OracleResult {
    OracleResult {
        job_id,
        batch_id,
        status: "failed".to_string(),
        row_count: 0,
        checksum: String::new(),
        retryable: matches!(error_class, OracleErrorClass::Retryable),
        error_class: match error_class {
            OracleErrorClass::Retryable => "retryable".to_string(),
            OracleErrorClass::Permanent => "permanent".to_string(),
        },
        error_text,
        finished_at: Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::{
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        checksum, classify_oracle_error, handle_load, resolve_payload, sink_target,
        OracleErrorClass, OracleLoad, SinkTarget,
    };

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn inline_payload(payload: &str) -> String {
        format!(
            "inline://json/{}",
            URL_SAFE_NO_PAD.encode(payload.as_bytes())
        )
    }

    fn unique_test_name(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{prefix}-{}-{nanos}", std::process::id())
    }

    fn proxy_payload() -> String {
        inline_payload(
            r#"{"type":"tunnel_open","host":"example.com","time":"2026-04-21T00:00:00Z","peer_ip":"10.0.0.2","wg_pubkey":"peer","device_id":"device-1","identity_source":"registered","peer_hostname":"phone.local","client_ua":"UA","bytes_up":0,"bytes_down":0,"blocked":false,"obfuscation_profile":"default"}"#,
        )
    }

    fn wireless_payload() -> String {
        inline_payload(
            r#"{"event_type":"wifi_management_frame","observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor-1","location_id":"lab","interface":"wlan0","channel":11,"bssid":"10:20:30:40:50:60","source_mac":"10:20:30:40:50:60","destination_mac":"ff:ff:ff:ff:ff:ff","ssid":"CorpWiFi","frame_subtype":"beacon","signal_dbm":-42,"sequence_number":1,"raw_len":44,"tags":["wifi"],"security_flags":10,"wps_device_name":"AP","wps_manufacturer":"Acme","wps_model_name":"Model 1","device_fingerprint":"0123456789abcdef","handshake_captured":false,"device_id":null,"username":null,"identity_source":"mac_observed"}"#,
        )
    }

    #[test]
    fn emits_success_result() {
        let result = handle_load(OracleLoad {
            job_id: "job-1".to_string(),
            batch_id: "batch-1".to_string(),
            batch_no: 0,
            stream_name: "proxy.events".to_string(),
            payload_ref: proxy_payload(),
            cursor_start: "1".to_string(),
            cursor_end: "2".to_string(),
            attempt: 1,
        });

        assert_eq!(result.status, "success");
        assert_eq!(result.row_count, 1);
        assert!(!result.retryable);
    }

    #[test]
    fn accepts_wireless_audit_loads() {
        let result = handle_load(OracleLoad {
            job_id: "job-2".to_string(),
            batch_id: "batch-2".to_string(),
            batch_no: 0,
            stream_name: "wireless.audit".to_string(),
            payload_ref: wireless_payload(),
            cursor_start: "20".to_string(),
            cursor_end: "21".to_string(),
            attempt: 1,
        });

        assert_eq!(result.status, "success");
        assert!(!result.checksum.is_empty());
    }

    #[test]
    fn rejects_unknown_streams() {
        let result = handle_load(OracleLoad {
            job_id: "job-3".to_string(),
            batch_id: "batch-3".to_string(),
            batch_no: 0,
            stream_name: "other.events".to_string(),
            payload_ref: proxy_payload(),
            cursor_start: "20".to_string(),
            cursor_end: "21".to_string(),
            attempt: 1,
        });

        assert_eq!(result.status, "failed");
        assert_eq!(result.error_class, "permanent");
        assert!(!result.retryable);
    }

    #[test]
    fn classifies_retryable_failures() {
        assert_eq!(
            classify_oracle_error("timeout while writing batch"),
            OracleErrorClass::Retryable
        );
    }

    #[test]
    fn classifies_permanent_failures() {
        assert_eq!(
            classify_oracle_error("unique constraint violated"),
            OracleErrorClass::Permanent
        );
    }

    #[test]
    fn resolves_sink_targets() {
        assert_eq!(
            sink_target("proxy.events").unwrap(),
            SinkTarget::ProxyEvents
        );
        assert_eq!(
            sink_target("wireless.audit").unwrap(),
            SinkTarget::WirelessAudit
        );
        assert!(sink_target("unknown").is_err());
    }

    #[test]
    fn resolves_inline_payloads() {
        assert_eq!(
            resolve_payload(&inline_payload(r#"{"ok":true}"#)).unwrap(),
            r#"{"ok":true}"#
        );
    }

    #[test]
    fn rejects_outbox_path_traversal() {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let root = std::env::temp_dir().join(unique_test_name("oracle-worker-outbox"));
        let base = root.join("base");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(root.join("escape.json"), "{}").unwrap();
        std::env::set_var("SYNC_OUTBOX_DIR", &base);

        let error = resolve_payload("outbox://../escape.json").unwrap_err();

        std::env::remove_var("SYNC_OUTBOX_DIR");
        std::fs::remove_dir_all(&root).unwrap();
        assert!(error.contains("invalid outbox path escapes base"));
    }

    #[test]
    fn checksum_is_deterministic_and_target_sensitive() {
        let payload = r#"{"ok":true}"#;
        let first = checksum(SinkTarget::ProxyEvents, payload);
        let second = checksum(SinkTarget::ProxyEvents, payload);
        let other_target = checksum(SinkTarget::WirelessAudit, payload);

        assert_eq!(first, second);
        assert_ne!(first, other_target);
        assert_eq!(first.len(), 64);
    }
}
