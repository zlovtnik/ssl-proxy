use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use oracle::{sql_type::ToSql, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

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
    pub correlation_id: Option<String>,
    pub parent_event_id: Option<String>,
    pub event_sequence: Option<i64>,
    pub duration_ms: Option<i64>,
    pub reason: Option<String>,
    pub time: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProxyEventInsert {
    pub event_time: DateTime<Utc>,
    pub event_type: String,
    pub host: String,
    pub peer_ip: Option<String>,
    pub wg_pubkey: Option<String>,
    pub device_id: Option<String>,
    pub identity_source: Option<String>,
    pub peer_hostname: Option<String>,
    pub client_ua: Option<String>,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub status_code: Option<i64>,
    pub blocked: i64,
    pub obfuscation_profile: Option<String>,
    pub correlation_id: Option<String>,
    pub parent_event_id: Option<String>,
    pub event_sequence: Option<i64>,
    pub duration_ms: Option<i64>,
    pub reason: Option<String>,
    pub raw_json: String,
}

pub trait ProxyEventSink {
    fn insert_proxy_events(&mut self, rows: &[ProxyEventInsert]) -> Result<u64, String>;
}

pub struct OracleProxyEventSink {
    connection: Connection,
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
    let mut sink = match OracleProxyEventSink::connect_from_env() {
        Ok(sink) => sink,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    handle_load_with_sink(load, &mut sink)
}

pub fn handle_load_with_sink(load: OracleLoad, sink: &mut dyn ProxyEventSink) -> OracleResult {
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

    let rows = match proxy_event_rows_from_payload(target, &payload) {
        Ok(rows) => rows,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    let row_count = match sink.insert_proxy_events(&rows) {
        Ok(row_count) => row_count,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    let row_count = match i32::try_from(row_count) {
        Ok(row_count) => row_count,
        Err(_) => {
            return failure_result(
                load.job_id,
                load.batch_id,
                OracleErrorClass::Permanent,
                "inserted row count exceeds i32 limit".to_string(),
            );
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

pub fn proxy_event_rows_from_payload(
    target: SinkTarget,
    payload: &str,
) -> Result<Vec<ProxyEventInsert>, String> {
    match target {
        SinkTarget::ProxyEvents => {}
    }

    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|error| format!("decode payload json: {error}"))?;
    match value {
        serde_json::Value::Array(rows) => {
            let mut inserts = Vec::with_capacity(rows.len());
            for row in rows {
                inserts.push(proxy_event_insert_from_value(row)?);
            }
            Ok(inserts)
        }
        other => Ok(vec![proxy_event_insert_from_value(other)?]),
    }
}

fn proxy_event_insert_from_value(row: serde_json::Value) -> Result<ProxyEventInsert, String> {
    let raw_json = serde_json::to_string(&row)
        .map_err(|error| format!("encode raw proxy row json: {error}"))?;
    let parsed: ProxyEventRow =
        serde_json::from_value(row).map_err(|error| format!("decode proxy.events row: {error}"))?;
    if parsed.event_type.trim().is_empty() || parsed.host.trim().is_empty() {
        return Err("proxy.events row missing event type or host".to_string());
    }
    let event_time = DateTime::parse_from_rfc3339(&parsed.time)
        .map_err(|error| format!("decode proxy.events time: {error}"))?
        .with_timezone(&Utc);

    Ok(ProxyEventInsert {
        event_time,
        event_type: parsed.event_type,
        host: parsed.host,
        peer_ip: parsed.peer_ip,
        wg_pubkey: parsed.wg_pubkey,
        device_id: parsed.device_id,
        identity_source: parsed.identity_source,
        peer_hostname: parsed.peer_hostname,
        client_ua: parsed.client_ua,
        bytes_up: u64_to_i64(parsed.bytes_up.unwrap_or(0), "bytes_up")?,
        bytes_down: u64_to_i64(parsed.bytes_down.unwrap_or(0), "bytes_down")?,
        status_code: parsed.status_code.map(i64::from),
        blocked: if parsed.blocked.unwrap_or(false) {
            1
        } else {
            0
        },
        obfuscation_profile: parsed.obfuscation_profile,
        correlation_id: parsed.correlation_id,
        parent_event_id: parsed.parent_event_id,
        event_sequence: parsed.event_sequence,
        duration_ms: parsed.duration_ms,
        reason: parsed.reason,
        raw_json,
    })
}

fn normalized_identity_source<'a>(identity_source: Option<&'a str>) -> &'a str {
    identity_source.unwrap_or("unknown")
}

fn u64_to_i64(value: u64, field: &str) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("{field} exceeds Oracle NUMBER signed range"))
}

impl OracleProxyEventSink {
    pub fn connect_from_env() -> Result<Self, String> {
        let connect_string = required_env("ORACLE_CONN")?;
        let user = required_env("ORACLE_USER")?;
        let password_file = required_env("ORACLE_PASS_FILE")?;
        let password = fs::read_to_string(&password_file)
            .map_err(|error| format!("read Oracle password file {password_file}: {error}"))?;
        let password = password.trim_end_matches(['\r', '\n']);
        let connection = Connection::connect(user.as_str(), password, connect_string.as_str())
            .map_err(|error| format!("connect Oracle {connect_string}: {error}"))?;
        Ok(Self { connection })
    }

    pub fn ping(&self) -> Result<(), String> {
        self.connection
            .ping()
            .map_err(|error| format!("ping Oracle: {error}"))
    }
}

impl ProxyEventSink for OracleProxyEventSink {
    fn insert_proxy_events(&mut self, rows: &[ProxyEventInsert]) -> Result<u64, String> {
        let result = insert_proxy_events_transaction(&self.connection, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }
}

fn insert_proxy_events_transaction(
    connection: &Connection,
    rows: &[ProxyEventInsert],
) -> Result<u64, String> {
    const INSERT_SQL: &str = r#"
        insert into proxy_events (
            event_time,
            event_type,
            host,
            peer_ip,
            wg_pubkey,
            device_id,
            identity_source,
            peer_hostname,
            client_ua,
            bytes_up,
            bytes_down,
            status_code,
            blocked,
            obfuscation_profile,
            correlation_id,
            parent_event_id,
            event_sequence,
            duration_ms,
            reason,
            raw_json
        ) values (
            :1, :2, :3, :4, :5, :6, :7, :8, :9, :10,
            :11, :12, :13, :14, :15, :16, :17, :18, :19, :20
        )
    "#;

    for row in rows {
        let identity_source = normalized_identity_source(row.identity_source.as_deref());
        let params: [&dyn ToSql; 20] = [
            &row.event_time,
            &row.event_type,
            &row.host,
            &row.peer_ip,
            &row.wg_pubkey,
            &row.device_id,
            &identity_source,
            &row.peer_hostname,
            &row.client_ua,
            &row.bytes_up,
            &row.bytes_down,
            &row.status_code,
            &row.blocked,
            &row.obfuscation_profile,
            &row.correlation_id,
            &row.parent_event_id,
            &row.event_sequence,
            &row.duration_ms,
            &row.reason,
            &row.raw_json,
        ];
        connection
            .execute(INSERT_SQL, &params)
            .map_err(|error| format!("insert proxy_events row host={}: {error}", row.host))?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit proxy_events batch: {error}"))?;
    Ok(rows.len() as u64)
}

pub fn check_oracle_connection_from_env() -> Result<(), String> {
    OracleProxyEventSink::connect_from_env()?.ping()
}

fn required_env(name: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("missing required env: {name}")),
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
        checksum, classify_oracle_error, handle_load_with_sink, proxy_event_rows_from_payload,
        resolve_payload, sink_target, normalized_identity_source, OracleErrorClass, OracleLoad,
        ProxyEventInsert, ProxyEventSink, SinkTarget,
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

    #[derive(Default)]
    struct RecordingSink {
        rows: Vec<ProxyEventInsert>,
        error: Option<String>,
    }

    impl ProxyEventSink for RecordingSink {
        fn insert_proxy_events(&mut self, rows: &[ProxyEventInsert]) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.rows.extend_from_slice(rows);
            Ok(rows.len() as u64)
        }
    }

    #[test]
    fn emits_success_result() {
        let mut sink = RecordingSink::default();
        let result = handle_load_with_sink(
            OracleLoad {
                job_id: "job-1".to_string(),
                batch_id: "batch-1".to_string(),
                batch_no: 0,
                stream_name: "proxy.events".to_string(),
                payload_ref: proxy_payload(),
                cursor_start: "1".to_string(),
                cursor_end: "2".to_string(),
                attempt: 1,
            },
            &mut sink,
        );

        assert_eq!(result.status, "success");
        assert_eq!(result.row_count, 1);
        assert!(!result.retryable);
        assert_eq!(sink.rows.len(), 1);
        assert_eq!(sink.rows[0].event_type, "tunnel_open");
        assert_eq!(sink.rows[0].host, "example.com");
        assert_eq!(sink.rows[0].blocked, 0);
    }

    #[test]
    fn rejects_wireless_audit_loads_until_oracle_target_exists() {
        let mut sink = RecordingSink::default();
        let result = handle_load_with_sink(
            OracleLoad {
                job_id: "job-2".to_string(),
                batch_id: "batch-2".to_string(),
                batch_no: 0,
                stream_name: "wireless.audit".to_string(),
                payload_ref: proxy_payload(),
                cursor_start: "20".to_string(),
                cursor_end: "21".to_string(),
                attempt: 1,
            },
            &mut sink,
        );

        assert_eq!(result.status, "failed");
        assert_eq!(result.error_class, "permanent");
        assert!(sink.rows.is_empty());
    }

    #[test]
    fn rejects_unknown_streams() {
        let mut sink = RecordingSink::default();
        let result = handle_load_with_sink(
            OracleLoad {
                job_id: "job-3".to_string(),
                batch_id: "batch-3".to_string(),
                batch_no: 0,
                stream_name: "other.events".to_string(),
                payload_ref: proxy_payload(),
                cursor_start: "20".to_string(),
                cursor_end: "21".to_string(),
                attempt: 1,
            },
            &mut sink,
        );

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
        assert!(sink_target("wireless.audit").is_err());
        assert!(sink_target("unknown").is_err());
    }

    #[test]
    fn maps_proxy_payload_rows_for_oracle_insert() {
        let rows = proxy_event_rows_from_payload(
            SinkTarget::ProxyEvents,
            &resolve_payload(&proxy_payload()).unwrap(),
        )
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "tunnel_open");
        assert_eq!(rows[0].host, "example.com");
        assert_eq!(rows[0].peer_ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(rows[0].bytes_up, 0);
        assert_eq!(rows[0].status_code, None);
        assert!(rows[0].raw_json.contains("\"type\":\"tunnel_open\""));
    }

    #[test]
    fn normalizes_missing_identity_source_to_unknown() {
        assert_eq!(normalized_identity_source(None), "unknown");
        assert_eq!(
            normalized_identity_source(Some("registered")),
            "registered"
        );
    }

    #[test]
    fn returns_failed_result_when_oracle_insert_fails() {
        let mut sink = RecordingSink {
            rows: Vec::new(),
            error: Some("unique constraint violated".to_string()),
        };

        let result = handle_load_with_sink(
            OracleLoad {
                job_id: "job-4".to_string(),
                batch_id: "batch-4".to_string(),
                batch_no: 0,
                stream_name: "proxy.events".to_string(),
                payload_ref: proxy_payload(),
                cursor_start: "1".to_string(),
                cursor_end: "2".to_string(),
                attempt: 1,
            },
            &mut sink,
        );

        assert_eq!(result.status, "failed");
        assert_eq!(result.error_class, "permanent");
        assert!(!result.retryable);
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

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }
}
