use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use oracle::{sql_type::ToSql, Connection};
use r2d2_oracle::OracleConnectionManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, env, fs, path::PathBuf};

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut msg = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        msg.push_str(" | caused by: ");
        msg.push_str(&cause.to_string());
        source = cause.source();
    }
    msg
}

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

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BlockedFingerprint {
    #[serde(default)]
    pub tls_ver: Option<String>,
    #[serde(default)]
    pub alpn: Option<String>,
    #[serde(default)]
    pub ja3_lite: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BlockedMetrics {
    #[serde(default)]
    pub attempt_count: Option<i64>,
    #[serde(default)]
    pub blocked_bytes: Option<i64>,
    #[serde(default)]
    pub total_blocked_bytes_approx: Option<i64>,
    #[serde(default)]
    pub frequency_hz: Option<f64>,
    #[serde(default)]
    pub risk_score: Option<f64>,
    #[serde(default)]
    pub iat_ms: Option<i64>,
    #[serde(default)]
    pub consecutive_blocks: Option<i64>,
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
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub blocked_session_id: Option<String>,
    #[serde(default)]
    pub attempt_count: Option<i64>,
    #[serde(default)]
    pub blocked_bytes: Option<i64>,
    #[serde(default)]
    pub frequency_hz: Option<f64>,
    #[serde(default)]
    pub risk_score: Option<f64>,
    #[serde(default)]
    pub consecutive_blocks: Option<i64>,
    #[serde(default)]
    pub iat_ms: Option<i64>,
    #[serde(default)]
    pub tarpit_held_ms: Option<i64>,
    #[serde(default)]
    pub fingerprint: Option<BlockedFingerprint>,
    #[serde(default)]
    pub metrics: Option<BlockedMetrics>,
    #[serde(default)]
    pub resolved_ip: Option<String>,
    #[serde(default)]
    pub asn_org: Option<String>,
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
    fn insert_proxy_events(
        &mut self,
        batch_id: &str,
        rows: &[ProxyEventInsert],
        blocked_rows: &[BlockedEventInsert],
    ) -> Result<u64, String>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct BlockedEventInsert {
    pub row_sequence: i64,
    pub host: String,
    pub blocked_bytes: i64,
    pub frequency_hz: Option<f64>,
    pub risk_score: Option<f64>,
    pub category: Option<String>,
    pub verdict: Option<String>,
    pub tarpit_held_ms: i64,
    pub iat_ms: Option<i64>,
    pub consecutive_blocks: Option<i64>,
    pub last_verdict: Option<String>,
    pub tls_ver: Option<String>,
    pub alpn: Option<String>,
    pub ja3_lite: Option<String>,
    pub resolved_ip: Option<String>,
    pub asn_org: Option<String>,
}

pub enum OracleConnection {
    Direct(Connection),
    Pooled(r2d2::PooledConnection<OracleConnectionManager>),
}

impl std::ops::Deref for OracleConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        match self {
            OracleConnection::Direct(ref conn) => conn,
            OracleConnection::Pooled(ref conn) => conn.deref(),
        }
    }
}

pub struct OracleProxyEventSink {
    connection: OracleConnection,
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
    let validated = match validate_load(&load) {
        Ok(validated) => validated,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    let mut sink = match OracleProxyEventSink::connect_from_env() {
        Ok(sink) => sink,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    handle_validated_load(load, validated, &mut sink)
}

pub fn handle_load_with_pool(load: OracleLoad, pool: &r2d2::Pool<OracleConnectionManager>) -> OracleResult {
    let validated = match validate_load(&load) {
        Ok(validated) => validated,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    let mut sink = match OracleProxyEventSink::connect_from_pool(pool) {
        Ok(sink) => sink,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    handle_validated_load(load, validated, &mut sink)
}

pub fn handle_load_with_sink(load: OracleLoad, sink: &mut dyn ProxyEventSink) -> OracleResult {
    let validated = match validate_load(&load) {
        Ok(validated) => validated,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };

    if !validated.rows.is_empty() {
        let event_types: Vec<&str> = validated
            .rows
            .iter()
            .map(|r| r.event_type.as_str())
            .collect();
        let mut event_summary: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for et in &event_types {
            *event_summary.entry(et).or_insert(0) += 1;
        }
        let summary: Vec<String> = event_summary
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        eprintln!(
            "service=oracle-worker event=batch_validate batch_id={} stream_name={} total_rows={} event_types=\"{}\"",
            load.batch_id,
            load.stream_name,
            validated.rows.len(),
            summary.join(" ")
        );
    }

    handle_validated_load(load, validated, sink)
}

struct ValidatedLoad {
    target: SinkTarget,
    payload: String,
    rows: Vec<ProxyEventInsert>,
    blocked_rows: Vec<BlockedEventInsert>,
}

fn validate_load(load: &OracleLoad) -> Result<ValidatedLoad, String> {
    if load.job_id.is_empty() {
        return Err("job_id must not be empty".to_string());
    }

    let target = sink_target(&load.stream_name)
        .map_err(|_| format!("unsupported stream_name {}", load.stream_name))?;
    let payload = resolve_payload(&load.payload_ref)?;
    let values = payload_rows(target, &payload)?;
    let rows = proxy_event_rows_from_values(target, &values)?;
    let blocked_rows = blocked_event_rows_from_values(target, &values)?;
    Ok(ValidatedLoad {
        target,
        payload,
        rows,
        blocked_rows,
    })
}

fn handle_validated_load(
    load: OracleLoad,
    validated: ValidatedLoad,
    sink: &mut dyn ProxyEventSink,
) -> OracleResult {
    eprintln!(
        "service=oracle-worker event=batch_insert_start batch_id={} proxy_event_count={} blocked_event_count={}",
        load.batch_id,
        validated.rows.len(),
        validated.blocked_rows.len(),
    );

    let row_count =
        match sink.insert_proxy_events(&load.batch_id, &validated.rows, &validated.blocked_rows) {
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
        checksum: checksum(validated.target, &validated.payload),
        retryable: false,
        error_class: String::new(),
        error_text: String::new(),
        finished_at: crate::time::now_rfc3339(),
    }
}

pub fn proxy_event_rows_from_payload(
    target: SinkTarget,
    payload: &str,
) -> Result<Vec<ProxyEventInsert>, String> {
    let rows = payload_rows(target, payload)?;
    proxy_event_rows_from_values(target, &rows)
}

pub fn blocked_event_rows_from_payload(
    target: SinkTarget,
    payload: &str,
) -> Result<Vec<BlockedEventInsert>, String> {
    let rows = payload_rows(target, payload)?;
    blocked_event_rows_from_values(target, &rows)
}

fn payload_rows(target: SinkTarget, payload: &str) -> Result<Vec<serde_json::Value>, String> {
    match target {
        SinkTarget::ProxyEvents => {}
    }

    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|error| format!("decode payload json: {error}"))?;
    match value {
        serde_json::Value::Array(rows) => Ok(rows),
        other => Ok(vec![other]),
    }
}

fn proxy_event_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<ProxyEventInsert>, String> {
    match target {
        SinkTarget::ProxyEvents => {}
    }

    let mut inserts = Vec::with_capacity(rows.len());
    for row in rows {
        inserts.push(proxy_event_insert_from_value(row)?);
    }
    Ok(inserts)
}

fn blocked_event_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<BlockedEventInsert>, String> {
    match target {
        SinkTarget::ProxyEvents => {}
    }

    let mut inserts = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let proxy_row = proxy_event_insert_from_value(row)?;
        if let Some(blocked_row) = blocked_event_insert_from_value(row, &proxy_row)? {
            inserts.push(BlockedEventInsert {
                row_sequence: i64::try_from(index + 1)
                    .map_err(|_| "blocked_events row_sequence exceeds i64".to_string())?,
                ..blocked_row
            });
        }
    }
    Ok(inserts)
}

fn proxy_event_insert_from_value(row: &serde_json::Value) -> Result<ProxyEventInsert, String> {
    let raw_json = serde_json::to_string(row)
        .map_err(|error| format!("encode raw proxy row json: {error}"))?;
    let parsed: ProxyEventRow = serde_json::from_value(row.clone())
        .map_err(|error| format!("decode proxy.events row: {error}"))?;
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

fn blocked_event_insert_from_value(
    row: &serde_json::Value,
    proxy_row: &ProxyEventInsert,
) -> Result<Option<BlockedEventInsert>, String> {
    let parsed: ProxyEventRow = serde_json::from_value(row.clone())
        .map_err(|error| format!("decode blocked.events row: {error}"))?;
    if !parsed.blocked.unwrap_or(false) {
        return Ok(None);
    }

    let blocked_bytes = parsed
        .blocked_bytes
        .or_else(|| {
            parsed
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.blocked_bytes)
        })
        .or_else(|| {
            parsed
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.total_blocked_bytes_approx)
        })
        .unwrap_or_else(|| proxy_row.bytes_up.saturating_add(proxy_row.bytes_down));

    let frequency_hz = parsed.frequency_hz.or_else(|| {
        parsed
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.frequency_hz)
    });
    let risk_score = parsed.risk_score.or_else(|| {
        parsed
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.risk_score)
    });
    let consecutive_blocks = parsed
        .consecutive_blocks
        .or_else(|| {
            parsed
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.consecutive_blocks)
        })
        .or(parsed.attempt_count)
        .or_else(|| {
            parsed
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.attempt_count)
        });
    let iat_ms = parsed
        .iat_ms
        .or_else(|| parsed.metrics.as_ref().and_then(|metrics| metrics.iat_ms));
    let tarpit_held_ms = parsed.tarpit_held_ms.unwrap_or(0);
    let fingerprint = parsed.fingerprint.as_ref();
    let category = parsed
        .category
        .clone()
        .or_else(|| Some("unknown".to_string()));
    let verdict = parsed
        .verdict
        .clone()
        .or_else(|| Some("BLOCKED".to_string()));

    Ok(Some(BlockedEventInsert {
        row_sequence: 0,
        host: proxy_row.host.clone(),
        blocked_bytes,
        frequency_hz,
        risk_score,
        category,
        verdict: verdict.clone(),
        tarpit_held_ms,
        iat_ms,
        consecutive_blocks,
        last_verdict: verdict,
        tls_ver: fingerprint.and_then(|value| value.tls_ver.clone()),
        alpn: fingerprint.and_then(|value| value.alpn.clone()),
        ja3_lite: fingerprint.and_then(|value| value.ja3_lite.clone()),
        resolved_ip: parsed.resolved_ip.clone(),
        asn_org: parsed.asn_org.clone(),
    }))
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
        let start = std::time::Instant::now();
        let connection = Connection::connect(user.as_str(), password, connect_string.as_str())
            .map_err(|error| format!("connect Oracle {connect_string}: {}", error_chain(&error)))?;
        let duration_ms = start.elapsed().as_millis();
        eprintln!(
            "service=oracle-worker event=connection_acquired pool=false duration_ms={}",
            duration_ms
        );
        Ok(Self { connection: OracleConnection::Direct(connection) })
    }

    pub fn connect_from_pool(pool: &r2d2::Pool<OracleConnectionManager>) -> Result<Self, String> {
        let start = std::time::Instant::now();
        let connection = pool.get().map_err(|error| format!(
            "get Oracle connection from pool (pool_size={} idle={} state={:?}): {}",
            pool.max_size(),
            pool.state().idle_connections,
            pool.state(),
            error_chain(&error)
        ))?;
        let duration_ms = start.elapsed().as_millis();
        eprintln!(
            "service=oracle-worker event=connection_acquired pool=true duration_ms={}",
            duration_ms
        );
        Ok(Self { connection: OracleConnection::Pooled(connection) })
    }

    pub fn ping(&self) -> Result<(), String> {
        self.connection
            .ping()
            .map_err(|error| format!("ping Oracle: {}", error_chain(&error)))
    }
}

impl ProxyEventSink for OracleProxyEventSink {
    fn insert_proxy_events(
        &mut self,
        batch_id: &str,
        rows: &[ProxyEventInsert],
        blocked_rows: &[BlockedEventInsert],
    ) -> Result<u64, String> {
        let result = insert_event_batch_transaction(&self.connection, batch_id, rows, blocked_rows);
        if let Err(error) = result {
            let _ = self.connection.rollback();
            if is_proxy_events_batch_row_duplicate(&error) {
                let retry_result =
                    insert_event_batch_transaction(&self.connection, batch_id, rows, blocked_rows);
                if retry_result.is_err() {
                    let _ = self.connection.rollback();
                }
                return retry_result;
            }
            return Err(error);
        }
        result
    }
}

fn insert_event_batch_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[ProxyEventInsert],
    blocked_rows: &[BlockedEventInsert],
) -> Result<u64, String> {
    const INSERT_SQL: &str = r#"
        insert into proxy_events (
            batch_id,
            row_sequence,
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
            :1,
            :2,
            :3,
            :4,
            :5,
            :6,
            :7,
            :8,
            :9,
            :10,
            :11,
            :12,
            :13,
            :14,
            :15,
            :16,
            :17,
            :18,
            :19,
            :20,
            :21,
            :22
        )
    "#;

    let existing_row_sequences = existing_proxy_row_sequences(connection, batch_id)?;
    let pending_rows = pending_proxy_event_rows(rows.len(), &existing_row_sequences)?;

    if !pending_rows.is_empty() {
        let identity_sources = rows
            .iter()
            .map(|row| normalized_identity_source(row.identity_source.as_deref()))
            .collect::<Vec<_>>();
        let mut batch = connection
            .batch(INSERT_SQL, pending_rows.len())
            .build()
            .map_err(|error| format!("prepare proxy_events batch insert: {}", error_chain(&error)))?;

        for (index, row_sequence) in pending_rows {
            let row = &rows[index];
            let params: [&dyn ToSql; 22] = [
                &batch_id,
                &row_sequence,
                &row.event_time,
                &row.event_type,
                &row.host,
                &row.peer_ip,
                &row.wg_pubkey,
                &row.device_id,
                &identity_sources[index],
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
            batch
                .append_row(&params)
                .map_err(|error| format!("append proxy_events row host={}: {}", row.host, error_chain(&error)))?;
        }
        batch
            .execute()
            .map_err(|error| format!("execute proxy_events batch insert: {}", error_chain(&error)))?;
    }
    upsert_blocked_events_transaction(connection, blocked_rows, &existing_row_sequences)?;
    connection
        .commit()
        .map_err(|error| format!("commit proxy_events batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

fn pending_proxy_event_rows(
    row_count: usize,
    existing_row_sequences: &HashSet<i64>,
) -> Result<Vec<(usize, i64)>, String> {
    let mut pending = Vec::with_capacity(row_count);
    for index in 0..row_count {
        let row_number = index
            .checked_add(1)
            .ok_or_else(|| "proxy_events row_sequence exceeds i64".to_string())?;
        let row_sequence = i64::try_from(row_number)
            .map_err(|_| "proxy_events row_sequence exceeds i64".to_string())?;
        if !existing_row_sequences.contains(&row_sequence) {
            pending.push((index, row_sequence));
        }
    }
    Ok(pending)
}

fn is_proxy_events_batch_row_duplicate(message: &str) -> bool {
    let normalized = message.to_ascii_uppercase();
    normalized.contains("ORA-00001") && normalized.contains("PROXY_EVENTS_BATCH_ROW_IDX")
}

fn existing_proxy_row_sequences(
    connection: &Connection,
    batch_id: &str,
) -> Result<HashSet<i64>, String> {
    let mut existing = HashSet::new();
    let rows = connection
        .query(
            "select row_sequence from proxy_events where batch_id = :1",
            &[&batch_id],
        )
        .map_err(|error| format!("query existing proxy_events batch rows: {}", error_chain(&error)))?;
    for row_result in rows {
        let row = row_result.map_err(|error| format!("read existing proxy_events row: {}", error_chain(&error)))?;
        let row_sequence: i64 = row
            .get(0)
            .map_err(|error| format!("read existing proxy_events row_sequence: {}", error_chain(&error)))?;
        existing.insert(row_sequence);
    }
    Ok(existing)
}

fn upsert_blocked_events_transaction(
    connection: &Connection,
    rows: &[BlockedEventInsert],
    existing_proxy_row_sequences: &HashSet<i64>,
) -> Result<(), String> {
    if rows.is_empty() {
        return Ok(());
    }

    const UPSERT_SQL: &str = r#"
        merge into blocked_events be
        using (
            select
                :1 as host,
                :2 as blocked_bytes,
                :3 as frequency_hz,
                :4 as risk_score,
                :5 as category,
                :6 as verdict,
                :7 as tarpit_held_ms,
                :8 as iat_ms,
                :9 as consecutive_blocks,
                :10 as last_verdict,
                :11 as tls_ver,
                :12 as alpn,
                :13 as ja3_lite,
                :14 as resolved_ip,
                :15 as asn_org
            from dual
        ) src
        on (be.host = src.host)
        when matched then update set
            be.blocked_attempts = be.blocked_attempts + 1,
            be.blocked_bytes = be.blocked_bytes + nvl(src.blocked_bytes, 0),
            be.frequency_hz = nvl(
                src.frequency_hz,
                case
                    when (cast(systimestamp as date) - cast(be.first_seen as date)) * 86400 > 0
                    then (be.blocked_attempts + 1) /
                        ((cast(systimestamp as date) - cast(be.first_seen as date)) * 86400)
                    else be.frequency_hz
                end
            ),
            be.verdict = nvl(src.verdict, be.verdict),
            be.category = nvl(src.category, be.category),
            be.risk_score = nvl(
                src.risk_score,
                (be.blocked_bytes + nvl(src.blocked_bytes, 0)) * nvl(src.frequency_hz, be.frequency_hz)
            ),
            be.tarpit_held_ms = be.tarpit_held_ms + nvl(src.tarpit_held_ms, 0),
            be.iat_ms = nvl(src.iat_ms, be.iat_ms),
            be.consecutive_blocks = nvl(src.consecutive_blocks, be.consecutive_blocks + 1),
            be.last_verdict = nvl(src.last_verdict, nvl(src.verdict, be.last_verdict)),
            be.tls_ver = nvl(src.tls_ver, be.tls_ver),
            be.alpn = nvl(src.alpn, be.alpn),
            be.ja3_lite = nvl(src.ja3_lite, be.ja3_lite),
            be.resolved_ip = nvl(src.resolved_ip, be.resolved_ip),
            be.asn_org = nvl(src.asn_org, be.asn_org),
            be.updated_at = systimestamp
        when not matched then insert (
            host,
            blocked_attempts,
            blocked_bytes,
            frequency_hz,
            verdict,
            category,
            risk_score,
            tarpit_held_ms,
            iat_ms,
            consecutive_blocks,
            last_verdict,
            tls_ver,
            alpn,
            ja3_lite,
            resolved_ip,
            asn_org,
            updated_at,
            first_seen
        ) values (
            src.host,
            1,
            nvl(src.blocked_bytes, 0),
            nvl(src.frequency_hz, 0),
            nvl(src.verdict, 'BLOCKED'),
            nvl(src.category, 'unknown'),
            nvl(src.risk_score, nvl(src.blocked_bytes, 0) * nvl(src.frequency_hz, 0)),
            nvl(src.tarpit_held_ms, 0),
            src.iat_ms,
            nvl(src.consecutive_blocks, 1),
            nvl(src.last_verdict, nvl(src.verdict, 'BLOCKED')),
            src.tls_ver,
            src.alpn,
            src.ja3_lite,
            src.resolved_ip,
            src.asn_org,
            systimestamp,
            systimestamp
        )
    "#;

    for row in rows {
        if existing_proxy_row_sequences.contains(&row.row_sequence) {
            continue;
        }
        let params: [&dyn ToSql; 15] = [
            &row.host,
            &row.blocked_bytes,
            &row.frequency_hz,
            &row.risk_score,
            &row.category,
            &row.verdict,
            &row.tarpit_held_ms,
            &row.iat_ms,
            &row.consecutive_blocks,
            &row.last_verdict,
            &row.tls_ver,
            &row.alpn,
            &row.ja3_lite,
            &row.resolved_ip,
            &row.asn_org,
        ];
        connection
            .execute(UPSERT_SQL, &params)
            .map_err(|error| format!("upsert blocked_events row host={}: {}", row.host, error_chain(&error)))?;
    }

    Ok(())
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
        finished_at: crate::time::now_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::{
        collections::HashSet,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        checksum, classify_oracle_error, handle_load_with_sink,
        is_proxy_events_batch_row_duplicate, normalized_identity_source, pending_proxy_event_rows,
        proxy_event_rows_from_payload, resolve_payload, sink_target, BlockedEventInsert,
        OracleErrorClass, OracleLoad, ProxyEventInsert, ProxyEventSink, SinkTarget,
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
            r#"{"type":"tunnel_open","host":"example.com","time":"2026-04-21T00:00:00Z","peer_ip":"10.0.0.2","wg_pubkey":"peer","device_id":"device-1","identity_source":"registered","peer_hostname":"phone.local","client_ua":"UA","bytes_up":0,"bytes_down":0,"blocked":false,"obfuscation_profile":"default","correlation_id":"session-1","event_sequence":1,"kind":"connect","category":"analytics","reason":"allowed_sni","resolved_ips":["192.0.2.10"],"selected_ip":"192.0.2.10","tls_ver":"TLS1.3","alpn":"h2","cipher_suites_count":4,"ja3_lite":"ja3-lite"}"#,
        )
    }

    fn proxy_close_payload() -> String {
        inline_payload(
            r#"{"type":"tunnel_close","host":"example.com","time":"2026-04-21T00:00:01Z","peer_ip":"10.0.0.2","wg_pubkey":"peer","device_id":"device-1","identity_source":"registered","peer_hostname":"phone.local","client_ua":"UA","bytes_up":123,"bytes_down":456,"blocked":false,"obfuscation_profile":"default","correlation_id":"session-1","event_sequence":2,"kind":"connect","category":"analytics","reason":"allowed_sni","duration_ms":789,"resolved_ips":["192.0.2.10"],"selected_ip":"192.0.2.10","tls_ver":"TLS1.3","alpn":"h2","cipher_suites_count":4,"ja3_lite":"ja3-lite"}"#,
        )
    }

    fn blocked_payload() -> String {
        inline_payload(
            r#"{"type":"block","host":"blocked.example","time":"2026-04-21T00:00:00Z","peer_ip":"10.0.0.2","wg_pubkey":"peer","device_id":"device-1","identity_source":"registered","peer_hostname":"phone.local","client_ua":"UA","bytes_up":12,"bytes_down":34,"blocked":true,"category":"analytics","verdict":"HEURISTIC_FLAG_DATA_EXFIL","metrics":{"attempt_count":4,"total_blocked_bytes_approx":46,"frequency_hz":2.5,"risk_score":115.0,"iat_ms":88,"consecutive_blocks":4},"fingerprint":{"tls_ver":"TLS1.3","alpn":"h2","ja3_lite":"ja3-lite-hash"}}"#,
        )
    }

    #[derive(Default)]
    struct RecordingSink {
        batch_ids: Vec<String>,
        rows: Vec<ProxyEventInsert>,
        blocked_rows: Vec<BlockedEventInsert>,
        error: Option<String>,
    }

    impl ProxyEventSink for RecordingSink {
        fn insert_proxy_events(
            &mut self,
            batch_id: &str,
            rows: &[ProxyEventInsert],
            blocked_rows: &[BlockedEventInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.rows.extend_from_slice(rows);
            self.blocked_rows.extend_from_slice(blocked_rows);
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
        assert_eq!(sink.batch_ids, vec!["batch-1".to_string()]);
        assert_eq!(sink.rows.len(), 1);
        assert_eq!(sink.rows[0].event_type, "tunnel_open");
        assert_eq!(sink.rows[0].host, "example.com");
        assert_eq!(sink.rows[0].blocked, 0);
        assert_eq!(sink.rows[0].correlation_id.as_deref(), Some("session-1"));
        assert_eq!(sink.rows[0].event_sequence, Some(1));
        assert_eq!(sink.rows[0].reason.as_deref(), Some("allowed_sni"));
        assert!(sink.rows[0].raw_json.contains("\"ja3_lite\":\"ja3-lite\""));
        assert!(sink.blocked_rows.is_empty());
    }

    #[test]
    fn preserves_enriched_tunnel_close_context() {
        let mut sink = RecordingSink::default();
        let result = handle_load_with_sink(
            OracleLoad {
                job_id: "job-1c".to_string(),
                batch_id: "batch-1c".to_string(),
                batch_no: 0,
                stream_name: "proxy.events".to_string(),
                payload_ref: proxy_close_payload(),
                cursor_start: "1".to_string(),
                cursor_end: "2".to_string(),
                attempt: 1,
            },
            &mut sink,
        );

        assert_eq!(result.status, "success");
        assert_eq!(sink.rows.len(), 1);
        let row = &sink.rows[0];
        assert_eq!(row.event_type, "tunnel_close");
        assert_eq!(row.correlation_id.as_deref(), Some("session-1"));
        assert_eq!(row.event_sequence, Some(2));
        assert_eq!(row.duration_ms, Some(789));
        assert_eq!(row.reason.as_deref(), Some("allowed_sni"));
        assert_eq!(row.bytes_up, 123);
        assert_eq!(row.bytes_down, 456);
        assert!(row.raw_json.contains("\"selected_ip\":\"192.0.2.10\""));
        assert!(row.raw_json.contains("\"tls_ver\":\"TLS1.3\""));
    }

    #[test]
    fn emits_blocked_rows_for_blocked_events() {
        let mut sink = RecordingSink::default();
        let result = handle_load_with_sink(
            OracleLoad {
                job_id: "job-1b".to_string(),
                batch_id: "batch-1b".to_string(),
                batch_no: 0,
                stream_name: "proxy.events".to_string(),
                payload_ref: blocked_payload(),
                cursor_start: "1".to_string(),
                cursor_end: "2".to_string(),
                attempt: 1,
            },
            &mut sink,
        );

        assert_eq!(result.status, "success");
        assert_eq!(result.row_count, 1);
        assert_eq!(sink.batch_ids, vec!["batch-1b".to_string()]);
        assert_eq!(sink.rows.len(), 1);
        assert_eq!(sink.blocked_rows.len(), 1);
        assert_eq!(sink.blocked_rows[0].host, "blocked.example");
        assert_eq!(sink.blocked_rows[0].blocked_bytes, 46);
        assert_eq!(sink.blocked_rows[0].category.as_deref(), Some("analytics"));
        assert_eq!(
            sink.blocked_rows[0].verdict.as_deref(),
            Some("HEURISTIC_FLAG_DATA_EXFIL")
        );
        assert_eq!(sink.blocked_rows[0].tls_ver.as_deref(), Some("TLS1.3"));
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
    fn pending_proxy_event_rows_includes_all_rows_when_batch_is_new() {
        let existing = HashSet::new();

        assert_eq!(
            pending_proxy_event_rows(3, &existing).unwrap(),
            vec![(0, 1), (1, 2), (2, 3)]
        );
    }

    #[test]
    fn pending_proxy_event_rows_skips_fully_inserted_batch() {
        let existing = HashSet::from([1, 2, 3]);

        assert!(pending_proxy_event_rows(3, &existing).unwrap().is_empty());
    }

    #[test]
    fn pending_proxy_event_rows_keeps_only_missing_retry_rows() {
        let existing = HashSet::from([1, 3]);

        assert_eq!(
            pending_proxy_event_rows(4, &existing).unwrap(),
            vec![(1, 2), (3, 4)]
        );
    }

    #[test]
    fn detects_proxy_events_batch_row_duplicate_error() {
        assert!(is_proxy_events_batch_row_duplicate(
            "OCI Error: ORA-00001: unique constraint (USCIS_APP.PROXY_EVENTS_BATCH_ROW_IDX) violated"
        ));
        assert!(!is_proxy_events_batch_row_duplicate(
            "OCI Error: ORA-00001: unique constraint (USCIS_APP.OTHER_IDX) violated"
        ));
        assert!(!is_proxy_events_batch_row_duplicate(
            "OCI Error: ORA-00060: deadlock detected while waiting for resource"
        ));
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
        assert_eq!(normalized_identity_source(Some("registered")), "registered");
    }

    #[test]
    fn returns_failed_result_when_oracle_insert_fails() {
        let mut sink = RecordingSink {
            batch_ids: Vec::new(),
            rows: Vec::new(),
            blocked_rows: Vec::new(),
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
