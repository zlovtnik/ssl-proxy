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
    WirelessAuditFrames,
    WirelessBandwidth,
    WirelessRogueAp,
    WirelessDeauthFlood,
    WirelessSignalAnomaly,
    WirelessPmfAttack,
    WirelessClientInventory,
    WirelessProbeRequests,
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

    fn insert_wireless_audit_frames(
        &mut self,
        batch_id: &str,
        rows: &[WirelessAuditFrameInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_bandwidth(
        &mut self,
        batch_id: &str,
        rows: &[WirelessBandwidthInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_rogue_ap(
        &mut self,
        batch_id: &str,
        rows: &[WirelessRogueApInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_deauth_flood(
        &mut self,
        batch_id: &str,
        rows: &[WirelessDeauthFloodInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_signal_anomaly(
        &mut self,
        batch_id: &str,
        rows: &[WirelessSignalAnomalyInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_pmf_attack(
        &mut self,
        batch_id: &str,
        rows: &[WirelessPmfAttackInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_client_inventory(
        &mut self,
        batch_id: &str,
        rows: &[WirelessClientInventoryInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_probe_requests(
        &mut self,
        batch_id: &str,
        rows: &[WirelessProbeRequestInsert],
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

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessAuditFrameInsert {
    pub row_sequence: i64,
    pub event_type: String,
    pub observed_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: i64,
    pub frame_type: Option<String>,
    pub frame_subtype: String,
    pub bssid: Option<String>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub transmitter_mac: Option<String>,
    pub receiver_mac: Option<String>,
    pub destination_bssid: Option<String>,
    pub ssid: Option<String>,
    pub signal_dbm: Option<i64>,
    pub sequence_number: Option<i64>,
    pub raw_len: i64,
    pub is_retry: i64,
    pub is_more_data: i64,
    pub is_power_save: i64,
    pub is_protected: i64,
    pub is_to_ds: i64,
    pub is_from_ds: i64,
    pub is_handshake: i64,
    pub security_flags: i64,
    pub device_id: Option<String>,
    pub username: Option<String>,
    pub identity_source: String,
    pub tags: String,
    pub anomaly_reasons: String,
    pub raw_json: String,
    pub reg_domain: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessBandwidthInsert {
    pub row_sequence: i64,
    pub schema_version: i64,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: i64,
    pub source_mac: String,
    pub destination_bssid: String,
    pub ssid: Option<String>,
    pub bytes: i64,
    pub frame_count: i64,
    pub retry_count: i64,
    pub more_data_count: i64,
    pub power_save_count: i64,
    pub strongest_signal_dbm: Option<i64>,
    pub hist_under_100: i64,
    pub hist_100_500: i64,
    pub hist_500_1000: i64,
    pub hist_1000_1500: i64,
    pub inter_arrival_p50_ms: Option<i64>,
    pub external_bssid: i64,
    pub threshold_exceeded: i64,
    pub wall_clock_delta_ms: Option<i64>,
    pub window_is_partial: i64,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessRogueApInsert {
    pub row_sequence: i64,
    pub detected_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: i64,
    pub rogue_bssid: String,
    pub ssid: Option<String>,
    pub signal_dbm: Option<i64>,
    pub ssid_impersonation: i64,
    pub raw_json: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessDeauthFloodInsert {
    pub row_sequence: i64,
    pub detected_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: i64,
    pub attacker_mac: Option<String>,
    pub target_bssid: Option<String>,
    pub target_ssid: Option<String>,
    pub deauth_count: i64,
    pub window_secs: i64,
    pub threshold: i64,
    pub signal_dbm: Option<i64>,
    pub raw_json: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessSignalAnomalyInsert {
    pub row_sequence: i64,
    pub detected_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub source_mac: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: i64,
    pub baseline_dbm: i64,
    pub observed_dbm: i64,
    pub dbm_delta: i64,
    pub configured_delta: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessPmfAttackInsert {
    pub row_sequence: i64,
    pub detected_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub target_mac: String,
    pub target_bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: Option<i64>,
    pub attack_tag: String,
    pub reconnect_window_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessClientInventoryInsert {
    pub sensor_id: String,
    pub location_id: String,
    pub snapshot_at: DateTime<Utc>,
    pub client_mac: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub device_id: Option<String>,
    pub username: Option<String>,
    pub identity_source: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    pub signal_dbm: Option<i64>,
    pub is_authorized: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessProbeRequestInsert {
    pub row_sequence: i64,
    pub client_mac: String,
    pub ssid: String,
    pub known_bssid: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub probe_count: i64,
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
        "wireless.audit" => Ok(SinkTarget::WirelessAuditFrames),
        "audit.wireless.bandwidth" => Ok(SinkTarget::WirelessBandwidth),
        "wireless.rogue_ap" | "wireless.alert.rogue_ap" => Ok(SinkTarget::WirelessRogueAp),
        "wireless.deauth_flood" | "wireless.alert.deauth_flood" => {
            Ok(SinkTarget::WirelessDeauthFlood)
        }
        "wireless.signal_anomaly" | "wireless.alert.signal_anomaly" => {
            Ok(SinkTarget::WirelessSignalAnomaly)
        }
        "wireless.pmf_attack" | "wireless.alert.pmf_attack" => Ok(SinkTarget::WirelessPmfAttack),
        "wireless.client_inventory" | "wireless.client.inventory" => {
            Ok(SinkTarget::WirelessClientInventory)
        }
        "wireless.probe_requests" | "wireless.probe.flush" => Ok(SinkTarget::WirelessProbeRequests),
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

pub fn handle_load_with_pool(
    load: OracleLoad,
    pool: &r2d2::Pool<OracleConnectionManager>,
) -> OracleResult {
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
        let mut event_summary: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
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
    wireless_audit_rows: Vec<WirelessAuditFrameInsert>,
    wireless_bandwidth_rows: Vec<WirelessBandwidthInsert>,
    wireless_rogue_ap_rows: Vec<WirelessRogueApInsert>,
    wireless_deauth_flood_rows: Vec<WirelessDeauthFloodInsert>,
    wireless_signal_anomaly_rows: Vec<WirelessSignalAnomalyInsert>,
    wireless_pmf_attack_rows: Vec<WirelessPmfAttackInsert>,
    wireless_client_inventory_rows: Vec<WirelessClientInventoryInsert>,
    wireless_probe_request_rows: Vec<WirelessProbeRequestInsert>,
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
    let wireless_audit_rows = wireless_audit_rows_from_values(target, &values)?;
    let wireless_bandwidth_rows = wireless_bandwidth_rows_from_values(target, &values)?;
    let wireless_rogue_ap_rows = wireless_rogue_ap_rows_from_values(target, &values)?;
    let wireless_deauth_flood_rows = wireless_deauth_flood_rows_from_values(target, &values)?;
    let wireless_signal_anomaly_rows = wireless_signal_anomaly_rows_from_values(target, &values)?;
    let wireless_pmf_attack_rows = wireless_pmf_attack_rows_from_values(target, &values)?;
    let wireless_client_inventory_rows =
        wireless_client_inventory_rows_from_values(target, &values)?;
    let wireless_probe_request_rows = wireless_probe_request_rows_from_values(target, &values)?;
    Ok(ValidatedLoad {
        target,
        payload,
        rows,
        blocked_rows,
        wireless_audit_rows,
        wireless_bandwidth_rows,
        wireless_rogue_ap_rows,
        wireless_deauth_flood_rows,
        wireless_signal_anomaly_rows,
        wireless_pmf_attack_rows,
        wireless_client_inventory_rows,
        wireless_probe_request_rows,
    })
}

fn handle_validated_load(
    load: OracleLoad,
    validated: ValidatedLoad,
    sink: &mut dyn ProxyEventSink,
) -> OracleResult {
    let input_row_count = match validated.target {
        SinkTarget::ProxyEvents => validated.rows.len(),
        SinkTarget::WirelessAuditFrames => validated.wireless_audit_rows.len(),
        SinkTarget::WirelessBandwidth => validated.wireless_bandwidth_rows.len(),
        SinkTarget::WirelessRogueAp => validated.wireless_rogue_ap_rows.len(),
        SinkTarget::WirelessDeauthFlood => validated.wireless_deauth_flood_rows.len(),
        SinkTarget::WirelessSignalAnomaly => validated.wireless_signal_anomaly_rows.len(),
        SinkTarget::WirelessPmfAttack => validated.wireless_pmf_attack_rows.len(),
        SinkTarget::WirelessClientInventory => validated.wireless_client_inventory_rows.len(),
        SinkTarget::WirelessProbeRequests => validated.wireless_probe_request_rows.len(),
    };
    eprintln!(
        "service=oracle-worker event=batch_insert_start batch_id={} target={} row_count={} blocked_event_count={}",
        load.batch_id,
        validated.target.checksum_tag(),
        input_row_count,
        validated.blocked_rows.len(),
    );

    let row_count = match validated.target {
        SinkTarget::ProxyEvents => {
            sink.insert_proxy_events(&load.batch_id, &validated.rows, &validated.blocked_rows)
        }
        SinkTarget::WirelessAuditFrames => {
            sink.insert_wireless_audit_frames(&load.batch_id, &validated.wireless_audit_rows)
        }
        SinkTarget::WirelessBandwidth => {
            sink.insert_wireless_bandwidth(&load.batch_id, &validated.wireless_bandwidth_rows)
        }
        SinkTarget::WirelessRogueAp => {
            sink.insert_wireless_rogue_ap(&load.batch_id, &validated.wireless_rogue_ap_rows)
        }
        SinkTarget::WirelessDeauthFlood => {
            sink.insert_wireless_deauth_flood(&load.batch_id, &validated.wireless_deauth_flood_rows)
        }
        SinkTarget::WirelessSignalAnomaly => sink.insert_wireless_signal_anomaly(
            &load.batch_id,
            &validated.wireless_signal_anomaly_rows,
        ),
        SinkTarget::WirelessPmfAttack => {
            sink.insert_wireless_pmf_attack(&load.batch_id, &validated.wireless_pmf_attack_rows)
        }
        SinkTarget::WirelessClientInventory => sink.insert_wireless_client_inventory(
            &load.batch_id,
            &validated.wireless_client_inventory_rows,
        ),
        SinkTarget::WirelessProbeRequests => sink
            .insert_wireless_probe_requests(&load.batch_id, &validated.wireless_probe_request_rows),
    };
    let row_count = match row_count {
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
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|error| format!("decode payload json: {error}"))?;
    if target == SinkTarget::WirelessProbeRequests {
        if let Some(rows) = value.get("probes").and_then(serde_json::Value::as_array) {
            return Ok(rows.clone());
        }
    }
    if target == SinkTarget::WirelessClientInventory {
        if let Some(clients) = value.get("clients").and_then(serde_json::Value::as_array) {
            let mut rows = Vec::with_capacity(clients.len());
            for client in clients {
                let mut merged = client.as_object().cloned().ok_or_else(|| {
                    "wireless client inventory clients must contain objects".to_string()
                })?;
                if let Some(sensor_id) = value.get("sensor_id") {
                    merged.insert("sensor_id".to_string(), sensor_id.clone());
                }
                if let Some(location_id) = value.get("location_id") {
                    merged.insert("location_id".to_string(), location_id.clone());
                }
                if let Some(snapshot_at) = value
                    .get("snapshot_at")
                    .or_else(|| value.get("observed_at"))
                {
                    merged.insert("snapshot_at".to_string(), snapshot_at.clone());
                }
                rows.push(serde_json::Value::Object(merged));
            }
            return Ok(rows);
        }
    }
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
        _ => return Ok(Vec::new()),
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
        _ => return Ok(Vec::new()),
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

fn wireless_audit_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessAuditFrameInsert>, String> {
    if target != SinkTarget::WirelessAuditFrames {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| wireless_audit_row_from_value(index, row))
        .collect()
}

fn wireless_audit_row_from_value(
    index: usize,
    row: &serde_json::Value,
) -> Result<WirelessAuditFrameInsert, String> {
    let raw_json = raw_json(row, "wireless.audit row")?;
    Ok(WirelessAuditFrameInsert {
        row_sequence: row_sequence(index, "wireless.audit")?,
        event_type: required_string(row, "event_type", "wireless.audit")?,
        observed_at: required_timestamp(row, "observed_at", "wireless.audit")?,
        sensor_id: required_string(row, "sensor_id", "wireless.audit")?,
        location_id: required_string(row, "location_id", "wireless.audit")?,
        interface: required_string(row, "interface", "wireless.audit")?,
        channel: required_i64(row, "channel", "wireless.audit")?,
        frame_type: optional_string(row, "frame_type"),
        frame_subtype: required_string(row, "frame_subtype", "wireless.audit")?,
        bssid: optional_string(row, "bssid"),
        source_mac: optional_string(row, "source_mac"),
        destination_mac: optional_string(row, "destination_mac"),
        transmitter_mac: optional_string(row, "transmitter_mac"),
        receiver_mac: optional_string(row, "receiver_mac"),
        destination_bssid: optional_string(row, "destination_bssid"),
        ssid: optional_string(row, "ssid"),
        signal_dbm: optional_i64(row, "signal_dbm"),
        sequence_number: optional_i64(row, "sequence_number"),
        raw_len: required_i64(row, "raw_len", "wireless.audit")?,
        is_retry: bool_flag(row, "retry"),
        is_more_data: bool_flag(row, "more_data"),
        is_power_save: bool_flag(row, "power_save"),
        is_protected: bool_flag(row, "protected"),
        is_to_ds: bool_flag(row, "to_ds"),
        is_from_ds: bool_flag(row, "from_ds"),
        is_handshake: bool_flag(row, "handshake_captured"),
        security_flags: optional_i64(row, "security_flags").unwrap_or(0),
        device_id: optional_string(row, "device_id"),
        username: optional_string(row, "username"),
        identity_source: optional_string(row, "identity_source")
            .unwrap_or_else(|| "unknown".to_string()),
        tags: json_array_string(row, "tags")?,
        anomaly_reasons: json_array_string(row, "anomaly_reasons")?,
        raw_json,
        reg_domain: optional_string(row, "reg_domain"),
    })
}

fn wireless_bandwidth_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessBandwidthInsert>, String> {
    if target != SinkTarget::WirelessBandwidth {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| wireless_bandwidth_row_from_value(index, row))
        .collect()
}

fn wireless_bandwidth_row_from_value(
    index: usize,
    row: &serde_json::Value,
) -> Result<WirelessBandwidthInsert, String> {
    Ok(WirelessBandwidthInsert {
        row_sequence: row_sequence(index, "audit.wireless.bandwidth")?,
        schema_version: optional_i64(row, "schema_version").unwrap_or(1),
        window_start: required_timestamp(row, "window_start", "audit.wireless.bandwidth")?,
        window_end: required_timestamp(row, "window_end", "audit.wireless.bandwidth")?,
        sensor_id: required_string(row, "sensor_id", "audit.wireless.bandwidth")?,
        location_id: required_string(row, "location_id", "audit.wireless.bandwidth")?,
        interface: required_string(row, "interface", "audit.wireless.bandwidth")?,
        channel: required_i64(row, "channel", "audit.wireless.bandwidth")?,
        source_mac: required_string(row, "source_mac", "audit.wireless.bandwidth")?,
        destination_bssid: required_string(row, "destination_bssid", "audit.wireless.bandwidth")?,
        ssid: optional_string(row, "ssid"),
        bytes: required_i64(row, "bytes", "audit.wireless.bandwidth")?,
        frame_count: required_i64(row, "frame_count", "audit.wireless.bandwidth")?,
        retry_count: optional_i64(row, "retry_count").unwrap_or(0),
        more_data_count: optional_i64(row, "more_data_count").unwrap_or(0),
        power_save_count: optional_i64(row, "power_save_count").unwrap_or(0),
        strongest_signal_dbm: optional_i64(row, "strongest_signal_dbm"),
        hist_under_100: nested_i64(row, "frame_size_histogram", "under_100").unwrap_or(0),
        hist_100_500: nested_i64(row, "frame_size_histogram", "range_100_500").unwrap_or(0),
        hist_500_1000: nested_i64(row, "frame_size_histogram", "range_500_1000").unwrap_or(0),
        hist_1000_1500: nested_i64(row, "frame_size_histogram", "range_1000_1500").unwrap_or(0),
        inter_arrival_p50_ms: optional_i64(row, "inter_arrival_p50_ms"),
        external_bssid: bool_flag(row, "external_bssid"),
        threshold_exceeded: bool_flag(row, "threshold_exceeded"),
        wall_clock_delta_ms: optional_i64(row, "wall_clock_delta_ms"),
        window_is_partial: bool_flag(row, "window_is_partial"),
        published_at: optional_timestamp(row, "published_at")?,
    })
}

fn wireless_rogue_ap_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessRogueApInsert>, String> {
    if target != SinkTarget::WirelessRogueAp {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| wireless_rogue_ap_row_from_value(index, row))
        .collect()
}

fn wireless_rogue_ap_row_from_value(
    index: usize,
    row: &serde_json::Value,
) -> Result<WirelessRogueApInsert, String> {
    let raw_json = raw_json(row, "wireless rogue AP row")?;
    let reasons = row.get("reasons").and_then(serde_json::Value::as_array);
    let ssid_impersonation = bool_flag(row, "ssid_impersonation")
        | i64::from(reasons.is_some_and(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|reason| matches!(reason, "ssid_impersonation" | "bssid_spoofing"))
        }));
    Ok(WirelessRogueApInsert {
        row_sequence: row_sequence(index, "wireless.alert.rogue_ap")?,
        detected_at: timestamp_alias(row, "detected_at", "observed_at", "wireless.alert.rogue_ap")?,
        sensor_id: required_string(row, "sensor_id", "wireless.alert.rogue_ap")?,
        location_id: required_string(row, "location_id", "wireless.alert.rogue_ap")?,
        interface: required_string(row, "interface", "wireless.alert.rogue_ap")?,
        channel: required_i64(row, "channel", "wireless.alert.rogue_ap")?,
        rogue_bssid: string_alias(row, "rogue_bssid", "bssid", "wireless.alert.rogue_ap")?,
        ssid: optional_string(row, "ssid"),
        signal_dbm: optional_i64(row, "signal_dbm"),
        ssid_impersonation,
        raw_json,
    })
}

fn wireless_deauth_flood_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessDeauthFloodInsert>, String> {
    if target != SinkTarget::WirelessDeauthFlood {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| wireless_deauth_flood_row_from_value(index, row))
        .collect()
}

fn wireless_deauth_flood_row_from_value(
    index: usize,
    row: &serde_json::Value,
) -> Result<WirelessDeauthFloodInsert, String> {
    let raw_json = raw_json(row, "wireless deauth flood row")?;
    Ok(WirelessDeauthFloodInsert {
        row_sequence: row_sequence(index, "wireless.alert.deauth_flood")?,
        detected_at: timestamp_alias(
            row,
            "detected_at",
            "observed_at",
            "wireless.alert.deauth_flood",
        )?,
        sensor_id: required_string(row, "sensor_id", "wireless.alert.deauth_flood")?,
        location_id: required_string(row, "location_id", "wireless.alert.deauth_flood")?,
        interface: required_string(row, "interface", "wireless.alert.deauth_flood")?,
        channel: optional_i64(row, "channel").unwrap_or(0),
        attacker_mac: optional_string(row, "attacker_mac")
            .or_else(|| optional_string(row, "source_mac")),
        target_bssid: optional_string(row, "target_bssid")
            .or_else(|| optional_string(row, "bssid")),
        target_ssid: optional_string(row, "target_ssid").or_else(|| optional_string(row, "ssid")),
        deauth_count: i64_alias(
            row,
            "deauth_count",
            "frame_count",
            "wireless.alert.deauth_flood",
        )?,
        window_secs: required_i64(row, "window_secs", "wireless.alert.deauth_flood")?,
        threshold: optional_i64(row, "threshold").unwrap_or(0),
        signal_dbm: optional_i64(row, "signal_dbm"),
        raw_json,
    })
}

fn wireless_signal_anomaly_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessSignalAnomalyInsert>, String> {
    if target != SinkTarget::WirelessSignalAnomaly {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(WirelessSignalAnomalyInsert {
                row_sequence: row_sequence(index, "wireless.alert.signal_anomaly")?,
                detected_at: timestamp_alias(
                    row,
                    "detected_at",
                    "observed_at",
                    "wireless.alert.signal_anomaly",
                )?,
                sensor_id: required_string(row, "sensor_id", "wireless.alert.signal_anomaly")?,
                location_id: required_string(row, "location_id", "wireless.alert.signal_anomaly")?,
                source_mac: required_string(row, "source_mac", "wireless.alert.signal_anomaly")?,
                bssid: optional_string(row, "bssid"),
                ssid: optional_string(row, "ssid"),
                channel: required_i64(row, "channel", "wireless.alert.signal_anomaly")?,
                baseline_dbm: required_i64(row, "baseline_dbm", "wireless.alert.signal_anomaly")?,
                observed_dbm: required_i64(row, "observed_dbm", "wireless.alert.signal_anomaly")?,
                dbm_delta: required_i64(row, "dbm_delta", "wireless.alert.signal_anomaly")?.abs(),
                configured_delta: required_i64(
                    row,
                    "configured_delta",
                    "wireless.alert.signal_anomaly",
                )?,
            })
        })
        .collect()
}

fn wireless_pmf_attack_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessPmfAttackInsert>, String> {
    if target != SinkTarget::WirelessPmfAttack {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(WirelessPmfAttackInsert {
                row_sequence: row_sequence(index, "wireless.alert.pmf_attack")?,
                detected_at: timestamp_alias(
                    row,
                    "detected_at",
                    "observed_at",
                    "wireless.alert.pmf_attack",
                )?,
                sensor_id: required_string(row, "sensor_id", "wireless.alert.pmf_attack")?,
                location_id: required_string(row, "location_id", "wireless.alert.pmf_attack")?,
                target_mac: string_alias(
                    row,
                    "target_mac",
                    "source_mac",
                    "wireless.alert.pmf_attack",
                )?,
                target_bssid: optional_string(row, "target_bssid")
                    .or_else(|| optional_string(row, "bssid")),
                ssid: optional_string(row, "ssid"),
                channel: optional_i64(row, "channel"),
                attack_tag: required_string(row, "attack_tag", "wireless.alert.pmf_attack")?,
                reconnect_window_ms: optional_i64(row, "reconnect_window_ms"),
            })
        })
        .collect()
}

fn wireless_client_inventory_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessClientInventoryInsert>, String> {
    if target != SinkTarget::WirelessClientInventory {
        return Ok(Vec::new());
    }
    rows.iter()
        .map(|row| {
            Ok(WirelessClientInventoryInsert {
                sensor_id: required_string(row, "sensor_id", "wireless.client.inventory")?,
                location_id: required_string(row, "location_id", "wireless.client.inventory")?,
                snapshot_at: required_timestamp(row, "snapshot_at", "wireless.client.inventory")?,
                client_mac: string_alias(
                    row,
                    "client_mac",
                    "source_mac",
                    "wireless.client.inventory",
                )?,
                bssid: optional_string(row, "bssid"),
                ssid: optional_string(row, "ssid"),
                device_id: optional_string(row, "device_id"),
                username: optional_string(row, "username"),
                identity_source: optional_string(row, "identity_source"),
                last_seen: required_timestamp(row, "last_seen", "wireless.client.inventory")?,
                first_seen: required_timestamp(row, "first_seen", "wireless.client.inventory")?,
                signal_dbm: optional_i64(row, "signal_dbm")
                    .or_else(|| optional_i64(row, "last_signal_dbm")),
                is_authorized: bool_flag(row, "is_authorized"),
            })
        })
        .collect()
}

fn wireless_probe_request_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessProbeRequestInsert>, String> {
    if target != SinkTarget::WirelessProbeRequests {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(WirelessProbeRequestInsert {
                row_sequence: row_sequence(index, "wireless.probe.flush")?,
                client_mac: required_string(row, "client_mac", "wireless.probe.flush")?,
                ssid: required_string(row, "ssid", "wireless.probe.flush")?,
                known_bssid: optional_string(row, "known_bssid"),
                first_seen: required_timestamp(row, "first_seen", "wireless.probe.flush")?,
                last_seen: required_timestamp(row, "last_seen", "wireless.probe.flush")?,
                probe_count: required_i64(row, "probe_count", "wireless.probe.flush")?,
            })
        })
        .collect()
}

fn row_sequence(index: usize, context: &str) -> Result<i64, String> {
    let row_number = index
        .checked_add(1)
        .ok_or_else(|| format!("{context} row_sequence exceeds i64"))?;
    i64::try_from(row_number).map_err(|_| format!("{context} row_sequence exceeds i64"))
}

fn raw_json(row: &serde_json::Value, context: &str) -> Result<String, String> {
    serde_json::to_string(row).map_err(|error| format!("encode raw {context} json: {error}"))
}

fn required_string(row: &serde_json::Value, field: &str, context: &str) -> Result<String, String> {
    optional_string(row, field)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{context} row missing {field}"))
}

fn string_alias(
    row: &serde_json::Value,
    first: &str,
    second: &str,
    context: &str,
) -> Result<String, String> {
    optional_string(row, first)
        .or_else(|| optional_string(row, second))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{context} row missing {first}/{second}"))
}

fn optional_string(row: &serde_json::Value, field: &str) -> Option<String> {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required_i64(row: &serde_json::Value, field: &str, context: &str) -> Result<i64, String> {
    optional_i64(row, field).ok_or_else(|| format!("{context} row missing numeric {field}"))
}

fn i64_alias(
    row: &serde_json::Value,
    first: &str,
    second: &str,
    context: &str,
) -> Result<i64, String> {
    optional_i64(row, first)
        .or_else(|| optional_i64(row, second))
        .ok_or_else(|| format!("{context} row missing numeric {first}/{second}"))
}

fn optional_i64(row: &serde_json::Value, field: &str) -> Option<i64> {
    let value = row.get(field)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
}

fn nested_i64(row: &serde_json::Value, object: &str, field: &str) -> Option<i64> {
    let value = row.get(object)?.get(field)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
}

fn bool_flag(row: &serde_json::Value, field: &str) -> i64 {
    i64::from(
        row.get(field)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    )
}

fn required_timestamp(
    row: &serde_json::Value,
    field: &str,
    context: &str,
) -> Result<DateTime<Utc>, String> {
    let value = required_string(row, field, context)?;
    parse_rfc3339_utc(&value, field)
}

fn timestamp_alias(
    row: &serde_json::Value,
    first: &str,
    second: &str,
    context: &str,
) -> Result<DateTime<Utc>, String> {
    let value = optional_string(row, first)
        .or_else(|| optional_string(row, second))
        .ok_or_else(|| format!("{context} row missing {first}/{second}"))?;
    parse_rfc3339_utc(&value, first)
}

fn optional_timestamp(
    row: &serde_json::Value,
    field: &str,
) -> Result<Option<DateTime<Utc>>, String> {
    optional_string(row, field)
        .map(|value| parse_rfc3339_utc(&value, field))
        .transpose()
}

fn parse_rfc3339_utc(value: &str, field: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| format!("decode {field} timestamp: {error}"))
}

fn json_array_string(row: &serde_json::Value, field: &str) -> Result<String, String> {
    match row.get(field) {
        Some(value @ serde_json::Value::Array(_)) => {
            serde_json::to_string(value).map_err(|error| format!("encode {field}: {error}"))
        }
        Some(serde_json::Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(format!("{field} must be a JSON array or string")),
        None => Ok("[]".to_string()),
    }
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
        Ok(Self {
            connection: OracleConnection::Direct(connection),
        })
    }

    pub fn connect_from_pool(pool: &r2d2::Pool<OracleConnectionManager>) -> Result<Self, String> {
        let start = std::time::Instant::now();
        let connection = pool.get().map_err(|error| {
            format!(
                "get Oracle connection from pool (pool_size={} idle={} state={:?}): {}",
                pool.max_size(),
                pool.state().idle_connections,
                pool.state(),
                error_chain(&error)
            )
        })?;
        let duration_ms = start.elapsed().as_millis();
        eprintln!(
            "service=oracle-worker event=connection_acquired pool=true duration_ms={}",
            duration_ms
        );
        Ok(Self {
            connection: OracleConnection::Pooled(connection),
        })
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

    fn insert_wireless_audit_frames(
        &mut self,
        batch_id: &str,
        rows: &[WirelessAuditFrameInsert],
    ) -> Result<u64, String> {
        let result = insert_wireless_audit_frames_transaction(&self.connection, batch_id, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_bandwidth(
        &mut self,
        batch_id: &str,
        rows: &[WirelessBandwidthInsert],
    ) -> Result<u64, String> {
        let result = insert_wireless_bandwidth_transaction(&self.connection, batch_id, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_rogue_ap(
        &mut self,
        batch_id: &str,
        rows: &[WirelessRogueApInsert],
    ) -> Result<u64, String> {
        let result = insert_wireless_rogue_ap_transaction(&self.connection, batch_id, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_deauth_flood(
        &mut self,
        batch_id: &str,
        rows: &[WirelessDeauthFloodInsert],
    ) -> Result<u64, String> {
        let result = insert_wireless_deauth_flood_transaction(&self.connection, batch_id, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_signal_anomaly(
        &mut self,
        batch_id: &str,
        rows: &[WirelessSignalAnomalyInsert],
    ) -> Result<u64, String> {
        let result = insert_wireless_signal_anomaly_transaction(&self.connection, batch_id, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_pmf_attack(
        &mut self,
        batch_id: &str,
        rows: &[WirelessPmfAttackInsert],
    ) -> Result<u64, String> {
        let result = insert_wireless_pmf_attack_transaction(&self.connection, batch_id, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_client_inventory(
        &mut self,
        _batch_id: &str,
        rows: &[WirelessClientInventoryInsert],
    ) -> Result<u64, String> {
        let result = insert_wireless_client_inventory_transaction(&self.connection, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_probe_requests(
        &mut self,
        batch_id: &str,
        rows: &[WirelessProbeRequestInsert],
    ) -> Result<u64, String> {
        let result = insert_wireless_probe_requests_transaction(&self.connection, batch_id, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
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
            .map_err(|error| {
                format!("prepare proxy_events batch insert: {}", error_chain(&error))
            })?;

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
            batch.append_row(&params).map_err(|error| {
                format!(
                    "append proxy_events row host={}: {}",
                    row.host,
                    error_chain(&error)
                )
            })?;
        }
        batch.execute().map_err(|error| {
            format!("execute proxy_events batch insert: {}", error_chain(&error))
        })?;
    }
    upsert_blocked_events_transaction(connection, blocked_rows, &existing_row_sequences)?;
    connection
        .commit()
        .map_err(|error| format!("commit proxy_events batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

fn insert_wireless_audit_frames_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessAuditFrameInsert],
) -> Result<u64, String> {
    if rows.is_empty() {
        return Ok(0);
    }
    let first = rows
        .iter()
        .min_by_key(|row| row.observed_at)
        .ok_or_else(|| "wireless audit batch unexpectedly empty".to_string())?;
    let sensor_params: [&dyn ToSql; 5] = [
        &first.sensor_id,
        &first.location_id,
        &first.interface,
        &first.reg_domain,
        &first.observed_at,
    ];
    connection
        .execute(
            "BEGIN WL_UPSERT_SENSOR(:1, :2, :3, :4, :5); END;",
            &sensor_params,
        )
        .map_err(|error| format!("call WL_UPSERT_SENSOR: {}", error_chain(&error)))?;

    const SQL: &str = r#"
        merge into WL_AUDIT_FRAMES tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 EVENT_TYPE, :4 OBSERVED_AT,
                   :5 SENSOR_ID, :6 LOCATION_ID, :7 INTERFACE, :8 CHANNEL,
                   :9 FRAME_TYPE, :10 FRAME_SUBTYPE, :11 BSSID, :12 SOURCE_MAC,
                   :13 DESTINATION_MAC, :14 TRANSMITTER_MAC, :15 RECEIVER_MAC,
                   :16 DESTINATION_BSSID, :17 SSID, :18 SIGNAL_DBM,
                   :19 SEQUENCE_NUMBER, :20 RAW_LEN, :21 IS_RETRY,
                   :22 IS_MORE_DATA, :23 IS_POWER_SAVE, :24 IS_PROTECTED,
                   :25 IS_TO_DS, :26 IS_FROM_DS, :27 IS_HANDSHAKE,
                   :28 SECURITY_FLAGS, :29 DEVICE_ID, :30 USERNAME,
                   :31 IDENTITY_SOURCE, :32 TAGS, :33 ANOMALY_REASONS,
                   :34 RAW_JSON
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, EVENT_TYPE, OBSERVED_AT, SENSOR_ID, LOCATION_ID,
            INTERFACE, CHANNEL, FRAME_TYPE, FRAME_SUBTYPE, BSSID, SOURCE_MAC,
            DESTINATION_MAC, TRANSMITTER_MAC, RECEIVER_MAC, DESTINATION_BSSID, SSID,
            SIGNAL_DBM, SEQUENCE_NUMBER, RAW_LEN, IS_RETRY, IS_MORE_DATA,
            IS_POWER_SAVE, IS_PROTECTED, IS_TO_DS, IS_FROM_DS, IS_HANDSHAKE,
            SECURITY_FLAGS, DEVICE_ID, USERNAME, IDENTITY_SOURCE, TAGS,
            ANOMALY_REASONS, RAW_JSON
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.EVENT_TYPE, src.OBSERVED_AT,
            src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL,
            src.FRAME_TYPE, src.FRAME_SUBTYPE, src.BSSID, src.SOURCE_MAC,
            src.DESTINATION_MAC, src.TRANSMITTER_MAC, src.RECEIVER_MAC,
            src.DESTINATION_BSSID, src.SSID, src.SIGNAL_DBM, src.SEQUENCE_NUMBER,
            src.RAW_LEN, src.IS_RETRY, src.IS_MORE_DATA, src.IS_POWER_SAVE,
            src.IS_PROTECTED, src.IS_TO_DS, src.IS_FROM_DS, src.IS_HANDSHAKE,
            src.SECURITY_FLAGS, src.DEVICE_ID, src.USERNAME, src.IDENTITY_SOURCE,
            src.TAGS, src.ANOMALY_REASONS, src.RAW_JSON
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 34] = [
            &batch_id,
            &row.row_sequence,
            &row.event_type,
            &row.observed_at,
            &row.sensor_id,
            &row.location_id,
            &row.interface,
            &row.channel,
            &row.frame_type,
            &row.frame_subtype,
            &row.bssid,
            &row.source_mac,
            &row.destination_mac,
            &row.transmitter_mac,
            &row.receiver_mac,
            &row.destination_bssid,
            &row.ssid,
            &row.signal_dbm,
            &row.sequence_number,
            &row.raw_len,
            &row.is_retry,
            &row.is_more_data,
            &row.is_power_save,
            &row.is_protected,
            &row.is_to_ds,
            &row.is_from_ds,
            &row.is_handshake,
            &row.security_flags,
            &row.device_id,
            &row.username,
            &row.identity_source,
            &row.tags,
            &row.anomaly_reasons,
            &row.raw_json,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_AUDIT_FRAMES row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WL_AUDIT_FRAMES batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

fn insert_wireless_bandwidth_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessBandwidthInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_BW_WINDOWS tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 SCHEMA_VERSION, :4 WINDOW_START,
                   :5 WINDOW_END, :6 SENSOR_ID, :7 LOCATION_ID, :8 INTERFACE,
                   :9 CHANNEL, :10 SOURCE_MAC, :11 DESTINATION_BSSID, :12 SSID,
                   :13 BYTES, :14 FRAME_COUNT, :15 RETRY_COUNT, :16 MORE_DATA_COUNT,
                   :17 POWER_SAVE_COUNT, :18 STRONGEST_SIGNAL_DBM, :19 HIST_UNDER_100,
                   :20 HIST_100_500, :21 HIST_500_1000, :22 HIST_1000_1500,
                   :23 INTER_ARRIVAL_P50_MS, :24 EXTERNAL_BSSID, :25 THRESHOLD_EXCEEDED,
                   :26 WALL_CLOCK_DELTA_MS, :27 WINDOW_IS_PARTIAL, :28 PUBLISHED_AT
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, SCHEMA_VERSION, WINDOW_START, WINDOW_END,
            SENSOR_ID, LOCATION_ID, INTERFACE, CHANNEL, SOURCE_MAC, DESTINATION_BSSID,
            SSID, BYTES, FRAME_COUNT, RETRY_COUNT, MORE_DATA_COUNT, POWER_SAVE_COUNT,
            STRONGEST_SIGNAL_DBM, HIST_UNDER_100, HIST_100_500, HIST_500_1000,
            HIST_1000_1500, INTER_ARRIVAL_P50_MS, EXTERNAL_BSSID, THRESHOLD_EXCEEDED,
            WALL_CLOCK_DELTA_MS, WINDOW_IS_PARTIAL, PUBLISHED_AT
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.SCHEMA_VERSION, src.WINDOW_START,
            src.WINDOW_END, src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL,
            src.SOURCE_MAC, src.DESTINATION_BSSID, src.SSID, src.BYTES, src.FRAME_COUNT,
            src.RETRY_COUNT, src.MORE_DATA_COUNT, src.POWER_SAVE_COUNT,
            src.STRONGEST_SIGNAL_DBM, src.HIST_UNDER_100, src.HIST_100_500,
            src.HIST_500_1000, src.HIST_1000_1500, src.INTER_ARRIVAL_P50_MS,
            src.EXTERNAL_BSSID, src.THRESHOLD_EXCEEDED, src.WALL_CLOCK_DELTA_MS,
            src.WINDOW_IS_PARTIAL, src.PUBLISHED_AT
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 28] = [
            &batch_id,
            &row.row_sequence,
            &row.schema_version,
            &row.window_start,
            &row.window_end,
            &row.sensor_id,
            &row.location_id,
            &row.interface,
            &row.channel,
            &row.source_mac,
            &row.destination_bssid,
            &row.ssid,
            &row.bytes,
            &row.frame_count,
            &row.retry_count,
            &row.more_data_count,
            &row.power_save_count,
            &row.strongest_signal_dbm,
            &row.hist_under_100,
            &row.hist_100_500,
            &row.hist_500_1000,
            &row.hist_1000_1500,
            &row.inter_arrival_p50_ms,
            &row.external_bssid,
            &row.threshold_exceeded,
            &row.wall_clock_delta_ms,
            &row.window_is_partial,
            &row.published_at,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_BW_WINDOWS row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .execute("BEGIN WL_BW_MERGE_ALERTS(:1); END;", &[&batch_id])
        .map_err(|error| format!("call WL_BW_MERGE_ALERTS: {}", error_chain(&error)))?;
    connection
        .commit()
        .map_err(|error| format!("commit WL_BW_WINDOWS batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

fn insert_wireless_rogue_ap_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessRogueApInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_ALERT_ROGUE_AP tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 DETECTED_AT, :4 SENSOR_ID,
                   :5 LOCATION_ID, :6 INTERFACE, :7 CHANNEL, :8 ROGUE_BSSID,
                   :9 SSID, :10 SIGNAL_DBM, :11 SSID_IMPERSONATION, :12 RAW_JSON
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID, INTERFACE,
            CHANNEL, ROGUE_BSSID, SSID, SIGNAL_DBM, SSID_IMPERSONATION, RAW_JSON
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT, src.SENSOR_ID,
            src.LOCATION_ID, src.INTERFACE, src.CHANNEL, src.ROGUE_BSSID,
            src.SSID, src.SIGNAL_DBM, src.SSID_IMPERSONATION, src.RAW_JSON
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 12] = [
            &batch_id,
            &row.row_sequence,
            &row.detected_at,
            &row.sensor_id,
            &row.location_id,
            &row.interface,
            &row.channel,
            &row.rogue_bssid,
            &row.ssid,
            &row.signal_dbm,
            &row.ssid_impersonation,
            &row.raw_json,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_ALERT_ROGUE_AP row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WL_ALERT_ROGUE_AP batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

fn insert_wireless_deauth_flood_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessDeauthFloodInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_ALERT_DEAUTH_FLOOD tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 DETECTED_AT, :4 SENSOR_ID,
                   :5 LOCATION_ID, :6 INTERFACE, :7 CHANNEL, :8 ATTACKER_MAC,
                   :9 TARGET_BSSID, :10 TARGET_SSID, :11 DEAUTH_COUNT,
                   :12 WINDOW_SECS, :13 THRESHOLD, :14 SIGNAL_DBM, :15 RAW_JSON
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID, INTERFACE,
            CHANNEL, ATTACKER_MAC, TARGET_BSSID, TARGET_SSID, DEAUTH_COUNT,
            WINDOW_SECS, THRESHOLD, SIGNAL_DBM, RAW_JSON
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT, src.SENSOR_ID,
            src.LOCATION_ID, src.INTERFACE, src.CHANNEL, src.ATTACKER_MAC,
            src.TARGET_BSSID, src.TARGET_SSID, src.DEAUTH_COUNT, src.WINDOW_SECS,
            src.THRESHOLD, src.SIGNAL_DBM, src.RAW_JSON
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 15] = [
            &batch_id,
            &row.row_sequence,
            &row.detected_at,
            &row.sensor_id,
            &row.location_id,
            &row.interface,
            &row.channel,
            &row.attacker_mac,
            &row.target_bssid,
            &row.target_ssid,
            &row.deauth_count,
            &row.window_secs,
            &row.threshold,
            &row.signal_dbm,
            &row.raw_json,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_ALERT_DEAUTH_FLOOD row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection.commit().map_err(|error| {
        format!(
            "commit WL_ALERT_DEAUTH_FLOOD batch: {}",
            error_chain(&error)
        )
    })?;
    Ok(rows.len() as u64)
}

fn insert_wireless_signal_anomaly_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessSignalAnomalyInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_ALERT_SIGNAL_ANOMALY tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 DETECTED_AT, :4 SENSOR_ID,
                   :5 LOCATION_ID, :6 SOURCE_MAC, :7 BSSID, :8 SSID, :9 CHANNEL,
                   :10 BASELINE_DBM, :11 OBSERVED_DBM, :12 DBM_DELTA,
                   :13 CONFIGURED_DELTA
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID, SOURCE_MAC,
            BSSID, SSID, CHANNEL, BASELINE_DBM, OBSERVED_DBM, DBM_DELTA, CONFIGURED_DELTA
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT, src.SENSOR_ID,
            src.LOCATION_ID, src.SOURCE_MAC, src.BSSID, src.SSID, src.CHANNEL,
            src.BASELINE_DBM, src.OBSERVED_DBM, src.DBM_DELTA, src.CONFIGURED_DELTA
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 13] = [
            &batch_id,
            &row.row_sequence,
            &row.detected_at,
            &row.sensor_id,
            &row.location_id,
            &row.source_mac,
            &row.bssid,
            &row.ssid,
            &row.channel,
            &row.baseline_dbm,
            &row.observed_dbm,
            &row.dbm_delta,
            &row.configured_delta,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_ALERT_SIGNAL_ANOMALY row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection.commit().map_err(|error| {
        format!(
            "commit WL_ALERT_SIGNAL_ANOMALY batch: {}",
            error_chain(&error)
        )
    })?;
    Ok(rows.len() as u64)
}

fn insert_wireless_pmf_attack_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessPmfAttackInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_ALERT_PMF_ATTACK tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 DETECTED_AT, :4 SENSOR_ID,
                   :5 LOCATION_ID, :6 TARGET_MAC, :7 TARGET_BSSID, :8 SSID,
                   :9 CHANNEL, :10 ATTACK_TAG, :11 RECONNECT_WINDOW_MS
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID, TARGET_MAC,
            TARGET_BSSID, SSID, CHANNEL, ATTACK_TAG, RECONNECT_WINDOW_MS
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT, src.SENSOR_ID,
            src.LOCATION_ID, src.TARGET_MAC, src.TARGET_BSSID, src.SSID,
            src.CHANNEL, src.ATTACK_TAG, src.RECONNECT_WINDOW_MS
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 11] = [
            &batch_id,
            &row.row_sequence,
            &row.detected_at,
            &row.sensor_id,
            &row.location_id,
            &row.target_mac,
            &row.target_bssid,
            &row.ssid,
            &row.channel,
            &row.attack_tag,
            &row.reconnect_window_ms,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_ALERT_PMF_ATTACK row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WL_ALERT_PMF_ATTACK batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

fn insert_wireless_client_inventory_transaction(
    connection: &Connection,
    rows: &[WirelessClientInventoryInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_CLIENT_INVENTORY tgt
        using (
            select :1 SENSOR_ID, :2 LOCATION_ID, :3 SNAPSHOT_AT, :4 CLIENT_MAC,
                   :5 BSSID, :6 SSID, :7 DEVICE_ID, :8 USERNAME, :9 IDENTITY_SOURCE,
                   :10 LAST_SEEN, :11 FIRST_SEEN, :12 SIGNAL_DBM, :13 IS_AUTHORIZED
            from dual
        ) src
        on (
            tgt.SENSOR_ID = src.SENSOR_ID
            and tgt.SNAPSHOT_AT = src.SNAPSHOT_AT
            and tgt.CLIENT_MAC = src.CLIENT_MAC
        )
        when matched then update set
            tgt.LOCATION_ID = src.LOCATION_ID,
            tgt.BSSID = src.BSSID,
            tgt.SSID = src.SSID,
            tgt.DEVICE_ID = src.DEVICE_ID,
            tgt.USERNAME = src.USERNAME,
            tgt.IDENTITY_SOURCE = src.IDENTITY_SOURCE,
            tgt.LAST_SEEN = src.LAST_SEEN,
            tgt.FIRST_SEEN = src.FIRST_SEEN,
            tgt.SIGNAL_DBM = src.SIGNAL_DBM,
            tgt.IS_AUTHORIZED = src.IS_AUTHORIZED
        when not matched then insert (
            SENSOR_ID, LOCATION_ID, SNAPSHOT_AT, CLIENT_MAC, BSSID, SSID,
            DEVICE_ID, USERNAME, IDENTITY_SOURCE, LAST_SEEN, FIRST_SEEN,
            SIGNAL_DBM, IS_AUTHORIZED
        ) values (
            src.SENSOR_ID, src.LOCATION_ID, src.SNAPSHOT_AT, src.CLIENT_MAC,
            src.BSSID, src.SSID, src.DEVICE_ID, src.USERNAME, src.IDENTITY_SOURCE,
            src.LAST_SEEN, src.FIRST_SEEN, src.SIGNAL_DBM, src.IS_AUTHORIZED
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 13] = [
            &row.sensor_id,
            &row.location_id,
            &row.snapshot_at,
            &row.client_mac,
            &row.bssid,
            &row.ssid,
            &row.device_id,
            &row.username,
            &row.identity_source,
            &row.last_seen,
            &row.first_seen,
            &row.signal_dbm,
            &row.is_authorized,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_CLIENT_INVENTORY client_mac={}: {}",
                row.client_mac,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WL_CLIENT_INVENTORY batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

fn insert_wireless_probe_requests_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessProbeRequestInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_PROBE_REQUESTS tgt
        using (
            select :1 BATCH_ID, :2 CLIENT_MAC, :3 SSID, :4 KNOWN_BSSID,
                   :5 FIRST_SEEN, :6 LAST_SEEN, :7 PROBE_COUNT
            from dual
        ) src
        on (
            tgt.BATCH_ID = src.BATCH_ID
            and tgt.CLIENT_MAC = src.CLIENT_MAC
            and tgt.SSID = src.SSID
        )
        when matched then update set
            tgt.KNOWN_BSSID = src.KNOWN_BSSID,
            tgt.FIRST_SEEN = src.FIRST_SEEN,
            tgt.LAST_SEEN = src.LAST_SEEN,
            tgt.PROBE_COUNT = src.PROBE_COUNT
        when not matched then insert (
            BATCH_ID, CLIENT_MAC, SSID, KNOWN_BSSID, FIRST_SEEN, LAST_SEEN, PROBE_COUNT
        ) values (
            src.BATCH_ID, src.CLIENT_MAC, src.SSID, src.KNOWN_BSSID,
            src.FIRST_SEEN, src.LAST_SEEN, src.PROBE_COUNT
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 7] = [
            &batch_id,
            &row.client_mac,
            &row.ssid,
            &row.known_bssid,
            &row.first_seen,
            &row.last_seen,
            &row.probe_count,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_PROBE_REQUESTS row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WL_PROBE_REQUESTS batch: {}", error_chain(&error)))?;
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
        .map_err(|error| {
            format!(
                "query existing proxy_events batch rows: {}",
                error_chain(&error)
            )
        })?;
    for row_result in rows {
        let row = row_result
            .map_err(|error| format!("read existing proxy_events row: {}", error_chain(&error)))?;
        let row_sequence: i64 = row.get(0).map_err(|error| {
            format!(
                "read existing proxy_events row_sequence: {}",
                error_chain(&error)
            )
        })?;
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
        connection.execute(UPSERT_SQL, &params).map_err(|error| {
            format!(
                "upsert blocked_events row host={}: {}",
                row.host,
                error_chain(&error)
            )
        })?;
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
            SinkTarget::WirelessAuditFrames => "wireless.audit",
            SinkTarget::WirelessBandwidth => "audit.wireless.bandwidth",
            SinkTarget::WirelessRogueAp => "wireless.alert.rogue_ap",
            SinkTarget::WirelessDeauthFlood => "wireless.alert.deauth_flood",
            SinkTarget::WirelessSignalAnomaly => "wireless.alert.signal_anomaly",
            SinkTarget::WirelessPmfAttack => "wireless.alert.pmf_attack",
            SinkTarget::WirelessClientInventory => "wireless.client.inventory",
            SinkTarget::WirelessProbeRequests => "wireless.probe.flush",
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
        WirelessAuditFrameInsert, WirelessBandwidthInsert, WirelessClientInventoryInsert,
        WirelessDeauthFloodInsert, WirelessPmfAttackInsert, WirelessProbeRequestInsert,
        WirelessRogueApInsert, WirelessSignalAnomalyInsert,
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
        wireless_audit_rows: Vec<WirelessAuditFrameInsert>,
        wireless_bandwidth_rows: Vec<WirelessBandwidthInsert>,
        wireless_rogue_ap_rows: Vec<WirelessRogueApInsert>,
        wireless_deauth_flood_rows: Vec<WirelessDeauthFloodInsert>,
        wireless_signal_anomaly_rows: Vec<WirelessSignalAnomalyInsert>,
        wireless_pmf_attack_rows: Vec<WirelessPmfAttackInsert>,
        wireless_client_inventory_rows: Vec<WirelessClientInventoryInsert>,
        wireless_probe_request_rows: Vec<WirelessProbeRequestInsert>,
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

        fn insert_wireless_audit_frames(
            &mut self,
            batch_id: &str,
            rows: &[WirelessAuditFrameInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.wireless_audit_rows.extend_from_slice(rows);
            Ok(rows.len() as u64)
        }

        fn insert_wireless_bandwidth(
            &mut self,
            batch_id: &str,
            rows: &[WirelessBandwidthInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.wireless_bandwidth_rows.extend_from_slice(rows);
            Ok(rows.len() as u64)
        }

        fn insert_wireless_rogue_ap(
            &mut self,
            batch_id: &str,
            rows: &[WirelessRogueApInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.wireless_rogue_ap_rows.extend_from_slice(rows);
            Ok(rows.len() as u64)
        }

        fn insert_wireless_deauth_flood(
            &mut self,
            batch_id: &str,
            rows: &[WirelessDeauthFloodInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.wireless_deauth_flood_rows.extend_from_slice(rows);
            Ok(rows.len() as u64)
        }

        fn insert_wireless_signal_anomaly(
            &mut self,
            batch_id: &str,
            rows: &[WirelessSignalAnomalyInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.wireless_signal_anomaly_rows.extend_from_slice(rows);
            Ok(rows.len() as u64)
        }

        fn insert_wireless_pmf_attack(
            &mut self,
            batch_id: &str,
            rows: &[WirelessPmfAttackInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.wireless_pmf_attack_rows.extend_from_slice(rows);
            Ok(rows.len() as u64)
        }

        fn insert_wireless_client_inventory(
            &mut self,
            batch_id: &str,
            rows: &[WirelessClientInventoryInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.wireless_client_inventory_rows.extend_from_slice(rows);
            Ok(rows.len() as u64)
        }

        fn insert_wireless_probe_requests(
            &mut self,
            batch_id: &str,
            rows: &[WirelessProbeRequestInsert],
        ) -> Result<u64, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            self.batch_ids.push(batch_id.to_string());
            self.wireless_probe_request_rows.extend_from_slice(rows);
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
    fn routes_wireless_audit_loads_to_frame_sink() {
        let mut sink = RecordingSink::default();
        let result = handle_load_with_sink(
            OracleLoad {
                job_id: "job-2".to_string(),
                batch_id: "batch-2".to_string(),
                batch_no: 0,
                stream_name: "wireless.audit".to_string(),
                payload_ref: inline_payload(
                    r#"{"event_type":"wifi_management_frame","observed_at":"2026-04-21T00:00:00Z","sensor_id":"aa:bb:cc:dd:ee:ff","location_id":"lab","interface":"wlan0","channel":6,"frame_type":"management","frame_subtype":"beacon","bssid":"10:20:30:40:50:60","ssid":"corp","signal_dbm":-42,"sequence_number":7,"raw_len":128,"retry":true,"more_data":false,"power_save":false,"protected":true,"to_ds":false,"from_ds":false,"handshake_captured":false,"security_flags":2,"identity_source":"unknown","tags":["threat:signal_anomaly"],"anomaly_reasons":["signal_anomaly"]}"#,
                ),
                cursor_start: "20".to_string(),
                cursor_end: "21".to_string(),
                attempt: 1,
            },
            &mut sink,
        );

        assert_eq!(result.status, "success");
        assert_eq!(result.row_count, 1);
        assert_eq!(sink.wireless_audit_rows.len(), 1);
        assert_eq!(sink.wireless_audit_rows[0].sensor_id, "aa:bb:cc:dd:ee:ff");
        assert_eq!(sink.wireless_audit_rows[0].is_retry, 1);
        assert_eq!(
            sink.wireless_audit_rows[0].tags,
            r#"["threat:signal_anomaly"]"#
        );
    }

    #[test]
    fn routes_wireless_bandwidth_loads_to_bandwidth_sink() {
        let mut sink = RecordingSink::default();
        let result = handle_load_with_sink(
            OracleLoad {
                job_id: "job-bw".to_string(),
                batch_id: "batch-bw".to_string(),
                batch_no: 0,
                stream_name: "audit.wireless.bandwidth".to_string(),
                payload_ref: inline_payload(
                    r#"{"schema_version":1,"event_type":"wireless_bandwidth_window","window_start":"2026-04-21T00:00:00Z","window_end":"2026-04-21T00:01:00Z","sensor_id":"aa:bb:cc:dd:ee:ff","location_id":"lab","interface":"wlan0","channel":6,"source_mac":"aa:bb:cc:dd:ee:01","destination_bssid":"10:20:30:40:50:60","ssid":"corp","bytes":524288001,"frame_count":9,"retry_count":1,"more_data_count":2,"power_save_count":3,"strongest_signal_dbm":-40,"external_bssid":true,"threshold_exceeded":true,"frame_size_histogram":{"under_100":1,"range_100_500":2,"range_500_1000":3,"range_1000_1500":4},"inter_arrival_p50_ms":17,"wall_clock_delta_ms":50,"window_is_partial":false,"published_at":"2026-04-21T00:01:01Z"}"#,
                ),
                cursor_start: "1".to_string(),
                cursor_end: "2".to_string(),
                attempt: 1,
            },
            &mut sink,
        );

        assert_eq!(result.status, "success");
        assert_eq!(sink.wireless_bandwidth_rows.len(), 1);
        let row = &sink.wireless_bandwidth_rows[0];
        assert_eq!(row.threshold_exceeded, 1);
        assert_eq!(row.hist_1000_1500, 4);
    }

    #[test]
    fn routes_wireless_alert_and_inventory_targets() {
        let cases = [
            (
                "wireless.alert.rogue_ap",
                r#"{"event_type":"wireless_rogue_ap","observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor","location_id":"lab","interface":"wlan0","channel":6,"bssid":"aa:bb:cc:dd:ee:01","ssid":"corp","reasons":["bssid_spoofing"]}"#,
            ),
            (
                "wireless.alert.deauth_flood",
                r#"{"event_type":"wireless_deauth_flood","observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor","location_id":"lab","interface":"wlan0","bssid":"aa:bb:cc:dd:ee:02","frame_count":20,"window_secs":30}"#,
            ),
            (
                "wireless.alert.signal_anomaly",
                r#"{"observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor","location_id":"lab","source_mac":"aa:bb:cc:dd:ee:03","channel":6,"baseline_dbm":-80,"observed_dbm":-40,"dbm_delta":40,"configured_delta":25}"#,
            ),
            (
                "wireless.alert.pmf_attack",
                r#"{"observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor","location_id":"lab","target_mac":"aa:bb:cc:dd:ee:04","channel":6,"attack_tag":"threat:pmf_deauth_attack","reconnect_window_ms":3000}"#,
            ),
            (
                "wireless.client.inventory",
                r#"{"sensor_id":"sensor","location_id":"lab","observed_at":"2026-04-21T00:00:00Z","clients":[{"source_mac":"aa:bb:cc:dd:ee:05","first_seen":"2026-04-20T00:00:00Z","last_seen":"2026-04-21T00:00:00Z","last_signal_dbm":-50}]}"#,
            ),
            (
                "wireless.probe.flush",
                r#"{"operation":"flush_probe_batch","probes":[{"ssid":"corp","client_mac":"aa:bb:cc:dd:ee:06","known_bssid":"10:20:30:40:50:60","first_seen":"2026-04-21T00:00:00Z","last_seen":"2026-04-21T00:01:00Z","probe_count":3}]}"#,
            ),
        ];

        for (subject, payload) in cases {
            let mut sink = RecordingSink::default();
            let result = handle_load_with_sink(
                OracleLoad {
                    job_id: format!("job-{subject}"),
                    batch_id: format!("batch-{subject}"),
                    batch_no: 0,
                    stream_name: subject.to_string(),
                    payload_ref: inline_payload(payload),
                    cursor_start: "1".to_string(),
                    cursor_end: "2".to_string(),
                    attempt: 1,
                },
                &mut sink,
            );
            assert_eq!(result.status, "success", "{subject}");
            assert_eq!(result.row_count, 1, "{subject}");
        }
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
        assert_eq!(
            sink_target("wireless.audit").unwrap(),
            SinkTarget::WirelessAuditFrames
        );
        assert_eq!(
            sink_target("wireless.alert.rogue_ap").unwrap(),
            SinkTarget::WirelessRogueAp
        );
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
            error: Some("unique constraint violated".to_string()),
            ..RecordingSink::default()
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
