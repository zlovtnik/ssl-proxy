use chrono::{DateTime, Utc};
use serde::Deserialize;

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
