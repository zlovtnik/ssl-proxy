//! Text content builder — maps an `EmbeddingJob` to its embedding text and metadata.
//!
//! This module mirrors the Ruby `VectorEmbeddings::TextBuilder` reference implementation.
//! Each `embedding_kind` ("event", "device", "behaviour_window") has a dedicated build
//! function that queries the source table and produces identity-stripped semantic text
//! plus associated metadata for the `EmbeddingInput`.

use crate::db::{EmbeddingInput, EmbeddingJob};
use crate::WorkerError;
use sqlx::PgPool;
use tracing::instrument;

/// Build the embedding text and metadata for a job.
///
/// Dispatches to the correct builder based on `job.embedding_kind`.
///
/// # Returns
///
/// A tuple of `(embedding_text, EmbeddingInput)` where `embedding_text` is the
/// identity-stripped semantic text to embed, and `EmbeddingInput` contains the
/// text plus the metadata fields (observed_at, stream_name, sensor_id, location_id, mac).
///
/// # Errors
///
/// Returns `WorkerError::TextBuild` if:
/// - `embedding_kind` is unrecognised
/// - The source row is not found in the database
/// - A database query fails
#[instrument(skip(pool), fields(job_id = %job.job_id, source_table = %job.source_table, source_key = %job.source_key, embedding_kind = %job.embedding_kind))]
pub async fn build_text(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<(String, EmbeddingInput), WorkerError> {
    match job.embedding_kind.as_str() {
        "event" => build_event(pool, job).await,
        "device" => build_device(pool, job).await,
        "behaviour_window" => build_behaviour_window(pool, job).await,
        other => Err(WorkerError::text_build(format!(
            "unsupported embedding_kind: '{}'",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Event builder
// ---------------------------------------------------------------------------

/// Semantic-only fields for events — excludes MACs, IPs, sensor/location identity.
const EVENT_SEMANTIC_FIELDS: &[&str] = &[
    "frame_type",
    "frame_subtype",
    "app_protocol",
    "transport_protocol",
    "security_flags",
    "dns_query_name",
    "mdns_name",
    "dhcp_hostname",
    "wps_device_name",
    "wps_manufacturer",
    "wps_model_name",
    "device_fingerprint",
    "handshake_captured",
    "protected",
    "channel_number",
    "signal_dbm",
    "retry",
    "more_data",
    "power_save",
];

async fn build_event(pool: &PgPool, job: &EmbeddingJob) -> Result<(String, EmbeddingInput), WorkerError> {
    let row = sqlx::query_as::<_, EventRow>(
        r#"
        SELECT
            observed_at,
            stream_name,
            COALESCE(sensor_id, payload->>'sensor_id') AS sensor_id,
            COALESCE(location_id, payload->>'location_id') AS location_id,
            LOWER(COALESCE(source_mac, payload->>'source_mac')) AS source_mac,
            COALESCE(ssid, payload->>'ssid') AS ssid,
            COALESCE(frame_type, payload->>'frame_type') AS frame_type,
            payload->>'frame_subtype' AS frame_subtype,
            COALESCE(channel_number::text, payload->>'channel_number', payload->>'channel') AS channel_number,
            COALESCE(signal_dbm::text, payload->>'signal_dbm') AS signal_dbm,
            COALESCE(retry::text, payload->>'retry') AS retry,
            COALESCE(more_data::text, payload->>'more_data') AS more_data,
            COALESCE(power_save::text, payload->>'power_save') AS power_save,
            COALESCE(protected::text, payload->>'protected') AS protected,
            COALESCE(security_flags::text, payload->>'security_flags') AS security_flags,
            COALESCE(app_protocol, payload->>'app_protocol') AS app_protocol,
            COALESCE(transport_protocol, payload->>'transport_protocol') AS transport_protocol,
            COALESCE(dns_query_name, payload->>'dns_query_name') AS dns_query_name,
            COALESCE(mdns_name, payload->>'mdns_name') AS mdns_name,
            COALESCE(dhcp_hostname, payload->>'dhcp_hostname') AS dhcp_hostname,
            COALESCE(wps_device_name, payload->>'wps_device_name') AS wps_device_name,
            COALESCE(wps_manufacturer, payload->>'wps_manufacturer') AS wps_manufacturer,
            COALESCE(wps_model_name, payload->>'wps_model_name') AS wps_model_name,
            COALESCE(device_fingerprint, payload->>'device_fingerprint') AS device_fingerprint,
            COALESCE(handshake_captured::text, payload->>'handshake_captured') AS handshake_captured
        FROM sync_scan_ingest
        WHERE dedupe_key = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("event query failed: {e}")))?
    .ok_or_else(|| WorkerError::text_build(format!("event not found: {}", job.source_key)))?;

    let mut lines = vec!["kind: event".to_string()];
    for field in EVENT_SEMANTIC_FIELDS {
        append_value(&mut lines, field, row.get_field(field));
    }
    append_value(&mut lines, "ssid", row.ssid.as_deref());
    let text = lines.join("\n");

    let input = EmbeddingInput {
        text,
        source_observed_at: row.observed_at,
        source_stream_name: row.stream_name,
        source_sensor_id: row.sensor_id,
        source_location_id: row.location_id,
        source_mac: row.source_mac,
    };

    Ok((input.text.clone(), input))
}

/// Intermediate row for event queries.
#[derive(Debug, sqlx::FromRow)]
struct EventRow {
    observed_at: Option<chrono::DateTime<chrono::Utc>>,
    stream_name: Option<String>,
    sensor_id: Option<String>,
    location_id: Option<String>,
    source_mac: Option<String>,
    ssid: Option<String>,
    frame_type: Option<String>,
    frame_subtype: Option<String>,
    channel_number: Option<String>,
    signal_dbm: Option<String>,
    retry: Option<String>,
    more_data: Option<String>,
    power_save: Option<String>,
    protected: Option<String>,
    security_flags: Option<String>,
    app_protocol: Option<String>,
    transport_protocol: Option<String>,
    dns_query_name: Option<String>,
    mdns_name: Option<String>,
    dhcp_hostname: Option<String>,
    wps_device_name: Option<String>,
    wps_manufacturer: Option<String>,
    wps_model_name: Option<String>,
    device_fingerprint: Option<String>,
    handshake_captured: Option<String>,
}

impl EventRow {
    fn get_field(&self, name: &str) -> Option<&str> {
        match name {
            "frame_type" => self.frame_type.as_deref(),
            "frame_subtype" => self.frame_subtype.as_deref(),
            "app_protocol" => self.app_protocol.as_deref(),
            "transport_protocol" => self.transport_protocol.as_deref(),
            "security_flags" => self.security_flags.as_deref(),
            "dns_query_name" => self.dns_query_name.as_deref(),
            "mdns_name" => self.mdns_name.as_deref(),
            "dhcp_hostname" => self.dhcp_hostname.as_deref(),
            "wps_device_name" => self.wps_device_name.as_deref(),
            "wps_manufacturer" => self.wps_manufacturer.as_deref(),
            "wps_model_name" => self.wps_model_name.as_deref(),
            "device_fingerprint" => self.device_fingerprint.as_deref(),
            "handshake_captured" => self.handshake_captured.as_deref(),
            "protected" => self.protected.as_deref(),
            "channel_number" => self.channel_number.as_deref(),
            "signal_dbm" => self.signal_dbm.as_deref(),
            "retry" => self.retry.as_deref(),
            "more_data" => self.more_data.as_deref(),
            "power_save" => self.power_save.as_deref(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Device builder
// ---------------------------------------------------------------------------

const DEVICE_FIELDS: &[&str] = &[
    "mac_id",
    "display_name",
    "username",
    "hostname",
    "os_hint",
    "mac_hint",
    "wg_pubkey",
    "first_seen",
    "last_seen",
];

#[derive(Debug, sqlx::FromRow)]
struct DeviceRow {
    mac_id: Option<String>,
    display_name: Option<String>,
    username: Option<String>,
    hostname: Option<String>,
    os_hint: Option<String>,
    mac_hint: Option<String>,
    wg_pubkey: Option<String>,
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

async fn build_device(pool: &PgPool, job: &EmbeddingJob) -> Result<(String, EmbeddingInput), WorkerError> {
    let row = sqlx::query_as::<_, DeviceRow>(
        r#"
        SELECT mac_id, display_name, username, hostname, os_hint, mac_hint, wg_pubkey, first_seen, last_seen
        FROM devices
        WHERE mac_id = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("device query failed: {e}")))?
    .ok_or_else(|| WorkerError::text_build(format!("device not found: {}", job.source_key)))?;

    let mut lines = vec!["kind: device".to_string()];
    for field in DEVICE_FIELDS {
        if let Some(val) = row.get_field(field) {
            if !val.is_empty() {
                lines.push(format!("{}: {}", field, val));
            }
        }
    }
    let text = lines.join("\n");

    let input = EmbeddingInput {
        text,
        source_observed_at: row.last_seen,
        source_stream_name: None,
        source_sensor_id: None,
        source_location_id: None,
        source_mac: row.mac_id,
    };

    Ok((input.text.clone(), input))
}

impl DeviceRow {
    fn get_field(&self, name: &str) -> Option<String> {
        match name {
            "mac_id" => self.mac_id.clone(),
            "display_name" => self.display_name.clone(),
            "username" => self.username.clone(),
            "hostname" => self.hostname.clone(),
            "os_hint" => self.os_hint.clone(),
            "mac_hint" => self.mac_hint.clone(),
            "wg_pubkey" => self.wg_pubkey.clone(),
            "first_seen" => self.first_seen.as_ref().map(|dt| dt.to_rfc3339()),
            "last_seen" => self.last_seen.as_ref().map(|dt| dt.to_rfc3339()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Behaviour window builder
// ---------------------------------------------------------------------------

/// Snapshot fields used when `embedding_text` is not available.
const SNAPSHOT_FIELDS: &[&str] = &[
    "source_mac",
    "location_id",
    "sensor_id",
    "window_start",
    "window_end",
    "event_count",
    "protocol_mix",
    "frame_type_distribution",
    "signal_min_dbm",
    "signal_max_dbm",
    "signal_avg_dbm",
    "retry_count",
    "protected_count",
    "unprotected_count",
    "unique_bssid_count",
    "mac_rotation_indicators",
];

#[derive(Debug, sqlx::FromRow)]
struct BehaviourWindowRow {
    embedding_text: Option<String>,
    text_summary: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    sensor_id: Option<String>,
    location_id: Option<String>,
    source_mac: Option<String>,
    event_count: Option<i64>,
    protocol_mix: Option<serde_json::Value>,
    frame_type_distribution: Option<serde_json::Value>,
    signal_min_dbm: Option<f64>,
    signal_max_dbm: Option<f64>,
    signal_avg_dbm: Option<f64>,
    retry_count: Option<i64>,
    protected_count: Option<i64>,
    unprotected_count: Option<i64>,
    unique_bssid_count: Option<i64>,
    mac_rotation_indicators: Option<serde_json::Value>,
}

async fn build_behaviour_window(pool: &PgPool, job: &EmbeddingJob) -> Result<(String, EmbeddingInput), WorkerError> {
    let row = sqlx::query_as::<_, BehaviourWindowRow>(
        r#"
        SELECT
            embedding_text,
            text_summary,
            window_start,
            sensor_id,
            location_id,
            source_mac,
            event_count,
            protocol_mix,
            frame_type_distribution,
            signal_min_dbm,
            signal_max_dbm,
            signal_avg_dbm,
            retry_count,
            protected_count,
            unprotected_count,
            unique_bssid_count,
            mac_rotation_indicators
        FROM vec_behaviour_snapshots
        WHERE snapshot_id::text = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("behaviour_window query failed: {e}")))?
    .ok_or_else(|| WorkerError::text_build(format!("behaviour_window not found: {}", job.source_key)))?;

    // Prefer identity-stripped embedding_text; fall back to text_summary, then field-based construction.
    let text = if let Some(ref et) = row.embedding_text {
        if !et.is_empty() {
            et.clone()
        } else if let Some(ref ts) = row.text_summary {
            if !ts.is_empty() {
                ts.clone()
            } else {
                build_snapshot_fallback(&row)
            }
        } else {
            build_snapshot_fallback(&row)
        }
    } else if let Some(ref ts) = row.text_summary {
        if !ts.is_empty() {
            ts.clone()
        } else {
            build_snapshot_fallback(&row)
        }
    } else {
        build_snapshot_fallback(&row)
    };

    let input = EmbeddingInput {
        text,
        source_observed_at: row.window_start,
        source_stream_name: None,
        source_sensor_id: row.sensor_id,
        source_location_id: row.location_id,
        source_mac: row.source_mac,
    };

    Ok((input.text.clone(), input))
}

/// Build a fallback text from individual snapshot fields when no pre-built text exists.
fn build_snapshot_fallback(row: &BehaviourWindowRow) -> String {
    let mut lines = vec!["kind: behaviour_window".to_string()];
    for field in SNAPSHOT_FIELDS {
        let val: Option<String> = match *field {
            "source_mac" => row.source_mac.clone(),
            "location_id" => row.location_id.clone(),
            "sensor_id" => row.sensor_id.clone(),
            "window_start" => row.window_start.as_ref().map(|dt| dt.to_rfc3339()),
            "window_end" => None,
            "event_count" => row.event_count.map(|v| v.to_string()),
            "protocol_mix" => row.protocol_mix.as_ref().map(normalize_json),
            "frame_type_distribution" => row.frame_type_distribution.as_ref().map(normalize_json),
            "signal_min_dbm" => row.signal_min_dbm.map(|v| v.to_string()),
            "signal_max_dbm" => row.signal_max_dbm.map(|v| v.to_string()),
            "signal_avg_dbm" => row.signal_avg_dbm.map(|v| v.to_string()),
            "retry_count" => row.retry_count.map(|v| v.to_string()),
            "protected_count" => row.protected_count.map(|v| v.to_string()),
            "unprotected_count" => row.unprotected_count.map(|v| v.to_string()),
            "unique_bssid_count" => row.unique_bssid_count.map(|v| v.to_string()),
            "mac_rotation_indicators" => row.mac_rotation_indicators.as_ref().map(normalize_json),
            _ => None,
        };
        if let Some(ref v) = val {
            if !v.is_empty() {
                lines.push(format!("{}: {}", field, v));
            }
        }
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Append a `"field: value"` line if the value is non-empty.
fn append_value(lines: &mut Vec<String>, field: &str, value: Option<&str>) {
    match value {
        Some(v) if !v.is_empty() => lines.push(format!("{}: {}", field, v)),
        _ => {}
    }
}

/// Normalise a JSON value for text output, matching the Ruby `normalize_json`.
fn normalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, &serde_json::Value> =
                map.iter().map(|(k, v)| (k.clone(), v)).collect();
            serde_json::to_string(&sorted).unwrap_or_default()
        }
        serde_json::Value::Array(arr) => {
            let mut sorted: Vec<String> = arr.iter().map(|v| v.to_string()).collect();
            sorted.sort();
            serde_json::to_string(&sorted).unwrap_or_default()
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_value_skips_none() {
        let mut lines = vec!["kind: event".to_string()];
        append_value(&mut lines, "field_a", None);
        append_value(&mut lines, "field_b", Some(""));
        append_value(&mut lines, "field_c", Some("value"));
        assert_eq!(lines, vec!["kind: event", "field_c: value"]);
    }

    #[test]
    fn normalize_json_object_sorts_keys() {
        let mut map = serde_json::Map::new();
        map.insert("z".into(), serde_json::json!(1));
        map.insert("a".into(), serde_json::json!(2));
        let val = serde_json::Value::Object(map);
        let result = normalize_json(&val);
        // Verify keys appear in sorted order (a before z)
        let a_pos = result.find(r#""a":2"#).expect("key 'a:2' not found");
        let z_pos = result.find(r#""z":1"#).expect("key 'z:1' not found");
        assert!(a_pos < z_pos, "keys should be sorted: 'a' before 'z'");
    }
}