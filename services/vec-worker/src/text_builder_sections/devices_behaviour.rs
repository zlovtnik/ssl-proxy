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
            "ssid" => self.ssid.as_deref(),
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
    // wg_pubkey intentionally excluded - no semantic value, leaks infra topology
    "first_seen",
    "last_seen",
    "cluster_size",
];

#[derive(Debug, sqlx::FromRow)]
struct DeviceRow {
    mac_id: Option<String>,
    display_name: Option<String>,
    username: Option<String>,
    hostname: Option<String>,
    os_hint: Option<String>,
    mac_hint: Option<String>,
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    cluster_size: Option<i32>,
}

async fn build_device(pool: &PgPool, job: &EmbeddingJob) -> Result<EmbeddingInput, WorkerError> {
    let row = sqlx::query_as::<_, DeviceRow>(
        r#"
        SELECT d.mac_id, d.display_name, d.username, d.hostname, d.os_hint, d.mac_hint,
               d.first_seen, d.last_seen,
               COALESCE(dic.size, 1) AS cluster_size
        FROM devices d
        LEFT JOIN device_identity_clusters dic ON d.mac_id = ANY(dic.mac_ids)
        WHERE d.mac_id = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("device query failed: {e}")))?
    .ok_or_else(|| WorkerError::text_build(format!("device not found: {}", job.source_key)))?;

    Ok(device_row_to_input(&row))
}

#[derive(Debug, sqlx::FromRow)]
struct DeviceBatchRow {
    mac_id: String,
    display_name: Option<String>,
    username: Option<String>,
    hostname: Option<String>,
    os_hint: Option<String>,
    mac_hint: Option<String>,
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    cluster_size: Option<i32>,
}

async fn build_devices_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, DeviceBatchRow>(
        r#"
        SELECT d.mac_id, d.display_name, d.username, d.hostname, d.os_hint, d.mac_hint,
               d.first_seen, d.last_seen,
               COALESCE(dic.size, 1) AS cluster_size
        FROM devices d
        LEFT JOIN device_identity_clusters dic ON d.mac_id = ANY(dic.mac_ids)
        WHERE d.mac_id = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("device batch query failed: {e}")))?;

    for row in rows {
        let device_row = DeviceRow {
            mac_id: Some(row.mac_id.clone()),
            display_name: row.display_name,
            username: row.username,
            hostname: row.hostname,
            os_hint: row.os_hint,
            mac_hint: row.mac_hint,
            first_seen: row.first_seen,
            last_seen: row.last_seen,
            cluster_size: row.cluster_size,
        };
        out.insert(row.mac_id, device_row_to_input(&device_row));
    }
    Ok(())
}

fn device_row_to_input(row: &DeviceRow) -> EmbeddingInput {
    let mut lines = vec!["kind: device".to_string()];
    for field in DEVICE_FIELDS {
        match *field {
            "first_seen" | "last_seen" => {
                let val = match *field {
                    "first_seen" => row.first_seen.as_ref().map(|dt| dt.to_rfc3339()),
                    "last_seen" => row.last_seen.as_ref().map(|dt| dt.to_rfc3339()),
                    _ => unreachable!(),
                };
                if let Some(ref v) = val {
                    if !v.is_empty() {
                        lines.push(format!("{}: {}", field, v));
                    }
                }
            }
            "cluster_size" => {
                if let Some(size) = row.cluster_size {
                    if size > 1 {
                        lines.push(format!("{}: {}", field, size));
                    }
                }
            }
            _ => append_value(&mut lines, field, row.get_field(field)),
        }
    }
    let text = clamp_text(&lines.join("\n"));
    EmbeddingInput {
        text,
        source_observed_at: row.last_seen,
        source_stream_name: None,
        source_sensor_id: None,
        source_location_id: None,
        source_mac: row.mac_id.clone(),
    }
}

impl DeviceRow {
    fn get_field(&self, name: &str) -> Option<&str> {
        match name {
            "mac_id" => self.mac_id.as_deref(),
            "display_name" => self.display_name.as_deref(),
            "username" => self.username.as_deref(),
            "hostname" => self.hostname.as_deref(),
            "os_hint" => self.os_hint.as_deref(),
            "mac_hint" => self.mac_hint.as_deref(),
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
    window_end: Option<chrono::DateTime<chrono::Utc>>,
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

async fn build_behaviour_window(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let row = sqlx::query_as::<_, BehaviourWindowRow>(
        r#"
        SELECT
            embedding_text,
            text_summary,
            window_start,
            window_end,
            sensor_id,
            location_id,
            source_mac,
            event_count,
            protocol_mix,
            frame_type_distribution,
            signal_min_dbm::float8,
            signal_max_dbm::float8,
            signal_avg_dbm::float8,
            retry_count,
            protected_count,
            unprotected_count,
            unique_bssid_count,
            mac_rotation_indicators
        FROM vec_behaviour_snapshots
        WHERE snapshot_id::text = $1
           OR snapshot_key = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("behaviour_window query failed: {e}")))?
    .ok_or_else(|| {
        WorkerError::text_build(format!("behaviour_window not found: {}", job.source_key))
    })?;

    Ok(behaviour_row_to_input(&row))
}

#[derive(Debug, sqlx::FromRow)]
struct BehaviourBatchRow {
    query_key: String,
    embedding_text: Option<String>,
    text_summary: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    window_end: Option<chrono::DateTime<chrono::Utc>>,
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

async fn build_behaviour_windows_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, BehaviourBatchRow>(
        r#"
        SELECT
            CASE
              WHEN snapshot_key = ANY($1::text[]) THEN snapshot_key
              ELSE snapshot_id::text
            END AS query_key,
            embedding_text,
            text_summary,
            window_start,
            window_end,
            sensor_id,
            location_id,
            source_mac,
            event_count,
            protocol_mix,
            frame_type_distribution,
            signal_min_dbm::float8,
            signal_max_dbm::float8,
            signal_avg_dbm::float8,
            retry_count,
            protected_count,
            unprotected_count,
            unique_bssid_count,
            mac_rotation_indicators
        FROM vec_behaviour_snapshots
        WHERE snapshot_id::text = ANY($1::text[])
           OR snapshot_key = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("behaviour_window batch query failed: {e}")))?;

    for row in rows {
        let behaviour_row = BehaviourWindowRow {
            embedding_text: row.embedding_text,
            text_summary: row.text_summary,
            window_start: row.window_start,
            window_end: row.window_end,
            sensor_id: row.sensor_id,
            location_id: row.location_id,
            source_mac: row.source_mac,
            event_count: row.event_count,
            protocol_mix: row.protocol_mix,
            frame_type_distribution: row.frame_type_distribution,
            signal_min_dbm: row.signal_min_dbm,
            signal_max_dbm: row.signal_max_dbm,
            signal_avg_dbm: row.signal_avg_dbm,
            retry_count: row.retry_count,
            protected_count: row.protected_count,
            unprotected_count: row.unprotected_count,
            unique_bssid_count: row.unique_bssid_count,
            mac_rotation_indicators: row.mac_rotation_indicators,
        };
        out.insert(row.query_key, behaviour_row_to_input(&behaviour_row));
    }
    Ok(())
}
