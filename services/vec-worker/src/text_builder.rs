//! Text content builder - maps an `EmbeddingJob` to its embedding text and metadata.
//!
//! This module mirrors the Ruby `VectorEmbeddings::TextBuilder` reference implementation.
//! Each supported `embedding_kind` has a dedicated build
//! function that queries the source table and produces identity-stripped semantic text
//! plus associated metadata for the `EmbeddingInput`.

use crate::db::{EmbeddingInput, EmbeddingJob};
use crate::sequence_score;
use crate::WorkerError;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::instrument;

// ---------------------------------------------------------------------------
// Token budget
// ---------------------------------------------------------------------------

/// Hard token limit for the configured embedding model.
/// Matches `VECTOR_EMBEDDING_DIMENSIONS`-adjacent models (nomic-embed-text,
/// all-minilm, bge-small, etc.) which share a 512-token context window.
/// The runtime config `max_input_tokens` (default 512) provides a coarser
/// character-level safety net in `prepare_chunk`; the helpers here enforce
/// word-level budget at text construction time.
pub const MAX_TOKENS: usize = 384;

/// Tokens consumed by fixed structural lines common to all builders
/// (kind, hour_of_day, day_of_week, is_weekend, is_business_hours, one spare).
/// Keep this conservative - it is subtracted from the per-field budget.
const OVERHEAD_TOKENS: usize = 16;

/// Effective token budget available for variable-length content.
const CONTENT_TOKEN_BUDGET: usize = MAX_TOKENS - OVERHEAD_TOKENS;

/// Conservative words-to-tokens multiplier denominator.
/// 1 word per 3 tokens means we never exceed MAX_TOKENS even if every
/// word tokenises as 3 tokens (worst case for WiFi data with BPE tokenizer).
const WORDS_PER_TOKEN_DENOM: usize = 3;
const WORDS_PER_TOKEN_NUM: usize = 1;

/// Maximum whitespace-separated words allowed in a variable-length field.
#[inline]
fn word_budget(token_budget: usize) -> usize {
    (token_budget * WORDS_PER_TOKEN_NUM) / WORDS_PER_TOKEN_DENOM
}

/// Truncate a space-separated token string to at most `max_words` words.
/// Appends `(+N truncated)` when truncation occurs so the model is aware.
///
/// Example:
/// ```text
/// // 500-word sequence truncated to 300:
/// "BEACON AUTH ASSOC_REQ ... (already 300 words) ... (+200 truncated)"
/// ```
fn truncate_token_sequence(tokens: &str, max_words: usize) -> String {
    let word_count = tokens.split_whitespace().count();
    if word_count <= max_words {
        return tokens.to_string();
    }
    let dropped = word_count - max_words;
    tracing::warn!(
        original_word_count = word_count,
        max_words,
        dropped,
        "frame_sequence token sequence truncated to fit model context window"
    );
    let mut truncated = join_first_words(tokens, max_words);
    truncated.push_str(&format!(" (+{} truncated)", dropped));
    truncated
}

/// Truncate a free-form string to at most `max_words` whitespace-separated words.
/// Appends `...` when truncation occurs.
fn truncate_words(s: &str, max_words: usize) -> String {
    if s.split_whitespace().count() <= max_words {
        return s.to_string();
    }
    let mut truncated = join_first_words(s, max_words);
    truncated.push_str("...");
    truncated
}

/// Clamp the entire assembled text to MAX_TOKENS worth of words.
/// Applied as a final safety net after all per-field truncation.
/// Splits on whitespace, keeps the first N words, rejoins with single spaces.
fn clamp_text(text: &str) -> String {
    let max_words = word_budget(MAX_TOKENS);
    let word_count = text.split_whitespace().count();
    if word_count <= max_words {
        return text.to_string();
    }
    tracing::debug!(
        original_word_count = word_count,
        max_words,
        "embedding text clamped to token budget (defensive)"
    );
    let mut truncated = join_first_words(text, max_words);
    truncated.push_str("...");
    truncated
}

fn join_first_words(s: &str, max_words: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_words.saturating_mul(8)));
    for (i, word) in s.split_whitespace().take(max_words).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// Build the embedding text and metadata for a job.
///
/// Dispatches to the correct builder based on `job.embedding_kind`.
///
/// # Returns
///
/// `EmbeddingInput` containing the identity-stripped semantic text to embed plus
/// metadata fields (observed_at, stream_name, sensor_id, location_id, mac).
///
/// # Errors
///
/// Returns `WorkerError::TextBuild` if:
/// - `embedding_kind` is unrecognised
/// - The source row is not found in the database
/// - A database query fails
#[instrument(skip(pool), fields(job_id = %job.job_id, source_table = %job.source_table, source_key = %job.source_key, embedding_kind = %job.embedding_kind))]
pub async fn build_text(pool: &PgPool, job: &EmbeddingJob) -> Result<EmbeddingInput, WorkerError> {
    match job.embedding_kind.as_str() {
        "event" => build_event(pool, job).await,
        "device" => build_device(pool, job).await,
        "behaviour_window" => build_behaviour_window(pool, job).await,
        "baseline_profile" => build_baseline_profile(pool, job).await,
        "frame_sequence" => build_frame_sequence(pool, job).await,
        "infrastructure_subgraph" => build_infrastructure_subgraph(pool, job).await,
        "timing_profile" => build_timing_profile(pool, job).await,
        other => Err(WorkerError::text_build(format!(
            "unsupported embedding_kind: '{}'",
            other
        ))),
    }
}

/// Build embedding text for many jobs using batched source-table queries.
///
/// Returns a map keyed by `source_key`. Jobs whose source row is missing are omitted.
#[instrument(skip(pool, jobs))]
pub async fn build_text_batch(
    pool: &PgPool,
    jobs: &[EmbeddingJob],
) -> Result<HashMap<String, EmbeddingInput>, WorkerError> {
    if jobs.is_empty() {
        return Ok(HashMap::new());
    }
    if jobs.len() == 1 {
        let job = &jobs[0];
        let input = build_text(pool, job).await?;
        let mut map = HashMap::with_capacity(1);
        map.insert(job.source_key.clone(), input);
        return Ok(map);
    }

    let mut events = Vec::new();
    let mut devices = Vec::new();
    let mut behaviours = Vec::new();
    let mut baseline_profiles = Vec::new();
    let mut frame_sequences = Vec::new();
    let mut infrastructure_subgraphs = Vec::new();
    let mut timing_profiles = Vec::new();

    for job in jobs {
        match job.embedding_kind.as_str() {
            "event" => events.push(job),
            "device" => devices.push(job),
            "behaviour_window" => behaviours.push(job),
            "baseline_profile" => baseline_profiles.push(job),
            "frame_sequence" => frame_sequences.push(job),
            "infrastructure_subgraph" => infrastructure_subgraphs.push(job),
            "timing_profile" => timing_profiles.push(job),
            other => {
                return Err(WorkerError::text_build(format!(
                    "unsupported embedding_kind: '{other}'"
                )));
            }
        }
    }

    let mut out = HashMap::with_capacity(jobs.len());
    if !events.is_empty() {
        build_events_batch(pool, &events, &mut out).await?;
    }
    if !devices.is_empty() {
        build_devices_batch(pool, &devices, &mut out).await?;
    }
    if !behaviours.is_empty() {
        build_behaviour_windows_batch(pool, &behaviours, &mut out).await?;
    }
    if !baseline_profiles.is_empty() {
        build_baseline_profiles_batch(pool, &baseline_profiles, &mut out).await?;
    }
    if !frame_sequences.is_empty() {
        build_frame_sequences_batch(pool, &frame_sequences, &mut out).await?;
    }
    if !infrastructure_subgraphs.is_empty() {
        build_infrastructure_subgraphs_batch(pool, &infrastructure_subgraphs, &mut out).await?;
    }
    if !timing_profiles.is_empty() {
        build_timing_profiles_batch(pool, &timing_profiles, &mut out).await?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Event builder
// ---------------------------------------------------------------------------

/// Semantic-only fields for events - excludes MACs, IPs, sensor/location identity.
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
    "ssid",
    "device_fingerprint",
    "handshake_captured",
    "protected",
    "channel_number",
    "signal_dbm",
    "retry",
    "more_data",
    "power_save",
];

async fn build_event(pool: &PgPool, job: &EmbeddingJob) -> Result<EmbeddingInput, WorkerError> {
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
        FROM sync_events_expanded
        WHERE dedupe_key = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("event query failed: {e}")))?
    .ok_or_else(|| WorkerError::text_build(format!("event not found: {}", job.source_key)))?;

    Ok(event_row_to_input(&row))
}

#[derive(Debug, sqlx::FromRow)]
struct EventBatchRow {
    dedupe_key: String,
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

async fn build_events_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, EventBatchRow>(
        r#"
        SELECT
            dedupe_key,
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
        FROM sync_events_expanded
        WHERE dedupe_key = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("event batch query failed: {e}")))?;

    for row in rows {
        let event_row = event_batch_to_row(&row);
        let input = event_row_to_input(&event_row);
        out.insert(row.dedupe_key.clone(), input);
    }
    Ok(())
}

fn event_batch_to_row(row: &EventBatchRow) -> EventRow {
    EventRow {
        observed_at: row.observed_at,
        stream_name: row.stream_name.clone(),
        sensor_id: row.sensor_id.clone(),
        location_id: row.location_id.clone(),
        source_mac: row.source_mac.clone(),
        ssid: row.ssid.clone(),
        frame_type: row.frame_type.clone(),
        frame_subtype: row.frame_subtype.clone(),
        channel_number: row.channel_number.clone(),
        signal_dbm: row.signal_dbm.clone(),
        retry: row.retry.clone(),
        more_data: row.more_data.clone(),
        power_save: row.power_save.clone(),
        protected: row.protected.clone(),
        security_flags: row.security_flags.clone(),
        app_protocol: row.app_protocol.clone(),
        transport_protocol: row.transport_protocol.clone(),
        dns_query_name: row.dns_query_name.clone(),
        mdns_name: row.mdns_name.clone(),
        dhcp_hostname: row.dhcp_hostname.clone(),
        wps_device_name: row.wps_device_name.clone(),
        wps_manufacturer: row.wps_manufacturer.clone(),
        wps_model_name: row.wps_model_name.clone(),
        device_fingerprint: row.device_fingerprint.clone(),
        handshake_captured: row.handshake_captured.clone(),
    }
}

fn event_row_to_input(row: &EventRow) -> EmbeddingInput {
    let mut lines = vec!["kind: event".to_string()];
    for field in EVENT_SEMANTIC_FIELDS {
        let value = if *field == "wps_device_name" {
            row.wps_device_name.as_deref().map(normalize_wps_name)
        } else {
            row.get_field(field).map(|s| s.to_string())
        };
        append_value(&mut lines, field, value.as_deref());
    }
    // Temporal context from observed_at (when available).
    if let Some(dt) = row.observed_at {
        lines.extend(temporal_context_lines(dt));
    }
    let text = clamp_text(&lines.join("\n"));
    EmbeddingInput {
        text,
        source_observed_at: row.observed_at,
        source_stream_name: row.stream_name.clone(),
        source_sensor_id: row.sensor_id.clone(),
        source_location_id: row.location_id.clone(),
        source_mac: row.source_mac.clone(),
    }
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

fn behaviour_row_to_input(row: &BehaviourWindowRow) -> EmbeddingInput {
    let text = if let Some(ref et) = row.embedding_text {
        if !et.is_empty() {
            // Prepend temporal context when using pre-built text (may be stale without it).
            let mut lines: Vec<String> = Vec::new();
            lines.push("kind: behaviour_window".to_string());
            if let Some(dt) = row.window_start {
                lines.extend(temporal_context_lines(dt));
            }
            for line in et.lines() {
                if line.starts_with("kind:") {
                    continue;
                }
                lines.push(line.to_string());
            }
            // Add burst_velocity
            if let Some(epm) = events_per_minute(row) {
                lines.push(format!("events_per_minute: {epm:.1}"));
            }
            clamp_text(&lines.join("\n"))
        } else if let Some(ref ts) = row.text_summary {
            if !ts.is_empty() {
                // Prepend temporal context to text_summary as well.
                let mut lines: Vec<String> = Vec::new();
                lines.push("kind: behaviour_window".to_string());
                if let Some(dt) = row.window_start {
                    lines.extend(temporal_context_lines(dt));
                }
                for line in ts.lines() {
                    if line.starts_with("kind:") {
                        continue;
                    }
                    lines.push(line.to_string());
                }
                if let Some(epm) = events_per_minute(row) {
                    lines.push(format!("events_per_minute: {epm:.1}"));
                }
                clamp_text(&lines.join("\n"))
            } else {
                build_snapshot_fallback(row)
            }
        } else {
            build_snapshot_fallback(row)
        }
    } else if let Some(ref ts) = row.text_summary {
        if !ts.is_empty() {
            let mut lines: Vec<String> = Vec::new();
            lines.push("kind: behaviour_window".to_string());
            if let Some(dt) = row.window_start {
                lines.extend(temporal_context_lines(dt));
            }
            for line in ts.lines() {
                if line.starts_with("kind:") {
                    continue;
                }
                lines.push(line.to_string());
            }
            if let Some(epm) = events_per_minute(row) {
                lines.push(format!("events_per_minute: {epm:.1}"));
            }
            clamp_text(&lines.join("\n"))
        } else {
            build_snapshot_fallback(row)
        }
    } else {
        build_snapshot_fallback(row)
    };

    EmbeddingInput {
        text,
        source_observed_at: row.window_start,
        source_stream_name: None,
        source_sensor_id: row.sensor_id.clone(),
        source_location_id: row.location_id.clone(),
        source_mac: row.source_mac.clone(),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct BaselineProfileRow {
    bssid: String,
    metric: String,
    p5: Option<f64>,
    p50: Option<f64>,
    p95: Option<f64>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct BaselineProfileBatchRow {
    query_key: String,
    bssid: String,
    metric: String,
    p5: Option<f64>,
    p50: Option<f64>,
    p95: Option<f64>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn build_baseline_profile(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let rows = sqlx::query_as::<_, BaselineProfileRow>(
        r#"
        SELECT
            bssid,
            metric,
            p5::float8,
            p50::float8,
            p95::float8,
            updated_at
        FROM vec_baseline_profiles
        WHERE bssid = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("baseline_profile query failed: {e}")))?;

    if rows.is_empty() {
        return Err(WorkerError::text_build(format!(
            "baseline_profile not found: {}",
            job.source_key
        )));
    }

    Ok(baseline_profile_rows_to_input(&rows))
}

async fn build_baseline_profiles_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, BaselineProfileBatchRow>(
        r#"
        SELECT
            bssid AS query_key,
            bssid,
            metric,
            p5::float8,
            p50::float8,
            p95::float8,
            updated_at
        FROM vec_baseline_profiles
        WHERE bssid = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("baseline_profile batch query failed: {e}")))?;

    let mut grouped: HashMap<String, Vec<BaselineProfileBatchRow>> = HashMap::new();
    for row in rows {
        grouped.entry(row.query_key.clone()).or_default().push(row);
    }

    for job in jobs {
        if let Some(rows) = grouped.get(&job.source_key) {
            let baseline_rows: Vec<BaselineProfileRow> = rows
                .iter()
                .map(|row| BaselineProfileRow {
                    bssid: row.bssid.clone(),
                    metric: row.metric.clone(),
                    p5: row.p5,
                    p50: row.p50,
                    p95: row.p95,
                    updated_at: row.updated_at,
                })
                .collect();
            let row_refs: Vec<&BaselineProfileRow> = baseline_rows.iter().collect();
            out.insert(
                job.source_key.clone(),
                baseline_profile_rows_to_input_ref(&row_refs),
            );
        }
    }

    Ok(())
}

fn baseline_profile_rows_to_input(rows: &[BaselineProfileRow]) -> EmbeddingInput {
    let row_refs: Vec<&BaselineProfileRow> = rows.iter().collect();
    baseline_profile_rows_to_input_ref(&row_refs)
}

fn baseline_profile_rows_to_input_ref(rows: &[&BaselineProfileRow]) -> EmbeddingInput {
    let mut metrics = rows.to_vec();
    metrics.sort_by(|left, right| left.metric.cmp(&right.metric));

    // Each metric line is ~8 tokens (metric name + 3 percentile values).
    // Budget: (CONTENT_TOKEN_BUDGET - 4 fixed lines) / 8 tokens per line.
    const MAX_METRIC_LINES: usize = (CONTENT_TOKEN_BUDGET - 4) / 8; // ~61 metrics

    let mut lines = vec!["kind: baseline_profile".to_string()];
    if let Some(first) = metrics.first() {
        lines.push(format!("bssid: {}", first.bssid));
    }
    for (i, row) in metrics.iter().enumerate() {
        if i >= MAX_METRIC_LINES {
            lines.push(format!(
                "(+{} metrics truncated)",
                metrics.len() - MAX_METRIC_LINES
            ));
            tracing::warn!(
                original_metric_count = metrics.len(),
                max_metric_lines = MAX_METRIC_LINES,
                "baseline_profile metrics truncated to fit model context window"
            );
            break;
        }
        let mut metric_text = format!("metric: {}", row.metric);
        if let Some(value) = row.p5 {
            metric_text.push_str(&format!(" p5: {}", value));
        }
        if let Some(value) = row.p50 {
            metric_text.push_str(&format!(" p50: {}", value));
        }
        if let Some(value) = row.p95 {
            metric_text.push_str(&format!(" p95: {}", value));
        }
        lines.push(metric_text);
    }

    let source_observed_at = rows.iter().filter_map(|row| row.updated_at).max();

    EmbeddingInput {
        text: clamp_text(&lines.join("\n")),
        source_observed_at,
        source_stream_name: None,
        source_sensor_id: None,
        source_location_id: None,
        source_mac: Some(rows[0].bssid.clone()),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct FrameSequenceRow {
    session_key: String,
    source_mac: Option<String>,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    window_end: Option<chrono::DateTime<chrono::Utc>>,
    sequence_tokens: String,
    semantic_tokens: Option<String>,
    frame_count: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct FrameSequenceBatchRow {
    query_key: String,
    session_key: String,
    source_mac: Option<String>,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    window_end: Option<chrono::DateTime<chrono::Utc>>,
    sequence_tokens: String,
    semantic_tokens: Option<String>,
    frame_count: i64,
}

fn insert_log_prob_line(text: &mut String, score: f64) {
    if let Some(pos) = text.rfind("frame_count:") {
        let (before, after) = text.split_at(pos);
        *text = format!("{}log_prob: {:.6}\n{}", before, score, after);
    }
}

async fn build_frame_sequence(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let row = sqlx::query_as::<_, FrameSequenceRow>(
        r#"
        SELECT
            session_key,
            source_mac,
            sensor_id,
            location_id,
            window_start,
            window_end,
            sequence_tokens,
            semantic_tokens,
            frame_count
        FROM vec_frame_sequences
        WHERE session_key = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("frame_sequence query failed: {e}")))?
    .ok_or_else(|| {
        WorkerError::text_build(format!("frame_sequence not found: {}", job.source_key))
    })?;

    let mut input = frame_sequence_row_to_input(&row);

    match sequence_score::load_frame_sequence_scorer(pool).await {
        Ok(scorer) => {
            let score = scorer.score_text(&row.sequence_tokens);
            insert_log_prob_line(&mut input.text, score);
        }
        Err(e) => {
            // Non-fatal: log_prob is informational, don't fail the job.
            tracing::warn!(error = %e, session_key = %row.session_key, "failed to load sequence scorer");
        }
    }

    Ok(input)
}

async fn build_frame_sequences_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, FrameSequenceBatchRow>(
        r#"
        SELECT
            session_key AS query_key,
            session_key,
            source_mac,
            sensor_id,
            location_id,
            window_start,
            window_end,
            sequence_tokens,
            semantic_tokens,
            frame_count
        FROM vec_frame_sequences
        WHERE session_key = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("frame_sequence batch query failed: {e}")))?;

    let scorer = sequence_score::load_frame_sequence_scorer(pool)
        .await
        .map_err(|e| WorkerError::text_build(format!("sequence scorer load failed: {e}")))?;

    for row in rows {
        let mut input = frame_sequence_row_to_input(&FrameSequenceRow {
            session_key: row.session_key.clone(),
            source_mac: row.source_mac.clone(),
            sensor_id: row.sensor_id.clone(),
            location_id: row.location_id.clone(),
            window_start: row.window_start,
            window_end: row.window_end,
            sequence_tokens: row.sequence_tokens.clone(),
            semantic_tokens: row.semantic_tokens.clone(),
            frame_count: row.frame_count,
        });

        let score = scorer.score_text(&row.sequence_tokens);
        insert_log_prob_line(&mut input.text, score);

        out.insert(row.query_key.clone(), input);
    }
    Ok(())
}

fn frame_sequence_row_to_input(row: &FrameSequenceRow) -> EmbeddingInput {
    let mut lines = vec!["kind: frame_sequence".to_string()];

    // Semantic tokens are single uppercase words - each is ~1 token.
    // Reserve OVERHEAD_TOKENS for the fixed structural lines; the rest goes to tokens.
    let token_word_budget = MAX_TOKENS - OVERHEAD_TOKENS;
    let token_source = row
        .semantic_tokens
        .as_deref()
        .filter(|tokens| !tokens.trim().is_empty())
        .unwrap_or(&row.sequence_tokens);
    let truncated_tokens = truncate_token_sequence(token_source, token_word_budget);
    lines.push(format!("tokens: {}", truncated_tokens));

    if let Some(start) = row.window_start {
        if let Some(end) = row.window_end {
            let duration_secs = (end - start).num_seconds();
            lines.push(format!("window_secs: {}", duration_secs));
        }
    }
    lines.push(format!("frame_count: {}", row.frame_count));

    // Note: log_prob is appended by the builder callers (build_frame_sequence /
    // build_frame_sequences_batch) after loading the transition model into the
    // Rust sequence scorer. See those functions for the score injection.
    // When computed, a "log_prob: {score}" line is inserted before frame_count.

    // Tokens are already truncated to token_word_budget (1 word ~ 1 token for
    // frame subtypes like BEACON, AUTH, etc.), so re-clamping with the generic
    // word_budget(MAX_TOKENS) = 128 words would double-truncate.  We use the full
    // text as-is; truncate_token_sequence above handles the budget precisely.
    let text = lines.join("\n");
    EmbeddingInput {
        text,
        source_observed_at: row.window_start,
        source_stream_name: None,
        source_sensor_id: row.sensor_id.clone(),
        source_location_id: row.location_id.clone(),
        source_mac: row.source_mac.clone(),
    }
}

// ---------------------------------------------------------------------------
// Timing profile builder
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct TimingProfileRow {
    source_mac: String,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    tsft_p50_us: Option<f64>,
    tsft_p95_us: Option<f64>,
    tsft_jitter: Option<f64>,
    wall_p50_ms: Option<f64>,
    wall_jitter_ms: Option<f64>,
    beacon_interval_median_ms: Option<f64>,
    beacon_jitter_ms: Option<f64>,
    embedding_text: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct TimingProfileBatchRow {
    query_key: String,
    source_mac: String,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    tsft_p50_us: Option<f64>,
    tsft_p95_us: Option<f64>,
    tsft_jitter: Option<f64>,
    wall_p50_ms: Option<f64>,
    wall_jitter_ms: Option<f64>,
    beacon_interval_median_ms: Option<f64>,
    beacon_jitter_ms: Option<f64>,
    embedding_text: Option<String>,
}

async fn build_timing_profile(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let row = sqlx::query_as::<_, TimingProfileRow>(
        r#"
        SELECT
            source_mac,
            sensor_id,
            location_id,
            window_start,
            tsft_p50_us::float8,
            tsft_p95_us::float8,
            tsft_jitter::float8,
            wall_p50_ms::float8,
            wall_jitter_ms::float8,
            beacon_interval_median_ms::float8,
            beacon_jitter_ms::float8,
            embedding_text
        FROM vec_timing_profiles
        WHERE profile_id::text = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("timing_profile query failed: {e}")))?
    .ok_or_else(|| {
        WorkerError::text_build(format!("timing_profile not found: {}", job.source_key))
    })?;

    Ok(timing_profile_row_to_input(&row))
}

async fn build_timing_profiles_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, TimingProfileBatchRow>(
        r#"
        SELECT
            profile_id::text AS query_key,
            source_mac,
            sensor_id,
            location_id,
            window_start,
            tsft_p50_us::float8,
            tsft_p95_us::float8,
            tsft_jitter::float8,
            wall_p50_ms::float8,
            wall_jitter_ms::float8,
            beacon_interval_median_ms::float8,
            beacon_jitter_ms::float8,
            embedding_text
        FROM vec_timing_profiles
        WHERE profile_id::text = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("timing_profile batch query failed: {e}")))?;

    for row in rows {
        let timing_row = TimingProfileRow {
            source_mac: row.source_mac,
            sensor_id: row.sensor_id,
            location_id: row.location_id,
            window_start: row.window_start,
            tsft_p50_us: row.tsft_p50_us,
            tsft_p95_us: row.tsft_p95_us,
            tsft_jitter: row.tsft_jitter,
            wall_p50_ms: row.wall_p50_ms,
            wall_jitter_ms: row.wall_jitter_ms,
            beacon_interval_median_ms: row.beacon_interval_median_ms,
            beacon_jitter_ms: row.beacon_jitter_ms,
            embedding_text: row.embedding_text,
        };
        out.insert(row.query_key, timing_profile_row_to_input(&timing_row));
    }
    Ok(())
}

fn timing_profile_row_to_input(row: &TimingProfileRow) -> EmbeddingInput {
    let text = row
        .embedding_text
        .as_deref()
        .filter(|text| !text.trim().is_empty())
        .map(|text| {
            let mut lines = Vec::new();
            lines.push("kind: timing_profile".to_string());
            if let Some(dt) = row.window_start {
                lines.extend(temporal_context_lines(dt));
            }
            for line in text.lines() {
                if line.starts_with("kind:") {
                    continue;
                }
                lines.push(line.to_string());
            }
            clamp_text(&lines.join("\n"))
        })
        .unwrap_or_else(|| {
            let mut lines = vec!["kind: timing_profile".to_string()];
            if let Some(dt) = row.window_start {
                lines.extend(temporal_context_lines(dt));
            }
            push_optional_f64(&mut lines, "tsft_p50_us", row.tsft_p50_us);
            push_optional_f64(&mut lines, "tsft_p95_us", row.tsft_p95_us);
            push_optional_f64(&mut lines, "tsft_jitter", row.tsft_jitter);
            push_optional_f64(&mut lines, "wall_p50_ms", row.wall_p50_ms);
            push_optional_f64(&mut lines, "wall_jitter_ms", row.wall_jitter_ms);
            push_optional_f64(
                &mut lines,
                "beacon_interval_ms",
                row.beacon_interval_median_ms,
            );
            push_optional_f64(&mut lines, "beacon_jitter_ms", row.beacon_jitter_ms);
            clamp_text(&lines.join("\n"))
        });

    EmbeddingInput {
        text,
        source_observed_at: row.window_start,
        source_stream_name: None,
        source_sensor_id: row.sensor_id.clone(),
        source_location_id: row.location_id.clone(),
        source_mac: Some(row.source_mac.clone()),
    }
}

fn push_optional_f64(lines: &mut Vec<String>, field: &str, value: Option<f64>) {
    if let Some(value) = value {
        lines.push(format!("{field}: {value:.3}"));
    }
}

// ---------------------------------------------------------------------------
// Infrastructure subgraph builder
// ---------------------------------------------------------------------------

/// Row returned by the ego-graph query for a single BSSID.
#[derive(Debug, sqlx::FromRow)]
struct InfrastructureGraphRow {
    node_a: String,
    node_a_type: String,
    node_b: String,
    node_b_type: String,
    edge_type: String,
    weight: Option<f64>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

/// Build embedding text for an infrastructure subgraph centered on a BSSID.
///
/// Queries `vec_infrastructure_graph` for all edges where the BSSID appears as
/// either `node_a` or `node_b` and serializes the ego-graph as structured text.
async fn build_infrastructure_subgraph(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let bssid = &job.source_key;

    let rows = sqlx::query_as::<_, InfrastructureGraphRow>(
        r#"
        SELECT
            node_a, node_a_type,
            node_b, node_b_type,
            edge_type, weight::float8, last_seen
        FROM vec_infrastructure_graph
        WHERE node_a = $1 OR node_b = $1
        ORDER BY weight DESC, last_seen DESC
        "#,
    )
    .bind(bssid)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("infrastructure_graph query failed: {e}")))?;

    if rows.is_empty() {
        return Err(WorkerError::text_build(format!(
            "infrastructure_subgraph not found: {bssid}"
        )));
    }

    Ok(build_ego_graph_input(bssid, &rows))
}

#[derive(Debug, sqlx::FromRow)]
struct InfrastructureGraphBatchRow {
    query_key: String,
    node_a: String,
    node_a_type: String,
    node_b: String,
    node_b_type: String,
    edge_type: String,
    weight: Option<f64>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

async fn build_infrastructure_subgraphs_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();

    let rows = sqlx::query_as::<_, InfrastructureGraphBatchRow>(
        r#"
        SELECT DISTINCT ON (
            LEAST(node_a, node_b),
            GREATEST(node_a, node_b),
            edge_type,
            endpoint
          )
            endpoint AS query_key,
            node_a, node_a_type,
            node_b, node_b_type,
            edge_type, weight::float8, last_seen
        FROM vec_infrastructure_graph
        CROSS JOIN LATERAL (
          VALUES
            (CASE WHEN node_a = ANY($1::text[]) THEN node_a END),
            (CASE WHEN node_b = ANY($1::text[]) THEN node_b END)
        ) AS endpoints(endpoint)
        WHERE endpoint IS NOT NULL
        ORDER BY
          LEAST(node_a, node_b),
          GREATEST(node_a, node_b),
          edge_type,
          endpoint,
          last_seen DESC
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        WorkerError::text_build(format!("infrastructure_graph batch query failed: {e}"))
    })?;

    // Group rows by query_key
    let mut grouped: HashMap<String, Vec<InfrastructureGraphRow>> = HashMap::new();
    for row in rows {
        let graph_row = InfrastructureGraphRow {
            node_a: row.node_a,
            node_a_type: row.node_a_type,
            node_b: row.node_b,
            node_b_type: row.node_b_type,
            edge_type: row.edge_type,
            weight: row.weight,
            last_seen: row.last_seen,
        };
        grouped.entry(row.query_key).or_default().push(graph_row);
    }

    for job in jobs {
        if let Some(rows) = grouped.get(&job.source_key) {
            out.insert(
                job.source_key.clone(),
                build_ego_graph_input(&job.source_key, rows),
            );
        }
    }

    Ok(())
}

/// Build an ego-graph text representation from infrastructure graph edges.
///
/// Format:
/// ```text
/// kind: infrastructure_subgraph
/// center: aa:bb:cc:dd:ee:ff
/// clients: 14
/// vendor_diversity: 3
/// edges: association:14, probe_target:5, roaming:3, ...
/// ```
fn build_ego_graph_input(bssid: &str, rows: &[InfrastructureGraphRow]) -> EmbeddingInput {
    let mut lines = vec![
        "kind: infrastructure_subgraph".to_string(),
        format!("center: {bssid}"),
    ];

    // Count distinct clients (client_mac neighbors via association)
    let mut client_set: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // Count distinct edge types
    let mut edge_type_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    // Collect all unique SSID neighbors
    let mut ssid_set: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // Collect all unique vendor OUIs
    let mut vendor_set: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for row in rows {
        let neighbor = if row.node_a == bssid {
            (&row.node_b as &str, &row.node_b_type as &str)
        } else {
            (&row.node_a as &str, &row.node_a_type as &str)
        };

        match neighbor.1 {
            "client_mac" if row.edge_type == "association" => {
                client_set.insert(neighbor.0);
            }
            "ssid" if row.edge_type == "probe_target" => {
                ssid_set.insert(neighbor.0);
            }
            "vendor" => {
                vendor_set.insert(neighbor.0);
            }
            _ => {}
        }

        *edge_type_counts.entry(&row.edge_type).or_insert(0) += 1usize;
    }

    if !ssid_set.is_empty() {
        lines.push(format!("ssid: {}", ssid_set.len()));
    }
    if !client_set.is_empty() {
        lines.push(format!("clients: {}", client_set.len()));
    }
    if !vendor_set.is_empty() {
        lines.push(format!("vendor_diversity: {}", vendor_set.len()));
    }

    // Serialize edge type distribution
    let mut edge_parts: Vec<String> = edge_type_counts
        .into_iter()
        .map(|(et, count)| format!("{et}:{count}"))
        .collect();
    edge_parts.sort();
    lines.push(format!("edges: {}", edge_parts.join(",")));

    // Find max last_seen for the source time
    let last_seen = rows.iter().filter_map(|r| r.last_seen).max();

    EmbeddingInput {
        text: clamp_text(&lines.join("\n")),
        source_observed_at: last_seen,
        source_stream_name: None,
        source_sensor_id: None,
        source_location_id: None,
        source_mac: Some(bssid.to_string()),
    }
}

/// Build a fallback text from individual snapshot fields when no pre-built text exists.
fn build_snapshot_fallback(row: &BehaviourWindowRow) -> String {
    // Each of the three JSON fields gets at most 1/4 of the content budget.
    // The rest (3/4) is reserved for scalar fields, temporal context, and kind line.
    let json_field_budget = word_budget(CONTENT_TOKEN_BUDGET / 4);

    let mut lines = vec!["kind: behaviour_window".to_string()];
    // Add temporal context right after the kind line.
    if let Some(dt) = row.window_start {
        lines.extend(temporal_context_lines(dt));
    }
    for field in SNAPSHOT_FIELDS {
        let val: Option<String> = match *field {
            "source_mac" => row.source_mac.clone(),
            "location_id" => row.location_id.clone(),
            "sensor_id" => row.sensor_id.clone(),
            "window_start" => row.window_start.as_ref().map(|dt| dt.to_rfc3339()),
            "window_end" => row.window_end.as_ref().map(|dt| dt.to_rfc3339()),
            "event_count" => row.event_count.map(|v| v.to_string()),
            "protocol_mix" => row
                .protocol_mix
                .as_ref()
                .map(|v| truncate_words(&normalize_json(v), json_field_budget)),
            "frame_type_distribution" => row
                .frame_type_distribution
                .as_ref()
                .map(|v| truncate_words(&normalize_json(v), json_field_budget)),
            "signal_min_dbm" => row.signal_min_dbm.map(|v| v.to_string()),
            "signal_max_dbm" => row.signal_max_dbm.map(|v| v.to_string()),
            "signal_avg_dbm" => row.signal_avg_dbm.map(|v| v.to_string()),
            "retry_count" => row.retry_count.map(|v| v.to_string()),
            "protected_count" => row.protected_count.map(|v| v.to_string()),
            "unprotected_count" => row.unprotected_count.map(|v| v.to_string()),
            "unique_bssid_count" => row.unique_bssid_count.map(|v| v.to_string()),
            "mac_rotation_indicators" => row
                .mac_rotation_indicators
                .as_ref()
                .map(|v| truncate_words(&normalize_json(v), json_field_budget)),
            _ => None,
        };
        if let Some(ref v) = val {
            if !v.is_empty() {
                lines.push(format!("{}: {}", field, v));
            }
        }
    }
    // Add burst_velocity at the end.
    if let Some(epm) = events_per_minute(row) {
        lines.push(format!("events_per_minute: {epm:.1}"));
    }
    clamp_text(&lines.join("\n"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Append a `"field: value"` line if the value is non-empty and semantically meaningful.
fn append_value(lines: &mut Vec<String>, field: &str, value: Option<&str>) {
    match value {
        Some(v) if !is_empty_value(v) => lines.push(format!("{}: {}", field, v)),
        _ => {}
    }
}

/// Returns `true` for values that carry no semantic signal for an embedding model.
///
/// These are boolean-false, zero-integer, and null-like tokens that would add noise
/// if included in the text representation.
fn is_empty_value(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "none" | "null" | "unknown"
    )
}

/// Normalise a WPS device name for embedding: strip screen-size prefixes,
/// lowercase, and remove brand/trailing suffixes.
///
/// This groups similar devices (e.g. `60" Hisense Roku TV` and `55" Hisense Roku TV`)
/// into the same vector-space region.
fn normalize_wps_name(name: &str) -> String {
    let mut s = name.to_lowercase();

    // Strip leading screen-size patterns like `60"`, `55"`, `65 inch`, etc.
    // Find the first non-digit character to get the full number prefix.
    let digit_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if digit_end > 0 {
        let rest = &s[digit_end..];
        if rest.starts_with('"') || rest.starts_with('\'') {
            s = rest[1..].trim().to_string();
        } else if rest.starts_with(" inch") || rest.starts_with("-inch") {
            s = rest[5..].trim().to_string();
        }
    }

    // Strip trailing brand/type suffixes (case-insensitive already due to lowercasing)
    let suffixes = [
        " tv",
        " smart tv",
        " roku tv",
        " android tv",
        " led tv",
        " lcd tv",
        " 4k tv",
        " hd tv",
        " full hd tv",
        " uhd tv",
        " television",
        " smart television",
        " monitor",
        " display",
    ];
    for suffix in &suffixes {
        if s.ends_with(suffix) {
            s = s[..s.len() - suffix.len()].trim().to_string();
            break;
        }
    }

    s
}

/// Produce four temporal-context lines for a given UTC datetime.
///
/// Returns lines like:
/// ```text
/// hour_of_day: 14
/// day_of_week: Tuesday
/// is_weekend: false
/// is_business_hours: true
/// ```
fn temporal_context_lines(dt: chrono::DateTime<chrono::Utc>) -> Vec<String> {
    use chrono::{Datelike, Timelike};
    let hour = dt.hour();
    let day_name = dt.format("%A").to_string();
    let is_weekend = matches!(dt.weekday(), chrono::Weekday::Sat | chrono::Weekday::Sun);
    let is_business_hours = !is_weekend && hour >= 9 && hour < 17;
    vec![
        format!("hour_of_day: {}", hour),
        format!("day_of_week: {}", day_name),
        format!("is_weekend: {}", is_weekend),
        format!("is_business_hours: {}", is_business_hours),
    ]
}

/// Compute `events_per_minute` for a behaviour window row.
///
/// Returns `None` when `event_count` or `window_start`/`window_end` are missing,
/// or when the window duration is zero.
fn events_per_minute(row: &BehaviourWindowRow) -> Option<f64> {
    let count = row.event_count? as f64;
    let start = row.window_start?;
    let end = row.window_end?;
    let duration_secs = (end - start)
        .to_std()
        .ok()
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let duration_mins = duration_secs / 60.0;
    if duration_mins <= 0.0 {
        return None;
    }
    Some(count / duration_mins)
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

    #[test]
    fn is_empty_value_filters_noise() {
        assert!(is_empty_value(""));
        assert!(is_empty_value("0"));
        assert!(is_empty_value("false"));
        assert!(is_empty_value("FALSE"));
        assert!(is_empty_value("None"));
        assert!(is_empty_value("null"));
        assert!(is_empty_value("unknown"));
        assert!(!is_empty_value("beacon"));
        assert!(!is_empty_value("management"));
        assert!(!is_empty_value("-79"));
        assert!(!is_empty_value("my-network"));
    }

    #[test]
    fn append_value_skips_empty_values() {
        let mut lines = vec!["kind: event".to_string()];
        append_value(&mut lines, "security_flags", Some("0"));
        append_value(&mut lines, "protected", Some("false"));
        append_value(&mut lines, "channel_number", Some("6"));
        append_value(&mut lines, "signal_dbm", Some("-79"));
        assert_eq!(
            lines,
            vec!["kind: event", "channel_number: 6", "signal_dbm: -79"]
        );
    }

    #[test]
    fn normalize_wps_name_strips_screen_size() {
        assert_eq!(normalize_wps_name(r#"60" Hisense Roku TV"#), "hisense roku");
        assert_eq!(
            normalize_wps_name(r#"55" Samsung Smart TV"#),
            "samsung smart"
        );
        assert_eq!(normalize_wps_name("65 inch LG TV"), "lg");
        assert_eq!(normalize_wps_name("Apple TV"), "apple");
        // "null" is preserved by normalize but filtered by is_empty_value
        assert_eq!(normalize_wps_name("null"), "null");
    }

    #[test]
    fn normalize_wps_name_lowercases_no_op() {
        // A name that's already clean should remain unchanged (minus lowercasing)
        assert_eq!(normalize_wps_name("Google Chromecast"), "google chromecast");
        assert_eq!(normalize_wps_name("Amazon Fire Stick"), "amazon fire stick");
    }

    #[test]
    fn truncate_token_sequence_no_op_when_short() {
        let budget = MAX_TOKENS - OVERHEAD_TOKENS;
        let tokens = "BEACON AUTH ASSOC_REQ EAPOL DATA_QOS";
        assert_eq!(truncate_token_sequence(tokens, budget), tokens);
    }

    #[test]
    fn truncate_token_sequence_truncates_and_annotates() {
        let budget = MAX_TOKENS - OVERHEAD_TOKENS; // 368
        let tokens: String = (0..600).map(|_| "BEACON").collect::<Vec<_>>().join(" ");
        let result = truncate_token_sequence(&tokens, budget);
        assert!(
            result.contains("(+232 truncated)"),
            "expected truncation annotation, got: {}",
            &result[..result.len().min(80)]
        );
        // Should not exceed budget (368 content words + annotation words)
        let content_words = result
            .split_whitespace()
            .take_while(|w| !w.starts_with("(+"))
            .count();
        assert_eq!(content_words, budget);
    }

    #[test]
    fn clamp_text_no_op_when_within_budget() {
        let text = "kind: frame_sequence\ntokens: BEACON AUTH\nframe_count: 2";
        assert_eq!(clamp_text(text), text);
    }

    #[test]
    fn clamp_text_clamps_oversized_text() {
        let long_value: String = (0..500)
            .map(|i| format!("word{}", i))
            .collect::<Vec<_>>()
            .join(" ");
        let text = format!("kind: event\nfield: {}", long_value);
        let clamped = clamp_text(&text);
        let word_count = clamped.split_whitespace().count();
        assert!(
            word_count <= word_budget(MAX_TOKENS),
            "clamped text has {} words, expected <= {}",
            word_count,
            word_budget(MAX_TOKENS)
        );
    }

    #[test]
    fn word_budget_512_is_170() {
        // (512 * 1) / 3 = 170 words at the 3-tokens-per-word ratio
        assert_eq!(word_budget(512), 170);
    }

    #[test]
    fn insert_log_prob_line_does_not_reclamp_frame_sequence_text() {
        let tokens = (0..(MAX_TOKENS - OVERHEAD_TOKENS))
            .map(|_| "BEACON")
            .collect::<Vec<_>>()
            .join(" ");
        let mut text = format!(
            "kind: frame_sequence\ntokens: {}\nsource_mac: aa:bb:cc:dd:ee:ff\nframe_count: {}",
            tokens,
            MAX_TOKENS - OVERHEAD_TOKENS
        );

        insert_log_prob_line(&mut text, -12.345678);

        assert!(text.contains("log_prob: -12.345678"));
        assert!(text.contains("frame_count: 368"));
        let content_words = text
            .split_whitespace()
            .filter(|word| *word == "BEACON")
            .count();
        assert_eq!(content_words, MAX_TOKENS - OVERHEAD_TOKENS);
    }

    #[test]
    fn frame_sequence_token_budget_is_368() {
        // Verify the direct budget for frame sequences (1 token per word, no multiplier)
        assert_eq!(MAX_TOKENS - OVERHEAD_TOKENS, 368);
    }
}
