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
