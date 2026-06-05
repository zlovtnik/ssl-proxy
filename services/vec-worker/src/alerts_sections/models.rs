use crate::sequence_score;
use crate::WorkerError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use std::time::Duration;
use tracing::{info, instrument, warn};

/// Threshold configuration for alert generation.
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Minimum near-duplicate pairs to trigger an alert (default: 10).
    pub near_duplicate_threshold: i64,
    /// How often to sweep for alerts in worker loop iterations (default: 10).
    pub sweep_interval: u64,
    /// Composite AP risk threshold used for high-risk AP dependent detectors.
    pub ap_risk_threshold: f64,
    /// Maximum graph traversal depth for rogue RF path analysis.
    pub graph_max_depth: i32,
    /// Maximum acceptable log probability before a frame sequence is anomalous.
    pub sequence_threshold: f64,
    /// Maximum physically plausible RF travel speed in meters per second.
    pub impossible_travel_max_speed_mps: f64,
    /// Lookback window for plaintext DNS leak checks.
    pub dns_lookback_minutes: i32,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            near_duplicate_threshold: 10,
            sweep_interval: 10,
            ap_risk_threshold: 0.75,
            graph_max_depth: 3,
            sequence_threshold: -15.0,
            impossible_travel_max_speed_mps: 50.0,
            dns_lookback_minutes: 15,
        }
    }
}

impl AlertConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            near_duplicate_threshold: read_env(
                "VECTOR_ALERT_NEAR_DUPLICATE_THRESHOLD",
                defaults.near_duplicate_threshold,
            ),
            sweep_interval: read_env("VECTOR_ALERT_SWEEP_INTERVAL", defaults.sweep_interval).max(1),
            ap_risk_threshold: read_env(
                "VECTOR_ALERT_AP_RISK_THRESHOLD",
                defaults.ap_risk_threshold,
            ),
            graph_max_depth: read_env("VECTOR_ALERT_GRAPH_MAX_DEPTH", defaults.graph_max_depth)
                .max(1),
            sequence_threshold: read_env(
                "VECTOR_ALERT_SEQUENCE_THRESHOLD",
                defaults.sequence_threshold,
            ),
            impossible_travel_max_speed_mps: read_env(
                "VECTOR_ALERT_IMPOSSIBLE_TRAVEL_MAX_SPEED_MPS",
                defaults.impossible_travel_max_speed_mps,
            ),
            dns_lookback_minutes: read_env(
                "VECTOR_ALERT_DNS_LOOKBACK_MINUTES",
                defaults.dns_lookback_minutes,
            )
            .max(1),
        }
    }
}

fn read_env<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr + Copy,
    T::Err: std::fmt::Display,
{
    match std::env::var(name) {
        Ok(raw) => match raw.parse::<T>() {
            Ok(value) => value,
            Err(e) => {
                warn!(env_var = name, value = %raw, error = %e, "invalid alert config value; using default");
                default
            }
        },
        Err(_) => default,
    }
}

/// A row returned by the repetition score query.
#[derive(Debug, sqlx::FromRow)]
struct DeviceRepetitionScore {
    source_mac: Option<String>,
    near_duplicate_pairs: Option<i64>,
    min_distance: Option<f64>,
    avg_distance: Option<f64>,
    unique_events_implicated: Option<i64>,
}

/// Metadata payload for a near-duplicate alert.
#[derive(Debug, Serialize)]
struct NearDuplicateMeta {
    near_duplicate_pairs: i64,
    min_distance: f64,
    avg_distance: f64,
    unique_events_implicated: i64,
}

/// Check for devices exceeding the near-duplicate threshold and insert alerts.
///
/// Queries the `v_device_repetition_score` materialized view and compares each
/// device's `near_duplicate_pairs` count against `config.near_duplicate_threshold`.
/// Avoids inserting duplicate alerts for the same alert_type + source_mac within
/// the last hour.
#[instrument(skip(pool))]
pub async fn check_near_duplicates(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let rows = sqlx::query_as::<_, DeviceRepetitionScore>(
        r#"
        SELECT
            source_mac,
            near_duplicate_pairs,
            min_distance,
            avg_distance,
            unique_events_implicated
        FROM v_device_repetition_score
        WHERE near_duplicate_pairs >= $1
        "#,
    )
    .bind(config.near_duplicate_threshold)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("near_duplicate query failed: {e}")))?;

    if rows.is_empty() {
        return Ok(0);
    }

    let mut inserted = 0usize;
    for row in &rows {
        let mac = row.source_mac.as_deref();
        let meta = NearDuplicateMeta {
            near_duplicate_pairs: row.near_duplicate_pairs.unwrap_or(0),
            min_distance: row.min_distance.unwrap_or(1.0),
            avg_distance: row.avg_distance.unwrap_or(1.0),
            unique_events_implicated: row.unique_events_implicated.unwrap_or(0),
        };
        let meta_json = serde_json::to_string(&meta).map_err(|e| {
            WorkerError::alerts(format!("near_duplicate metadata encode failed: {e}"))
        })?;

        // Insert only if no identical alert exists in the last hour
        let result = sqlx::query(
            r#"
            INSERT INTO vec_alerts (alert_type, source_mac, score, metadata)
            SELECT 'near_duplicate_cluster', $1, $2, $3::jsonb
            WHERE NOT EXISTS (
                SELECT 1 FROM vec_alerts a
                WHERE a.alert_type = 'near_duplicate_cluster'
                  AND a.source_mac IS NOT DISTINCT FROM $1
                  AND a.created_at > NOW() - INTERVAL '1 hour'
            )
              -- Track 6: Exclude locally-administered MACs (AP beacon noise)
              AND NOT (
                $1 IS NOT NULL
                AND (get_byte(decode(split_part($1, ':', 1), 'hex'), 0) & 2) = 2
              )
              -- Track 6: Exclude MACs that are known AP BSSIDs (from risk scoring)
              AND NOT EXISTS (
                SELECT 1 FROM mv_ap_risk_score ap
                WHERE ap.bssid = $1
              )
            "#,
        )
        .bind(mac)
        .bind(row.near_duplicate_pairs.unwrap_or(0) as f64)
        .bind(meta_json)
        .execute(pool)
        .await;

        match result {
            Ok(r) => {
                if r.rows_affected() > 0 {
                    inserted += 1;
                    info!(
                        source_mac = mac,
                        near_duplicate_pairs = row.near_duplicate_pairs,
                        "near-duplicate alert inserted"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, source_mac = mac, "failed to insert near-duplicate alert");
            }
        }
    }

    info!(inserted, "near-duplicate alert sweep complete");
    Ok(inserted)
}

#[instrument(skip(pool))]
pub async fn check_rogue_clusters(pool: &PgPool) -> Result<usize, WorkerError> {
    let inserted: i32 = sqlx::query_scalar("SELECT vec_detect_rogue_clusters()")
        .fetch_one(pool)
        .await
        .map_err(|e| WorkerError::alerts(format!("rogue cluster query failed: {e}")))?;

    let inserted = inserted.max(0) as usize;
    info!(inserted, "rogue cluster alert sweep complete");
    Ok(inserted)
}

/// Track 6.1: Check for high-risk APs using the composite risk score.
///
/// Calls `check_high_risk_aps()` which inserts alerts into `vec_alerts`
/// with `alert_type = 'high_risk_ap'` when `composite_risk > 0.75`.
#[instrument(skip(pool))]
pub async fn check_high_risk_aps(pool: &PgPool) -> Result<usize, WorkerError> {
    check_high_risk_aps_with_threshold(pool, AlertConfig::default().ap_risk_threshold).await
}

#[instrument(skip(pool))]
pub async fn check_high_risk_aps_with_threshold(
    pool: &PgPool,
    threshold: f64,
) -> Result<usize, WorkerError> {
    let inserted: i32 = sqlx::query_scalar("SELECT check_high_risk_aps($1)")
        .bind(threshold)
        .fetch_one(pool)
        .await
        .map_err(|e| WorkerError::alerts(format!("high_risk_ap query failed: {e}")))?;

    let inserted = inserted.max(0) as usize;
    if inserted > 0 {
        info!(inserted, "high-risk AP alerts inserted");
    }
    Ok(inserted)
}

/// Check for devices whose recent event embeddings drift away from their own
/// historical cluster centroid.
#[instrument(skip(pool))]
pub async fn check_embedding_drift(pool: &PgPool) -> Result<usize, WorkerError> {
    let result = sqlx::query(
        r#"
        INSERT INTO vec_alerts (alert_type, source_mac, score, explanation_text, metadata)
        SELECT
          'embedding_drift',
          e.source_mac,
          (e.embedding::vector(768) <=> dic.embedding_centroid) AS drift_score,
          concat(
            'Embedding drift for ', e.source_mac,
            ': distance=',
            round((e.embedding::vector(768) <=> dic.embedding_centroid)::numeric, 3),
            ', centroid_sample_count=',
            dic.centroid_sample_count::text
          ),
          jsonb_build_object(
            'drift_distance', (e.embedding::vector(768) <=> dic.embedding_centroid),
            'centroid_sample_count', dic.centroid_sample_count,
            'embedding_id', e.embedding_id,
            'cluster_id', dic.cluster_id
          )
        FROM vec_embeddings e
        JOIN device_identity_clusters dic
          ON EXISTS (
            SELECT 1
            FROM unnest(dic.mac_ids) AS cluster_mac(mac)
            WHERE lower(cluster_mac.mac) = lower(e.source_mac)
          )
        WHERE e.embedding_kind = 'event'
          AND e.embedding_dimensions = 768
          AND e.embedded_at >= now() - interval '30 minutes'
          AND e.source_mac IS NOT NULL
          AND dic.embedding_centroid IS NOT NULL
          AND dic.centroid_sample_count >= 10
          AND (e.embedding::vector(768) <=> dic.embedding_centroid) > 0.20
          AND NOT EXISTS (
            SELECT 1 FROM vec_alerts a
            WHERE a.alert_type = 'embedding_drift'
              AND a.source_mac IS NOT DISTINCT FROM e.source_mac
              AND a.created_at > now() - interval '1 hour'
          )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("embedding_drift query failed: {e}")))?;

    let inserted = result.rows_affected() as usize;
    if inserted > 0 {
        info!(inserted, "embedding drift alerts inserted");
    }
    Ok(inserted)
}

#[derive(Debug, sqlx::FromRow)]
struct FrameSequenceAlertRow {
    session_key: String,
    source_mac: Option<String>,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    sequence_tokens: String,
    semantic_tokens: Option<String>,
    frame_count: i64,
}

#[derive(Debug, Serialize)]
struct DeauthPrecursorMeta<'a> {
    reason: &'a str,
    session_key: &'a str,
    log_prob: f64,
    threshold: f64,
    frame_count: i64,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
}

#[instrument(skip(pool))]
pub async fn check_deauth_precursors(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let rows = sqlx::query_as::<_, FrameSequenceAlertRow>(
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
        WHERE window_end >= now() - interval '1 hour'
          AND frame_count >= 3
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("deauth precursor query failed: {e}")))?;

    if rows.is_empty() {
        return Ok(0);
    }

    let scorer = sequence_score::load_frame_sequence_scorer(pool)
        .await
        .map_err(|e| WorkerError::alerts(format!("sequence scorer load failed: {e}")))?;

    let mut inserted = 0usize;
    for row in rows {
        if has_termination_token(&row.sequence_tokens, row.semantic_tokens.as_deref()) {
            continue;
        }

        let log_prob = scorer.score_text(&row.sequence_tokens);
        if log_prob >= config.sequence_threshold {
            continue;
        }

        let metadata = serde_json::json!(DeauthPrecursorMeta {
            reason: "low_probability_pre_deauth_sequence",
            session_key: &row.session_key,
            log_prob,
            threshold: config.sequence_threshold,
            frame_count: row.frame_count,
            window_start: row.window_start,
            window_end: row.window_end,
        });

        let result = sqlx::query(
            r#"
            INSERT INTO vec_alerts (
              alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata
            )
            SELECT
              'deauth_precursor',
              $1,
              $2,
              $3,
              abs($4::double precision),
              concat('Predictive deauth precursor for session ', $5, ': log_prob=', round($4::numeric, 3)),
              $6::jsonb
            WHERE NOT EXISTS (
              SELECT 1
              FROM vec_alerts a
              WHERE a.alert_type = 'deauth_precursor'
                AND a.source_mac IS NOT DISTINCT FROM $1
                AND a.metadata->>'session_key' = $5
                AND a.created_at > now() - interval '1 hour'
            )
            "#,
        )
        .bind(&row.source_mac)
        .bind(&row.sensor_id)
        .bind(&row.location_id)
        .bind(log_prob)
        .bind(&row.session_key)
        .bind(metadata)
        .execute(pool)
        .await;

        match result {
            Ok(done) => inserted += done.rows_affected() as usize,
            Err(e) => {
                warn!(error = %e, session_key = %row.session_key, "failed to insert deauth precursor alert")
            }
        }
    }

    if inserted > 0 {
        info!(inserted, "deauth precursor alerts inserted");
    }
    Ok(inserted)
}
