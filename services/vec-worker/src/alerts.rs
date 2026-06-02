//! Alert generation — periodic checks that produce structured alerts in `vec_alerts`.
//!
//! Each function queries a database view or table, compares against thresholds, and
//! inserts rows into `vec_alerts`. These functions are called periodically from the
//! main worker loop.

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

fn has_termination_token(sequence_tokens: &str, semantic_tokens: Option<&str>) -> bool {
    let raw_has_termination = sequence_tokens.split_whitespace().any(|token| {
        token.eq_ignore_ascii_case("DEAUTH")
            || token.eq_ignore_ascii_case("DEAUTHENTICATION")
            || token.eq_ignore_ascii_case("DISASSOC")
            || token.eq_ignore_ascii_case("DISASSOCIATION")
    });

    raw_has_termination
        || semantic_tokens
            .map(|tokens| {
                tokens
                    .split_whitespace()
                    .any(|token| token.eq_ignore_ascii_case("TERMINATION"))
            })
            .unwrap_or(false)
}

#[instrument(skip(pool))]
pub async fn check_zero_trust_overlay_risk(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let result = sqlx::query(
        r#"
        WITH signals AS (
          SELECT
            d.wg_pubkey,
            d.mac_id AS source_mac,
            max(s.sensor_id) AS sensor_id,
            max(s.location_id) AS location_id,
            max(ap.composite_risk) AS high_risk_ap_score,
            0::double precision AS embedding_drift_score,
            array_remove(array_agg(DISTINCT ap.bssid), NULL) AS bssids
          FROM sync_events_expanded s
          JOIN devices d
            ON lower(d.mac_id) = lower(s.source_mac)
          JOIN mv_ap_risk_score ap
            ON ap.bssid = lower(coalesce(nullif(s.bssid, ''), nullif(s.destination_bssid, '')))
          WHERE d.wg_pubkey IS NOT NULL
            AND s.stream_name = 'wireless.audit'
            AND s.status = 'batched'
            AND s.observed_at >= now() - interval '1 hour'
            AND ap.composite_risk > $1
          GROUP BY d.wg_pubkey, d.mac_id

          UNION ALL

          SELECT
            d.wg_pubkey,
            d.mac_id AS source_mac,
            NULL::text AS sensor_id,
            NULL::text AS location_id,
            0::double precision AS high_risk_ap_score,
            max(a.score) AS embedding_drift_score,
            ARRAY[]::text[] AS bssids
          FROM vec_alerts a
          JOIN devices d
            ON lower(d.mac_id) = lower(a.source_mac)
          WHERE d.wg_pubkey IS NOT NULL
            AND a.alert_type = 'embedding_drift'
            AND a.created_at >= now() - interval '1 hour'
          GROUP BY d.wg_pubkey, d.mac_id
        ),
        rolled AS (
          SELECT
            wg_pubkey,
            source_mac,
            max(sensor_id) FILTER (WHERE sensor_id IS NOT NULL) AS sensor_id,
            max(location_id) FILTER (WHERE location_id IS NOT NULL) AS location_id,
            max(high_risk_ap_score) AS high_risk_ap_score,
            max(embedding_drift_score) AS embedding_drift_score,
            array_remove(array_agg(DISTINCT bssid.value), NULL) AS bssids
          FROM signals
          LEFT JOIN LATERAL unnest(signals.bssids) AS bssid(value) ON true
          GROUP BY wg_pubkey, source_mac
        )
        INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
        SELECT
          'zero_trust_overlay_risk',
          source_mac,
          sensor_id,
          location_id,
          greatest(coalesce(high_risk_ap_score, 0), coalesce(embedding_drift_score, 0)),
          concat(
            'Zero-trust overlay risk for wg_pubkey ', wg_pubkey,
            ': high_risk_ap_score=', round(coalesce(high_risk_ap_score, 0)::numeric, 3),
            ', embedding_drift_score=', round(coalesce(embedding_drift_score, 0)::numeric, 3)
          ),
          jsonb_build_object(
            'wg_pubkey', wg_pubkey,
            'source_mac', source_mac,
            'bssids', bssids,
            'high_risk_ap_score', high_risk_ap_score,
            'embedding_drift_score', embedding_drift_score,
            'ap_risk_threshold', $1
          )
        FROM rolled
        WHERE greatest(coalesce(high_risk_ap_score, 0), coalesce(embedding_drift_score, 0)) > 0
          AND NOT EXISTS (
            SELECT 1
            FROM vec_alerts a
            WHERE a.alert_type = 'zero_trust_overlay_risk'
              AND a.source_mac IS NOT DISTINCT FROM rolled.source_mac
              AND a.metadata->>'wg_pubkey' = rolled.wg_pubkey
              AND a.created_at > now() - interval '1 hour'
          )
        "#,
    )
    .bind(config.ap_risk_threshold)
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("zero_trust_overlay_risk query failed: {e}")))?;

    let inserted = result.rows_affected() as usize;
    if inserted > 0 {
        info!(inserted, "zero-trust overlay risk alerts inserted");
    }
    Ok(inserted)
}

#[instrument(skip(pool))]
pub async fn check_dns_privacy_leaks(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let result = sqlx::query(
        r#"
        WITH policy_devices AS (
          SELECT d.mac_id, d.wg_pubkey, p.allow_mdns
          FROM devices d
          JOIN vec_dns_policy p ON p.wg_pubkey = d.wg_pubkey
          WHERE d.wg_pubkey IS NOT NULL
            AND p.policy = 'secure_required'
        ),
        wireless_dns AS (
          SELECT
            pd.wg_pubkey,
            pd.mac_id AS source_mac,
            s.sensor_id,
            s.location_id,
            s.observed_at,
            CASE
              WHEN nullif(s.dns_query_name, '') IS NOT NULL THEN 'plaintext_dns'
              WHEN nullif(s.mdns_name, '') IS NOT NULL AND NOT pd.allow_mdns THEN 'mdns_disallowed'
            END AS leak_reason,
            lower(coalesce(nullif(s.dns_query_name, ''), nullif(s.mdns_name, ''))) AS query_name
          FROM policy_devices pd
          JOIN sync_events_expanded s
            ON lower(s.source_mac) = lower(pd.mac_id)
          WHERE s.stream_name = 'wireless.audit'
            AND s.status = 'batched'
            AND s.observed_at >= now() - ($1::integer * interval '1 minute')
            AND (
              nullif(s.dns_query_name, '') IS NOT NULL
              OR (nullif(s.mdns_name, '') IS NOT NULL AND NOT pd.allow_mdns)
            )
        ),
        candidates AS (
          SELECT DISTINCT ON (wg_pubkey, source_mac, leak_reason, query_name)
            wd.*,
            EXISTS (
              SELECT 1
              FROM vec_dns_resolver_ledger ledger
              WHERE ledger.wg_pubkey = wd.wg_pubkey
                AND ledger.observed_at >= now() - ($1::integer * interval '1 minute')
                AND ledger.protocol IN ('doh', 'dot', 'wireguard_dns', 'dnscrypt')
                AND (
                  lower(ledger.query_name) = wd.query_name
                  OR ledger.query_name_hash = encode(digest(wd.query_name, 'sha256'), 'hex')
                )
            ) AS resolver_ledger_match
          FROM wireless_dns wd
          WHERE leak_reason IS NOT NULL
          ORDER BY wg_pubkey, source_mac, leak_reason, query_name, observed_at DESC
        )
        INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
        SELECT
          'dns_privacy_leak',
          source_mac,
          sensor_id,
          location_id,
          CASE WHEN leak_reason = 'plaintext_dns' THEN 1.0 ELSE 0.5 END,
          concat('DNS privacy leak for wg_pubkey ', wg_pubkey, ': ', leak_reason, ' query=', query_name),
          jsonb_build_object(
            'wg_pubkey', wg_pubkey,
            'source_mac', source_mac,
            'query_name', query_name,
            'reason', leak_reason,
            'resolver_ledger_match', resolver_ledger_match,
            'lookback_minutes', $1
          )
        FROM candidates
        WHERE NOT EXISTS (
          SELECT 1
          FROM vec_alerts a
          WHERE a.alert_type = 'dns_privacy_leak'
            AND a.source_mac IS NOT DISTINCT FROM candidates.source_mac
            AND a.metadata->>'wg_pubkey' = candidates.wg_pubkey
            AND a.metadata->>'query_name' = candidates.query_name
            AND a.metadata->>'reason' = candidates.leak_reason
            AND a.created_at > now() - interval '1 hour'
        )
        "#,
    )
    .bind(config.dns_lookback_minutes)
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("dns_privacy_leak query failed: {e}")))?;

    let inserted = result.rows_affected() as usize;
    if inserted > 0 {
        info!(inserted, "DNS privacy leak alerts inserted");
    }
    Ok(inserted)
}

#[derive(Debug, sqlx::FromRow)]
struct TravelObservation {
    cluster_id: i64,
    source_mac: String,
    sensor_id: String,
    location_id: String,
    observed_at: DateTime<Utc>,
    latitude: f64,
    longitude: f64,
}

#[instrument(skip(pool))]
pub async fn check_rf_impossible_travel(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let observations = sqlx::query_as::<_, TravelObservation>(
        r#"
        WITH cluster_macs AS (
          SELECT cluster_id, lower(mac) AS source_mac
          FROM device_identity_clusters
          CROSS JOIN LATERAL unnest(mac_ids) AS cluster_mac(mac)
        ),
        recent AS (
          SELECT DISTINCT ON (
            cm.cluster_id,
            s.sensor_id,
            coalesce(s.location_id, ''),
            date_trunc('minute', s.observed_at)
          )
            cm.cluster_id,
            cm.source_mac,
            loc.sensor_id,
            loc.location_id,
            s.observed_at,
            loc.latitude,
            loc.longitude
          FROM cluster_macs cm
          JOIN sync_events_expanded s
            ON lower(s.source_mac) = cm.source_mac
          JOIN vec_rf_sensor_locations loc
            ON loc.enabled
           AND loc.sensor_id = s.sensor_id
           AND loc.location_id = coalesce(s.location_id, '')
          WHERE s.stream_name = 'wireless.audit'
            AND s.status = 'batched'
            AND s.observed_at >= now() - interval '1 hour'
          ORDER BY
            cm.cluster_id,
            s.sensor_id,
            coalesce(s.location_id, ''),
            date_trunc('minute', s.observed_at),
            s.observed_at ASC
        )
        SELECT *
        FROM recent
        ORDER BY cluster_id, observed_at ASC
        LIMIT 10000
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("rf impossible travel query failed: {e}")))?;

    let mut inserted = 0usize;
    let mut previous: Option<&TravelObservation> = None;
    for current in &observations {
        if let Some(prev) = previous {
            if prev.cluster_id == current.cluster_id {
                if let Some(speed_mps) = impossible_travel_speed_mps(prev, current) {
                    if speed_mps > config.impossible_travel_max_speed_mps {
                        inserted += insert_rf_impossible_travel_alert(
                            pool, config, prev, current, speed_mps,
                        )
                        .await?;
                    }
                }
            }
        }
        previous = Some(current);
    }

    if inserted > 0 {
        info!(inserted, "RF impossible travel alerts inserted");
    }
    Ok(inserted)
}

async fn insert_rf_impossible_travel_alert(
    pool: &PgPool,
    config: &AlertConfig,
    prev: &TravelObservation,
    current: &TravelObservation,
    speed_mps: f64,
) -> Result<usize, WorkerError> {
    let distance_m = haversine_meters(
        prev.latitude,
        prev.longitude,
        current.latitude,
        current.longitude,
    );
    let elapsed_secs = (current.observed_at - prev.observed_at).num_seconds();
    let metadata = serde_json::json!({
        "cluster_id": current.cluster_id,
        "source_mac": current.source_mac,
        "from_sensor_id": prev.sensor_id,
        "from_location_id": prev.location_id,
        "to_sensor_id": current.sensor_id,
        "to_location_id": current.location_id,
        "from_observed_at": prev.observed_at,
        "to_observed_at": current.observed_at,
        "distance_m": distance_m,
        "elapsed_secs": elapsed_secs,
        "speed_mps": speed_mps,
        "max_speed_mps": config.impossible_travel_max_speed_mps,
    });

    let result = sqlx::query(
        r#"
        INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
        SELECT
          'rf_impossible_travel',
          $1,
          $2,
          $3,
          $4,
          concat('RF impossible travel for cluster ', $5::text, ': speed_mps=', round($4::numeric, 2)),
          $6::jsonb
        WHERE NOT EXISTS (
          SELECT 1
          FROM vec_alerts a
          WHERE a.alert_type = 'rf_impossible_travel'
            AND a.metadata->>'cluster_id' = $5::text
            AND a.created_at > now() - interval '1 hour'
        )
        "#,
    )
    .bind(&current.source_mac)
    .bind(&current.sensor_id)
    .bind(&current.location_id)
    .bind(speed_mps)
    .bind(current.cluster_id)
    .bind(metadata)
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("rf impossible travel insert failed: {e}")))?;

    Ok(result.rows_affected() as usize)
}

fn impossible_travel_speed_mps(
    prev: &TravelObservation,
    current: &TravelObservation,
) -> Option<f64> {
    if prev.sensor_id == current.sensor_id && prev.location_id == current.location_id {
        return None;
    }
    let elapsed_secs = (current.observed_at - prev.observed_at).num_seconds();
    if elapsed_secs <= 0 {
        return None;
    }
    let meters = haversine_meters(
        prev.latitude,
        prev.longitude,
        current.latitude,
        current.longitude,
    );
    Some(meters / elapsed_secs as f64)
}

fn haversine_meters(lat_a: f64, lon_a: f64, lat_b: f64, lon_b: f64) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_000.0;
    let d_lat = (lat_b - lat_a).to_radians();
    let d_lon = (lon_b - lon_a).to_radians();
    let lat_a = lat_a.to_radians();
    let lat_b = lat_b.to_radians();

    let a = (d_lat / 2.0).sin().powi(2) + lat_a.cos() * lat_b.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    EARTH_RADIUS_M * c
}

#[instrument(skip(pool))]
pub async fn check_rogue_rf_paths(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let result = sqlx::query(
        r#"
        WITH RECURSIVE seed AS (
          SELECT bssid AS root_bssid, composite_risk
          FROM mv_ap_risk_score
          WHERE composite_risk > $1
        ),
        walk AS (
          SELECT
            root_bssid,
            composite_risk,
            root_bssid AS node,
            'bssid'::text AS node_type,
            ARRAY[root_bssid] AS path,
            0 AS depth
          FROM seed

          UNION ALL

          SELECT
            walk.root_bssid,
            walk.composite_risk,
            edge.next_node,
            edge.next_node_type,
            walk.path || edge.next_node,
            walk.depth + 1
          FROM walk
          JOIN LATERAL (
            SELECT
              node_b AS next_node,
              node_b_type AS next_node_type,
              edge_type
            FROM vec_infrastructure_graph
            WHERE node_a = walk.node
              AND node_a_type = walk.node_type
              AND last_seen >= now() - interval '24 hours'
            UNION ALL
            SELECT
              node_a AS next_node,
              node_a_type AS next_node_type,
              edge_type
            FROM vec_infrastructure_graph
            WHERE node_b = walk.node
              AND node_b_type = walk.node_type
              AND last_seen >= now() - interval '24 hours'
          ) edge ON true
          WHERE walk.depth < $2
            AND edge.edge_type IN ('association', 'roaming', 'rf_proximity')
            AND NOT edge.next_node = ANY(walk.path)
        ),
        candidates AS (
          SELECT DISTINCT ON (root_bssid, node, node_type)
            root_bssid,
            composite_risk,
            node,
            node_type,
            path,
            depth
          FROM walk
          WHERE depth > 0
            AND node_type IN ('client_mac', 'bssid')
          ORDER BY root_bssid, node, node_type, depth ASC
          LIMIT 200
        )
        INSERT INTO vec_alerts (alert_type, source_mac, score, explanation_text, metadata)
        SELECT
          'rogue_rf_path',
          CASE WHEN node_type = 'client_mac' THEN node ELSE root_bssid END,
          composite_risk,
          concat('Rogue RF path from high-risk AP ', root_bssid, ' to ', node_type, ' ', node, ' depth=', depth),
          jsonb_build_object(
            'root_bssid', root_bssid,
            'target_node', node,
            'target_node_type', node_type,
            'path', path,
            'depth', depth,
            'max_depth', $2,
            'composite_risk', composite_risk,
            'ap_risk_threshold', $1
          )
        FROM candidates
        WHERE NOT EXISTS (
          SELECT 1
          FROM vec_alerts a
          WHERE a.alert_type = 'rogue_rf_path'
            AND a.source_mac IS NOT DISTINCT FROM CASE WHEN candidates.node_type = 'client_mac' THEN candidates.node ELSE candidates.root_bssid END
            AND a.metadata->>'root_bssid' = candidates.root_bssid
            AND a.metadata->>'target_node' = candidates.node
            AND a.created_at > now() - interval '1 hour'
        )
        "#,
    )
    .bind(config.ap_risk_threshold)
    .bind(config.graph_max_depth)
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("rogue_rf_path query failed: {e}")))?;

    let inserted = result.rows_affected() as usize;
    if inserted > 0 {
        info!(inserted, "rogue RF path alerts inserted");
    }
    Ok(inserted)
}

/// Run all configured alert checks in the correct order.
///
/// Refreshes `v_device_repetition_score` and `mv_ap_risk_score` (materialized views)
/// at the start of each sweep so that alert queries run against current data,
/// not stale snapshots. The CONCURRENTLY flag allows reads during the refresh
/// (requires the unique index on `source_mac`, which is created in V019).
#[instrument(skip(pool))]
pub async fn run_alert_sweep(pool: &PgPool, config: &AlertConfig) -> Result<(), WorkerError> {
    // Refresh the materialized view before querying it so alerts are based on
    // current data. REFRESH MATERIALIZED VIEW CONCURRENTLY requires a unique
    // index, which V019 creates on (source_mac).
    refresh_materialized_view_with_timeout(
        pool,
        "v_device_repetition_score",
        "REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score",
    )
    .await;

    // Refresh the AP risk score materialized view
    refresh_materialized_view_with_timeout(
        pool,
        "mv_ap_risk_score",
        "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_ap_risk_score",
    )
    .await;

    let nd = check_near_duplicates(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "near_duplicate check failed");
            0
        });
    debug_assert!(nd <= usize::MAX);

    let rc = check_rogue_clusters(pool).await.unwrap_or_else(|e| {
        warn!(error = %e, "rogue cluster check failed");
        0
    });
    debug_assert!(rc <= usize::MAX);

    let deauth = check_deauth_precursors(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "deauth precursor check failed");
            0
        });
    debug_assert!(deauth <= usize::MAX);

    let hra = check_high_risk_aps_with_threshold(pool, config.ap_risk_threshold)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "high_risk_ap check failed");
            0
        });
    debug_assert!(hra <= usize::MAX);

    let drift = check_embedding_drift(pool).await.unwrap_or_else(|e| {
        warn!(error = %e, "embedding_drift check failed");
        0
    });
    debug_assert!(drift <= usize::MAX);

    let zero_trust = check_zero_trust_overlay_risk(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "zero_trust_overlay_risk check failed");
            0
        });
    debug_assert!(zero_trust <= usize::MAX);

    let dns = check_dns_privacy_leaks(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "dns_privacy_leak check failed");
            0
        });
    debug_assert!(dns <= usize::MAX);

    let travel = check_rf_impossible_travel(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "rf_impossible_travel check failed");
            0
        });
    debug_assert!(travel <= usize::MAX);

    let paths = check_rogue_rf_paths(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "rogue_rf_path check failed");
            0
        });
    debug_assert!(paths <= usize::MAX);

    Ok(())
}

async fn refresh_materialized_view_with_timeout(
    pool: &PgPool,
    view_name: &'static str,
    statement: &'static str,
) {
    const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

    match tokio::time::timeout(REFRESH_TIMEOUT, sqlx::query(statement).execute(pool)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!(error = %e, view_name, "failed to refresh materialized view, alert sweep may use stale data");
        }
        Err(_) => {
            warn!(
                view_name,
                timeout_ms = REFRESH_TIMEOUT.as_millis(),
                "timed out refreshing materialized view, alert sweep may use stale data"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn observation(
        cluster_id: i64,
        sensor_id: &str,
        location_id: &str,
        observed_at: DateTime<Utc>,
        latitude: f64,
        longitude: f64,
    ) -> TravelObservation {
        TravelObservation {
            cluster_id,
            source_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            sensor_id: sensor_id.to_string(),
            location_id: location_id.to_string(),
            observed_at,
            latitude,
            longitude,
        }
    }

    #[test]
    fn termination_filter_matches_raw_and_semantic_tokens() {
        assert!(has_termination_token("AUTH DEAUTH", None));
        assert!(has_termination_token(
            "AUTH ASSOC_REQ",
            Some("DISCOVERY TERMINATION")
        ));
        assert!(!has_termination_token(
            "PROBE_REQ AUTH ASSOC_REQ",
            Some("DISCOVERY ASSOCIATION")
        ));
    }

    #[test]
    fn haversine_distance_is_close_for_one_equator_degree() {
        let meters = haversine_meters(0.0, 0.0, 0.0, 1.0);
        assert!((meters - 111_195.0).abs() < 250.0);
    }

    #[test]
    fn impossible_travel_speed_requires_distinct_sensor_or_location() {
        let t0 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let t1 = Utc.timestamp_opt(1_700_000_060, 0).unwrap();
        let same_sensor = observation(1, "sensor-a", "", t0, 0.0, 0.0);
        let same_sensor_later = observation(1, "sensor-a", "", t1, 0.0, 1.0);
        assert!(impossible_travel_speed_mps(&same_sensor, &same_sensor_later).is_none());

        let other_sensor = observation(1, "sensor-b", "", t1, 0.0, 1.0);
        let speed = impossible_travel_speed_mps(&same_sensor, &other_sensor).unwrap();
        assert!(speed > 1_800.0);
    }
}
