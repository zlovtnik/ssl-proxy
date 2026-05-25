//! Alert generation — periodic checks that produce structured alerts in `vec_alerts`.
//!
//! Each function queries a database view or table, compares against thresholds, and
//! inserts rows into `vec_alerts`. These functions are called periodically from the
//! main worker loop.

use crate::WorkerError;
use sqlx::PgPool;
use serde::Serialize;
use tracing::{info, instrument, warn};

/// Threshold configuration for alert generation.
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Minimum near-duplicate pairs to trigger an alert (default: 10).
    pub near_duplicate_threshold: i64,
    /// How often to sweep for alerts in worker loop iterations (default: 10).
    pub sweep_interval: u64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            near_duplicate_threshold: 10,
            sweep_interval: 10,
        }
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
        let meta = serde_json::json!(NearDuplicateMeta {
            near_duplicate_pairs: row.near_duplicate_pairs.unwrap_or(0),
            min_distance: row.min_distance.unwrap_or(1.0),
            avg_distance: row.avg_distance.unwrap_or(1.0),
            unique_events_implicated: row.unique_events_implicated.unwrap_or(0),
        });

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
            "#,
        )
        .bind(mac)
        .bind(row.near_duplicate_pairs.unwrap_or(0) as f64)
        .bind(meta.to_string())
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
    let inserted: i64 = sqlx::query_scalar(
        "SELECT vec_detect_rogue_clusters()",
    )
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
    let inserted: i8 = sqlx::query_scalar(
        "SELECT check_high_risk_aps()",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("high_risk_ap query failed: {e}")))?;

    let inserted = inserted.max(0) as usize;
    if inserted > 0 {
        info!(inserted, "high-risk AP alerts inserted");
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
pub async fn run_alert_sweep(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<(), WorkerError> {
    // Refresh the materialized view before querying it so alerts are based on
    // current data. REFRESH MATERIALIZED VIEW CONCURRENTLY requires a unique
    // index, which V019 creates on (source_mac).
    if let Err(e) = sqlx::query(
        "REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score",
    )
    .execute(pool)
    .await
    {
        warn!(error = %e, "failed to refresh v_device_repetition_score, alert sweep may use stale data");
    }

    // Refresh the AP risk score materialized view
    if let Err(e) = sqlx::query(
        "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_ap_risk_score",
    )
    .execute(pool)
    .await
    {
        warn!(error = %e, "failed to refresh mv_ap_risk_score, alert sweep may use stale data");
    }

    let nd = check_near_duplicates(pool, config).await?;
    debug_assert!(nd <= usize::MAX);

    let rc = check_rogue_clusters(pool).await?;
    debug_assert!(rc <= usize::MAX);

    let hra = check_high_risk_aps(pool).await?;
    debug_assert!(hra <= usize::MAX);

    Ok(())
}

