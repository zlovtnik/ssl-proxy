//! Database layer — pure async functions for job leasing, embedding upsert,
//! worker-state heartbeats, and lease reaping.
//!
//! Every function is a free-standing `pub async fn` that takes `&PgPool` plus
//! its required data.  No structs with methods — just functions.
//!
//! # Types
//!
//! * [`EmbeddingJob`] — row returned by `vec_lease_embedding_jobs()`
//! * [`EmbeddingInput`] — bundles text + metadata for `upsert_embedding`
//! * [`WorkerStateParams`] — input parameters for `mark_worker_state`

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashSet;
use std::time::Duration;
use tracing::instrument;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A row from the `vec_embedding_jobs` table, returned by the
/// `vec_lease_embedding_jobs()` PL/pgSQL function.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmbeddingJob {
    pub job_id: i64,
    pub source_table: String,
    pub source_key: String,
    pub embedding_model: String,
    pub embedding_kind: String,
    pub status: String,
    pub priority: i32,
    pub attempts: i32,
    pub max_attempts: i32,
    pub lease_token: Option<String>,
    pub leased_at: Option<DateTime<Utc>>,
    pub locked_by: Option<String>,
    pub due_at: DateTime<Utc>,
    pub content_sha256: Option<String>,
    pub last_error: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Bundles the embedding text and its source metadata.
///
/// This corresponds to the `Input` struct built by the Ruby
/// `VectorEmbeddings::TextBuilder`.
#[derive(Debug, Clone)]
pub struct EmbeddingInput {
    /// Identity-stripped semantic text to embed.
    pub text: String,
    pub source_observed_at: Option<DateTime<Utc>>,
    pub source_stream_name: Option<String>,
    pub source_sensor_id: Option<String>,
    pub source_location_id: Option<String>,
    pub source_mac: Option<String>,
}

/// Parameters for [`mark_worker_state`].
#[derive(Debug, Clone)]
pub struct WorkerStateParams {
    pub worker_name: String,
    pub status: String,
    pub last_cursor: Option<String>,
    pub last_run_started_at: Option<DateTime<Utc>>,
    pub last_run_finished_at: Option<DateTime<Utc>>,
    pub rows_processed: i64,
    pub last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Row payload for [`complete_embedding_batch`].
#[derive(Debug, Clone, Serialize)]
pub struct CompleteBatchRow {
    pub job_id: i64,
    pub lease_token: Option<String>,
    pub source_table: String,
    pub source_key: String,
    pub source_observed_at: Option<DateTime<Utc>>,
    pub source_stream_name: Option<String>,
    pub source_sensor_id: Option<String>,
    pub source_location_id: Option<String>,
    pub source_mac: Option<String>,
    pub embedding_model: String,
    pub embedding_kind: String,
    pub embedding_dimensions: i32,
    pub content_sha256: String,
    pub content_text: String,
    /// pgvector literal, e.g. `[1.0,2.0,...]`.
    pub embedding: String,
    pub metadata: serde_json::Value,
    /// Human-readable alert explanation text, populated for alert-type embedding jobs.
    pub explanation_text: Option<String>,
}

/// Open a new connection pool with explicit timeouts and warm-up.
///
/// Sets `acquire_timeout(10s)` — fail fast instead of silently waiting 30s.
/// Sets `idle_timeout(300s)` — reclaim idle connections after 5 minutes.
/// Sets `max_lifetime(1800s)` — force connection recycling every 30 minutes.
/// Sets `min_connections` to pre-warm the pool and avoid cold-start thundering herd.
#[instrument(skip(database_url))]
pub async fn connect_with_options(
    database_url: &str,
    max_connections: u32,
    min_connections: u32,
) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections.max(1))
        .min_connections(min_connections.min(max_connections.max(1)))
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .connect(database_url)
        .await
}

/// Open a new connection pool to the PostgreSQL database (convenience wrapper).
///
/// Uses `min_connections=3` to pre-warm the pool. Call once at startup and
/// share the pool via `Arc` or injection.
#[instrument(skip(database_url))]
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    connect_with_options(database_url, max_connections, 3).await
}

// ---------------------------------------------------------------------------
// Job lifecycle
// ---------------------------------------------------------------------------

/// Lease a batch of embedding jobs from `vec_embedding_jobs`.
///
/// Calls `SELECT * FROM vec_lease_embedding_jobs($1, $2, make_interval(secs => $3))`.
///
/// The PL/pgSQL function atomically selects pending/expired jobs, marks them
/// as `leased`, increments `attempts`, sets `lease_token` / `leased_at` /
/// `locked_by`, and returns the full rows.
#[instrument(skip(pool))]
pub async fn lease_jobs(
    pool: &PgPool,
    batch_size: i32,
    worker_name: &str,
    lease_seconds: i64,
) -> Result<Vec<EmbeddingJob>, sqlx::Error> {
    sqlx::query_as::<_, EmbeddingJob>(
        "SELECT * FROM vec_lease_embedding_jobs($1, $2, make_interval(secs => $3))",
    )
    .bind(batch_size)
    .bind(worker_name)
    .bind(lease_seconds)
    .fetch_all(pool)
    .await
}

/// Mark a job as completed.
///
/// Sets `status = 'completed'`, records the `content_sha256`, and clears
/// lease fields.
#[instrument(skip(pool))]
pub async fn complete_job(
    pool: &PgPool,
    job_id: i64,
    lease_token: Option<&str>,
    content_sha256: &str,
) -> Result<(), sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE vec_embedding_jobs
        SET status = 'completed',
            content_sha256 = $1,
            completed_at = now(),
            lease_token = NULL,
            leased_at = NULL,
            locked_by = NULL,
            last_error = NULL,
            updated_at = now()
        WHERE job_id = $2
          AND lease_token IS NOT DISTINCT FROM $3
        "#,
    )
    .bind(content_sha256)
    .bind(job_id)
    .bind(lease_token)
    .execute(pool)
    .await?;

    if result.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }

    Ok(())
}

/// Mark a job as completed within a transaction.
///
/// Transaction-aware variant of [`complete_job`] that accepts a mutable transaction
/// reference instead of a pool. Used to atomically complete the embedding upsert
/// and job completion together.
#[instrument(skip(tx))]
pub async fn complete_job_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: i64,
    lease_token: Option<&str>,
    content_sha256: &str,
) -> Result<(), sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE vec_embedding_jobs
        SET status = 'completed',
            content_sha256 = $1,
            completed_at = now(),
            lease_token = NULL,
            leased_at = NULL,
            locked_by = NULL,
            last_error = NULL,
            updated_at = now()
        WHERE job_id = $2
          AND lease_token IS NOT DISTINCT FROM $3
        "#,
    )
    .bind(content_sha256)
    .bind(job_id)
    .bind(lease_token)
    .execute(&mut **tx)
    .await?;

    if result.rows_affected() != 1 {
        // If the UPDATE matched 0 rows, the job may already be completed.
        // Check its status — if already completed, treat as success (idempotent).
        let status: Option<String> =
            sqlx::query_scalar(r#"SELECT status FROM vec_embedding_jobs WHERE job_id = $1"#)
                .bind(job_id)
                .fetch_optional(&mut **tx)
                .await?
                .flatten();

        match status.as_deref() {
            Some("completed") => return Ok(()),
            _ => return Err(sqlx::Error::RowNotFound),
        }
    }

    Ok(())
}

/// Record a job failure.
///
/// If `attempts >= max_attempts` the status becomes `failed`; otherwise it
/// is reset to `pending` with an exponential backoff: `min(300, max(10, attempts * 10))`.
/// Lease fields are cleared.
#[instrument(skip(pool))]
pub async fn fail_job(
    pool: &PgPool,
    job_id: i64,
    lease_token: Option<&str>,
    attempts: i32,
    max_attempts: i32,
    error_message: &str,
) -> Result<(), sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE vec_embedding_jobs
        SET status = CASE WHEN $2 >= $3 THEN 'failed' ELSE 'pending' END,
            lease_token = NULL,
            leased_at = NULL,
            locked_by = NULL,
            last_error = $1,
            due_at = now() + make_interval(secs => $4),
            updated_at = now()
        WHERE job_id = $5
          AND lease_token IS NOT DISTINCT FROM $6
        "#,
    )
    .bind(error_message)
    .bind(attempts)
    .bind(max_attempts)
    .bind(backoff_seconds(attempts))
    .bind(job_id)
    .bind(lease_token)
    .execute(pool)
    .await?;

    if result.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }

    Ok(())
}

/// Compute exponential-backoff seconds matching the Ruby reference:
/// `least(300, greatest(10, attempts * 10))`.
fn backoff_seconds(attempts: i32) -> i64 {
    let raw = (attempts as i64).saturating_mul(10);
    raw.clamp(10, 300)
}

// ---------------------------------------------------------------------------
// Embedding upsert
// ---------------------------------------------------------------------------

/// Upsert an embedding row into `vec_embeddings`.
///
/// Matches the Ruby reference implementation exactly:
/// - `INSERT INTO vec_embeddings (...) VALUES (...) ON CONFLICT (source_table, source_key, embedding_model, embedding_kind) DO UPDATE SET ...`
/// - The vector is formatted as `[f32,f32,...]::vector`.
///
/// `dimensions` is the expected number of dimensions for the embedding model,
/// typically `config.dimensions` from the worker configuration.
#[instrument(skip(pool, job, input, vector))]
pub async fn upsert_embedding(
    pool: &PgPool,
    job: &EmbeddingJob,
    input: &EmbeddingInput,
    content_sha256: &str,
    vector: &[f32],
    dimensions: i32,
) -> Result<(), sqlx::Error> {
    let vector_literal = format_vector_literal(vector);

    sqlx::query(
        r#"
        INSERT INTO vec_embeddings (
            source_table, source_key, source_observed_at, source_stream_name,
            source_sensor_id, source_location_id, source_mac,
            embedding_model, embedding_kind, embedding_dimensions,
            content_sha256, content_text, embedding, metadata,
            embedded_at, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4,
            $5, $6, $7,
            $8, $9, $10,
            $11, $12, $13::vector, $14::jsonb,
            now(), now(), now()
        )
        ON CONFLICT (source_table, source_key, embedding_model, embedding_kind)
        DO UPDATE SET
            source_observed_at = EXCLUDED.source_observed_at,
            source_stream_name = EXCLUDED.source_stream_name,
            source_sensor_id = EXCLUDED.source_sensor_id,
            source_location_id = EXCLUDED.source_location_id,
            source_mac = EXCLUDED.source_mac,
            embedding_dimensions = EXCLUDED.embedding_dimensions,
            content_sha256 = EXCLUDED.content_sha256,
            content_text = EXCLUDED.content_text,
            embedding = EXCLUDED.embedding,
            metadata = EXCLUDED.metadata,
            embedded_at = now(),
            updated_at = now()
        WHERE vec_embeddings.source_observed_at IS DISTINCT FROM EXCLUDED.source_observed_at
           OR vec_embeddings.source_stream_name IS DISTINCT FROM EXCLUDED.source_stream_name
           OR vec_embeddings.source_sensor_id IS DISTINCT FROM EXCLUDED.source_sensor_id
           OR vec_embeddings.source_location_id IS DISTINCT FROM EXCLUDED.source_location_id
           OR vec_embeddings.source_mac IS DISTINCT FROM EXCLUDED.source_mac
           OR vec_embeddings.embedding_dimensions IS DISTINCT FROM EXCLUDED.embedding_dimensions
           OR vec_embeddings.content_sha256 IS DISTINCT FROM EXCLUDED.content_sha256
           OR vec_embeddings.content_text IS DISTINCT FROM EXCLUDED.content_text
           OR vec_embeddings.metadata IS DISTINCT FROM EXCLUDED.metadata
        "#,
    )
    .bind(&job.source_table)
    .bind(&job.source_key)
    .bind(input.source_observed_at)
    .bind(&input.source_stream_name)
    .bind(&input.source_sensor_id)
    .bind(&input.source_location_id)
    .bind(&input.source_mac)
    .bind(&job.embedding_model)
    .bind(&job.embedding_kind)
    .bind(dimensions)
    .bind(content_sha256)
    .bind(&input.text)
    .bind(&vector_literal)
    .bind(serde_json::json!(build_metadata(input)))
    .execute(pool)
    .await?;

    Ok(())
}

/// Upsert an embedding row into `vec_embeddings` within a transaction.
///
/// Transaction-aware variant of [`upsert_embedding`] that accepts a mutable transaction
/// reference instead of a pool. Used to atomically complete the embedding upsert
/// and job completion together.
#[instrument(skip(tx, job, input, vector))]
pub async fn upsert_embedding_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &EmbeddingJob,
    input: &EmbeddingInput,
    content_sha256: &str,
    vector: &[f32],
    dimensions: i32,
) -> Result<(), sqlx::Error> {
    let vector_literal = format_vector_literal(vector);

    sqlx::query(
        r#"
        INSERT INTO vec_embeddings (
            source_table, source_key, source_observed_at, source_stream_name,
            source_sensor_id, source_location_id, source_mac,
            embedding_model, embedding_kind, embedding_dimensions,
            content_sha256, content_text, embedding, metadata,
            embedded_at, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4,
            $5, $6, $7,
            $8, $9, $10,
            $11, $12, $13::vector, $14::jsonb,
            now(), now(), now()
        )
        ON CONFLICT (source_table, source_key, embedding_model, embedding_kind)
        DO UPDATE SET
            source_observed_at = EXCLUDED.source_observed_at,
            source_stream_name = EXCLUDED.source_stream_name,
            source_sensor_id = EXCLUDED.source_sensor_id,
            source_location_id = EXCLUDED.source_location_id,
            source_mac = EXCLUDED.source_mac,
            embedding_dimensions = EXCLUDED.embedding_dimensions,
            content_sha256 = EXCLUDED.content_sha256,
            content_text = EXCLUDED.content_text,
            embedding = EXCLUDED.embedding,
            metadata = EXCLUDED.metadata,
            embedded_at = now(),
            updated_at = now()
        WHERE vec_embeddings.source_observed_at IS DISTINCT FROM EXCLUDED.source_observed_at
           OR vec_embeddings.source_stream_name IS DISTINCT FROM EXCLUDED.source_stream_name
           OR vec_embeddings.source_sensor_id IS DISTINCT FROM EXCLUDED.source_sensor_id
           OR vec_embeddings.source_location_id IS DISTINCT FROM EXCLUDED.source_location_id
           OR vec_embeddings.source_mac IS DISTINCT FROM EXCLUDED.source_mac
           OR vec_embeddings.embedding_dimensions IS DISTINCT FROM EXCLUDED.embedding_dimensions
           OR vec_embeddings.content_sha256 IS DISTINCT FROM EXCLUDED.content_sha256
           OR vec_embeddings.content_text IS DISTINCT FROM EXCLUDED.content_text
           OR vec_embeddings.metadata IS DISTINCT FROM EXCLUDED.metadata
        "#,
    )
    .bind(&job.source_table)
    .bind(&job.source_key)
    .bind(input.source_observed_at)
    .bind(&input.source_stream_name)
    .bind(&input.source_sensor_id)
    .bind(&input.source_location_id)
    .bind(&input.source_mac)
    .bind(&job.embedding_model)
    .bind(&job.embedding_kind)
    .bind(dimensions)
    .bind(content_sha256)
    .bind(&input.text)
    .bind(&vector_literal)
    .bind(serde_json::json!(build_metadata(input)))
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Upsert embeddings and mark jobs completed in one database round-trip.
///
/// Calls `vec_complete_embedding_batch($1::jsonb)`. All rows must pass lease-token
/// checks or they are skipped by the function (not counted in the return value).
#[instrument(skip(pool, rows))]
pub async fn complete_embedding_batch(
    pool: &PgPool,
    rows: &[CompleteBatchRow],
) -> Result<i32, sqlx::Error> {
    if rows.is_empty() {
        return Ok(0);
    }
    let payload = serde_json::to_value(rows).map_err(|e| sqlx::Error::Decode(e.into()))?;
    let (count,): (i32,) =
        sqlx::query_as("SELECT vec_complete_embedding_batch($1::jsonb) AS completed_count")
            .bind(payload)
            .fetch_one(pool)
            .await?;
    Ok(count)
}

/// Return the subset of job IDs that are already completed.
#[instrument(skip(pool, job_ids))]
pub async fn completed_job_ids(
    pool: &PgPool,
    job_ids: &[i64],
) -> Result<HashSet<i64>, sqlx::Error> {
    if job_ids.is_empty() {
        return Ok(HashSet::new());
    }

    let rows: Vec<i64> = sqlx::query_scalar(
        r#"
        SELECT job_id
        FROM vec_embedding_jobs
        WHERE job_id = ANY($1::bigint[])
          AND status = 'completed'
        "#,
    )
    .bind(job_ids)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().collect())
}

/// Build a [`CompleteBatchRow`] from job, input, digest, and vector.
pub fn complete_batch_row(
    job: &EmbeddingJob,
    input: &EmbeddingInput,
    content_sha256: &str,
    vector: &[f32],
    dimensions: i32,
) -> CompleteBatchRow {
    CompleteBatchRow {
        job_id: job.job_id,
        lease_token: job.lease_token.clone(),
        source_table: job.source_table.clone(),
        source_key: job.source_key.clone(),
        source_observed_at: input.source_observed_at,
        source_stream_name: input.source_stream_name.clone(),
        source_sensor_id: input.source_sensor_id.clone(),
        source_location_id: input.source_location_id.clone(),
        source_mac: input.source_mac.clone(),
        embedding_model: job.embedding_model.clone(),
        embedding_kind: job.embedding_kind.clone(),
        embedding_dimensions: dimensions,
        content_sha256: content_sha256.to_string(),
        content_text: input.text.clone(),
        embedding: format_vector_literal(vector),
        metadata: build_metadata(input),
        explanation_text: None,
    }
}

/// Build the metadata JSON object from an `EmbeddingInput`.
fn build_metadata(input: &EmbeddingInput) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(ref v) = input.source_stream_name {
        map.insert("source_stream_name".to_string(), serde_json::json!(v));
    }
    if let Some(ref v) = input.source_sensor_id {
        map.insert("source_sensor_id".to_string(), serde_json::json!(v));
    }
    if let Some(ref v) = input.source_location_id {
        map.insert("source_location_id".to_string(), serde_json::json!(v));
    }
    if let Some(ref v) = input.source_mac {
        map.insert("source_mac".to_string(), serde_json::json!(v));
    }
    serde_json::Value::Object(map)
}

/// Format a slice of floats as `[f1,f2,...]` — a valid pgvector literal.
fn format_vector_literal(vector: &[f32]) -> String {
    let mut s = String::with_capacity(vector.len() * 12 + 2);
    s.push('[');
    for (i, val) in vector.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write_float(&mut s, *val);
    }
    s.push(']');
    s
}

/// Append a float to a string with minimal representation.
fn write_float(s: &mut String, val: f32) {
    use std::fmt::Write;
    if val.fract() == 0.0 && val.is_finite() {
        let _ = write!(s, "{:.1}", val);
    } else {
        let _ = write!(s, "{}", val);
    }
}

// ---------------------------------------------------------------------------
// Worker state heartbeat
// ---------------------------------------------------------------------------

/// Upsert a row in `vec_worker_state`.
///
/// Matches the Ruby reference:
/// - `INSERT INTO vec_worker_state (...) VALUES (...) ON CONFLICT (worker_name) DO UPDATE SET ...`
/// - `rows_processed` is *incremented* when the new value is positive, otherwise left unchanged.
/// - `last_cursor`, `last_run_started_at`, `last_run_finished_at` use
///   `COALESCE(EXCLUDED.*, vec_worker_state.*)`.
#[instrument(skip(pool))]
pub async fn mark_worker_state(
    pool: &PgPool,
    params: &WorkerStateParams,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO vec_worker_state (
            worker_name, status, last_cursor, last_run_started_at,
            last_run_finished_at, rows_processed, last_error, updated_at
        )
        VALUES (
            $1, $2, $3, $4,
            $5, $6, $7, now()
        )
        ON CONFLICT (worker_name) DO UPDATE SET
            status = EXCLUDED.status,
            last_cursor = COALESCE(EXCLUDED.last_cursor, vec_worker_state.last_cursor),
            last_run_started_at = COALESCE(EXCLUDED.last_run_started_at, vec_worker_state.last_run_started_at),
            last_run_finished_at = COALESCE(EXCLUDED.last_run_finished_at, vec_worker_state.last_run_finished_at),
            rows_processed = CASE
                WHEN EXCLUDED.rows_processed > 0
                THEN vec_worker_state.rows_processed + EXCLUDED.rows_processed
                ELSE vec_worker_state.rows_processed
            END,
            last_error = EXCLUDED.last_error,
            updated_at = now()
        "#,
    )
    .bind(&params.worker_name)
    .bind(&params.status)
    .bind(&params.last_cursor)
    .bind(params.last_run_started_at)
    .bind(params.last_run_finished_at)
    .bind(params.rows_processed)
    .bind(&params.last_error)
    .execute(pool)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Lease reaper
// ---------------------------------------------------------------------------

/// Release any leases that have expired in the database.
///
/// Calls `SELECT vec_release_expired_leases()` which returns the number of
/// jobs that were reset to `pending`.  The PostgreSQL function returns
/// `integer`, so we decode into `i32`.
#[instrument(skip(pool))]
pub async fn release_expired_leases(pool: &PgPool) -> Result<i32, sqlx::Error> {
    let row: (i32,) = sqlx::query_as("SELECT vec_release_expired_leases()")
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}

#[instrument(skip(pool))]
pub async fn count_high_risk_aps(pool: &PgPool, threshold: f64) -> Result<i64, sqlx::Error> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM mv_ap_risk_score WHERE composite_risk > $1")
            .bind(threshold)
            .fetch_one(pool)
            .await?;

    Ok(row.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_seconds_clamps_low() {
        assert_eq!(backoff_seconds(0), 10);
        assert_eq!(backoff_seconds(1), 10);
    }

    #[test]
    fn backoff_seconds_linear() {
        assert_eq!(backoff_seconds(2), 20);
        assert_eq!(backoff_seconds(5), 50);
    }

    #[test]
    fn backoff_seconds_clamps_high() {
        assert_eq!(backoff_seconds(30), 300);
        assert_eq!(backoff_seconds(100), 300);
    }

    #[test]
    fn format_vector_literal_empty() {
        assert_eq!(format_vector_literal(&[]), "[]");
    }

    #[test]
    fn format_vector_literal_integers() {
        let v = format_vector_literal(&[1.0, 2.0, 3.0]);
        assert_eq!(v, "[1.0,2.0,3.0]");
    }

    #[test]
    fn format_vector_literal_fractional() {
        let v = format_vector_literal(&[0.123456, -1.5, 3.14159]);
        assert!(v.starts_with('['));
        assert!(v.ends_with(']'));
        assert!(v.contains("0.123456"));
        assert!(v.contains("-1.5"));
    }

    #[test]
    fn build_metadata_skips_nones() {
        let input = EmbeddingInput {
            text: "test".into(),
            source_observed_at: None,
            source_stream_name: Some("wireless.audit".into()),
            source_sensor_id: None,
            source_location_id: Some("loc-1".into()),
            source_mac: None,
        };
        let meta = build_metadata(&input);
        let obj = meta.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert_eq!(obj["source_stream_name"], "wireless.audit");
        assert_eq!(obj["source_location_id"], "loc-1");
    }
}
