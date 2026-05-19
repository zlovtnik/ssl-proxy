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
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
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

/// Open a new connection pool to the PostgreSQL database.
///
/// Uses `sqlx::PgPoolOptions` with default settings.  Call once at startup
/// and share the pool via `Arc` or injection.
#[instrument]
pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
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
    content_sha256: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
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
        "#,
    )
    .bind(content_sha256)
    .bind(job_id)
    .execute(pool)
    .await?;

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
    attempts: i32,
    max_attempts: i32,
    error_message: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
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
        "#,
    )
    .bind(error_message)
    .bind(attempts)
    .bind(max_attempts)
    .bind(backoff_seconds(attempts))
    .bind(job_id)
    .execute(pool)
    .await?;

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
#[instrument(skip(pool, vector))]
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