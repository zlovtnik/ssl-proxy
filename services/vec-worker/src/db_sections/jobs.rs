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

#[derive(Serialize)]
struct EmbeddingMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    source_stream_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_sensor_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_location_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_mac: Option<&'a str>,
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
    .bind(build_metadata(input))
    .execute(pool)
    .await?;

    Ok(())
}
