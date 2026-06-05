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
    .bind(build_metadata(input))
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

/// Upsert one embedding and mark its job completed in one database round-trip.
///
/// Calls `vec_complete_one_embedding($1::jsonb)`. Returns `false` when the job
/// row no longer matches the lease token.
#[instrument(skip(pool, row))]
pub async fn complete_one_embedding(
    pool: &PgPool,
    row: &CompleteBatchRow,
) -> Result<bool, sqlx::Error> {
    let payload = serde_json::to_value(row).map_err(|e| sqlx::Error::Decode(e.into()))?;
    sqlx::query_scalar("SELECT vec_complete_one_embedding($1::jsonb)")
        .bind(payload)
        .fetch_one(pool)
        .await
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
    let metadata = EmbeddingMetadata {
        source_stream_name: input.source_stream_name.as_deref(),
        source_sensor_id: input.source_sensor_id.as_deref(),
        source_location_id: input.source_location_id.as_deref(),
        source_mac: input.source_mac.as_deref(),
    };
    serde_json::to_value(metadata).expect("embedding metadata serialization cannot fail")
}

/// Format a slice of floats as `[f1,f2,...]` — a valid pgvector literal.
fn format_vector_literal(vector: &[f32]) -> String {
    let mut s = String::with_capacity(vector.len() * 9 + 2);
    let mut buffer = ryu::Buffer::new();
    s.push('[');
    for (i, val) in vector.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write_float(&mut s, &mut buffer, *val);
    }
    s.push(']');
    s
}

/// Append a float to a string with minimal representation.
fn write_float(s: &mut String, buffer: &mut ryu::Buffer, val: f32) {
    if val.is_finite() {
        s.push_str(buffer.format_finite(val));
    } else {
        use std::fmt::Write;

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

/// Attempt to acquire a DB advisory lock for the alert sweep.
/// Returns true if the lock was acquired (caller should run the sweep).
/// The lock is automatically released at the end of the session or
/// by calling finish_alert_sweep.
#[instrument(skip(pool))]
pub async fn try_begin_alert_sweep(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as("SELECT vec_try_begin_maintenance_job('alert-sweep')")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Release the DB advisory lock for the alert sweep.
#[instrument(skip(pool))]
pub async fn finish_alert_sweep(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT vec_finish_maintenance_job('alert-sweep')")
        .execute(pool)
        .await?;
    Ok(())
}
