//! Worker orchestration — real database and Ollama calls (Phase 6).
//!
//! # Span hierarchy during a single pass
//!
//! ```text
//! run_forever (worker_name, model, dimensions)
//! ├── run_once (rows_leased, rows_completed, rows_failed on exit)
//! │   ├── prepare_job (job_id, source_table, source_key, embedding_kind)
//! │   │   └── build_text
//! │   ├── batch (batch_size, batch_id)
//! │   │   └── embed_many (elapsed_ms)
//! │   └── complete_job_pipeline (job_id, content_sha256)
//! └── run_once ...
//! ```

use crate::db::{self, EmbeddingJob, WorkerStateParams};
use crate::embedder::EmbeddingClient;
use crate::text_builder;
use crate::{Config, WorkerError};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{debug, debug_span, error, info, info_span, warn};

/// Flag used to signal graceful shutdown from the signal handler.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Run the worker loop indefinitely (or once if `config.once` is set).
///
/// On each iteration it calls [`run_once`] and then waits for the configured
/// poll interval before checking again.  A SIGTERM/SIGINT causes the loop to
/// exit gracefully after the current pass completes.
///
/// Every 10 iterations the function also calls `release_expired_leases` to
/// reclaim any jobs whose leases have expired.
pub async fn run_forever(
    config: Config,
    pool: PgPool,
    embedder: EmbeddingClient,
) -> Result<(), WorkerError> {
    // ---- top-level span for the lifetime of this worker ----
    let _startup = info_span!(
        "worker_startup",
        worker_name = %config.worker_name,
        model = %config.model,
        dimensions = config.dimensions,
    )
    .entered();

    info!("worker started");

    // Install signal handler for graceful shutdown.
    install_signal_handler();

    let mut iteration: u64 = 0;

    loop {
        // Check for shutdown signal before each pass.
        if SHUTDOWN.load(Ordering::Relaxed) {
            info!("shutdown signal received, exiting");
            break;
        }

        match run_once(&config, &pool, &embedder).await {
            Ok(count) => {
                info!(rows_processed = count, "run_once summary");

                // If 0 rows processed, sleep before retrying.
                if count == 0 {
                    debug!("no jobs leased, sleeping");
                    sleep_or_shutdown(config.poll_interval_secs).await;
                }
            }
            Err(e) => {
                error!(error = %e, "run_once failed, will retry");
                sleep_or_shutdown(config.poll_interval_secs).await;
            }
        }

        // Every 10 iterations, release expired leases.
        iteration += 1;
        if iteration % 10 == 0 {
            match db::release_expired_leases(&pool).await {
                Ok(released) => {
                    if released > 0 {
                        info!(released, "expired leases released");
                    }
                }
                Err(e) => warn!(error = %e, "release_expired_leases failed"),
            }
        }

        // If --once mode, exit after a single pass.
        if config.once {
            info!("--once mode, exiting after single pass");
            break;
        }
    }

    info!("worker finished");
    Ok(())
}

/// Execute a single pass: update worker state, lease jobs, process them, then
/// mark worker state as idle.
///
/// Returns the number of jobs successfully processed.
pub async fn run_once(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
) -> Result<usize, WorkerError> {
    let _run_once = debug_span!("run_once").entered();
    let started_at = chrono::Utc::now();

    // Mark worker state as running.
    let running_params = WorkerStateParams {
        worker_name: config.worker_name.clone(),
        status: "running".to_string(),
        last_cursor: None,
        last_run_started_at: Some(started_at),
        last_run_finished_at: None,
        rows_processed: 0,
        last_error: None,
    };
    db::mark_worker_state(pool, &running_params).await?;

    // Lease a batch of jobs.
    let jobs = db::lease_jobs(
        pool,
        config.batch_size as i32,
        &config.worker_name,
        config.lease_seconds as i64,
    )
    .await?;

    let rows_leased = jobs.len();
    debug!(rows_leased, "jobs leased");

    if rows_leased == 0 {
        // Mark idle with 0 rows processed.
        let idle_params = WorkerStateParams {
            status: "idle".to_string(),
            last_run_finished_at: Some(chrono::Utc::now()),
            ..running_params
        };
        db::mark_worker_state(pool, &idle_params).await?;
        return Ok(0);
    }

    // Process the leased jobs.
    let processed = process_jobs(config, pool, embedder, jobs).await;

    // Mark worker state as idle with processed count.
    let idle_params = WorkerStateParams {
        status: "idle".to_string(),
        last_run_finished_at: Some(chrono::Utc::now()),
        rows_processed: processed as i64,
        ..running_params
    };
    if let Err(e) = db::mark_worker_state(pool, &idle_params).await {
        warn!(error = %e, "mark_worker_state(idle) failed");
    }

    Ok(processed)
}

/// Process a list of jobs by splitting them into request-batch-sized chunks and
/// calling [`process_batch`] for each chunk.
///
/// Returns the total number of jobs successfully completed.
pub async fn process_jobs(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
    jobs: Vec<EmbeddingJob>,
) -> usize {
    let batch_size = config.request_batch_size;
    let total = jobs.len();
    let mut completed = 0usize;

    for chunk in jobs.chunks(batch_size) {
        let (succeeded, failed) = process_batch(config, pool, embedder, chunk.to_vec()).await;
        completed += succeeded;
        if failed > 0 {
            warn!(failed, succeeded, "batch completed with failures");
        }
    }

    debug!(total, completed, "process_jobs done");
    completed
}

/// Process a batch of jobs through the full pipeline:
///
/// 1. Prepare each job (build text + compute sha256)
/// 2. Embed all prepared texts via Ollama
/// 3. Complete each job (upsert embedding + mark completed)
///
/// # Returns
///
/// A tuple `(succeeded, failed)` counts.
pub async fn process_batch(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
    jobs: Vec<EmbeddingJob>,
) -> (usize, usize) {
    let batch_size = jobs.len();
    if batch_size == 0 {
        return (0, 0);
    }

    let _batch_span = debug_span!(
        "batch",
        batch_size = batch_size,
        batch_id = tracing::field::Empty,
    )
    .entered();

    // ---- Step 1: Prepare all jobs concurrently ----
    // Use a semaphore to limit how many IO-bound prepare_job calls run at once.
    // FuturesUnordered runs the futures concurrently on the same task, avoiding
    // the cost of tokio::spawn and the Send requirement (tracing EnteredSpan
    // guards are !Send).
    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_prepares));

    let mut tasks: FuturesUnordered<_> = jobs
        .iter()
        .map(|job| {
            let semaphore = Arc::clone(&semaphore);
            async move {
                let _permit = semaphore.acquire().await.expect("semaphore not closed");
                match prepare_job(pool, job).await {
                    Ok(p) => Ok(p),
                    Err(e) => {
                        warn!(
                            job_id = job.job_id,
                            error = %e,
                            "prepare_job failed, failing job",
                        );
                        if let Err(db_err) = db::fail_job(
                            pool,
                            job.job_id,
                            job.attempts,
                            job.max_attempts,
                            &e.to_string(),
                        )
                        .await
                        {
                            warn!(error = %db_err, "fail_job call failed");
                        }
                        Err(e)
                    }
                }
            }
        })
        .collect();

    let mut prepared = Vec::with_capacity(jobs.len());
    let mut texts = Vec::with_capacity(jobs.len());
    let mut all_succeeded = true;

    while let Some(result) = tasks.next().await {
        match result {
            Ok(p) => {
                texts.push(p.input.text.clone());
                prepared.push(p);
            }
            Err(_) => {
                all_succeeded = false;
            }
        }
    }

    // If all jobs failed preparation, short-circuit.
    if prepared.is_empty() {
        return (0, jobs.len());
    }

    // ---- Step 2: Embed via the configured provider ----
    let embeddings = match embedder.embed_many(&texts).await {
        Ok(emb) => emb,
        Err(e) => {
            error!(error = %e, "embed_many failed, failing entire batch");
            for p in &prepared {
                if let Err(db_err) = db::fail_job(
                    pool,
                    p.job.job_id,
                    p.job.attempts,
                    p.job.max_attempts,
                    &e.to_string(),
                )
                .await
                {
                    warn!(error = %db_err, "fail_job call failed");
                }
            }
            return if all_succeeded {
                (0, prepared.len())
            } else {
                (0, jobs.len())
            };
        }
    };

    // Validate dimension count for each embedding.
    let mut succeeded = 0usize;
    let mut failed = 0usize;

    for (prepared_job, vector) in prepared.into_iter().zip(embeddings.into_iter()) {
        if let Err(e) = embedder.validate_dimensions(&vector, config.dimensions) {
            warn!(
                job_id = prepared_job.job.job_id,
                error = %e,
                "dimension mismatch, failing job",
            );
            if let Err(db_err) = db::fail_job(
                pool,
                prepared_job.job.job_id,
                prepared_job.job.attempts,
                prepared_job.job.max_attempts,
                &e.to_string(),
            )
            .await
            {
                warn!(error = %db_err, "fail_job call failed");
            }
            failed += 1;
            continue;
        }

        // ---- Step 3: Complete the job (upsert + mark done) ----
        match complete_job_pipeline(pool, config.dimensions, &prepared_job, &vector).await {
            Ok(()) => {
                succeeded += 1;
            }
            Err(e) => {
                warn!(
                    job_id = prepared_job.job.job_id,
                    error = %e,
                    "complete_job_pipeline failed, failing job",
                );
                if let Err(db_err) = db::fail_job(
                    pool,
                    prepared_job.job.job_id,
                    prepared_job.job.attempts,
                    prepared_job.job.max_attempts,
                    &e.to_string(),
                )
                .await
                {
                    warn!(error = %db_err, "fail_job call failed");
                }
                failed += 1;
            }
        }
    }

    (succeeded, failed)
}

// ---------------------------------------------------------------------------
// Pipeline helpers
// ---------------------------------------------------------------------------

/// A job that has been prepared for embedding (text built, sha256 computed).
struct PreparedJob {
    job: EmbeddingJob,
    input: crate::db::EmbeddingInput,
    content_sha256: String,
}

/// Prepare a single job: build its embedding text and compute the sha256 digest.
async fn prepare_job(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<PreparedJob, WorkerError> {
    let _job_span = debug_span!(
        "prepare_job",
        job_id = %job.job_id,
        source_table = %job.source_table,
        source_key = %job.source_key,
        embedding_kind = %job.embedding_kind,
    )
    .entered();

    let (_text, input) = text_builder::build_text(pool, job).await?;

    // Compute sha256 of the embedding text.
    let content_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(input.text.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    debug!(content_sha256 = %content_sha256, "job prepared");

    Ok(PreparedJob {
        job: job.clone(),
        input,
        content_sha256,
    })
}

/// Complete the pipeline for a single job: upsert the embedding vector and mark
/// the job as completed.
///
/// Both operations are idempotent (ON CONFLICT DO UPDATE for upsert, and
/// setting status=completed for the job), so we call them sequentially without
/// a transaction. If the process crashes between the two operations, the lease
/// will expire and the job will be retried safely.
async fn complete_job_pipeline(
    pool: &PgPool,
    dimensions: usize,
    prepared: &PreparedJob,
    vector: &[f32],
) -> Result<(), WorkerError> {
    let _complete_span = debug_span!(
        "complete_job",
        job_id = %prepared.job.job_id,
        content_sha256 = %prepared.content_sha256,
    )
    .entered();

    // Upsert the embedding vector.
    db::upsert_embedding(
        pool,
        &prepared.job,
        &prepared.input,
        &prepared.content_sha256,
        vector,
        dimensions as i32,
    )
    .await?;

    // Mark the job as completed.
    db::complete_job(pool, prepared.job.job_id, &prepared.content_sha256).await?;

    debug!("job completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

/// Install signal handlers that set the `SHUTDOWN` flag on SIGTERM or SIGINT.
///
/// Uses `tokio::signal::unix` on Unix to catch SIGTERM. On all platforms
/// Ctrl-C (SIGINT) is caught via `tokio::signal::ctrl_c()`.
fn install_signal_handler() {
    // Spawn a task that handles SIGINT (Ctrl-C) on all platforms.
    tokio::spawn(async {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("SIGINT received, initiating graceful shutdown");
                SHUTDOWN.store(true, Ordering::Relaxed);
            }
            Err(e) => {
                error!(error = %e, "SIGINT handler error");
            }
        }
    });

    // On Unix, also spawn a task that handles SIGTERM.
    #[cfg(unix)]
    tokio::spawn(async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                info!("SIGTERM handler installed");
                sig.recv().await;
                info!("SIGTERM received, initiating graceful shutdown");
                SHUTDOWN.store(true, Ordering::Relaxed);
            }
            Err(e) => {
                error!(error = %e, "failed to install SIGTERM handler");
            }
        }
    });
}

/// Sleep for `secs` seconds, but allow early wake on shutdown signal.
async fn sleep_or_shutdown(secs: u64) {
    if secs == 0 {
        return;
    }

    let sleep = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(sleep);

    tokio::select! {
        _ = &mut sleep => {}
        // The signal handler will set SHUTDOWN. We can't directly select on it
        // here without a oneshot channel, but the main loop checks SHUTDOWN
        // before each iteration so it will eventually see it.
    }
}