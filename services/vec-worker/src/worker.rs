//! Worker orchestration — real database and embedding provider calls.
//!
//! # Span hierarchy during a single pass
//!
//! ```text
//! run_forever (worker_name, model, dimensions)
//! ├── run_once (rows_leased, rows_completed, rows_failed on exit)
//! │   ├── prepare_chunk (prepare_ms)
//! │   ├── embed_chunk (embed_ms)
//! │   └── complete_chunk (complete_ms)
//! └── run_once ...
//! ```

use crate::alerts::{self, AlertConfig};
use crate::db::{self, CompleteBatchRow, EmbeddingJob, WorkerStateParams};
use crate::embedder::EmbeddingClient;
use crate::text_builder;
use crate::{Config, WorkerError};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, debug_span, error, info, info_span, warn};

/// Run the worker loop indefinitely (or once if `config.once` is set).
pub async fn run_forever(
    config: Config,
    pool: PgPool,
    embedder: EmbeddingClient,
) -> Result<(), WorkerError> {
    let _startup = info_span!(
        "worker_startup",
        worker_name = %config.worker_name,
        model = %config.model,
        dimensions = config.dimensions,
    )
    .entered();

    info!("worker started");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    install_signal_handler(shutdown_tx);

    let mut iteration: u64 = 0;

    loop {
        if *shutdown_rx.borrow() {
            info!("shutdown signal received, exiting");
            break;
        }

        match run_once(&config, &pool, &embedder).await {
            Ok(count) => {
                info!(rows_processed = count, "run_once summary");
                if count == 0 {
                    debug!("no jobs leased, sleeping");
                    sleep_or_shutdown(config.poll_interval_secs, shutdown_rx.clone()).await;
                }
            }
            Err(e) => {
                error!(error = %e, "run_once failed, will retry");
                sleep_or_shutdown(config.poll_interval_secs, shutdown_rx.clone()).await;
            }
        }

        iteration += 1;

        // Periodic maintenance: release expired leases every 10 iterations
        if iteration % 10 == 0 {
            match db::release_expired_leases(&pool).await {
                Ok(released) if released > 0 => {
                    info!(released, "expired leases released");
                }
                Err(e) => warn!(error = %e, "release_expired_leases failed"),
                _ => {}
            }

            // Periodic alert sweep every 10 iterations
            let alert_cfg = AlertConfig::default();
            if let Err(e) = alerts::run_alert_sweep(&pool, &alert_cfg).await {
                warn!(error = %e, "alert sweep failed");
            }
        }

        if config.once {
            info!("--once mode, exiting after single pass");
            break;
        }
    }

    info!("worker finished");
    Ok(())
}

/// Execute a single pass: update worker state, lease jobs, process them, then idle.
pub async fn run_once(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
) -> Result<usize, WorkerError> {
    let _run_once = debug_span!("run_once").entered();
    let started_at = chrono::Utc::now();

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
        let idle_params = WorkerStateParams {
            status: "idle".to_string(),
            last_run_finished_at: Some(chrono::Utc::now()),
            ..running_params
        };
        db::mark_worker_state(pool, &idle_params).await?;
        return Ok(0);
    }

    let processed = process_jobs(config, pool, embedder, jobs).await;

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

/// Process leased jobs with pipelined prepare / embed / complete across request chunks.
pub async fn process_jobs(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
    jobs: Vec<EmbeddingJob>,
) -> usize {
    let chunks: Vec<Vec<EmbeddingJob>> = jobs
        .chunks(config.request_batch_size)
        .map(|c| c.to_vec())
        .collect();
    let total = jobs.len();
    let n = chunks.len();

    if n == 0 {
        return 0;
    }

    let embed_sem = Arc::new(Semaphore::new(config.max_concurrent_embed_requests.max(1)));
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut next_prepare: Option<JoinHandle<PrepareChunkResult>> = None;
    let mut complete_handle: Option<JoinHandle<CompleteChunkResult>> = None;

    for i in 0..n {
        let chunk = chunks[i].clone();
        let prepared = match next_prepare.take() {
            Some(handle) => handle.await.unwrap_or_else(|e| panic!("prepare panicked: {e}")),
            None => prepare_chunk(pool, chunk).await,
        };

        if i + 1 < n {
            let next_chunk = chunks[i + 1].clone();
            let pool = pool.clone();
            next_prepare = Some(tokio::spawn(async move {
                prepare_chunk(&pool, next_chunk).await
            }));
        }

        let embedded = embed_chunk(config, pool, embedder, prepared, &embed_sem).await;

        if let Some(handle) = complete_handle.take() {
            let result = handle.await.unwrap_or_else(|e| panic!("complete panicked: {e}"));
            succeeded += result.succeeded;
            failed += result.failed;
        }

        let cfg = config.clone();
        let pool = pool.clone();
        complete_handle = Some(tokio::spawn(async move {
            complete_chunk(&cfg, &pool, embedded).await
        }));
    }

    if let Some(handle) = complete_handle {
        let result = handle.await.unwrap_or_else(|e| panic!("complete panicked: {e}"));
        succeeded += result.succeeded;
        failed += result.failed;
    }

    debug!(total, succeeded, failed, "process_jobs done");
    succeeded
}

// ---------------------------------------------------------------------------
// Chunk pipeline stages
// ---------------------------------------------------------------------------

struct PreparedJob {
    job: EmbeddingJob,
    input: crate::db::EmbeddingInput,
    content_sha256: String,
}

struct PrepareChunkResult {
    prepared: Vec<PreparedJob>,
    failed: usize,
    prepare_ms: u64,
}

struct EmbeddedChunkResult {
    items: Vec<(PreparedJob, Vec<f32>)>,
    failed: usize,
    prepare_ms: u64,
    embed_ms: u64,
}

struct CompleteChunkResult {
    succeeded: usize,
    failed: usize,
}

async fn prepare_chunk(pool: &PgPool, jobs: Vec<EmbeddingJob>) -> PrepareChunkResult {
    let start = Instant::now();
    let batch_size = jobs.len();

    let inputs = match text_builder::build_text_batch(pool, &jobs).await {
        Ok(map) => map,
        Err(e) => {
            warn!(error = %e, "build_text_batch failed, failing entire chunk");
            let mut failed = 0usize;
            for job in &jobs {
                if fail_job_with_error(pool, job, &e.to_string()).await {
                    failed += 1;
                }
            }
            return PrepareChunkResult {
                prepared: Vec::new(),
                failed,
                prepare_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let mut prepared = Vec::with_capacity(jobs.len());
    let mut failed = 0usize;

    for job in jobs {
        match inputs.get(&job.source_key) {
            Some(input) => {
                prepared.push(PreparedJob {
                    job,
                    input: input.clone(),
                    content_sha256: sha256_hex(&input.text),
                });
            }
            None => {
                let msg = format!("source row not found: {}", job.source_key);
                warn!(job_id = job.job_id, "{msg}");
                if fail_job_with_error(pool, &job, &msg).await {
                    failed += 1;
                }
            }
        }
    }

    let prepare_ms = start.elapsed().as_millis() as u64;
    debug!(batch_size, prepare_ms, prepared = prepared.len(), failed, "prepare_chunk done");

    PrepareChunkResult {
        prepared,
        failed,
        prepare_ms,
    }
}

async fn embed_chunk(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
    prepared_chunk: PrepareChunkResult,
    embed_sem: &Semaphore,
) -> EmbeddedChunkResult {
    let start = Instant::now();
    let prepare_ms = prepared_chunk.prepare_ms;
    let mut failed = prepared_chunk.failed;

    if prepared_chunk.prepared.is_empty() {
        return EmbeddedChunkResult {
            items: Vec::new(),
            failed,
            prepare_ms,
            embed_ms: 0,
        };
    }

    let texts: Vec<String> = prepared_chunk
        .prepared
        .iter()
        .map(|p| p.input.text.clone())
        .collect();

    let _permit = embed_sem.acquire().await.expect("embed semaphore closed");

    let embeddings = match embedder.embed_many(&texts).await {
        Ok(emb) => emb,
        Err(e) => {
            error!(error = %e, "embed_many failed, failing entire chunk");
            for p in &prepared_chunk.prepared {
                if fail_job_with_error(pool, &p.job, &e.to_string()).await {
                    failed += 1;
                }
            }
            return EmbeddedChunkResult {
                items: Vec::new(),
                failed,
                prepare_ms,
                embed_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let embed_ms = start.elapsed().as_millis() as u64;
    let mut items = Vec::with_capacity(prepared_chunk.prepared.len());

    for (prepared_job, vector) in prepared_chunk.prepared.into_iter().zip(embeddings) {
        if let Err(e) = embedder.validate_dimensions(&vector, config.dimensions) {
            warn!(
                job_id = prepared_job.job.job_id,
                error = %e,
                "dimension mismatch, failing job",
            );
            if fail_job_with_error(pool, &prepared_job.job, &e.to_string()).await {
                failed += 1;
            }
            continue;
        }
        items.push((prepared_job, vector));
    }

    EmbeddedChunkResult {
        items,
        failed,
        prepare_ms,
        embed_ms,
    }
}

async fn complete_chunk(
    config: &Config,
    pool: &PgPool,
    embedded: EmbeddedChunkResult,
) -> CompleteChunkResult {
    let start = Instant::now();
    let mut succeeded = 0usize;
    let mut failed = embedded.failed;

    if embedded.items.is_empty() {
        let complete_ms = start.elapsed().as_millis() as u64;
        log_batch_metrics(
            embedded.prepare_ms,
            embedded.embed_ms,
            complete_ms,
            succeeded,
            failed,
        );
        return CompleteChunkResult { succeeded, failed };
    }

    let dimensions = config.dimensions as i32;
    let batch_rows: Vec<CompleteBatchRow> = embedded
        .items
        .iter()
        .map(|(p, v)| {
            db::complete_batch_row(&p.job, &p.input, &p.content_sha256, v, dimensions)
        })
        .collect();

    match db::complete_embedding_batch(pool, &batch_rows).await {
        Ok(completed) => {
            let completed = completed as usize;
            if completed == batch_rows.len() {
                succeeded = completed;
            } else if completed > 0 {
                warn!(
                    expected = batch_rows.len(),
                    completed,
                    "bulk complete partial, falling back per job"
                );
                let (s, f) = complete_jobs_fallback(config, pool, &embedded.items).await;
                succeeded = s;
                failed += f;
            } else {
                warn!("bulk complete returned 0, falling back per job");
                let (s, f) = complete_jobs_fallback(config, pool, &embedded.items).await;
                succeeded = s;
                failed += f;
            }
        }
        Err(e) => {
            warn!(error = %e, "bulk complete failed, falling back per job");
            let (s, f) = complete_jobs_fallback(config, pool, &embedded.items).await;
            succeeded = s;
            failed += f;
        }
    }

    let complete_ms = start.elapsed().as_millis() as u64;
    log_batch_metrics(
        embedded.prepare_ms,
        embedded.embed_ms,
        complete_ms,
        succeeded,
        failed,
    );

    CompleteChunkResult { succeeded, failed }
}

async fn complete_jobs_fallback(
    config: &Config,
    pool: &PgPool,
    items: &[(PreparedJob, Vec<f32>)],
) -> (usize, usize) {
    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_completes));
    let mut tasks: FuturesUnordered<_> = items
        .iter()
        .map(|(prepared, vector)| {
            let semaphore = Arc::clone(&semaphore);
            let pool = pool.clone();
            let dimensions = config.dimensions;
            async move {
                let _permit = semaphore.acquire().await.expect("complete semaphore closed");
                match complete_job_pipeline(&pool, dimensions, prepared, vector).await {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        if fail_job_with_error(&pool, &prepared.job, &e.to_string()).await {
                            Err(())
                        } else {
                            Err(())
                        }
                    }
                }
            }
        })
        .collect();

    let mut succeeded = 0usize;
    let mut failed = 0usize;
    while let Some(result) = tasks.next().await {
        match result {
            Ok(()) => succeeded += 1,
            Err(()) => failed += 1,
        }
    }
    (succeeded, failed)
}

fn log_batch_metrics(
    prepare_ms: u64,
    embed_ms: u64,
    complete_ms: u64,
    jobs_ok: usize,
    jobs_failed: usize,
) {
    info!(
        prepare_ms,
        embed_ms,
        complete_ms,
        jobs_ok,
        jobs_failed,
        "batch timing"
    );
}

async fn complete_job_pipeline(
    pool: &PgPool,
    dimensions: usize,
    prepared: &PreparedJob,
    vector: &[f32],
) -> Result<(), WorkerError> {
    let mut tx = pool.begin().await?;

    db::upsert_embedding_tx(
        &mut tx,
        &prepared.job,
        &prepared.input,
        &prepared.content_sha256,
        vector,
        dimensions as i32,
    )
    .await?;

    db::complete_job_tx(
        &mut tx,
        prepared.job.job_id,
        prepared.job.lease_token.as_deref(),
        &prepared.content_sha256,
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

async fn fail_job_with_error(pool: &PgPool, job: &EmbeddingJob, message: &str) -> bool {
    db::fail_job(
        pool,
        job.job_id,
        job.lease_token.as_deref(),
        job.attempts,
        job.max_attempts,
        message,
    )
    .await
    .is_ok()
}

fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

fn install_signal_handler(shutdown_tx: watch::Sender<bool>) {
    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            match signal::ctrl_c().await {
                Ok(()) => {
                    info!("SIGINT received, initiating graceful shutdown");
                    let _ = shutdown_tx.send(true);
                }
                Err(e) => error!(error = %e, "SIGINT handler error"),
            }
        }
    });

    #[cfg(unix)]
    tokio::spawn(async move {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                info!("SIGTERM handler installed");
                sig.recv().await;
                info!("SIGTERM received, initiating graceful shutdown");
                let _ = shutdown_tx.send(true);
            }
            Err(e) => error!(error = %e, "failed to install SIGTERM handler"),
        }
    });
}

async fn sleep_or_shutdown(secs: u64, mut shutdown_rx: watch::Receiver<bool>) {
    if secs == 0 || *shutdown_rx.borrow() {
        return;
    }

    let sleep = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(sleep);

    tokio::select! {
        _ = &mut sleep => {}
        _ = shutdown_rx.changed() => {}
    }
}
