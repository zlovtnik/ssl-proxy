//! Worker orchestration — real database and embedding provider calls.
//!
//! # Span hierarchy during a single pass
//!
//! ```text
//! run_forever (worker_name, model, dimensions)
//! ├── run_once (drain_batches, rows_leased, rows_completed, rows_failed on exit)
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
use std::collections::HashSet;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, debug_span, error, info, info_span, warn};

/// Run the worker loop indefinitely (or once if `config.once` is set).
pub async fn run_forever(
    config: Config,
    pool: PgPool,
    alert_pool: PgPool,
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
    let mut consecutive_permanent_failures: u32 = 0;
    const PERMANENT_FAILURE_CIRCUIT_BREAKER: u32 = 5;

    loop {
        if *shutdown_rx.borrow() {
            info!("shutdown signal received, exiting");
            break;
        }

        match run_once(&config, &pool, &embedder).await {
            Ok(result) => {
                info!(
                    rows_processed = result.processed,
                    permanent_failures = result.permanent_failures,
                    rows_leased = result.rows_leased,
                    drain_batches = result.drain_batches,
                    drain_ms = result.drain_ms,
                    drained_to_empty = result.drained_to_empty,
                    max_drain_batches_reached = result.max_drain_batches_reached,
                    "run_once drain summary"
                );

                // Track permanent (4xx) embed failures for circuit breaker.
                // Reset on any successful processing; increment when all leased
                // jobs in the batch hit permanent errors (e.g. oversized payload
                // against a misconfigured llama.cpp).
                let mut slept_for_circuit_breaker = false;
                if result.processed > 0 {
                    consecutive_permanent_failures = 0;
                } else if result.permanent_failures > 0 {
                    consecutive_permanent_failures += 1;
                    if consecutive_permanent_failures >= PERMANENT_FAILURE_CIRCUIT_BREAKER {
                        error!(
                            consecutive_permanent_failures,
                            "circuit breaker tripped: too many consecutive permanent embed failures. \
                             Check VECTOR_EMBEDDING_MODEL, token limits, and provider health. \
                             Sleeping 60s before retry."
                        );
                        consecutive_permanent_failures = 0;
                        sleep_or_shutdown(60, shutdown_rx.clone()).await;
                        slept_for_circuit_breaker = true;
                    }
                }

                match loop_action_after_success(config.once, &result) {
                    LoopAction::ContinueImmediately => {}
                    LoopAction::SleepIdle => {
                        if !slept_for_circuit_breaker {
                            debug!("drain cycle reached empty queue, sleeping");
                            sleep_or_shutdown(config.poll_interval_secs, shutdown_rx.clone()).await;
                        }
                    }
                    LoopAction::ExitOnce => {
                        info!("--once mode, exiting after drain cycle");
                        break;
                    }
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

            // Periodic alert sweep every 10 iterations; run in the background on
            // the dedicated alert pool so it cannot starve the embed/complete loop.
            //
            // Uses a DB advisory lock (vec_try_begin_maintenance_job) so only one
            // replica runs the sweep at a time.  The lock is released when the
            // spawned task completes.
            //
            // Skip the sweep when the main pool is under pressure — if idle
            // connections are scarce, the embed/complete pipeline needs them
            // more than the observability sweep does.  The sweep will run on a
            // later iteration when headroom is available.
            const ALERT_MIN_FREE_CONNECTIONS: usize = 3;
            let idle = pool.num_idle();
            if idle >= ALERT_MIN_FREE_CONNECTIONS {
                let alert_pool = alert_pool.clone();
                match db::try_begin_alert_sweep(&alert_pool).await {
                    Ok(true) => {
                        tokio::spawn(async move {
                            let alert_cfg = AlertConfig::default();
                            if let Err(e) = alerts::run_alert_sweep(&alert_pool, &alert_cfg).await {
                                warn!(error = %e, "alert sweep failed (background)");
                            }
                            // count_high_risk_aps also uses the alert pool so the main loop
                            // is never blocked by a COUNT(*) on mv_ap_risk_score.
                            match db::count_high_risk_aps(&alert_pool, 0.75).await {
                                Ok(count) => info!(high_risk_ap_count = count, "high-risk AP summary"),
                                Err(e) => warn!(error = %e, "failed to query high-risk AP count"),
                            }
                            // Release the DB advisory lock.
                            if let Err(e) = db::finish_alert_sweep(&alert_pool).await {
                                warn!(error = %e, "failed to release alert sweep lock");
                            }
                        });
                    }
                    Ok(false) => {
                        debug!("skipping alert sweep — another replica already holds the lock");
                    }
                    Err(e) => {
                        warn!(error = %e, "alert sweep attempt failed");
                    }
                }
            } else {
                debug!(
                    idle_connections = idle,
                    min_required = ALERT_MIN_FREE_CONNECTIONS,
                    "skipping alert sweep — pool under pressure"
                );
            }
        }
    }

    info!("worker finished");
    Ok(())
}

/// Result of a single `run_once` pass.
pub struct RunOnceResult {
    /// Number of jobs that were successfully completed.
    pub processed: usize,
    /// Number of jobs that failed with a permanent error (e.g. 400 Bad Request).
    /// These jobs will not be retried.
    pub permanent_failures: usize,
    /// Total number of jobs that were leased in this pass.
    pub rows_leased: usize,
    /// Number of lease/process batches completed in this drain cycle.
    pub drain_batches: usize,
    /// Whether the drain cycle ended because a lease attempt returned no jobs.
    pub drained_to_empty: bool,
    /// Whether `VECTOR_EMBEDDING_MAX_DRAIN_BATCHES` stopped this drain cycle.
    pub max_drain_batches_reached: bool,
    /// Wall-clock time spent in the drain cycle.
    pub drain_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum DrainDecision {
    Continue,
    Empty,
    MaxBatchesReached,
}

#[derive(Debug, PartialEq, Eq)]
enum LoopAction {
    ContinueImmediately,
    SleepIdle,
    ExitOnce,
}

fn drain_decision(
    rows_leased: usize,
    drain_batches: usize,
    max_drain_batches: usize,
) -> DrainDecision {
    if rows_leased == 0 {
        DrainDecision::Empty
    } else if max_drain_batches > 0 && drain_batches >= max_drain_batches {
        DrainDecision::MaxBatchesReached
    } else {
        DrainDecision::Continue
    }
}

fn loop_action_after_success(once: bool, result: &RunOnceResult) -> LoopAction {
    if once {
        LoopAction::ExitOnce
    } else if result.drained_to_empty {
        LoopAction::SleepIdle
    } else {
        LoopAction::ContinueImmediately
    }
}

fn should_mark_progress_heartbeat(jobs_ok: usize, jobs_failed: usize) -> bool {
    jobs_ok > 0 || jobs_failed > 0
}

/// Execute a drain cycle: update worker state, lease and process jobs until empty,
/// then mark idle only after a lease returns no work.
pub async fn run_once(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
) -> Result<RunOnceResult, WorkerError> {
    let _run_once = debug_span!("run_once").entered();
    let drain_started = Instant::now();
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
    mark_worker_state_with_timeout(config, pool, &running_params).await?;

    let mut result = RunOnceResult {
        processed: 0,
        permanent_failures: 0,
        rows_leased: 0,
        drain_batches: 0,
        drained_to_empty: false,
        max_drain_batches_reached: false,
        drain_ms: 0,
    };

    loop {
        let jobs = lease_jobs_with_timeout(config, pool).await?;
        let rows_leased = jobs.len();
        debug!(
            rows_leased,
            drain_batches = result.drain_batches,
            "jobs leased"
        );

        if rows_leased == 0 {
            result.drained_to_empty = true;
            let idle_params = WorkerStateParams {
                status: "idle".to_string(),
                last_run_finished_at: Some(chrono::Utc::now()),
                rows_processed: 0,
                ..running_params
            };
            mark_worker_state_with_timeout(config, pool, &idle_params).await?;
            result.drain_ms = drain_started.elapsed().as_millis() as u64;
            return Ok(result);
        }

        result.rows_leased += rows_leased;
        result.drain_batches += 1;
        if rows_leased == config.batch_size {
            debug!(
                rows_leased,
                drain_batches = result.drain_batches,
                max_drain_batches = config.max_drain_batches,
                "leased full vector batch; continuing drain cycle"
            );
        }

        let (processed, permanent_failures) = process_jobs(config, pool, embedder, jobs).await;
        result.processed += processed;
        result.permanent_failures += permanent_failures;

        match drain_decision(rows_leased, result.drain_batches, config.max_drain_batches) {
            DrainDecision::Continue => {}
            DrainDecision::Empty => unreachable!("empty lease handled before processing"),
            DrainDecision::MaxBatchesReached => {
                result.max_drain_batches_reached = true;
                result.drain_ms = drain_started.elapsed().as_millis() as u64;
                info!(
                    drain_batches = result.drain_batches,
                    rows_leased = result.rows_leased,
                    rows_processed = result.processed,
                    max_drain_batches = config.max_drain_batches,
                    "max drain batches reached; yielding without idle sleep"
                );
                return Ok(result);
            }
        }
    }
}

/// Process leased jobs with pipelined prepare / embed / complete across request chunks.
///
/// Returns `(succeeded, permanent_failures)`.
pub async fn process_jobs(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
    jobs: Vec<EmbeddingJob>,
) -> (usize, usize) {
    let chunks: Vec<Vec<EmbeddingJob>> = jobs
        .chunks(config.request_batch_size)
        .map(|c| c.to_vec())
        .collect();
    let total = jobs.len();
    let n = chunks.len();

    if n == 0 {
        return (0, 0);
    }

    let embed_sem = Arc::new(Semaphore::new(config.max_concurrent_embed_requests.max(1)));
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut permanent_failed = 0usize;
    let mut next_prepare: Option<JoinHandle<PrepareChunkResult>> = None;
    let mut complete_handle: Option<JoinHandle<CompleteChunkResult>> = None;
    // Queue of in-flight embed tasks (preserves chunk order)
    let mut embed_handles: VecDeque<JoinHandle<EmbeddedChunkResult>> = VecDeque::new();

    for i in 0..n {
        let chunk = chunks[i].clone();
        let prepared = match next_prepare.take() {
            Some(handle) => handle
                .await
                .unwrap_or_else(|e| panic!("prepare panicked: {e}")),
            None => prepare_chunk(config, pool, chunk).await,
        };

        if i + 1 < n {
            let next_chunk = chunks[i + 1].clone();
            let pool = pool.clone();
            let cfg = config.clone();
            next_prepare = Some(tokio::spawn(async move {
                prepare_chunk(&cfg, &pool, next_chunk).await
            }));
        }

        // Spawn embed task so preparation can continue while embedding runs.
        let cfg_clone = config.clone();
        let pool_clone = pool.clone();
        let embedder_clone = embedder.clone();
        let embed_sem_clone = Arc::clone(&embed_sem);
        let embed_handle = tokio::spawn(async move {
            embed_chunk(
                &cfg_clone,
                &pool_clone,
                &embedder_clone,
                prepared,
                &embed_sem_clone,
            )
            .await
        });
        embed_handles.push_back(embed_handle);

        // If the oldest embed task finished, consume it and spawn its completion.
        if let Some(front) = embed_handles.front() {
            if front.is_finished() {
                let handle = embed_handles.pop_front().unwrap();
                let embedded = handle
                    .await
                    .unwrap_or_else(|e| panic!("embed panicked: {e}"));

                if let Some(handle) = complete_handle.take() {
                    let result = handle
                        .await
                        .unwrap_or_else(|e| panic!("complete panicked: {e}"));
                    succeeded += result.succeeded;
                    failed += result.failed;
                }

                permanent_failed += embedded.permanent_failed;

                let cfg = config.clone();
                let pool = pool.clone();
                complete_handle = Some(tokio::spawn(async move {
                    complete_chunk(&cfg, &pool, embedded).await
                }));
            }
        }
    }

    // Drain remaining embed tasks in order, spawning completes as each finishes.
    while let Some(handle) = embed_handles.pop_front() {
        let embedded = handle
            .await
            .unwrap_or_else(|e| panic!("embed panicked: {e}"));

        if let Some(handle) = complete_handle.take() {
            let result = handle
                .await
                .unwrap_or_else(|e| panic!("complete panicked: {e}"));
            succeeded += result.succeeded;
            failed += result.failed;
        }

        permanent_failed += embedded.permanent_failed;

        let cfg = config.clone();
        let pool = pool.clone();
        complete_handle = Some(tokio::spawn(async move {
            complete_chunk(&cfg, &pool, embedded).await
        }));
    }

    if let Some(handle) = complete_handle {
        let result = handle
            .await
            .unwrap_or_else(|e| panic!("complete panicked: {e}"));
        succeeded += result.succeeded;
        failed += result.failed;
    }

    debug!(
        total,
        succeeded, failed, permanent_failed, "process_jobs done"
    );
    (succeeded, permanent_failed)
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
    /// Jobs that failed with a permanent error (e.g. 400 Bad Request) and
    /// will not be retried.  Subset of `failed` when the error was permanent.
    permanent_failed: usize,
    prepare_ms: u64,
    embed_ms: u64,
}

struct CompleteChunkResult {
    succeeded: usize,
    failed: usize,
}

async fn prepare_chunk(
    config: &Config,
    pool: &PgPool,
    jobs: Vec<EmbeddingJob>,
) -> PrepareChunkResult {
    let start = Instant::now();
    let batch_size = jobs.len();

    let inputs = match text_builder::build_text_batch(pool, &jobs).await {
        Ok(map) => map,
        Err(e) => {
            warn!(error = %e, "build_text_batch failed, failing entire chunk");
            let mut failed = 0usize;
            for job in &jobs {
                if fail_job_with_error(config, pool, job, &e.to_string()).await {
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

    // Truncation guard: ≈ 1.5 chars per token for BPE tokenizer on structured WiFi data.
    // MAC addrs, hex, and underscore tokens (ASSOC_REQ) can inflate to 3+ chars per token,
    // so 3/2 gives headroom under the provider's context limit.
    let max_chars = config.max_input_tokens.saturating_mul(3) / 2;
    let mut truncated_count = 0usize;
    let mut prepared = Vec::with_capacity(jobs.len());
    let mut failed = 0usize;

    for job in jobs {
        match inputs.get(&job.source_key) {
            Some(input) => {
                let mut trimmed = input.clone();
                if trimmed.text.len() > max_chars {
                    // Truncate at the last newline before the character limit so we don't
                    // cut a line in the middle (preserving the structured field format).
                    let limit = max_chars;
                    let cut = trimmed.text[..limit].rfind('\n').unwrap_or(limit);
                    trimmed.text.truncate(cut);
                    trimmed.text.push_str("\n[truncated]");
                    truncated_count += 1;
                }
                let content_sha256 = sha256_hex(&trimmed.text);
                prepared.push(PreparedJob {
                    job,
                    input: trimmed,
                    content_sha256,
                });
            }
            None => {
                let msg = format!("source row not found: {}", job.source_key);
                warn!(job_id = job.job_id, "{msg}");
                if fail_job_with_error(config, pool, &job, &msg).await {
                    failed += 1;
                }
            }
        }
    }

    let prepare_ms = start.elapsed().as_millis() as u64;
    if truncated_count > 0 {
        debug!(
            truncated_count,
            max_input_tokens = config.max_input_tokens,
            "inputs truncated to fit max_input_tokens"
        );
    }
    debug!(
        batch_size,
        prepare_ms,
        prepared = prepared.len(),
        failed,
        "prepare_chunk done"
    );

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
            permanent_failed: 0,
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
            let permanent = is_permanent_embed_error(&e);
            if permanent {
                error!(
                    error = %e,
                    permanent = true,
                    "embed_many failed with permanent error — marking jobs failed immediately"
                );
            } else {
                error!(error = %e, permanent = false, "embed_many failed, failing chunk");
            }
            let mut perm_fails = 0usize;
            for p in &prepared_chunk.prepared {
                if permanent {
                    fail_job_permanent(config, pool, &p.job, &e.to_string()).await;
                    failed += 1;
                    perm_fails += 1;
                } else if fail_job_with_error(config, pool, &p.job, &e.to_string()).await {
                    failed += 1;
                }
            }
            return EmbeddedChunkResult {
                items: Vec::new(),
                failed,
                permanent_failed: perm_fails,
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
            if fail_job_with_error(config, pool, &prepared_job.job, &e.to_string()).await {
                failed += 1;
            }
            continue;
        }
        items.push((prepared_job, vector));
    }

    EmbeddedChunkResult {
        items,
        failed,
        permanent_failed: 0,
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
        heartbeat_after_chunk(config, pool, succeeded, failed).await;
        return CompleteChunkResult { succeeded, failed };
    }

    let dimensions = config.dimensions as i32;
    let batch_rows: Vec<CompleteBatchRow> = embedded
        .items
        .iter()
        .map(|(p, v)| db::complete_batch_row(&p.job, &p.input, &p.content_sha256, v, dimensions))
        .collect();

    match complete_embedding_batch_with_timeout(config, pool, &batch_rows).await {
        Ok(completed) => {
            let completed = completed as usize;
            if completed == batch_rows.len() {
                succeeded = completed;
            } else if completed > 0 {
                debug!(
                    expected = batch_rows.len(),
                    completed, "bulk complete partial, retrying unresolved jobs"
                );
                let fallback_plan =
                    unresolved_completion_items(config, pool, &embedded.items).await;
                let (s, f) = complete_jobs_fallback(config, pool, &fallback_plan.items).await;
                succeeded = if fallback_plan.includes_completed_rows {
                    s
                } else {
                    completed + s
                };
                failed += f;
            } else {
                warn!("bulk complete returned 0, falling back per job");
                let fallback_items: Vec<_> = embedded.items.iter().collect();
                let (s, f) = complete_jobs_fallback(config, pool, &fallback_items).await;
                succeeded = s;
                failed += f;
            }
        }
        Err(e) if is_db_pressure_error(&e) => {
            warn!(
                error = %e,
                jobs = embedded.items.len(),
                "bulk complete failed under database pressure; skipping per-job fallback"
            );
            failed += embedded.items.len();
        }
        Err(e) => {
            warn!(error = %e, "bulk complete failed, falling back per job");
            let fallback_items: Vec<_> = embedded.items.iter().collect();
            let (s, f) = complete_jobs_fallback(config, pool, &fallback_items).await;
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
    heartbeat_after_chunk(config, pool, succeeded, failed).await;

    CompleteChunkResult { succeeded, failed }
}

async fn heartbeat_after_chunk(config: &Config, pool: &PgPool, jobs_ok: usize, jobs_failed: usize) {
    if !should_mark_progress_heartbeat(jobs_ok, jobs_failed) {
        return;
    }

    let params = WorkerStateParams {
        worker_name: config.worker_name.clone(),
        status: "running".to_string(),
        last_cursor: None,
        last_run_started_at: None,
        last_run_finished_at: None,
        rows_processed: jobs_ok as i64,
        last_error: None,
    };

    if let Err(e) = mark_worker_state_with_timeout(config, pool, &params).await {
        warn!(
            error = %e,
            jobs_ok,
            jobs_failed,
            "worker progress heartbeat failed"
        );
    }
}

struct CompletionFallbackPlan<'a> {
    items: Vec<&'a (PreparedJob, Vec<f32>)>,
    includes_completed_rows: bool,
}

async fn unresolved_completion_items<'a>(
    config: &Config,
    pool: &PgPool,
    items: &'a [(PreparedJob, Vec<f32>)],
) -> CompletionFallbackPlan<'a> {
    let job_ids: Vec<i64> = items
        .iter()
        .map(|(prepared, _)| prepared.job.job_id)
        .collect();
    let completed_ids = match completed_job_ids_with_timeout(config, pool, &job_ids).await {
        Ok(ids) => ids,
        Err(e) => {
            warn!(
                error = %e,
                job_count = job_ids.len(),
                "failed to inspect partial bulk completion; retrying full chunk"
            );
            return CompletionFallbackPlan {
                items: items.iter().collect(),
                includes_completed_rows: true,
            };
        }
    };

    CompletionFallbackPlan {
        items: items
            .iter()
            .filter(|(prepared, _)| !completed_ids.contains(&prepared.job.job_id))
            .collect(),
        includes_completed_rows: false,
    }
}

async fn complete_jobs_fallback(
    config: &Config,
    pool: &PgPool,
    items: &[&(PreparedJob, Vec<f32>)],
) -> (usize, usize) {
    if items.is_empty() {
        return (0, 0);
    }

    // Cap fallback concurrency so at least 6 connections remain for
    // lease/state/prepare operations running in parallel.
    let pool_max = config.effective_pool_max_connections() as usize;
    let safe_concurrency = config
        .max_concurrent_completes
        .min(pool_max.saturating_sub(6))
        .max(1);
    let semaphore = Arc::new(Semaphore::new(safe_concurrency));
    let mut tasks: FuturesUnordered<_> = items
        .iter()
        .map(|(prepared, vector)| {
            let semaphore = Arc::clone(&semaphore);
            let pool = pool.clone();
            let config = config.clone();
            let dimensions = config.dimensions;
            async move {
                let _permit = semaphore
                    .acquire()
                    .await
                    .expect("complete semaphore closed");
                match complete_job_pipeline_with_timeout(
                    &config, &pool, dimensions, prepared, vector,
                )
                .await
                {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        warn!(
                            error = %e,
                            job_id = prepared.job.job_id,
                            "fallback completion failed"
                        );
                        if matches!(e, WorkerError::DbTimeout { .. }) {
                            return Err(());
                        }

                        if fail_job_with_error(&config, &pool, &prepared.job, &e.to_string()).await
                        {
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
        embed_ms, complete_ms, jobs_ok, jobs_failed, "batch timing"
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

async fn complete_embedding_batch_with_timeout(
    config: &Config,
    pool: &PgPool,
    rows: &[CompleteBatchRow],
) -> Result<i32, WorkerError> {
    with_db_timeout(
        Duration::from_secs(config.db_call_timeout_seconds),
        "complete_embedding_batch",
        db::complete_embedding_batch(pool, rows),
    )
    .await
}

async fn completed_job_ids_with_timeout(
    config: &Config,
    pool: &PgPool,
    job_ids: &[i64],
) -> Result<HashSet<i64>, WorkerError> {
    with_db_timeout(
        Duration::from_secs(config.db_call_timeout_seconds),
        "completed_job_ids",
        db::completed_job_ids(pool, job_ids),
    )
    .await
}

async fn complete_job_pipeline_with_timeout(
    config: &Config,
    pool: &PgPool,
    dimensions: usize,
    prepared: &PreparedJob,
    vector: &[f32],
) -> Result<(), WorkerError> {
    with_worker_timeout(
        Duration::from_secs(config.db_call_timeout_seconds),
        "complete_job_pipeline",
        complete_job_pipeline(pool, dimensions, prepared, vector),
    )
    .await
}

async fn mark_worker_state_with_timeout(
    config: &Config,
    pool: &PgPool,
    params: &WorkerStateParams,
) -> Result<(), WorkerError> {
    with_db_timeout(
        Duration::from_secs(config.db_call_timeout_seconds),
        "mark_worker_state",
        db::mark_worker_state(pool, params),
    )
    .await
}

async fn lease_jobs_with_timeout(
    config: &Config,
    pool: &PgPool,
) -> Result<Vec<EmbeddingJob>, WorkerError> {
    with_db_timeout(
        Duration::from_secs(config.db_call_timeout_seconds),
        "lease_jobs",
        db::lease_jobs(
            pool,
            config.batch_size as i32,
            &config.worker_name,
            config.lease_seconds as i64,
        ),
    )
    .await
}

async fn fail_job_with_error_with_timeout(
    config: &Config,
    pool: &PgPool,
    job: &EmbeddingJob,
    message: &str,
) -> Result<(), WorkerError> {
    with_db_timeout(
        Duration::from_secs(config.db_call_timeout_seconds),
        "fail_job",
        db::fail_job(
            pool,
            job.job_id,
            job.lease_token.as_deref(),
            job.attempts,
            job.max_attempts,
            message,
        ),
    )
    .await
}

async fn fail_job_permanent_with_timeout(
    config: &Config,
    pool: &PgPool,
    job: &EmbeddingJob,
    message: &str,
) -> Result<(), WorkerError> {
    with_db_timeout(
        Duration::from_secs(config.db_call_timeout_seconds),
        "fail_job_permanent",
        db::fail_job(
            pool,
            job.job_id,
            job.lease_token.as_deref(),
            job.max_attempts,
            job.max_attempts,
            message,
        ),
    )
    .await
}

async fn with_db_timeout<T, Fut>(
    timeout_duration: Duration,
    operation: &'static str,
    future: Fut,
) -> Result<T, WorkerError>
where
    Fut: Future<Output = Result<T, sqlx::Error>>,
{
    match tokio::time::timeout(timeout_duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(WorkerError::DbTimeout {
            operation,
            timeout_ms: timeout_duration.as_millis(),
        }),
    }
}

async fn with_worker_timeout<T, Fut>(
    timeout_duration: Duration,
    operation: &'static str,
    future: Fut,
) -> Result<T, WorkerError>
where
    Fut: Future<Output = Result<T, WorkerError>>,
{
    match tokio::time::timeout(timeout_duration, future).await {
        Ok(result) => result,
        Err(_) => Err(WorkerError::DbTimeout {
            operation,
            timeout_ms: timeout_duration.as_millis(),
        }),
    }
}

/// Returns true for HTTP errors that are permanent and should not be retried.
///
/// A 400 Bad Request from an embedding provider means the payload is invalid
/// (oversized, malformed JSON, unsupported model parameter).  Retrying with
/// the same payload will always produce the same result — waste of attempts
/// and pool connections.
///
/// 5xx errors and network failures are transient and should retry normally.
fn is_permanent_embed_error(e: &WorkerError) -> bool {
    match e {
        WorkerError::Http(re) => re
            .status()
            .map(|s| {
                // 429 Too Many Requests is retriable, all other 4xx are permanent.
                s.is_client_error() && s != reqwest::StatusCode::TOO_MANY_REQUESTS
            })
            .unwrap_or(false),
        WorkerError::DimensionMismatch { .. } => true, // model mismatch — permanent
        _ => false,
    }
}

fn is_db_pressure_error(e: &WorkerError) -> bool {
    matches!(
        e,
        WorkerError::DbTimeout { .. } | WorkerError::Database(sqlx::Error::PoolTimedOut)
    )
}

async fn fail_job_with_error(
    config: &Config,
    pool: &PgPool,
    job: &EmbeddingJob,
    message: &str,
) -> bool {
    match fail_job_with_error_with_timeout(config, pool, job, message).await {
        Ok(()) => true,
        Err(e) => {
            warn!(
                error = %e,
                job_id = job.job_id,
                "failed to mark embedding job failed"
            );
            false
        }
    }
}

/// Mark a job as permanently failed by setting attempts = max_attempts before
/// calling fail_job.  This bypasses the retry backoff for errors that are known
/// to be unrecoverable (e.g. 400 Bad Request with oversized payload).
async fn fail_job_permanent(config: &Config, pool: &PgPool, job: &EmbeddingJob, message: &str) {
    if let Err(e) = fail_job_permanent_with_timeout(config, pool, job, message).await {
        warn!(
            error = %e,
            job_id = job.job_id,
            "failed to mark embedding job permanently failed"
        );
    }
}

fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(
        rows_leased: usize,
        drained_to_empty: bool,
        max_drain_batches_reached: bool,
    ) -> RunOnceResult {
        RunOnceResult {
            processed: rows_leased,
            permanent_failures: 0,
            rows_leased,
            drain_batches: usize::from(rows_leased > 0),
            drained_to_empty,
            max_drain_batches_reached,
            drain_ms: 1,
        }
    }

    #[test]
    fn drain_continues_after_successful_full_batch_without_cap() {
        assert_eq!(drain_decision(64, 1, 0), DrainDecision::Continue);
        assert_eq!(
            loop_action_after_success(false, &result(64, false, false)),
            LoopAction::ContinueImmediately
        );
    }

    #[test]
    fn drain_sleeps_only_after_empty_lease() {
        assert_eq!(drain_decision(0, 3, 0), DrainDecision::Empty);
        assert_eq!(
            loop_action_after_success(false, &result(0, true, false)),
            LoopAction::SleepIdle
        );
        assert_eq!(
            loop_action_after_success(false, &result(64, false, true)),
            LoopAction::ContinueImmediately
        );
    }

    #[test]
    fn once_mode_exits_after_drain_cycle() {
        assert_eq!(
            loop_action_after_success(true, &result(128, true, false)),
            LoopAction::ExitOnce
        );
    }

    #[test]
    fn max_drain_batches_yields_without_idle_sleep() {
        assert_eq!(drain_decision(64, 2, 2), DrainDecision::MaxBatchesReached);
        assert_eq!(
            loop_action_after_success(false, &result(128, false, true)),
            LoopAction::ContinueImmediately
        );
    }

    #[test]
    fn progress_heartbeat_is_requested_after_each_nonempty_chunk() {
        assert!(should_mark_progress_heartbeat(1, 0));
        assert!(should_mark_progress_heartbeat(0, 1));
        assert!(!should_mark_progress_heartbeat(0, 0));
    }

    #[tokio::test]
    async fn db_timeout_returns_retryable_worker_error() {
        let err = with_db_timeout(Duration::from_millis(1), "lease_jobs", async {
            tokio::time::sleep(Duration::from_millis(25)).await;
            Ok::<_, sqlx::Error>(())
        })
        .await
        .expect_err("timeout should return an error");

        match err {
            WorkerError::DbTimeout {
                operation,
                timeout_ms,
            } => {
                assert_eq!(operation, "lease_jobs");
                assert_eq!(timeout_ms, 1);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn db_pressure_errors_skip_fallback() {
        assert!(is_db_pressure_error(&WorkerError::DbTimeout {
            operation: "complete_embedding_batch",
            timeout_ms: 30_000,
        }));
        assert!(is_db_pressure_error(&WorkerError::Database(
            sqlx::Error::PoolTimedOut,
        )));
    }
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
