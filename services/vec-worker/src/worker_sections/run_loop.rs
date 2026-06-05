use crate::alerts::{self, AlertConfig};
use crate::db::{self, CompleteBatchRow, EmbeddingJob, WorkerStateParams};
use crate::embedder::EmbeddingClient;
use crate::text_builder;
use crate::{Config, WorkerError};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
#[cfg(feature = "parallel-prepare")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::{watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, debug_span, error, info, info_span, warn};

static FALLBACK_COMPLETIONS: AtomicU64 = AtomicU64::new(0);

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

    let alert_cfg = AlertConfig::from_env();
    let mut iteration: u64 = 0;
    let mut consecutive_permanent_failures: u32 = 0;
    let mut alert_sweep_handle: Option<JoinHandle<()>> = None;
    const PERMANENT_FAILURE_CIRCUIT_BREAKER: u32 = 5;

    loop {
        observe_finished_alert_sweep(&mut alert_sweep_handle).await;

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
                    kind_stats = ?result.kind_stats,
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

        // Periodic maintenance: release expired leases and run alert sweeps on
        // the configured iteration cadence.
        if iteration % alert_cfg.sweep_interval == 0 {
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
            if alert_sweep_handle.is_some() {
                debug!("skipping alert sweep - previous sweep still running");
            } else if idle >= ALERT_MIN_FREE_CONNECTIONS {
                let alert_pool = alert_pool.clone();
                match db::try_begin_alert_sweep(&alert_pool).await {
                    Ok(true) => {
                        let alert_cfg = alert_cfg.clone();
                        alert_sweep_handle = Some(tokio::spawn(async move {
                            if let Err(e) = alerts::run_alert_sweep(&alert_pool, &alert_cfg).await {
                                warn!(error = %e, "alert sweep failed (background)");
                            }
                            // count_high_risk_aps also uses the alert pool so the main loop
                            // is never blocked by a COUNT(*) on mv_ap_risk_score.
                            match db::count_high_risk_aps(&alert_pool, alert_cfg.ap_risk_threshold)
                                .await
                            {
                                Ok(count) => {
                                    info!(high_risk_ap_count = count, "high-risk AP summary")
                                }
                                Err(e) => warn!(error = %e, "failed to query high-risk AP count"),
                            }
                            // Release the DB advisory lock.
                            if let Err(e) = db::finish_alert_sweep(&alert_pool).await {
                                warn!(error = %e, "failed to release alert sweep lock");
                            }
                        }));
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

    if let Some(handle) = alert_sweep_handle {
        if let Err(e) = handle.await {
            warn!(error = %e, "alert sweep task failed during shutdown");
        }
    }

    info!("worker finished");
    Ok(())
}

async fn observe_finished_alert_sweep(handle: &mut Option<JoinHandle<()>>) {
    if let Some(task) = handle.take() {
        if task.is_finished() {
            if let Err(e) = task.await {
                warn!(error = %e, "alert sweep task panicked");
            }
        } else {
            *handle = Some(task);
        }
    }
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
    /// Per-kind lease, completion, and failure counts for this drain cycle.
    pub kind_stats: BTreeMap<String, KindRunStats>,
}

/// Per-kind worker counters for one drain cycle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KindRunStats {
    pub leased: usize,
    pub completed: usize,
    pub failed: usize,
    pub permanent_failed: usize,
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
        kind_stats: BTreeMap::new(),
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
        add_leased_jobs(&mut result.kind_stats, &jobs);
        if rows_leased == config.batch_size {
            debug!(
                rows_leased,
                drain_batches = result.drain_batches,
                max_drain_batches = config.max_drain_batches,
                "leased full vector batch; continuing drain cycle"
            );
        }

        let processed = process_jobs(config, pool, embedder, jobs).await;
        result.processed += processed.succeeded;
        result.permanent_failures += processed.permanent_failures;
        add_process_stats(&mut result.kind_stats, &processed);

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
#[derive(Debug, Default)]
pub struct ProcessJobsResult {
    pub succeeded: usize,
    pub failed: usize,
    pub permanent_failures: usize,
    pub completed_by_kind: BTreeMap<String, usize>,
    pub failed_by_kind: BTreeMap<String, usize>,
    pub permanent_failed_by_kind: BTreeMap<String, usize>,
}
