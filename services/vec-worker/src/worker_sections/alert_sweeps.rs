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

/// Returns true for HTTP errors that are permanent and should not be retried.
///
/// A 400 Bad Request from an embedding provider means the payload is invalid
/// (oversized, malformed JSON, unsupported model parameter).  Retrying with
/// the same payload will always produce the same result — waste of attempts
/// and pool connections.
///
/// 5xx errors and network failures are transient and should retry normally.
fn permanent_embed_error_category(e: &WorkerError) -> Option<&'static str> {
    match e {
        WorkerError::Http(re) => re.status().and_then(|s| {
            // 429 Too Many Requests is retriable, all other 4xx are permanent.
            if s.is_client_error() && s != reqwest::StatusCode::TOO_MANY_REQUESTS {
                Some("http_4xx")
            } else {
                None
            }
        }),
        WorkerError::DimensionMismatch { .. } => Some("dim_mismatch"),
        _ => None,
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
async fn fail_job_permanent(
    config: &Config,
    pool: &PgPool,
    job: &EmbeddingJob,
    category: &'static str,
    message: &str,
) -> bool {
    let mut categorized_message =
        String::with_capacity("[PERM:] ".len() + category.len() + message.len());
    let _ = write!(&mut categorized_message, "[PERM:{category}] {message}");

    match fail_job_permanent_with_timeout(config, pool, job, &categorized_message).await {
        Ok(()) => true,
        Err(e) => {
            warn!(
                error = %e,
                job_id = job.job_id,
                "failed to mark embedding job permanently failed"
            );
            false
        }
    }
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
