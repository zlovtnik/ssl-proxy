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
    let mut failed_by_kind = prepared_chunk.failed_by_kind;
    let mut permanent_failed = 0usize;
    let mut permanent_failed_by_kind = BTreeMap::new();

    if prepared_chunk.prepared.is_empty() {
        return EmbeddedChunkResult {
            chunk_index: prepared_chunk.chunk_index,
            items: Vec::new(),
            failed,
            permanent_failed: 0,
            failed_by_kind,
            permanent_failed_by_kind,
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
            let permanent_category = permanent_embed_error_category(&e);
            if let Some(category) = permanent_category {
                error!(
                    error = %e,
                    permanent = true,
                    permanent_failure_category = category,
                    "embed_many failed with permanent error — marking jobs failed immediately"
                );
            } else {
                error!(error = %e, permanent = false, "embed_many failed, failing chunk");
            }
            for p in &prepared_chunk.prepared {
                let job = p.job();
                if let Some(category) = permanent_category {
                    fail_job_permanent(config, pool, job, category, &e.to_string()).await;
                    failed += 1;
                    permanent_failed += 1;
                    increment_count(&mut failed_by_kind, &job.embedding_kind);
                    increment_count(&mut permanent_failed_by_kind, &job.embedding_kind);
                } else if fail_job_with_error(config, pool, job, &e.to_string()).await {
                    failed += 1;
                    increment_count(&mut failed_by_kind, &job.embedding_kind);
                }
            }
            return EmbeddedChunkResult {
                chunk_index: prepared_chunk.chunk_index,
                items: Vec::new(),
                failed,
                permanent_failed,
                failed_by_kind,
                permanent_failed_by_kind,
                prepare_ms,
                embed_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let embed_ms = start.elapsed().as_millis() as u64;
    let mut items = Vec::with_capacity(prepared_chunk.prepared.len());

    for (prepared_job, vector) in prepared_chunk.prepared.into_iter().zip(embeddings) {
        let job = prepared_job.job();
        if let Err(e) = embedder.validate_dimensions(&vector, config.dimensions) {
            warn!(
                job_id = job.job_id,
                error = %e,
                "dimension mismatch, failing job",
            );
            if fail_job_permanent(config, pool, job, "dim_mismatch", &e.to_string()).await {
                failed += 1;
                permanent_failed += 1;
                increment_count(&mut failed_by_kind, &job.embedding_kind);
                increment_count(&mut permanent_failed_by_kind, &job.embedding_kind);
            }
            continue;
        }
        items.push((prepared_job, vector));
    }

    EmbeddedChunkResult {
        chunk_index: prepared_chunk.chunk_index,
        items,
        failed,
        permanent_failed,
        failed_by_kind,
        permanent_failed_by_kind,
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
    let mut succeeded_by_kind = BTreeMap::new();
    let mut failed_by_kind = embedded.failed_by_kind;

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
        return CompleteChunkResult {
            succeeded,
            failed,
            succeeded_by_kind,
            failed_by_kind,
        };
    }

    let dimensions = config.dimensions as i32;
    let batch_rows: Vec<CompleteBatchRow> = embedded
        .items
        .iter()
        .map(|(p, v)| db::complete_batch_row(p.job(), &p.input, &p.content_sha256, v, dimensions))
        .collect();

    match complete_embedding_batch_with_timeout(config, pool, &batch_rows).await {
        Ok(completed) => {
            let completed = completed as usize;
            if completed == batch_rows.len() {
                succeeded = completed;
                let item_refs: Vec<_> = embedded.items.iter().collect();
                succeeded_by_kind = count_items_by_kind(&item_refs);
            } else if completed > 0 {
                debug!(
                    expected = batch_rows.len(),
                    completed, "bulk complete partial, retrying unresolved jobs"
                );
                let fallback_plan =
                    unresolved_completion_items(config, pool, &embedded.items).await;
                let fallback_result =
                    complete_jobs_fallback(config, pool, &fallback_plan.items).await;
                succeeded = if fallback_plan.includes_completed_rows {
                    fallback_result.succeeded
                } else {
                    let completed_by_kind = count_completed_items_by_kind(
                        &embedded.items,
                        &fallback_plan.completed_ids,
                    );
                    add_counts(&mut succeeded_by_kind, &completed_by_kind);
                    completed + fallback_result.succeeded
                };
                add_counts(&mut succeeded_by_kind, &fallback_result.succeeded_by_kind);
                failed += fallback_result.failed;
                add_counts(&mut failed_by_kind, &fallback_result.failed_by_kind);
            } else {
                warn!("bulk complete returned 0, falling back per job");
                let fallback_items: Vec<_> = embedded.items.iter().collect();
                let fallback_result = complete_jobs_fallback(config, pool, &fallback_items).await;
                succeeded = fallback_result.succeeded;
                succeeded_by_kind = fallback_result.succeeded_by_kind;
                failed += fallback_result.failed;
                add_counts(&mut failed_by_kind, &fallback_result.failed_by_kind);
            }
        }
        Err(e) if is_db_pressure_error(&e) => {
            warn!(
                error = %e,
                jobs = embedded.items.len(),
                "bulk complete failed under database pressure; skipping per-job fallback"
            );
            failed += embedded.items.len();
            let failed_items: Vec<_> = embedded.items.iter().collect();
            let bulk_failed_by_kind = count_items_by_kind(&failed_items);
            add_counts(&mut failed_by_kind, &bulk_failed_by_kind);
        }
        Err(e) => {
            warn!(error = %e, "bulk complete failed, falling back per job");
            let fallback_items: Vec<_> = embedded.items.iter().collect();
            let fallback_result = complete_jobs_fallback(config, pool, &fallback_items).await;
            succeeded = fallback_result.succeeded;
            succeeded_by_kind = fallback_result.succeeded_by_kind;
            failed += fallback_result.failed;
            add_counts(&mut failed_by_kind, &fallback_result.failed_by_kind);
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

    CompleteChunkResult {
        succeeded,
        failed,
        succeeded_by_kind,
        failed_by_kind,
    }
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
    completed_ids: HashSet<i64>,
    includes_completed_rows: bool,
}

async fn unresolved_completion_items<'a>(
    config: &Config,
    pool: &PgPool,
    items: &'a [(PreparedJob, Vec<f32>)],
) -> CompletionFallbackPlan<'a> {
    let job_ids: Vec<i64> = items
        .iter()
        .map(|(prepared, _)| prepared.job().job_id)
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
                completed_ids: HashSet::new(),
                includes_completed_rows: true,
            };
        }
    };

    CompletionFallbackPlan {
        items: items
            .iter()
            .filter(|(prepared, _)| !completed_ids.contains(&prepared.job().job_id))
            .collect(),
        completed_ids,
        includes_completed_rows: false,
    }
}

async fn complete_jobs_fallback(
    config: &Config,
    pool: &PgPool,
    items: &[&(PreparedJob, Vec<f32>)],
) -> CompleteChunkResult {
    if items.is_empty() {
        return CompleteChunkResult {
            succeeded: 0,
            failed: 0,
            succeeded_by_kind: BTreeMap::new(),
            failed_by_kind: BTreeMap::new(),
        };
    }

    let fallback_completions_total = FALLBACK_COMPLETIONS.fetch_add(1, Ordering::Relaxed) + 1;
    warn!(
        fallback_completions_total,
        fallback_jobs = items.len(),
        "complete_jobs_fallback invoked"
    );

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
            let dimensions = config.dimensions as i32;
            let kind = prepared.job().embedding_kind.clone();
            async move {
                let _permit = semaphore
                    .acquire()
                    .await
                    .expect("complete semaphore closed");
                let row = db::complete_batch_row(
                    prepared.job(),
                    &prepared.input,
                    &prepared.content_sha256,
                    vector,
                    dimensions,
                );
                match complete_one_embedding_with_timeout(&config, &pool, &row).await {
                    Ok(true) => Ok(kind),
                    Ok(false) => {
                        warn!(
                            job_id = prepared.job().job_id,
                            "fallback completion skipped; lease token no longer matches"
                        );
                        Err(kind)
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            job_id = prepared.job().job_id,
                            "fallback completion failed"
                        );
                        if matches!(e, WorkerError::DbTimeout { .. }) {
                            return Err(kind);
                        }

                        fail_job_with_error(&config, &pool, prepared.job(), &e.to_string()).await;
                        Err(kind)
                    }
                }
            }
        })
        .collect();

    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut succeeded_by_kind = BTreeMap::new();
    let mut failed_by_kind = BTreeMap::new();
    while let Some(result) = tasks.next().await {
        match result {
            Ok(kind) => {
                succeeded += 1;
                increment_count(&mut succeeded_by_kind, &kind);
            }
            Err(kind) => {
                failed += 1;
                increment_count(&mut failed_by_kind, &kind);
            }
        }
    }
    CompleteChunkResult {
        succeeded,
        failed,
        succeeded_by_kind,
        failed_by_kind,
    }
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

async fn complete_one_embedding_with_timeout(
    config: &Config,
    pool: &PgPool,
    row: &CompleteBatchRow,
) -> Result<bool, WorkerError> {
    with_db_timeout(
        Duration::from_secs(config.db_call_timeout_seconds),
        "complete_one_embedding",
        db::complete_one_embedding(pool, row),
    )
    .await
}
