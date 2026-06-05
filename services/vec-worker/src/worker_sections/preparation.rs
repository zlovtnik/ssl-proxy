pub async fn process_jobs(
    config: &Config,
    pool: &PgPool,
    embedder: &EmbeddingClient,
    jobs: Vec<EmbeddingJob>,
) -> ProcessJobsResult {
    let total = jobs.len();
    let jobs = Arc::new(jobs);
    let request_batch_size = config.request_batch_size.max(1);
    let n = total.div_ceil(request_batch_size);

    if n == 0 {
        return ProcessJobsResult::default();
    }

    let embed_sem = Arc::new(Semaphore::new(config.max_concurrent_embed_requests.max(1)));
    let mut result = ProcessJobsResult::default();
    let mut next_prepare: Option<JoinHandle<PrepareChunkResult>> = None;
    let mut complete_handle: Option<JoinHandle<CompleteChunkResult>> = None;
    let mut embed_tasks = JoinSet::new();
    let mut completed_embeds: BTreeMap<usize, EmbeddedChunkResult> = BTreeMap::new();
    let mut next_complete_index = 0usize;

    for i in 0..n {
        let chunk = JobChunk::new(Arc::clone(&jobs), i, request_batch_size);
        let prepared = match next_prepare.take() {
            Some(handle) => handle
                .await
                .unwrap_or_else(|e| panic!("prepare panicked: {e}")),
            None => prepare_chunk(config, pool, chunk).await,
        };

        if i + 1 < n {
            let next_chunk = JobChunk::new(Arc::clone(&jobs), i + 1, request_batch_size);
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
        embed_tasks.spawn(async move {
            embed_chunk(
                &cfg_clone,
                &pool_clone,
                &embedder_clone,
                prepared,
                &embed_sem_clone,
            )
            .await
        });

        while let Some(joined) = embed_tasks.join_next().now_or_never().flatten() {
            let embedded = joined.unwrap_or_else(|e| panic!("embed panicked: {e}"));
            completed_embeds.insert(embedded.chunk_index, embedded);
            flush_completed_embeds_in_order(
                config,
                pool,
                &mut result,
                &mut complete_handle,
                &mut completed_embeds,
                &mut next_complete_index,
            )
            .await;
        }
    }

    while let Some(joined) = embed_tasks.join_next().await {
        let embedded = joined.unwrap_or_else(|e| panic!("embed panicked: {e}"));
        completed_embeds.insert(embedded.chunk_index, embedded);
        flush_completed_embeds_in_order(
            config,
            pool,
            &mut result,
            &mut complete_handle,
            &mut completed_embeds,
            &mut next_complete_index,
        )
        .await;
    }

    if let Some(handle) = complete_handle {
        let complete_result = handle
            .await
            .unwrap_or_else(|e| panic!("complete panicked: {e}"));
        add_complete_result(&mut result, complete_result);
    }

    debug!(
        total,
        succeeded = result.succeeded,
        failed = result.failed,
        permanent_failed = result.permanent_failures,
        completed_by_kind = ?result.completed_by_kind,
        failed_by_kind = ?result.failed_by_kind,
        permanent_failed_by_kind = ?result.permanent_failed_by_kind,
        "process_jobs done"
    );
    result
}

fn add_complete_result(process: &mut ProcessJobsResult, complete: CompleteChunkResult) {
    process.succeeded += complete.succeeded;
    process.failed += complete.failed;
    add_counts(&mut process.completed_by_kind, &complete.succeeded_by_kind);
    add_counts(&mut process.failed_by_kind, &complete.failed_by_kind);
}

fn add_leased_jobs(stats: &mut BTreeMap<String, KindRunStats>, jobs: &[EmbeddingJob]) {
    for job in jobs {
        stats.entry(job.embedding_kind.clone()).or_default().leased += 1;
    }
}

fn add_process_stats(stats: &mut BTreeMap<String, KindRunStats>, process: &ProcessJobsResult) {
    for (kind, count) in &process.completed_by_kind {
        stats.entry(kind.clone()).or_default().completed += count;
    }
    for (kind, count) in &process.failed_by_kind {
        stats.entry(kind.clone()).or_default().failed += count;
    }
    for (kind, count) in &process.permanent_failed_by_kind {
        stats.entry(kind.clone()).or_default().permanent_failed += count;
    }
}

fn increment_count(counts: &mut BTreeMap<String, usize>, kind: &str) {
    *counts.entry(kind.to_string()).or_default() += 1;
}

fn add_counts(target: &mut BTreeMap<String, usize>, source: &BTreeMap<String, usize>) {
    for (kind, count) in source {
        *target.entry(kind.clone()).or_default() += count;
    }
}

async fn flush_completed_embeds_in_order(
    config: &Config,
    pool: &PgPool,
    result: &mut ProcessJobsResult,
    complete_handle: &mut Option<JoinHandle<CompleteChunkResult>>,
    completed_embeds: &mut BTreeMap<usize, EmbeddedChunkResult>,
    next_complete_index: &mut usize,
) {
    while let Some(embedded) = completed_embeds.remove(&*next_complete_index) {
        if let Some(handle) = complete_handle.take() {
            let complete_result = handle
                .await
                .unwrap_or_else(|e| panic!("complete panicked: {e}"));
            add_complete_result(result, complete_result);
        }

        result.permanent_failures += embedded.permanent_failed;
        add_counts(
            &mut result.permanent_failed_by_kind,
            &embedded.permanent_failed_by_kind,
        );

        let cfg = config.clone();
        let pool = pool.clone();
        *complete_handle = Some(tokio::spawn(async move {
            complete_chunk(&cfg, &pool, embedded).await
        }));
        *next_complete_index += 1;
    }
}

fn count_items_by_kind(items: &[&(PreparedJob, Vec<f32>)]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (prepared, _) in items {
        increment_count(&mut counts, &prepared.job().embedding_kind);
    }
    counts
}

fn count_completed_items_by_kind(
    items: &[(PreparedJob, Vec<f32>)],
    completed_ids: &HashSet<i64>,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (prepared, _) in items {
        let job = prepared.job();
        if completed_ids.contains(&job.job_id) {
            increment_count(&mut counts, &job.embedding_kind);
        }
    }
    counts
}

// ---------------------------------------------------------------------------
// Chunk pipeline stages
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct JobChunk {
    all_jobs: Arc<Vec<EmbeddingJob>>,
    start: usize,
    end: usize,
    chunk_index: usize,
}

impl JobChunk {
    fn new(
        all_jobs: Arc<Vec<EmbeddingJob>>,
        chunk_index: usize,
        request_batch_size: usize,
    ) -> Self {
        let start = chunk_index * request_batch_size;
        let end = (start + request_batch_size).min(all_jobs.len());
        Self {
            all_jobs,
            start,
            end,
            chunk_index,
        }
    }

    fn jobs(&self) -> &[EmbeddingJob] {
        &self.all_jobs[self.start..self.end]
    }

    fn len(&self) -> usize {
        self.end - self.start
    }

    fn indices(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }
}

struct PreparedJob {
    all_jobs: Arc<Vec<EmbeddingJob>>,
    job_index: usize,
    input: crate::db::EmbeddingInput,
    content_sha256: String,
}

impl PreparedJob {
    fn job(&self) -> &EmbeddingJob {
        &self.all_jobs[self.job_index]
    }
}

struct PrepareChunkResult {
    chunk_index: usize,
    prepared: Vec<PreparedJob>,
    failed: usize,
    failed_by_kind: BTreeMap<String, usize>,
    prepare_ms: u64,
}

struct EmbeddedChunkResult {
    chunk_index: usize,
    items: Vec<(PreparedJob, Vec<f32>)>,
    failed: usize,
    /// Jobs that failed with a permanent error (e.g. 400 Bad Request) and
    /// will not be retried.  Subset of `failed` when the error was permanent.
    permanent_failed: usize,
    failed_by_kind: BTreeMap<String, usize>,
    permanent_failed_by_kind: BTreeMap<String, usize>,
    prepare_ms: u64,
    embed_ms: u64,
}

struct CompleteChunkResult {
    succeeded: usize,
    failed: usize,
    succeeded_by_kind: BTreeMap<String, usize>,
    failed_by_kind: BTreeMap<String, usize>,
}

async fn prepare_chunk(config: &Config, pool: &PgPool, chunk: JobChunk) -> PrepareChunkResult {
    let start = Instant::now();
    let batch_size = chunk.len();
    let jobs = chunk.jobs();

    let inputs = match text_builder::build_text_batch(pool, jobs).await {
        Ok(map) => map,
        Err(e) => {
            warn!(error = %e, "build_text_batch failed, failing entire chunk");
            let mut failed = 0usize;
            let mut failed_by_kind = BTreeMap::new();
            for job in jobs {
                if fail_job_with_error(config, pool, job, &e.to_string()).await {
                    failed += 1;
                    increment_count(&mut failed_by_kind, &job.embedding_kind);
                }
            }
            return PrepareChunkResult {
                chunk_index: chunk.chunk_index,
                prepared: Vec::new(),
                failed,
                failed_by_kind,
                prepare_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    // Truncation guard: ≈ 1.5 chars per token for BPE tokenizer on structured WiFi data.
    // MAC addrs, hex, and underscore tokens (ASSOC_REQ) can inflate to 3+ chars per token,
    // so 3/2 gives headroom under the provider's context limit.
    let max_chars = config.max_input_tokens.saturating_mul(3) / 2;
    let mut truncated_count = 0usize;
    let mut trimmed_jobs = Vec::with_capacity(jobs.len());
    let mut failed = 0usize;
    let mut failed_by_kind = BTreeMap::new();

    for job_index in chunk.indices() {
        let job = &chunk.all_jobs[job_index];
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
                trimmed_jobs.push((job_index, trimmed));
            }
            None => {
                let msg = format!("source row not found: {}", job.source_key);
                warn!(job_id = job.job_id, "{msg}");
                if fail_job_with_error(config, pool, &job, &msg).await {
                    failed += 1;
                    increment_count(&mut failed_by_kind, &job.embedding_kind);
                }
            }
        }
    }

    let content_hashes = content_hashes_for_trimmed_jobs(&chunk.all_jobs, &trimmed_jobs);
    let mut prepared = Vec::with_capacity(trimmed_jobs.len());
    for ((job_index, input), content_sha256) in trimmed_jobs.into_iter().zip(content_hashes) {
        prepared.push(PreparedJob {
            all_jobs: Arc::clone(&chunk.all_jobs),
            job_index,
            input,
            content_sha256,
        });
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
        chunk_index: chunk.chunk_index,
        prepared,
        failed,
        failed_by_kind,
        prepare_ms,
    }
}

#[cfg(feature = "parallel-prepare")]
fn content_hashes_for_trimmed_jobs(
    all_jobs: &[EmbeddingJob],
    trimmed_jobs: &[(usize, crate::db::EmbeddingInput)],
) -> Vec<String> {
    trimmed_jobs
        .par_iter()
        .map(|(job_index, input)| content_hash_for_job(&all_jobs[*job_index], &input.text))
        .collect()
}

#[cfg(not(feature = "parallel-prepare"))]
fn content_hashes_for_trimmed_jobs(
    all_jobs: &[EmbeddingJob],
    trimmed_jobs: &[(usize, crate::db::EmbeddingInput)],
) -> Vec<String> {
    trimmed_jobs
        .iter()
        .map(|(job_index, input)| content_hash_for_job(&all_jobs[*job_index], &input.text))
        .collect()
}

fn content_hash_for_job(job: &EmbeddingJob, text: &str) -> String {
    job.content_sha256
        .as_ref()
        .filter(|hash| !hash.is_empty())
        .cloned()
        .unwrap_or_else(|| sha256_hex(text))
}
