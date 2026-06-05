fn behaviour_row_to_input(row: &BehaviourWindowRow) -> EmbeddingInput {
    let text = if let Some(ref et) = row.embedding_text {
        if !et.is_empty() {
            // Prepend temporal context when using pre-built text (may be stale without it).
            let mut lines: Vec<String> = Vec::new();
            lines.push("kind: behaviour_window".to_string());
            if let Some(dt) = row.window_start {
                lines.extend(temporal_context_lines(dt));
            }
            for line in et.lines() {
                if line.starts_with("kind:") {
                    continue;
                }
                lines.push(line.to_string());
            }
            // Add burst_velocity
            if let Some(epm) = events_per_minute(row) {
                lines.push(format!("events_per_minute: {epm:.1}"));
            }
            clamp_text(&lines.join("\n"))
        } else if let Some(ref ts) = row.text_summary {
            if !ts.is_empty() {
                // Prepend temporal context to text_summary as well.
                let mut lines: Vec<String> = Vec::new();
                lines.push("kind: behaviour_window".to_string());
                if let Some(dt) = row.window_start {
                    lines.extend(temporal_context_lines(dt));
                }
                for line in ts.lines() {
                    if line.starts_with("kind:") {
                        continue;
                    }
                    lines.push(line.to_string());
                }
                if let Some(epm) = events_per_minute(row) {
                    lines.push(format!("events_per_minute: {epm:.1}"));
                }
                clamp_text(&lines.join("\n"))
            } else {
                build_snapshot_fallback(row)
            }
        } else {
            build_snapshot_fallback(row)
        }
    } else if let Some(ref ts) = row.text_summary {
        if !ts.is_empty() {
            let mut lines: Vec<String> = Vec::new();
            lines.push("kind: behaviour_window".to_string());
            if let Some(dt) = row.window_start {
                lines.extend(temporal_context_lines(dt));
            }
            for line in ts.lines() {
                if line.starts_with("kind:") {
                    continue;
                }
                lines.push(line.to_string());
            }
            if let Some(epm) = events_per_minute(row) {
                lines.push(format!("events_per_minute: {epm:.1}"));
            }
            clamp_text(&lines.join("\n"))
        } else {
            build_snapshot_fallback(row)
        }
    } else {
        build_snapshot_fallback(row)
    };

    EmbeddingInput {
        text,
        source_observed_at: row.window_start,
        source_stream_name: None,
        source_sensor_id: row.sensor_id.clone(),
        source_location_id: row.location_id.clone(),
        source_mac: row.source_mac.clone(),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct BaselineProfileRow {
    bssid: String,
    metric: String,
    p5: Option<f64>,
    p50: Option<f64>,
    p95: Option<f64>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct BaselineProfileBatchRow {
    query_key: String,
    bssid: String,
    metric: String,
    p5: Option<f64>,
    p50: Option<f64>,
    p95: Option<f64>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn build_baseline_profile(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let rows = sqlx::query_as::<_, BaselineProfileRow>(
        r#"
        SELECT
            bssid,
            metric,
            p5::float8,
            p50::float8,
            p95::float8,
            updated_at
        FROM vec_baseline_profiles
        WHERE bssid = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("baseline_profile query failed: {e}")))?;

    if rows.is_empty() {
        return Err(WorkerError::text_build(format!(
            "baseline_profile not found: {}",
            job.source_key
        )));
    }

    Ok(baseline_profile_rows_to_input(&rows))
}

async fn build_baseline_profiles_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, BaselineProfileBatchRow>(
        r#"
        SELECT
            bssid AS query_key,
            bssid,
            metric,
            p5::float8,
            p50::float8,
            p95::float8,
            updated_at
        FROM vec_baseline_profiles
        WHERE bssid = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("baseline_profile batch query failed: {e}")))?;

    let mut grouped: HashMap<String, Vec<BaselineProfileBatchRow>> = HashMap::new();
    for row in rows {
        grouped.entry(row.query_key.clone()).or_default().push(row);
    }

    for job in jobs {
        if let Some(rows) = grouped.get(&job.source_key) {
            let baseline_rows: Vec<BaselineProfileRow> = rows
                .iter()
                .map(|row| BaselineProfileRow {
                    bssid: row.bssid.clone(),
                    metric: row.metric.clone(),
                    p5: row.p5,
                    p50: row.p50,
                    p95: row.p95,
                    updated_at: row.updated_at,
                })
                .collect();
            let row_refs: Vec<&BaselineProfileRow> = baseline_rows.iter().collect();
            out.insert(
                job.source_key.clone(),
                baseline_profile_rows_to_input_ref(&row_refs),
            );
        }
    }

    Ok(())
}

fn baseline_profile_rows_to_input(rows: &[BaselineProfileRow]) -> EmbeddingInput {
    let row_refs: Vec<&BaselineProfileRow> = rows.iter().collect();
    baseline_profile_rows_to_input_ref(&row_refs)
}

fn baseline_profile_rows_to_input_ref(rows: &[&BaselineProfileRow]) -> EmbeddingInput {
    let mut metrics = rows.to_vec();
    metrics.sort_by(|left, right| left.metric.cmp(&right.metric));

    // Each metric line is ~8 tokens (metric name + 3 percentile values).
    // Budget: (CONTENT_TOKEN_BUDGET - 4 fixed lines) / 8 tokens per line.
    const MAX_METRIC_LINES: usize = (CONTENT_TOKEN_BUDGET - 4) / 8; // ~61 metrics

    let mut lines = vec!["kind: baseline_profile".to_string()];
    if let Some(first) = metrics.first() {
        lines.push(format!("bssid: {}", first.bssid));
    }
    for (i, row) in metrics.iter().enumerate() {
        if i >= MAX_METRIC_LINES {
            lines.push(format!(
                "(+{} metrics truncated)",
                metrics.len() - MAX_METRIC_LINES
            ));
            tracing::warn!(
                original_metric_count = metrics.len(),
                max_metric_lines = MAX_METRIC_LINES,
                "baseline_profile metrics truncated to fit model context window"
            );
            break;
        }
        let mut metric_text = format!("metric: {}", row.metric);
        if let Some(value) = row.p5 {
            metric_text.push_str(&format!(" p5: {}", value));
        }
        if let Some(value) = row.p50 {
            metric_text.push_str(&format!(" p50: {}", value));
        }
        if let Some(value) = row.p95 {
            metric_text.push_str(&format!(" p95: {}", value));
        }
        lines.push(metric_text);
    }

    let source_observed_at = rows.iter().filter_map(|row| row.updated_at).max();

    EmbeddingInput {
        text: clamp_text(&lines.join("\n")),
        source_observed_at,
        source_stream_name: None,
        source_sensor_id: None,
        source_location_id: None,
        source_mac: Some(rows[0].bssid.clone()),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct FrameSequenceRow {
    session_key: String,
    source_mac: Option<String>,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    window_end: Option<chrono::DateTime<chrono::Utc>>,
    sequence_tokens: String,
    semantic_tokens: Option<String>,
    frame_count: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct FrameSequenceBatchRow {
    query_key: String,
    session_key: String,
    source_mac: Option<String>,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    window_end: Option<chrono::DateTime<chrono::Utc>>,
    sequence_tokens: String,
    semantic_tokens: Option<String>,
    frame_count: i64,
}

fn insert_log_prob_line(text: &mut String, score: f64) {
    if let Some(pos) = text.rfind("frame_count:") {
        let (before, after) = text.split_at(pos);
        *text = format!("{}log_prob: {:.6}\n{}", before, score, after);
    }
}

async fn build_frame_sequence(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let row = sqlx::query_as::<_, FrameSequenceRow>(
        r#"
        SELECT
            session_key,
            source_mac,
            sensor_id,
            location_id,
            window_start,
            window_end,
            sequence_tokens,
            semantic_tokens,
            frame_count
        FROM vec_frame_sequences
        WHERE session_key = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("frame_sequence query failed: {e}")))?
    .ok_or_else(|| {
        WorkerError::text_build(format!("frame_sequence not found: {}", job.source_key))
    })?;

    let mut input = frame_sequence_row_to_input(&row);

    match sequence_score::load_frame_sequence_scorer(pool).await {
        Ok(scorer) => {
            let score = scorer.score_text(&row.sequence_tokens);
            insert_log_prob_line(&mut input.text, score);
        }
        Err(e) => {
            // Non-fatal: log_prob is informational, don't fail the job.
            tracing::warn!(error = %e, session_key = %row.session_key, "failed to load sequence scorer");
        }
    }

    Ok(input)
}

async fn build_frame_sequences_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, FrameSequenceBatchRow>(
        r#"
        SELECT
            session_key AS query_key,
            session_key,
            source_mac,
            sensor_id,
            location_id,
            window_start,
            window_end,
            sequence_tokens,
            semantic_tokens,
            frame_count
        FROM vec_frame_sequences
        WHERE session_key = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("frame_sequence batch query failed: {e}")))?;

    let scorer = sequence_score::load_frame_sequence_scorer(pool)
        .await
        .map_err(|e| WorkerError::text_build(format!("sequence scorer load failed: {e}")))?;

    for row in rows {
        let mut input = frame_sequence_row_to_input(&FrameSequenceRow {
            session_key: row.session_key.clone(),
            source_mac: row.source_mac.clone(),
            sensor_id: row.sensor_id.clone(),
            location_id: row.location_id.clone(),
            window_start: row.window_start,
            window_end: row.window_end,
            sequence_tokens: row.sequence_tokens.clone(),
            semantic_tokens: row.semantic_tokens.clone(),
            frame_count: row.frame_count,
        });

        let score = scorer.score_text(&row.sequence_tokens);
        insert_log_prob_line(&mut input.text, score);

        out.insert(row.query_key.clone(), input);
    }
    Ok(())
}

fn frame_sequence_row_to_input(row: &FrameSequenceRow) -> EmbeddingInput {
    let mut lines = vec!["kind: frame_sequence".to_string()];

    // Semantic tokens are single uppercase words - each is ~1 token.
    // Reserve OVERHEAD_TOKENS for the fixed structural lines; the rest goes to tokens.
    let token_word_budget = MAX_TOKENS - OVERHEAD_TOKENS;
    let token_source = row
        .semantic_tokens
        .as_deref()
        .filter(|tokens| !tokens.trim().is_empty())
        .unwrap_or(&row.sequence_tokens);
    let truncated_tokens = truncate_token_sequence(token_source, token_word_budget);
    lines.push(format!("tokens: {}", truncated_tokens));

    if let Some(start) = row.window_start {
        if let Some(end) = row.window_end {
            let duration_secs = (end - start).num_seconds();
            lines.push(format!("window_secs: {}", duration_secs));
        }
    }
    lines.push(format!("frame_count: {}", row.frame_count));

    // Note: log_prob is appended by the builder callers (build_frame_sequence /
    // build_frame_sequences_batch) after loading the transition model into the
    // Rust sequence scorer. See those functions for the score injection.
    // When computed, a "log_prob: {score}" line is inserted before frame_count.

    // Tokens are already truncated to token_word_budget (1 word ~ 1 token for
    // frame subtypes like BEACON, AUTH, etc.), so re-clamping with the generic
    // word_budget(MAX_TOKENS) = 128 words would double-truncate.  We use the full
    // text as-is; truncate_token_sequence above handles the budget precisely.
    let text = lines.join("\n");
    EmbeddingInput {
        text,
        source_observed_at: row.window_start,
        source_stream_name: None,
        source_sensor_id: row.sensor_id.clone(),
        source_location_id: row.location_id.clone(),
        source_mac: row.source_mac.clone(),
    }
}
