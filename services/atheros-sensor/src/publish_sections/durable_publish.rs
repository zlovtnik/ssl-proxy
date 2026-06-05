pub async fn publish_oracle_payload_durable(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    operation: &'static str,
    stream_name: &str,
    payload: &str,
    observed_at: &str,
) -> Result<(), PublishError> {
    let key = sha256_hex(payload);
    let prepared = match prepare_publish(publisher, stream_name, payload, &key, observed_at) {
        Ok(prepared) => prepared,
        Err(error) => {
            persist_publish_failure(
                state,
                backlog,
                stream_name,
                &key,
                payload.to_string(),
                error,
            )
            .await?;
            return Ok(());
        }
    };
    if let Err(error) =
        queue_publish_with_backpressure(publisher, operation, stream_name, payload, &key).await
    {
        persist_publish_failure(
            state,
            backlog,
            stream_name,
            &key,
            payload.to_string(),
            error,
        )
        .await?;
        return Ok(());
    }

    let drained = flush_memory_backlog(state, backlog).await;
    if drained {
        close_backlog_circuit_breaker(state);
    }

    if let Err(error) = enqueue_prepared_publish(publisher, &key, &prepared).await {
        persist_publish_failure(
            state,
            backlog,
            stream_name,
            &key,
            payload.to_string(),
            error,
        )
        .await?;
        return Ok(());
    }
    debug!(
        dedupe_key = %key,
        topic = stream_name,
        payload_bytes = payload.len(),
        "queued wireless Oracle-bound event"
    );
    Ok(())
}

/// Persists a failed publish attempt to the backlog store.
async fn persist_publish_failure(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    stream_name: &str,
    dedupe_key: &str,
    payload: String,
    error: String,
) -> Result<(), PublishError> {
    if circuit_breaker_is_open(state, stream_name, dedupe_key, &payload, &error) {
        return Err(PublishError::Queued(error));
    }

    if let Err(backlog_err) = backlog
        .save_pending(dedupe_key, stream_name, &payload, &error)
        .await
    {
        queue_in_memory_after_backlog_failure(
            state,
            dedupe_key.to_string(),
            stream_name.to_string(),
            payload,
            error.clone(),
            backlog_err,
        );
        return Err(PublishError::Queued(error));
    }

    warn!(
        dedupe_key,
        publish_error = %error,
        "publish enqueue failed; audit entry sent to coordinator backlog"
    );
    Ok(())
}

/// Checks if the coordinator backlog circuit breaker is open.
fn circuit_breaker_is_open(
    state: &SharedPublishState,
    stream_name: &str,
    dedupe_key: &str,
    payload: &str,
    error: &str,
) -> bool {
    let mut state = state.lock().unwrap();
    match state.circuit_breaker_state {
        CircuitBreakerState::Closed => false,
        CircuitBreakerState::Open => {
            if let Some(opened_at) = state.circuit_breaker_opened_at {
                let elapsed = opened_at.elapsed();
                let timeout = state.circuit_breaker_timeout();
                const WARN_BUCKET_SIZE: u64 = 60;
                let bucket_id = elapsed.as_secs() / WARN_BUCKET_SIZE;
                if state.circuit_open_last_warn_bucket != Some(bucket_id) {
                    state.circuit_open_last_warn_bucket = Some(bucket_id);
                    warn!(
                        circuit_open_secs = elapsed.as_secs(),
                        circuit_timeout_ms = timeout.as_millis() as u64,
                        failure_count = state.circuit_breaker_failure_count,
                        memory_backlog_len = state.memory_backlog.len(),
                        memory_backlog_cap = state.memory_backlog_capacity.get(),
                        "Redpanda circuit breaker still open -- audit entries accumulating in memory"
                    );
                }
                if elapsed < timeout {
                    let memory_backlog_entries = state.put_memory_backlog(
                        dedupe_key.to_string(),
                        stream_name.to_string(),
                        payload,
                        error,
                    );
                    state.journal_append(dedupe_key, stream_name, payload, error);
                    warn!(
                        dedupe_key,
                        publish_error = %error,
                        memory_backlog_entries,
                        circuit_open_for_ms = elapsed.as_millis() as u64,
                        circuit_breaker_timeout_ms = timeout.as_millis() as u64,
                        failure_count = state.circuit_breaker_failure_count,
                        "backlog circuit breaker open; queued audit entry in memory"
                    );
                    return true;
                }
            }
            state.circuit_breaker_state = CircuitBreakerState::HalfOpen;
            state.circuit_breaker_opened_at = None;
            state.circuit_open_last_warn_bucket = None;
            info!(
                dedupe_key,
                "backlog circuit breaker probe starting (half-open)"
            );
            false
        }
        CircuitBreakerState::HalfOpen => false,
    }
}

/// Queues an entry in the in-memory backlog after a backlog publish failure.
fn queue_in_memory_after_backlog_failure(
    state: &SharedPublishState,
    dedupe_key: String,
    stream_name: String,
    payload: String,
    error: String,
    backlog_err: BacklogError,
) {
    let mut s = state.lock().unwrap();
    if s.circuit_breaker_state == CircuitBreakerState::Closed
        || s.circuit_breaker_state == CircuitBreakerState::HalfOpen
    {
        s.circuit_breaker_state = CircuitBreakerState::Open;
        s.circuit_breaker_opened_at = Some(Instant::now());
        s.circuit_breaker_failure_count = s.circuit_breaker_failure_count.saturating_add(1);
        s.circuit_open_last_warn_bucket = None;
        error!(
            dedupe_key = %dedupe_key,
            publish_error = %error,
            %backlog_err,
            circuit_breaker_timeout_ms = s.circuit_breaker_timeout().as_millis() as u64,
            failure_count = s.circuit_breaker_failure_count,
            "backlog publish failed; opening circuit breaker"
        );
    }

    let payload_ref = payload.clone();
    let error_ref = error.clone();
    let memory_backlog_entries = s.put_memory_backlog(
        dedupe_key.clone(),
        stream_name.clone(),
        &payload_ref,
        &error_ref,
    );
    s.journal_append(
        &dedupe_key,
        &stream_name,
        &payload_ref,
        &backlog_err.to_string(),
    );
    warn!(
        dedupe_key = %dedupe_key,
        memory_backlog_entries,
        "queued audit entry in memory backlog after backlog publish failure"
    );
}

/// Flushes memory backlog to the coordinator.
pub(crate) async fn flush_memory_backlog(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
) -> bool {
    let memory_entries = state.lock().unwrap().drain_memory_backlog();
    if !memory_entries.is_empty() {
        info!(
            memory_backlog_entries = memory_entries.len(),
            "flushing memory backlog to coordinator"
        );
    }
    let mut memory_entries = memory_entries.into_iter();
    let mut all_succeeded = true;
    while let Some((key, (stream, payload, err, _))) = memory_entries.next() {
        if let Err(backlog_err) = backlog.save_pending(&key, &stream, &payload, &err).await {
            error!(
                dedupe_key = %key,
                stream_name = %stream,
                %backlog_err,
                "failed to flush memory backlog entry to coordinator"
            );
            queue_in_memory_after_backlog_failure(state, key, stream, payload, err, backlog_err);
            for (remaining_key, (remaining_stream, remaining_payload, remaining_err, _)) in
                memory_entries
            {
                state.lock().unwrap().put_memory_backlog(
                    remaining_key,
                    remaining_stream,
                    &remaining_payload,
                    &remaining_err,
                );
            }
            return false;
        }
        let journal_path = state.lock().unwrap().journal_path.clone();
        if let Some(ref jp) = journal_path {
            remove_journal_entry(jp, &key);
        }
        all_succeeded = true;
    }
    all_succeeded
}

fn remove_journal_entry(journal_path: &std::path::Path, dedupe_key: &str) {
    let content = match std::fs::read_to_string(journal_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let remaining: Vec<&str> = content
        .lines()
        .filter(|line| {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) {
                parsed.get("dedupe_key").and_then(|v| v.as_str()) != Some(dedupe_key)
            } else {
                true
            }
        })
        .collect();
    if remaining.len() < content.lines().count() {
        let _ = std::fs::write(journal_path, remaining.join("\n") + "\n");
    }
}

/// Loads journal entries from disk and replays them through the backlog.
pub async fn replay_journal(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
) -> Result<u64, PublishError> {
    let journal_path = {
        let s = state.lock().unwrap();
        s.journal_path.clone()
    };
    let Some(ref journal_path) = journal_path else {
        return Ok(0);
    };
    let content = match std::fs::read_to_string(journal_path) {
        Ok(c) if !c.trim().is_empty() => c,
        _ => return Ok(0),
    };
    let mut replayed = 0u64;
    let mut retained_lines = Vec::new();
    for line in content.lines() {
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                retained_lines.push(line.to_string());
                continue;
            }
        };
        let dedupe_key = parsed["dedupe_key"].as_str().unwrap_or("").to_string();
        let stream_name = parsed["stream_name"]
            .as_str()
            .unwrap_or("wireless.audit")
            .to_string();
        let payload = parsed["payload"].as_str().unwrap_or("").to_string();
        let error = parsed["error"].as_str().unwrap_or("").to_string();
        if dedupe_key.is_empty() || payload.is_empty() {
            retained_lines.push(line.to_string());
            continue;
        }
        match backlog
            .save_pending(&dedupe_key, &stream_name, &payload, &error)
            .await
        {
            Ok(()) => {
                replayed += 1;
                info!(%dedupe_key, %stream_name, "replayed journal entry to coordinator backlog");
            }
            Err(e) => {
                warn!(%dedupe_key, %stream_name, %e, "failed to replay journal entry; will retry via memory flush");
                retained_lines.push(line.to_string());
                let mut s = state.lock().unwrap();
                s.put_memory_backlog(dedupe_key, stream_name, &payload, &error);
            }
        }
    }
    if replayed > 0 {
        let retained = if retained_lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", retained_lines.join("\n"))
        };
        let _ = std::fs::write(journal_path, retained);
        info!(
            replayed,
            retained = retained_lines.len(),
            "publish journal replayed"
        );
    }
    Ok(replayed)
}

/// Closes the backlog circuit breaker after a successful write.
fn close_backlog_circuit_breaker(state: &SharedPublishState) {
    let mut s = state.lock().unwrap();
    if s.circuit_breaker_state != CircuitBreakerState::Closed {
        s.circuit_breaker_state = CircuitBreakerState::Closed;
        s.circuit_breaker_opened_at = None;
        s.circuit_breaker_failure_count = 0;
        s.circuit_open_last_warn_bucket = None;
        info!("backlog circuit breaker closed, backlog resumed");
    }
}
