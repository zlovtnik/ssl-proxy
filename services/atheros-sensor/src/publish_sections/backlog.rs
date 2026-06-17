/// Retries pending backlog entries that fall within the audit window.
pub async fn reconcile_backlog(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    audit_window: &AuditWindow,
) -> Result<(), PublishError> {
    let pending = backlog.list_pending().await?;
    debug!(
        pending_count = pending.len(),
        "starting backlog reconciliation"
    );
    for entry in pending {
        let observed_at = match extract_observed_at(&entry.payload) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    %error,
                    "skipping backlog entry with malformed observed_at"
                );
                continue;
            }
        };
        let observed_at_dt = match parse_observed_at_timestamp(&observed_at) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    observed_at = %observed_at,
                    %error,
                    "skipping backlog entry with invalid observed_at timestamp"
                );
                continue;
            }
        };
        if !audit_window.is_active_at(observed_at_dt) {
            debug!(
                dedupe_key = %entry.dedupe_key,
                stream_name = %entry.stream_name,
                observed_at = %observed_at,
                "skipping backlog entry outside audit window"
            );
            continue;
        }

        let prepared = match prepare_publish(
            publisher,
            &entry.stream_name,
            &entry.payload,
            &entry.dedupe_key,
            &observed_at,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    attempt_count = entry.attempt_count,
                    %error,
                    "backlog entry publish preparation failed"
                );
                continue;
            }
        };
        if entry.failure_stage == BacklogFailureStage::PrePublish {
            if let Err(error) = queue_publish_with_backpressure(
                publisher,
                "retry_primary_publish",
                &entry.stream_name,
                &entry.payload,
                &entry.dedupe_key,
            )
            .await
            {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    attempt_count = entry.attempt_count,
                    %error,
                    "backlog entry primary publish retry failed"
                );
                if let Err(persist_err) = persist_publish_failure(
                    state,
                    backlog,
                    &entry.stream_name,
                    &entry.dedupe_key,
                    entry.payload.clone(),
                    error,
                    BacklogFailureStage::PrePublish,
                )
                .await
                {
                    warn!(
                        dedupe_key = %entry.dedupe_key,
                        stream_name = %entry.stream_name,
                        attempt_count = entry.attempt_count,
                        persist_error = %persist_err,
                        "failed to persist backlog entry after primary publish retry failure"
                    );
                }
                continue;
            }
        }

        if let Err(error) = enqueue_prepared_publish(publisher, &entry.dedupe_key, &prepared).await
        {
            warn!(
                dedupe_key = %entry.dedupe_key,
                stream_name = %entry.stream_name,
                attempt_count = entry.attempt_count,
                %error,
                "backlog entry publish retry enqueue failed"
            );
            if let Err(persist_err) = persist_publish_failure(
                state,
                backlog,
                &entry.stream_name,
                &entry.dedupe_key,
                entry.payload.clone(),
                error,
                BacklogFailureStage::PostPublish,
            )
            .await
            {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    attempt_count = entry.attempt_count,
                    persist_error = %persist_err,
                    "failed to persist backlog entry after publish retry enqueue failure"
                );
            }
            continue;
        }
        backlog.mark_synced(&entry.dedupe_key).await?;
        info!(
            dedupe_key = %entry.dedupe_key,
            stream_name = %entry.stream_name,
            attempt_count = entry.attempt_count,
            "backlog entry reconciled"
        );
    }
    Ok(())
}

fn prepare_publish(
    publisher: &dyn PublishClient,
    stream_name: &str,
    payload: &str,
    dedupe_key: &str,
    observed_at: &str,
) -> Result<PreparedPublish, String> {
    let observed_at_dt = DateTime::parse_from_rfc3339(observed_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| format!("invalid observed_at timestamp {observed_at:?}: {error}"))?;
    let payload_ref = publisher.payload_ref_for_event(payload, observed_at)?;
    let request = ScanRequest {
        stream_name: stream_name.to_string(),
        dedupe_key: dedupe_key.to_string(),
        payload_ref: payload_ref.clone(),
        observed_at: observed_at.to_string(),
    };
    let request_payload = serde_json::to_string(&request)
        .map_err(|error| format!("serialize scan request: {error}"))?;
    Ok(PreparedPublish {
        request_payload,
        stream_name: stream_name.to_string(),
        dedupe_key: dedupe_key.to_string(),
        payload_ref,
        observed_at: observed_at_dt,
    })
}

async fn enqueue_prepared_publish(
    publisher: &dyn PublishClient,
    dedupe_key: &str,
    prepared: &PreparedPublish,
) -> Result<(), String> {
    queue_publish_with_backpressure(
        publisher,
        "publish_scan_request",
        SYNC_SCAN_REQUEST_TOPIC,
        &prepared.request_payload,
        dedupe_key,
    )
    .await?;
    debug!(
        dedupe_key,
        topic = SYNC_SCAN_REQUEST_TOPIC,
        payload_bytes = prepared.request_payload.len(),
        "queued scan request"
    );
    Ok(())
}

async fn queue_publish_with_backpressure(
    publisher: &dyn PublishClient,
    stage: &str,
    topic: &str,
    payload: &str,
    dedupe_key: &str,
) -> Result<(), String> {
    let started = Instant::now();
    match publisher.enqueue_message(topic, payload) {
        Ok(()) => {
            crate::metrics::record_redpanda_publish(true, started.elapsed().as_millis());
            Ok(())
        }
        Err(error) if error == ENQUEUE_TIMEOUT_ERROR => {
            debug!(
                dedupe_key,
                topic,
                payload_bytes = payload.len(),
                "sync publisher queue full; retrying with backpressure"
            );
            let publish_result = publisher
                .publish_message(topic, payload)
                .await
                .map_err(|error| {
                    format!("stage={stage} topic={topic} dedupe_key={dedupe_key}: {error}")
                });
            crate::metrics::record_redpanda_publish(
                publish_result.is_ok(),
                started.elapsed().as_millis(),
            );
            publish_result
        }
        Err(error) => {
            crate::metrics::record_redpanda_publish(false, started.elapsed().as_millis());
            Err(format!(
                "stage={stage} topic={topic} dedupe_key={dedupe_key}: {error}"
            ))
        }
    }
}

fn extract_observed_at(payload: &str) -> Result<String, PublishError> {
    let parsed: serde_json::Value = serde_json::from_str(payload)?;
    let observed_at = parsed
        .get("observed_at")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| PublishError::Publish("missing observed_at".to_string()))?;
    Ok(observed_at.to_string())
}

fn parse_observed_at_timestamp(observed_at: &str) -> Result<DateTime<Utc>, PublishError> {
    DateTime::parse_from_rfc3339(observed_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            PublishError::Publish(format!(
                "invalid observed_at timestamp {observed_at:?}: {error}"
            ))
        })
}

fn dedupe_key(payload: &str) -> String {
    sha256_hex(payload)
}

fn sha256_hex(payload: &str) -> String {
    crate::digest::sha256_hex(&[payload.as_bytes()])
}

/// Periodic drain of memory backlog -- runs regardless of circuit breaker state.
pub async fn periodic_memory_backlog_flush(state: &SharedPublishState, backlog: &dyn BacklogStore) {
    let backlog_len = state.lock().unwrap().memory_backlog.len();
    if backlog_len == 0 {
        return;
    }
    info!(
        memory_backlog_entries = backlog_len,
        "periodic memory backlog drain"
    );
    let drained = flush_memory_backlog(state, backlog).await;
    if drained {
        close_backlog_circuit_breaker(state);
    }
}
