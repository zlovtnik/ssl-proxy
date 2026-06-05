impl OrderedCommitTracker {
    fn mark_started(&mut self, target: &CommitTarget) {
        self.partitions
            .entry(target.partition_key())
            .or_insert_with(|| PartitionCommitState {
                next_uncommitted_offset: target.offset,
                completed_offsets: BTreeSet::new(),
            });
    }

    fn mark_completed(&mut self, target: &CommitTarget) -> Result<Option<CommitReady>, String> {
        let key = target.partition_key();
        let state = self
            .partitions
            .entry(key.clone())
            .or_insert_with(|| PartitionCommitState {
                next_uncommitted_offset: target.offset,
                completed_offsets: BTreeSet::new(),
            });

        if target.offset < state.next_uncommitted_offset {
            return Ok(None);
        }

        state.completed_offsets.insert(target.offset);
        let mut advanced = false;
        while state
            .completed_offsets
            .remove(&state.next_uncommitted_offset)
        {
            state.next_uncommitted_offset = state
                .next_uncommitted_offset
                .checked_add(1)
                .ok_or_else(|| {
                    format!(
                        "commit offset overflow for topic {} partition {}",
                        key.topic, key.partition
                    )
                })?;
            advanced = true;
        }

        if advanced {
            Ok(Some(CommitReady {
                topic: key.topic,
                partition: key.partition,
                next_offset: state.next_uncommitted_offset,
            }))
        } else {
            Ok(None)
        }
    }
}

fn commit_completed_offset(
    consumer: &StreamConsumer,
    commit_tracker: &mut OrderedCommitTracker,
    completed: CompletedLoad,
) -> Result<(), String> {
    if let Some(commit_ready) = commit_tracker.mark_completed(&completed.commit_target)? {
        commit_load_offset(consumer, &commit_ready, &completed.batch_id)?;
    }
    Ok(())
}

fn commit_load_offset(
    consumer: &StreamConsumer,
    target: &CommitReady,
    batch_id: &str,
) -> Result<(), String> {
    let mut offsets = TopicPartitionList::new();
    offsets
        .add_partition_offset(
            &target.topic,
            target.partition,
            Offset::Offset(target.next_offset),
        )
        .map_err(|error| format!("build commit offset for batch {batch_id}: {error}"))?;
    consumer
        .commit(&offsets, CommitMode::Async)
        .map_err(|error| format!("commit load message for batch {batch_id}: {error}"))
}

fn process_task_result(
    task: Option<Result<Result<CompletedLoad, String>, tokio::task::JoinError>>,
    consumer: &StreamConsumer,
    commit_tracker: &mut OrderedCommitTracker,
) -> Result<(), String> {
    match task {
        Some(Ok(Ok(completed))) => {
            commit_completed_offset(consumer, commit_tracker, completed)?;
        }
        None => {}
        Some(Ok(Err(error))) => {
            eprintln!(
                "service={SERVICE_NAME} event=worker_load_task_error error=\"{}\"",
                escape_for_log(&error)
            );
        }
        Some(Err(error)) => {
            eprintln!(
                "service={SERVICE_NAME} event=worker_load_task_panic error=\"{}\"",
                escape_for_log(&error.to_string())
            );
        }
    }
    Ok(())
}

fn build_consumer(config: &RunConfig) -> Result<StreamConsumer, String> {
    ClientConfig::new()
        .set("bootstrap.servers", &config.redpanda_bootstrap_servers)
        .set("group.id", &config.load_consumer)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .map_err(|error| format!("create Redpanda consumer: {error}"))
}

fn build_producer(config: &RunConfig) -> Result<FutureProducer, String> {
    ClientConfig::new()
        .set("bootstrap.servers", &config.redpanda_bootstrap_servers)
        .create()
        .map_err(|error| format!("create Redpanda producer: {error}"))
}

fn log_result(
    batch_id: &str,
    status: &str,
    row_count: i32,
    duration_ms: u128,
    result: &worker::OracleResult,
) {
    if status == "success" {
        println!(
            "service={SERVICE_NAME} event=worker_load status=ok batch_id={batch_id} result_status=success row_count={row_count} duration_ms={duration_ms}"
        );
        return;
    }
    eprintln!(
        "service={SERVICE_NAME} event=worker_load status=ok batch_id={batch_id} result_status={status} row_count={row_count} duration_ms={duration_ms} error_class={} retryable={} error=\"{}\"",
        result.error_class,
        result.retryable,
        escape_for_log(&result.error_text)
    );
}

async fn wait_for_shutdown_signal() -> Result<&'static str, String> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|error| format!("register SIGTERM handler: {error}"))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| format!("wait for SIGINT: {error}"))?;
                Ok("SIGINT")
            }
            _ = terminate.recv() => Ok("SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| format!("wait for SIGINT: {error}"))?;
        Ok("SIGINT")
    }
}

impl CommitTarget {
    fn partition_key(&self) -> PartitionKey {
        PartitionKey {
            topic: self.topic.clone(),
            partition: self.partition,
        }
    }
}
