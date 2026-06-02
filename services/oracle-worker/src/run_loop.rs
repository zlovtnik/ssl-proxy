use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

use futures::FutureExt;
use r2d2::Pool;
use r2d2_oracle::OracleConnectionManager;
use rdkafka::{
    consumer::{CommitMode, Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
    ClientConfig, Offset, TopicPartitionList,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::RunConfig;
use crate::healthcheck::healthcheck;
use crate::log::escape_for_log;
use crate::metrics;
use crate::window::{self, CollectedMessage, CommitTarget};
use crate::{worker, HEARTBEAT_INTERVAL_SECS, SERVICE_NAME};

pub(crate) async fn run_loop(
    config: Arc<RunConfig>,
    pool: Arc<Pool<OracleConnectionManager>>,
    started: Instant,
) -> Result<(), String> {
    let consumer = Arc::new(build_consumer(&config)?);
    consumer
        .subscribe(&[config.load_topic.as_str()])
        .map_err(|error| format!("subscribe to {}: {error}", config.load_topic))?;
    let producer = Arc::new(build_producer(&config)?);

    let semaphore = Arc::new(Semaphore::new(config.oracle_worker_parallelism));
    let mut commit_tracker = OrderedCommitTracker::default();
    let mut last_heartbeat = Instant::now();
    let mut window_no = 0u64;

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        if let Some(signal) = shutdown.as_mut().now_or_never() {
            let signal = signal?;
            println!("service={SERVICE_NAME} event=signal_received signal={signal}");
            break;
        }

        let window_start = Instant::now();
        window_no = window_no
            .checked_add(1)
            .ok_or_else(|| "window counter overflow".to_string())?;

        let window_budget = Duration::from_secs(config.window_duration_secs);
        let (messages, summary) =
            window::collect(&consumer, config.window_max_messages, window_budget).await;
        println!(
            "service={SERVICE_NAME} event=window_collected window_no={window_no} count={} poison={} collect_ms={}",
            summary.collected, summary.poison, summary.elapsed_collect_ms
        );

        if !messages.is_empty() {
            let mut join_set = JoinSet::new();
            for message in messages {
                process_collected_message(
                    message,
                    &consumer,
                    &mut commit_tracker,
                    &mut join_set,
                    &semaphore,
                    &producer,
                    &config,
                    &pool,
                )
                .await?;
            }

            while let Some(task) = join_set.join_next().await {
                process_task_result(Some(task), &consumer, &mut commit_tracker)?;
            }
        }

        log_window_complete(
            window_no,
            window_start.elapsed().as_millis(),
            window_budget,
            window_start
                .checked_add(window_budget)
                .unwrap_or(window_start)
                .saturating_duration_since(Instant::now())
                .as_millis(),
            summary.collected,
            summary.poison,
        );

        let sleep_target = window_start
            .checked_add(window_budget)
            .unwrap_or(window_start);
        tokio::time::sleep_until(tokio::time::Instant::from_std(sleep_target)).await;

        if last_heartbeat.elapsed() >= Duration::from_secs(HEARTBEAT_INTERVAL_SECS) {
            emit_heartbeat(started, &mut last_heartbeat, &pool).await?;
        }
    }

    println!(
        "service={SERVICE_NAME} event=shutdown status=graceful uptime_s={}",
        started.elapsed().as_secs()
    );
    Ok(())
}

async fn process_collected_message(
    message: CollectedMessage,
    consumer: &StreamConsumer,
    commit_tracker: &mut OrderedCommitTracker,
    join_set: &mut JoinSet<Result<CompletedLoad, String>>,
    semaphore: &Arc<Semaphore>,
    producer: &Arc<FutureProducer>,
    config: &Arc<RunConfig>,
    pool: &Arc<Pool<OracleConnectionManager>>,
) -> Result<(), String> {
    let CollectedMessage {
        commit_target,
        load,
        payload_bytes,
    } = message;

    let load = match load {
        Ok(load) => load,
        Err(error) => {
            log_collected_poison_message(&commit_target, payload_bytes, &error);
            commit_completed_offset(
                consumer,
                commit_tracker,
                CompletedLoad {
                    batch_id: "poison-message".to_string(),
                    commit_target,
                },
            )?;
            return Ok(());
        }
    };

    commit_tracker.mark_started(&commit_target);
    metrics::record_batch_received();
    let permit = semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| format!("acquire semaphore permit: {error}"))?;
    println!(
        "service={SERVICE_NAME} event=batch_received batch_id={} batch_no={} stream_name={} payload_ref={} cursor_start={} cursor_end={} attempt={} payload_bytes={}",
        load.batch_id,
        load.batch_no,
        load.stream_name,
        load.payload_ref,
        load.cursor_start,
        load.cursor_end,
        load.attempt,
        payload_bytes,
    );

    let config = Arc::clone(config);
    let pool = Arc::clone(pool);
    let producer = Arc::clone(producer);

    join_set.spawn(async move {
        let _permit = permit;
        handle_load_message(&producer, &config, &pool, load, commit_target).await
    });
    Ok(())
}

fn log_collected_poison_message(
    commit_target: &CommitTarget,
    payload_bytes: usize,
    error: &serde_json::Error,
) {
    let topic = escape_for_log(&commit_target.topic);
    let error = escape_for_log(&format!("deserialize OracleLoad payload: {error}"));
    eprintln!(
        "service={SERVICE_NAME} event=worker_load status=error classification=poison topic={topic} partition={} offset={} payload_bytes={} error=\"{}\"",
        commit_target.partition,
        commit_target.offset,
        payload_bytes,
        error,
    );
}

fn log_window_complete(
    window_no: u64,
    processing_ms: u128,
    window_budget: Duration,
    sleeping_ms: u128,
    collected: usize,
    poison: usize,
) {
    metrics::record_window(collected, poison, processing_ms);
    let lines = window_complete_log_lines(
        window_no,
        processing_ms,
        window_budget,
        sleeping_ms,
        collected,
    );
    if let Some(overrun) = lines.overrun {
        eprintln!("{overrun}");
    }
    println!("{}", lines.complete);
}

#[derive(Debug, Eq, PartialEq)]
struct WindowCompleteLogLines {
    overrun: Option<String>,
    complete: String,
}

fn window_complete_log_lines(
    window_no: u64,
    processing_ms: u128,
    window_budget: Duration,
    sleeping_ms: u128,
    collected: usize,
) -> WindowCompleteLogLines {
    let window_budget_ms = window_budget.as_millis();
    let overrun = if processing_ms > window_budget_ms {
        Some(format!(
            "service={SERVICE_NAME} event=window_overrun window_no={window_no} processing_ms={processing_ms} over_budget_ms={}",
            processing_ms - window_budget_ms
        ))
    } else {
        None
    };
    let complete = format!(
        "service={SERVICE_NAME} event=window_complete window_no={window_no} processing_ms={processing_ms} sleeping_ms={sleeping_ms} collected={collected}"
    );
    WindowCompleteLogLines { overrun, complete }
}

async fn emit_heartbeat(
    started: Instant,
    last_heartbeat: &mut Instant,
    pool: &Pool<OracleConnectionManager>,
) -> Result<(), String> {
    metrics::record_heartbeat();
    println!(
        "service={SERVICE_NAME} event=heartbeat uptime_s={} interval_s={HEARTBEAT_INTERVAL_SECS} since_last_heartbeat_s={}",
        started.elapsed().as_secs(),
        last_heartbeat.elapsed().as_secs(),
    );
    *last_heartbeat = Instant::now();
    tokio::task::spawn_blocking(|| healthcheck("run"))
        .await
        .map_err(|error| format!("healthcheck task panicked: {error}"))??;
    let state = pool.state();
    println!(
        "service={SERVICE_NAME} event=pool_state connections={} idle={} max={}",
        state.connections,
        state.idle_connections,
        pool.max_size()
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct CompletedLoad {
    batch_id: String,
    commit_target: CommitTarget,
}

async fn handle_load_message(
    producer: &FutureProducer,
    config: &Arc<RunConfig>,
    pool: &Arc<Pool<OracleConnectionManager>>,
    load: worker::OracleLoad,
    commit_target: CommitTarget,
) -> Result<CompletedLoad, String> {
    let batch_started = Instant::now();
    let pool = Arc::clone(pool);
    let result = tokio::task::spawn_blocking(move || worker::handle_load_with_pool(load, &pool))
        .await
        .map_err(|error| format!("oracle load task panicked: {error}"))?;
    publish_result(producer, config, commit_target, result, batch_started).await
}

async fn publish_result(
    producer: &FutureProducer,
    config: &RunConfig,
    commit_target: CommitTarget,
    result: worker::OracleResult,
    batch_started: Instant,
) -> Result<CompletedLoad, String> {
    let batch_id = result.batch_id.clone();
    let status = result.status.clone();
    let batch_duration_ms = batch_started.elapsed().as_millis();
    let row_count = result.row_count;
    let payload = serde_json::to_vec(&result)
        .map_err(|error| format!("serialize OracleResult for batch {batch_id}: {error}"))?;
    if let Err((error, _)) = producer
        .send(
            FutureRecord::to(config.result_topic.as_str())
                .payload(&payload)
                .key(batch_id.as_str()),
            Duration::from_secs(5),
        )
        .await
    {
        metrics::record_batch_result(false, batch_duration_ms);
        return Err(format!("publish result for batch {batch_id}: {error}"));
    }
    metrics::record_batch_result(status == "success", batch_duration_ms);
    log_result(&batch_id, &status, row_count, batch_duration_ms, &result);
    if status != "success" {
        return Err(format!(
            "oracle load failed for batch {batch_id}; result_status={status}; offset not committed"
        ));
    }
    Ok(CompletedLoad {
        batch_id,
        commit_target,
    })
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PartitionKey {
    topic: String,
    partition: i32,
}

#[derive(Debug)]
struct PartitionCommitState {
    next_uncommitted_offset: i64,
    completed_offsets: BTreeSet<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommitReady {
    topic: String,
    partition: i32,
    next_offset: i64,
}

#[derive(Debug, Default)]
struct OrderedCommitTracker {
    partitions: BTreeMap<PartitionKey, PartitionCommitState>,
}

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

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{sync::Semaphore, task::JoinSet};

    use super::{window_complete_log_lines, CommitTarget, OrderedCommitTracker};

    #[test]
    fn ordered_commit_tracker_waits_for_lower_offset() {
        let mut tracker = OrderedCommitTracker::default();
        let first = commit_target(2, 41);
        let second = commit_target(2, 42);
        tracker.mark_started(&first);
        tracker.mark_started(&second);

        assert_eq!(tracker.mark_completed(&second).unwrap(), None);

        let ready = tracker.mark_completed(&first).unwrap().unwrap();
        assert_eq!(ready.partition, 2);
        assert_eq!(ready.next_offset, 43);
    }

    #[test]
    fn ordered_commit_tracker_tracks_partitions_independently() {
        let mut tracker = OrderedCommitTracker::default();
        let partition_0 = commit_target(0, 10);
        let partition_1 = commit_target(1, 99);
        tracker.mark_started(&partition_0);
        tracker.mark_started(&partition_1);

        let ready = tracker.mark_completed(&partition_1).unwrap().unwrap();
        assert_eq!(ready.partition, 1);
        assert_eq!(ready.next_offset, 100);

        let ready = tracker.mark_completed(&partition_0).unwrap().unwrap();
        assert_eq!(ready.partition, 0);
        assert_eq!(ready.next_offset, 11);
    }

    #[test]
    fn ordered_commit_tracker_rejects_offset_overflow() {
        let mut tracker = OrderedCommitTracker::default();
        let target = commit_target(0, i64::MAX);
        tracker.mark_started(&target);

        assert!(tracker.mark_completed(&target).is_err());
    }

    #[tokio::test]
    async fn window_overrun_log_fires_when_tasks_exceed_budget() {
        let started = std::time::Instant::now();
        let semaphore = Arc::new(Semaphore::new(1));
        let mut join_set = JoinSet::new();

        for _ in 0..3 {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            join_set.spawn(async move {
                let _permit = permit;
                tokio::time::sleep(Duration::from_millis(20)).await;
            });
        }

        while join_set.join_next().await.is_some() {}

        let lines = window_complete_log_lines(
            7,
            started.elapsed().as_millis(),
            Duration::from_millis(10),
            0,
            3,
        );
        let overrun = lines.overrun.expect("expected overrun log line");
        assert!(overrun.contains("event=window_overrun"));
        assert!(overrun.contains("window_no=7"));
        assert!(overrun.contains("over_budget_ms="));
    }

    fn commit_target(partition: i32, offset: i64) -> CommitTarget {
        CommitTarget {
            topic: "sync.oracle.load".to_string(),
            partition,
            offset,
        }
    }
}
