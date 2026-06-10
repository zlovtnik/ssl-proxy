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
    message::{Header, OwnedHeaders},
    producer::{FutureProducer, FutureRecord},
    ClientConfig, Offset, TopicPartitionList,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{field, info_span, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

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
        trace_headers,
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

    let span = info_span!(
        "oracle.batch.process",
        "messaging.system" = "redpanda",
        "messaging.destination.name" = %commit_target.topic,
        "messaging.operation" = "process",
        "batch.id" = %load.batch_id,
        "stream.name" = %load.stream_name,
        status = field::Empty
    );
    if !trace_headers.is_empty() {
        let _ = span.set_parent(crate::observability::extract_trace_context(&trace_headers));
    }

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
        load.batch_no.unwrap_or(0),
        load.stream_name,
        load.payload_ref.as_deref().unwrap_or(""),
        load.cursor_start.as_deref().unwrap_or(""),
        load.cursor_end.as_deref().unwrap_or(""),
        load.attempt,
        payload_bytes,
    );

    let config = Arc::clone(config);
    let pool = Arc::clone(pool);
    let producer = Arc::clone(producer);

    join_set.spawn(async move {
        let _permit = permit;
        let result = handle_load_message(&producer, &config, &pool, load, commit_target)
            .instrument(span.clone())
            .await;
        span.record("status", if result.is_ok() { "ok" } else { "error" });
        result
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
    metrics::record_pool_state(state.connections, state.idle_connections, pool.max_size());
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
    let span = info_span!(
        "redpanda.publish",
        "messaging.system" = "redpanda",
        "messaging.destination.name" = %config.result_topic,
        "messaging.operation" = "publish",
        "batch.id" = %batch_id,
        status = field::Empty
    );
    let mut record = FutureRecord::to(config.result_topic.as_str())
        .payload(&payload)
        .key(batch_id.as_str());
    if let Some(headers) = current_trace_headers() {
        record = record.headers(headers);
    }
    if let Err((error, _)) = producer
        .send(record, Duration::from_secs(5))
        .instrument(span.clone())
        .await
    {
        span.record("status", "error");
        metrics::record_batch_result(false, batch_duration_ms);
        return Err(format!("publish result for batch {batch_id}: {error}"));
    }
    span.record("status", "ok");
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

fn current_trace_headers() -> Option<OwnedHeaders> {
    let headers = crate::observability::current_trace_headers();
    if headers.is_empty() {
        return None;
    }

    let mut owned = OwnedHeaders::new();
    for (key, value) in headers {
        owned = owned.insert(Header {
            key: key.as_str(),
            value: Some(value.as_str()),
        });
    }
    Some(owned)
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
