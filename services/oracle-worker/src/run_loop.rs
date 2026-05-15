use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use r2d2::Pool;
use r2d2_oracle::OracleConnectionManager;
use rdkafka::{
    consumer::{CommitMode, Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
    ClientConfig, Message, Offset, TopicPartitionList,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::RunConfig;
use crate::healthcheck::healthcheck;
use crate::log::{escape_for_log, log_poison_message};
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
    let mut in_flight = JoinSet::new();
    let mut last_heartbeat = Instant::now();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            signal = &mut shutdown => {
                let signal = signal?;
                println!("service={SERVICE_NAME} event=signal_received signal={signal}");
                break;
            }
            task = in_flight.join_next(), if !in_flight.is_empty() => {
                log_task_result(task);
            }
            _ = heartbeat.tick() => {
                emit_heartbeat(started, &mut last_heartbeat, &pool).await?;
            }
            next_message = consumer.recv() => {
                let message = next_message.map_err(|error| format!("consume {} message: {error}", config.load_topic))?;
                let permit = semaphore.clone().acquire_owned().await
                    .map_err(|error| format!("acquire semaphore permit: {error}"))?;

                let payload = message.payload().unwrap_or_default();
                let load = match serde_json::from_slice::<worker::OracleLoad>(payload) {
                    Ok(load) => load,
                    Err(error) => {
                        log_poison_message(&message, &error);
                        consumer
                            .commit_message(&message, CommitMode::Async)
                            .map_err(|ack_error| format!("commit poison message: {ack_error}"))?;
                        drop(permit);
                        continue;
                    }
                };
                println!(
                    "service={SERVICE_NAME} event=batch_received batch_id={} batch_no={} stream_name={} payload_ref={} cursor_start={} cursor_end={} attempt={} payload_bytes={}",
                    load.batch_id,
                    load.batch_no,
                    load.stream_name,
                    load.payload_ref,
                    load.cursor_start,
                    load.cursor_end,
                    load.attempt,
                    payload.len(),
                );

                let commit_target = CommitTarget {
                    topic: message.topic().to_string(),
                    partition: message.partition(),
                    offset: message.offset(),
                };
                let config = Arc::clone(&config);
                let pool = Arc::clone(&pool);
                let producer = Arc::clone(&producer);
                let consumer = Arc::clone(&consumer);

                in_flight.spawn(async move {
                    let _permit = permit;
                    handle_load_message(&producer, &config, &pool, &consumer, load, commit_target).await
                });
                while let Some(task) = in_flight.try_join_next() {
                    log_task_result(Some(task));
                }
            }
        }
    }

    while let Some(task) = in_flight.join_next().await {
        log_task_result(Some(task));
    }

    println!(
        "service={SERVICE_NAME} event=shutdown status=graceful uptime_s={}",
        started.elapsed().as_secs()
    );
    Ok(())
}

async fn emit_heartbeat(
    started: Instant,
    last_heartbeat: &mut Instant,
    pool: &Pool<OracleConnectionManager>,
) -> Result<(), String> {
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
struct CommitTarget {
    topic: String,
    partition: i32,
    offset: i64,
}

async fn handle_load_message(
    producer: &FutureProducer,
    config: &Arc<RunConfig>,
    pool: &Arc<Pool<OracleConnectionManager>>,
    consumer: &StreamConsumer,
    load: worker::OracleLoad,
    commit_target: CommitTarget,
) -> Result<(), String> {
    let batch_started = Instant::now();
    let pool = Arc::clone(pool);
    let result = tokio::task::spawn_blocking(move || worker::handle_load_with_pool(load, &pool))
        .await
        .map_err(|error| format!("oracle load task panicked: {error}"))?;
    publish_result(producer, config, consumer, commit_target, result, batch_started).await
}

async fn publish_result(
    producer: &FutureProducer,
    config: &RunConfig,
    consumer: &StreamConsumer,
    commit_target: CommitTarget,
    result: worker::OracleResult,
    batch_started: Instant,
) -> Result<(), String> {
    let batch_id = result.batch_id.clone();
    let status = result.status.clone();
    let batch_duration_ms = batch_started.elapsed().as_millis();
    let row_count = result.row_count;
    let payload = serde_json::to_vec(&result)
        .map_err(|error| format!("serialize OracleResult for batch {batch_id}: {error}"))?;
    producer
        .send(
            FutureRecord::to(config.result_topic.as_str())
                .payload(&payload)
                .key(batch_id.as_str()),
            Duration::from_secs(5),
        )
        .await
        .map_err(|(error, _)| format!("publish result for batch {batch_id}: {error}"))?;
    commit_load_offset(consumer, &commit_target, &batch_id)?;
    log_result(&batch_id, &status, row_count, batch_duration_ms, &result);
    Ok(())
}

fn commit_load_offset(
    consumer: &StreamConsumer,
    target: &CommitTarget,
    batch_id: &str,
) -> Result<(), String> {
    let next_offset = target
        .next_commit_offset()
        .ok_or_else(|| format!("commit offset overflow for batch {batch_id}"))?;
    let mut offsets = TopicPartitionList::new();
    offsets
        .add_partition_offset(&target.topic, target.partition, Offset::Offset(next_offset))
        .map_err(|error| format!("build commit offset for batch {batch_id}: {error}"))?;
    consumer
        .commit(&offsets, CommitMode::Async)
        .map_err(|error| format!("commit load message for batch {batch_id}: {error}"))
}

fn log_task_result(task: Option<Result<Result<(), String>, tokio::task::JoinError>>) {
    match task {
        Some(Ok(Ok(()))) | None => {}
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
    fn next_commit_offset(&self) -> Option<i64> {
        self.offset.checked_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::CommitTarget;

    #[test]
    fn commit_target_advances_to_next_offset() {
        let target = CommitTarget {
            topic: "sync.oracle.load".to_string(),
            partition: 2,
            offset: 41,
        };

        assert_eq!(target.next_commit_offset(), Some(42));
    }

    #[test]
    fn commit_target_rejects_offset_overflow() {
        let target = CommitTarget {
            topic: "sync.oracle.load".to_string(),
            partition: 0,
            offset: i64::MAX,
        };

        assert_eq!(target.next_commit_offset(), None);
    }
}
