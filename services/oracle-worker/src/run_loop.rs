use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use r2d2::Pool;
use r2d2_oracle::OracleConnectionManager;
use rdkafka::{
    consumer::{CommitMode, Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
    ClientConfig, Message,
};
use tokio::sync::Semaphore;

use crate::config::RunConfig;
use crate::healthcheck::healthcheck;
use crate::log::{escape_for_log, log_poison_message};
use crate::{worker, HEARTBEAT_INTERVAL_SECS, SERVICE_NAME};

pub(crate) async fn run_loop(
    config: Arc<RunConfig>,
    pool: Arc<Pool<OracleConnectionManager>>,
    started: Instant,
) -> Result<(), String> {
    let consumer = build_consumer(&config)?;
    consumer
        .subscribe(&[config.load_topic.as_str()])
        .map_err(|error| format!("subscribe to {}: {error}", config.load_topic))?;
    let producer = Arc::new(build_producer(&config)?);

    let semaphore = Arc::new(Semaphore::new(config.oracle_worker_parallelism));
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
            _ = heartbeat.tick() => {
                emit_heartbeat(started, &mut last_heartbeat, &pool).await?;
            }
            next_message = consumer.recv() => {
                let message = next_message.map_err(|error| format!("consume {} message: {error}", config.load_topic))?;
                let permit = semaphore.clone().acquire_owned().await
                    .map_err(|error| format!("acquire semaphore permit: {error}"))?;
                let config = config.clone();
                let pool = pool.clone();
                let producer = producer.clone();

                if let Err(e) = handle_load_message(&producer, &config, &pool, &consumer, message).await {
                    eprintln!("service={SERVICE_NAME} event=worker_load_task_error error=\"{}\"", escape_for_log(&e));
                }
                drop(permit);
            }
        }
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

async fn handle_load_message(
    producer: &FutureProducer,
    config: &Arc<RunConfig>,
    pool: &Arc<Pool<OracleConnectionManager>>,
    consumer: &StreamConsumer,
    message: rdkafka::message::BorrowedMessage<'_>,
) -> Result<(), String> {
    let payload = message.payload().unwrap_or_default();
    let load = match serde_json::from_slice::<worker::OracleLoad>(payload) {
        Ok(load) => load,
        Err(error) => {
            log_poison_message(&message, &error);
            consumer
                .commit_message(&message, CommitMode::Async)
                .map_err(|ack_error| format!("commit poison message: {ack_error}"))?;
            return Ok(());
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

    let batch_started = Instant::now();
    let pool = Arc::clone(pool);
    let result = tokio::task::spawn_blocking(move || worker::handle_load_with_pool(load, &pool))
        .await
        .map_err(|error| format!("oracle load task panicked: {error}"))?;
    publish_result(producer, config, consumer, &message, result, batch_started).await
}

async fn publish_result(
    producer: &FutureProducer,
    config: &RunConfig,
    consumer: &StreamConsumer,
    message: &rdkafka::message::BorrowedMessage<'_>,
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
    consumer
        .commit_message(message, CommitMode::Async)
        .map_err(|error| format!("commit load message for batch {batch_id}: {error}"))?;
    log_result(&batch_id, &status, row_count, batch_duration_ms, &result);
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
