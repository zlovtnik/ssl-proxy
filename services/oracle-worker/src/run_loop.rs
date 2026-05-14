use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_nats::jetstream;
use futures::StreamExt;
use r2d2::Pool;
use r2d2_oracle::OracleConnectionManager;
use tokio::sync::Semaphore;

use crate::config::RunConfig;
use crate::consumer::ensure_load_consumer;
use crate::healthcheck::healthcheck;
use crate::log::{escape_for_log, log_poison_message};
use crate::{worker, HEARTBEAT_INTERVAL_SECS, SERVICE_NAME};

pub(crate) async fn run_loop(
    config: Arc<RunConfig>,
    pool: Arc<Pool<OracleConnectionManager>>,
    started: Instant,
) -> Result<(), String> {
    let client = async_nats::connect(config.sync_nats_url.clone())
        .await
        .map_err(|error| format!("connect NATS {}: {error}", config.sync_nats_url))?;
    let jetstream = jetstream::new(client);
    let stream = jetstream
        .get_stream(config.audit_stream_name.clone())
        .await
        .map_err(|error| format!("get JetStream stream {}: {error}", config.audit_stream_name))?;
    let consumer = ensure_load_consumer(&stream, &config).await?;
    let mut messages = consumer
        .messages()
        .await
        .map_err(|error| format!("open pull consumer message stream: {error}"))?;

    let semaphore = Arc::new(Semaphore::new(config.oracle_worker_parallelism));
    let jetstream = Arc::new(jetstream);
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
            next_message = messages.next() => {
                match next_message {
                    Some(Ok(message)) => {
                        let permit = semaphore.clone().acquire_owned().await
                            .map_err(|error| format!("acquire semaphore permit: {error}"))?;
                        let jetstream = jetstream.clone();
                        let config = config.clone();
                        let pool = pool.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_load_message(&jetstream, &config, &pool, message).await {
                                eprintln!("service={SERVICE_NAME} event=worker_load_task_error error=\"{}\"", escape_for_log(&e));
                            }
                        });
                    }
                    Some(Err(error)) => return Err(format!("consume sync.oracle.load message: {error}")),
                    None => return Err("sync.oracle.load consumer stream ended unexpectedly".to_string()),
                }
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
    jetstream: &Arc<jetstream::Context>,
    config: &Arc<RunConfig>,
    pool: &Arc<Pool<OracleConnectionManager>>,
    message: jetstream::Message,
) -> Result<(), String> {
    let load = match serde_json::from_slice::<worker::OracleLoad>(&message.payload) {
        Ok(load) => load,
        Err(error) => {
            log_poison_message(&message, &error);
            message
                .ack()
                .await
                .map_err(|ack_error| format!("ack poison message: {ack_error}"))?;
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
        message.payload.len(),
    );

    let batch_started = Instant::now();
    let pool = Arc::clone(pool);
    let result = tokio::task::spawn_blocking(move || worker::handle_load_with_pool(load, &pool))
        .await
        .map_err(|error| format!("oracle load task panicked: {error}"))?;
    publish_result(jetstream, config, &message, result, batch_started).await
}

async fn publish_result(
    jetstream: &jetstream::Context,
    config: &RunConfig,
    message: &jetstream::Message,
    result: worker::OracleResult,
    batch_started: Instant,
) -> Result<(), String> {
    let batch_id = result.batch_id.clone();
    let status = result.status.clone();
    let batch_duration_ms = batch_started.elapsed().as_millis();
    let row_count = result.row_count;
    let payload = serde_json::to_vec(&result)
        .map_err(|error| format!("serialize OracleResult for batch {batch_id}: {error}"))?;
    let publish_ack = jetstream
        .publish(config.result_subject.clone(), payload.into())
        .await
        .map_err(|error| {
            format!(
                "publish sync.oracle.result for batch {batch_id} to {}: {error}",
                config.result_subject
            )
        })?;
    publish_ack
        .await
        .map_err(|error| format!("await publish ack for batch {batch_id}: {error}"))?;
    message
        .ack()
        .await
        .map_err(|error| format!("ack sync.oracle.load message for batch {batch_id}: {error}"))?;
    log_result(&batch_id, &status, row_count, batch_duration_ms, &result);
    Ok(())
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
