mod config;
mod consumer;
mod env;
mod healthcheck;
mod infra;
mod log;
mod metrics;
mod observability;
mod pool;
mod run_loop;
mod time;
mod window;
mod worker;

use std::{
    env as std_env,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

pub(crate) const SERVICE_NAME: &str = "oracle-worker";
pub(crate) const HEARTBEAT_INTERVAL_SECS: u64 = 300;
pub(crate) const DEFAULT_AUDIT_STREAM_NAME: &str = "AUDIT_STREAM";
pub(crate) const DEFAULT_SYNC_LOAD_TOPIC: &str = "sync.oracle.load";
pub(crate) const DEFAULT_SYNC_RESULT_TOPIC: &str = "sync.oracle.result";
pub(crate) const DEFAULT_SYNC_LOAD_CONSUMER: &str = "oracle-worker-load";
pub(crate) const DEFAULT_ORACLE_WORKER_PARALLELISM: usize = 3;

fn main() {
    let mode = std_env::args().nth(1).unwrap_or_else(|| "run".to_string());
    println!("service={SERVICE_NAME} event=process_start mode={mode}");
    let outcome = match mode.as_str() {
        "run" => run(),
        "healthcheck" => healthcheck::healthcheck("healthcheck"),
        other => Err(format!(
            "unknown mode: {other}. expected run or healthcheck"
        )),
    };

    if let Err(error) = outcome {
        eprintln!(
            "service={SERVICE_NAME} event=fatal status=error mode={mode} error=\"{}\"",
            log::escape_for_log(&error)
        );
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let started = Instant::now();
    metrics::init(started);
    healthcheck::healthcheck("run")?;
    thread::sleep(Duration::from_millis(500));
    println!("service={SERVICE_NAME} event=ready mode=run status=ok");
    let config = Arc::new(config::RunConfig::load()?);
    metrics::spawn_server(config.metrics_port)?;
    let pool = pool::build_oracle_pool(&config)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("initialize tokio runtime: {error}"))?;
    let otel_provider = observability::init_tracing(SERVICE_NAME);
    let result = runtime.block_on(run_loop::run_loop(config, pool, started));
    observability::shutdown_tracer_provider(otel_provider);
    result
}
