use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::SERVICE_NAME;

static STARTED_AT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
static WINDOW_TOTAL: AtomicU64 = AtomicU64::new(0);
static WINDOW_MESSAGES_TOTAL: AtomicU64 = AtomicU64::new(0);
static WINDOW_POISON_TOTAL: AtomicU64 = AtomicU64::new(0);
static WINDOW_LAST_PROCESSING_MS: AtomicU64 = AtomicU64::new(0);
static BATCH_RECEIVED_TOTAL: AtomicU64 = AtomicU64::new(0);
static BATCH_SUCCESS_TOTAL: AtomicU64 = AtomicU64::new(0);
static BATCH_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);
static BATCH_LAST_DURATION_MS: AtomicU64 = AtomicU64::new(0);
static HEARTBEAT_TOTAL: AtomicU64 = AtomicU64::new(0);
static POOL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static POOL_IDLE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static POOL_MAX_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
const METRICS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
struct OperationMetric {
    calls: u64,
    errors: u64,
    duration_ms_total: u64,
    duration_ms_last: u64,
}

static ORACLE_OPERATIONS: OnceLock<Mutex<BTreeMap<String, OperationMetric>>> = OnceLock::new();

pub(crate) fn init(started: Instant) {
    let _ = STARTED_AT.set(started);
}

pub(crate) fn spawn_server(port: u16) -> Result<(), String> {
    let address = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(address.as_str())
        .map_err(|error| format!("bind oracle-worker metrics endpoint {address}: {error}"))?;
    thread::Builder::new()
        .name("oracle-worker-metrics".to_string())
        .spawn(move || run_server(listener))
        .map_err(|error| format!("spawn oracle-worker metrics thread: {error}"))?;
    println!("service={SERVICE_NAME} event=metrics_server status=ok bind={address}");
    Ok(())
}

pub(crate) fn record_window(collected: usize, poison: usize, processing_ms: u128) {
    WINDOW_TOTAL.fetch_add(1, Ordering::Relaxed);
    WINDOW_MESSAGES_TOTAL.fetch_add(collected as u64, Ordering::Relaxed);
    WINDOW_POISON_TOTAL.fetch_add(poison as u64, Ordering::Relaxed);
    WINDOW_LAST_PROCESSING_MS.store(processing_ms as u64, Ordering::Relaxed);
}

pub(crate) fn record_batch_received() {
    BATCH_RECEIVED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_batch_result(success: bool, duration_ms: u128) {
    if success {
        BATCH_SUCCESS_TOTAL.fetch_add(1, Ordering::Relaxed);
    } else {
        BATCH_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    BATCH_LAST_DURATION_MS.store(duration_ms as u64, Ordering::Relaxed);
}

pub(crate) fn record_heartbeat() {
    HEARTBEAT_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_pool_state(connections: u32, idle_connections: u32, max_connections: u32) {
    POOL_CONNECTIONS.store(connections as u64, Ordering::Relaxed);
    POOL_IDLE_CONNECTIONS.store(idle_connections as u64, Ordering::Relaxed);
    POOL_MAX_CONNECTIONS.store(max_connections as u64, Ordering::Relaxed);
}

pub(crate) fn record_oracle_call(operation: &str, success: bool, duration_ms: u128) {
    let mut operations = oracle_operations().lock().unwrap();
    let metric = operations.entry(operation.to_string()).or_default();
    metric.calls = metric.calls.saturating_add(1);
    if !success {
        metric.errors = metric.errors.saturating_add(1);
    }
    let duration = duration_ms.min(u128::from(u64::MAX)) as u64;
    metric.duration_ms_total = metric.duration_ms_total.saturating_add(duration);
    metric.duration_ms_last = duration;
}

fn run_server(listener: TcpListener) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) = handle_request(stream) {
                        eprintln!(
                            "service={SERVICE_NAME} event=metrics_request status=error error=\"{}\"",
                            crate::log::escape_for_log(&error.to_string())
                        );
                    }
                });
            }
            Err(error) => {
                eprintln!(
                    "service={SERVICE_NAME} event=metrics_server status=error error=\"{}\"",
                    crate::log::escape_for_log(&error.to_string())
                );
            }
        }
    }
}

fn handle_request(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(METRICS_CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(METRICS_CONNECTION_TIMEOUT))?;
    let mut buffer = [0u8; 1024];
    let read = stream.read(&mut buffer)?;
    if read == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buffer[..read]);
    let line = request.lines().next().unwrap_or("");
    let is_metrics = line.starts_with("GET /metrics ");

    if !is_metrics {
        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")?;
        return Ok(());
    }

    let body = render_metrics();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn render_metrics() -> String {
    let uptime = STARTED_AT
        .get()
        .map(|started| started.elapsed().as_secs_f64())
        .unwrap_or(0.0);
    let oracle_operations = oracle_operations().lock().unwrap().clone();

    let mut body = format!(
        concat!(
            "# HELP oracle_worker_up Process health status.\n",
            "# TYPE oracle_worker_up gauge\n",
            "oracle_worker_up 1\n",
            "# HELP oracle_worker_uptime_seconds Oracle worker uptime.\n",
            "# TYPE oracle_worker_uptime_seconds gauge\n",
            "oracle_worker_uptime_seconds {uptime}\n",
            "# HELP oracle_worker_windows_total Processing windows completed.\n",
            "# TYPE oracle_worker_windows_total counter\n",
            "oracle_worker_windows_total {windows}\n",
            "# HELP oracle_worker_window_messages_total Messages observed across windows.\n",
            "# TYPE oracle_worker_window_messages_total counter\n",
            "oracle_worker_window_messages_total {window_messages}\n",
            "# HELP oracle_worker_window_poison_total Poison payloads observed.\n",
            "# TYPE oracle_worker_window_poison_total counter\n",
            "oracle_worker_window_poison_total {window_poison}\n",
            "# HELP oracle_worker_window_last_processing_ms Last window processing time in ms.\n",
            "# TYPE oracle_worker_window_last_processing_ms gauge\n",
            "oracle_worker_window_last_processing_ms {window_last_processing}\n",
            "# HELP oracle_worker_batches_received_total Batches received from Redpanda.\n",
            "# TYPE oracle_worker_batches_received_total counter\n",
            "oracle_worker_batches_received_total {batches_received}\n",
            "# HELP oracle_worker_batches_success_total Batches completed successfully.\n",
            "# TYPE oracle_worker_batches_success_total counter\n",
            "oracle_worker_batches_success_total {batches_success}\n",
            "# HELP oracle_worker_batches_failed_total Batches failed during processing.\n",
            "# TYPE oracle_worker_batches_failed_total counter\n",
            "oracle_worker_batches_failed_total {batches_failed}\n",
            "# HELP oracle_worker_batch_last_duration_ms Last batch end-to-end processing duration.\n",
            "# TYPE oracle_worker_batch_last_duration_ms gauge\n",
            "oracle_worker_batch_last_duration_ms {batch_last_duration}\n",
            "# HELP oracle_worker_heartbeats_total Periodic heartbeat events emitted.\n",
            "# TYPE oracle_worker_heartbeats_total counter\n",
            "oracle_worker_heartbeats_total {heartbeats}\n",
            "# HELP oracle_worker_pool_connections Oracle pool open connections.\n",
            "# TYPE oracle_worker_pool_connections gauge\n",
            "oracle_worker_pool_connections {pool_connections}\n",
            "# HELP oracle_worker_pool_idle_connections Oracle pool idle connections.\n",
            "# TYPE oracle_worker_pool_idle_connections gauge\n",
            "oracle_worker_pool_idle_connections {pool_idle_connections}\n",
            "# HELP oracle_worker_pool_max_connections Oracle pool configured maximum connections.\n",
            "# TYPE oracle_worker_pool_max_connections gauge\n",
            "oracle_worker_pool_max_connections {pool_max_connections}\n",
        ),
        uptime = uptime,
        windows = WINDOW_TOTAL.load(Ordering::Relaxed),
        window_messages = WINDOW_MESSAGES_TOTAL.load(Ordering::Relaxed),
        window_poison = WINDOW_POISON_TOTAL.load(Ordering::Relaxed),
        window_last_processing = WINDOW_LAST_PROCESSING_MS.load(Ordering::Relaxed),
        batches_received = BATCH_RECEIVED_TOTAL.load(Ordering::Relaxed),
        batches_success = BATCH_SUCCESS_TOTAL.load(Ordering::Relaxed),
        batches_failed = BATCH_FAILED_TOTAL.load(Ordering::Relaxed),
        batch_last_duration = BATCH_LAST_DURATION_MS.load(Ordering::Relaxed),
        heartbeats = HEARTBEAT_TOTAL.load(Ordering::Relaxed),
        pool_connections = POOL_CONNECTIONS.load(Ordering::Relaxed),
        pool_idle_connections = POOL_IDLE_CONNECTIONS.load(Ordering::Relaxed),
        pool_max_connections = POOL_MAX_CONNECTIONS.load(Ordering::Relaxed),
    );

    if !oracle_operations.is_empty() {
        body.push_str(
            "# HELP oracle_worker_oracle_calls_total Oracle calls grouped by operation.\n",
        );
        body.push_str("# TYPE oracle_worker_oracle_calls_total counter\n");
        for (operation, metric) in &oracle_operations {
            body.push_str(&format!(
                "oracle_worker_oracle_calls_total{{operation=\"{}\"}} {}\n",
                escape_label(operation),
                metric.calls
            ));
        }

        body.push_str(
            "# HELP oracle_worker_oracle_errors_total Oracle call errors grouped by operation.\n",
        );
        body.push_str("# TYPE oracle_worker_oracle_errors_total counter\n");
        for (operation, metric) in &oracle_operations {
            body.push_str(&format!(
                "oracle_worker_oracle_errors_total{{operation=\"{}\"}} {}\n",
                escape_label(operation),
                metric.errors
            ));
        }

        body.push_str("# HELP oracle_worker_oracle_duration_ms_total Oracle call duration total in milliseconds.\n");
        body.push_str("# TYPE oracle_worker_oracle_duration_ms_total counter\n");
        for (operation, metric) in &oracle_operations {
            body.push_str(&format!(
                "oracle_worker_oracle_duration_ms_total{{operation=\"{}\"}} {}\n",
                escape_label(operation),
                metric.duration_ms_total
            ));
        }

        body.push_str("# HELP oracle_worker_oracle_last_duration_ms Last Oracle call duration in milliseconds.\n");
        body.push_str("# TYPE oracle_worker_oracle_last_duration_ms gauge\n");
        for (operation, metric) in &oracle_operations {
            body.push_str(&format!(
                "oracle_worker_oracle_last_duration_ms{{operation=\"{}\"}} {}\n",
                escape_label(operation),
                metric.duration_ms_last
            ));
        }
    }

    body
}

fn oracle_operations() -> &'static Mutex<BTreeMap<String, OperationMetric>> {
    ORACLE_OPERATIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
