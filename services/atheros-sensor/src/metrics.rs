//! Optional Prometheus text exposition format 0.0.4 endpoint for operational observability.
//!
//! The server only starts when ATH_SENSOR_METRICS_PORT is set; if unset, spawn_metrics_server
//! returns immediately with no listener. Counters (packets_seen, decoded_frames,
//! unsupported_frames, malformed_frames, audit_window_drops, capture_errors, pipeline_errors,
//! mac_lookup_failures)
//! accumulate monotonically for the lifetime of the process.
//! The HTTP server uses Hyper HTTP/1 with one tokio task per accepted connection; it binds
//! only to 127.0.0.1 and serves a single /metrics path in Prometheus text format 0.0.4.

use std::{
    convert::Infallible,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::publish::{CircuitBreakerState, SharedPublishState};
use crate::stats::{CaptureStats, CaptureStatsSnapshot};

pub type SharedStats = Arc<CaptureStats>;

static STARTED_AT: OnceLock<Instant> = OnceLock::new();
static REDPANDA_PUBLISH_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_PUBLISH_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_PUBLISH_DURATION_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_PUBLISH_LAST_DURATION_MS: AtomicU64 = AtomicU64::new(0);
static REDPANDA_REQUEST_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_REQUEST_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_REQUEST_DURATION_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_REQUEST_LAST_DURATION_MS: AtomicU64 = AtomicU64::new(0);
static TEXTFILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn shared_stats() -> SharedStats {
    let _ = STARTED_AT.set(Instant::now());
    Arc::new(CaptureStats::default())
}

pub(crate) fn record_redpanda_publish(success: bool, duration_ms: u128) {
    REDPANDA_PUBLISH_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !success {
        REDPANDA_PUBLISH_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    let duration = duration_ms.min(u128::from(u64::MAX)) as u64;
    REDPANDA_PUBLISH_DURATION_MS_TOTAL.fetch_add(duration, Ordering::Relaxed);
    REDPANDA_PUBLISH_LAST_DURATION_MS.store(duration, Ordering::Relaxed);
}

pub(crate) fn record_redpanda_request(success: bool, duration_ms: u128) {
    REDPANDA_REQUEST_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !success {
        REDPANDA_REQUEST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    let duration = duration_ms.min(u128::from(u64::MAX)) as u64;
    REDPANDA_REQUEST_DURATION_MS_TOTAL.fetch_add(duration, Ordering::Relaxed);
    REDPANDA_REQUEST_LAST_DURATION_MS.store(duration, Ordering::Relaxed);
}

/// Spawns the metrics HTTP server on 127.0.0.1 (not 0.0.0.0) serving exactly one path:
/// /metrics. No-op when port is None, returning immediately with no listener.
pub fn spawn_metrics_server(
    port: Option<u16>,
    stats: SharedStats,
    publish_state: SharedPublishState,
) {
    let Some(port) = port else {
        return;
    };
    tokio::spawn(async move {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                warn!(%error, port, "atheros sensor metrics bind failed");
                return;
            }
        };
        info!(%addr, path = "/metrics", "atheros sensor metrics endpoint listening");
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "metrics accept failed");
                    continue;
                }
            };
            let stats = Arc::clone(&stats);
            let ps = Arc::clone(&publish_state);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service =
                    service_fn(move |req| serve_metrics(req, Arc::clone(&stats), Arc::clone(&ps)));
                if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
                    warn!(%error, "metrics connection failed");
                }
            });
        }
    });
}

pub fn spawn_metrics_textfile_writer(
    path: std::path::PathBuf,
    stats: SharedStats,
    publish_state: SharedPublishState,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let snapshot = stats.snapshot();
            let (cb_state, journal_bytes) = publish_state_snapshot(&publish_state);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let body = render_metrics_body(&snapshot, cb_state, journal_bytes, timestamp);
            if let Err(error) = write_textfile_atomic(&path, body.as_bytes()) {
                warn!(%error, path = %path.display(), "atheros sensor textfile write failed");
            }
        }
    });
}

fn write_textfile_atomic(path: &Path, body: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "textfile path has no parent")
    })?;
    fs::create_dir_all(parent)?;
    let sequence = TEXTFILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid textfile name"))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(body)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn publish_state_snapshot(publish_state: &SharedPublishState) -> (u8, u64) {
    let publish_state = publish_state.lock().unwrap();
    let cb_state = match publish_state.circuit_breaker_state {
        CircuitBreakerState::Closed => 0,
        CircuitBreakerState::HalfOpen => 1,
        CircuitBreakerState::Open => 2,
    };
    (cb_state, publish_state.journal_bytes())
}

/// Serves Prometheus text format (version 0.0.4) with counters (packets_seen, decoded_frames,
/// unsupported_frames, malformed_frames, audit_window_drops, capture_errors, pipeline_errors,
/// mac_lookup_failures, channel_hop_count), gauges (bandwidth_window_lag_ms,
/// memory_backlog_len, probe_accumulator_len, journal_bytes, circuit_breaker_state),
/// and counter (channel_hops_total) and returns 404 for all other paths.
async fn serve_metrics(
    req: Request<hyper::body::Incoming>,
    stats: SharedStats,
    publish_state: SharedPublishState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != "/metrics" {
        let mut response = Response::new(Full::from(Bytes::from_static(b"not found\n")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
    }
    let stats = stats.snapshot();
    let (cb_state, journal_bytes) = publish_state_snapshot(&publish_state);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let body = render_metrics_body(&stats, cb_state, journal_bytes, timestamp);
    Ok(Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(Full::from(Bytes::from(body)))
        .unwrap())
}

fn render_metrics_body(
    stats: &CaptureStatsSnapshot,
    cb_state: u8,
    journal_bytes: u64,
    textfile_timestamp_seconds: u64,
) -> String {
    let lag_line = match stats.bandwidth_window_lag_ms {
        Some(ms) => format!("atheros_bandwidth_window_lag_ms {ms}\n"),
        None => String::new(),
    };
    let uptime = STARTED_AT
        .get()
        .map(|started| started.elapsed().as_secs_f64())
        .unwrap_or(0.0);
    format!(
        "# TYPE atheros_up gauge\natheros_up 1\n\
         # TYPE atheros_uptime_seconds gauge\natheros_uptime_seconds {uptime}\n\
         # HELP atheros_sensor_textfile_timestamp_seconds Unix timestamp of the latest complete textfile snapshot.\n\
         # TYPE atheros_sensor_textfile_timestamp_seconds gauge\natheros_sensor_textfile_timestamp_seconds {textfile_timestamp_seconds}\n\
         # TYPE atheros_packets_seen counter\natheros_packets_seen {}\n\
         # TYPE atheros_decoded_frames counter\natheros_decoded_frames {}\n\
         # TYPE atheros_unsupported_frames counter\natheros_unsupported_frames {}\n\
         # TYPE atheros_malformed_frames counter\natheros_malformed_frames {}\n\
         # TYPE atheros_audit_window_drops counter\natheros_audit_window_drops {}\n\
         # TYPE atheros_capture_errors counter\natheros_capture_errors {}\n\
         # TYPE atheros_pipeline_errors counter\natheros_pipeline_errors {}\n\
         # TYPE atheros_mac_lookup_failures counter\natheros_mac_lookup_failures {}\n\
         # TYPE atheros_channel_hop_count counter\natheros_channel_hop_count {}\n\
         # TYPE atheros_channel_hops_total counter\natheros_channel_hops_total {}\n\
         # TYPE atheros_bandwidth_window_lag_ms gauge\n\
         {}\
         # TYPE atheros_memory_backlog_len gauge\natheros_memory_backlog_len {}\n\
         # TYPE atheros_probe_accumulator_len gauge\natheros_probe_accumulator_len {}\n\
         # TYPE atheros_journal_bytes gauge\natheros_journal_bytes {}\n\
         # TYPE atheros_circuit_breaker_state gauge\natheros_circuit_breaker_state {}\n\
         # TYPE atheros_redpanda_publish_total counter\natheros_redpanda_publish_total {}\n\
         # TYPE atheros_redpanda_publish_errors_total counter\natheros_redpanda_publish_errors_total {}\n\
         # TYPE atheros_redpanda_publish_duration_ms_total counter\natheros_redpanda_publish_duration_ms_total {}\n\
         # TYPE atheros_redpanda_publish_last_duration_ms gauge\natheros_redpanda_publish_last_duration_ms {}\n\
         # TYPE atheros_redpanda_request_total counter\natheros_redpanda_request_total {}\n\
         # TYPE atheros_redpanda_request_errors_total counter\natheros_redpanda_request_errors_total {}\n\
         # TYPE atheros_redpanda_request_duration_ms_total counter\natheros_redpanda_request_duration_ms_total {}\n\
         # TYPE atheros_redpanda_request_last_duration_ms gauge\natheros_redpanda_request_last_duration_ms {}\n",
        stats.packets_seen,
        stats.decoded_frames,
        stats.unsupported_frames,
        stats.malformed_frames,
        stats.audit_window_drops,
        stats.capture_errors,
        stats.pipeline_errors,
        stats.mac_lookup_failures,
        stats.channel_hop_count,
        stats.channel_hop_count,
        lag_line,
        stats.memory_backlog_len,
        stats.probe_accumulator_len,
        journal_bytes,
        cb_state,
        REDPANDA_PUBLISH_TOTAL.load(Ordering::Relaxed),
        REDPANDA_PUBLISH_ERRORS_TOTAL.load(Ordering::Relaxed),
        REDPANDA_PUBLISH_DURATION_MS_TOTAL.load(Ordering::Relaxed),
        REDPANDA_PUBLISH_LAST_DURATION_MS.load(Ordering::Relaxed),
        REDPANDA_REQUEST_TOTAL.load(Ordering::Relaxed),
        REDPANDA_REQUEST_ERRORS_TOTAL.load(Ordering::Relaxed),
        REDPANDA_REQUEST_DURATION_MS_TOTAL.load(Ordering::Relaxed),
        REDPANDA_REQUEST_LAST_DURATION_MS.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_metrics_includes_malformed_probe_and_journal_metrics() {
        let stats = CaptureStats::default();
        for _ in 0..7 {
            stats.increment_malformed_frames();
        }
        stats.set_probe_accumulator_len(9);
        stats.set_memory_backlog_len(3);

        let body = render_metrics_body(&stats.snapshot(), 2, 4096, 1_700_000_000);

        assert!(body.contains("atheros_malformed_frames 7\n"));
        assert!(body.contains("atheros_probe_accumulator_len 9\n"));
        assert!(body.contains("atheros_journal_bytes 4096\n"));
        assert!(body.contains("atheros_circuit_breaker_state 2\n"));
        assert!(body.contains("atheros_sensor_textfile_timestamp_seconds 1700000000\n"));
    }

    #[test]
    fn textfile_write_is_atomic_and_stale_detectable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("atheros_sensor.prom");
        write_textfile_atomic(
            &path,
            b"atheros_sensor_textfile_timestamp_seconds 1700000000\n",
        )
        .unwrap();

        let rendered = fs::read_to_string(&path).unwrap();
        assert_eq!(
            rendered,
            "atheros_sensor_textfile_timestamp_seconds 1700000000\n"
        );
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }
}
