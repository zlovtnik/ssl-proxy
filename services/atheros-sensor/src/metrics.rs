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
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Instant,
};

use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::publish::{CircuitBreakerState, SharedPublishState};
use crate::stats::CaptureStats;

pub type SharedStats = Arc<Mutex<CaptureStats>>;

static STARTED_AT: OnceLock<Instant> = OnceLock::new();
static REDPANDA_PUBLISH_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_PUBLISH_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_PUBLISH_DURATION_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_PUBLISH_LAST_DURATION_MS: AtomicU64 = AtomicU64::new(0);
static REDPANDA_REQUEST_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_REQUEST_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_REQUEST_DURATION_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REDPANDA_REQUEST_LAST_DURATION_MS: AtomicU64 = AtomicU64::new(0);

pub fn shared_stats() -> SharedStats {
    let _ = STARTED_AT.set(Instant::now());
    Arc::new(Mutex::new(CaptureStats::default()))
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
    let stats = stats.lock().unwrap().clone();
    let (cb_state, journal_bytes) = {
        let publish_state = publish_state.lock().unwrap();
        let cb_state = match publish_state.circuit_breaker_state {
            CircuitBreakerState::Closed => 0,
            CircuitBreakerState::HalfOpen => 1,
            CircuitBreakerState::Open => 2,
        };
        (cb_state, publish_state.journal_bytes())
    };
    let body = render_metrics_body(&stats, cb_state, journal_bytes);
    Ok(Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(Full::from(Bytes::from(body)))
        .unwrap())
}

fn render_metrics_body(stats: &CaptureStats, cb_state: u8, journal_bytes: u64) -> String {
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
        let stats = CaptureStats {
            malformed_frames: 7,
            probe_accumulator_len: 9,
            memory_backlog_len: 3,
            ..CaptureStats::default()
        };

        let body = render_metrics_body(&stats, 2, 4096);

        assert!(body.contains("atheros_malformed_frames 7\n"));
        assert!(body.contains("atheros_probe_accumulator_len 9\n"));
        assert!(body.contains("atheros_journal_bytes 4096\n"));
        assert!(body.contains("atheros_circuit_breaker_state 2\n"));
    }
}
