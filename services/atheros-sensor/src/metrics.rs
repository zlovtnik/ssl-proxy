//! Optional Prometheus text exposition format 0.0.4 endpoint for operational observability.
//!
//! The server only starts when ATH_SENSOR_METRICS_PORT is set; if unset, spawn_metrics_server
//! returns immediately with no listener. Counters (packets_seen, decoded_frames,
//! unsupported_frames, audit_window_drops, capture_errors, pipeline_errors, mac_lookup_failures)
//! accumulate monotonically for the lifetime of the process.
//! The HTTP server uses Hyper HTTP/1 with one tokio task per accepted connection; it binds
//! only to 127.0.0.1 and serves a single /metrics path in Prometheus text format 0.0.4.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::stats::CaptureStats;

pub type SharedStats = Arc<Mutex<CaptureStats>>;

pub fn shared_stats() -> SharedStats {
    Arc::new(Mutex::new(CaptureStats::default()))
}

/// Spawns the metrics HTTP server on 127.0.0.1 (not 0.0.0.0) serving exactly one path:
/// /metrics. No-op when port is None, returning immediately with no listener.
pub fn spawn_metrics_server(port: Option<u16>, stats: SharedStats) {
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
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| serve_metrics(req, Arc::clone(&stats)));
                if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
                    warn!(%error, "metrics connection failed");
                }
            });
        }
    });
}

/// Serves Prometheus text format (version 0.0.4) with counters (packets_seen, decoded_frames,
/// unsupported_frames, audit_window_drops, capture_errors, pipeline_errors, mac_lookup_failures)
/// and returns 404 for all other paths.
async fn serve_metrics(
    req: Request<hyper::body::Incoming>,
    stats: SharedStats,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != "/metrics" {
        let mut response = Response::new(Full::from(Bytes::from_static(b"not found\n")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
    }
    let stats = stats.lock().unwrap().clone();
    let body = format!(
        "# TYPE atheros_packets_seen counter\natheros_packets_seen {}\n\
         # TYPE atheros_decoded_frames counter\natheros_decoded_frames {}\n\
         # TYPE atheros_unsupported_frames counter\natheros_unsupported_frames {}\n\
         # TYPE atheros_audit_window_drops counter\natheros_audit_window_drops {}\n\
         # TYPE atheros_capture_errors counter\natheros_capture_errors {}\n\
         # TYPE atheros_pipeline_errors counter\natheros_pipeline_errors {}\n\
         # TYPE atheros_mac_lookup_failures counter\natheros_mac_lookup_failures {}\n",
        stats.packets_seen,
        stats.decoded_frames,
        stats.unsupported_frames,
        stats.audit_window_drops,
        stats.capture_errors,
        stats.pipeline_errors,
        stats.mac_lookup_failures,
    );
    Ok(Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(Full::from(Bytes::from(body)))
        .unwrap())
}
