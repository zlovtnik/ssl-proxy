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

use crate::{backlog::PostgresBacklog, stats::CaptureStats};

pub type SharedStats = Arc<Mutex<CaptureStats>>;

pub fn shared_stats() -> SharedStats {
    Arc::new(Mutex::new(CaptureStats::default()))
}

pub fn spawn_metrics_server(port: Option<u16>, stats: SharedStats, backlog: Arc<PostgresBacklog>) {
    let Some(port) = port else {
        return;
    };
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
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
            let backlog = Arc::clone(&backlog);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    serve_metrics(req, Arc::clone(&stats), Arc::clone(&backlog))
                });
                if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
                    warn!(%error, "metrics connection failed");
                }
            });
        }
    });
}

async fn serve_metrics(
    req: Request<hyper::body::Incoming>,
    stats: SharedStats,
    backlog: Arc<PostgresBacklog>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != "/metrics" {
        let mut response = Response::new(Full::from(Bytes::from_static(b"not found\n")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
    }
    let stats = stats.lock().unwrap().clone();
    let pool = backlog.pool_status();
    let body = format!(
        "# TYPE atheros_packets_seen counter\natheros_packets_seen {}\n\
         # TYPE atheros_decoded_frames counter\natheros_decoded_frames {}\n\
         # TYPE atheros_unsupported_frames counter\natheros_unsupported_frames {}\n\
         # TYPE atheros_audit_window_drops counter\natheros_audit_window_drops {}\n\
         # TYPE atheros_capture_errors counter\natheros_capture_errors {}\n\
         # TYPE atheros_pipeline_errors counter\natheros_pipeline_errors {}\n\
         # TYPE atheros_mac_lookup_failures counter\natheros_mac_lookup_failures {}\n\
         # TYPE atheros_postgres_pool_available gauge\natheros_postgres_pool_available {}\n\
         # TYPE atheros_postgres_pool_waiting gauge\natheros_postgres_pool_waiting {}\n",
        stats.packets_seen,
        stats.decoded_frames,
        stats.unsupported_frames,
        stats.audit_window_drops,
        stats.capture_errors,
        stats.pipeline_errors,
        stats.mac_lookup_failures,
        pool.available,
        pool.waiting,
    );
    Ok(Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(Full::from(Bytes::from(body)))
        .unwrap())
}
