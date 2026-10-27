//! Bounded aggregate observations for the authenticated Search API.
//!
//! This handler belongs only to the private observability listener. Counters
//! are cumulative process measurements, never rates or ingestion readiness.

use axum::{extract::State, http::header, Json};
use serde::Serialize;
use std::sync::{atomic::Ordering, OnceLock};

use crate::state::SharedState;

#[derive(Serialize)]
pub struct TelemetrySnapshot {
    schema_version: u8,
    measured_at: String,
    instance_id: &'static str,
    active_tunnels: u64,
    counters: Counters,
    classifications: Classifications,
    publisher: sync_plane::SyncPublisherTelemetrySnapshot,
}

#[derive(Serialize)]
struct Counters {
    tunnels_opened: u64,
    bytes_up: u64,
    bytes_down: u64,
    blocked: u64,
    allowed: u64,
    obfuscated: u64,
    host_stats_dropped: u64,
}

#[derive(Serialize)]
struct Classifications {
    ads_tracker: u64,
    analytics: u64,
    cdn: u64,
    essential_api: u64,
    auth: u64,
    unknown: u64,
}

fn process_identity() -> &'static str {
    static INSTANCE_ID: OnceLock<String> = OnceLock::new();
    INSTANCE_ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

pub async fn snapshot(
    State(state): State<SharedState>,
) -> (
    [(header::HeaderName, &'static str); 1],
    Json<TelemetrySnapshot>,
) {
    let classes = state.classification_counts_snapshot();
    // Only non-destructive atomic loads and bounded in-memory publisher reads.
    // Do not use dashboard stats or bandwidth cursors: readers must not consume
    // each other's samples, nor trigger filesystem spool scans.
    let report = TelemetrySnapshot {
        schema_version: 1,
        measured_at: chrono::Utc::now().to_rfc3339(),
        instance_id: process_identity(),
        active_tunnels: state.active_tunnels.load(Ordering::Relaxed),
        counters: Counters {
            tunnels_opened: state.tunnels_opened.load(Ordering::Relaxed),
            bytes_up: state.bytes_up.load(Ordering::Relaxed),
            bytes_down: state.bytes_down.load(Ordering::Relaxed),
            blocked: state.blocked_count.load(Ordering::Relaxed),
            allowed: state.allowed_count.load(Ordering::Relaxed),
            obfuscated: state.obfuscated_count.load(Ordering::Relaxed),
            host_stats_dropped: state.host_stats_dropped.load(Ordering::Relaxed),
        },
        classifications: Classifications {
            ads_tracker: classes[0],
            analytics: classes[1],
            cdn: classes[2],
            essential_api: classes[3],
            auth: classes[4],
            unknown: classes[5],
        },
        publisher: state.publisher.telemetry_snapshot(),
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(report))
}
