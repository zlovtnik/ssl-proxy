use axum::{
    extract::{connect_info::ConnectInfo, Path, Query, State},
    http::HeaderMap,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::atomic::Ordering, time::Instant};
use tracing::{info, warn};

use crate::state::SharedState;

/// Serializable snapshot of one host's heuristic stats.
#[derive(Serialize)]
pub struct HostSnapshot {
    pub host: String,
    pub blocked_attempts: u64,
    pub blocked_bytes_approx: u64,
    pub frequency_hz: f64,
    pub risk_score: f64,
    pub verdict: &'static str,
    pub tarpit_held_ms: u64,
    pub battery_saved_mwh: f64,
    pub category: &'static str,
    pub consecutive_blocks: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat_ema_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter_ema_ms: Option<u64>,
    pub low_jitter_streak: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regularity_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suites_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_lite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reason: Option<String>,
}

#[derive(Serialize)]
pub struct ReadySyncStatus {
    pub publisher: sync_plane::SyncPublisherHealthSnapshot,
}

#[derive(Serialize)]
pub struct ReadyReport {
    pub status: &'static str,
    pub local: &'static str,
    pub sync: ReadySyncStatus,
}

#[derive(Serialize)]
pub struct SyncTopicCount {
    pub topic: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct SyncStatusReport {
    pub status: &'static str,
    pub publisher: sync_plane::SyncPublisherHealthSnapshot,
    pub published_topics: Vec<SyncTopicCount>,
    pub last_error: Option<String>,
}

/// GET /health — liveness probe for the admin surface.
pub async fn health(State(state): State<SharedState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "wireguard_relay": state.wg_relay_metrics.snapshot(),
        })),
    )
        .into_response()
}

/// GET /metrics - Prometheus exposition for the proxy admin surface.
pub async fn metrics(State(state): State<SharedState>) -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4")],
        render_metrics_body(&state),
    )
        .into_response()
}

/// GET /ready — readiness probe for the local process surfaces.
pub async fn ready(State(state): State<SharedState>) -> impl IntoResponse {
    let publisher = state.publisher.health_snapshot();
    let status = if publisher.configured && publisher.last_error.is_some() {
        "degraded"
    } else {
        "ok"
    };
    let status_code = if publisher.configured && publisher.last_error.is_some() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    (
        status_code,
        Json(ReadyReport {
            status,
            local: "ok",
            sync: ReadySyncStatus { publisher },
        }),
    )
        .into_response()
}

fn render_metrics_body(state: &crate::state::AppState) -> String {
    let publisher = state.publisher.health_snapshot();
    let wg_relay = state.wg_relay_metrics.snapshot();
    let classifications = state.classification_counts_snapshot();
    format!(
        concat!(
            "# HELP ssl_proxy_up Process health status.\n",
            "# TYPE ssl_proxy_up gauge\n",
            "ssl_proxy_up 1\n",
            "# HELP ssl_proxy_tunnels_opened_total Total proxy tunnels opened.\n",
            "# TYPE ssl_proxy_tunnels_opened_total counter\n",
            "ssl_proxy_tunnels_opened_total {tunnels_opened}\n",
            "# HELP ssl_proxy_active_tunnels Active proxy tunnels.\n",
            "# TYPE ssl_proxy_active_tunnels gauge\n",
            "ssl_proxy_active_tunnels {active_tunnels}\n",
            "# HELP ssl_proxy_bytes_up_total Total upstream bytes observed.\n",
            "# TYPE ssl_proxy_bytes_up_total counter\n",
            "ssl_proxy_bytes_up_total {bytes_up}\n",
            "# HELP ssl_proxy_bytes_down_total Total downstream bytes observed.\n",
            "# TYPE ssl_proxy_bytes_down_total counter\n",
            "ssl_proxy_bytes_down_total {bytes_down}\n",
            "# HELP ssl_proxy_blocked_total Total blocked proxy decisions.\n",
            "# TYPE ssl_proxy_blocked_total counter\n",
            "ssl_proxy_blocked_total {blocked}\n",
            "# HELP ssl_proxy_allowed_total Total allowed proxy decisions.\n",
            "# TYPE ssl_proxy_allowed_total counter\n",
            "ssl_proxy_allowed_total {allowed}\n",
            "# HELP ssl_proxy_obfuscated_total Total obfuscated proxy flows.\n",
            "# TYPE ssl_proxy_obfuscated_total counter\n",
            "ssl_proxy_obfuscated_total {obfuscated}\n",
            "# HELP ssl_proxy_classifications_total Total proxy classifications by bounded category.\n",
            "# TYPE ssl_proxy_classifications_total counter\n",
            "ssl_proxy_classifications_total{{category=\"ads_tracker\"}} {class_ads_tracker}\n",
            "ssl_proxy_classifications_total{{category=\"analytics\"}} {class_analytics}\n",
            "ssl_proxy_classifications_total{{category=\"cdn\"}} {class_cdn}\n",
            "ssl_proxy_classifications_total{{category=\"essential_api\"}} {class_essential_api}\n",
            "ssl_proxy_classifications_total{{category=\"auth\"}} {class_auth}\n",
            "ssl_proxy_classifications_total{{category=\"unknown\"}} {class_unknown}\n",
            "# HELP ssl_proxy_host_stats_dropped_total Total dropped host-stat updates.\n",
            "# TYPE ssl_proxy_host_stats_dropped_total counter\n",
            "ssl_proxy_host_stats_dropped_total {host_stats_dropped}\n",
            "# HELP ssl_proxy_hosts_tracked Current tracked host count.\n",
            "# TYPE ssl_proxy_hosts_tracked gauge\n",
            "ssl_proxy_hosts_tracked {hosts_tracked}\n",
            "# HELP ssl_proxy_peers_tracked Current tracked peer count.\n",
            "# TYPE ssl_proxy_peers_tracked gauge\n",
            "ssl_proxy_peers_tracked {peers_tracked}\n",
            "# HELP ssl_proxy_dashboard_event_retry_queue_len Dashboard event retry queue length.\n",
            "# TYPE ssl_proxy_dashboard_event_retry_queue_len gauge\n",
            "ssl_proxy_dashboard_event_retry_queue_len {dashboard_queue}\n",
            "# HELP ssl_proxy_sync_publish_queue_depth Sync publisher queue depth.\n",
            "# TYPE ssl_proxy_sync_publish_queue_depth gauge\n",
            "ssl_proxy_sync_publish_queue_depth {sync_queue_depth}\n",
            "# HELP ssl_proxy_sync_publish_queue_capacity Sync publisher queue capacity.\n",
            "# TYPE ssl_proxy_sync_publish_queue_capacity gauge\n",
            "ssl_proxy_sync_publish_queue_capacity {sync_queue_capacity}\n",
            "# HELP ssl_proxy_sync_publish_spool_pending Sync publisher spool files pending.\n",
            "# TYPE ssl_proxy_sync_publish_spool_pending gauge\n",
            "ssl_proxy_sync_publish_spool_pending {sync_spool_pending}\n",
            "# HELP ssl_proxy_sync_publish_spooled_total Sync publishes spooled after transport pressure.\n",
            "# TYPE ssl_proxy_sync_publish_spooled_total counter\n",
            "ssl_proxy_sync_publish_spooled_total {sync_spooled_total}\n",
            "# HELP ssl_proxy_sync_publish_enqueue_timeouts_total Sync publisher enqueue timeouts.\n",
            "# TYPE ssl_proxy_sync_publish_enqueue_timeouts_total counter\n",
            "ssl_proxy_sync_publish_enqueue_timeouts_total {sync_enqueue_timeouts}\n",
            "# HELP ssl_proxy_wg_relay_active_sessions Active WireGuard relay sessions.\n",
            "# TYPE ssl_proxy_wg_relay_active_sessions gauge\n",
            "ssl_proxy_wg_relay_active_sessions {wg_relay_active_sessions}\n",
            "# HELP ssl_proxy_wg_relay_packets_forwarded_total WireGuard relay packets forwarded.\n",
            "# TYPE ssl_proxy_wg_relay_packets_forwarded_total counter\n",
            "ssl_proxy_wg_relay_packets_forwarded_total{{direction=\"client_to_server\"}} {wg_relay_packets_client_to_server}\n",
            "ssl_proxy_wg_relay_packets_forwarded_total{{direction=\"server_to_client\"}} {wg_relay_packets_server_to_client}\n",
            "# HELP ssl_proxy_wg_relay_decode_errors_total WireGuard relay packet decode errors.\n",
            "# TYPE ssl_proxy_wg_relay_decode_errors_total counter\n",
            "ssl_proxy_wg_relay_decode_errors_total {wg_relay_decode_errors}\n",
            "# HELP ssl_proxy_wg_relay_encode_errors_total WireGuard relay packet encode errors.\n",
            "# TYPE ssl_proxy_wg_relay_encode_errors_total counter\n",
            "ssl_proxy_wg_relay_encode_errors_total {wg_relay_encode_errors}\n",
            "# HELP ssl_proxy_wg_relay_replay_detected_total WireGuard relay replay-detected drops.\n",
            "# TYPE ssl_proxy_wg_relay_replay_detected_total counter\n",
            "ssl_proxy_wg_relay_replay_detected_total {wg_relay_replay_detected}\n",
            "# HELP ssl_proxy_wg_relay_sessions_evicted_total WireGuard relay sessions evicted.\n",
            "# TYPE ssl_proxy_wg_relay_sessions_evicted_total counter\n",
            "ssl_proxy_wg_relay_sessions_evicted_total{{reason=\"idle\"}} {wg_relay_sessions_evicted_idle}\n",
            "ssl_proxy_wg_relay_sessions_evicted_total{{reason=\"send_failure\"}} {wg_relay_sessions_evicted_send_failure}\n",
            "ssl_proxy_wg_relay_sessions_evicted_total{{reason=\"shutdown\"}} {wg_relay_sessions_closed_shutdown}\n",
        ),
        tunnels_opened = state.tunnels_opened.load(Ordering::Relaxed),
        active_tunnels = state.active_tunnels.load(Ordering::Relaxed),
        bytes_up = state.bytes_up.load(Ordering::Relaxed),
        bytes_down = state.bytes_down.load(Ordering::Relaxed),
        blocked = state.blocked_count.load(Ordering::Relaxed),
        allowed = state.allowed_count.load(Ordering::Relaxed),
        obfuscated = state.obfuscated_count.load(Ordering::Relaxed),
        class_ads_tracker = classifications[0],
        class_analytics = classifications[1],
        class_cdn = classifications[2],
        class_essential_api = classifications[3],
        class_auth = classifications[4],
        class_unknown = classifications[5],
        host_stats_dropped = state.host_stats_dropped.load(Ordering::Relaxed),
        hosts_tracked = state.host_stats.len(),
        peers_tracked = state.peer_counters.len(),
        dashboard_queue = state.dashboard_event_queue_len(),
        sync_queue_depth = publisher.queue_depth,
        sync_queue_capacity = publisher.queue_capacity,
        sync_spool_pending = publisher.spool_pending,
        sync_spooled_total = publisher.spooled_total,
        sync_enqueue_timeouts = publisher.enqueue_timeouts_total,
        wg_relay_active_sessions = wg_relay.active_sessions,
        wg_relay_packets_client_to_server = wg_relay.packets_client_to_server,
        wg_relay_packets_server_to_client = wg_relay.packets_server_to_client,
        wg_relay_decode_errors = wg_relay.decode_errors,
        wg_relay_encode_errors = wg_relay.encode_errors,
        wg_relay_replay_detected = wg_relay.replay_detected,
        wg_relay_sessions_evicted_idle = wg_relay.sessions_evicted_idle,
        wg_relay_sessions_evicted_send_failure = wg_relay.sessions_evicted_send_failure,
        wg_relay_sessions_closed_shutdown = wg_relay.sessions_closed_shutdown,
    )
}

/// GET /sync/status — local sync-plane publisher and topic accounting.
pub async fn sync_status(State(state): State<SharedState>) -> Json<SyncStatusReport> {
    let publisher = state.publisher.health_snapshot();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for message in state.publisher.published_messages() {
        *counts.entry(message.topic).or_default() += 1;
    }
    let status = if publisher.configured && publisher.last_error.is_some() {
        "degraded"
    } else {
        "ok"
    };
    Json(SyncStatusReport {
        status,
        last_error: publisher.last_error.clone(),
        publisher,
        published_topics: counts
            .into_iter()
            .map(|(topic, count)| SyncTopicCount { topic, count })
            .collect(),
    })
}

/// GET /security/patch-cadence — exposes the latest patch SLA posture report.
pub async fn patch_cadence_report(State(state): State<SharedState>) -> impl IntoResponse {
    let Some(path) = state.config.admin.patch_cadence_report_path.as_deref() else {
        return (
            StatusCode::NOT_FOUND,
            "PATCH_CADENCE_REPORT_PATH not configured",
        )
            .into_response();
    };

    match crate::security::load_patch_cadence_report(path) {
        Ok(report) => Json(report).into_response(),
        Err(e) => {
            warn!(%path, %e, "failed to load patch cadence report");
            (StatusCode::SERVICE_UNAVAILABLE, e).into_response()
        }
    }
}

/// GET /security/recovery-drills — exposes the latest recovery-drill evidence report.
pub async fn recovery_drill_report(State(state): State<SharedState>) -> impl IntoResponse {
    let Some(path) = state.config.admin.recovery_drill_report_path.as_deref() else {
        return (
            StatusCode::NOT_FOUND,
            "RECOVERY_DRILL_REPORT_PATH not configured",
        )
            .into_response();
    };

    match crate::security::load_recovery_drill_report(path) {
        Ok(report) => Json(report).into_response(),
        Err(e) => {
            warn!(%path, %e, "failed to load recovery drill report");
            (StatusCode::SERVICE_UNAVAILABLE, e).into_response()
        }
    }
}

fn to_snapshot(host: String, e: &crate::state::HostStats) -> HostSnapshot {
    HostSnapshot {
        host,
        blocked_attempts: e.blocked_attempts,
        blocked_bytes_approx: e.blocked_bytes_approx,
        frequency_hz: (e.frequency_hz() * 100.0).round() / 100.0,
        risk_score: e.risk_score().round(),
        verdict: e.verdict(),
        tarpit_held_ms: e.tarpit_held_ms,
        battery_saved_mwh: (e.battery_saved_approx() * 1_000_000.0).round() / 1_000_000.0,
        category: e.category,
        consecutive_blocks: e.consecutive_blocks,
        iat_ms: e.iat_ms,
        iat_ema_ms: e.iat_ema_ms,
        jitter_ema_ms: e.jitter_ema_ms,
        low_jitter_streak: e.low_jitter_streak,
        regularity_score: e
            .regularity_score()
            .map(|score| (score * 100.0).round() / 100.0),
        tls_ver: e.tls_ver.clone(),
        alpn: e.alpn.clone(),
        cipher_suites_count: e.cipher_suites_count,
        ja3_lite: e.ja3_lite.clone(),
        resolved_ip: e.resolved_ip.clone(),
        asn_org: e.asn_org.clone(),
        last_reason: e.last_reason.map(str::to_string),
    }
}

/// GET /hosts — returns a JSON array of all tracked hosts sorted by risk score.
pub async fn hosts_snapshot(State(state): State<SharedState>) -> Json<Vec<HostSnapshot>> {
    let mut rows: Vec<HostSnapshot> = state
        .host_stats
        .iter()
        .map(|e| to_snapshot(e.key().clone(), e.value()))
        .collect();
    rows.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Json(rows)
}

/// GET /hosts/{hostname} — single host detail or 404 (Epic 6.2).
pub async fn host_detail(
    State(state): State<SharedState>,
    Path(hostname): Path<String>,
) -> Result<Json<HostSnapshot>, StatusCode> {
    state
        .host_stats
        .get(&hostname)
        .map(|e| Json(to_snapshot(hostname.clone(), e.value())))
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Deserialize)]
pub struct DevicesQuery {
    #[serde(default)]
    pub wg_pubkey: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceUpsertRequest {
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub wg_pubkey: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub os_hint: Option<String>,
    #[serde(default)]
    pub mac_hint: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub regenerate_claim_token: Option<bool>,
}

/// Response payload returned by the device upsert endpoint.
///
/// `claim_token` is only generated for new devices or when
/// `regenerate_claim_token=true` is requested. For metadata-only updates,
/// `claim_token` is `None` and omitted from JSON.
#[derive(Serialize)]
pub struct DeviceUpsertResponse {
    pub device_id: String,
    /// Plaintext claim token for bootstrap/rotation flows.
    ///
    /// This is `Some(...)` only when a new token is minted; otherwise it is
    /// `None` and skipped during serialization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_token: Option<String>,
    pub device: crate::state::DeviceInfo,
}

#[derive(Serialize)]
pub struct ClaimResponse {
    pub device_id: String,
    pub wg_pubkey: String,
    pub peer_ip: String,
    pub claimed_at: String,
    pub expires_at: String,
}

#[derive(Serialize)]
pub struct PeerSummary {
    pub wg_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake_at: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub blocked_bytes_approx: u64,
    pub allowed_bytes: u64,
    pub blocked_count: u64,
    pub allowed_count: u64,
    pub sessions_active: u64,
}

#[derive(Deserialize)]
pub struct BandwidthQuery {
    #[serde(default = "default_window")]
    pub window: String,
}

#[derive(Serialize)]
pub struct BandwidthPoint {
    pub bucket: String,
    pub wg_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub bytes_up_delta: u64,
    pub bytes_down_delta: u64,
    pub blocked_bytes_delta: u64,
    pub allowed_bytes_delta: u64,
    pub blocked_count_delta: u64,
    pub allowed_count_delta: u64,
    pub sessions_active: u64,
    pub blocked_bytes_is_approx: bool,
}

#[derive(Deserialize)]
pub struct TopHostsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_metric")]
    pub metric: String,
}

pub async fn list_devices(
    State(state): State<SharedState>,
    Query(query): Query<DevicesQuery>,
) -> Json<Vec<crate::state::DeviceInfo>> {
    Json(state.list_devices(query.wg_pubkey.as_deref()))
}
