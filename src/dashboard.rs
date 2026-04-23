//! Admin API handlers for health, stats, hosts, and devices.
//!
//! This module serves health/readiness endpoints, host statistics snapshots, and
//! broadcast tasks for live stats. It does not proxy client traffic itself.

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
    pub publisher: crate::transport::SyncPublisherHealthSnapshot,
}

#[derive(Serialize)]
pub struct ReadyReport {
    pub status: &'static str,
    pub local: &'static str,
    pub sync: ReadySyncStatus,
}

#[derive(Serialize)]
pub struct SyncSubjectCount {
    pub subject: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct SyncStatusReport {
    pub status: &'static str,
    pub publisher: crate::transport::SyncPublisherHealthSnapshot,
    pub published_subjects: Vec<SyncSubjectCount>,
    pub last_error: Option<String>,
}

/// GET /health — liveness probe for the admin surface.
pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok").into_response()
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

/// GET /sync/status — local sync-plane publisher and subject accounting.
pub async fn sync_status(State(state): State<SharedState>) -> Json<SyncStatusReport> {
    let publisher = state.publisher.health_snapshot();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for message in state.publisher.published_messages() {
        *counts.entry(message.subject).or_default() += 1;
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
        published_subjects: counts
            .into_iter()
            .map(|(subject, count)| SyncSubjectCount { subject, count })
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

pub async fn get_device(
    State(state): State<SharedState>,
    Path(device_id): Path<String>,
) -> Result<Json<crate::state::DeviceInfo>, StatusCode> {
    state
        .get_device(&device_id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn upsert_device(
    State(state): State<SharedState>,
    Json(body): Json<DeviceUpsertRequest>,
) -> Result<Json<DeviceUpsertResponse>, StatusCode> {
    let now = chrono::Utc::now().to_rfc3339();
    let device_id = body
        .device_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let existing = state.get_device(&device_id);
    let regenerate_claim_token = existing.is_none() || body.regenerate_claim_token.unwrap_or(false);
    let claim_token = if regenerate_claim_token {
        Some(crate::identity::mint_device_token())
    } else {
        None
    };
    let claim_token_hash = claim_token
        .as_deref()
        .map(crate::identity::hash_device_token)
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|device| device.claim_token_hash.clone())
        });
    let first_seen = existing
        .as_ref()
        .map(|device| device.first_seen.clone())
        .unwrap_or_else(|| now.clone());
    let device = crate::state::DeviceInfo {
        device_id: device_id.clone(),
        wg_pubkey: body.wg_pubkey.or_else(|| {
            existing
                .as_ref()
                .and_then(|device| device.wg_pubkey.clone())
        }),
        claim_token_hash,
        display_name: body.display_name.or_else(|| {
            existing
                .as_ref()
                .and_then(|device| device.display_name.clone())
        }),
        username: body
            .username
            .or_else(|| existing.as_ref().and_then(|device| device.username.clone())),
        hostname: body
            .hostname
            .or_else(|| existing.as_ref().and_then(|device| device.hostname.clone())),
        os_hint: body
            .os_hint
            .or_else(|| existing.as_ref().and_then(|device| device.os_hint.clone())),
        mac_hint: body
            .mac_hint
            .or_else(|| existing.as_ref().and_then(|device| device.mac_hint.clone())),
        first_seen,
        last_seen: now,
        notes: body
            .notes
            .or_else(|| existing.as_ref().and_then(|device| device.notes.clone())),
    };
    state.upsert_device(device.clone());

    Ok(Json(DeviceUpsertResponse {
        device_id,
        claim_token,
        device,
    }))
}

pub async fn claim_device(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<ClaimResponse>, StatusCode> {
    let token = crate::identity::extract_device_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let hash = crate::identity::hash_device_token(&token);
    let device = state
        .find_device_by_claim_hash(&hash)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let peer_ip = addr.ip().to_string();
    let wg_pubkey = state
        .resolve_wg_pubkey(Some(&peer_ip))
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let peer_hostname = state
        .ptr_cache
        .get(&peer_ip)
        .and_then(|entry| entry.ptr_hostname.clone());
    let user_agent = crate::identity::extract_user_agent(&headers);
    let device = crate::identity::update_device_metadata(
        device,
        Some(&wg_pubkey),
        user_agent.as_deref(),
        peer_hostname.as_deref(),
    );
    state.upsert_device(device.clone());

    let claim = state
        .refresh_claim(&device.device_id, &wg_pubkey, &peer_ip)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ClaimResponse {
        device_id: claim.device_id,
        wg_pubkey: claim.wg_pubkey,
        peer_ip: claim.peer_ip,
        claimed_at: claim.claimed_at,
        expires_at: claim.expires_at,
    }))
}

pub async fn stats_peers(State(state): State<SharedState>) -> Json<Vec<PeerSummary>> {
    let wg_peers = state.wg_peers_snapshot();
    let mut peers: Vec<_> = wg_peers
        .inventory
        .values()
        .map(|peer| {
            let counters = state.peer_counters.get(&peer.wg_pubkey);
            let active_claim = peer
                .peer_ip
                .as_deref()
                .and_then(|ip| state.find_claim(Some(&peer.wg_pubkey), Some(ip)));
            let preferred_device = active_claim
                .as_ref()
                .and_then(|claim| state.get_device(&claim.device_id))
                .or_else(|| {
                    state
                        .list_devices(Some(&peer.wg_pubkey))
                        .into_iter()
                        .max_by(|a, b| a.last_seen.cmp(&b.last_seen))
                });

            PeerSummary {
                wg_pubkey: peer.wg_pubkey.clone(),
                peer_ip: peer.peer_ip.clone(),
                peer_hostname: peer
                    .peer_ip
                    .as_deref()
                    .and_then(|ip| state.ptr_cache.get(ip))
                    .and_then(|entry| entry.ptr_hostname.clone()),
                display_name: preferred_device
                    .as_ref()
                    .and_then(|device| device.display_name.clone()),
                username: preferred_device
                    .as_ref()
                    .and_then(|device| device.username.clone()),
                active_device_id: active_claim.map(|claim| claim.device_id),
                last_handshake_at: peer.last_handshake_at.clone(),
                bytes_up: counters
                    .as_ref()
                    .map(|value| value.bytes_up.load(Ordering::Relaxed))
                    .unwrap_or(0),
                bytes_down: counters
                    .as_ref()
                    .map(|value| value.bytes_down.load(Ordering::Relaxed))
                    .unwrap_or(0),
                blocked_bytes_approx: counters
                    .as_ref()
                    .map(|value| value.blocked_bytes_approx.load(Ordering::Relaxed))
                    .unwrap_or(0),
                allowed_bytes: counters
                    .as_ref()
                    .map(|value| value.allowed_bytes.load(Ordering::Relaxed))
                    .unwrap_or(0),
                blocked_count: counters
                    .as_ref()
                    .map(|value| value.blocked_count.load(Ordering::Relaxed))
                    .unwrap_or(0),
                allowed_count: counters
                    .as_ref()
                    .map(|value| value.allowed_count.load(Ordering::Relaxed))
                    .unwrap_or(0),
                sessions_active: counters
                    .as_ref()
                    .map(|value| value.sessions_open.load(Ordering::Relaxed))
                    .unwrap_or(0),
            }
        })
        .collect();
    peers.sort_by(|a, b| b.bytes_down.cmp(&a.bytes_down));
    Json(peers)
}

pub async fn stats_hosts_top(
    State(state): State<SharedState>,
    Query(query): Query<TopHostsQuery>,
) -> Json<Vec<HostSnapshot>> {
    let mut rows: Vec<_> = state
        .host_stats
        .iter()
        .map(|entry| to_snapshot(entry.key().clone(), entry.value()))
        .collect();
    match query.metric.as_str() {
        "blocks" => rows.sort_by(|a, b| b.blocked_attempts.cmp(&a.blocked_attempts)),
        _ => rows.sort_by(|a, b| b.blocked_bytes_approx.cmp(&a.blocked_bytes_approx)),
    }
    rows.truncate(query.limit.min(rows.len()));
    Json(rows)
}

pub async fn stats_bandwidth(
    State(state): State<SharedState>,
    Query(query): Query<BandwidthQuery>,
) -> Json<Vec<BandwidthPoint>> {
    let window = match query.window.as_str() {
        "1h" | "24h" | "7d" => query.window.as_str(),
        _ => "1h",
    };
    let wg_peers = state.wg_peers_snapshot();

    let now = chrono::Utc::now().to_rfc3339();
    let bucket = format!("{window}:{now}");
    Json(
        wg_peers
            .inventory
            .values()
            .map(|peer| {
                let (current, previous, sessions_active) =
                    state.snapshot_and_swap_bandwidth_cursor(&peer.wg_pubkey);
                let preferred_device = state
                    .list_devices(Some(&peer.wg_pubkey))
                    .into_iter()
                    .max_by(|a, b| a.last_seen.cmp(&b.last_seen));
                BandwidthPoint {
                    bucket: bucket.clone(),
                    wg_pubkey: peer.wg_pubkey.clone(),
                    device_id: preferred_device
                        .as_ref()
                        .map(|device| device.device_id.clone()),
                    display_name: preferred_device
                        .as_ref()
                        .and_then(|device| device.display_name.clone()),
                    username: preferred_device
                        .as_ref()
                        .and_then(|device| device.username.clone()),
                    bytes_up_delta: current.bytes_up.saturating_sub(previous.bytes_up),
                    bytes_down_delta: current.bytes_down.saturating_sub(previous.bytes_down),
                    blocked_bytes_delta: current
                        .blocked_bytes_approx
                        .saturating_sub(previous.blocked_bytes_approx),
                    allowed_bytes_delta: current
                        .allowed_bytes
                        .saturating_sub(previous.allowed_bytes),
                    blocked_count_delta: current
                        .blocked_count
                        .saturating_sub(previous.blocked_count),
                    allowed_count_delta: current
                        .allowed_count
                        .saturating_sub(previous.allowed_count),
                    sessions_active,
                    blocked_bytes_is_approx: true,
                }
            })
            .collect(),
    )
}

/// GET /stats/summary — aggregate overview (Epic 6.4).
#[derive(Serialize)]
pub struct StatsSummary {
    total_hosts: usize,
    tarpit_count: usize,
    top_category: Option<String>,
    highest_risk_host: Option<String>,
}

#[derive(Serialize)]
pub struct LiveStats {
    active_tunnels: u64,
    tunnels_opened: u64,
    #[serde(rename = "up_kBps")]
    up_k_bps: u64,
    #[serde(rename = "down_kBps")]
    down_k_bps: u64,
    bytes_up: u64,
    bytes_down: u64,
    blocked: u64,
    obfuscated: u64,
}

pub async fn stats_summary(State(state): State<SharedState>) -> Json<StatsSummary> {
    let mut cat_counts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    let mut tarpit_count = 0usize;
    let mut highest_risk: Option<(String, f64)> = None;
    for e in state.host_stats.iter() {
        let v = e.verdict();
        if v == "TARPIT" {
            tarpit_count += 1;
        }
        *cat_counts.entry(e.category).or_insert(0) += 1;
        let rs = e.risk_score();
        if highest_risk.as_ref().map(|(_, r)| rs > *r).unwrap_or(true) {
            highest_risk = Some((e.key().clone(), rs));
        }
    }
    let top_category = cat_counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(k, _)| k.to_string());
    Json(StatsSummary {
        total_hosts: state.host_stats.len(),
        tarpit_count,
        top_category,
        highest_risk_host: highest_risk.map(|(h, _)| h),
    })
}

pub async fn stats_live(State(state): State<SharedState>) -> Json<LiveStats> {
    let bytes_up = state.bytes_up.load(Ordering::Relaxed);
    let bytes_down = state.bytes_down.load(Ordering::Relaxed);

    let (up_k_bps, down_k_bps) = {
        let mut last_sample = state
            .last_sample_instant
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let elapsed = last_sample.elapsed().as_secs_f64();

        let last_up = state.last_bytes_up.swap(bytes_up, Ordering::Relaxed);
        let last_down = state.last_bytes_down.swap(bytes_down, Ordering::Relaxed);

        *last_sample = Instant::now();

        if !(0.001..=300.0).contains(&elapsed) {
            // First sample or stale, return 0, next poll will have valid rate
            (0, 0)
        } else {
            let delta_up = bytes_up.saturating_sub(last_up) as f64;
            let delta_down = bytes_down.saturating_sub(last_down) as f64;

            // Convert bytes -> KB/s: bytes / seconds / 1024
            let up_rate = (delta_up / elapsed / 1024.0).round() as u64;
            let down_rate = (delta_down / elapsed / 1024.0).round() as u64;

            (up_rate, down_rate)
        }
    };

    Json(LiveStats {
        active_tunnels: state.active_tunnels.load(Ordering::Relaxed),
        tunnels_opened: state.tunnels_opened.load(Ordering::Relaxed),
        up_k_bps,
        down_k_bps,
        bytes_up,
        bytes_down,
        blocked: state.blocked_count.load(Ordering::Relaxed),
        obfuscated: state.obfuscated_count.load(Ordering::Relaxed),
    })
}

fn default_window() -> String {
    "1h".to_string()
}

fn default_limit() -> usize {
    20
}

fn default_metric() -> String {
    "bytes".to_string()
}

/// Spawns a background task that evicts stale host statistics every five minutes.
///
/// # Examples
///
/// ```no_run
/// use tokio_util::sync::CancellationToken;
/// // `state` should be a `SharedState` instance from your application.
/// let token = CancellationToken::new();
/// spawn_host_eviction_task(state, token.clone());
/// // later, to stop the task:
/// token.cancel();
/// ```
pub fn spawn_host_eviction_task(state: SharedState, token: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        info!("host eviction task started");
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("host eviction task shutting down");
                    return;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(300)) => {
                    state.evict_stale_hosts(600);
                    state.evict_stale_dns_entries(3600);
                    state.evict_expired_claims();
                }
            }
        }
    });
}
