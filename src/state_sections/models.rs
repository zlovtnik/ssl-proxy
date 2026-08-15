use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::blocklist::SEED;

/// Shared application state handle passed through Axum and background tasks.
pub type SharedState = Arc<AppState>;

/// Metadata cached from a DNS resolution or reverse lookup.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ResolvedMeta {
    pub resolved_at: Instant,
    pub resolved_ips: Vec<String>,
    pub ptr_hostname: Option<String>,
    pub asn_org: Option<String>,
}

impl Default for ResolvedMeta {
    fn default() -> Self {
        Self {
            resolved_at: Instant::now(),
            resolved_ips: Vec::new(),
            ptr_hostname: None,
            asn_org: None,
        }
    }
}

impl ResolvedMeta {
    pub fn fresh(&self, ttl_secs: u64) -> bool {
        self.resolved_at.elapsed().as_secs() < ttl_secs
    }
}

/// Snapshot of one WireGuard peer from `wg show <iface> dump`.
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct WgPeerSnapshot {
    pub interface: String,
    pub wg_pubkey: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub peer_ip: Option<String>,
    pub last_handshake_at: Option<String>,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
}

/// Stable device metadata held in memory and optionally mirrored to Oracle.
#[derive(Clone, Debug, Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_token_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_hint: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Active short-lived claim binding a device to the current peer.
#[derive(Clone, Debug, Serialize)]
pub struct DeviceClaim {
    pub device_id: String,
    pub wg_pubkey: String,
    pub peer_ip: String,
    pub claimed_at: String,
    pub expires_at: String,
    #[serde(skip_serializing)]
    pub expires_instant: Instant,
}

impl DeviceClaim {
    pub fn active(&self) -> bool {
        Instant::now() < self.expires_instant
    }
}

/// Per-peer counters kept in RAM and flushed into minute buckets.
pub struct PeerCounters {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub blocked_bytes_approx: AtomicU64,
    pub allowed_bytes: AtomicU64,
    pub blocked_count: AtomicU64,
    pub allowed_count: AtomicU64,
    pub sessions_open: AtomicU64,
    pub wg_rx_bytes: AtomicU64,
    pub wg_tx_bytes: AtomicU64,
    pub last_seen: Mutex<Instant>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BandwidthCursor {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub blocked_bytes_approx: u64,
    pub allowed_bytes: u64,
    pub blocked_count: u64,
    pub allowed_count: u64,
}

#[derive(Clone, Debug, Default)]
pub struct WgPeersSnapshot {
    pub inventory: HashMap<String, WgPeerSnapshot>,
    pub pubkey_by_ip: HashMap<String, String>,
}

const DASHBOARD_EVENT_QUEUE_CAPACITY: usize = 1024;
pub(crate) const DASHBOARD_EVENT_MAX_RETRY_ATTEMPTS: u8 = 3;
pub(crate) const EVENT_DEDUP_WINDOW: Duration = Duration::from_millis(500);
const EVENT_DEDUP_MAX_KEYS: usize = 4096;

struct DashboardEventRetry {
    raw: String,
    event_name: String,
    host: String,
    attempt_count: u8,
}

impl Default for PeerCounters {
    fn default() -> Self {
        Self {
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            blocked_bytes_approx: AtomicU64::new(0),
            allowed_bytes: AtomicU64::new(0),
            blocked_count: AtomicU64::new(0),
            allowed_count: AtomicU64::new(0),
            sessions_open: AtomicU64::new(0),
            wg_rx_bytes: AtomicU64::new(0),
            wg_tx_bytes: AtomicU64::new(0),
            last_seen: Mutex::new(Instant::now()),
        }
    }
}

impl PeerCounters {
    fn touch(&self) {
        if let Ok(mut last_seen) = self.last_seen.lock() {
            *last_seen = Instant::now();
        }
    }
}

/// Per-host heuristic counters — kept in RAM only.
pub struct HostStats {
    pub blocked_attempts: u64,
    pub blocked_bytes_approx: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub tarpit_held_ms: u64,
    pub category: &'static str,
    pub iat_ms: Option<u64>,
    pub iat_ema_ms: Option<u64>,
    pub jitter_ema_ms: Option<u64>,
    pub low_jitter_streak: u32,
    pub last_verdict: &'static str,
    pub consecutive_blocks: u32,
    pub tls_ver: Option<String>,
    pub alpn: Option<String>,
    pub cipher_suites_count: Option<u8>,
    pub ja3_lite: Option<String>,
    pub resolved_ip: Option<String>,
    pub asn_org: Option<String>,
    pub last_reason: Option<&'static str>,
}

impl HostStats {
    fn new(bytes: u64, category: &'static str) -> Self {
        let now = Instant::now();
        Self {
            blocked_attempts: 1,
            blocked_bytes_approx: bytes,
            first_seen: now,
            last_seen: now,
            tarpit_held_ms: 0,
            category,
            iat_ms: None,
            iat_ema_ms: None,
            jitter_ema_ms: None,
            low_jitter_streak: 0,
            last_verdict: "BLOCKED",
            consecutive_blocks: 1,
            tls_ver: None,
            alpn: None,
            cipher_suites_count: None,
            ja3_lite: None,
            resolved_ip: None,
            asn_org: None,
            last_reason: None,
        }
    }

    pub fn frequency_hz(&self) -> f64 {
        let secs = self.first_seen.elapsed().as_secs_f64();
        if secs < 0.001 {
            return 0.0;
        }
        self.blocked_attempts as f64 / secs
    }

    pub fn risk_score(&self) -> f64 {
        self.blocked_bytes_approx as f64 * self.frequency_hz()
    }

    pub fn regularity_score(&self) -> Option<f64> {
        let iat = self.iat_ema_ms?;
        if iat == 0 {
            return None;
        }
        let jitter = self.jitter_ema_ms.unwrap_or(iat);
        Some(1.0 - (jitter.min(iat) as f64 / iat as f64))
    }

    pub fn verdict(&self) -> &'static str {
        let hz = self.frequency_hz();
        let regularity = self.regularity_score().unwrap_or(0.0);
        let sustained_low_jitter = self.low_jitter_streak >= 3 && regularity >= 0.80;
        if hz > 8.0 && self.category == "analytics" && sustained_low_jitter {
            return "TARPIT";
        }
        if hz > 12.0 && sustained_low_jitter {
            return "HEURISTIC_FLAG_DATA_EXFIL";
        }
        if hz > 1.0 {
            return "AGGRESSIVE_POLLING";
        }
        if self.risk_score() > 100_000.0 {
            return "HEURISTIC_FLAG_DATA_EXFIL";
        }
        if self.blocked_attempts > 10 {
            return "PERSISTENT_RECONNECT";
        }
        "BLOCKED"
    }

    pub fn battery_saved_approx(&self) -> f64 {
        let held_secs = self.tarpit_held_ms as f64 / 1000.0;
        0.5 * held_secs / 3600.0
    }

    fn observe_iat(&mut self, iat_ms: u64) {
        self.iat_ms = Some(iat_ms);
        self.iat_ema_ms = Some(match self.iat_ema_ms {
            Some(previous) => weighted_ema(previous, iat_ms, 4),
            None => iat_ms,
        });
        let baseline = self.iat_ema_ms.unwrap_or(iat_ms);
        let delta = baseline.abs_diff(iat_ms);
        self.jitter_ema_ms = Some(match self.jitter_ema_ms {
            Some(previous) => weighted_ema(previous, delta, 4),
            None => delta,
        });
        let low_jitter_cutoff = (baseline / 5).max(5);
        if delta <= low_jitter_cutoff {
            self.low_jitter_streak = self.low_jitter_streak.saturating_add(1);
        } else {
            self.low_jitter_streak = 0;
        }
    }
}

fn weighted_ema(previous: u64, current: u64, weight: u64) -> u64 {
    if weight <= 1 {
        return current;
    }
    previous.saturating_mul(weight - 1).saturating_add(current) / weight
}

/// Process-wide application state shared by all handlers and background tasks.
pub struct AppState {
    pub client: crate::proxy::ProxyClient,
    pub resolver: hickory_resolver::TokioAsyncResolver,
    pub stats_tx: broadcast::Sender<String>,
    pub events_tx: broadcast::Sender<String>,
    dashboard_event_queue: Mutex<VecDeque<DashboardEventRetry>>,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub active_tunnels: AtomicU64,
    pub tunnels_opened: AtomicU64,
    pub blocked_count: AtomicU64,
    pub allowed_count: AtomicU64,
    pub classification_counts: [AtomicU64; 6],
    pub obfuscated_count: AtomicU64,
    pub host_stats_dropped: AtomicU64,
    pub blocklist: ArcSwap<HashSet<String>>,
    pub host_stats: DashMap<String, HostStats>,
    pub peer_counters: DashMap<String, PeerCounters>,
    pub bandwidth_cursors: DashMap<String, BandwidthCursor>,
    bandwidth_cursor_snapshot_lock: Mutex<()>,
    wg_peers: ArcSwap<WgPeersSnapshot>,
    pub devices: DashMap<String, DeviceInfo>,
    pub claim_tokens: DashMap<String, String>,
    pub device_claims: DashMap<String, DeviceClaim>,
    pub tarpit_sem: std::sync::Arc<tokio::sync::Semaphore>,
    pub dns_cache: DashMap<String, ResolvedMeta>,
    pub dns_negative_cache: DashMap<String, Instant>,
    pub ptr_cache: DashMap<String, ResolvedMeta>,
    pub publisher: std::sync::Arc<sync_plane::SyncPublisher>,
    pub forensic: crate::forensic::SharedForensicState,
    pub wg_relay_metrics: Arc<crate::wg_relay::RelayMetrics>,
    event_dedup: DashMap<String, Instant>,
    pub config: crate::config::Config,

    /// Bandwidth rate calculation snapshot
    pub last_bytes_up: AtomicU64,
    pub last_bytes_down: AtomicU64,
    pub last_sample_instant: Mutex<Instant>,
}
