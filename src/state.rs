//! Shared application state used by proxy, tunnel, polling, and dashboard handlers.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use tracing::warn;

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
    ((previous * (weight - 1)) + current) / weight
}

/// Process-wide application state shared by all handlers and background tasks.
pub struct AppState {
    pub client: crate::proxy::ProxyClient,
    pub resolver: hickory_resolver::TokioAsyncResolver,
    pub stats_tx: broadcast::Sender<String>,
    pub events_tx: broadcast::Sender<String>,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub active_tunnels: AtomicU64,
    pub tunnels_opened: AtomicU64,
    pub blocked_count: AtomicU64,
    pub allowed_count: AtomicU64,
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
    pub publisher: std::sync::Arc<crate::transport::SyncPublisher>,
    pub forensic: crate::forensic::SharedForensicState,
    pub config: crate::config::Config,

    /// Bandwidth rate calculation snapshot
    pub last_bytes_up: AtomicU64,
    pub last_bytes_down: AtomicU64,
    pub last_sample_instant: Mutex<Instant>,
}

impl AppState {
    pub fn new(
        client: crate::proxy::ProxyClient,
        resolver: hickory_resolver::TokioAsyncResolver,
        stats_tx: broadcast::Sender<String>,
        events_tx: broadcast::Sender<String>,
        config: crate::config::Config,
    ) -> SharedState {
        let seed = SEED.iter().map(|s| s.to_string()).collect();
        let state = Arc::new(Self {
            client,
            resolver,
            stats_tx,
            events_tx,
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            active_tunnels: AtomicU64::new(0),
            tunnels_opened: AtomicU64::new(0),
            blocked_count: AtomicU64::new(0),
            allowed_count: AtomicU64::new(0),
            obfuscated_count: AtomicU64::new(0),
            host_stats_dropped: AtomicU64::new(0),
            blocklist: ArcSwap::from_pointee(seed),
            host_stats: DashMap::new(),
            peer_counters: DashMap::new(),
            bandwidth_cursors: DashMap::new(),
            bandwidth_cursor_snapshot_lock: Mutex::new(()),
            wg_peers: ArcSwap::from_pointee(WgPeersSnapshot::default()),
            devices: DashMap::new(),
            claim_tokens: DashMap::new(),
            device_claims: DashMap::new(),
            tarpit_sem: crate::tunnel::tarpit_semaphore(config.proxy.tarpit_max_connections),
            dns_cache: DashMap::new(),
            dns_negative_cache: DashMap::new(),
            ptr_cache: DashMap::new(),
            publisher: std::sync::Arc::new(crate::transport::SyncPublisher::new(&config.sync)),
            forensic: crate::forensic::ForensicState::new(config.proxy.forensic_sentry_enabled),
            config,

            last_bytes_up: AtomicU64::new(0),
            last_bytes_down: AtomicU64::new(0),
            last_sample_instant: Mutex::new(Instant::now()),
        });

        state
    }

    #[allow(dead_code)]
    pub fn record_tunnel_open(&self) {
        self.record_tunnel_open_for_peer(None);
    }

    pub fn record_tunnel_open_for_peer(&self, wg_pubkey: Option<&str>) {
        self.active_tunnels.fetch_add(1, Ordering::Relaxed);
        self.tunnels_opened.fetch_add(1, Ordering::Relaxed);
        if let Some(key) = wg_pubkey {
            let counters = self.peer_counters.entry(key.to_string()).or_default();
            counters.sessions_open.fetch_add(1, Ordering::Relaxed);
            counters.touch();
        }
    }

    pub fn snapshot_and_swap_bandwidth_cursor(
        &self,
        wg_pubkey: &str,
    ) -> (BandwidthCursor, BandwidthCursor, u64) {
        let _guard = self
            .bandwidth_cursor_snapshot_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let (current, sessions_active) = self
            .peer_counters
            .get(wg_pubkey)
            .map(|value| {
                (
                    BandwidthCursor {
                        bytes_up: value.bytes_up.load(Ordering::Relaxed),
                        bytes_down: value.bytes_down.load(Ordering::Relaxed),
                        blocked_bytes_approx: value.blocked_bytes_approx.load(Ordering::Relaxed),
                        allowed_bytes: value.allowed_bytes.load(Ordering::Relaxed),
                        blocked_count: value.blocked_count.load(Ordering::Relaxed),
                        allowed_count: value.allowed_count.load(Ordering::Relaxed),
                    },
                    value.sessions_open.load(Ordering::Relaxed),
                )
            })
            .unwrap_or_default();
        let previous = self
            .bandwidth_cursors
            .insert(wg_pubkey.to_string(), current)
            .unwrap_or_default();
        (current, previous, sessions_active)
    }

    #[allow(dead_code)]
    pub fn record_tunnel_close(&self, up: u64, down: u64) {
        self.record_tunnel_close_for_peer(None, up, down);
    }

    pub fn record_tunnel_close_for_peer(&self, wg_pubkey: Option<&str>, up: u64, down: u64) {
        self.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.bytes_down.fetch_add(down, Ordering::Relaxed);
        self.active_tunnels
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();

        if let Some(counters) = wg_pubkey.and_then(|key| self.peer_counters.get(key)) {
            counters.bytes_up.fetch_add(up, Ordering::Relaxed);
            counters.bytes_down.fetch_add(down, Ordering::Relaxed);
            counters
                .allowed_bytes
                .fetch_add(up + down, Ordering::Relaxed);
            counters.allowed_count.fetch_add(1, Ordering::Relaxed);
            counters
                .sessions_open
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                })
                .ok();
            counters.touch();
        }
    }

    pub fn record_blocked(&self) {
        self.blocked_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_allowed(&self) {
        self.allowed_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_peer_block(&self, wg_pubkey: Option<&str>, approx_bytes: u64) {
        if let Some(key) = wg_pubkey {
            let counters = self.peer_counters.entry(key.to_string()).or_default();
            counters
                .blocked_bytes_approx
                .fetch_add(approx_bytes, Ordering::Relaxed);
            counters.blocked_count.fetch_add(1, Ordering::Relaxed);
            counters.touch();
        }
    }

    pub fn record_host_block(
        &self,
        host: &str,
        connect_header_bytes: u64,
        category: &'static str,
    ) -> Option<(&'static str, &'static str)> {
        const MAX_TRACKED_HOSTS: usize = 100_000;
        let now = Instant::now();
        if let Some(mut s) = self.host_stats.get_mut(host) {
            let iat = now.duration_since(s.last_seen).as_millis() as u64;
            s.observe_iat(iat);
            s.blocked_attempts += 1;
            s.blocked_bytes_approx += connect_header_bytes;
            s.last_seen = now;
            s.category = category;
            s.consecutive_blocks = s.consecutive_blocks.saturating_add(1);
            let prev = s.last_verdict;
            let next = s.verdict();
            if prev != next {
                s.last_verdict = next;
                return Some((prev, next));
            }
            None
        } else if self.host_stats.len() < MAX_TRACKED_HOSTS {
            self.host_stats
                .entry(host.to_string())
                .or_insert_with(|| HostStats::new(connect_header_bytes, category));
            None
        } else {
            warn!(%host, count = self.host_stats.len(), "MAX_TRACKED_HOSTS limit reached, dropping host statistics");
            self.host_stats_dropped.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub fn record_host_allow(&self, host: &str) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.consecutive_blocks = 0;
            s.low_jitter_streak = 0;
        }
    }

    pub fn record_host_reason(&self, host: &str, reason: &'static str) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.last_reason = Some(reason);
        }
    }

    pub fn record_tls_fingerprint(
        &self,
        host: &str,
        tls_ver: Option<String>,
        alpn: Option<String>,
        cipher_suites_count: Option<u8>,
        ja3_lite: Option<String>,
    ) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.tls_ver = tls_ver;
            s.alpn = alpn;
            s.cipher_suites_count = cipher_suites_count;
            s.ja3_lite = ja3_lite;
        }
    }

    pub fn record_resolved(&self, host: &str, resolved_ips: Vec<String>, asn_org: Option<String>) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.resolved_ip = resolved_ips.first().cloned();
            s.asn_org = asn_org.clone();
        }
        self.dns_cache.insert(
            host.to_string(),
            ResolvedMeta {
                resolved_at: Instant::now(),
                resolved_ips,
                ptr_hostname: None,
                asn_org,
            },
        );
    }

    pub fn record_peer_hostname(&self, peer_ip: &str, hostname: Option<String>) {
        self.ptr_cache.insert(
            peer_ip.to_string(),
            ResolvedMeta {
                resolved_at: Instant::now(),
                resolved_ips: vec![peer_ip.to_string()],
                ptr_hostname: hostname,
                asn_org: None,
            },
        );
    }

    pub fn record_tarpit_held(&self, host: &str, held_ms: u64) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.tarpit_held_ms = s.tarpit_held_ms.saturating_add(held_ms);
        }
    }

    pub fn evict_stale_hosts(&self, ttl_secs: u64) {
        self.host_stats
            .retain(|_, v| v.last_seen.elapsed().as_secs() < ttl_secs);
    }

    pub fn evict_stale_dns_entries(&self, ttl_secs: u64) {
        self.dns_cache
            .retain(|_, v| v.resolved_at.elapsed().as_secs() < ttl_secs);
        self.ptr_cache
            .retain(|_, v| v.resolved_at.elapsed().as_secs() < ttl_secs);
        self.dns_negative_cache
            .retain(|_, v| v.elapsed().as_secs() < ttl_secs);
    }

    pub fn evict_expired_claims(&self) {
        self.device_claims.retain(|_, claim| claim.active());
    }

    pub fn upsert_device(&self, device: DeviceInfo) {
        if let Some(hash) = device.claim_token_hash.as_ref() {
            self.claim_tokens
                .insert(hash.clone(), device.device_id.clone());
        }
        self.devices.insert(device.device_id.clone(), device);
    }

    pub fn find_device_by_claim_hash(&self, claim_token_hash: &str) -> Option<DeviceInfo> {
        let device_id = self.claim_tokens.get(claim_token_hash)?.clone();
        self.devices.get(&device_id).map(|entry| entry.clone())
    }

    pub fn list_devices(&self, wg_pubkey: Option<&str>) -> Vec<DeviceInfo> {
        let mut devices: Vec<_> = self
            .devices
            .iter()
            .filter(|entry| {
                wg_pubkey
                    .map(|key| entry.wg_pubkey.as_deref() == Some(key))
                    .unwrap_or(true)
            })
            .map(|entry| entry.clone())
            .collect();
        devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        devices
    }

    pub fn get_device(&self, device_id: &str) -> Option<DeviceInfo> {
        self.devices.get(device_id).map(|entry| entry.clone())
    }

    pub fn wg_peers_snapshot(&self) -> Arc<WgPeersSnapshot> {
        self.wg_peers.load_full()
    }

    pub fn resolve_wg_pubkey(&self, peer_ip: Option<&str>) -> Option<String> {
        let peer_ip = peer_ip?;
        let wg_peers = self.wg_peers_snapshot();
        wg_peers.pubkey_by_ip.get(peer_ip).cloned()
    }

    pub fn refresh_claim(
        &self,
        device_id: &str,
        wg_pubkey: &str,
        peer_ip: &str,
    ) -> Option<DeviceClaim> {
        let ttl = Duration::from_secs(self.config.runtime.device_claim_ttl_secs);
        let now = chrono::Utc::now();
        let claim = DeviceClaim {
            device_id: device_id.to_string(),
            wg_pubkey: wg_pubkey.to_string(),
            peer_ip: peer_ip.to_string(),
            claimed_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::seconds(ttl.as_secs() as i64)).to_rfc3339(),
            expires_instant: Instant::now() + ttl,
        };
        self.device_claims
            .insert(format!("{wg_pubkey}|{peer_ip}"), claim.clone());
        Some(claim)
    }

    pub fn find_claim(
        &self,
        wg_pubkey: Option<&str>,
        peer_ip: Option<&str>,
    ) -> Option<DeviceClaim> {
        let key = format!("{}|{}", wg_pubkey?, peer_ip?);
        let claim = self.device_claims.get(&key)?;
        if claim.active() {
            Some(claim.clone())
        } else {
            drop(claim);
            self.device_claims.remove(&key);
            None
        }
    }

    pub fn refresh_wg_peers(&self, peers: &[WgPeerSnapshot]) {
        let mut inventory = HashMap::with_capacity(peers.len());
        let mut pubkey_by_ip = HashMap::new();

        for peer in peers {
            if let Some(ip) = peer.peer_ip.as_ref() {
                pubkey_by_ip.insert(ip.clone(), peer.wg_pubkey.clone());
            }
            for allowed_ip in &peer.allowed_ips {
                if let Some((ip, _mask)) = allowed_ip.split_once('/') {
                    pubkey_by_ip.insert(ip.to_string(), peer.wg_pubkey.clone());
                }
            }
            inventory.insert(peer.wg_pubkey.clone(), peer.clone());

            let counters = self
                .peer_counters
                .entry(peer.wg_pubkey.clone())
                .or_default();
            counters
                .wg_rx_bytes
                .store(peer.rx_bytes_total, Ordering::Relaxed);
            counters
                .wg_tx_bytes
                .store(peer.tx_bytes_total, Ordering::Relaxed);
            counters.touch();
        }

        self.wg_peers.store(Arc::new(WgPeersSnapshot {
            inventory,
            pubkey_by_ip,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::TokioAsyncResolver;
    use tokio::sync::broadcast;

    async fn create_test_state() -> SharedState {
        let (stats_tx, _) = broadcast::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        AppState::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new()),
            resolver,
            stats_tx,
            events_tx,
            crate::config::Config::for_tests(),
        )
    }

    #[tokio::test]
    async fn host_stats_transition_to_tarpit() {
        let state = create_test_state().await;
        let host = "test.analytics.host";

        assert!(state.record_host_block(host, 100, "analytics").is_none());

        {
            let mut stats = state.host_stats.get_mut(host).unwrap();
            stats.blocked_attempts = 100;
            stats.first_seen = Instant::now() - Duration::from_secs(10);
            stats.last_seen = Instant::now() - Duration::from_millis(100);
            stats.iat_ema_ms = Some(100);
            stats.jitter_ema_ms = Some(5);
            stats.low_jitter_streak = 3;
        }

        let verdict_change = state.record_host_block(host, 100, "analytics");
        assert_eq!(verdict_change, Some(("BLOCKED", "TARPIT")));
    }

    #[tokio::test]
    async fn low_jitter_state_accumulates_for_regular_blocking() {
        let state = create_test_state().await;
        let host = "regular.analytics.host";

        assert!(state.record_host_block(host, 100, "analytics").is_none());
        {
            let mut stats = state.host_stats.get_mut(host).unwrap();
            stats.last_seen = Instant::now() - Duration::from_millis(100);
        }
        let _ = state.record_host_block(host, 100, "analytics");
        {
            let mut stats = state.host_stats.get_mut(host).unwrap();
            stats.last_seen = Instant::now() - Duration::from_millis(100);
        }
        let _ = state.record_host_block(host, 100, "analytics");

        let stats = state.host_stats.get(host).unwrap();
        assert!(stats.iat_ema_ms.is_some());
        assert!(stats.jitter_ema_ms.is_some());
        assert!(stats.low_jitter_streak >= 1);
    }

    #[tokio::test]
    async fn stale_hosts_are_evicted() {
        let state = create_test_state().await;
        state.record_host_block("active.host", 100, "test");
        state.record_host_block("stale.host", 100, "test");
        {
            let mut stats = state.host_stats.get_mut("stale.host").unwrap();
            stats.last_seen = Instant::now() - Duration::from_secs(3600);
        }

        state.evict_stale_hosts(600);
        assert!(state.host_stats.contains_key("active.host"));
        assert!(!state.host_stats.contains_key("stale.host"));
    }

    #[tokio::test]
    async fn claim_lookup_expires() {
        let state = create_test_state().await;
        let device = DeviceInfo {
            device_id: "device-1".to_string(),
            wg_pubkey: Some("pubkey-1".to_string()),
            claim_token_hash: Some("hash".to_string()),
            display_name: Some("Test Device".to_string()),
            username: None,
            hostname: None,
            os_hint: None,
            mac_hint: None,
            first_seen: chrono::Utc::now().to_rfc3339(),
            last_seen: chrono::Utc::now().to_rfc3339(),
            notes: None,
        };
        state.upsert_device(device);
        let claim = state
            .refresh_claim("device-1", "pubkey-1", "10.0.0.2")
            .unwrap();
        assert!(claim.active());
        assert!(state
            .find_claim(Some("pubkey-1"), Some("10.0.0.2"))
            .is_some());

        state.device_claims.insert(
            "pubkey-1|10.0.0.2".to_string(),
            DeviceClaim {
                expires_instant: Instant::now() - Duration::from_secs(1),
                ..claim
            },
        );
        assert!(state
            .find_claim(Some("pubkey-1"), Some("10.0.0.2"))
            .is_none());
    }

    #[tokio::test]
    async fn peer_counters_are_created_and_updated_atomically() {
        let state = create_test_state().await;

        state.record_tunnel_open_for_peer(Some("pubkey-1"));
        state.record_peer_block(Some("pubkey-1"), 512);

        let counters = state.peer_counters.get("pubkey-1").unwrap();
        assert_eq!(counters.sessions_open.load(Ordering::Relaxed), 1);
        assert_eq!(counters.blocked_count.load(Ordering::Relaxed), 1);
        assert_eq!(counters.blocked_bytes_approx.load(Ordering::Relaxed), 512);
    }

    #[tokio::test]
    async fn refresh_wg_peers_replaces_snapshot_consistently() {
        let state = create_test_state().await;
        let first = WgPeerSnapshot {
            interface: "wg0".to_string(),
            wg_pubkey: "pubkey-1".to_string(),
            peer_ip: Some("10.0.0.2".to_string()),
            allowed_ips: vec!["10.0.0.2/32".to_string()],
            rx_bytes_total: 100,
            tx_bytes_total: 200,
            ..WgPeerSnapshot::default()
        };
        let second = WgPeerSnapshot {
            interface: "wg0".to_string(),
            wg_pubkey: "pubkey-2".to_string(),
            peer_ip: Some("10.0.0.3".to_string()),
            allowed_ips: vec!["10.0.0.3/32".to_string()],
            rx_bytes_total: 300,
            tx_bytes_total: 400,
            ..WgPeerSnapshot::default()
        };

        state.refresh_wg_peers(&[first.clone()]);
        assert_eq!(
            state.resolve_wg_pubkey(Some("10.0.0.2")),
            Some("pubkey-1".to_string())
        );
        assert!(state.wg_peers_snapshot().inventory.contains_key("pubkey-1"));

        state.refresh_wg_peers(&[second.clone()]);
        let snapshot = state.wg_peers_snapshot();
        assert_eq!(snapshot.inventory.len(), 1);
        assert!(snapshot.inventory.contains_key("pubkey-2"));
        assert!(!snapshot.inventory.contains_key("pubkey-1"));
        assert_eq!(
            snapshot.pubkey_by_ip.get("10.0.0.3").map(String::as_str),
            Some("pubkey-2")
        );
        assert!(snapshot.pubkey_by_ip.get("10.0.0.2").is_none());
    }

    #[tokio::test]
    async fn record_resolved_preserves_all_cached_ips() {
        let state = create_test_state().await;
        state.record_host_block("example.com", 42, "test");
        state.record_resolved(
            "example.com",
            vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()],
            Some("Example ASN".to_string()),
        );

        let cached = state.dns_cache.get("example.com").unwrap();
        assert_eq!(
            cached.resolved_ips,
            vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()]
        );
        drop(cached);

        let host = state.host_stats.get("example.com").unwrap();
        assert_eq!(host.resolved_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(host.asn_org.as_deref(), Some("Example ASN"));
    }
}
