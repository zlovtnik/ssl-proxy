use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use thiserror::Error;
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{info, info_span, warn, Span};

use crate::{
    udp_tuning::DEFAULT_UDP_SOCKET_BUFFER_BYTES,
    wg_packet_obfuscation::{
        cleanup_interval, decode_packet_in_place, encode_packet_in_place, PacketDecodeError,
        PacketDirection, PacketEncodeError, PacketEncodeState, ReplayWindow, WgPacketObfuscation,
        MAX_UDP_PACKET_SIZE,
    },
};

pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:51821";
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_BUFFER_POOL_CAPACITY: usize = 256;
pub const DEFAULT_SEND_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_MAX_DATAGRAM_BYTES: usize = 1500;
pub const DEFAULT_HEALTH_ADDR: &str = "127.0.0.1:51822";
pub const DEFAULT_JITTER_MAX_MS: u64 = 0;
pub const DEFAULT_CHAFF_PPS: u64 = 0;
pub const MAX_CHAFF_PPS: u64 = 1_000_000;
const SEND_QUEUE_HEALTH_DEGRADED_UTILIZATION_PERCENT: u64 = 80;
const SEND_QUEUE_FULL_LOG_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub packets_per_sec: u64,
    pub burst_packets: u64,
}

impl RateLimitConfig {
    pub fn new(packets_per_sec: u64, burst_packets: u64) -> Option<Self> {
        (packets_per_sec > 0 && burst_packets > 0).then_some(Self {
            packets_per_sec,
            burst_packets,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgObfsShimConfig {
    pub listen_addr: SocketAddr,
    pub server_addrs: Vec<SocketAddr>,
    pub obfuscation: WgPacketObfuscation,
    pub idle_timeout: Duration,
    pub max_sessions: Option<usize>,
    pub cleanup_interval: Option<Duration>,
    pub drain_timeout: Duration,
    pub rate_limit: Option<RateLimitConfig>,
    pub buffer_pool_capacity: usize,
    pub send_queue_capacity: usize,
    pub max_datagram_bytes: usize,
    pub udp_socket_buffer_bytes: usize,
    pub health_addr: Option<SocketAddr>,
    pub metrics_addr: Option<SocketAddr>,
    pub send_jitter_max: Duration,
    pub chaff_pps: u64,
}

impl WgObfsShimConfig {
    pub fn new(
        listen_addr: SocketAddr,
        server_addr: SocketAddr,
        obfuscation: WgPacketObfuscation,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            listen_addr,
            server_addrs: vec![server_addr],
            obfuscation,
            idle_timeout,
            max_sessions: None,
            cleanup_interval: None,
            drain_timeout: Duration::from_secs(DEFAULT_DRAIN_TIMEOUT_SECS),
            rate_limit: None,
            buffer_pool_capacity: DEFAULT_BUFFER_POOL_CAPACITY,
            send_queue_capacity: DEFAULT_SEND_QUEUE_CAPACITY,
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
            udp_socket_buffer_bytes: DEFAULT_UDP_SOCKET_BUFFER_BYTES,
            health_addr: None,
            metrics_addr: None,
            send_jitter_max: Duration::from_millis(DEFAULT_JITTER_MAX_MS),
            chaff_pps: DEFAULT_CHAFF_PPS,
        }
    }

    pub fn with_server_addrs(
        listen_addr: SocketAddr,
        server_addrs: Vec<SocketAddr>,
        obfuscation: WgPacketObfuscation,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        if server_addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WireGuard shim requires at least one server address",
            ));
        }

        Ok(Self {
            listen_addr,
            server_addrs,
            obfuscation,
            idle_timeout,
            max_sessions: None,
            cleanup_interval: None,
            drain_timeout: Duration::from_secs(DEFAULT_DRAIN_TIMEOUT_SECS),
            rate_limit: None,
            buffer_pool_capacity: DEFAULT_BUFFER_POOL_CAPACITY,
            send_queue_capacity: DEFAULT_SEND_QUEUE_CAPACITY,
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
            udp_socket_buffer_bytes: DEFAULT_UDP_SOCKET_BUFFER_BYTES,
            health_addr: None,
            metrics_addr: None,
            send_jitter_max: Duration::from_millis(DEFAULT_JITTER_MAX_MS),
            chaff_pps: DEFAULT_CHAFF_PPS,
        })
    }

    pub fn primary_server_addr(&self) -> SocketAddr {
        self.server_addrs[0]
    }

    fn send_queue_capacity(&self) -> usize {
        self.send_queue_capacity.max(1)
    }

    fn cleanup_interval(&self) -> Duration {
        self.cleanup_interval
            .unwrap_or_else(|| cleanup_interval(self.idle_timeout))
    }

    fn buffer_pool_capacity(&self) -> usize {
        self.buffer_pool_capacity.max(1)
    }

    fn max_datagram_bytes(&self) -> usize {
        self.max_datagram_bytes.clamp(1, MAX_UDP_PACKET_SIZE)
    }

    fn chaff_interval(&self) -> Option<Duration> {
        if self.chaff_pps == 0
            || self.chaff_pps > MAX_CHAFF_PPS
            || !self.obfuscation.uses_framed_encoding()
        {
            return None;
        }
        let nanos_per_packet = 1_000_000_000u64 / self.chaff_pps.max(1);
        Some(Duration::from_nanos(nanos_per_packet.max(1)))
    }
}

#[derive(Debug, Error)]
pub enum ShimError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("failed to encode WireGuard packet: {0}")]
    Encode(#[from] PacketEncodeError),
    #[error("failed to decode WireGuard packet: {0}")]
    Decode(#[from] PacketDecodeError),
    #[error("session rate limit exceeded")]
    RateLimited,
}

#[derive(Default)]
pub struct ShimMetrics {
    active_sessions: AtomicU64,
    packets_client_to_server: AtomicU64,
    packets_server_to_client: AtomicU64,
    decode_errors: AtomicU64,
    encode_errors: AtomicU64,
    replay_detected: AtomicU64,
    sessions_evicted_idle: AtomicU64,
    sessions_evicted_send_failure: AtomicU64,
    sessions_evicted_table_limit: AtomicU64,
    sessions_closed_shutdown: AtomicU64,
    rate_limited_drops: AtomicU64,
    buffer_pool_exhausted: AtomicU64,
    buffer_pool_wait_millis_total: AtomicU64,
    send_queue_depth: AtomicU64,
    send_queue_capacity: AtomicU64,
    send_queue_depth_high_watermark: AtomicU64,
    send_queue_max_session_depth: AtomicU64,
    send_queue_max_session_utilization_percent: AtomicU64,
    send_queue_dequeued: AtomicU64,
    send_queue_wait_millis_total: AtomicU64,
    send_queue_drops: AtomicU64,
    chaff_packets_sent: AtomicU64,
}

impl ShimMetrics {
    pub fn active_sessions(&self) -> u64 {
        self.active_sessions.load(Ordering::Relaxed)
    }

    fn send_queue_depth(&self) -> u64 {
        self.send_queue_depth.load(Ordering::Relaxed)
    }

    fn send_queue_capacity(&self) -> u64 {
        self.send_queue_capacity.load(Ordering::Relaxed)
    }

    fn record_send_queue_capacity_add(&self, capacity: usize) {
        self.send_queue_capacity
            .fetch_add(capacity as u64, Ordering::Relaxed);
    }

    fn record_send_queue_capacity_sub(&self, capacity: usize) {
        subtract_saturating(&self.send_queue_capacity, capacity as u64);
    }

    fn reserve_send_queue_slot(&self) -> u64 {
        self.send_queue_depth.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn release_send_queue_slots(&self, count: u64) {
        subtract_saturating(&self.send_queue_depth, count);
    }

    fn record_send_queue_accepted(
        &self,
        session_depth: usize,
        session_capacity: usize,
        total_depth: u64,
    ) {
        update_atomic_max(&self.send_queue_depth_high_watermark, total_depth);
        update_atomic_max(&self.send_queue_max_session_depth, session_depth as u64);
        update_atomic_max(
            &self.send_queue_max_session_utilization_percent,
            utilization_percent(session_depth, session_capacity),
        );
    }

    fn record_send_queue_dequeued(&self, queued_at_millis: u64, now_millis: u64) {
        self.send_queue_dequeued.fetch_add(1, Ordering::Relaxed);
        self.send_queue_wait_millis_total.fetch_add(
            now_millis.saturating_sub(queued_at_millis),
            Ordering::Relaxed,
        );
    }

    fn record_send_queue_full_drop(&self, session_capacity: usize) {
        self.send_queue_drops.fetch_add(1, Ordering::Relaxed);
        update_atomic_max(&self.send_queue_max_session_depth, session_capacity as u64);
        update_atomic_max(&self.send_queue_max_session_utilization_percent, 100);
    }

    #[cfg(feature = "metrics")]
    fn render_openmetrics(&self) -> String {
        format!(
            concat!(
                "# TYPE wg_obfs_shim_active_sessions gauge\n",
                "wg_obfs_shim_active_sessions {}\n",
                "# TYPE wg_obfs_shim_packets_forwarded_total counter\n",
                "wg_obfs_shim_packets_forwarded_total{{direction=\"client_to_server\"}} {}\n",
                "wg_obfs_shim_packets_forwarded_total{{direction=\"server_to_client\"}} {}\n",
                "# TYPE wg_obfs_shim_decode_errors_total counter\n",
                "wg_obfs_shim_decode_errors_total {}\n",
                "# TYPE wg_obfs_shim_replay_detected_total counter\n",
                "wg_obfs_shim_replay_detected_total {}\n",
                "# TYPE wg_obfs_shim_encode_errors_total counter\n",
                "wg_obfs_shim_encode_errors_total {}\n",
                "# TYPE wg_obfs_shim_sessions_evicted_total counter\n",
                "wg_obfs_shim_sessions_evicted_total{{reason=\"idle\"}} {}\n",
                "wg_obfs_shim_sessions_evicted_total{{reason=\"send_failure\"}} {}\n",
                "wg_obfs_shim_sessions_evicted_total{{reason=\"table_limit\"}} {}\n",
                "wg_obfs_shim_sessions_evicted_total{{reason=\"shutdown\"}} {}\n",
                "# TYPE wg_obfs_shim_rate_limited_drops_total counter\n",
                "wg_obfs_shim_rate_limited_drops_total {}\n",
                "# TYPE wg_obfs_shim_buffer_pool_exhausted_total counter\n",
                "wg_obfs_shim_buffer_pool_exhausted_total {}\n",
                "# TYPE wg_obfs_shim_buffer_pool_wait_millis_total counter\n",
                "wg_obfs_shim_buffer_pool_wait_millis_total {}\n",
                "# TYPE wg_obfs_shim_send_queue_depth gauge\n",
                "wg_obfs_shim_send_queue_depth {}\n",
                "# TYPE wg_obfs_shim_send_queue_capacity gauge\n",
                "wg_obfs_shim_send_queue_capacity {}\n",
                "# TYPE wg_obfs_shim_send_queue_depth_high_watermark gauge\n",
                "wg_obfs_shim_send_queue_depth_high_watermark {}\n",
                "# TYPE wg_obfs_shim_send_queue_max_session_depth gauge\n",
                "wg_obfs_shim_send_queue_max_session_depth {}\n",
                "# TYPE wg_obfs_shim_send_queue_max_session_utilization_percent gauge\n",
                "wg_obfs_shim_send_queue_max_session_utilization_percent {}\n",
                "# TYPE wg_obfs_shim_send_queue_dequeued_total counter\n",
                "wg_obfs_shim_send_queue_dequeued_total {}\n",
                "# TYPE wg_obfs_shim_send_queue_wait_millis_total counter\n",
                "wg_obfs_shim_send_queue_wait_millis_total {}\n",
                "# TYPE wg_obfs_shim_send_queue_drops_total counter\n",
                "wg_obfs_shim_send_queue_drops_total {}\n",
                "# TYPE wg_obfs_shim_chaff_packets_sent_total counter\n",
                "wg_obfs_shim_chaff_packets_sent_total {}\n",
                "# EOF\n"
            ),
            self.active_sessions.load(Ordering::Relaxed),
            self.packets_client_to_server.load(Ordering::Relaxed),
            self.packets_server_to_client.load(Ordering::Relaxed),
            self.decode_errors.load(Ordering::Relaxed),
            self.replay_detected.load(Ordering::Relaxed),
            self.encode_errors.load(Ordering::Relaxed),
            self.sessions_evicted_idle.load(Ordering::Relaxed),
            self.sessions_evicted_send_failure.load(Ordering::Relaxed),
            self.sessions_evicted_table_limit.load(Ordering::Relaxed),
            self.sessions_closed_shutdown.load(Ordering::Relaxed),
            self.rate_limited_drops.load(Ordering::Relaxed),
            self.buffer_pool_exhausted.load(Ordering::Relaxed),
            self.buffer_pool_wait_millis_total.load(Ordering::Relaxed),
            self.send_queue_depth.load(Ordering::Relaxed),
            self.send_queue_capacity.load(Ordering::Relaxed),
            self.send_queue_depth_high_watermark.load(Ordering::Relaxed),
            self.send_queue_max_session_depth.load(Ordering::Relaxed),
            self.send_queue_max_session_utilization_percent
                .load(Ordering::Relaxed),
            self.send_queue_dequeued.load(Ordering::Relaxed),
            self.send_queue_wait_millis_total.load(Ordering::Relaxed),
            self.send_queue_drops.load(Ordering::Relaxed),
            self.chaff_packets_sent.load(Ordering::Relaxed),
        )
    }
}

fn update_atomic_max(target: &AtomicU64, value: u64) {
    let mut current = target.load(Ordering::Relaxed);
    while value > current {
        match target.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn subtract_saturating(target: &AtomicU64, count: u64) {
    let _ = target.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(count))
    });
}

fn utilization_percent(depth: usize, capacity: usize) -> u64 {
    if capacity == 0 {
        return 0;
    }
    ((depth as u128 * 100) / capacity as u128).min(100) as u64
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ShimHealthSnapshot {
    pub status: &'static str,
    pub sessions: u64,
    pub replay_detected: u64,
    pub queue: ShimQueueHealthSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ShimQueueHealthSnapshot {
    pub status: &'static str,
    pub active_sessions: u64,
    pub depth: u64,
    pub capacity: u64,
    pub utilization_percent: u64,
    pub max_session_depth: u64,
    pub max_session_capacity: u64,
    pub max_session_utilization_percent: u64,
    pub depth_high_watermark: u64,
    pub max_session_depth_high_watermark: u64,
    pub max_session_utilization_high_watermark_percent: u64,
    pub dequeued_total: u64,
    pub wait_millis_total: u64,
    pub drops_total: u64,
    pub buffer_pool_exhausted_total: u64,
    pub buffer_pool_wait_millis_total: u64,
    pub reasons: Vec<&'static str>,
}

#[derive(Clone)]
pub struct ShimHealthHandle {
    metrics: Arc<ShimMetrics>,
    sessions: Arc<DashMap<SocketAddr, Arc<ShimSession>>>,
}

impl ShimHealthHandle {
    pub fn snapshot(&self) -> ShimHealthSnapshot {
        let queue = self.queue_health_snapshot();
        let status = if queue.status == "ok" { "ok" } else { "degraded" };
        ShimHealthSnapshot {
            status,
            sessions: self.active_sessions(),
            replay_detected: self.replay_detected(),
            queue,
        }
    }

    pub fn active_sessions(&self) -> u64 {
        self.metrics.active_sessions()
    }

    pub fn replay_detected(&self) -> u64 {
        self.metrics.replay_detected.load(Ordering::Relaxed)
    }

    pub fn queue_health_snapshot(&self) -> ShimQueueHealthSnapshot {
        let mut depth = 0u64;
        let mut capacity = 0u64;
        let mut max_session_depth = 0u64;
        let mut max_session_capacity = 0u64;
        let mut max_session_utilization_percent = 0u64;

        for entry in self.sessions.iter() {
            let session = entry.value();
            let session_depth = session.send_queue_depth() as u64;
            let session_capacity = session.send_queue_capacity() as u64;
            depth = depth.saturating_add(session_depth);
            capacity = capacity.saturating_add(session_capacity);
            if session_depth > max_session_depth {
                max_session_depth = session_depth;
                max_session_capacity = session_capacity;
            }
            max_session_utilization_percent = max_session_utilization_percent
                .max(utilization_percent(session_depth as usize, session_capacity as usize));
        }

        let drops_total = self.metrics.send_queue_drops.load(Ordering::Relaxed);
        let buffer_pool_exhausted_total = self.metrics.buffer_pool_exhausted.load(Ordering::Relaxed);
        let utilization_percent = utilization_percent(depth as usize, capacity as usize);
        let mut reasons = Vec::new();
        if max_session_utilization_percent >= SEND_QUEUE_HEALTH_DEGRADED_UTILIZATION_PERCENT {
            reasons.push("send_queue_utilization_high");
        }

        ShimQueueHealthSnapshot {
            status: if reasons.is_empty() { "ok" } else { "degraded" },
            active_sessions: self.active_sessions(),
            depth,
            capacity,
            utilization_percent,
            max_session_depth,
            max_session_capacity,
            max_session_utilization_percent,
            depth_high_watermark: self
                .metrics
                .send_queue_depth_high_watermark
                .load(Ordering::Relaxed),
            max_session_depth_high_watermark: self
                .metrics
                .send_queue_max_session_depth
                .load(Ordering::Relaxed),
            max_session_utilization_high_watermark_percent: self
                .metrics
                .send_queue_max_session_utilization_percent
                .load(Ordering::Relaxed),
            dequeued_total: self.metrics.send_queue_dequeued.load(Ordering::Relaxed),
            wait_millis_total: self
                .metrics
                .send_queue_wait_millis_total
                .load(Ordering::Relaxed),
            drops_total,
            buffer_pool_exhausted_total,
            buffer_pool_wait_millis_total: self
                .metrics
                .buffer_pool_wait_millis_total
                .load(Ordering::Relaxed),
            reasons,
        }
    }
}

pub struct WgObfsShimRuntime {
    pub local_addr: SocketAddr,
    pub handle: JoinHandle<()>,
    config: Arc<ArcSwap<WgObfsShimConfig>>,
    metrics: Arc<ShimMetrics>,
    sessions: Arc<DashMap<SocketAddr, Arc<ShimSession>>>,
}

impl WgObfsShimRuntime {
    pub fn update_config(&self, config: WgObfsShimConfig) {
        self.config.store(Arc::new(config));
    }

    pub fn config_snapshot(&self) -> Arc<WgObfsShimConfig> {
        self.config.load_full()
    }

    pub fn health_handle(&self) -> ShimHealthHandle {
        ShimHealthHandle {
            metrics: self.metrics.clone(),
            sessions: self.sessions.clone(),
        }
    }

    pub fn active_sessions(&self) -> u64 {
        self.metrics.active_sessions()
    }
}

#[derive(Debug)]
struct RateLimitedLogNotice {
    interval: Duration,
    last_log: Option<Instant>,
    suppressed: u64,
}

impl RateLimitedLogNotice {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_log: None,
            suppressed: 0,
        }
    }

    fn record(&mut self, now: Instant) -> Option<u64> {
        match self.last_log {
            Some(last_log) if now.duration_since(last_log) < self.interval => {
                self.suppressed += 1;
                None
            }
            _ => {
                let suppressed = self.suppressed;
                self.suppressed = 0;
                self.last_log = Some(now);
                Some(suppressed)
            }
        }
    }
}

#[derive(Clone)]
struct ShimClock {
    started: Instant,
}

impl ShimClock {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    fn now_millis(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

struct UdpBufferPool {
    buffers: Mutex<Vec<Box<[u8]>>>,
}

impl UdpBufferPool {
    fn new(capacity: usize, buffer_len: usize) -> Self {
        let buffer_len = buffer_len.clamp(1, MAX_UDP_PACKET_SIZE);
        let mut buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buffers.push(vec![0u8; buffer_len].into_boxed_slice());
        }
        Self {
            buffers: Mutex::new(buffers),
        }
    }

    fn lease(self: &Arc<Self>) -> Option<UdpBufferLease> {
        let buffer = self
            .buffers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop()?;
        Some(UdpBufferLease {
            buffer: Some(buffer),
            pool: self.clone(),
        })
    }

    #[cfg(test)]
    fn available(&self) -> usize {
        self.buffers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }

}

struct UdpBufferLease {
    buffer: Option<Box<[u8]>>,
    pool: Arc<UdpBufferPool>,
}

impl Deref for UdpBufferLease {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer.as_deref().expect("buffer lease is present")
    }
}

impl DerefMut for UdpBufferLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_deref_mut().expect("buffer lease is present")
    }
}

impl Drop for UdpBufferLease {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool
                .buffers
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(buffer);
        }
    }
}

#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill_millis: u64,
}

impl TokenBucket {
    fn new(config: RateLimitConfig, now_millis: u64) -> Self {
        Self {
            capacity: config.burst_packets as f64,
            tokens: config.burst_packets as f64,
            refill_per_sec: config.packets_per_sec as f64,
            last_refill_millis: now_millis,
        }
    }

    fn try_take(&mut self, now_millis: u64) -> bool {
        let elapsed_ms = now_millis.saturating_sub(self.last_refill_millis);
        if elapsed_ms > 0 {
            self.tokens = (self.tokens + (elapsed_ms as f64 * self.refill_per_sec / 1_000.0))
                .min(self.capacity);
            self.last_refill_millis = now_millis;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct ShimSession {
    id: u64,
    config: Arc<WgObfsShimConfig>,
    upstream_tx: mpsc::Sender<QueuedUpstreamPacket>,
    upstream_port: AtomicU16,
    last_activity_millis: AtomicU64,
    shutdown: CancellationToken,
    receiver_task: Mutex<Option<JoinHandle<()>>>,
    client_to_server_encode: PacketEncodeState,
    server_to_client_replay: Mutex<ReplayWindow>,
    rate_limiter: Option<Mutex<TokenBucket>>,
    first_send_logged: AtomicBool,
    send_queue_depth: AtomicUsize,
    send_queue_capacity: usize,
    send_queue_full_notice: Mutex<RateLimitedLogNotice>,
    last_upstream_send_millis: AtomicU64,
    last_server_reply_millis: AtomicU64,
    last_server_rtt_millis: AtomicU64,
    last_server_rtt_known: AtomicBool,
    span: Span,
}
