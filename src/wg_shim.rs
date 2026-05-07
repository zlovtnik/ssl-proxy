//! Linux WireGuard obfuscation shim.
//!
//! The shim listens locally for plaintext WireGuard UDP packets from a client
//! and forwards them to the real server endpoint using the shared WireGuard
//! packet obfuscation codec.

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

use crate::wg_packet_obfuscation::{
    cleanup_interval, decode_packet_in_place, encode_packet_in_place, PacketDecodeError,
    PacketDirection, PacketEncodeError, PacketEncodeState, ReplayWindow, WgPacketObfuscation,
    MAX_UDP_PACKET_SIZE,
};

pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:51821";
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_BUFFER_POOL_CAPACITY: usize = 256;
pub const DEFAULT_SEND_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_HEALTH_ADDR: &str = "127.0.0.1:51822";

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
    pub health_addr: Option<SocketAddr>,
    pub metrics_addr: Option<SocketAddr>,
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
            health_addr: None,
            metrics_addr: None,
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
            health_addr: None,
            metrics_addr: None,
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
    sessions_evicted_idle: AtomicU64,
    sessions_evicted_send_failure: AtomicU64,
    sessions_evicted_table_limit: AtomicU64,
    sessions_closed_shutdown: AtomicU64,
    rate_limited_drops: AtomicU64,
    buffer_pool_exhausted: AtomicU64,
    buffer_pool_wait_millis_total: AtomicU64,
    send_queue_drops: AtomicU64,
}

impl ShimMetrics {
    pub fn active_sessions(&self) -> u64 {
        self.active_sessions.load(Ordering::Relaxed)
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
                "# TYPE wg_obfs_shim_send_queue_drops_total counter\n",
                "wg_obfs_shim_send_queue_drops_total {}\n",
                "# EOF\n"
            ),
            self.active_sessions.load(Ordering::Relaxed),
            self.packets_client_to_server.load(Ordering::Relaxed),
            self.packets_server_to_client.load(Ordering::Relaxed),
            self.decode_errors.load(Ordering::Relaxed),
            self.encode_errors.load(Ordering::Relaxed),
            self.sessions_evicted_idle.load(Ordering::Relaxed),
            self.sessions_evicted_send_failure.load(Ordering::Relaxed),
            self.sessions_evicted_table_limit.load(Ordering::Relaxed),
            self.sessions_closed_shutdown.load(Ordering::Relaxed),
            self.rate_limited_drops.load(Ordering::Relaxed),
            self.buffer_pool_exhausted.load(Ordering::Relaxed),
            self.buffer_pool_wait_millis_total.load(Ordering::Relaxed),
            self.send_queue_drops.load(Ordering::Relaxed),
        )
    }
}

#[derive(Clone)]
pub struct ShimHealthHandle {
    metrics: Arc<ShimMetrics>,
}

impl ShimHealthHandle {
    pub fn active_sessions(&self) -> u64 {
        self.metrics.active_sessions()
    }
}

pub struct WgObfsShimRuntime {
    pub local_addr: SocketAddr,
    pub handle: JoinHandle<()>,
    config: Arc<ArcSwap<WgObfsShimConfig>>,
    metrics: Arc<ShimMetrics>,
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
        }
    }

    pub fn active_sessions(&self) -> u64 {
        self.metrics.active_sessions()
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
    fn new(capacity: usize) -> Self {
        let mut buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buffers.push(vec![0u8; MAX_UDP_PACKET_SIZE].into_boxed_slice());
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
    last_upstream_send_millis: AtomicU64,
    last_server_reply_millis: AtomicU64,
    last_server_rtt_millis: AtomicU64,
    last_server_rtt_known: AtomicBool,
    span: Span,
}

impl ShimSession {
    fn new(
        id: u64,
        config: Arc<WgObfsShimConfig>,
        upstream_tx: mpsc::Sender<QueuedUpstreamPacket>,
        upstream_port: u16,
        now_millis: u64,
        span: Span,
    ) -> Self {
        let rate_limit = config.rate_limit;
        Self {
            id,
            config,
            upstream_tx,
            upstream_port: AtomicU16::new(upstream_port),
            last_activity_millis: AtomicU64::new(now_millis),
            shutdown: CancellationToken::new(),
            receiver_task: Mutex::new(None),
            client_to_server_encode: PacketEncodeState::new(now_millis),
            server_to_client_replay: Mutex::new(ReplayWindow::default()),
            rate_limiter: rate_limit.map(|config| Mutex::new(TokenBucket::new(config, now_millis))),
            first_send_logged: AtomicBool::new(false),
            last_upstream_send_millis: AtomicU64::new(0),
            last_server_reply_millis: AtomicU64::new(0),
            last_server_rtt_millis: AtomicU64::new(0),
            last_server_rtt_known: AtomicBool::new(false),
            span,
        }
    }

    fn touch(&self, now_millis: u64) {
        self.last_activity_millis
            .store(now_millis, Ordering::Relaxed);
    }

    fn idle_for(&self, now_millis: u64) -> Duration {
        Duration::from_millis(
            now_millis.saturating_sub(self.last_activity_millis.load(Ordering::Relaxed)),
        )
    }

    fn last_activity_millis(&self) -> u64 {
        self.last_activity_millis.load(Ordering::Relaxed)
    }

    fn close(&self) {
        self.shutdown.cancel();
    }

    fn set_receiver_task(&self, handle: JoinHandle<()>) {
        *self
            .receiver_task
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(handle);
    }

    fn take_receiver_task(&self) -> Option<JoinHandle<()>> {
        self.receiver_task
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }

    fn allow_upstream_send(&self, now_millis: u64) -> bool {
        self.rate_limiter
            .as_ref()
            .map(|bucket| {
                bucket
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .try_take(now_millis)
            })
            .unwrap_or(true)
    }

    fn record_first_send(&self) {
        if !self.first_send_logged.swap(true, Ordering::AcqRel) {
            self.span.in_scope(|| {
                info!(
                    session_id = self.id,
                    upstream_port = self.upstream_port.load(Ordering::Relaxed),
                    "WireGuard shim session first upstream send"
                );
            });
        }
    }

    fn set_upstream_port(&self, upstream_port: u16) {
        self.upstream_port.store(upstream_port, Ordering::Relaxed);
    }

    fn record_upstream_send(&self, now_millis: u64) {
        self.last_upstream_send_millis
            .store(now_millis, Ordering::Relaxed);
    }

    fn record_server_reply(&self, now_millis: u64) {
        let last_send = self.last_upstream_send_millis.load(Ordering::Relaxed);
        if last_send > 0 {
            self.last_server_rtt_millis
                .store(now_millis.saturating_sub(last_send), Ordering::Relaxed);
            self.last_server_rtt_known.store(true, Ordering::Release);
        }
        self.last_server_reply_millis
            .store(now_millis, Ordering::Relaxed);
    }

    fn last_server_reply_age_millis(&self, now_millis: u64) -> Option<u64> {
        let last_reply = self.last_server_reply_millis.load(Ordering::Relaxed);
        (last_reply > 0).then(|| now_millis.saturating_sub(last_reply))
    }

    fn last_server_rtt_millis(&self) -> Option<u64> {
        self.last_server_rtt_known
            .load(Ordering::Acquire)
            .then(|| self.last_server_rtt_millis.load(Ordering::Relaxed))
    }
}

struct QueuedUpstreamPacket {
    bytes: Vec<u8>,
    queued_at_millis: u64,
}

struct UpstreamConnection {
    socket: UdpSocket,
    server_addr: SocketAddr,
    local_port: u16,
}

#[derive(Clone)]
struct ShimSessionContext {
    listen_socket: Arc<UdpSocket>,
    config_store: Arc<ArcSwap<WgObfsShimConfig>>,
    sessions: Arc<DashMap<SocketAddr, Arc<ShimSession>>>,
    shutdown: CancellationToken,
    clock: Arc<ShimClock>,
    metrics: Arc<ShimMetrics>,
    next_session_id: Arc<AtomicU64>,
    buffer_pool: Arc<UdpBufferPool>,
    next_server_index: Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
enum SessionCloseReason {
    Idle,
    SendFailure,
    TableLimit,
    Shutdown,
}

impl SessionCloseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::SendFailure => "send_failure",
            Self::TableLimit => "table_limit",
            Self::Shutdown => "shutdown",
        }
    }
}

pub async fn spawn(
    config: WgObfsShimConfig,
    shutdown: CancellationToken,
) -> io::Result<JoinHandle<()>> {
    spawn_runtime(config, shutdown)
        .await
        .map(|runtime| runtime.handle)
}

#[allow(dead_code)]
pub(crate) async fn spawn_with_addrs(
    listen_addr: SocketAddr,
    server_addr: SocketAddr,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    spawn_with_config(
        WgObfsShimConfig::new(listen_addr, server_addr, obfuscation, idle_timeout),
        shutdown,
    )
    .await
}

pub(crate) async fn spawn_with_config(
    config: WgObfsShimConfig,
    shutdown: CancellationToken,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let runtime = spawn_runtime(config, shutdown).await?;
    Ok((runtime.local_addr, runtime.handle))
}

pub async fn spawn_runtime(
    config: WgObfsShimConfig,
    shutdown: CancellationToken,
) -> io::Result<WgObfsShimRuntime> {
    if config.server_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard shim requires at least one server address",
        ));
    }

    let listen_socket = Arc::new(UdpSocket::bind(config.listen_addr).await?);
    let local_addr = listen_socket.local_addr()?;
    let sessions = Arc::new(DashMap::new());
    let clock = Arc::new(ShimClock::new());
    let metrics = Arc::new(ShimMetrics::default());
    let next_session_id = Arc::new(AtomicU64::new(1));
    let buffer_pool = Arc::new(UdpBufferPool::new(config.buffer_pool_capacity()));
    let next_server_index = Arc::new(AtomicUsize::new(0));
    let config = Arc::new(ArcSwap::from_pointee(config));
    let context = ShimSessionContext {
        listen_socket,
        config_store: config.clone(),
        sessions,
        shutdown,
        clock,
        metrics: metrics.clone(),
        next_session_id,
        buffer_pool,
        next_server_index,
    };

    let task = tokio::spawn(run_shim(context));

    Ok(WgObfsShimRuntime {
        local_addr,
        handle: task,
        config,
        metrics,
    })
}

async fn run_shim(context: ShimSessionContext) {
    let startup_config = context.config_store.load_full();
    info!(
        listen_addr = %context.listen_socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0))),
        server_addrs = ?startup_config.server_addrs,
        magic_byte = ?startup_config.obfuscation.magic_byte,
        encryption_mode = ?startup_config.obfuscation.encryption_mode,
        idle_timeout_secs = startup_config.idle_timeout.as_secs(),
        cleanup_interval_secs = startup_config.cleanup_interval().as_secs_f64(),
        max_sessions = ?startup_config.max_sessions,
        "WireGuard obfuscation shim started"
    );

    let cleanup_task = tokio::spawn(run_cleanup_loop(context.clone()));

    #[cfg(feature = "metrics")]
    let metrics_task = startup_config.metrics_addr.map(|metrics_addr| {
        tokio::spawn(run_metrics_server(
            metrics_addr,
            context.metrics.clone(),
            context.shutdown.clone(),
        ))
    });
    #[cfg(not(feature = "metrics"))]
    if let Some(metrics_addr) = startup_config.metrics_addr {
        warn!(
            %metrics_addr,
            "WG obfuscation shim metrics address configured but binary was built without the metrics feature"
        );
    }

    loop {
        let Some(mut lease) = lease_buffer_or_wait(&context, None).await else {
            break;
        };

        tokio::select! {
            _ = context.shutdown.cancelled() => break,
            recv = context.listen_socket.recv_from(&mut lease) => {
                let (len, client_addr) = match recv {
                    Ok(result) => result,
                    Err(err) => {
                        if context.shutdown.is_cancelled() {
                            break;
                        }
                        warn!(%err, "WireGuard obfuscation shim receive failed");
                        continue;
                    }
                };

                let config = context.config_store.load_full();
                let session = match get_or_create_session(
                    client_addr,
                    config.clone(),
                    context.clone(),
                )
                .await
                {
                    Ok(session) => session,
                    Err(err) => {
                        warn!(%client_addr, %err, "failed to create WireGuard shim session");
                        continue;
                    }
                };

                let now = context.clock.now_millis();
                session.touch(now);
                if !session.allow_upstream_send(now) {
                    context.metrics.rate_limited_drops.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        %client_addr,
                        session_id = session.id,
                        "dropping WireGuard packet because per-session upstream rate limit was exceeded"
                    );
                    continue;
                }

                session.record_first_send();
                let encoded_len = match encode_packet_in_place(
                    &mut lease,
                    len,
                    &session.config.obfuscation,
                    &session.client_to_server_encode,
                    PacketDirection::ClientToServer,
                    now,
                ) {
                    Ok(encoded_len) => encoded_len,
                    Err(err) => {
                        context.metrics.encode_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(%client_addr, session_id = session.id, %err, "failed to encode WireGuard packet for upstream send");
                        continue;
                    }
                };

                let send_started_millis = context.clock.now_millis();
                let packet = QueuedUpstreamPacket {
                    bytes: lease[..encoded_len].to_vec(),
                    queued_at_millis: send_started_millis,
                };
                match session.upstream_tx.try_send(packet) {
                    Ok(()) => {
                        session.record_upstream_send(send_started_millis);
                        context.metrics.packets_client_to_server.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        context.metrics.send_queue_drops.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            %client_addr,
                            session_id = session.id,
                            "dropping WireGuard packet because per-session upstream send queue is full"
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        let failure_millis = context.clock.now_millis();
                        warn!(
                            %client_addr,
                            session_id = session.id,
                            upstream_port = session.upstream_port.load(Ordering::Relaxed),
                            last_server_reply_age_ms = ?session.last_server_reply_age_millis(failure_millis),
                            last_server_rtt_ms = ?session.last_server_rtt_millis(),
                            "failed to queue obfuscated WireGuard packet because session upstream task is closed"
                        );
                        close_session_if_current(
                            &context.sessions,
                            client_addr,
                            &session,
                            &context.metrics,
                            SessionCloseReason::SendFailure,
                        );
                    }
                }
            }
        }
    }

    let _ = cleanup_task.await;
    #[cfg(feature = "metrics")]
    if let Some(metrics_task) = metrics_task {
        let _ = metrics_task.await;
    }

    let sessions_to_close: Vec<_> = context
        .sessions
        .iter()
        .map(|entry| (*entry.key(), entry.value().clone()))
        .collect();
    let mut receiver_tasks = Vec::new();
    for (client_addr, session) in sessions_to_close {
        if close_session_if_current(
            &context.sessions,
            client_addr,
            &session,
            &context.metrics,
            SessionCloseReason::Shutdown,
        ) {
            if let Some(handle) = session.take_receiver_task() {
                receiver_tasks.push(handle);
            }
        }
    }
    drain_receiver_tasks(receiver_tasks, context.config_store.load().drain_timeout).await;

    info!("WireGuard obfuscation shim shutting down");
}

async fn get_or_create_session(
    client_addr: SocketAddr,
    config: Arc<WgObfsShimConfig>,
    context: ShimSessionContext,
) -> io::Result<Arc<ShimSession>> {
    if let Some(existing) = context.sessions.get(&client_addr) {
        return Ok(existing.clone());
    }

    enforce_session_limit(
        &context.sessions,
        config.max_sessions,
        &context.metrics,
        Some(client_addr),
    )?;
    let receiver_context = context.clone();
    match context.sessions.entry(client_addr) {
        dashmap::mapref::entry::Entry::Occupied(existing) => Ok(existing.get().clone()),
        dashmap::mapref::entry::Entry::Vacant(vacant) => {
            if context.shutdown.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "WireGuard shim shutdown is in progress",
                ));
            }

            let now = context.clock.now_millis();
            let session_id = context.next_session_id.fetch_add(1, Ordering::Relaxed);
            let (upstream_tx, upstream_rx) = mpsc::channel(config.send_queue_capacity());
            let span = info_span!(
                "wg_shim_session",
                client_addr = %client_addr,
                session_id,
            );
            let session = Arc::new(ShimSession::new(
                session_id,
                config.clone(),
                upstream_tx,
                0,
                now,
                span.clone(),
            ));
            let session = vacant.insert(session).clone();
            context
                .metrics
                .active_sessions
                .fetch_add(1, Ordering::Relaxed);
            session.span.in_scope(|| {
                info!("WireGuard shim session created");
            });
            let handle = tokio::spawn(run_session_receiver(
                client_addr,
                session.clone(),
                upstream_rx,
                receiver_context,
            ));
            session.set_receiver_task(handle);
            Ok(session)
        }
    }
}

async fn run_session_receiver(
    client_addr: SocketAddr,
    session: Arc<ShimSession>,
    mut upstream_rx: mpsc::Receiver<QueuedUpstreamPacket>,
    context: ShimSessionContext,
) {
    let mut connection = match connect_next_upstream(&session.config, &context.next_server_index)
        .await
    {
        Ok(connection) => {
            session.set_upstream_port(connection.local_port);
            connection
        }
        Err(err) => {
            warn!(%client_addr, session_id = session.id, %err, "failed to create initial WireGuard shim upstream socket");
            close_session_if_current(
                &context.sessions,
                client_addr,
                &session,
                &context.metrics,
                SessionCloseReason::SendFailure,
            );
            return;
        }
    };

    loop {
        let Some(mut lease) = lease_buffer_or_wait(&context, Some(&session.shutdown)).await else {
            break;
        };

        tokio::select! {
            _ = context.shutdown.cancelled() => break,
            _ = session.shutdown.cancelled() => break,
            queued = upstream_rx.recv() => {
                let Some(packet) = queued else {
                    break;
                };
                match send_with_failover(
                    &mut connection,
                    packet,
                    &session,
                    client_addr,
                    &session.config,
                    &context.next_server_index,
                    &context.clock,
                )
                .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        let failure_millis = context.clock.now_millis();
                        warn!(
                            %client_addr,
                            session_id = session.id,
                            upstream_port = session.upstream_port.load(Ordering::Relaxed),
                            last_server_reply_age_ms = ?session.last_server_reply_age_millis(failure_millis),
                            last_server_rtt_ms = ?session.last_server_rtt_millis(),
                            %err,
                            "failed to send obfuscated WireGuard packet to all configured upstream servers"
                        );
                        close_session_if_current(
                            &context.sessions,
                            client_addr,
                            &session,
                            &context.metrics,
                            SessionCloseReason::SendFailure,
                        );
                        break;
                    }
                }
            }
            recv = connection.socket.recv(&mut lease) => {
                let len = match recv {
                    Ok(len) => len,
                    Err(err) => {
                        warn!(
                            %client_addr,
                            session_id = session.id,
                            upstream_addr = %connection.server_addr,
                            %err,
                            "WireGuard shim session receive failed"
                        );
                        break;
                    }
                };

                let now = context.clock.now_millis();
                session.touch(now);
                // Server replies carry the relay encoder's salt in-band, so
                // the shim decodes without holding the relay's encode state.
                let decoded_len = {
                    let mut replay = session
                        .server_to_client_replay
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    match decode_packet_in_place(
                        &mut lease,
                        len,
                        &session.config.obfuscation,
                        Some(&mut replay),
                        PacketDirection::ServerToClient,
                    ) {
                        Ok(decoded_len) => decoded_len,
                        Err(PacketDecodeError::MagicByteMismatch) => {
                            context.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                            warn!(%client_addr, session_id = session.id, packet_len = len, "dropping server reply with missing or invalid obfuscation marker");
                            continue;
                        }
                        Err(PacketDecodeError::EmptyPayload) => {
                            context.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                            warn!(%client_addr, session_id = session.id, packet_len = len, "dropping server reply with empty obfuscation payload");
                            continue;
                        }
                        Err(err) => {
                            context.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                %client_addr,
                                session_id = session.id,
                                packet_len = len,
                                reason = err.as_str(),
                                %err,
                                "dropping server reply after structured decode failure"
                            );
                            continue;
                        }
                    }
                };
                session.record_server_reply(now);

                if let Err(err) = context.listen_socket.send_to(&lease[..decoded_len], client_addr).await {
                    warn!(%client_addr, session_id = session.id, %err, "failed to deliver plaintext WireGuard packet back to local client");
                    close_session_if_current(
                        &context.sessions,
                        client_addr,
                        &session,
                        &context.metrics,
                        SessionCloseReason::SendFailure,
                    );
                    break;
                }
                context.metrics.packets_server_to_client.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    let close_reason = if context.shutdown.is_cancelled() {
        SessionCloseReason::Shutdown
    } else {
        SessionCloseReason::SendFailure
    };
    close_session_if_current(
        &context.sessions,
        client_addr,
        &session,
        &context.metrics,
        close_reason,
    );
    session.close();
}

async fn connect_next_upstream(
    config: &WgObfsShimConfig,
    next_server_index: &AtomicUsize,
) -> io::Result<UpstreamConnection> {
    let server_count = config.server_addrs.len();
    if server_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard shim requires at least one server address",
        ));
    }

    let start = next_server_index.fetch_add(1, Ordering::Relaxed);
    for offset in 0..server_count {
        let index = (start + offset) % server_count;
        match connect_upstream(config.server_addrs[index], index).await {
            Ok(connection) => return Ok(connection),
            Err(err) => {
                warn!(
                    server_addr = %config.server_addrs[index],
                    %err,
                    "failed to connect WireGuard shim upstream socket"
                );
            }
        }
    }

    Err(io::Error::other(
        "failed to connect any configured WireGuard shim upstream server",
    ))
}

async fn send_with_failover(
    connection: &mut UpstreamConnection,
    packet: QueuedUpstreamPacket,
    session: &ShimSession,
    client_addr: SocketAddr,
    config: &WgObfsShimConfig,
    next_server_index: &AtomicUsize,
    clock: &ShimClock,
) -> io::Result<()> {
    let mut last_error = None;
    let max_attempts = config.server_addrs.len().max(1);
    for attempt in 0..max_attempts {
        match connection.socket.send(&packet.bytes).await {
            Ok(_) => {
                session.record_upstream_send(packet.queued_at_millis);
                return Ok(());
            }
            Err(err) => {
                last_error = Some(err);
                warn!(
                    %client_addr,
                    session_id = session.id,
                    attempt = attempt + 1,
                    upstream_addr = %connection.server_addr,
                    upstream_port = connection.local_port,
                    "WireGuard shim upstream send failed; trying next configured server"
                );
                *connection = connect_next_upstream(config, next_server_index).await?;
                session.set_upstream_port(connection.local_port);
                session.record_upstream_send(clock.now_millis());
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| io::Error::other("failed to send WireGuard shim upstream packet")))
}

async fn connect_upstream(
    server_addr: SocketAddr,
    _server_index: usize,
) -> io::Result<UpstreamConnection> {
    let bind_addr = upstream_bind_addr(server_addr);
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(server_addr).await?;
    let local_port = socket.local_addr()?.port();
    Ok(UpstreamConnection {
        socket,
        server_addr,
        local_port,
    })
}

fn upstream_bind_addr(server_addr: SocketAddr) -> SocketAddr {
    if server_addr.is_ipv6() {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    }
}

async fn run_cleanup_loop(context: ShimSessionContext) {
    let mut interval = tokio::time::interval(context.config_store.load().cleanup_interval());
    loop {
        tokio::select! {
            _ = context.shutdown.cancelled() => return,
            _ = interval.tick() => {
                let config = context.config_store.load_full();
                let now = context.clock.now_millis();
                let stale_sessions: Vec<_> = context.sessions
                    .iter()
                    .filter_map(|entry| {
                        let client_addr = *entry.key();
                        let session = entry.value().clone();
                        (session.idle_for(now) >= config.idle_timeout).then_some((client_addr, session))
                    })
                    .collect();

                for (client_addr, session) in stale_sessions {
                    close_session_if_current(
                        &context.sessions,
                        client_addr,
                        &session,
                        &context.metrics,
                        SessionCloseReason::Idle,
                    );
                }
            }
        }
    }
}

async fn lease_buffer_or_wait(
    context: &ShimSessionContext,
    session_shutdown: Option<&CancellationToken>,
) -> Option<UdpBufferLease> {
    if let Some(lease) = context.buffer_pool.lease() {
        return Some(lease);
    }

    let mut wait_started = Instant::now();
    loop {
        context
            .metrics
            .buffer_pool_exhausted
            .fetch_add(1, Ordering::Relaxed);
        tokio::select! {
            _ = context.shutdown.cancelled() => return None,
            _ = optional_cancelled(session_shutdown) => return None,
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        record_buffer_pool_wait_since(&context.metrics, wait_started);
        if let Some(lease) = context.buffer_pool.lease() {
            return Some(lease);
        }
        wait_started = Instant::now();
    }
}

async fn optional_cancelled(token: Option<&CancellationToken>) {
    if let Some(token) = token {
        token.cancelled().await;
    } else {
        std::future::pending::<()>().await;
    }
}

fn record_buffer_pool_wait_since(metrics: &ShimMetrics, wait_started: Instant) {
    let waited_millis = wait_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    metrics
        .buffer_pool_wait_millis_total
        .fetch_add(waited_millis, Ordering::Relaxed);
}

fn enforce_session_limit(
    sessions: &DashMap<SocketAddr, Arc<ShimSession>>,
    max_sessions: Option<usize>,
    metrics: &ShimMetrics,
    exclude: Option<SocketAddr>,
) -> io::Result<()> {
    let Some(max_sessions) = max_sessions else {
        return Ok(());
    };
    if max_sessions == 0 {
        return Err(io::Error::other("WireGuard shim max_sessions is zero"));
    }

    while sessions.len() >= max_sessions {
        if !evict_oldest_session(sessions, metrics, exclude) {
            return Err(io::Error::other(
                "WireGuard shim session limit reached and no session could be evicted",
            ));
        }
    }
    Ok(())
}

fn evict_oldest_session(
    sessions: &DashMap<SocketAddr, Arc<ShimSession>>,
    metrics: &ShimMetrics,
    exclude: Option<SocketAddr>,
) -> bool {
    let oldest = sessions
        .iter()
        .filter(|entry| Some(*entry.key()) != exclude)
        .min_by_key(|entry| entry.value().last_activity_millis())
        .map(|entry| (*entry.key(), entry.value().clone()));

    let Some((client_addr, session)) = oldest else {
        return false;
    };

    close_session_if_current(
        sessions,
        client_addr,
        &session,
        metrics,
        SessionCloseReason::TableLimit,
    )
}

fn close_session_if_current(
    sessions: &DashMap<SocketAddr, Arc<ShimSession>>,
    client_addr: SocketAddr,
    session: &Arc<ShimSession>,
    metrics: &ShimMetrics,
    reason: SessionCloseReason,
) -> bool {
    let removed = sessions
        .remove_if(&client_addr, |_, current| Arc::ptr_eq(current, session))
        .is_some();
    if removed {
        session.close();
        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        match reason {
            SessionCloseReason::Idle => {
                metrics
                    .sessions_evicted_idle
                    .fetch_add(1, Ordering::Relaxed);
            }
            SessionCloseReason::SendFailure => {
                metrics
                    .sessions_evicted_send_failure
                    .fetch_add(1, Ordering::Relaxed);
            }
            SessionCloseReason::TableLimit => {
                metrics
                    .sessions_evicted_table_limit
                    .fetch_add(1, Ordering::Relaxed);
            }
            SessionCloseReason::Shutdown => {
                metrics
                    .sessions_closed_shutdown
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        session.span.in_scope(|| {
            info!(
                reason = reason.as_str(),
                session_id = session.id,
                upstream_port = session.upstream_port.load(Ordering::Relaxed),
                "WireGuard shim session closed"
            );
        });
    }
    removed
}

async fn drain_receiver_tasks(mut handles: Vec<JoinHandle<()>>, drain_timeout: Duration) {
    let deadline = Instant::now() + drain_timeout;
    for mut handle in handles.drain(..) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            handle.abort();
            let _ = handle.await;
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(remaining) => {
                handle.abort();
                let _ = handle.await;
            }
            _ = &mut handle => {}
        }
    }
}

#[cfg(feature = "metrics")]
async fn run_metrics_server(
    metrics_addr: SocketAddr,
    metrics: Arc<ShimMetrics>,
    shutdown: CancellationToken,
) {
    use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};

    async fn metrics_handler(State(metrics): State<Arc<ShimMetrics>>) -> impl IntoResponse {
        (
            [(
                header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            metrics.render_openmetrics(),
        )
    }

    let listener = match tokio::net::TcpListener::bind(metrics_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            warn!(%metrics_addr, %err, "failed to bind WireGuard shim metrics listener");
            return;
        }
    };
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
    {
        warn!(%metrics_addr, %err, "WireGuard shim metrics server failed");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::prelude::*;
    use tokio::{
        sync::oneshot,
        time::{sleep, timeout},
    };

    use super::*;
    use crate::{
        wg_packet_obfuscation::{
            decode_packet as decode_obfuscated_packet, encode_packet, EncryptionMode,
            MagicPositionMode, PacketPadding,
        },
        wg_relay,
    };

    fn test_obfuscation(magic_byte: Option<u8>) -> WgPacketObfuscation {
        WgPacketObfuscation::new(b"test-obfuscation-key".to_vec(), magic_byte)
    }

    fn test_shim_config() -> Arc<WgObfsShimConfig> {
        Arc::new(WgObfsShimConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([127, 0, 0, 1], 1)),
            test_obfuscation(None),
            Duration::from_secs(30),
        ))
    }

    fn test_session_for_limit(id: u64, last_activity_millis: u64) -> Arc<ShimSession> {
        let (upstream_tx, _upstream_rx) = mpsc::channel(1);
        Arc::new(ShimSession::new(
            id,
            test_shim_config(),
            upstream_tx,
            0,
            last_activity_millis,
            info_span!("test_session", session_id = id),
        ))
    }

    proptest! {
        #[test]
        fn session_table_never_exceeds_max_sessions(
            max_sessions in 1usize..32,
            arrivals in prop::collection::vec(any::<u16>(), 1..128),
        ) {
            let sessions = DashMap::new();
            let metrics = ShimMetrics::default();

            for (index, port) in arrivals.into_iter().enumerate() {
                let client_addr = SocketAddr::from(([127, 0, 0, 1], port.max(1)));
                if !sessions.contains_key(&client_addr) {
                    enforce_session_limit(&sessions, Some(max_sessions), &metrics, Some(client_addr)).unwrap();
                    let session = test_session_for_limit(index as u64 + 1, index as u64);
                    sessions.insert(client_addr, session);
                    metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
                }

                prop_assert!(sessions.len() <= max_sessions);
            }
        }
    }

    #[tokio::test]
    async fn session_activity_uses_atomic_epoch_millis() {
        let (upstream_tx, _upstream_rx) = mpsc::channel(1);
        let session = ShimSession::new(
            1,
            test_shim_config(),
            upstream_tx,
            40000,
            10,
            info_span!("test_session", client_addr = "127.0.0.1:1"),
        );

        assert_eq!(session.idle_for(15), Duration::from_millis(5));
        session.touch(100);
        assert_eq!(session.idle_for(125), Duration::from_millis(25));
    }

    #[test]
    fn token_bucket_limits_and_refills() {
        let mut bucket = TokenBucket::new(
            RateLimitConfig {
                packets_per_sec: 2,
                burst_packets: 2,
            },
            0,
        );

        assert!(bucket.try_take(0));
        assert!(bucket.try_take(0));
        assert!(!bucket.try_take(0));
        assert!(bucket.try_take(500));
        assert!(!bucket.try_take(500));
        assert!(bucket.try_take(1_000));
    }

    #[test]
    fn buffer_pool_returns_lease_on_drop() {
        let pool = Arc::new(UdpBufferPool::new(1));
        let lease = pool.lease();
        assert!(lease.is_some());
        assert!(pool.lease().is_none());
        drop(lease);
        assert!(pool.lease().is_some());
    }

    #[test]
    fn buffer_pool_wait_counter_records_elapsed_millis_when_pool_empty() {
        let pool = Arc::new(UdpBufferPool::new(1));
        let lease = pool.lease();
        let metrics = ShimMetrics::default();
        let wait_started = Instant::now() - Duration::from_millis(3);

        assert!(lease.is_some());
        assert!(pool.lease().is_none());
        record_buffer_pool_wait_since(&metrics, wait_started);

        assert!(
            metrics
                .buffer_pool_wait_millis_total
                .load(Ordering::Relaxed)
                >= 3
        );
    }

    #[test]
    fn server_rtt_uses_explicit_known_state() {
        let (upstream_tx, _upstream_rx) = mpsc::channel(1);
        let session = ShimSession::new(
            1,
            test_shim_config(),
            upstream_tx,
            40000,
            10,
            info_span!("test_session", client_addr = "127.0.0.1:1"),
        );

        assert_eq!(session.last_server_rtt_millis(), None);
        session.record_server_reply(10);
        assert_eq!(session.last_server_rtt_millis(), None);
        session.record_upstream_send(20);
        session.record_server_reply(20);
        assert_eq!(session.last_server_rtt_millis(), Some(0));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn shim_metrics_render_openmetrics() {
        let metrics = ShimMetrics::default();
        metrics.active_sessions.store(2, Ordering::Relaxed);
        metrics.packets_client_to_server.store(3, Ordering::Relaxed);
        metrics
            .buffer_pool_wait_millis_total
            .store(4, Ordering::Relaxed);

        let rendered = metrics.render_openmetrics();

        assert!(rendered.contains("wg_obfs_shim_active_sessions 2"));
        assert!(rendered
            .contains("wg_obfs_shim_packets_forwarded_total{direction=\"client_to_server\"} 3"));
        assert!(rendered.contains("wg_obfs_shim_buffer_pool_wait_millis_total 4"));
        assert!(rendered.ends_with("# EOF\n"));
    }

    #[test]
    fn cleanup_interval_uses_override_when_configured() {
        let config = WgObfsShimConfig {
            cleanup_interval: Some(Duration::from_secs(17)),
            ..WgObfsShimConfig::new(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                SocketAddr::from(([127, 0, 0, 1], 1)),
                test_obfuscation(Some(0xAA)),
                Duration::from_secs(300),
            )
        };

        assert_eq!(config.cleanup_interval(), Duration::from_secs(17));
    }

    #[tokio::test]
    async fn shim_obfuscates_plaintext_and_decodes_replies() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
            let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
            assert_eq!(decoded, b"handshake-init");
            let response = encode_packet(b"handshake-reply", &obfuscation);
            server_socket.send_to(&response, shim_peer).await.unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"handshake-init", listen_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"handshake-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_uses_distinct_upstream_ports_per_local_client() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..2 {
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
                let response = encode_packet(&decoded, &obfuscation);
                server_socket.send_to(&response, shim_peer).await.unwrap();
            }
            peers
        });

        let client_one = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let client_two = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();

        client_one.send_to(b"peer-one", listen_addr).await.unwrap();
        client_two.send_to(b"peer-two", listen_addr).await.unwrap();

        let mut buf_one = [0u8; 2048];
        let mut buf_two = [0u8; 2048];
        let (len_one, _) = timeout(Duration::from_secs(1), client_one.recv_from(&mut buf_one))
            .await
            .unwrap()
            .unwrap();
        let (len_two, _) = timeout(Duration::from_secs(1), client_two.recv_from(&mut buf_two))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf_one[..len_one], b"peer-one");
        assert_eq!(&buf_two[..len_two], b"peer-two");

        let peers = upstream.await.unwrap();
        let unique_peers: HashSet<_> = peers.into_iter().map(|peer| peer.port()).collect();
        assert_eq!(unique_peers.len(), 2);

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_evicts_idle_sessions_and_recreates_upstream_socket() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let mut config = WgObfsShimConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_millis(100),
        );
        config.cleanup_interval = Some(Duration::from_millis(20));
        let (listen_addr, shim_task) = spawn_with_config(config, shutdown.clone()).await.unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..2 {
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
                let response = encode_packet(&decoded, &obfuscation);
                server_socket.send_to(&response, shim_peer).await.unwrap();
            }
            peers
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"first-packet", listen_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        sleep(Duration::from_millis(250)).await;

        client.send_to(b"second-packet", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let peers = upstream.await.unwrap();
        assert_eq!(peers.len(), 2);
        assert_ne!(peers[0].port(), peers[1].port());

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_max_sessions_evicts_oldest_session() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let mut config = WgObfsShimConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(30),
        );
        config.max_sessions = Some(1);
        let (listen_addr, shim_task) = spawn_with_config(config, shutdown.clone()).await.unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..3 {
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
                server_socket
                    .send_to(&encode_packet(&decoded, &obfuscation), shim_peer)
                    .await
                    .unwrap();
            }
            peers
        });

        let client_one = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let client_two = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let mut buf = [0u8; 2048];

        client_one.send_to(b"first", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client_one.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        client_two.send_to(b"second", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client_two.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        client_one.send_to(b"third", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client_one.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let peers = upstream.await.unwrap();
        assert_ne!(peers[0].port(), peers[1].port());
        assert_ne!(peers[1].port(), peers[2].port());

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_rate_limits_upstream_sends_per_session() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let mut config = WgObfsShimConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(30),
        );
        config.rate_limit = RateLimitConfig::new(1, 1);
        let (listen_addr, shim_task) = spawn_with_config(config, shutdown.clone()).await.unwrap();

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"first", listen_addr).await.unwrap();
        client.send_to(b"second", listen_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), server_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap(),
            b"first"
        );
        assert!(timeout(
            Duration::from_millis(200),
            server_socket.recv_from(&mut buf)
        )
        .await
        .is_err());

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_drops_magic_byte_mismatch_replies() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(
                decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap(),
                b"first"
            );
            server_socket
                .send_to(b"reply-without-magic", shim_peer)
                .await
                .unwrap();

            let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(
                decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap(),
                b"second"
            );
            server_socket
                .send_to(&encode_packet(b"second-reply", &obfuscation), shim_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"first", listen_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(250), client.recv_from(&mut buf))
                .await
                .is_err()
        );

        client.send_to(b"second", listen_addr).await.unwrap();
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"second-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_creates_concurrent_sessions_for_distinct_clients() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let server_obfuscation = obfuscation.clone();
        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..50 {
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &server_obfuscation).unwrap();
                let mut response = b"reply-".to_vec();
                response.extend_from_slice(&decoded);
                server_socket
                    .send_to(&encode_packet(&response, &server_obfuscation), shim_peer)
                    .await
                    .unwrap();
            }
            peers
        });

        let mut clients = Vec::new();
        for index in 0..50 {
            let payload = format!("client-{index}").into_bytes();
            clients.push(tokio::spawn(async move {
                let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap();
                client.send_to(&payload, listen_addr).await.unwrap();
                let mut buf = [0u8; 2048];
                let (len, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                let mut expected = b"reply-".to_vec();
                expected.extend_from_slice(&payload);
                assert_eq!(&buf[..len], expected.as_slice());
            }));
        }

        for client in clients {
            client.await.unwrap();
        }
        let peers = upstream.await.unwrap();
        let unique_ports = peers
            .into_iter()
            .map(|peer| peer.port())
            .collect::<HashSet<_>>();
        assert_eq!(unique_ports.len(), 50);

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_shutdown_mid_flight_exits_cleanly() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation,
            Duration::from_secs(30),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let (received_tx, received_rx) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let _ = server_socket.recv_from(&mut buf).await.unwrap();
            let _ = received_tx.send(());
            sleep(Duration::from_millis(100)).await;
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"in-flight", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), received_rx)
            .await
            .unwrap()
            .unwrap();
        shutdown.cancel();

        timeout(Duration::from_secs(2), shim_task)
            .await
            .unwrap()
            .unwrap();
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn shim_forwards_ipv6_loopback_packets() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            "[::1]:0".parse::<SocketAddr>().unwrap(),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(
                decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap(),
                b"ipv6"
            );
            server_socket
                .send_to(&encode_packet(b"ipv6-reply", &obfuscation), shim_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        client.send_to(b"ipv6", listen_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"ipv6-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_and_relay_round_trip_with_aead_framing() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA))
            .with_encryption_mode(EncryptionMode::Aead)
            .with_padding(PacketPadding::PowerOfTwo)
            .with_magic_position(MagicPositionMode::Randomized);

        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_server_addr, relay_task) = wg_relay::spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let (shim_listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            public_server_addr,
            obfuscation,
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"aead-handshake");
            internal_socket
                .send_to(b"aead-reply", relay_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"aead-handshake", shim_listen_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"aead-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_and_server_relay_round_trip_end_to_end() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));

        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_server_addr, relay_task) = wg_relay::spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let (shim_listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            public_server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"end-to-end-handshake");
            internal_socket
                .send_to(b"end-to-end-reply", relay_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"end-to-end-handshake", shim_listen_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"end-to-end-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
        relay_task.await.unwrap();
    }
}
