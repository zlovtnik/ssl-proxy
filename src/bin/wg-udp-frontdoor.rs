use axum::{
    extract::State,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use dashmap::{mapref::entry::Entry, DashMap};
use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};
use rand::Rng;
use serde::{Deserialize, Serialize};
use ssl_proxy::{
    udp_tuning::{bind_tuned_udp_socket, DEFAULT_UDP_SOCKET_BUFFER_BYTES},
    wg_packet_obfuscation::MAX_UDP_PACKET_SIZE,
};
use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{lookup_host, UdpSocket},
    signal,
    sync::{mpsc, Mutex, RwLock},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_CONFIG_FILE: &str = "/run/wg-rotation/frontdoor/wg-udp-frontdoor.toml";
const DEFAULT_HEALTH_ADDR: &str = "0.0.0.0:3003";
const DEFAULT_SESSION_IDLE_SECS: u64 = 300;
const DEFAULT_MAX_SESSIONS: usize = 65_536;
const DEFAULT_MAX_DATAGRAM_BYTES: usize = 1500;
const DEFAULT_DISPATCH_TASK_LIMIT: usize = 4096;
const MAX_DISPATCH_WORKERS: usize = 32;
const RATE_LIMITER_SHARDS: usize = 64;
const RATE_LIMITER_STALE_SOURCE_SECS: u64 = 0;

#[derive(Clone, Debug, Deserialize)]
struct FrontdoorConfig {
    #[serde(default)]
    listeners: Vec<ListenerConfig>,
    #[serde(default)]
    backends: Vec<BackendConfig>,
}

#[derive(Clone, Debug, Deserialize)]
struct ListenerConfig {
    name: String,
    bind_addr: SocketAddr,
    #[serde(default)]
    backends: Vec<String>,
    #[serde(default, alias = "session_idle")]
    session_idle_secs: Option<u64>,
    #[serde(default)]
    jitter_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct BackendConfig {
    name: String,
    addr: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Clone, Debug)]
struct RuntimeOptions {
    config_file: PathBuf,
    health_addr: SocketAddr,
    session_idle: Duration,
    rate_limit_pps: u64,
    max_sessions: usize,
    max_datagram_bytes: usize,
    dispatch_task_limit: usize,
    udp_socket_buffer_bytes: usize,
}

#[derive(Clone)]
struct RuntimeState {
    config: Arc<RwLock<FrontdoorConfig>>,
    resolved_backends: Arc<RwLock<HashMap<String, SocketAddr>>>,
    sessions: Arc<DashMap<SessionKey, Arc<BackendSession>>>,
    routes: Arc<DashMap<ClientRouteKey, PinnedRoute>>,
    session_admission: Arc<Mutex<()>>,
    rate_limiter: Arc<ShardedRateLimiter>,
    stats: Arc<FrontdoorStats>,
    prometheus_registry: Arc<Registry>,
    session_idle: Duration,
    max_sessions: usize,
    max_datagram_bytes: usize,
    dispatch_task_limit: usize,
    udp_socket_buffer_bytes: usize,
}

struct DispatchPacket {
    buffer: FrontdoorBufferLease,
    len: usize,
    client_addr: SocketAddr,
    received_at: Instant,
}

impl DispatchPacket {
    fn bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

struct FrontdoorBufferPool {
    buffers: StdMutex<Vec<Box<[u8]>>>,
}

impl FrontdoorBufferPool {
    fn new(capacity: usize, buffer_len: usize) -> Arc<Self> {
        let mut buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buffers.push(vec![0_u8; buffer_len].into_boxed_slice());
        }
        Arc::new(Self {
            buffers: StdMutex::new(buffers),
        })
    }

    fn lease(self: &Arc<Self>) -> Option<FrontdoorBufferLease> {
        let buffer = self
            .buffers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop()?;
        Some(FrontdoorBufferLease {
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

struct FrontdoorBufferLease {
    buffer: Option<Box<[u8]>>,
    pool: Arc<FrontdoorBufferPool>,
}

impl std::ops::Deref for FrontdoorBufferLease {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer.as_deref().expect("frontdoor buffer is leased")
    }
}

impl std::ops::DerefMut for FrontdoorBufferLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer
            .as_deref_mut()
            .expect("frontdoor buffer is leased")
    }
}

impl Drop for FrontdoorBufferLease {
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

#[derive(Clone)]
struct BackendSession {
    socket: Arc<UdpSocket>,
    last_activity_epoch: Arc<AtomicU64>,
    session_idle: Duration,
    jitter_ms: u64,
    cancellation: CancellationToken,
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct ClientRouteKey {
    listener: Arc<str>,
    client_addr: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackendRoute {
    backend_name: String,
    backend_addr: String,
}

#[derive(Clone)]
struct PinnedRoute {
    route: BackendRoute,
    session: Arc<BackendSession>,
}

#[derive(Clone, Eq)]
struct SessionKey {
    listener: Arc<str>,
    client_addr: SocketAddr,
    backend_name: String,
    backend_addr: String,
    resolved_backend_addr: SocketAddr,
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.listener == other.listener
            && self.client_addr == other.client_addr
            && self.backend_name == other.backend_name
            && self.backend_addr == other.backend_addr
            && self.resolved_backend_addr == other.resolved_backend_addr
    }
}

impl Hash for SessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.listener.hash(state);
        self.client_addr.hash(state);
        self.backend_name.hash(state);
        self.backend_addr.hash(state);
        self.resolved_backend_addr.hash(state);
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("listener", &self.listener)
            .field("client_addr", &self.client_addr)
            .field("backend_name", &self.backend_name)
            .field("backend_addr", &self.backend_addr)
            .field("resolved_backend_addr", &self.resolved_backend_addr)
            .finish()
    }
}

struct FrontdoorStats {
    client_packets: AtomicU64,
    backend_packets: AtomicU64,
    client_bytes: AtomicU64,
    backend_bytes: AtomicU64,
    dropped_rate_limited: AtomicU64,
    dropped_dispatch_saturated: AtomicU64,
    dispatch_queue_depth: AtomicU64,
    dispatch_queue_high_watermark: AtomicU64,
    session_creations: AtomicU64,
    sessions_evicted: AtomicU64,
    reload_successes: AtomicU64,
    reload_failures: AtomicU64,
    sessions_gauge: IntGauge,
    client_packets_counter: IntCounter,
    backend_packets_counter: IntCounter,
    client_bytes_counter: IntCounter,
    backend_bytes_counter: IntCounter,
    dropped_rate_limited_counter: IntCounter,
    dropped_dispatch_saturated_counter: IntCounter,
    dispatch_queue_depth_gauge: IntGauge,
    dispatch_queue_high_watermark_gauge: IntGauge,
    session_creations_counter: IntCounter,
    sessions_evicted_counter: IntCounter,
    reload_successes_counter: IntCounter,
    reload_failures_counter: IntCounter,
    forward_latency_us: Histogram,
    session_create_latency_ms: Histogram,
    dns_resolve_latency_ms: Histogram,
}

struct ShardedRateLimiter {
    limit_pps: u64,
    shards: [Mutex<RateLimiter>; RATE_LIMITER_SHARDS],
}

#[derive(Default)]
struct RateLimiter {
    limit_pps: u64,
    sources: HashMap<IpAddr, RateWindow>,
    last_cleanup_second: u64,
}

#[derive(Clone, Copy)]
struct RateWindow {
    second: u64,
    count: u64,
}

impl FrontdoorStats {
    fn new(registry: &Registry) -> Result<Self, FrontdoorError> {
        Ok(Self {
            client_packets: AtomicU64::new(0),
            backend_packets: AtomicU64::new(0),
            client_bytes: AtomicU64::new(0),
            backend_bytes: AtomicU64::new(0),
            dropped_rate_limited: AtomicU64::new(0),
            dropped_dispatch_saturated: AtomicU64::new(0),
            dispatch_queue_depth: AtomicU64::new(0),
            dispatch_queue_high_watermark: AtomicU64::new(0),
            session_creations: AtomicU64::new(0),
            sessions_evicted: AtomicU64::new(0),
            reload_successes: AtomicU64::new(0),
            reload_failures: AtomicU64::new(0),
            sessions_gauge: register_int_gauge(
                registry,
                "wg_frontdoor_sessions",
                "Active client/backend UDP sessions.",
            )?,
            client_packets_counter: register_int_counter(
                registry,
                "wg_frontdoor_client_packets_total",
                "Client packets received.",
            )?,
            backend_packets_counter: register_int_counter(
                registry,
                "wg_frontdoor_backend_packets_total",
                "Backend packets sent.",
            )?,
            client_bytes_counter: register_int_counter(
                registry,
                "wg_frontdoor_client_bytes_total",
                "Client bytes received.",
            )?,
            backend_bytes_counter: register_int_counter(
                registry,
                "wg_frontdoor_backend_bytes_total",
                "Backend bytes sent.",
            )?,
            dropped_rate_limited_counter: register_int_counter(
                registry,
                "wg_frontdoor_dropped_rate_limited_total",
                "Client packets dropped by source rate limit.",
            )?,
            dropped_dispatch_saturated_counter: register_int_counter(
                registry,
                "wg_frontdoor_dropped_dispatch_saturated_total",
                "Client packets dropped because dispatch queues were saturated.",
            )?,
            dispatch_queue_depth_gauge: register_int_gauge(
                registry,
                "wg_frontdoor_dispatch_queue_depth",
                "Datagrams currently waiting in frontdoor dispatch queues.",
            )?,
            dispatch_queue_high_watermark_gauge: register_int_gauge(
                registry,
                "wg_frontdoor_dispatch_queue_high_watermark",
                "Highest observed frontdoor dispatch queue depth.",
            )?,
            session_creations_counter: register_int_counter(
                registry,
                "wg_frontdoor_session_creations_total",
                "Backend sessions created.",
            )?,
            sessions_evicted_counter: register_int_counter(
                registry,
                "wg_frontdoor_sessions_evicted_total",
                "Backend sessions evicted by the global session cap.",
            )?,
            reload_successes_counter: register_int_counter(
                registry,
                "wg_frontdoor_config_reload_success_total",
                "Successful config reloads.",
            )?,
            reload_failures_counter: register_int_counter(
                registry,
                "wg_frontdoor_config_reload_failure_total",
                "Failed config reloads.",
            )?,
            forward_latency_us: register_histogram(
                registry,
                "wg_frontdoor_forward_latency_us",
                "Latency from client packet receipt to backend send completion in microseconds.",
                vec![50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0],
            )?,
            session_create_latency_ms: register_histogram(
                registry,
                "wg_frontdoor_session_create_latency_ms",
                "Latency to create a backend UDP session in milliseconds.",
                vec![1.0, 5.0, 10.0, 50.0, 100.0, 500.0],
            )?,
            dns_resolve_latency_ms: register_histogram(
                registry,
                "wg_frontdoor_dns_resolve_latency_ms",
                "Latency to resolve backend DNS in milliseconds.",
                vec![1.0, 5.0, 10.0, 50.0, 100.0, 500.0],
            )?,
        })
    }

    fn set_sessions(&self, sessions: usize) {
        self.sessions_gauge.set(sessions as i64);
    }

    fn record_client_packet(&self, bytes: usize) {
        self.client_packets.fetch_add(1, Ordering::Relaxed);
        self.client_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.client_packets_counter.inc();
        self.client_bytes_counter.inc_by(bytes as u64);
    }

    fn record_backend_packet(&self, bytes: usize) {
        self.backend_packets.fetch_add(1, Ordering::Relaxed);
        self.backend_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.backend_packets_counter.inc();
        self.backend_bytes_counter.inc_by(bytes as u64);
    }

    fn record_rate_limited_drop(&self) {
        self.dropped_rate_limited.fetch_add(1, Ordering::Relaxed);
        self.dropped_rate_limited_counter.inc();
    }

    fn record_dispatch_saturated_drop(&self) {
        self.dropped_dispatch_saturated
            .fetch_add(1, Ordering::Relaxed);
        self.dropped_dispatch_saturated_counter.inc();
    }

    fn record_dispatch_queued(&self) {
        let depth = self.dispatch_queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        self.dispatch_queue_depth_gauge.set(depth as i64);
        let mut current = self.dispatch_queue_high_watermark.load(Ordering::Relaxed);
        while depth > current {
            match self.dispatch_queue_high_watermark.compare_exchange_weak(
                current,
                depth,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.dispatch_queue_high_watermark_gauge.set(depth as i64);
                    break;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn record_dispatch_dequeued(&self) {
        let previous = self
            .dispatch_queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            })
            .unwrap_or(0);
        self.dispatch_queue_depth_gauge
            .set(previous.saturating_sub(1) as i64);
    }

    fn record_session_creation(&self) {
        self.session_creations.fetch_add(1, Ordering::Relaxed);
        self.session_creations_counter.inc();
    }

    fn record_session_eviction(&self) {
        self.sessions_evicted.fetch_add(1, Ordering::Relaxed);
        self.sessions_evicted_counter.inc();
    }

    fn record_reload_success(&self) {
        self.reload_successes.fetch_add(1, Ordering::Relaxed);
        self.reload_successes_counter.inc();
    }

    fn record_reload_failure(&self) {
        self.reload_failures.fetch_add(1, Ordering::Relaxed);
        self.reload_failures_counter.inc();
    }

    fn observe_forward_latency(&self, elapsed: Duration) {
        self.forward_latency_us.observe(elapsed.as_micros() as f64);
    }

    fn observe_session_create_latency(&self, elapsed: Duration) {
        self.session_create_latency_ms
            .observe(elapsed.as_millis() as f64);
    }

    fn observe_dns_resolve_latency(&self, elapsed: Duration) {
        self.dns_resolve_latency_ms
            .observe(elapsed.as_millis() as f64);
    }
}

fn register_int_counter(
    registry: &Registry,
    name: &str,
    help: &str,
) -> Result<IntCounter, FrontdoorError> {
    let counter = IntCounter::new(name, help)?;
    registry.register(Box::new(counter.clone()))?;
    Ok(counter)
}

fn register_int_gauge(
    registry: &Registry,
    name: &str,
    help: &str,
) -> Result<IntGauge, FrontdoorError> {
    let gauge = IntGauge::new(name, help)?;
    registry.register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

fn register_histogram(
    registry: &Registry,
    name: &str,
    help: &str,
    buckets: Vec<f64>,
) -> Result<Histogram, FrontdoorError> {
    let histogram = Histogram::with_opts(HistogramOpts::new(name, help).buckets(buckets))?;
    registry.register(Box::new(histogram.clone()))?;
    Ok(histogram)
}

#[derive(Debug)]
enum FrontdoorError {
    Config(String),
    Io(std::io::Error),
    Toml(toml::de::Error),
    Addr(std::net::AddrParseError),
    Metrics(prometheus::Error),
}

impl fmt::Display for FrontdoorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "{message}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Toml(error) => write!(f, "{error}"),
            Self::Addr(error) => write!(f, "{error}"),
            Self::Metrics(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for FrontdoorError {}

impl From<std::io::Error> for FrontdoorError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for FrontdoorError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

impl From<std::net::AddrParseError> for FrontdoorError {
    fn from(value: std::net::AddrParseError) -> Self {
        Self::Addr(value)
    }
}

impl From<prometheus::Error> for FrontdoorError {
    fn from(value: prometheus::Error) -> Self {
        Self::Metrics(value)
    }
}

#[tokio::main]
async fn main() {
    init_tracing();

    let options = match RuntimeOptions::from_env() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("wg-udp-frontdoor configuration error: {error}");
            std::process::exit(2);
        }
    };

    let config = match load_or_default_config(&options.config_file, options.session_idle) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load {:?}: {error}", options.config_file);
            std::process::exit(2);
        }
    };

    if let Err(error) = validate_runtime_config(&config, options.session_idle) {
        eprintln!("invalid frontdoor config: {error}");
        std::process::exit(2);
    }

    let prometheus_registry = Arc::new(Registry::new());
    let stats = match FrontdoorStats::new(&prometheus_registry) {
        Ok(stats) => Arc::new(stats),
        Err(error) => {
            eprintln!("failed to initialize frontdoor metrics: {error}");
            std::process::exit(2);
        }
    };

    let resolved_backends = match resolve_enabled_backend_cache(&config, None, &stats).await {
        Ok(cache) => cache,
        Err(error) => {
            eprintln!("failed to resolve enabled frontdoor backends: {error}");
            std::process::exit(2);
        }
    };

    let state = RuntimeState {
        config: Arc::new(RwLock::new(config.clone())),
        resolved_backends: Arc::new(RwLock::new(resolved_backends)),
        sessions: Arc::new(DashMap::new()),
        routes: Arc::new(DashMap::new()),
        session_admission: Arc::new(Mutex::new(())),
        rate_limiter: Arc::new(ShardedRateLimiter::new(options.rate_limit_pps)),
        stats,
        prometheus_registry,
        session_idle: options.session_idle,
        max_sessions: options.max_sessions,
        max_datagram_bytes: options.max_datagram_bytes,
        dispatch_task_limit: options.dispatch_task_limit,
        udp_socket_buffer_bytes: options.udp_socket_buffer_bytes,
    };

    let mut tasks = JoinSet::new();
    for listener in config.listeners {
        let listener_state = state.clone();
        tasks.spawn(async move {
            if let Err(error) = run_listener(listener, listener_state).await {
                error!(%error, "frontdoor listener stopped");
                Err::<(), FrontdoorError>(error)
            } else {
                Ok(())
            }
        });
    }

    tasks.spawn(run_health_server(options.health_addr, state.clone()));
    tasks.spawn(run_reload_task(options.config_file.clone(), state.clone()));

    loop {
        tokio::select! {
            signal_result = signal::ctrl_c() => {
                match signal_result {
                    Ok(()) => info!("shutdown signal received"),
                    Err(error) => error!(%error, "failed to install shutdown signal handler"),
                }
                break;
            }
            task_result = tasks.join_next() => {
                match task_result {
                    Some(Ok(Ok(()))) => {
                        warn!("frontdoor task exited");
                        break;
                    }
                    Some(Ok(Err(error))) => {
                        error!(%error, "frontdoor task failed");
                        std::process::exit(1);
                    }
                    Some(Err(error)) => {
                        error!(%error, "frontdoor task panicked");
                        std::process::exit(1);
                    }
                    None => break,
                }
            }
        }
    }
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "wg_udp_frontdoor=info".into());
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

impl RuntimeOptions {
    fn from_env() -> Result<Self, FrontdoorError> {
        let config_file = std::env::var("WG_FRONTDOOR_CONFIG_FILE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_CONFIG_FILE.to_string());
        let health_addr = std::env::var("WG_FRONTDOOR_HEALTH_ADDR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_HEALTH_ADDR.to_string())
            .parse()?;
        let idle_secs =
            read_u64_env("WG_FRONTDOOR_SESSION_IDLE_SECS", DEFAULT_SESSION_IDLE_SECS).max(1);
        let rate_limit_pps = read_u64_env("WG_FRONTDOOR_RATE_LIMIT_PPS", 0);
        let max_sessions = read_usize_env(
            "WG_FRONTDOOR_MAX_SESSIONS",
            DEFAULT_MAX_SESSIONS,
            1,
            usize::MAX,
        )?;
        let max_datagram_bytes = read_usize_env(
            "WG_OBFUSCATION_MAX_DATAGRAM_BYTES",
            DEFAULT_MAX_DATAGRAM_BYTES,
            1,
            MAX_UDP_PACKET_SIZE,
        )?;
        let dispatch_task_limit = read_usize_env(
            "WG_FRONTDOOR_DISPATCH_TASK_LIMIT",
            DEFAULT_DISPATCH_TASK_LIMIT,
            1,
            usize::MAX,
        )?;
        let udp_socket_buffer_bytes = read_usize_env(
            "WG_UDP_SOCKET_BUFFER_BYTES",
            DEFAULT_UDP_SOCKET_BUFFER_BYTES,
            1,
            usize::MAX,
        )?;

        Ok(Self {
            config_file: PathBuf::from(config_file),
            health_addr,
            session_idle: Duration::from_secs(idle_secs),
            rate_limit_pps,
            max_sessions,
            max_datagram_bytes,
            dispatch_task_limit,
            udp_socket_buffer_bytes,
        })
    }
}

fn read_u64_env(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(default)
}

fn read_usize_env(
    var: &str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, FrontdoorError> {
    let Some(raw) = std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(default);
    };
    let parsed = raw.parse::<usize>().map_err(|_| {
        FrontdoorError::Config(format!(
            "{var} must be an integer from {min} to {max}; got {raw:?}"
        ))
    })?;
    if parsed < min || parsed > max {
        return Err(FrontdoorError::Config(format!(
            "{var} must be an integer from {min} to {max}; got {raw:?}"
        )));
    }
    Ok(parsed)
}

fn default_enabled() -> bool {
    true
}

impl ListenerConfig {
    fn session_idle_or(&self, default: Duration) -> Duration {
        self.session_idle_secs
            .map(Duration::from_secs)
            .unwrap_or(default)
    }
}

fn load_or_default_config(
    path: &Path,
    default_session_idle: Duration,
) -> Result<FrontdoorConfig, FrontdoorError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse_config_with_session_idle(&contents, default_session_idle),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            warn!(
                config_file = ?path,
                "frontdoor config file missing; using active-only built-in defaults"
            );
            let config = default_config();
            validate_config_with_session_idle(&config, default_session_idle)?;
            Ok(config)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
fn parse_config(contents: &str) -> Result<FrontdoorConfig, FrontdoorError> {
    parse_config_with_session_idle(contents, Duration::from_secs(DEFAULT_SESSION_IDLE_SECS))
}

fn parse_config_with_session_idle(
    contents: &str,
    default_session_idle: Duration,
) -> Result<FrontdoorConfig, FrontdoorError> {
    let config: FrontdoorConfig = toml::from_str(contents)?;
    validate_config_with_session_idle(&config, default_session_idle)?;
    Ok(config)
}

fn validate_runtime_config(
    config: &FrontdoorConfig,
    default_session_idle: Duration,
) -> Result<(), FrontdoorError> {
    validate_config_with_session_idle(config, default_session_idle)
}

fn default_config() -> FrontdoorConfig {
    FrontdoorConfig {
        listeners: vec![
            ListenerConfig {
                name: "wg-public-443".to_string(),
                bind_addr: "0.0.0.0:443"
                    .parse()
                    .expect("default WireGuard port is valid"),
                backends: vec!["active-443".to_string()],
                session_idle_secs: None,
                jitter_ms: 0,
            },
            ListenerConfig {
                name: "wg-public-51820".to_string(),
                bind_addr: "0.0.0.0:51820"
                    .parse()
                    .expect("default WireGuard port is valid"),
                backends: vec!["active-51820".to_string()],
                session_idle_secs: None,
                jitter_ms: 0,
            },
        ],
        backends: vec![
            BackendConfig {
                name: "active-443".to_string(),
                addr: "ssl-proxy:443".to_string(),
                enabled: true,
            },
            BackendConfig {
                name: "active-51820".to_string(),
                addr: "ssl-proxy:51820".to_string(),
                enabled: true,
            },
        ],
    }
}

fn validate_config_with_session_idle(
    config: &FrontdoorConfig,
    default_session_idle: Duration,
) -> Result<(), FrontdoorError> {
    if config.listeners.is_empty() {
        return Err(FrontdoorError::Config(
            "at least one listener is required".to_string(),
        ));
    }
    if config.backends.is_empty() {
        return Err(FrontdoorError::Config(
            "at least one backend is required".to_string(),
        ));
    }

    let mut backend_names = HashMap::new();
    for backend in &config.backends {
        if backend.name.trim().is_empty() {
            return Err(FrontdoorError::Config(
                "backend name must not be empty".to_string(),
            ));
        }
        if backend.addr.trim().is_empty() {
            return Err(FrontdoorError::Config(format!(
                "backend {} addr must not be empty",
                backend.name
            )));
        }
        if backend_names.insert(backend.name.as_str(), true).is_some() {
            return Err(FrontdoorError::Config(format!(
                "duplicate backend name {}",
                backend.name
            )));
        }
    }

    let mut listener_names = HashMap::new();
    for listener in &config.listeners {
        if listener.name.trim().is_empty() {
            return Err(FrontdoorError::Config(
                "listener name must not be empty".to_string(),
            ));
        }
        if listener_names
            .insert(listener.name.as_str(), true)
            .is_some()
        {
            return Err(FrontdoorError::Config(format!(
                "duplicate listener name {}",
                listener.name
            )));
        }
        if listener.backends.is_empty() {
            return Err(FrontdoorError::Config(format!(
                "listener {} has no backends",
                listener.name
            )));
        }
        if listener.session_idle_secs.is_some_and(|secs| secs == 0) {
            return Err(FrontdoorError::Config(format!(
                "listener {} session_idle must be at least 1 second",
                listener.name
            )));
        }
        let session_idle_ms =
            u64::try_from(listener.session_idle_or(default_session_idle).as_millis())
                .unwrap_or(u64::MAX);
        if listener.jitter_ms >= session_idle_ms {
            return Err(FrontdoorError::Config(format!(
                "listener {} jitter_ms must be less than session_idle in milliseconds",
                listener.name
            )));
        }
        for backend in &listener.backends {
            if !backend_names.contains_key(backend.as_str()) {
                return Err(FrontdoorError::Config(format!(
                    "listener {} references unknown backend {}",
                    listener.name, backend
                )));
            }
        }
    }

    Ok(())
}

async fn run_listener(listener: ListenerConfig, state: RuntimeState) -> Result<(), FrontdoorError> {
    let socket = bind_tuned_udp_socket(
        listener.bind_addr,
        state.udp_socket_buffer_bytes,
        "wg-frontdoor-listener",
    )?;
    run_listener_with_socket(listener, state, socket).await
}

async fn run_listener_with_socket(
    listener: ListenerConfig,
    state: RuntimeState,
    socket: UdpSocket,
) -> Result<(), FrontdoorError> {
    let bind_addr = socket.local_addr()?;
    let socket = Arc::new(socket);
    info!(
        listener = %listener.name,
        %bind_addr,
        "WireGuard UDP frontdoor listener started"
    );

    let mut buf = vec![0_u8; state.max_datagram_bytes];
    let listener_name: Arc<str> = Arc::from(listener.name.clone());
    let worker_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, MAX_DISPATCH_WORKERS)
        .min(state.dispatch_task_limit);
    let worker_queue_capacity = state.dispatch_task_limit.div_ceil(worker_count);
    let buffer_pool = FrontdoorBufferPool::new(state.dispatch_task_limit, state.max_datagram_bytes);
    let mut dispatch_senders = Vec::with_capacity(worker_count);
    let base_capacity = state.dispatch_task_limit / worker_count;
    let remainder = state.dispatch_task_limit % worker_count;
    for worker_index in 0..worker_count {
        let capacity = base_capacity + usize::from(worker_index < remainder);
        let (tx, rx) = mpsc::channel(capacity);
        dispatch_senders.push(tx);
        tokio::spawn(run_dispatch_worker(
            listener_name.clone(),
            socket.clone(),
            state.clone(),
            rx,
        ));
    }
    info!(
        listener = %listener_name,
        worker_count,
        worker_queue_capacity,
        total_queue_capacity = state.dispatch_task_limit,
        "WireGuard UDP frontdoor dispatch workers started"
    );

    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;
        if !state.rate_limiter.allow(client_addr).await {
            state.stats.record_rate_limited_drop();
            debug!(%client_addr, listener = %listener_name, "dropping rate-limited packet");
            continue;
        }
        state.stats.record_client_packet(len);

        let Some(mut buffer) = buffer_pool.lease() else {
            state.stats.record_dispatch_saturated_drop();
            debug!(
                %client_addr,
                listener = %listener_name,
                "dropping client packet; dispatch buffer pool exhausted"
            );
            continue;
        };
        buffer[..len].copy_from_slice(&buf[..len]);
        let received_at = Instant::now();
        let worker_index = dispatch_worker_index(client_addr, worker_count);
        let packet = DispatchPacket {
            buffer,
            len,
            client_addr,
            received_at,
        };
        state.stats.record_dispatch_queued();
        match dispatch_senders[worker_index].try_send(packet) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                state.stats.record_dispatch_dequeued();
                state.stats.record_dispatch_saturated_drop();
                debug!(
                    %client_addr,
                    listener = %listener_name,
                    worker_index,
                    "dropping client packet; dispatch queue is full"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                state.stats.record_dispatch_dequeued();
                return Err(FrontdoorError::Config(format!(
                    "listener {listener_name} dispatch worker {worker_index} stopped"
                )));
            }
        }
    }
}

fn dispatch_worker_index(client_addr: SocketAddr, worker_count: usize) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    client_addr.hash(&mut hasher);
    hasher.finish() as usize % worker_count.max(1)
}

async fn run_dispatch_worker(
    listener_name: Arc<str>,
    listener_socket: Arc<UdpSocket>,
    state: RuntimeState,
    mut packets: mpsc::Receiver<DispatchPacket>,
) {
    while let Some(packet) = packets.recv().await {
        state.stats.record_dispatch_dequeued();
        dispatch_client_packet(
            &listener_name,
            packet.client_addr,
            &packet,
            packet.received_at,
            listener_socket.clone(),
            state.clone(),
        )
        .await;
    }
}

async fn dispatch_client_packet(
    listener_name: &Arc<str>,
    client_addr: SocketAddr,
    packet: &DispatchPacket,
    received_at: Instant,
    listener_socket: Arc<UdpSocket>,
    state: RuntimeState,
) {
    let route_key = ClientRouteKey {
        listener: listener_name.clone(),
        client_addr,
    };
    if let Some(session) = state
        .routes
        .get(&route_key)
        .map(|pinned| pinned.session.clone())
    {
        forward_packet_to_session(
            &session,
            packet,
            received_at,
            client_addr,
            "pinned",
            &state.stats,
        )
        .await;
        return;
    }

    let Some((listener_session_idle, jitter_ms, backends)) =
        dispatch_config_for_listener(&state, listener_name.as_ref()).await
    else {
        warn!(listener = %listener_name, "dropping client packet; listener no longer exists");
        return;
    };
    if backends.is_empty() {
        warn!(listener = %listener_name, "dropping client packet; no enabled backends");
        return;
    }

    for backend in
        route_backends_for_client(&state, listener_name.clone(), client_addr, backends).await
    {
        match get_or_create_session(
            listener_name.clone(),
            listener_session_idle,
            jitter_ms,
            client_addr,
            &backend,
            listener_socket.clone(),
            state.clone(),
        )
        .await
        {
            Ok(session) => {
                forward_packet_to_session(
                    &session,
                    packet,
                    received_at,
                    client_addr,
                    &backend.name,
                    &state.stats,
                )
                .await;
            }
            Err(error) => warn!(
                %error,
                %client_addr,
                backend = %backend.name,
                "failed to create backend session"
            ),
        }
    }
}

async fn forward_packet_to_session(
    session: &BackendSession,
    packet: &DispatchPacket,
    received_at: Instant,
    client_addr: SocketAddr,
    backend_name: &str,
    stats: &FrontdoorStats,
) {
    session
        .last_activity_epoch
        .store(now_epoch_secs(), Ordering::Relaxed);
    apply_jitter(session.jitter_ms).await;
    if let Err(error) = session.socket.send(packet.bytes()).await {
        warn!(
            %error,
            %client_addr,
            backend = %backend_name,
            "failed to send packet to backend"
        );
    } else {
        stats.record_backend_packet(packet.len);
        stats.observe_forward_latency(received_at.elapsed());
    }
}

async fn dispatch_config_for_listener(
    state: &RuntimeState,
    listener_name: &str,
) -> Option<(Duration, u64, Vec<BackendConfig>)> {
    let config = state.config.read().await;
    let listener = config
        .listeners
        .iter()
        .find(|listener| listener.name == listener_name)?;

    let session_idle = listener.session_idle_or(state.session_idle);
    let backends = listener
        .backends
        .iter()
        .filter_map(|name| config.backends.iter().find(|backend| backend.name == *name))
        .filter(|backend| backend.enabled)
        .cloned()
        .collect();
    Some((session_idle, listener.jitter_ms, backends))
}

async fn route_backends_for_client(
    state: &RuntimeState,
    listener_name: Arc<str>,
    client_addr: SocketAddr,
    enabled_backends: Vec<BackendConfig>,
) -> Vec<BackendConfig> {
    let route_key = ClientRouteKey {
        listener: listener_name.clone(),
        client_addr,
    };
    let Some(route) = state.routes.get(&route_key).map(|route| route.clone()) else {
        return enabled_backends;
    };

    if let Some(backend) = enabled_backends.iter().find(|backend| {
        backend.name == route.route.backend_name && backend.addr == route.route.backend_addr
    }) {
        return vec![backend.clone()];
    }

    state.routes.remove(&route_key);
    enabled_backends
}

async fn get_or_create_session(
    listener_name: Arc<str>,
    listener_session_idle: Duration,
    jitter_ms: u64,
    client_addr: SocketAddr,
    backend: &BackendConfig,
    listener_socket: Arc<UdpSocket>,
    state: RuntimeState,
) -> Result<Arc<BackendSession>, FrontdoorError> {
    let resolved_backend_addr = cached_backend_addr(&state, &backend.addr).await?;
    let key = SessionKey {
        listener: listener_name,
        client_addr,
        backend_name: backend.name.clone(),
        backend_addr: backend.addr.clone(),
        resolved_backend_addr,
    };

    if let Some(session) = state.sessions.get(&key).map(|session| session.clone()) {
        return Ok(session);
    }

    let session_create_started = Instant::now();
    let bind_addr = if resolved_backend_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let backend_socket = Arc::new(bind_tuned_udp_socket(
        bind_addr.parse().expect("static UDP bind address is valid"),
        state.udp_socket_buffer_bytes,
        "wg-frontdoor-backend",
    )?);
    backend_socket.connect(resolved_backend_addr).await?;
    state
        .stats
        .observe_session_create_latency(session_create_started.elapsed());

    let session = Arc::new(BackendSession {
        socket: backend_socket.clone(),
        last_activity_epoch: Arc::new(AtomicU64::new(now_epoch_secs())),
        session_idle: listener_session_idle,
        jitter_ms,
        cancellation: CancellationToken::new(),
    });

    {
        let _admission = state.session_admission.lock().await;
        if let Some(existing) = state.sessions.get(&key).map(|session| session.clone()) {
            return Ok(existing);
        }
        evict_oldest_session_if_full(&state);
        match state.sessions.entry(key.clone()) {
            Entry::Occupied(existing) => return Ok(existing.get().clone()),
            Entry::Vacant(vacant) => {
                vacant.insert(session.clone());
            }
        }
    }

    state.stats.record_session_creation();
    tokio::spawn(run_backend_session(
        key,
        session.clone(),
        listener_socket,
        state,
    ));
    Ok(session)
}

async fn resolve_backend_addr(
    addr: &str,
    stats: &FrontdoorStats,
) -> Result<SocketAddr, FrontdoorError> {
    let started = Instant::now();
    let mut addrs = lookup_host(addr).await?;
    stats.observe_dns_resolve_latency(started.elapsed());
    addrs
        .next()
        .ok_or_else(|| FrontdoorError::Config(format!("backend {addr:?} resolved no addresses")))
}

async fn cached_backend_addr(
    state: &RuntimeState,
    addr: &str,
) -> Result<SocketAddr, FrontdoorError> {
    if let Some(resolved) = state.resolved_backends.read().await.get(addr).copied() {
        return Ok(resolved);
    }

    let resolved = resolve_backend_addr(addr, &state.stats).await?;
    let mut cache = state.resolved_backends.write().await;
    Ok(*cache.entry(addr.to_string()).or_insert(resolved))
}

async fn resolve_enabled_backend_cache(
    config: &FrontdoorConfig,
    previous: Option<&HashMap<String, SocketAddr>>,
    stats: &FrontdoorStats,
) -> Result<HashMap<String, SocketAddr>, FrontdoorError> {
    let mut cache = HashMap::new();
    for backend in config.backends.iter().filter(|backend| backend.enabled) {
        if cache.contains_key(&backend.addr) {
            continue;
        }
        let resolved = resolve_backend_addr(&backend.addr, stats).await?;
        if let Some(previous_addr) = previous.and_then(|previous| previous.get(&backend.addr)) {
            if *previous_addr != resolved {
                warn!(
                    backend_addr = %backend.addr,
                    old_addr = %previous_addr,
                    new_addr = %resolved,
                    "frontdoor backend resolved address changed"
                );
            }
        }
        cache.insert(backend.addr.clone(), resolved);
    }
    Ok(cache)
}

fn evict_oldest_session_if_full(state: &RuntimeState) {
    if state.sessions.len() < state.max_sessions {
        return;
    }

    let Some(key) = state
        .sessions
        .iter()
        .min_by_key(|entry| entry.value().last_activity_epoch.load(Ordering::Relaxed))
        .map(|entry| entry.key().clone())
    else {
        return;
    };

    if let Some((evicted_key, session)) = state.sessions.remove(&key) {
        session.cancellation.cancel();
        remove_backend_route_if_current(state, &evicted_key, &session);
        state.stats.record_session_eviction();
        debug!(?evicted_key, "evicted oldest frontdoor backend session");
    }
}

async fn run_backend_session(
    key: SessionKey,
    session: Arc<BackendSession>,
    listener_socket: Arc<UdpSocket>,
    state: RuntimeState,
) {
    let mut buf = vec![0_u8; state.max_datagram_bytes];
    loop {
        let recv_result = tokio::select! {
            _ = session.cancellation.cancelled() => {
                debug!(?key, "backend session evicted");
                break;
            }
            recv_result = timeout(session.session_idle, session.socket.recv(&mut buf)) => recv_result,
        };

        match recv_result {
            Ok(Ok(len)) => {
                session
                    .last_activity_epoch
                    .store(now_epoch_secs(), Ordering::Relaxed);
                if !bind_backend_route_for_reply(&state, &key, &session).await {
                    debug!(
                        ?key,
                        "dropping backend reply from non-selected WireGuard route"
                    );
                    continue;
                }
                apply_jitter(session.jitter_ms).await;
                if let Err(error) = listener_socket.send_to(&buf[..len], key.client_addr).await {
                    warn!(
                        %error,
                        ?key,
                        "failed to send backend reply to client"
                    );
                    break;
                }
            }
            Ok(Err(error)) => {
                warn!(%error, ?key, "backend session receive failed");
                break;
            }
            Err(_) => {
                debug!(?key, "backend session idle timeout");
                break;
            }
        }
    }

    state.sessions.remove(&key);
    remove_backend_route_if_current(&state, &key, &session);
}

async fn apply_jitter(jitter_ms: u64) {
    if jitter_ms == 0 {
        return;
    }

    let delay_ms = rand::thread_rng().gen_range(0..jitter_ms);
    if delay_ms > 0 {
        sleep(Duration::from_millis(delay_ms)).await;
    }
}

async fn bind_backend_route_for_reply(
    state: &RuntimeState,
    key: &SessionKey,
    session: &Arc<BackendSession>,
) -> bool {
    let route_key = ClientRouteKey {
        listener: key.listener.clone(),
        client_addr: key.client_addr,
    };
    let route = BackendRoute {
        backend_name: key.backend_name.clone(),
        backend_addr: key.backend_addr.clone(),
    };

    if let Some(existing) = state.routes.get(&route_key) {
        return existing.route == route;
    }

    let config = state.config.read().await;
    if !backend_route_is_active(&config, &route_key, &route) {
        return false;
    }
    drop(config);

    match state.routes.entry(route_key) {
        Entry::Occupied(existing) => existing.get().route == route,
        Entry::Vacant(vacant) => {
            vacant.insert(PinnedRoute {
                route,
                session: session.clone(),
            });
            true
        }
    }
}

fn backend_route_is_active(
    config: &FrontdoorConfig,
    route_key: &ClientRouteKey,
    route: &BackendRoute,
) -> bool {
    let Some(listener) = config
        .listeners
        .iter()
        .find(|listener| listener.name.as_str() == route_key.listener.as_ref())
    else {
        return false;
    };
    if !listener
        .backends
        .iter()
        .any(|backend_name| backend_name == &route.backend_name)
    {
        return false;
    }

    config.backends.iter().any(|backend| {
        backend.enabled
            && backend.name.as_str() == route.backend_name
            && backend.addr.as_str() == route.backend_addr
    })
}

fn remove_backend_route_if_current(
    state: &RuntimeState,
    key: &SessionKey,
    session: &Arc<BackendSession>,
) {
    let route_key = ClientRouteKey {
        listener: key.listener.clone(),
        client_addr: key.client_addr,
    };
    let route = BackendRoute {
        backend_name: key.backend_name.clone(),
        backend_addr: key.backend_addr.clone(),
    };
    let route_matches = state
        .routes
        .get(&route_key)
        .is_some_and(|existing| existing.route == route && Arc::ptr_eq(&existing.session, session));
    if route_matches {
        state.routes.remove(&route_key);
    }
}

impl ShardedRateLimiter {
    fn new(limit_pps: u64) -> Self {
        Self {
            limit_pps,
            shards: std::array::from_fn(|_| Mutex::new(RateLimiter::new(limit_pps))),
        }
    }

    async fn allow(&self, source: SocketAddr) -> bool {
        if self.limit_pps == 0 {
            return true;
        }
        let source_ip = source.ip();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        source_ip.hash(&mut hasher);
        let shard = hasher.finish() as usize % RATE_LIMITER_SHARDS;
        self.shards[shard].lock().await.allow(source_ip)
    }
}

impl RateLimiter {
    fn new(limit_pps: u64) -> Self {
        Self {
            limit_pps,
            sources: HashMap::new(),
            last_cleanup_second: 0,
        }
    }

    fn allow(&mut self, source: IpAddr) -> bool {
        self.allow_at(source, now_epoch_secs())
    }

    fn allow_at(&mut self, source: IpAddr, second: u64) -> bool {
        if self.limit_pps == 0 {
            return true;
        }

        self.evict_stale_sources(second);

        let window = self
            .sources
            .entry(source)
            .or_insert(RateWindow { second, count: 0 });
        if window.second != second {
            window.second = second;
            window.count = 0;
        }

        if window.count >= self.limit_pps {
            return false;
        }

        window.count += 1;
        true
    }

    fn evict_stale_sources(&mut self, second: u64) {
        if second <= self.last_cleanup_second {
            return;
        }

        self.sources.retain(|_, window| {
            second.saturating_sub(window.second) <= RATE_LIMITER_STALE_SOURCE_SECS
        });
        self.last_cleanup_second = second;
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn run_health_server(addr: SocketAddr, state: RuntimeState) -> Result<(), FrontdoorError> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "frontdoor health server started");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
    listeners: usize,
    enabled_backends: usize,
    sessions: usize,
}

async fn health(State(state): State<RuntimeState>) -> Response {
    let config = state.config.read().await;
    let sessions = state.sessions.len();
    let body = HealthBody {
        status: "ok",
        listeners: config.listeners.len(),
        enabled_backends: config
            .backends
            .iter()
            .filter(|backend| backend.enabled)
            .count(),
        sessions,
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn metrics(State(state): State<RuntimeState>) -> Response {
    state.stats.set_sessions(state.sessions.len());
    let encoder = TextEncoder::new();
    match encoder.encode_to_string(&state.prometheus_registry.gather()) {
        Ok(body) => (
            StatusCode::OK,
            [(CONTENT_TYPE, encoder.format_type().to_string())],
            body,
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode prometheus metrics: {error}"),
        )
            .into_response(),
    }
}

async fn run_reload_task(config_file: PathBuf, state: RuntimeState) -> Result<(), FrontdoorError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sighup = signal(SignalKind::hangup())?;
        while sighup.recv().await.is_some() {
            reload_config(&config_file, &state).await;
        }
    }

    #[cfg(not(unix))]
    {
        let _ = config_file;
        let _ = state;
        std::future::pending().await;
    }

    Ok(())
}

async fn reload_config(config_file: &Path, state: &RuntimeState) {
    let reload_result =
        match load_or_default_config(config_file, state.session_idle).and_then(|config| {
            validate_runtime_config(&config, state.session_idle)?;
            Ok(config)
        }) {
            Ok(config) => {
                let previous_cache = state.resolved_backends.read().await.clone();
                resolve_enabled_backend_cache(&config, Some(&previous_cache), &state.stats)
                    .await
                    .map(|cache| (config, cache))
            }
            Err(error) => Err(error),
        };

    match reload_result {
        Ok((config, resolved_backends)) => {
            let listener_count = config.listeners.len();
            let backend_count = config
                .backends
                .iter()
                .filter(|backend| backend.enabled)
                .count();
            *state.config.write().await = config;
            *state.resolved_backends.write().await = resolved_backends;
            state.routes.clear();
            state.stats.record_reload_success();
            info!(
                listener_count,
                enabled_backend_count = backend_count,
                "frontdoor config reloaded"
            );
        }
        Err(error) => {
            state.stats.record_reload_failure();
            warn!(%error, config_file = ?config_file, "frontdoor config reload failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(config: FrontdoorConfig) -> RuntimeState {
        let prometheus_registry = Arc::new(Registry::new());
        let stats = Arc::new(FrontdoorStats::new(&prometheus_registry).unwrap());
        RuntimeState {
            config: Arc::new(RwLock::new(config)),
            resolved_backends: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(DashMap::new()),
            routes: Arc::new(DashMap::new()),
            session_admission: Arc::new(Mutex::new(())),
            rate_limiter: Arc::new(ShardedRateLimiter::new(0)),
            stats,
            prometheus_registry,
            session_idle: Duration::from_secs(5),
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
            dispatch_task_limit: DEFAULT_DISPATCH_TASK_LIMIT,
            udp_socket_buffer_bytes: DEFAULT_UDP_SOCKET_BUFFER_BYTES,
        }
    }

    #[test]
    fn wg_udp_frontdoor_config_parses() {
        let config = parse_config(
            r#"
[[listeners]]
name = "wg-public"
bind_addr = "127.0.0.1:0"
backends = ["active", "candidate"]
session_idle = 30
jitter_ms = 5

[[backends]]
name = "active"
addr = "127.0.0.1:51820"

[[backends]]
name = "candidate"
addr = "127.0.0.1:51821"
enabled = false
"#,
        )
        .unwrap();

        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.backends.len(), 2);
        assert_eq!(config.listeners[0].session_idle_secs, Some(30));
        assert_eq!(config.listeners[0].jitter_ms, 5);
        assert!(!config.backends[1].enabled);
    }

    #[test]
    fn wg_udp_frontdoor_rejects_unknown_backend() {
        let error = parse_config(
            r#"
[[listeners]]
name = "wg-public"
bind_addr = "127.0.0.1:0"
backends = ["missing"]

[[backends]]
name = "active"
addr = "127.0.0.1:51820"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unknown backend"));
    }

    #[test]
    fn wg_udp_frontdoor_rejects_duplicate_listener_name() {
        let error = parse_config(
            r#"
[[listeners]]
name = "wg-public"
bind_addr = "127.0.0.1:0"
backends = ["active"]

[[listeners]]
name = "wg-public"
bind_addr = "127.0.0.1:1"
backends = ["active"]

[[backends]]
name = "active"
addr = "127.0.0.1:51820"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("duplicate listener name wg-public"));
    }

    #[test]
    fn wg_udp_frontdoor_rejects_jitter_at_or_above_idle_timeout() {
        let error = parse_config(
            r#"
[[listeners]]
name = "wg-public"
bind_addr = "127.0.0.1:0"
backends = ["active"]
session_idle = 1
jitter_ms = 1000

[[backends]]
name = "active"
addr = "127.0.0.1:51820"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("jitter_ms must be less than session_idle"));
    }

    #[test]
    fn wg_udp_frontdoor_rate_limiter_resets_each_second() {
        let source: IpAddr = "127.0.0.1".parse().unwrap();
        let mut limiter = RateLimiter::new(2);

        assert!(limiter.allow_at(source, 10));
        assert!(limiter.allow_at(source, 10));
        assert!(!limiter.allow_at(source, 10));
        assert!(limiter.allow_at(source, 11));
    }

    #[tokio::test]
    async fn wg_udp_frontdoor_disabled_rate_limiter_allows_unbounded_packets() {
        let limiter = ShardedRateLimiter::new(0);
        let source: SocketAddr = "127.0.0.1:50000".parse().unwrap();

        for _ in 0..10_000 {
            assert!(limiter.allow(source).await);
        }
    }

    #[test]
    fn wg_udp_frontdoor_buffer_pool_reuses_datagram_storage() {
        let pool = FrontdoorBufferPool::new(1, 128);
        let mut lease = pool.lease().expect("buffer available");
        lease[..4].copy_from_slice(b"ping");
        assert_eq!(pool.available(), 0);
        drop(lease);
        assert_eq!(pool.available(), 1);
        assert!(pool.lease().is_some());
    }

    #[test]
    fn wg_udp_frontdoor_dispatch_sharding_is_stable_per_client() {
        let first: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:50001".parse().unwrap();

        assert_eq!(
            dispatch_worker_index(first, 8),
            dispatch_worker_index(first, 8)
        );
        assert!(dispatch_worker_index(first, 8) < 8);
        assert!(dispatch_worker_index(second, 8) < 8);
    }

    #[test]
    fn wg_udp_frontdoor_rate_limiter_evicts_stale_sources() {
        let mut limiter = RateLimiter::new(2);

        for octet in 1..=10 {
            let source: IpAddr = format!("127.0.0.{octet}").parse().unwrap();
            assert!(limiter.allow_at(source, 10));
        }
        assert_eq!(limiter.sources.len(), 10);

        let current_source: IpAddr = "127.0.0.20".parse().unwrap();
        assert!(limiter.allow_at(current_source, 11));

        assert_eq!(limiter.sources.len(), 1);
        assert!(limiter.sources.contains_key(&current_source));
    }

    #[tokio::test]
    async fn wg_udp_frontdoor_metrics_include_byte_counters() {
        let state = test_state(FrontdoorConfig {
            listeners: Vec::new(),
            backends: Vec::new(),
        });
        state.stats.record_client_packet(123);
        state.stats.record_backend_packet(456);

        let response = metrics(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("# HELP wg_frontdoor_client_bytes_total Client bytes received."));
        assert!(body.contains("wg_frontdoor_client_bytes_total 123"));
        assert!(body.contains("# HELP wg_frontdoor_backend_bytes_total Backend bytes sent."));
        assert!(body.contains("wg_frontdoor_backend_bytes_total 456"));
        assert!(body.contains("# HELP wg_frontdoor_forward_latency_us"));
        assert!(body.contains("# TYPE wg_frontdoor_forward_latency_us histogram"));
        assert!(body.contains("wg_frontdoor_dispatch_queue_depth"));
        assert!(body.contains("wg_frontdoor_dispatch_queue_high_watermark"));
    }

    #[tokio::test]
    async fn wg_udp_frontdoor_reply_binding_requires_active_backend() {
        let client_addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let backend_addr = "127.0.0.1:51820".to_string();
        let state = test_state(FrontdoorConfig {
            listeners: vec![ListenerConfig {
                name: "test".to_string(),
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                backends: vec!["a".to_string()],
                session_idle_secs: None,
                jitter_ms: 0,
            }],
            backends: vec![BackendConfig {
                name: "a".to_string(),
                addr: backend_addr.clone(),
                enabled: true,
            }],
        });
        let key = SessionKey {
            listener: Arc::from("test"),
            client_addr,
            backend_name: "a".to_string(),
            backend_addr: backend_addr.clone(),
            resolved_backend_addr: backend_addr.parse().unwrap(),
        };
        let route_key = ClientRouteKey {
            listener: Arc::from("test"),
            client_addr,
        };
        let expected_route = BackendRoute {
            backend_name: "a".to_string(),
            backend_addr,
        };
        let session = Arc::new(BackendSession {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            last_activity_epoch: Arc::new(AtomicU64::new(10)),
            session_idle: Duration::from_secs(5),
            jitter_ms: 0,
            cancellation: CancellationToken::new(),
        });

        assert!(bind_backend_route_for_reply(&state, &key, &session).await);
        assert_eq!(
            state
                .routes
                .get(&route_key)
                .map(|route| route.route.clone()),
            Some(expected_route.clone())
        );

        state.routes.clear();
        state.config.write().await.backends[0].enabled = false;
        assert!(!bind_backend_route_for_reply(&state, &key, &session).await);
        assert!(state.routes.is_empty());

        {
            let mut config = state.config.write().await;
            config.backends[0].enabled = true;
            config.listeners[0].backends.clear();
        }
        assert!(!bind_backend_route_for_reply(&state, &key, &session).await);
        assert!(state.routes.is_empty());
    }

    #[tokio::test]
    async fn wg_udp_frontdoor_evicts_oldest_session_when_full() {
        let mut state = test_state(FrontdoorConfig {
            listeners: Vec::new(),
            backends: Vec::new(),
        });
        state.max_sessions = 2;
        let client_addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let old_key = SessionKey {
            listener: Arc::from("test"),
            client_addr,
            backend_name: "a".to_string(),
            backend_addr: "127.0.0.1:51820".to_string(),
            resolved_backend_addr: "127.0.0.1:51820".parse().unwrap(),
        };
        let new_key = SessionKey {
            listener: Arc::from("test"),
            client_addr,
            backend_name: "b".to_string(),
            backend_addr: "127.0.0.1:51821".to_string(),
            resolved_backend_addr: "127.0.0.1:51821".parse().unwrap(),
        };
        let old_session = Arc::new(BackendSession {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            last_activity_epoch: Arc::new(AtomicU64::new(10)),
            session_idle: Duration::from_secs(5),
            jitter_ms: 0,
            cancellation: CancellationToken::new(),
        });
        let new_session = Arc::new(BackendSession {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            last_activity_epoch: Arc::new(AtomicU64::new(20)),
            session_idle: Duration::from_secs(5),
            jitter_ms: 0,
            cancellation: CancellationToken::new(),
        });
        state.sessions.insert(old_key.clone(), old_session.clone());
        state.sessions.insert(new_key.clone(), new_session);
        state.routes.insert(
            ClientRouteKey {
                listener: old_key.listener.clone(),
                client_addr,
            },
            PinnedRoute {
                route: BackendRoute {
                    backend_name: old_key.backend_name.clone(),
                    backend_addr: old_key.backend_addr.clone(),
                },
                session: old_session.clone(),
            },
        );

        evict_oldest_session_if_full(&state);

        assert!(old_session.cancellation.is_cancelled());
        assert!(!state.sessions.contains_key(&old_key));
        assert!(state.sessions.contains_key(&new_key));
        assert!(state.routes.is_empty());
        assert_eq!(state.stats.sessions_evicted.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn wg_udp_frontdoor_fans_out_and_routes_replies() {
        let backend_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_a_addr = backend_a.local_addr().unwrap();
        let backend_b_addr = backend_b.local_addr().unwrap();
        let listener_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let listener = ListenerConfig {
            name: "test".to_string(),
            bind_addr: listener_addr,
            backends: vec!["a".to_string(), "b".to_string()],
            session_idle_secs: None,
            jitter_ms: 0,
        };
        let config = FrontdoorConfig {
            listeners: vec![listener.clone()],
            backends: vec![
                BackendConfig {
                    name: "a".to_string(),
                    addr: backend_a_addr.to_string(),
                    enabled: true,
                },
                BackendConfig {
                    name: "b".to_string(),
                    addr: backend_b_addr.to_string(),
                    enabled: true,
                },
            ],
        };
        let state = test_state(config);

        let frontdoor = UdpSocket::bind(listener.bind_addr).await.unwrap();
        let frontdoor_addr = frontdoor.local_addr().unwrap();
        let mut listener = listener;
        listener.bind_addr = frontdoor_addr;
        tokio::spawn(run_listener_with_socket(listener, state, frontdoor));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello", frontdoor_addr).await.unwrap();

        let mut buf = [0_u8; 32];
        let (a_len, a_peer) = timeout(Duration::from_secs(2), backend_a.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..a_len], b"hello");
        let (b_len, _b_peer) = timeout(Duration::from_secs(2), backend_b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..b_len], b"hello");

        backend_a.send_to(b"ok", a_peer).await.unwrap();
        let (reply_len, _reply_peer) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..reply_len], b"ok");

        client.send_to(b"pinned", frontdoor_addr).await.unwrap();
        let (a_len, _a_peer) = timeout(Duration::from_secs(2), backend_a.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..a_len], b"pinned");

        assert!(
            timeout(Duration::from_millis(100), backend_b.recv_from(&mut buf))
                .await
                .is_err()
        );
    }
}
