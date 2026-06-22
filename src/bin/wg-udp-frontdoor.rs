use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{lookup_host, UdpSocket},
    signal,
    sync::{Mutex, RwLock},
    task::JoinSet,
    time::timeout,
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_CONFIG_FILE: &str = "/run/wg-rotation/frontdoor/wg-udp-frontdoor.toml";
const DEFAULT_HEALTH_ADDR: &str = "0.0.0.0:3003";
const DEFAULT_SESSION_IDLE_SECS: u64 = 300;
const MAX_DATAGRAM_BYTES: usize = 65_535;

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
}

#[derive(Clone)]
struct RuntimeState {
    config: Arc<RwLock<FrontdoorConfig>>,
    sessions: Arc<Mutex<HashMap<SessionKey, Arc<BackendSession>>>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    stats: Arc<FrontdoorStats>,
    session_idle: Duration,
}

#[derive(Clone)]
struct BackendSession {
    socket: Arc<UdpSocket>,
    last_activity_epoch: Arc<AtomicU64>,
}

#[derive(Clone, Eq)]
struct SessionKey {
    listener: String,
    client_addr: SocketAddr,
    backend_name: String,
    backend_addr: String,
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.listener == other.listener
            && self.client_addr == other.client_addr
            && self.backend_name == other.backend_name
            && self.backend_addr == other.backend_addr
    }
}

impl Hash for SessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.listener.hash(state);
        self.client_addr.hash(state);
        self.backend_name.hash(state);
        self.backend_addr.hash(state);
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("listener", &self.listener)
            .field("client_addr", &self.client_addr)
            .field("backend_name", &self.backend_name)
            .field("backend_addr", &self.backend_addr)
            .finish()
    }
}

#[derive(Default)]
struct FrontdoorStats {
    client_packets: AtomicU64,
    backend_packets: AtomicU64,
    client_bytes: AtomicU64,
    backend_bytes: AtomicU64,
    dropped_rate_limited: AtomicU64,
    session_creations: AtomicU64,
    reload_successes: AtomicU64,
    reload_failures: AtomicU64,
}

#[derive(Default)]
struct RateLimiter {
    limit_pps: u64,
    sources: HashMap<SocketAddr, RateWindow>,
}

#[derive(Clone, Copy)]
struct RateWindow {
    second: u64,
    count: u64,
}

#[derive(Debug)]
enum FrontdoorError {
    Config(String),
    Io(std::io::Error),
    Toml(toml::de::Error),
    Addr(std::net::AddrParseError),
}

impl fmt::Display for FrontdoorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "{message}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Toml(error) => write!(f, "{error}"),
            Self::Addr(error) => write!(f, "{error}"),
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

    let config = match load_or_default_config(&options.config_file) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load {:?}: {error}", options.config_file);
            std::process::exit(2);
        }
    };

    if let Err(error) = validate_config(&config) {
        eprintln!("invalid frontdoor config: {error}");
        std::process::exit(2);
    }

    let state = RuntimeState {
        config: Arc::new(RwLock::new(config.clone())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(options.rate_limit_pps))),
        stats: Arc::new(FrontdoorStats::default()),
        session_idle: options.session_idle,
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

        Ok(Self {
            config_file: PathBuf::from(config_file),
            health_addr,
            session_idle: Duration::from_secs(idle_secs),
            rate_limit_pps,
        })
    }
}

fn read_u64_env(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(default)
}

fn default_enabled() -> bool {
    true
}

fn load_or_default_config(path: &Path) -> Result<FrontdoorConfig, FrontdoorError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse_config(&contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            warn!(
                config_file = ?path,
                "frontdoor config file missing; using active-only built-in defaults"
            );
            Ok(default_config())
        }
        Err(error) => Err(error.into()),
    }
}

fn parse_config(contents: &str) -> Result<FrontdoorConfig, FrontdoorError> {
    let config: FrontdoorConfig = toml::from_str(contents)?;
    validate_config(&config)?;
    Ok(config)
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
            },
            ListenerConfig {
                name: "wg-public-51820".to_string(),
                bind_addr: "0.0.0.0:51820"
                    .parse()
                    .expect("default WireGuard port is valid"),
                backends: vec!["active-51820".to_string()],
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

fn validate_config(config: &FrontdoorConfig) -> Result<(), FrontdoorError> {
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

    for listener in &config.listeners {
        if listener.name.trim().is_empty() {
            return Err(FrontdoorError::Config(
                "listener name must not be empty".to_string(),
            ));
        }
        if listener.backends.is_empty() {
            return Err(FrontdoorError::Config(format!(
                "listener {} has no backends",
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
    let socket = Arc::new(UdpSocket::bind(listener.bind_addr).await?);
    info!(
        listener = %listener.name,
        bind_addr = %listener.bind_addr,
        "WireGuard UDP frontdoor listener started"
    );

    let mut buf = vec![0_u8; MAX_DATAGRAM_BYTES];
    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;
        if !state.rate_limiter.lock().await.allow(client_addr) {
            state
                .stats
                .dropped_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            debug!(%client_addr, listener = %listener.name, "dropping rate-limited packet");
            continue;
        }

        state.stats.client_packets.fetch_add(1, Ordering::Relaxed);
        state
            .stats
            .client_bytes
            .fetch_add(len as u64, Ordering::Relaxed);

        let backends = enabled_backends_for_listener(&state, &listener.name).await;
        if backends.is_empty() {
            warn!(listener = %listener.name, "dropping client packet; no enabled backends");
            continue;
        }

        for backend in backends {
            let packet = &buf[..len];
            match get_or_create_session(
                &listener.name,
                client_addr,
                &backend,
                socket.clone(),
                state.clone(),
            )
            .await
            {
                Ok(session) => {
                    session
                        .last_activity_epoch
                        .store(now_epoch_secs(), Ordering::Relaxed);
                    if let Err(error) = session.socket.send(packet).await {
                        warn!(
                            %error,
                            %client_addr,
                            backend = %backend.name,
                            "failed to send packet to backend"
                        );
                    } else {
                        state.stats.backend_packets.fetch_add(1, Ordering::Relaxed);
                        state
                            .stats
                            .backend_bytes
                            .fetch_add(len as u64, Ordering::Relaxed);
                    }
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
}

async fn enabled_backends_for_listener(
    state: &RuntimeState,
    listener_name: &str,
) -> Vec<BackendConfig> {
    let config = state.config.read().await;
    let Some(listener) = config
        .listeners
        .iter()
        .find(|listener| listener.name == listener_name)
    else {
        return Vec::new();
    };

    listener
        .backends
        .iter()
        .filter_map(|name| config.backends.iter().find(|backend| backend.name == *name))
        .filter(|backend| backend.enabled)
        .cloned()
        .collect()
}

async fn get_or_create_session(
    listener_name: &str,
    client_addr: SocketAddr,
    backend: &BackendConfig,
    listener_socket: Arc<UdpSocket>,
    state: RuntimeState,
) -> Result<Arc<BackendSession>, FrontdoorError> {
    let key = SessionKey {
        listener: listener_name.to_string(),
        client_addr,
        backend_name: backend.name.clone(),
        backend_addr: backend.addr.clone(),
    };

    if let Some(session) = state.sessions.lock().await.get(&key).cloned() {
        return Ok(session);
    }

    let backend_addr = resolve_backend_addr(&backend.addr).await?;
    let bind_addr = if backend_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let backend_socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    backend_socket.connect(backend_addr).await?;

    let session = Arc::new(BackendSession {
        socket: backend_socket.clone(),
        last_activity_epoch: Arc::new(AtomicU64::new(now_epoch_secs())),
    });

    {
        let mut sessions = state.sessions.lock().await;
        if let Some(existing) = sessions.get(&key).cloned() {
            return Ok(existing);
        }
        sessions.insert(key.clone(), session.clone());
    }

    state
        .stats
        .session_creations
        .fetch_add(1, Ordering::Relaxed);
    tokio::spawn(run_backend_session(
        key,
        session.clone(),
        listener_socket,
        state,
    ));
    Ok(session)
}

async fn resolve_backend_addr(addr: &str) -> Result<SocketAddr, FrontdoorError> {
    let mut addrs = lookup_host(addr).await?;
    addrs
        .next()
        .ok_or_else(|| FrontdoorError::Config(format!("backend {addr:?} resolved no addresses")))
}

async fn run_backend_session(
    key: SessionKey,
    session: Arc<BackendSession>,
    listener_socket: Arc<UdpSocket>,
    state: RuntimeState,
) {
    let mut buf = vec![0_u8; MAX_DATAGRAM_BYTES];
    loop {
        match timeout(state.session_idle, session.socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                session
                    .last_activity_epoch
                    .store(now_epoch_secs(), Ordering::Relaxed);
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

    state.sessions.lock().await.remove(&key);
}

impl RateLimiter {
    fn new(limit_pps: u64) -> Self {
        Self {
            limit_pps,
            sources: HashMap::new(),
        }
    }

    fn allow(&mut self, source: SocketAddr) -> bool {
        self.allow_at(source, now_epoch_secs())
    }

    fn allow_at(&mut self, source: SocketAddr, second: u64) -> bool {
        if self.limit_pps == 0 {
            return true;
        }

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
    let sessions = state.sessions.lock().await.len();
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
    let sessions = state.sessions.lock().await.len();
    let body = format!(
        concat!(
            "# HELP wg_frontdoor_sessions Active client/backend UDP sessions.\n",
            "# TYPE wg_frontdoor_sessions gauge\n",
            "wg_frontdoor_sessions {sessions}\n",
            "# HELP wg_frontdoor_client_packets_total Client packets received.\n",
            "# TYPE wg_frontdoor_client_packets_total counter\n",
            "wg_frontdoor_client_packets_total {client_packets}\n",
            "# HELP wg_frontdoor_backend_packets_total Backend packets sent.\n",
            "# TYPE wg_frontdoor_backend_packets_total counter\n",
            "wg_frontdoor_backend_packets_total {backend_packets}\n",
            "# HELP wg_frontdoor_dropped_rate_limited_total Client packets dropped by source rate limit.\n",
            "# TYPE wg_frontdoor_dropped_rate_limited_total counter\n",
            "wg_frontdoor_dropped_rate_limited_total {dropped}\n",
            "# HELP wg_frontdoor_config_reload_success_total Successful config reloads.\n",
            "# TYPE wg_frontdoor_config_reload_success_total counter\n",
            "wg_frontdoor_config_reload_success_total {reload_success}\n",
            "# HELP wg_frontdoor_config_reload_failure_total Failed config reloads.\n",
            "# TYPE wg_frontdoor_config_reload_failure_total counter\n",
            "wg_frontdoor_config_reload_failure_total {reload_failure}\n"
        ),
        sessions = sessions,
        client_packets = state.stats.client_packets.load(Ordering::Relaxed),
        backend_packets = state.stats.backend_packets.load(Ordering::Relaxed),
        dropped = state.stats.dropped_rate_limited.load(Ordering::Relaxed),
        reload_success = state.stats.reload_successes.load(Ordering::Relaxed),
        reload_failure = state.stats.reload_failures.load(Ordering::Relaxed),
    );
    (StatusCode::OK, body).into_response()
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
        futures::future::pending::<()>().await;
    }

    Ok(())
}

async fn reload_config(config_file: &Path, state: &RuntimeState) {
    match load_or_default_config(config_file).and_then(|config| {
        validate_config(&config)?;
        Ok(config)
    }) {
        Ok(config) => {
            let listener_count = config.listeners.len();
            let backend_count = config
                .backends
                .iter()
                .filter(|backend| backend.enabled)
                .count();
            *state.config.write().await = config;
            state.stats.reload_successes.fetch_add(1, Ordering::Relaxed);
            info!(
                listener_count,
                enabled_backend_count = backend_count,
                "frontdoor config reloaded"
            );
        }
        Err(error) => {
            state.stats.reload_failures.fetch_add(1, Ordering::Relaxed);
            warn!(%error, config_file = ?config_file, "frontdoor config reload failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wg_udp_frontdoor_config_parses() {
        let config = parse_config(
            r#"
[[listeners]]
name = "wg-public"
bind_addr = "127.0.0.1:0"
backends = ["active", "candidate"]

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
    fn wg_udp_frontdoor_rate_limiter_resets_each_second() {
        let source: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let mut limiter = RateLimiter::new(2);

        assert!(limiter.allow_at(source, 10));
        assert!(limiter.allow_at(source, 10));
        assert!(!limiter.allow_at(source, 10));
        assert!(limiter.allow_at(source, 11));
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
        let state = RuntimeState {
            config: Arc::new(RwLock::new(config)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(0))),
            stats: Arc::new(FrontdoorStats::default()),
            session_idle: Duration::from_secs(5),
        };

        let frontdoor = UdpSocket::bind(listener.bind_addr).await.unwrap();
        let frontdoor_addr = frontdoor.local_addr().unwrap();
        drop(frontdoor);
        let mut listener = listener;
        listener.bind_addr = frontdoor_addr;
        tokio::spawn(run_listener(listener, state));

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
    }
}
