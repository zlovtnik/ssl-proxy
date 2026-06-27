use axum::http::Method;
use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{any, get, post},
    Router,
};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use hyper::service::service_fn;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
#[cfg(feature = "quic")]
use ssl_proxy::quic;
use ssl_proxy::{
    blocklist, boringtun_control, check_proxy_auth, config, constant_time_eq, dashboard, forensic,
    observability, proxy, security, state, tunnel, wg_packet_obfuscation, wg_relay, wg_stats,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::broadcast, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn run_boringtun_subcommand() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("boringtun") {
        return None;
    }

    let result = match args.next().as_deref() {
        Some("genkey") => boringtun_control::generate_private_key_base64().map(|key| {
            println!("{key}");
        }),
        Some("pubkey") => {
            let private_key = args.next().ok_or_else(|| {
                boringtun_control::ControlError::Usage(
                    "usage: ssl-proxy boringtun pubkey <private-key-base64>".to_string(),
                )
            });
            private_key.and_then(|private_key| {
                boringtun_control::public_key_from_private_base64(&private_key).map(|key| {
                    println!("{key}");
                })
            })
        }
        Some("apply-config") => {
            let interface = args.next().ok_or_else(|| {
                boringtun_control::ControlError::Usage(
                    "usage: ssl-proxy boringtun apply-config <interface> <config-path>".to_string(),
                )
            });
            let path = args.next().ok_or_else(|| {
                boringtun_control::ControlError::Usage(
                    "usage: ssl-proxy boringtun apply-config <interface> <config-path>".to_string(),
                )
            });
            match (interface, path) {
                (Ok(interface), Ok(path)) => {
                    boringtun_control::apply_config(&interface, std::path::Path::new(&path))
                }
                (Err(err), _) | (_, Err(err)) => Err(err),
            }
        }
        Some("show") => {
            let interface = args.next().unwrap_or_else(|| "wg0".to_string());
            boringtun_control::show_interface(&interface).map(|output| {
                print!("{output}");
            })
        }
        Some("dump") => {
            let interface = args.next().unwrap_or_else(|| "wg0".to_string());
            boringtun_control::dump_interface(&interface).map(|output| {
                print!("{output}");
            })
        }
        Some(other) => Err(boringtun_control::ControlError::Usage(format!(
            "unknown boringtun subcommand: {other}"
        ))),
        None => Err(boringtun_control::ControlError::Usage(
            "usage: ssl-proxy boringtun <genkey|pubkey|apply-config|show|dump> ...".to_string(),
        )),
    };

    Some(match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    })
}

/// Determines whether the provided admin API key matches the configured key.
///
/// Matching is denied when the configured `key` is empty; otherwise performs a constant-time
/// comparison between `provided` and `key`.
///
/// # Examples
///
/// ```
/// assert!(admin_api_key_matches("s3cr3t", "s3cr3t"));
/// assert!(!admin_api_key_matches("wrong", "s3cr3t"));
/// assert!(!admin_api_key_matches("s3cr3t", ""));
/// ```
///
/// `true` if `provided` equals `key` and `key` is not empty, `false` otherwise.
fn admin_api_key_matches(provided: &str, key: &str) -> bool {
    !key.is_empty() && constant_time_eq(provided, key)
}

const ADMIN_AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const ADMIN_AUTH_MAX_FAILURES: u32 = 8;
const ADMIN_AUTH_MAX_TRACKED_IPS: usize = 4096;

#[derive(Clone, Debug)]
struct AdminAuthFailureState {
    window_started: Instant,
    failures: u32,
}

#[derive(Default)]
struct AdminAuthRateLimiter {
    failures_by_ip: dashmap::DashMap<IpAddr, AdminAuthFailureState>,
}

impl AdminAuthRateLimiter {
    fn record_failure(&self, ip: IpAddr, now: Instant) -> u32 {
        self.evict_expired(now);

        if let Some(mut entry) = self.failures_by_ip.get_mut(&ip) {
            return Self::increment_failure(entry.value_mut(), now);
        }

        if self.failures_by_ip.len() >= ADMIN_AUTH_MAX_TRACKED_IPS {
            return ADMIN_AUTH_MAX_FAILURES;
        }

        let mut entry = self
            .failures_by_ip
            .entry(ip)
            .or_insert_with(|| AdminAuthFailureState {
                window_started: now,
                failures: 0,
            });
        Self::increment_failure(entry.value_mut(), now)
    }

    fn increment_failure(entry: &mut AdminAuthFailureState, now: Instant) -> u32 {
        if now.duration_since(entry.window_started) >= ADMIN_AUTH_FAILURE_WINDOW {
            entry.window_started = now;
            entry.failures = 0;
        }

        entry.failures = entry.failures.saturating_add(1);
        entry.failures
    }

    fn evict_expired(&self, now: Instant) {
        let expired: Vec<IpAddr> = self
            .failures_by_ip
            .iter()
            .filter_map(|entry| {
                (now.duration_since(entry.window_started) >= ADMIN_AUTH_FAILURE_WINDOW)
                    .then_some(*entry.key())
            })
            .collect();
        for ip in expired {
            self.failures_by_ip.remove(&ip);
        }
    }

    fn record_success(&self, ip: IpAddr) {
        self.failures_by_ip.remove(&ip);
    }
}

fn install_rustls_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
}

fn init_tracing(config: &config::Config) -> Option<opentelemetry_sdk::trace::SdkTracerProvider> {
    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(
            "ssl_proxy=info"
                .parse()
                .expect("static directive must parse"),
        )
        .add_directive(
            "tower_http=info"
                .parse()
                .expect("static directive must parse"),
        );

    let otel_provider = observability::init_tracer_provider("ssl-proxy");
    if config.runtime.log_format == "json" {
        let otel_layer = otel_provider.as_ref().map(|provider| {
            use opentelemetry::trace::TracerProvider as _;
            tracing_opentelemetry::layer().with_tracer(provider.tracer("ssl-proxy"))
        });
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json().flatten_event(true))
            .with(otel_layer)
            .init();
    } else {
        let otel_layer = otel_provider.as_ref().map(|provider| {
            use opentelemetry::trace::TracerProvider as _;
            tracing_opentelemetry::layer().with_tracer(provider.tracer("ssl-proxy"))
        });
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(otel_layer)
            .init();
    }
    otel_provider
}

fn build_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.cache_size = 1024;
    // Prefer IPv4 first to avoid "Network unreachable" errors when IPv6 is not configured
    opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;

    let cloudflare_ips = [
        "1.1.1.1"
            .parse()
            .expect("static Cloudflare resolver address must parse"),
        "1.0.0.1"
            .parse()
            .expect("static Cloudflare resolver address must parse"),
    ];
    let resolver_config = ResolverConfig::from_parts(
        None,
        Vec::new(),
        NameServerConfigGroup::from_ips_https(
            &cloudflare_ips,
            443,
            "cloudflare-dns.com".to_string(),
            true,
        ),
    );
    TokioAsyncResolver::tokio(resolver_config, opts)
}

fn build_state(config: &config::Config) -> state::SharedState {
    let (stats_tx, _) = broadcast::channel(64);
    let (events_tx, _) = broadcast::channel(256);
    let client = build_proxy_http_client();
    let resolver = build_resolver();

    state::AppState::new(client, resolver, stats_tx, events_tx, config.clone())
}

fn build_proxy_http_client() -> proxy::ProxyClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_secs(10)));
    connector.set_keepalive(Some(Duration::from_secs(60)));
    connector.set_nodelay(true);

    let mut builder = Client::builder(TokioExecutor::new());
    builder.pool_max_idle_per_host(10);
    builder.pool_idle_timeout(Duration::from_secs(90));
    builder.http2_adaptive_window(true);
    builder.build(connector)
}

fn spawn_dashboard_event_retry_task(state: state::SharedState, shutdown: CancellationToken) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("dashboard event retry task shutting down");
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }
            state.flush_dashboard_event_queue();
        }
    });
}

fn spawn_background_tasks(
    config: &config::Config,
    state: state::SharedState,
    shutdown: CancellationToken,
) {
    spawn_dashboard_event_retry_task(state.clone(), shutdown.clone());
    forensic::spawn_hardware_worker(state.clone());
    blocklist::spawn_refresh_task(state.clone(), shutdown.clone());
    dashboard::spawn_host_eviction_task(state.clone(), shutdown.clone());
    wg_stats::spawn_wg_stats_poller(state.clone(), shutdown.clone());
    if config.proxy.max_connections == 0 {
        warn!("PROXY_MAX_CONNECTIONS=0 will reject all client connections");
    }
}

fn build_admin_cors(config: &config::Config) -> CorsLayer {
    if !config.admin.cors_allowed_origins.is_empty() {
        let parsed: Vec<axum::http::HeaderValue> = config
            .admin
            .cors_allowed_origins
            .iter()
            .filter_map(|origin| match origin.parse() {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(origin = %origin, %e, "invalid CORS origin, skipping");
                    None
                }
            })
            .collect();
        if parsed.is_empty() {
            warn!("CORS_ALLOWED_ORIGINS set but no valid origins parsed — no origins allowed");
        }
        CorsLayer::new()
            .allow_origin(parsed)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    } else if cfg!(debug_assertions) {
        info!("CORS_ALLOWED_ORIGINS not set, using permissive CORS (dev mode)");
        CorsLayer::permissive()
    } else {
        warn!("CORS_ALLOWED_ORIGINS not set in release build, defaulting to restrictive CORS");
        CorsLayer::new()
    }
}

fn build_admin_router(
    config: &config::Config,
    state: state::SharedState,
    cors: CorsLayer,
) -> Router {
    let admin_api_key = config.admin.api_key.clone();
    let require_mfa_claim = config.admin.require_mfa_claim;
    let mfa_header_names = config.admin.mfa_header_names.clone();
    let auth_rate_limiter = Arc::new(AdminAuthRateLimiter::default());
    let admin_routes = Router::new()
        .route("/hosts", get(dashboard::hosts_snapshot))
        .route("/hosts/:hostname", get(dashboard::host_detail))
        .route(
            "/devices",
            get(dashboard::list_devices).post(dashboard::upsert_device),
        )
        .route("/devices/:device_id", get(dashboard::get_device))
        .route("/stats/summary", get(dashboard::stats_summary))
        .route("/sync/status", get(dashboard::sync_status))
        .route(
            "/security/patch-cadence",
            get(dashboard::patch_cadence_report),
        )
        .route(
            "/security/recovery-drills",
            get(dashboard::recovery_drill_report),
        )
        .layer(middleware::from_fn(
            move |req: Request<Body>, next: Next| {
                let key = admin_api_key.clone();
                let mfa_headers = mfa_header_names.clone();
                let auth_rate_limiter = auth_rate_limiter.clone();
                async move {
                    let source_ip = req
                        .extensions()
                        .get::<axum::extract::ConnectInfo<SocketAddr>>()
                        .map(|axum::extract::ConnectInfo(addr)| addr.ip())
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                    // If no admin API key configured, deny all access to admin endpoints
                    let provided = req
                        .headers()
                        .get("x-api-key")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    if !admin_api_key_matches(provided, &key) {
                        let failures =
                            auth_rate_limiter.record_failure(source_ip, Instant::now());
                        if failures >= ADMIN_AUTH_MAX_FAILURES {
                            warn!(
                                source_ip = %source_ip,
                                failures,
                                window_secs = ADMIN_AUTH_FAILURE_WINDOW.as_secs(),
                                "admin access throttled after repeated API key failures"
                            );
                            return StatusCode::TOO_MANY_REQUESTS.into_response();
                        }
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    auth_rate_limiter.record_success(source_ip);
                    if require_mfa_claim
                        && !security::has_required_mfa_claim(req.headers(), &mfa_headers)
                    {
                        warn!(
                            claim_headers = ?mfa_headers,
                            "admin access denied: required MFA claim missing"
                        );
                        return StatusCode::FORBIDDEN.into_response();
                    }

                    next.run(req).await
                }
            },
        ))
        .with_state(state.clone());

    // Admin / dashboard listener — plaintext, internal only
    Router::new()
        .route("/health", get(dashboard::health))
        .route("/metrics", get(dashboard::metrics))
        .route("/ready", get(dashboard::ready))
        .route("/stats/live", get(dashboard::stats_live))
        .route("/stats/bandwidth", get(dashboard::stats_bandwidth))
        .route("/stats/peers", get(dashboard::stats_peers))
        .route("/stats/hosts/top", get(dashboard::stats_hosts_top))
        .route("/devices/claim", post(dashboard::claim_device))
        .merge(admin_routes)
        .nest_service("/dashboard", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn spawn_admin_listener(
    config: &config::Config,
    state: state::SharedState,
    shutdown: CancellationToken,
    cors: CorsLayer,
) {
    let admin_router = build_admin_router(config, state, cors);
    let admin_ip = config
        .admin
        .bind_addr
        .parse()
        .unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1]));
    let admin_addr = SocketAddr::from((admin_ip, config.admin.port));
    let admin_listener = tokio::net::TcpListener::bind(admin_addr)
        .await
        .unwrap_or_else(|e| {
            error!(%admin_addr, %e, "failed to bind admin listener");
            std::process::exit(1)
        });
    info!(%admin_addr, "admin/dashboard listener active (plaintext)");

    let admin_shutdown = shutdown.clone();
    tokio::spawn(async move {
        axum::serve(
            admin_listener,
            admin_router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { admin_shutdown.cancelled().await })
        .await
        .ok();
    });
}

fn log_runtime_ports(config: &config::Config) {
    info!(
        proxy_port = config.proxy.port,
        tproxy_port = config.proxy.transparent_port,
        wg_public_port = config.wireguard.port,
        wg_internal_port = config.wireguard.internal_port,
        admin_port = config.admin.port,
        explicit_proxy_enabled = config.proxy.explicit_enabled,
        wg_interface = ?config.wireguard.interface,
        upstream_proxy = ?config.proxy.upstream_proxy,
        tunnel_endpoint = ?config.proxy.tunnel_endpoint,
        obfuscation_profiles = ?config.obfuscation.enabled_profiles,
        wg_obfuscation_enabled = config.wireguard.obfuscation_enabled,
        wg_obfuscation_magic_byte = ?config.wireguard.obfuscation_magic_byte,
        "port assignment"
    );
    info!(
        transparent_tcp_redirect = "tcp/80,tcp/443 -> transparent proxy",
        fail_closed_no_sni = config.proxy.fail_closed_no_sni,
        drop_udp_443 = config.wireguard.drop_udp_443,
        "transparent enforcement policy"
    );
    log_wireguard_obfuscation_sizing(config);
}

fn log_wireguard_obfuscation_sizing(config: &config::Config) {
    if !config.wireguard.obfuscation_enabled {
        return;
    }

    let wg_mtu = std::env::var("WG_MTU")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(config::DEFAULT_WIREGUARD_PATH_MTU_BYTES);
    let settings = config.wireguard.packet_obfuscation();
    match wg_packet_obfuscation::encoded_packet_len_bounds(wg_mtu, &settings) {
        Ok(bounds) => {
            info!(
                wg_mtu,
                max_obfuscated_datagram_bytes = bounds.max_encoded_len,
                max_obfuscation_overhead_bytes = bounds.max_overhead_len(),
                configured_max_datagram_bytes = config.wireguard.obfuscation_max_datagram_bytes,
                udp_socket_buffer_bytes = config.wireguard.udp_socket_buffer_bytes,
                "WireGuard obfuscation datagram sizing"
            );
            if bounds.max_encoded_len > config::DEFAULT_WIREGUARD_PATH_MTU_BYTES {
                warn!(
                    wg_mtu,
                    max_obfuscated_datagram_bytes = bounds.max_encoded_len,
                    ethernet_path_mtu_bytes = config::DEFAULT_WIREGUARD_PATH_MTU_BYTES,
                    "WireGuard obfuscation can exceed a 1500-byte path MTU; reduce WG_MTU or use fixed MTU padding"
                );
            }
            if bounds.max_encoded_len > config.wireguard.obfuscation_max_datagram_bytes {
                warn!(
                    max_obfuscated_datagram_bytes = bounds.max_encoded_len,
                    configured_max_datagram_bytes = config.wireguard.obfuscation_max_datagram_bytes,
                    "WG_OBFUSCATION_MAX_DATAGRAM_BYTES is smaller than the expected encoded datagram size"
                );
            }
        }
        Err(err) => {
            warn!(
                wg_mtu,
                %err,
                "WireGuard obfuscation sizing could not fit the configured MTU"
            );
        }
    }
}

async fn spawn_wireguard_relay(
    config: &config::Config,
    state: state::SharedState,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if config.wireguard.obfuscation_enabled {
        Some(
            wg_relay::spawn_with_metrics(
                &config.wireguard,
                shutdown.clone(),
                state.wg_relay_metrics.clone(),
            )
                .await
                .unwrap_or_else(|e| {
                    error!(
                        public_port = config.wireguard.port,
                        internal_port = config.wireguard.internal_port,
                        error = %e,
                        "failed to bind WireGuard obfuscation relay"
                    );
                        std::process::exit(1)
                }),
        )
    } else {
        warn!(
            public_port = config.wireguard.port,
            "WG_OBFUSCATION_ENABLED=false — direct public WireGuard ingress is enabled"
        );
        None
    }
}
