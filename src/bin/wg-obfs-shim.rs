use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use serde::Deserialize;
use ssl_proxy::{
    wg_packet_obfuscation::{
        parse_magic_byte, EncryptionMode, MagicPositionMode, PacketPadding, WgPacketObfuscation,
        XorRekeyPolicy,
    },
    wg_shim::{
        self, RateLimitConfig, ShimHealthHandle, WgObfsShimConfig, WgObfsShimRuntime,
        DEFAULT_BUFFER_POOL_CAPACITY, DEFAULT_DRAIN_TIMEOUT_SECS, DEFAULT_HEALTH_ADDR,
        DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_LISTEN_ADDR, DEFAULT_SEND_QUEUE_CAPACITY,
    },
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

const HELP_TEXT: &str = "\
wg-obfs-shim

Linux WireGuard UDP obfuscation shim.

Usage:
  wg-obfs-shim [--config <path>]
  wg-obfs-shim --server <host:port> [--server <host:port>...] [--listen <host:port>] [--key <secret>]
               [--key-file <path>] [--magic-byte <0xNN|N>] [--idle-timeout-secs <seconds>]
               [--max-sessions <count>] [--cleanup-interval-secs <seconds>]
               [--drain-timeout-secs <seconds>] [--rate-limit-pps <count>]
               [--rate-limit-burst <count>] [--buffer-pool-capacity <count>]
               [--send-queue-capacity <count>] [--health-addr <host:port>]
               [--metrics-addr <host:port>] [--encryption-mode <xor|aead>]
               [--padding <none|power-of-two|fixed-mtu:N>]
               [--magic-position <fixed|randomized>]

Environment fallbacks:
  WG_OBFS_SERVER_ADDR
  WG_OBFS_SERVER_ADDRS
  WG_OBFS_SHIM_LISTEN_ADDR
  WG_OBFS_HEALTH_ADDR
  WG_OBFUSCATION_KEY
  WG_OBFUSCATION_KEY_FILE
  WG_OBFUSCATION_MAGIC_BYTE
  WG_OBFUSCATION_SESSION_IDLE_SECS
  WG_OBFS_SHIM_MAX_SESSIONS
  WG_OBFS_SHIM_CLEANUP_INTERVAL_SECS
  WG_OBFS_SHIM_DRAIN_TIMEOUT_SECS
  WG_OBFS_SHIM_RATE_LIMIT_PPS
  WG_OBFS_SHIM_RATE_LIMIT_BURST
  WG_OBFS_SHIM_BUFFER_POOL_CAPACITY
  WG_OBFS_SHIM_SEND_QUEUE_CAPACITY
  WG_OBFS_SHIM_METRICS_ADDR
  WG_OBFUSCATION_ENCRYPTION_MODE
  WG_OBFUSCATION_PADDING
  WG_OBFUSCATION_MAGIC_POSITION
  WG_OBFUSCATION_REPLAY_PROTECTION
  WG_OBFUSCATION_XOR_REKEY_PACKETS
  WG_OBFUSCATION_XOR_REKEY_SECS

Example:
  wg-obfs-shim --server 192.168.1.221:443 --listen 127.0.0.1:51821 --magic-byte 0xAA
";

#[derive(Debug, Default)]
struct CliOptions {
    config_path: Option<String>,
    listen_addr: Option<String>,
    server_addrs: Vec<String>,
    health_addr: Option<String>,
    key: Option<String>,
    key_file: Option<String>,
    magic_byte: Option<String>,
    idle_timeout_secs: Option<String>,
    max_sessions: Option<String>,
    cleanup_interval_secs: Option<String>,
    drain_timeout_secs: Option<String>,
    rate_limit_pps: Option<String>,
    rate_limit_burst: Option<String>,
    buffer_pool_capacity: Option<String>,
    send_queue_capacity: Option<String>,
    metrics_addr: Option<String>,
    encryption_mode: Option<String>,
    padding: Option<String>,
    magic_position: Option<String>,
    replay_protection: Option<String>,
    xor_rekey_packets: Option<String>,
    xor_rekey_secs: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct ProcessConfig {
    shims: Vec<WgObfsShimConfig>,
    health_addr: SocketAddr,
    config_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct TomlProcessConfig {
    health_addr: Option<String>,
    shim: Vec<TomlShimConfig>,
}

#[derive(Debug, Deserialize)]
struct TomlShimConfig {
    listen_addr: Option<String>,
    server_addr: Option<String>,
    server_addrs: Option<Vec<String>>,
    key: Option<String>,
    key_file: Option<String>,
    magic_byte: Option<String>,
    idle_timeout_secs: Option<u64>,
    max_sessions: Option<usize>,
    cleanup_interval_secs: Option<u64>,
    drain_timeout_secs: Option<u64>,
    rate_limit_pps: Option<u64>,
    rate_limit_burst: Option<u64>,
    buffer_pool_capacity: Option<usize>,
    send_queue_capacity: Option<usize>,
    metrics_addr: Option<String>,
    encryption_mode: Option<String>,
    padding: Option<String>,
    magic_position: Option<String>,
    replay_protection: Option<bool>,
    xor_rekey_packets: Option<u64>,
    xor_rekey_secs: Option<u64>,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let process_config = match parse_config(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(ConfigParseOutcome::Help) => {
            println!("{HELP_TEXT}");
            return ExitCode::SUCCESS;
        }
        Err(ConfigParseOutcome::Error(message)) => {
            eprintln!("{message}\n\n{HELP_TEXT}");
            return ExitCode::from(2);
        }
    };

    let shutdown = CancellationToken::new();
    let mut runtimes = Vec::new();
    for config in process_config.shims.iter().cloned() {
        match wg_shim::spawn_runtime(config, shutdown.clone()).await {
            Ok(runtime) => runtimes.push(runtime),
            Err(err) => {
                error!(%err, "failed to start WireGuard obfuscation shim");
                eprintln!("failed to start WireGuard obfuscation shim: {err}");
                shutdown.cancel();
                return ExitCode::FAILURE;
            }
        }
    }

    let health_handles = runtimes
        .iter()
        .map(|runtime| runtime.health_handle())
        .collect::<Vec<_>>();
    let health_task = tokio::spawn(run_health_server(
        process_config.health_addr,
        health_handles,
        shutdown.clone(),
    ));

    #[cfg(unix)]
    let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(signal) => Some(signal),
        Err(err) => {
            warn!(%err, "SIGHUP signal handler failed for WireGuard obfuscation shim");
            None
        }
    };

    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(err) = result {
                    error!(%err, "ctrl_c signal handler failed for WireGuard obfuscation shim");
                }
                shutdown.cancel();
                break;
            }
            _ = async {
                #[cfg(unix)]
                {
                    if let Some(hup) = hup.as_mut() {
                        hup.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }
                #[cfg(not(unix))]
                {
                    std::future::pending::<()>().await;
                }
            } => {
                if let Some(path) = process_config.config_path.as_deref() {
                    match load_process_config_from_file(path) {
                        Ok(reloaded) => apply_reloaded_config(&runtimes, &process_config, reloaded),
                        Err(err) => warn!(?err, path = %path.display(), "failed to reload WireGuard shim config after SIGHUP"),
                    }
                } else {
                    info!("ignoring SIGHUP because wg-obfs-shim was not started with --config");
                }
            }
        }
    }

    for runtime in runtimes {
        let _ = runtime.handle.await;
    }
    let _ = health_task.await;
    ExitCode::SUCCESS
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(
            "wg_obfs_shim=info"
                .parse()
                .expect("static directive must parse"),
        )
        .add_directive(
            "ssl_proxy=info"
                .parse()
                .expect("static directive must parse"),
        );
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigParseOutcome {
    Help,
    Error(String),
}

fn parse_config(
    args: impl IntoIterator<Item = String>,
) -> Result<ProcessConfig, ConfigParseOutcome> {
    let mut options = CliOptions::default();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Err(ConfigParseOutcome::Help),
            "--config" => options.config_path = Some(next_value(&mut args, "--config")?),
            "--listen" => options.listen_addr = Some(next_value(&mut args, "--listen")?),
            "--server" => options
                .server_addrs
                .push(next_value(&mut args, "--server")?),
            "--health-addr" => options.health_addr = Some(next_value(&mut args, "--health-addr")?),
            "--key" => options.key = Some(next_value(&mut args, "--key")?),
            "--key-file" => options.key_file = Some(next_value(&mut args, "--key-file")?),
            "--magic-byte" => options.magic_byte = Some(next_value(&mut args, "--magic-byte")?),
            "--idle-timeout-secs" => {
                options.idle_timeout_secs = Some(next_value(&mut args, "--idle-timeout-secs")?)
            }
            "--max-sessions" => {
                options.max_sessions = Some(next_value(&mut args, "--max-sessions")?)
            }
            "--cleanup-interval-secs" => {
                options.cleanup_interval_secs =
                    Some(next_value(&mut args, "--cleanup-interval-secs")?)
            }
            "--drain-timeout-secs" => {
                options.drain_timeout_secs = Some(next_value(&mut args, "--drain-timeout-secs")?)
            }
            "--rate-limit-pps" => {
                options.rate_limit_pps = Some(next_value(&mut args, "--rate-limit-pps")?)
            }
            "--rate-limit-burst" => {
                options.rate_limit_burst = Some(next_value(&mut args, "--rate-limit-burst")?)
            }
            "--buffer-pool-capacity" => {
                options.buffer_pool_capacity =
                    Some(next_value(&mut args, "--buffer-pool-capacity")?)
            }
            "--send-queue-capacity" => {
                options.send_queue_capacity = Some(next_value(&mut args, "--send-queue-capacity")?)
            }
            "--metrics-addr" => {
                options.metrics_addr = Some(next_value(&mut args, "--metrics-addr")?)
            }
            "--encryption-mode" => {
                options.encryption_mode = Some(next_value(&mut args, "--encryption-mode")?)
            }
            "--padding" => options.padding = Some(next_value(&mut args, "--padding")?),
            "--magic-position" => {
                options.magic_position = Some(next_value(&mut args, "--magic-position")?)
            }
            "--replay-protection" => {
                options.replay_protection = Some(next_value(&mut args, "--replay-protection")?)
            }
            "--xor-rekey-packets" => {
                options.xor_rekey_packets = Some(next_value(&mut args, "--xor-rekey-packets")?)
            }
            "--xor-rekey-secs" => {
                options.xor_rekey_secs = Some(next_value(&mut args, "--xor-rekey-secs")?)
            }
            other => {
                return Err(ConfigParseOutcome::Error(format!(
                    "unknown argument: {other}"
                )))
            }
        }
    }

    if let Some(path) = options.config_path.as_deref() {
        let mut config = load_process_config_from_file(PathBuf::from(path).as_path())?;
        config.config_path = Some(PathBuf::from(path));
        if let Some(raw) = optional_value(&options.health_addr, "WG_OBFS_HEALTH_ADDR") {
            config.health_addr = parse_socket_addr(raw, "health address")?;
        }
        return Ok(config);
    }

    parse_single_shim_process_config(&options)
}

fn parse_single_shim_process_config(
    options: &CliOptions,
) -> Result<ProcessConfig, ConfigParseOutcome> {
    let listen_addr = parse_socket_addr(
        options
            .listen_addr
            .clone()
            .or_else(|| std::env::var("WG_OBFS_SHIM_LISTEN_ADDR").ok())
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string()),
        "listen address",
    )?;
    let server_addrs = parse_server_addrs(options)?;
    let health_addr = parse_socket_addr(
        optional_value(&options.health_addr, "WG_OBFS_HEALTH_ADDR")
            .unwrap_or_else(|| DEFAULT_HEALTH_ADDR.to_string()),
        "health address",
    )?;

    let key = load_key(&options)?.ok_or_else(|| {
        ConfigParseOutcome::Error(
            "missing required obfuscation key; set --key, --key-file, WG_OBFUSCATION_KEY, or WG_OBFUSCATION_KEY_FILE".to_string(),
        )
    })?;
    let magic_byte = match options
        .magic_byte
        .clone()
        .or_else(|| std::env::var("WG_OBFUSCATION_MAGIC_BYTE").ok())
    {
        Some(raw) => Some(parse_magic_byte(&raw).ok_or_else(|| {
            ConfigParseOutcome::Error(format!(
                "invalid magic byte {raw:?}; expected decimal or 0xNN"
            ))
        })?),
        None => None,
    };

    let idle_timeout_secs = options
        .idle_timeout_secs
        .clone()
        .or_else(|| std::env::var("WG_OBFUSCATION_SESSION_IDLE_SECS").ok())
        .map(|raw| {
            raw.parse::<u64>().map_err(|_| {
                ConfigParseOutcome::Error(format!(
                    "invalid idle timeout {raw:?}; expected integer seconds"
                ))
            })
        })
        .transpose()?
        .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS)
        .max(1);

    let encryption_mode = parse_encryption_mode(optional_value(
        &options.encryption_mode,
        "WG_OBFUSCATION_ENCRYPTION_MODE",
    ))?;
    let replay_protection = parse_optional_bool(
        optional_value(
            &options.replay_protection,
            "WG_OBFUSCATION_REPLAY_PROTECTION",
        ),
        "replay protection",
    )?
    .unwrap_or(matches!(encryption_mode, EncryptionMode::Aead));
    let xor_rekey_packets = parse_optional_positive_u64(
        optional_value(
            &options.xor_rekey_packets,
            "WG_OBFUSCATION_XOR_REKEY_PACKETS",
        ),
        "XOR rekey packet count",
    )?;
    let xor_rekey_secs = parse_optional_positive_u64(
        optional_value(&options.xor_rekey_secs, "WG_OBFUSCATION_XOR_REKEY_SECS"),
        "XOR rekey seconds",
    )?;

    let obfuscation = WgPacketObfuscation::new(key.into_bytes(), magic_byte)
        .with_encryption_mode(encryption_mode)
        .with_padding(parse_padding(optional_value(
            &options.padding,
            "WG_OBFUSCATION_PADDING",
        ))?)
        .with_magic_position(parse_magic_position(optional_value(
            &options.magic_position,
            "WG_OBFUSCATION_MAGIC_POSITION",
        ))?)
        .with_xor_rekey(XorRekeyPolicy::new(xor_rekey_packets, xor_rekey_secs))
        .with_replay_protection(replay_protection);

    let mut config = WgObfsShimConfig::with_server_addrs(
        listen_addr,
        server_addrs,
        obfuscation,
        Duration::from_secs(idle_timeout_secs),
    )
    .map_err(|err| ConfigParseOutcome::Error(err.to_string()))?;
    config.max_sessions = parse_optional_usize(
        optional_value(&options.max_sessions, "WG_OBFS_SHIM_MAX_SESSIONS"),
        "max sessions",
    )?;
    config.cleanup_interval = parse_optional_duration_secs(
        optional_value(
            &options.cleanup_interval_secs,
            "WG_OBFS_SHIM_CLEANUP_INTERVAL_SECS",
        ),
        "cleanup interval",
    )?;
    config.drain_timeout = parse_optional_duration_secs(
        optional_value(
            &options.drain_timeout_secs,
            "WG_OBFS_SHIM_DRAIN_TIMEOUT_SECS",
        ),
        "drain timeout",
    )?
    .unwrap_or_else(|| Duration::from_secs(DEFAULT_DRAIN_TIMEOUT_SECS));
    config.rate_limit = parse_rate_limit(&options)?;
    config.buffer_pool_capacity = parse_optional_usize(
        optional_value(
            &options.buffer_pool_capacity,
            "WG_OBFS_SHIM_BUFFER_POOL_CAPACITY",
        ),
        "buffer pool capacity",
    )?
    .unwrap_or(DEFAULT_BUFFER_POOL_CAPACITY);
    config.send_queue_capacity = parse_optional_usize(
        optional_value(
            &options.send_queue_capacity,
            "WG_OBFS_SHIM_SEND_QUEUE_CAPACITY",
        ),
        "send queue capacity",
    )?
    .unwrap_or(DEFAULT_SEND_QUEUE_CAPACITY);
    config.health_addr = Some(health_addr);
    config.metrics_addr = optional_value(&options.metrics_addr, "WG_OBFS_SHIM_METRICS_ADDR")
        .map(|raw| parse_socket_addr(raw, "metrics address"))
        .transpose()?;

    Ok(ProcessConfig {
        shims: vec![config],
        health_addr,
        config_path: None,
    })
}

async fn run_health_server(
    health_addr: SocketAddr,
    handles: Vec<ShimHealthHandle>,
    shutdown: CancellationToken,
) {
    use axum::{
        extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router,
    };
    use serde_json::json;

    async fn health_handler(
        State(handles): State<Arc<Vec<ShimHealthHandle>>>,
    ) -> impl IntoResponse {
        let sessions = handles
            .iter()
            .map(ShimHealthHandle::active_sessions)
            .sum::<u64>();
        (
            StatusCode::OK,
            Json(json!({"status": "ok", "sessions": sessions})),
        )
    }

    let listener = match tokio::net::TcpListener::bind(health_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(%health_addr, %err, "failed to bind WireGuard shim health listener");
            return;
        }
    };
    let app = Router::new()
        .route("/health", get(health_handler))
        .with_state(Arc::new(handles));

    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
    {
        warn!(%health_addr, %err, "WireGuard shim health server failed");
    }
}

fn apply_reloaded_config(
    runtimes: &[WgObfsShimRuntime],
    current: &ProcessConfig,
    reloaded: ProcessConfig,
) {
    if reloaded.health_addr != current.health_addr {
        warn!(
            current_health_addr = %current.health_addr,
            reloaded_health_addr = %reloaded.health_addr,
            "SIGHUP health address changes require process restart"
        );
    }

    let mut by_listen_addr = HashMap::new();
    for config in reloaded.shims {
        by_listen_addr.insert(config.listen_addr, config);
    }

    for runtime in runtimes {
        let current_config = runtime.config_snapshot();
        if let Some(config) = by_listen_addr.remove(&current_config.listen_addr) {
            runtime.update_config(config);
            info!(
                listen_addr = %current_config.listen_addr,
                "reloaded WireGuard shim config for new sessions"
            );
        } else {
            warn!(
                listen_addr = %current_config.listen_addr,
                "SIGHUP removed a shim listener; listener topology changes require process restart"
            );
        }
    }

    for listen_addr in by_listen_addr.keys() {
        warn!(
            %listen_addr,
            "SIGHUP added a shim listener; listener topology changes require process restart"
        );
    }
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, ConfigParseOutcome> {
    args.next()
        .ok_or_else(|| ConfigParseOutcome::Error(format!("missing value for {flag}")))
}

fn optional_value(cli_value: &Option<String>, env_var: &str) -> Option<String> {
    cli_value
        .clone()
        .or_else(|| std::env::var(env_var).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_socket_addr(raw: String, label: &str) -> Result<SocketAddr, ConfigParseOutcome> {
    raw.parse::<SocketAddr>().map_err(|_| {
        ConfigParseOutcome::Error(format!("invalid {label} {raw:?}; expected host:port"))
    })
}

fn parse_server_addrs(options: &CliOptions) -> Result<Vec<SocketAddr>, ConfigParseOutcome> {
    let raw_addrs = if !options.server_addrs.is_empty() {
        options.server_addrs.clone()
    } else if let Some(raw) = std::env::var("WG_OBFS_SERVER_ADDRS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        split_addr_list(&raw)
    } else if let Some(raw) = std::env::var("WG_OBFS_SERVER_ADDR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        vec![raw]
    } else {
        return Err(ConfigParseOutcome::Error(
            "missing required server address; set --server, WG_OBFS_SERVER_ADDRS, or WG_OBFS_SERVER_ADDR"
                .to_string(),
        ));
    };

    parse_socket_addr_list(raw_addrs, "server address")
}

fn split_addr_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_socket_addr_list(
    raw_addrs: Vec<String>,
    label: &str,
) -> Result<Vec<SocketAddr>, ConfigParseOutcome> {
    if raw_addrs.is_empty() {
        return Err(ConfigParseOutcome::Error(format!(
            "{label} list must contain at least one address"
        )));
    }

    raw_addrs
        .into_iter()
        .map(|raw| parse_socket_addr(raw, label))
        .collect()
}

fn load_process_config_from_file(path: &Path) -> Result<ProcessConfig, ConfigParseOutcome> {
    let raw = std::fs::read_to_string(path).map_err(|err| {
        ConfigParseOutcome::Error(format!("failed to read config file {:?}: {err}", path))
    })?;
    let parsed = toml::from_str::<TomlProcessConfig>(&raw).map_err(|err| {
        ConfigParseOutcome::Error(format!("failed to parse config file {:?}: {err}", path))
    })?;
    let health_addr = parse_socket_addr(
        parsed
            .health_addr
            .unwrap_or_else(|| DEFAULT_HEALTH_ADDR.to_string()),
        "health address",
    )?;
    if parsed.shim.is_empty() {
        return Err(ConfigParseOutcome::Error(
            "config file must contain at least one [[shim]] section".to_string(),
        ));
    }

    let mut shims = Vec::with_capacity(parsed.shim.len());
    for raw_shim in parsed.shim {
        let config = build_toml_shim_config(raw_shim, health_addr)?;
        shims.push(config);
    }

    Ok(ProcessConfig {
        shims,
        health_addr,
        config_path: Some(path.to_path_buf()),
    })
}

fn build_toml_shim_config(
    raw: TomlShimConfig,
    health_addr: SocketAddr,
) -> Result<WgObfsShimConfig, ConfigParseOutcome> {
    let listen_addr = parse_socket_addr(
        raw.listen_addr
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string()),
        "listen address",
    )?;
    let mut server_raw = raw.server_addrs.unwrap_or_default();
    if let Some(server_addr) = raw.server_addr {
        server_raw.insert(0, server_addr);
    }
    let server_addrs = parse_socket_addr_list(server_raw, "server address")?;
    let key = load_key_from_values(raw.key, raw.key_file)?.ok_or_else(|| {
        ConfigParseOutcome::Error(
            "missing required obfuscation key in config file shim section".to_string(),
        )
    })?;
    let magic_byte = match raw.magic_byte {
        Some(raw) => Some(parse_magic_byte(&raw).ok_or_else(|| {
            ConfigParseOutcome::Error(format!(
                "invalid magic byte {raw:?}; expected decimal or 0xNN"
            ))
        })?),
        None => None,
    };
    let encryption_mode = parse_encryption_mode(raw.encryption_mode)?;
    let replay_protection = raw
        .replay_protection
        .unwrap_or(matches!(encryption_mode, EncryptionMode::Aead));
    let obfuscation = WgPacketObfuscation::new(key.into_bytes(), magic_byte)
        .with_encryption_mode(encryption_mode)
        .with_padding(parse_padding(raw.padding)?)
        .with_magic_position(parse_magic_position(raw.magic_position)?)
        .with_xor_rekey(XorRekeyPolicy::new(
            raw.xor_rekey_packets,
            raw.xor_rekey_secs,
        ))
        .with_replay_protection(replay_protection);

    let mut config = WgObfsShimConfig::with_server_addrs(
        listen_addr,
        server_addrs,
        obfuscation,
        Duration::from_secs(
            raw.idle_timeout_secs
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS)
                .max(1),
        ),
    )
    .map_err(|err| ConfigParseOutcome::Error(err.to_string()))?;
    config.max_sessions = raw.max_sessions;
    config.cleanup_interval = raw
        .cleanup_interval_secs
        .map(|secs| Duration::from_secs(secs.max(1)));
    config.drain_timeout = Duration::from_secs(
        raw.drain_timeout_secs
            .unwrap_or(DEFAULT_DRAIN_TIMEOUT_SECS)
            .max(1),
    );
    config.rate_limit = match (raw.rate_limit_pps, raw.rate_limit_burst) {
        (None, None) => None,
        (Some(pps), Some(burst)) => RateLimitConfig::new(pps, burst),
        _ => {
            return Err(ConfigParseOutcome::Error(
                "rate limiting requires both packets per second and burst values".to_string(),
            ))
        }
    };
    config.buffer_pool_capacity = raw
        .buffer_pool_capacity
        .unwrap_or(DEFAULT_BUFFER_POOL_CAPACITY);
    config.send_queue_capacity = raw
        .send_queue_capacity
        .unwrap_or(DEFAULT_SEND_QUEUE_CAPACITY);
    config.health_addr = Some(health_addr);
    config.metrics_addr = raw
        .metrics_addr
        .map(|raw| parse_socket_addr(raw, "metrics address"))
        .transpose()?;
    Ok(config)
}

fn parse_optional_positive_u64(
    raw: Option<String>,
    label: &str,
) -> Result<Option<u64>, ConfigParseOutcome> {
    raw.map(|raw| {
        raw.parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                ConfigParseOutcome::Error(format!(
                    "invalid {label} {raw:?}; expected positive integer"
                ))
            })
    })
    .transpose()
}

fn parse_optional_usize(
    raw: Option<String>,
    label: &str,
) -> Result<Option<usize>, ConfigParseOutcome> {
    raw.map(|raw| {
        raw.parse::<usize>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                ConfigParseOutcome::Error(format!(
                    "invalid {label} {raw:?}; expected positive integer"
                ))
            })
    })
    .transpose()
}

fn parse_optional_duration_secs(
    raw: Option<String>,
    label: &str,
) -> Result<Option<Duration>, ConfigParseOutcome> {
    parse_optional_positive_u64(raw, label).map(|value| value.map(Duration::from_secs))
}

fn parse_optional_bool(
    raw: Option<String>,
    label: &str,
) -> Result<Option<bool>, ConfigParseOutcome> {
    raw.map(|raw| match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(ConfigParseOutcome::Error(format!(
            "invalid {label} {raw:?}; expected boolean"
        ))),
    })
    .transpose()
}

fn parse_encryption_mode(raw: Option<String>) -> Result<EncryptionMode, ConfigParseOutcome> {
    let Some(raw) = raw else {
        return Ok(EncryptionMode::Xor);
    };
    match raw.to_ascii_lowercase().as_str() {
        "xor" => Ok(EncryptionMode::Xor),
        "aead" | "xchacha20-poly1305" | "xchacha20poly1305" => Ok(EncryptionMode::Aead),
        _ => Err(ConfigParseOutcome::Error(format!(
            "invalid encryption mode {raw:?}; expected xor or aead"
        ))),
    }
}

fn parse_padding(raw: Option<String>) -> Result<PacketPadding, ConfigParseOutcome> {
    let Some(raw) = raw else {
        return Ok(PacketPadding::None);
    };
    let normalized = raw.to_ascii_lowercase();
    match normalized.as_str() {
        "none" | "off" | "false" => Ok(PacketPadding::None),
        "power-of-two" | "power_of_two" | "pow2" => Ok(PacketPadding::PowerOfTwo),
        _ => normalized
            .strip_prefix("fixed-mtu:")
            .or_else(|| normalized.strip_prefix("fixed_mtu:"))
            .or_else(|| normalized.strip_prefix("fixed:"))
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .map(PacketPadding::FixedMtu)
            .ok_or_else(|| {
                ConfigParseOutcome::Error(format!(
                    "invalid padding {raw:?}; expected none, power-of-two, or fixed-mtu:N"
                ))
            }),
    }
}

fn parse_magic_position(raw: Option<String>) -> Result<MagicPositionMode, ConfigParseOutcome> {
    let Some(raw) = raw else {
        return Ok(MagicPositionMode::Fixed);
    };
    match raw.to_ascii_lowercase().as_str() {
        "fixed" => Ok(MagicPositionMode::Fixed),
        "randomized" | "randomised" | "random" => Ok(MagicPositionMode::Randomized),
        _ => Err(ConfigParseOutcome::Error(format!(
            "invalid magic position {raw:?}; expected fixed or randomized"
        ))),
    }
}

fn parse_rate_limit(options: &CliOptions) -> Result<Option<RateLimitConfig>, ConfigParseOutcome> {
    let pps = parse_optional_positive_u64(
        optional_value(&options.rate_limit_pps, "WG_OBFS_SHIM_RATE_LIMIT_PPS"),
        "rate limit pps",
    )?;
    let burst = parse_optional_positive_u64(
        optional_value(&options.rate_limit_burst, "WG_OBFS_SHIM_RATE_LIMIT_BURST"),
        "rate limit burst",
    )?;

    match (pps, burst) {
        (None, None) => Ok(None),
        (Some(pps), Some(burst)) => Ok(RateLimitConfig::new(pps, burst)),
        _ => Err(ConfigParseOutcome::Error(
            "rate limiting requires both packets per second and burst values".to_string(),
        )),
    }
}

fn load_key_from_values(
    key: Option<String>,
    key_file: Option<String>,
) -> Result<Option<String>, ConfigParseOutcome> {
    if let Some(key) = key.map(|value| value.trim().to_string()) {
        return Ok((!key.is_empty()).then_some(key));
    }

    if let Some(path) = key_file {
        return read_key_file(&path);
    }

    Ok(None)
}

fn load_key(options: &CliOptions) -> Result<Option<String>, ConfigParseOutcome> {
    if let Some(key) = options.key.as_ref().map(|value| value.trim().to_string()) {
        return Ok((!key.is_empty()).then_some(key));
    }

    if let Some(path) = options.key_file.as_ref() {
        return read_key_file(path);
    }

    if let Some(key) = std::env::var("WG_OBFUSCATION_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(key));
    }

    if let Some(path) = std::env::var("WG_OBFUSCATION_KEY_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return read_key_file(&path);
    }

    Ok(None)
}

fn read_key_file(path: &str) -> Result<Option<String>, ConfigParseOutcome> {
    std::fs::read_to_string(path)
        .map(|contents| contents.trim().to_string())
        .map(|contents| (!contents.is_empty()).then_some(contents))
        .map_err(|err| {
            ConfigParseOutcome::Error(format!(
                "failed to read obfuscation key file {path:?}: {err}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        sync::{Mutex, OnceLock},
    };

    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn clear_env() {
        for key in [
            "WG_OBFS_SERVER_ADDR",
            "WG_OBFS_SERVER_ADDRS",
            "WG_OBFS_SHIM_LISTEN_ADDR",
            "WG_OBFS_HEALTH_ADDR",
            "WG_OBFUSCATION_KEY",
            "WG_OBFUSCATION_KEY_FILE",
            "WG_OBFUSCATION_MAGIC_BYTE",
            "WG_OBFUSCATION_SESSION_IDLE_SECS",
            "WG_OBFS_SHIM_MAX_SESSIONS",
            "WG_OBFS_SHIM_CLEANUP_INTERVAL_SECS",
            "WG_OBFS_SHIM_DRAIN_TIMEOUT_SECS",
            "WG_OBFS_SHIM_RATE_LIMIT_PPS",
            "WG_OBFS_SHIM_RATE_LIMIT_BURST",
            "WG_OBFS_SHIM_BUFFER_POOL_CAPACITY",
            "WG_OBFS_SHIM_SEND_QUEUE_CAPACITY",
            "WG_OBFS_SHIM_METRICS_ADDR",
            "WG_OBFUSCATION_ENCRYPTION_MODE",
            "WG_OBFUSCATION_PADDING",
            "WG_OBFUSCATION_MAGIC_POSITION",
            "WG_OBFUSCATION_REPLAY_PROTECTION",
            "WG_OBFUSCATION_XOR_REKEY_PACKETS",
            "WG_OBFUSCATION_XOR_REKEY_SECS",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn parse_config_supports_cli_overrides() {
        let _guard = env_lock();
        clear_env();
        let process_config = parse_config([
            "--server".to_string(),
            "192.168.1.221:443".to_string(),
            "--server".to_string(),
            "192.168.1.222:443".to_string(),
            "--listen".to_string(),
            "127.0.0.1:51822".to_string(),
            "--health-addr".to_string(),
            "127.0.0.1:51823".to_string(),
            "--key".to_string(),
            "super-secret".to_string(),
            "--magic-byte".to_string(),
            "0xAA".to_string(),
            "--idle-timeout-secs".to_string(),
            "45".to_string(),
            "--max-sessions".to_string(),
            "128".to_string(),
            "--cleanup-interval-secs".to_string(),
            "3".to_string(),
            "--drain-timeout-secs".to_string(),
            "7".to_string(),
            "--rate-limit-pps".to_string(),
            "500".to_string(),
            "--rate-limit-burst".to_string(),
            "50".to_string(),
            "--buffer-pool-capacity".to_string(),
            "16".to_string(),
            "--send-queue-capacity".to_string(),
            "32".to_string(),
            "--metrics-addr".to_string(),
            "127.0.0.1:9900".to_string(),
            "--encryption-mode".to_string(),
            "aead".to_string(),
            "--padding".to_string(),
            "power-of-two".to_string(),
            "--magic-position".to_string(),
            "randomized".to_string(),
            "--xor-rekey-packets".to_string(),
            "64".to_string(),
        ])
        .unwrap();
        let config = &process_config.shims[0];

        assert_eq!(
            process_config.health_addr,
            "127.0.0.1:51823".parse::<SocketAddr>().unwrap()
        );

        assert_eq!(
            config.listen_addr,
            "127.0.0.1:51822".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            config.server_addrs,
            vec![
                "192.168.1.221:443".parse::<SocketAddr>().unwrap(),
                "192.168.1.222:443".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(config.obfuscation.magic_byte, Some(0xAA));
        assert_eq!(config.obfuscation.key, b"super-secret".to_vec());
        assert_eq!(config.obfuscation.encryption_mode, EncryptionMode::Aead);
        assert_eq!(config.obfuscation.padding, PacketPadding::PowerOfTwo);
        assert_eq!(
            config.obfuscation.magic_position,
            MagicPositionMode::Randomized
        );
        assert!(config.obfuscation.replay_protection);
        assert_eq!(
            config.obfuscation.xor_rekey,
            XorRekeyPolicy::new(Some(64), None)
        );
        assert_eq!(config.idle_timeout, Duration::from_secs(45));
        assert_eq!(config.max_sessions, Some(128));
        assert_eq!(config.cleanup_interval, Some(Duration::from_secs(3)));
        assert_eq!(config.drain_timeout, Duration::from_secs(7));
        assert_eq!(
            config.rate_limit,
            Some(RateLimitConfig {
                packets_per_sec: 500,
                burst_packets: 50
            })
        );
        assert_eq!(config.buffer_pool_capacity, 16);
        assert_eq!(config.send_queue_capacity, 32);
        assert_eq!(
            config.metrics_addr,
            Some("127.0.0.1:9900".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn parse_config_requires_server_address() {
        let _guard = env_lock();
        clear_env();
        let result = parse_config(["--key".to_string(), "super-secret".to_string()]);

        assert_eq!(
            result,
            Err(ConfigParseOutcome::Error(
                "missing required server address; set --server, WG_OBFS_SERVER_ADDRS, or WG_OBFS_SERVER_ADDR".to_string()
            ))
        );
    }

    #[test]
    fn parse_config_supports_env_server_addr_list_and_default_health() {
        let _guard = env_lock();
        clear_env();
        std::env::set_var("WG_OBFS_SERVER_ADDRS", "127.0.0.1:1111,127.0.0.1:2222");
        std::env::set_var("WG_OBFUSCATION_KEY", "super-secret");

        let process_config = parse_config(std::iter::empty::<String>()).unwrap();
        let config = &process_config.shims[0];

        assert_eq!(
            process_config.health_addr,
            DEFAULT_HEALTH_ADDR.parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            config.server_addrs,
            vec![
                "127.0.0.1:1111".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:2222".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_config_supports_toml_multi_shim_file() {
        let _guard = env_lock();
        clear_env();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
health_addr = "127.0.0.1:51824"

[[shim]]
listen_addr = "127.0.0.1:51821"
server_addrs = ["127.0.0.1:443", "127.0.0.1:444"]
key = "first-key"
magic_byte = "0xAA"
idle_timeout_secs = 45
send_queue_capacity = 17

[[shim]]
listen_addr = "127.0.0.1:51822"
server_addr = "127.0.0.1:445"
key = "second-key"
"#
        )
        .unwrap();

        let process_config =
            parse_config(["--config".to_string(), file.path().display().to_string()]).unwrap();

        assert_eq!(
            process_config.health_addr,
            "127.0.0.1:51824".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(process_config.shims.len(), 2);
        assert_eq!(
            process_config.shims[0].server_addrs,
            vec![
                "127.0.0.1:443".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:444".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(process_config.shims[0].send_queue_capacity, 17);
        assert_eq!(
            process_config.shims[1].server_addrs,
            vec!["127.0.0.1:445".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn parse_config_rejects_empty_toml_server_addrs() {
        let _guard = env_lock();
        clear_env();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
[[shim]]
listen_addr = "127.0.0.1:51821"
server_addrs = []
key = "first-key"
"#
        )
        .unwrap();

        let result = parse_config(["--config".to_string(), file.path().display().to_string()]);

        assert!(
            matches!(result, Err(ConfigParseOutcome::Error(message)) if message.contains("server address list must contain at least one address"))
        );
    }
}
