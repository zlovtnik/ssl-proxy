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
               [--metrics-addr <host:port> (requires --features metrics)] [--encryption-mode <xor|aead>]
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
  WG_OBFS_SHIM_METRICS_ADDR (requires --features metrics)
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
