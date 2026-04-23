use std::{net::SocketAddr, process::ExitCode, time::Duration};

use ssl_proxy::{
    wg_packet_obfuscation::{parse_magic_byte, WgPacketObfuscation},
    wg_shim::{self, WgObfsShimConfig, DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_LISTEN_ADDR},
};
use tokio_util::sync::CancellationToken;
use tracing::error;

const HELP_TEXT: &str = "\
wg-obfs-shim

Linux WireGuard UDP obfuscation shim.

Usage:
  wg-obfs-shim --server <host:port> [--listen <host:port>] [--key <secret>]
               [--key-file <path>] [--magic-byte <0xNN|N>] [--idle-timeout-secs <seconds>]

Environment fallbacks:
  WG_OBFS_SERVER_ADDR
  WG_OBFS_SHIM_LISTEN_ADDR
  WG_OBFUSCATION_KEY
  WG_OBFUSCATION_KEY_FILE
  WG_OBFUSCATION_MAGIC_BYTE
  WG_OBFUSCATION_SESSION_IDLE_SECS

Example:
  wg-obfs-shim --server 192.168.1.221:443 --listen 127.0.0.1:51821 --magic-byte 0xAA
";

#[derive(Debug, Default)]
struct CliOptions {
    listen_addr: Option<String>,
    server_addr: Option<String>,
    key: Option<String>,
    key_file: Option<String>,
    magic_byte: Option<String>,
    idle_timeout_secs: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let config = match parse_config(std::env::args().skip(1)) {
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
    let handle = match wg_shim::spawn(config.clone(), shutdown.clone()).await {
        Ok(handle) => handle,
        Err(err) => {
            error!(%err, "failed to start WireGuard obfuscation shim");
            eprintln!("failed to start WireGuard obfuscation shim: {err}");
            return ExitCode::FAILURE;
        }
    };

    match tokio::signal::ctrl_c().await {
        Ok(()) => shutdown.cancel(),
        Err(err) => {
            error!(%err, "ctrl_c signal handler failed for WireGuard obfuscation shim");
            shutdown.cancel();
            let _ = handle.await;
            return ExitCode::FAILURE;
        }
    }

    let _ = handle.await;
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
) -> Result<WgObfsShimConfig, ConfigParseOutcome> {
    let mut options = CliOptions::default();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Err(ConfigParseOutcome::Help),
            "--listen" => options.listen_addr = Some(next_value(&mut args, "--listen")?),
            "--server" => options.server_addr = Some(next_value(&mut args, "--server")?),
            "--key" => options.key = Some(next_value(&mut args, "--key")?),
            "--key-file" => options.key_file = Some(next_value(&mut args, "--key-file")?),
            "--magic-byte" => options.magic_byte = Some(next_value(&mut args, "--magic-byte")?),
            "--idle-timeout-secs" => {
                options.idle_timeout_secs = Some(next_value(&mut args, "--idle-timeout-secs")?)
            }
            other => {
                return Err(ConfigParseOutcome::Error(format!(
                    "unknown argument: {other}"
                )))
            }
        }
    }

    let listen_addr = parse_socket_addr(
        options
            .listen_addr
            .clone()
            .or_else(|| std::env::var("WG_OBFS_SHIM_LISTEN_ADDR").ok())
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string()),
        "listen address",
    )?;
    let server_addr = parse_socket_addr(
        options
            .server_addr
            .clone()
            .or_else(|| std::env::var("WG_OBFS_SERVER_ADDR").ok())
            .ok_or_else(|| {
                ConfigParseOutcome::Error(
                    "missing required server address; set --server or WG_OBFS_SERVER_ADDR"
                        .to_string(),
                )
            })?,
        "server address",
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

    Ok(WgObfsShimConfig::new(
        listen_addr,
        server_addr,
        WgPacketObfuscation::new(key.into_bytes(), magic_byte),
        Duration::from_secs(idle_timeout_secs),
    ))
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, ConfigParseOutcome> {
    args.next()
        .ok_or_else(|| ConfigParseOutcome::Error(format!("missing value for {flag}")))
}

fn parse_socket_addr(raw: String, label: &str) -> Result<SocketAddr, ConfigParseOutcome> {
    raw.parse::<SocketAddr>().map_err(|_| {
        ConfigParseOutcome::Error(format!("invalid {label} {raw:?}; expected host:port"))
    })
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
    use std::sync::{Mutex, OnceLock};

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
            "WG_OBFS_SHIM_LISTEN_ADDR",
            "WG_OBFUSCATION_KEY",
            "WG_OBFUSCATION_KEY_FILE",
            "WG_OBFUSCATION_MAGIC_BYTE",
            "WG_OBFUSCATION_SESSION_IDLE_SECS",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn parse_config_supports_cli_overrides() {
        let _guard = env_lock();
        clear_env();
        let config = parse_config([
            "--server".to_string(),
            "192.168.1.221:443".to_string(),
            "--listen".to_string(),
            "127.0.0.1:51822".to_string(),
            "--key".to_string(),
            "super-secret".to_string(),
            "--magic-byte".to_string(),
            "0xAA".to_string(),
            "--idle-timeout-secs".to_string(),
            "45".to_string(),
        ])
        .unwrap();

        assert_eq!(
            config.listen_addr,
            "127.0.0.1:51822".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            config.server_addr,
            "192.168.1.221:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.obfuscation.magic_byte, Some(0xAA));
        assert_eq!(config.obfuscation.key, b"super-secret".to_vec());
        assert_eq!(config.idle_timeout, Duration::from_secs(45));
    }

    #[test]
    fn parse_config_requires_server_address() {
        let _guard = env_lock();
        clear_env();
        let result = parse_config(["--key".to_string(), "super-secret".to_string()]);

        assert_eq!(
            result,
            Err(ConfigParseOutcome::Error(
                "missing required server address; set --server or WG_OBFS_SERVER_ADDR".to_string()
            ))
        );
    }
}
