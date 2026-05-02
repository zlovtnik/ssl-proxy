//! Environment-variable-only configuration model.
//!
//! All settings are read from environment variables at startup via AppConfig::from_env; there is
//! no config file. Secrets support a file-fallback pattern: read_secret checks the plain variable
//! first, then falls back to reading the path named by the _FILE variant, enabling Docker secrets
//! mounts without exposing values in the environment. ATH_SENSOR_REQUIRE_HOST_ENDPOINTS is a
//! deployment guard that rejects Docker service hostnames ("nats", "postgres") in NATS and
//! DATABASE_URL, enforcing host-network-mode endpoints when the sensor runs outside Docker.
//!
//! # AppConfig field mutability
//!
//! Fields that can be updated at runtime via a NATS push (no restart required):
//! `bpf` (BPF filter), `channel` (via `wireless.config.sensor`), and the `audit_window`
//! schedule (via `wireless.audit.config`).
//!
//! All other fields - including `database_url`, `snaplen`, `pcap_timeout_ms`,
//! `mac_device_lookup_enabled`, `log_idle_secs`, and all backlog/metrics settings - are
//! read once at startup and require a process restart to change.

use chrono::NaiveTime;
use ssl_proxy::config::SyncConfig;
use std::str::FromStr;
use thiserror::Error;
use tokio_postgres::{config::Host, Config as PostgresConfig};

use crate::audit::AuditWindow;

#[derive(Clone)]
pub struct AppConfig {
    pub device_override: Option<String>,
    pub location_id: String,
    pub channel: u8,
    pub reg_domain: String,
    pub bpf: String,
    pub snaplen: i32,
    pub pcap_timeout_ms: i32,
    pub log_idle_secs: u64,
    pub database_url: String,
    pub sync: SyncConfig,
    pub audit_window: AuditWindow,
    pub mac_device_lookup_enabled: bool,
    pub mac_device_cache_size: usize,
    pub channel_hop_enabled: bool,
    pub channel_hop_interval_ms: u64,
    pub client_inventory_flush_secs: u64,
    pub signal_anomaly_dbm_delta: i8,
    pub deauth_flood_threshold: u64,
    pub deauth_flood_window_secs: u64,
    pub deauth_flood_cooldown_secs: u64,
    pub export_handshakes: bool,
    pub handshake_ttl_secs: u64,
    pub authorized_network_cache_ttl_secs: u64,
    pub metrics_port: Option<u16>,
    pub shutdown_grace_secs: u64,
    pub backlog_max_attempts: i32,
    pub backlog_max_age_hours: i64,
    pub mac_lookup_error_ttl_secs: u64,
    pub audit_layer_stream: AuditLayerStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditLayerStream {
    Off,
    Stdout,
    Stderr,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    /// Fired when `DATABASE_URL` is not set or is blank.
    #[error("DATABASE_URL is required")]
    MissingDatabaseUrl,
    /// Fired when `ATH_SENSOR_CHANNEL` is set but cannot be parsed as a `u8`.
    #[error("invalid ATH_SENSOR_CHANNEL: {0}")]
    InvalidChannel(String),
    /// Fired when `ATH_SENSOR_SNAPLEN` is set but cannot be parsed as an `i32`.
    #[error("invalid ATH_SENSOR_SNAPLEN: {0}")]
    InvalidSnaplen(String),
    /// Fired when `ATH_SENSOR_PCAP_TIMEOUT_MS` is set but cannot be parsed as an `i32`.
    #[error("invalid ATH_SENSOR_PCAP_TIMEOUT_MS: {0}")]
    InvalidTimeout(String),
    /// Fired when `ATH_SENSOR_LOG_IDLE_SECS` is set but cannot be parsed as a `u64`.
    #[error("invalid ATH_SENSOR_LOG_IDLE_SECS: {0}")]
    InvalidLogIdleSecs(String),
    /// Fired when `ATH_SENSOR_METRICS_PORT` is set but cannot be parsed as a `u16`.
    #[error("invalid ATH_SENSOR_METRICS_PORT: {0}")]
    InvalidMetricsPort(String),
    /// Fired when `AUDIT_WINDOW_START` is set but cannot be parsed as `HH:MM`.
    #[error("invalid AUDIT_WINDOW_START: {0}")]
    InvalidAuditWindowStart(String),
    /// Fired when `AUDIT_WINDOW_END` is set but cannot be parsed as `HH:MM`.
    #[error("invalid AUDIT_WINDOW_END: {0}")]
    InvalidAuditWindowEnd(String),
    /// Fired when `DATABASE_URL` is set but cannot be parsed as a valid Postgres connection string.
    #[error("invalid DATABASE_URL: {0}")]
    InvalidDatabaseUrl(String),
    /// Fired when `ATH_SENSOR_REQUIRE_HOST_ENDPOINTS=true` and a NATS or Postgres URL resolves
    /// to a Docker service hostname (`nats` or `postgres`) instead of a host-reachable address.
    #[error("{variable} points at Docker service host `{host}`, but ATH_SENSOR_REQUIRE_HOST_ENDPOINTS=true requires host-reachable endpoints for host network mode; use 127.0.0.1 or another host-reachable address")]
    HostNetworkEndpoint {
        variable: &'static str,
        host: String,
    },
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let sync = SyncConfig {
            nats_url: std::env::var("SYNC_NATS_URL")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            connect_timeout_ms: parse_u64("SYNC_NATS_CONNECT_TIMEOUT_MS", 2_000).unwrap_or(2_000),
            publish_timeout_ms: parse_u64("SYNC_NATS_PUBLISH_TIMEOUT_MS", 2_000).unwrap_or(2_000),
            publish_queue_capacity: parse_usize("SYNC_PUBLISH_QUEUE_CAPACITY", 8_192)
                .unwrap_or(8_192),
            publish_enqueue_timeout_ms: parse_u64("SYNC_PUBLISH_ENQUEUE_TIMEOUT_MS", 25)
                .unwrap_or(25),
            username: std::env::var("SYNC_NATS_USERNAME")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            password: read_secret("SYNC_NATS_PASSWORD", "SYNC_NATS_PASSWORD_FILE"),
            tls_enabled: read_bool("SYNC_NATS_TLS_ENABLED", false),
            tls_server_name: std::env::var("SYNC_NATS_TLS_SERVER_NAME")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            tls_ca_cert_path: std::env::var("SYNC_NATS_TLS_CA_CERT_PATH")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            tls_client_cert_path: std::env::var("SYNC_NATS_TLS_CLIENT_CERT_PATH")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            tls_client_key_path: std::env::var("SYNC_NATS_TLS_CLIENT_KEY_PATH")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            inline_payload_max_bytes: parse_usize("SYNC_INLINE_PAYLOAD_MAX_BYTES", 65_535)
                .unwrap_or(65_535),
            outbox_dir: std::env::var("SYNC_OUTBOX_DIR")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "/tmp/atheros-sensor-sync-outbox".to_string()),
            publish_spool_dir: std::env::var("SYNC_PUBLISH_SPOOL_DIR")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "/tmp/atheros-sensor-sync-outbox/publish-spool".to_string()),
        };
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or(ConfigError::MissingDatabaseUrl)?;

        if read_bool("ATH_SENSOR_REQUIRE_HOST_ENDPOINTS", false) {
            validate_host_network_endpoints(sync.nats_url.as_deref(), &database_url)?;
        }

        Ok(Self {
            device_override: std::env::var("ATH_SENSOR_DEVICE")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            location_id: std::env::var("ATH_SENSOR_LOCATION_ID")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unknown-location".to_string()),
            channel: parse_u8("ATH_SENSOR_CHANNEL", 6).map_err(ConfigError::InvalidChannel)?,
            reg_domain: std::env::var("ATH_SENSOR_REG_DOMAIN")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "US".to_string()),
            bpf: std::env::var("ATH_SENSOR_BPF")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "type mgt or type data".to_string()),
            snaplen: parse_i32("ATH_SENSOR_SNAPLEN", 4096).map_err(ConfigError::InvalidSnaplen)?,
            pcap_timeout_ms: parse_i32("ATH_SENSOR_PCAP_TIMEOUT_MS", 250)
                .map_err(ConfigError::InvalidTimeout)?,
            log_idle_secs: parse_u64("ATH_SENSOR_LOG_IDLE_SECS", 30)
                .map_err(ConfigError::InvalidLogIdleSecs)?,
            database_url,
            sync,
            audit_window: audit_window_from_env()?,
            mac_device_lookup_enabled: read_bool("ATH_SENSOR_MAC_DEVICE_LOOKUP_ENABLED", true),
            mac_device_cache_size: parse_usize("ATH_SENSOR_MAC_DEVICE_CACHE_SIZE", 4_096)
                .unwrap_or(4_096)
                .max(1),
            channel_hop_enabled: read_bool("ATH_SENSOR_CHANNEL_HOP_ENABLED", false),
            channel_hop_interval_ms: parse_u64("ATH_SENSOR_CHANNEL_HOP_INTERVAL_MS", 1_000)
                .unwrap_or(1_000)
                .max(100),
            client_inventory_flush_secs: parse_u64("ATH_SENSOR_CLIENT_INVENTORY_FLUSH_SECS", 60)
                .unwrap_or(60)
                .max(1),
            signal_anomaly_dbm_delta: parse_i8("ATH_SENSOR_SIGNAL_ANOMALY_DBM_DELTA", 15)
                .unwrap_or(15)
                .max(1),
            deauth_flood_threshold: parse_u64("ATH_SENSOR_DEAUTH_FLOOD_THRESHOLD", 20)
                .unwrap_or(20)
                .max(1),
            deauth_flood_window_secs: parse_u64("ATH_SENSOR_DEAUTH_FLOOD_WINDOW_SECS", 30)
                .unwrap_or(30)
                .max(1),
            deauth_flood_cooldown_secs: parse_u64("ATH_SENSOR_DEAUTH_FLOOD_COOLDOWN_SECS", 60)
                .unwrap_or(60)
                .max(1),
            export_handshakes: read_bool("ATH_SENSOR_EXPORT_HANDSHAKES", false),
            handshake_ttl_secs: parse_u64("ATH_SENSOR_HANDSHAKE_TTL_SECS", 60)
                .unwrap_or(60)
                .max(1),
            authorized_network_cache_ttl_secs: parse_u64(
                "ATH_SENSOR_AUTHORIZED_NETWORK_CACHE_TTL_SECS",
                60,
            )
            .unwrap_or(60)
            .max(1),
            metrics_port: parse_optional_u16("ATH_SENSOR_METRICS_PORT")
                .map_err(ConfigError::InvalidMetricsPort)?,
            shutdown_grace_secs: parse_u64("ATH_SENSOR_SHUTDOWN_GRACE_SECS", 5)
                .unwrap_or(5)
                .max(1),
            backlog_max_attempts: parse_i32("ATH_SENSOR_BACKLOG_MAX_ATTEMPTS", 10)
                .unwrap_or(10)
                .max(1),
            backlog_max_age_hours: parse_i64("ATH_SENSOR_BACKLOG_MAX_AGE_HOURS", 72)
                .unwrap_or(72)
                .max(1),
            mac_lookup_error_ttl_secs: parse_u64("ATH_SENSOR_MAC_LOOKUP_ERROR_TTL_SECS", 30)
                .unwrap_or(30)
                .max(1),
            audit_layer_stream: audit_layer_stream_from_env(),
        })
    }
}

fn validate_host_network_endpoints(
    nats_url: Option<&str>,
    database_url: &str,
) -> Result<(), ConfigError> {
    if let Some(host) = nats_url.and_then(nats_host) {
        reject_docker_service_host("SYNC_NATS_URL", &host)?;
    }

    let postgres_config = PostgresConfig::from_str(database_url)
        .map_err(|error| ConfigError::InvalidDatabaseUrl(error.to_string()))?;
    for host in postgres_config.get_hosts() {
        if let Host::Tcp(host) = host {
            reject_docker_service_host("DATABASE_URL", host)?;
        }
    }

    Ok(())
}

fn reject_docker_service_host(variable: &'static str, host: &str) -> Result<(), ConfigError> {
    if matches!(host.to_ascii_lowercase().as_str(), "nats" | "postgres") {
        return Err(ConfigError::HostNetworkEndpoint {
            variable,
            host: host.to_string(),
        });
    }
    Ok(())
}
//todo: doc it!
fn nats_host(nats_url: &str) -> Option<String> {
    let trimmed = nats_url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .strip_prefix("tls://")
        .or_else(|| trimmed.strip_prefix("nats://"))
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split('/')
        .next()?
        .trim()
        .rsplit('@')
        .next()
        .unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map(|(host, _)| host.trim_start_matches('['))
            .unwrap_or(authority)
    } else {
        authority
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority)
    };
    let host = host.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}
//todo: doc it!
fn audit_window_from_env() -> Result<AuditWindow, ConfigError> {
    let timezone = std::env::var("AUDIT_WINDOW_TZ")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| Some(ssl_proxy::time::EASTERN_TIME_ZONE_NAME.to_string()));
    let days = std::env::var("AUDIT_WINDOW_DAYS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let start = match std::env::var("AUDIT_WINDOW_START")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(value) => Some(
            NaiveTime::parse_from_str(&value, "%H:%M")
                .map_err(|_| ConfigError::InvalidAuditWindowStart(value))?,
        ),
        None => None,
    };
    let end = match std::env::var("AUDIT_WINDOW_END")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(value) => Some(
            NaiveTime::parse_from_str(&value, "%H:%M")
                .map_err(|_| ConfigError::InvalidAuditWindowEnd(value))?,
        ),
        None => None,
    };

    Ok(AuditWindow::from_parts(timezone, days, start, end))
}
//todo: doc it!
fn parse_u8(name: &str, default: u8) -> Result<u8, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<u8>().map_err(|_| value),
        _ => Ok(default),
    }
}
//todo: doc it!
fn parse_i32(name: &str, default: i32) -> Result<i32, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<i32>().map_err(|_| value),
        _ => Ok(default),
    }
}
//todo: doc it!
fn parse_i64(name: &str, default: i64) -> Result<i64, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<i64>().map_err(|_| value),
        _ => Ok(default),
    }
}
//todo: doc it!
fn parse_i8(name: &str, default: i8) -> Result<i8, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<i8>().map_err(|_| value),
        _ => Ok(default),
    }
}
//todo: doc it!
fn parse_optional_u16(name: &str) -> Result<Option<u16>, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            value.trim().parse::<u16>().map(Some).map_err(|_| value)
        }
        _ => Ok(None),
    }
}
//todo: doc it!
fn audit_layer_stream_from_env() -> AuditLayerStream {
    match std::env::var("ATH_SENSOR_AUDIT_LAYER_STREAM")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("stdout") => AuditLayerStream::Stdout,
        Some("stderr") => AuditLayerStream::Stderr,
        _ => AuditLayerStream::Off,
    }
}
//todo: doc it!
fn parse_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<u64>().map_err(|_| value),
        _ => Ok(default),
    }
}
//todo: doc it!
fn parse_usize(name: &str, default: usize) -> Result<usize, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<usize>().map_err(|_| value),
        _ => Ok(default),
    }
}
//todo: doc it!
fn read_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}
//todo: doc it!
fn read_secret(value_var: &str, file_var: &str) -> Option<String> {
    if let Ok(value) = std::env::var(value_var) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let path = std::env::var(file_var).ok()?;
    let trimmed = std::fs::read_to_string(path).ok()?;
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct TestEnv {
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            clear_env();
        }
    }

    fn test_env() -> TestEnv {
        let guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        clear_env();
        TestEnv { _guard: guard }
    }

    fn clear_env() {
        for name in [
            "ATH_SENSOR_REQUIRE_HOST_ENDPOINTS",
            "DATABASE_URL",
            "SYNC_NATS_URL",
            "SYNC_NATS_CONNECT_TIMEOUT_MS",
            "SYNC_NATS_PUBLISH_TIMEOUT_MS",
            "SYNC_NATS_USERNAME",
            "SYNC_NATS_PASSWORD",
            "SYNC_NATS_PASSWORD_FILE",
            "SYNC_NATS_TLS_ENABLED",
            "SYNC_NATS_TLS_SERVER_NAME",
            "SYNC_NATS_TLS_CA_CERT_PATH",
            "SYNC_NATS_TLS_CLIENT_CERT_PATH",
            "SYNC_NATS_TLS_CLIENT_KEY_PATH",
            "SYNC_INLINE_PAYLOAD_MAX_BYTES",
            "SYNC_OUTBOX_DIR",
            "ATH_SENSOR_DEVICE",
            "ATH_SENSOR_LOCATION_ID",
            "ATH_SENSOR_CHANNEL",
            "ATH_SENSOR_REG_DOMAIN",
            "ATH_SENSOR_BPF",
            "ATH_SENSOR_SNAPLEN",
            "ATH_SENSOR_PCAP_TIMEOUT_MS",
            "ATH_SENSOR_LOG_IDLE_SECS",
            "ATH_SENSOR_MAC_DEVICE_LOOKUP_ENABLED",
            "ATH_SENSOR_MAC_DEVICE_CACHE_SIZE",
            "ATH_SENSOR_CHANNEL_HOP_ENABLED",
            "ATH_SENSOR_CHANNEL_HOP_INTERVAL_MS",
            "ATH_SENSOR_CLIENT_INVENTORY_FLUSH_SECS",
            "ATH_SENSOR_SIGNAL_ANOMALY_DBM_DELTA",
            "ATH_SENSOR_DEAUTH_FLOOD_THRESHOLD",
            "ATH_SENSOR_DEAUTH_FLOOD_WINDOW_SECS",
            "ATH_SENSOR_DEAUTH_FLOOD_COOLDOWN_SECS",
            "ATH_SENSOR_EXPORT_HANDSHAKES",
            "ATH_SENSOR_HANDSHAKE_TTL_SECS",
            "ATH_SENSOR_AUTHORIZED_NETWORK_CACHE_TTL_SECS",
            "ATH_SENSOR_METRICS_PORT",
            "ATH_SENSOR_SHUTDOWN_GRACE_SECS",
            "ATH_SENSOR_BACKLOG_MAX_ATTEMPTS",
            "ATH_SENSOR_BACKLOG_MAX_AGE_HOURS",
            "ATH_SENSOR_MAC_LOOKUP_ERROR_TTL_SECS",
            "ATH_SENSOR_AUDIT_LAYER_STREAM",
            "AUDIT_WINDOW_TZ",
            "AUDIT_WINDOW_DAYS",
            "AUDIT_WINDOW_START",
            "AUDIT_WINDOW_END",
        ] {
            std::env::remove_var(name);
        }
    }

    #[test]
    fn host_endpoint_validation_accepts_loopback_endpoints() {
        let _env = test_env();
        std::env::set_var("ATH_SENSOR_REQUIRE_HOST_ENDPOINTS", "true");
        std::env::set_var("SYNC_NATS_URL", "nats://127.0.0.1:4222");
        std::env::set_var("DATABASE_URL", "postgres://sync:sync@127.0.0.1:5432/sync");

        let config = AppConfig::from_env().unwrap();

        assert_eq!(
            config.sync.nats_url.as_deref(),
            Some("nats://127.0.0.1:4222")
        );
        assert_eq!(config.sync.publish_timeout_ms, 2_000);
        assert_eq!(
            config.database_url,
            "postgres://sync:sync@127.0.0.1:5432/sync"
        );
    }

    #[test]
    fn log_idle_secs_defaults_to_30() {
        let _env = test_env();
        std::env::set_var("DATABASE_URL", "postgres://sync:sync@127.0.0.1:5432/sync");

        let config = AppConfig::from_env().unwrap();

        assert_eq!(config.log_idle_secs, 30);
        assert!(config.mac_device_lookup_enabled);
        assert_eq!(config.mac_device_cache_size, 4_096);
    }

    #[test]
    fn log_idle_secs_accepts_override() {
        let _env = test_env();
        std::env::set_var("DATABASE_URL", "postgres://sync:sync@127.0.0.1:5432/sync");
        std::env::set_var("ATH_SENSOR_LOG_IDLE_SECS", "5");

        let config = AppConfig::from_env().unwrap();

        assert_eq!(config.log_idle_secs, 5);
    }

    #[test]
    fn log_idle_secs_allows_zero_to_disable() {
        let _env = test_env();
        std::env::set_var("DATABASE_URL", "postgres://sync:sync@127.0.0.1:5432/sync");
        std::env::set_var("ATH_SENSOR_LOG_IDLE_SECS", "0");

        let config = AppConfig::from_env().unwrap();

        assert_eq!(config.log_idle_secs, 0);
    }

    #[test]
    fn log_idle_secs_rejects_invalid_value() {
        let _env = test_env();
        std::env::set_var("DATABASE_URL", "postgres://sync:sync@127.0.0.1:5432/sync");
        std::env::set_var("ATH_SENSOR_LOG_IDLE_SECS", "soon");

        let error = match AppConfig::from_env() {
            Ok(_) => panic!("expected invalid idle log interval to fail configuration"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConfigError::InvalidLogIdleSecs(ref value) if value == "soon"
        ));
    }

    #[test]
    fn host_endpoint_validation_rejects_nats_service_host() {
        let _env = test_env();
        std::env::set_var("ATH_SENSOR_REQUIRE_HOST_ENDPOINTS", "true");
        std::env::set_var("SYNC_NATS_URL", "nats://nats:4222");
        std::env::set_var("DATABASE_URL", "postgres://sync:sync@127.0.0.1:5432/sync");

        let error = match AppConfig::from_env() {
            Ok(_) => panic!("expected host-network endpoint validation to reject NATS host"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConfigError::HostNetworkEndpoint {
                variable: "SYNC_NATS_URL",
                ref host
            } if host == "nats"
        ));
    }

    #[test]
    fn nats_host_extracts_host_with_userinfo() {
        assert_eq!(
            nats_host("nats://user:pass@nats:4222").as_deref(),
            Some("nats")
        );
    }

    #[test]
    fn host_endpoint_validation_rejects_postgres_service_host() {
        let _env = test_env();
        std::env::set_var("ATH_SENSOR_REQUIRE_HOST_ENDPOINTS", "true");
        std::env::set_var("SYNC_NATS_URL", "nats://127.0.0.1:4222");
        std::env::set_var("DATABASE_URL", "postgres://sync:sync@postgres:5432/sync");

        let error = match AppConfig::from_env() {
            Ok(_) => panic!("expected host-network endpoint validation to reject Postgres host"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConfigError::HostNetworkEndpoint {
                variable: "DATABASE_URL",
                ref host
            } if host == "postgres"
        ));
    }
}
