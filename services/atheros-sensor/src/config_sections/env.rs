use chrono::NaiveTime;
use ssl_proxy::config::SyncConfig;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use thiserror::Error;

use crate::audit::AuditWindow;
use crate::state_key::DetectorLimits;

pub const DEFAULT_PUBLISH_JOURNAL_PATH: &str = "/tmp/atheros-sensor-publish-journal.jsonl";

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
    pub sync: SyncConfig,
    pub audit_window: AuditWindow,
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
    pub audit_layer_stream: AuditLayerStream,
    pub memory_backlog_size: NonZeroUsize,
    pub memory_backlog_flush_interval_secs: u64,
    pub publish_journal_path: Option<PathBuf>,
    pub circuit_breaker_initial_timeout_ms: u64,
    pub circuit_breaker_max_timeout_ms: u64,
    pub authorized_network_cache_backoff_ms: u64,
    pub redpanda_request_timeout_ms: u64,
    pub mac_device_lookup_enabled: bool,
    pub mac_lookup_error_ttl_secs: u64,
    pub detector_limits: DetectorLimits,
    pub clock_skew_anomaly_us: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditLayerStream {
    Off,
    Stdout,
    Stderr,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid ATH_SENSOR_CHANNEL: {0}")]
    InvalidChannel(String),
    #[error("invalid ATH_SENSOR_SNAPLEN: {0}")]
    InvalidSnaplen(String),
    #[error("invalid ATH_SENSOR_PCAP_TIMEOUT_MS: {0}")]
    InvalidTimeout(String),
    #[error("invalid ATH_SENSOR_LOG_IDLE_SECS: {0}")]
    InvalidLogIdleSecs(String),
    #[error("invalid ATH_SENSOR_METRICS_PORT: {0}")]
    InvalidMetricsPort(String),
    #[error("invalid AUDIT_WINDOW_START: {0}")]
    InvalidAuditWindowStart(String),
    #[error("invalid AUDIT_WINDOW_END: {0}")]
    InvalidAuditWindowEnd(String),
    #[error(
        "SYNC_REDPANDA_SASL_USERNAME is set but SYNC_REDPANDA_SASL_PASSWORD or SYNC_REDPANDA_SASL_PASSWORD_FILE is missing"
    )]
    MissingSyncRedpandaSaslPassword,
    #[error("SYNC_REDPANDA_SASL_PASSWORD is set but SYNC_REDPANDA_SASL_USERNAME is missing")]
    MissingSyncRedpandaSaslUsername,
    #[error("SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION is set but SYNC_REDPANDA_SSL_KEY_LOCATION is missing")]
    MissingSyncRedpandaSslKeyLocation,
    #[error("SYNC_REDPANDA_SSL_KEY_LOCATION is set but SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION is missing")]
    MissingSyncRedpandaSslCertificateLocation,
    #[error("{variable} points at Docker service host `{host}`, but ATH_SENSOR_REQUIRE_HOST_ENDPOINTS=true requires host-reachable endpoints for host network mode; use 127.0.0.1 or another host-reachable address")]
    HostNetworkEndpoint {
        variable: &'static str,
        host: String,
    },
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let sync = SyncConfig {
            redpanda_bootstrap_servers: std::env::var("SYNC_REDPANDA_BOOTSTRAP_SERVERS")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            connect_timeout_ms: parse_u64("SYNC_REDPANDA_CONNECT_TIMEOUT_MS", 2_000)
                .unwrap_or(2_000),
            publish_timeout_ms: parse_u64("SYNC_REDPANDA_PUBLISH_TIMEOUT_MS", 2_000)
                .unwrap_or(2_000),
            publish_queue_capacity: parse_usize("SYNC_PUBLISH_QUEUE_CAPACITY", 8_192)
                .unwrap_or(8_192),
            publish_enqueue_timeout_ms: parse_u64("SYNC_PUBLISH_ENQUEUE_TIMEOUT_MS", 25)
                .unwrap_or(25),
            security_protocol: std::env::var("SYNC_REDPANDA_SECURITY_PROTOCOL")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            sasl_mechanisms: std::env::var("SYNC_REDPANDA_SASL_MECHANISMS")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            sasl_username: std::env::var("SYNC_REDPANDA_SASL_USERNAME")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            sasl_password: read_secret(
                "SYNC_REDPANDA_SASL_PASSWORD",
                "SYNC_REDPANDA_SASL_PASSWORD_FILE",
            ),
            ssl_ca_location: std::env::var("SYNC_REDPANDA_SSL_CA_LOCATION")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            ssl_certificate_location: std::env::var("SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            ssl_key_location: std::env::var("SYNC_REDPANDA_SSL_KEY_LOCATION")
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
        validate_sync_config(&sync)?;
        if read_bool("ATH_SENSOR_REQUIRE_HOST_ENDPOINTS", false) {
            validate_host_network_endpoints(sync.redpanda_bootstrap_servers.as_deref())?;
        }

        let memory_backlog_size_val = parse_usize("ATH_SENSOR_MEMORY_BACKLOG_SIZE", 1024)
            .unwrap_or(1024)
            .max(64);
        let memory_backlog_size = NonZeroUsize::new(memory_backlog_size_val)
            .unwrap_or_else(|| NonZeroUsize::new(1024).unwrap());

        let publish_journal_path = std::env::var("ATH_SENSOR_PUBLISH_JOURNAL_PATH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PUBLISH_JOURNAL_PATH));

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
            sync,
            audit_window: audit_window_from_env()?,
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
            audit_layer_stream: audit_layer_stream_from_env(),
            memory_backlog_size,
            memory_backlog_flush_interval_secs: parse_u64(
                "ATH_SENSOR_MEMORY_BACKLOG_FLUSH_INTERVAL_SECS",
                30,
            )
            .unwrap_or(30),
            publish_journal_path: Some(publish_journal_path),
            circuit_breaker_initial_timeout_ms: parse_u64(
                "ATH_SENSOR_CIRCUIT_BREAKER_INITIAL_TIMEOUT_MS",
                10_000,
            )
            .unwrap_or(10_000),
            circuit_breaker_max_timeout_ms: parse_u64(
                "ATH_SENSOR_CIRCUIT_BREAKER_MAX_TIMEOUT_MS",
                320_000,
            )
            .unwrap_or(320_000),
            authorized_network_cache_backoff_ms: parse_u64(
                "ATH_SENSOR_AUTHORIZED_NETWORK_CACHE_BACKOFF_MS",
                30_000,
            )
            .unwrap_or(30_000),
            redpanda_request_timeout_ms: parse_u64(
                "ATH_SENSOR_REDPANDA_REQUEST_TIMEOUT_MS",
                10_000,
            )
            .unwrap_or(10_000)
            .max(1),
            mac_device_lookup_enabled: read_bool("ATH_SENSOR_MAC_DEVICE_LOOKUP_ENABLED", true),
            mac_lookup_error_ttl_secs: parse_u64("ATH_SENSOR_MAC_LOOKUP_ERROR_TTL_SECS", 30)
                .unwrap_or(30)
                .max(1),
            detector_limits: DetectorLimits {
                mac_state_capacity: parse_usize("ATH_SENSOR_MAC_STATE_CAPACITY", 100_000)
                    .unwrap_or(100_000),
                ssid_state_capacity: parse_usize("ATH_SENSOR_SSID_STATE_CAPACITY", 16_384)
                    .unwrap_or(16_384),
                session_state_capacity: parse_usize("ATH_SENSOR_SESSION_STATE_CAPACITY", 65_536)
                    .unwrap_or(65_536),
                client_probe_ssid_capacity: parse_usize(
                    "ATH_SENSOR_CLIENT_PROBE_SSID_CAPACITY",
                    64,
                )
                .unwrap_or(64),
                pipeline_workers: parse_usize("ATH_SENSOR_PIPELINE_WORKERS", 1).unwrap_or(1),
                pipeline_queue_capacity: parse_usize("ATH_SENSOR_PIPELINE_QUEUE_CAPACITY", 1_024)
                    .unwrap_or(1_024),
            }
            .clamp(),
            clock_skew_anomaly_us: parse_i64("ATH_SENSOR_CLOCK_SKEW_ANOMALY_US", 250_000)
                .unwrap_or(250_000)
                .max(0),
        })
    }
}

fn validate_sync_config(sync: &SyncConfig) -> Result<(), ConfigError> {
    match (&sync.sasl_username, &sync.sasl_password) {
        (Some(_), None) => return Err(ConfigError::MissingSyncRedpandaSaslPassword),
        (None, Some(_)) => return Err(ConfigError::MissingSyncRedpandaSaslUsername),
        _ => {}
    }

    match (&sync.ssl_certificate_location, &sync.ssl_key_location) {
        (Some(_), None) => Err(ConfigError::MissingSyncRedpandaSslKeyLocation),
        (None, Some(_)) => Err(ConfigError::MissingSyncRedpandaSslCertificateLocation),
        _ => Ok(()),
    }
}

fn validate_host_network_endpoints(
    redpanda_bootstrap_servers: Option<&str>,
) -> Result<(), ConfigError> {
    if let Some(host) = redpanda_bootstrap_servers.and_then(redpanda_host) {
        reject_docker_service_host("SYNC_REDPANDA_BOOTSTRAP_SERVERS", &host)?;
    }
    Ok(())
}

fn reject_docker_service_host(variable: &'static str, host: &str) -> Result<(), ConfigError> {
    if matches!(host.to_ascii_lowercase().as_str(), "redpanda") {
        return Err(ConfigError::HostNetworkEndpoint {
            variable,
            host: host.to_string(),
        });
    }
    Ok(())
}

fn redpanda_host(redpanda_bootstrap_servers: &str) -> Option<String> {
    let trimmed = redpanda_bootstrap_servers.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .strip_prefix("tls://")
        .or_else(|| trimmed.strip_prefix("redpanda://"))
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

fn parse_u8(name: &str, default: u8) -> Result<u8, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<u8>().map_err(|_| value),
        _ => Ok(default),
    }
}

fn parse_i32(name: &str, default: i32) -> Result<i32, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<i32>().map_err(|_| value),
        _ => Ok(default),
    }
}

fn parse_i64(name: &str, default: i64) -> Result<i64, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<i64>().map_err(|_| value),
        _ => Ok(default),
    }
}

fn parse_i8(name: &str, default: i8) -> Result<i8, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<i8>().map_err(|_| value),
        _ => Ok(default),
    }
}

fn parse_optional_u16(name: &str) -> Result<Option<u16>, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            value.trim().parse::<u16>().map(Some).map_err(|_| value)
        }
        _ => Ok(None),
    }
}
