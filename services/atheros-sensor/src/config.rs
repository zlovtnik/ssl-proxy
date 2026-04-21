use chrono::NaiveTime;
use ssl_proxy::config::SyncConfig;
use thiserror::Error;

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
    pub database_url: String,
    pub sync: SyncConfig,
    pub audit_window: AuditWindow,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("DATABASE_URL is required")]
    MissingDatabaseUrl,
    #[error("invalid ATH_SENSOR_CHANNEL: {0}")]
    InvalidChannel(String),
    #[error("invalid ATH_SENSOR_SNAPLEN: {0}")]
    InvalidSnaplen(String),
    #[error("invalid ATH_SENSOR_PCAP_TIMEOUT_MS: {0}")]
    InvalidTimeout(String),
    #[error("invalid AUDIT_WINDOW_START: {0}")]
    InvalidAuditWindowStart(String),
    #[error("invalid AUDIT_WINDOW_END: {0}")]
    InvalidAuditWindowEnd(String),
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let sync = SyncConfig {
            nats_url: std::env::var("SYNC_NATS_URL")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            connect_timeout_ms: parse_u64("SYNC_NATS_CONNECT_TIMEOUT_MS", 2_000).unwrap_or(2_000),
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
        };

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
                .unwrap_or_else(|| "type mgt".to_string()),
            snaplen: parse_i32("ATH_SENSOR_SNAPLEN", 4096).map_err(ConfigError::InvalidSnaplen)?,
            pcap_timeout_ms: parse_i32("ATH_SENSOR_PCAP_TIMEOUT_MS", 250)
                .map_err(ConfigError::InvalidTimeout)?,
            database_url: std::env::var("DATABASE_URL")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .ok_or(ConfigError::MissingDatabaseUrl)?,
            sync,
            audit_window: audit_window_from_env()?,
        })
    }
}

fn audit_window_from_env() -> Result<AuditWindow, ConfigError> {
    let timezone = std::env::var("AUDIT_WINDOW_TZ")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
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

fn parse_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<u64>().map_err(|_| value),
        _ => Ok(default),
    }
}

fn parse_usize(name: &str, default: usize) -> Result<usize, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            value.trim().parse::<usize>().map_err(|_| value)
        }
        _ => Ok(default),
    }
}

fn read_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

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
