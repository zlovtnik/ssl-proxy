use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use chrono::NaiveTime;
use serde::Deserialize;
use sync_plane::SyncConfig;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tracing::{error, info, warn};

use crate::{
    audit::{AuditWindow, SharedAuditWindow},
    backlog::inline_request_reply_transport_supported,
    capture::CaptureControl,
    channel_control::set_channel,
    model::AuditContext,
};

pub const AUDIT_CONFIG_TOPIC: &str = "wireless.audit.config";
pub const AUTHORIZED_NETWORKS_CONFIG_TOPIC: &str = "wireless.config.authorized_networks";
pub const SENSOR_CONFIG_TOPIC: &str = "wireless.config.sensor";
const REDPANDA_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn redpanda_security_protocol_uses_tls(config: &SyncConfig) -> bool {
    config
        .security_protocol
        .as_deref()
        .is_some_and(|protocol| protocol.to_ascii_uppercase().contains("SSL"))
}

pub fn supports_config_subscriber_transport(config: &SyncConfig) -> bool {
    let Some(redpanda_bootstrap_servers) = config.redpanda_bootstrap_servers.as_deref() else {
        return false;
    };
    let trimmed = redpanda_bootstrap_servers.trim();
    trimmed.starts_with("redpanda://")
        && !redpanda_security_protocol_uses_tls(config)
        && inline_request_reply_transport_supported(trimmed)
}

pub fn config_subscriber_disabled_reason(config: &SyncConfig) -> Option<String> {
    let redpanda_bootstrap_servers = config.redpanda_bootstrap_servers.as_deref()?;
    let trimmed = redpanda_bootstrap_servers.trim();
    if !trimmed.starts_with("redpanda://") {
        return Some("config subscribers support plain redpanda:// endpoints only".to_string());
    }
    if redpanda_security_protocol_uses_tls(config) {
        return Some(
            "config subscribers do not support SSL-enabled Redpanda security protocols".to_string(),
        );
    }
    (!inline_request_reply_transport_supported(trimmed)).then(|| {
        format!(
            "Kafka Redpanda listener {redpanda_bootstrap_servers} does not expose the raw subscriber protocol"
        )
    })
}

#[derive(Debug, Deserialize)]
struct AuditWindowUpdate {
    location_id: Option<String>,
    timezone: Option<String>,
    days: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SensorConfigUpdate {
    location_id: Option<String>,
    bpf: Option<String>,
    channel: Option<u8>,
    log_idle_secs: Option<u64>,
}

#[derive(Debug, Eq, PartialEq)]
/// Parsed components of a `redpanda://[user:pass@]host:port` URL.
///
/// Credentials are percent-decoded before storage; callers that embed special characters
/// (e.g. `@`, `:`) in usernames or passwords must percent-encode them in the URL or the
/// authority split will produce incorrect user/host boundaries.
struct RedpandaEndpoint {
    address: String,
    user: Option<String>,
    password: Option<String>,
}

/// Spawns the audit window config subscriber with automatic reconnect loop. Any error from
/// run_subscriber_once logs a warning and retries after 5 seconds indefinitely, allowing
/// transient Redpanda restarts without restarting the sensor process.
pub fn spawn_audit_window_config_subscriber(
    config: SyncConfig,
    location_id: String,
    audit_window: SharedAuditWindow,
) {
    tokio::spawn(async move {
        loop {
            if let Err(error) =
                run_subscriber_once(&config, &location_id, Arc::clone(&audit_window)).await
            {
                warn!(%error, topic = AUDIT_CONFIG_TOPIC, "audit config subscriber disconnected");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Spawns the authorized network config subscriber with automatic reconnect loop. Only bumps
/// a generation counter; the actual reload happens lazily in process_packet when the generation
/// changes, avoiding blocking the subscriber task on coordinator requests.
pub fn spawn_authorized_network_config_subscriber(config: SyncConfig, generation: Arc<AtomicU64>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) =
                run_invalidation_subscriber_once(&config, Arc::clone(&generation)).await
            {
                warn!(%error, topic = AUTHORIZED_NETWORKS_CONFIG_TOPIC, "authorized network config subscriber disconnected");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Spawns the sensor config subscriber with automatic reconnect loop. Channel and BPF filter
/// updates take effect immediately via set_channel and capture_control.apply_filter. The
/// log_idle_secs requires a sensor restart to take effect.
pub fn spawn_sensor_config_subscriber(
    config: SyncConfig,
    location_id: String,
    context: Arc<RwLock<AuditContext>>,
    capture_control: CaptureControl,
    current_filter: Arc<RwLock<String>>,
) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = run_sensor_config_subscriber_once(
                &config,
                &location_id,
                Arc::clone(&context),
                capture_control.clone(),
                Arc::clone(&current_filter),
            )
            .await
            {
                warn!(%error, topic = SENSOR_CONFIG_TOPIC, "sensor config subscriber disconnected");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Reconnects on any error (connection drop, parse failure, Redpanda -ERR) with 5-second
/// backoff; allows transient Redpanda restarts without restarting the sensor process.
async fn run_subscriber_once(
    config: &SyncConfig,
    location_id: &str,
    audit_window: SharedAuditWindow,
) -> Result<(), String> {
    let Some(redpanda_bootstrap_servers) = config.redpanda_bootstrap_servers.as_deref() else {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        return Ok(());
    };
    if redpanda_bootstrap_servers.starts_with("tls://")
        || redpanda_security_protocol_uses_tls(config)
    {
        return Err(
            "audit config subscriber supports plain redpanda:// endpoints only".to_string(),
        );
    }
    let endpoint = parse_redpanda_endpoint(redpanda_bootstrap_servers)?;
    let stream = timeout(
        REDPANDA_CONNECT_TIMEOUT,
        TcpStream::connect(&endpoint.address),
    )
    .await
    .map_err(|_| {
        format!(
            "connect to Redpanda {} timed out after {:?}",
            endpoint.address, REDPANDA_CONNECT_TIMEOUT
        )
    })?
    .map_err(|error| format!("connect to Redpanda {}: {error}", endpoint.address))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|error| format!("read Redpanda INFO: {error}"))?;
    if !line.starts_with("INFO ") {
        return Err(format!("expected Redpanda INFO banner, got: {line}"));
    }

    let user = config.sasl_username.clone().or(endpoint.user);
    let password = config.sasl_password.clone().or(endpoint.password);
    let mut connect_options = serde_json::json!({
        "lang": "rust",
        "version": env!("CARGO_PKG_VERSION"),
        "verbose": false,
        "pedantic": false
    });
    if let Some(user) = user {
        connect_options["user"] = serde_json::Value::String(user);
    }
    if let Some(password) = password {
        connect_options["pass"] = serde_json::Value::String(password);
    }
    write_half
        .write_all(
            format!(
                "CONNECT {}\r\nPING\r\nSUB {AUDIT_CONFIG_TOPIC} 1\r\n",
                connect_options
            )
            .as_bytes(),
        )
        .await
        .map_err(|error| format!("subscribe to Redpanda: {error}"))?;
    info!(
        topic = AUDIT_CONFIG_TOPIC,
        "audit config subscriber connected"
    );

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .await
            .map_err(|error| format!("read Redpanda frame: {error}"))?;
        if bytes == 0 {
            return Err("Redpanda connection closed".to_string());
        }
        let trimmed = line.trim_end();
        if trimmed == "PING" {
            write_half
                .write_all(b"PONG\r\n")
                .await
                .map_err(|error| format!("write Redpanda PONG: {error}"))?;
            continue;
        }
        if trimmed.starts_with("+OK") {
            continue;
        }
        if trimmed.starts_with("-ERR") {
            return Err(format!("Redpanda returned {trimmed}"));
        }
        if !trimmed.starts_with("MSG ") {
            continue;
        }

        let size = trimmed
            .split_whitespace()
            .last()
            .ok_or_else(|| format!("missing Redpanda message size: {trimmed}"))?
            .parse::<usize>()
            .map_err(|error| format!("invalid Redpanda message size: {error}"))?;
        let mut payload = vec![0_u8; size];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|error| format!("read Redpanda payload: {error}"))?;
        let mut terminator = [0_u8; 2];
        reader
            .read_exact(&mut terminator)
            .await
            .map_err(|error| format!("read Redpanda payload terminator: {error}"))?;
        if terminator != *b"\r\n" {
            return Err("invalid Redpanda payload terminator".to_string());
        }
        let payload = String::from_utf8(payload)
            .map_err(|error| format!("audit config payload is not UTF-8: {error}"))?;
        match parse_audit_window_update(&payload, location_id) {
            Ok(Some(window)) => match audit_window.write() {
                Ok(mut current) => {
                    *current = window;
                    info!(
                        topic = AUDIT_CONFIG_TOPIC,
                        location_id, "audit window updated from Redpanda"
                    );
                }
                Err(error) => {
                    error!(%error, "audit window lock poisoned; ignoring config update");
                }
            },
            Ok(None) => {}
            Err(error) => warn!(%error, "invalid audit window config update"),
        }
    }
}

/// Reconnects on any error with 5-second backoff; increments generation counter on
/// every message to invalidate the authorized network cache in the main loop.
async fn run_invalidation_subscriber_once(
    config: &SyncConfig,
    generation: Arc<AtomicU64>,
) -> Result<(), String> {
    run_message_loop(config, AUTHORIZED_NETWORKS_CONFIG_TOPIC, |payload| {
        generation.fetch_add(1, Ordering::Relaxed);
        info!(
            topic = AUTHORIZED_NETWORKS_CONFIG_TOPIC,
            payload_bytes = payload.len(),
            "authorized network cache invalidated from Redpanda"
        );
        Ok(())
    })
    .await
}

/// Reconnects on any error with 5-second backoff; applies BPF and channel updates live.
async fn run_sensor_config_subscriber_once(
    config: &SyncConfig,
    current_location_id: &str,
    context: Arc<RwLock<AuditContext>>,
    capture_control: CaptureControl,
    current_filter: Arc<RwLock<String>>,
) -> Result<(), String> {
    run_message_loop(config, SENSOR_CONFIG_TOPIC, |payload| {
        let update: SensorConfigUpdate =
            serde_json::from_str(payload).map_err(|error| format!("decode JSON: {error}"))?;
        if let Some(location_id) = update.location_id.as_deref() {
            if location_id != "*" && location_id != current_location_id {
                return Ok(());
            }
        }
        if let Some(channel) = update.channel {
            let interface = context
                .read()
                .map_err(|_| "sensor context lock poisoned".to_string())?
                .interface
                .clone();
            let before = context
                .read()
                .map_err(|_| "sensor context lock poisoned".to_string())?
                .channel;
            set_channel(&interface, channel).map_err(|error| error.to_string())?;
            context
                .write()
                .map_err(|_| "sensor context lock poisoned".to_string())?
                .channel = channel;
            info!(
                before_channel = before,
                after_channel = channel,
                interface = %interface,
                "sensor channel reloaded from Redpanda"
            );
        }
        if let Some(bpf) = update
            .bpf
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            // Update the shared filter state so the hopper knows it changed.
            if let Ok(mut filter) = current_filter.write() {
                *filter = bpf.to_string();
            }
            capture_control.apply_filter(bpf.to_string());
            info!(bpf = %bpf, "sensor BPF reloaded from Redpanda");
        }
        if update.log_idle_secs.is_some() {
            info!(
                log_idle_secs = ?update.log_idle_secs,
                "sensor config update received; restart required for this field"
            );
        }
        Ok(())
    })
    .await
}
