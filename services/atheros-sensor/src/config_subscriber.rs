//! Raw-TCP Redpanda subscribers for live configuration push.
//!
//! Implements three subscribers: audit window schedule updates, authorized network cache
//! invalidation, and sensor config (BPF filter, channel). They speak the Redpanda text protocol
//! directly over raw TCP rather than using a Redpanda client library to avoid pulling in a
//! heavyweight async dependency for what is essentially three SUB connections. TLS is
//! intentionally unsupported here; these subscribers require plain redpanda:// endpoints.
//! Each subscriber runs in its own Tokio task with a reconnect loop: on any error the
//! connection is dropped and retried after a 5-second backoff, so transient Redpanda restarts
//! or network blips are recovered automatically without restarting the sensor process.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use chrono::NaiveTime;
use serde::Deserialize;
use ssl_proxy::config::SyncConfig;
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
    if redpanda_bootstrap_servers.starts_with("tls://") {
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
/// Runs a Redpanda subscriber over raw TCP for the given topic, calling `on_payload` for each message.
///
/// TLS is intentionally **unsupported**: if the Redpanda URL starts with `tls://` or `false`
/// is true, the function returns an error immediately. This avoids pulling in the heavyweight
/// `rdkafka` crate dependency — the sensor only needs three simple SUB connections, and raw TCP
/// with the Redpanda text protocol keeps the binary lean. Callers implement the reconnect loop;
/// this function returns `Err` on any connection, protocol, or payload processing error.
async fn run_message_loop<F>(
    config: &SyncConfig,
    topic: &'static str,
    mut on_payload: F,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    let Some(redpanda_bootstrap_servers) = config.redpanda_bootstrap_servers.as_deref() else {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        return Ok(());
    };
    if redpanda_bootstrap_servers.starts_with("tls://") {
        return Err("config subscriber supports plain redpanda:// endpoints only".to_string());
    }
    let endpoint = parse_redpanda_endpoint(redpanda_bootstrap_servers)?;
    let stream = timeout(
        REDPANDA_CONNECT_TIMEOUT,
        TcpStream::connect(&endpoint.address),
    )
    .await
    .map_err(|_| format!("connect to Redpanda {} timed out", endpoint.address))?
    .map_err(|error| format!("connect to Redpanda {}: {error}", endpoint.address))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|error| format!("read Redpanda INFO: {error}"))?;
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
        .write_all(format!("CONNECT {}\r\nPING\r\nSUB {topic} 1\r\n", connect_options).as_bytes())
        .await
        .map_err(|error| format!("subscribe to Redpanda: {error}"))?;
    info!(topic, "sensor config subscriber connected");
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
        let payload = String::from_utf8(payload)
            .map_err(|error| format!("config payload is not UTF-8: {error}"))?;
        on_payload(&payload)?;
    }
}

/// Parses audit window config JSON and returns a new AuditWindow. When enabled is false,
/// returns a window with "__disabled__" as the days string, which never matches any weekday,
/// effectively disabling the audit window.
fn parse_audit_window_update(
    payload: &str,
    current_location_id: &str,
) -> Result<Option<AuditWindow>, String> {
    let update: AuditWindowUpdate =
        serde_json::from_str(payload).map_err(|error| format!("decode JSON: {error}"))?;
    if let Some(location_id) = update.location_id.as_deref() {
        if location_id != "*" && location_id != current_location_id {
            return Ok(None);
        }
    }
    if update.enabled == Some(false) {
        return Ok(Some(AuditWindow::from_parts(
            update.timezone,
            Some("__disabled__".to_string()),
            None,
            None,
        )));
    }
    let start = match parse_time(update.start_time.as_deref(), "start_time") {
        Ok(time) => time,
        Err(error) => {
            warn!(%error, start_time = ?update.start_time, "invalid audit window start_time; keeping previous window state");
            return Ok(None);
        }
    };
    let end = match parse_time(update.end_time.as_deref(), "end_time") {
        Ok(time) => time,
        Err(error) => {
            warn!(%error, end_time = ?update.end_time, "invalid audit window end_time; keeping previous window state");
            return Ok(None);
        }
    };
    Ok(Some(AuditWindow::from_parts(
        update.timezone,
        update.days,
        start,
        end,
    )))
}
/// Parses a time string into a `NaiveTime`, accepting `%H:%M:%S`, `%H:%M`, `%k:%M:%S`, and `%k:%M`
/// formats. The `%k` variants allow single-digit hours (e.g. `"9:00"`) without a leading zero.
///
/// Returns `Ok(None)` when `value` is `None` or empty. Returns `Err` with the field name on
/// complete parse failure (none of the four format strings matched).
fn parse_time(value: Option<&str>, field: &'static str) -> Result<Option<NaiveTime>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    NaiveTime::parse_from_str(value, "%H:%M:%S")
        .or_else(|_| NaiveTime::parse_from_str(value, "%H:%M"))
        .or_else(|_| NaiveTime::parse_from_str(value, "%k:%M:%S"))
        .or_else(|_| NaiveTime::parse_from_str(value, "%k:%M"))
        .map(Some)
        .map_err(|_| format!("invalid {field} value={value:?}: expected HH:MM or HH:MM:SS"))
}

/// Parses redpanda://[user:pass@]host:port into address and credentials; uses raw TCP
/// (no TLS) to avoid heavyweight rdkafka dependency for simple SUB connections.
/// Credentials are percent-decoded; callers must percent-encode special chars in userinfo.
/// Parses redpanda://[user:pass@]host:port URLs into address and credentials. Handles three forms:
/// redpanda://host:port, redpanda://host (port defaults to 9092), and redpanda://user:pass@host:port.
/// Credentials are percent-decoded; callers must percent-encode special chars (@ :) in userinfo.
fn parse_redpanda_endpoint(redpanda_bootstrap_servers: &str) -> Result<RedpandaEndpoint, String> {
    let trimmed = redpanda_bootstrap_servers.trim();
    let authority = trimmed
        .strip_prefix("redpanda://")
        .ok_or_else(|| "expected redpanda:// URL".to_string())?
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err("missing Redpanda authority".to_string());
    }

    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, authority),
    };
    let (user, password) = match userinfo.and_then(|value| value.split_once(':')) {
        Some((user, password)) => (
            Some(percent_decode_userinfo(user)?),
            Some(percent_decode_userinfo(password)?),
        ),
        None => (userinfo.map(percent_decode_userinfo).transpose()?, None),
    };
    let address = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:9092")
    };
    Ok(RedpandaEndpoint {
        address,
        user,
        password,
    })
}

/// Decodes %XX sequences in Redpanda userinfo (username or password); handles @ and : chars.
fn percent_decode_userinfo(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes
                .get(index + 1)
                .copied()
                .and_then(hex_value)
                .ok_or_else(|| "invalid percent-encoded Redpanda userinfo".to_string())?;
            let low = bytes
                .get(index + 2)
                .copied()
                .and_then(hex_value)
                .ok_or_else(|| "invalid percent-encoded Redpanda userinfo".to_string())?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|_| "invalid UTF-8 in Redpanda userinfo".to_string())
}
/// Converts an ASCII hex digit byte to its numeric value.
///
/// Accepts `0-9`, `a-f`, and `A-F`. Returns `None` for any other byte. This is the inner
/// helper of [`percent_decode_userinfo`], used to decode `%XX` percent-encoded sequences in
/// Redpanda URL userinfo fields.
fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn sync_config(redpanda_bootstrap_servers: Option<&str>) -> SyncConfig {
        SyncConfig {
            redpanda_bootstrap_servers: redpanda_bootstrap_servers.map(str::to_string),
            connect_timeout_ms: 2_000,
            publish_timeout_ms: 2_000,
            publish_queue_capacity: 8_192,
            publish_enqueue_timeout_ms: 25,
            security_protocol: None,
            sasl_mechanisms: None,
            sasl_username: None,
            sasl_password: None,
            ssl_ca_location: None,
            ssl_certificate_location: None,
            ssl_key_location: None,
            inline_payload_max_bytes: 65_535,
            outbox_dir: "/tmp/atheros-sensor-sync-outbox".to_string(),
            publish_spool_dir: "/tmp/atheros-sensor-sync-outbox/publish-spool".to_string(),
        }
    }

    #[test]
    fn parses_matching_audit_window_config() {
        let payload = r#"{"location_id":"lab","timezone":"America/New_York","days":"mon","start_time":"09:00","end_time":"17:00","enabled":true}"#;

        let window = parse_audit_window_update(payload, "lab").unwrap().unwrap();

        assert!(window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 16, 0, 0).unwrap()));
        assert!(!window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 21, 16, 0, 0).unwrap()));
    }

    #[test]
    fn ignores_other_locations() {
        let payload = r#"{"location_id":"branch","timezone":"America/New_York","enabled":true}"#;

        assert!(parse_audit_window_update(payload, "lab").unwrap().is_none());
    }

    #[test]
    fn disabled_window_is_never_active() {
        let payload = r#"{"location_id":"lab","timezone":"America/New_York","enabled":false}"#;

        let window = parse_audit_window_update(payload, "lab").unwrap().unwrap();

        assert!(!window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 16, 0, 0).unwrap()));
    }

    #[test]
    fn parses_redpanda_endpoint_with_userinfo() {
        assert_eq!(
            parse_redpanda_endpoint("redpanda://user:pass@127.0.0.1:9092").unwrap(),
            RedpandaEndpoint {
                address: "127.0.0.1:9092".to_string(),
                user: Some("user".to_string()),
                password: Some("pass".to_string())
            }
        );
    }

    #[test]
    fn parses_redpanda_endpoint_with_percent_encoded_userinfo() {
        assert_eq!(
            parse_redpanda_endpoint("redpanda://user%40example:p%40ss%3Aword@127.0.0.1:9092")
                .unwrap(),
            RedpandaEndpoint {
                address: "127.0.0.1:9092".to_string(),
                user: Some("user@example".to_string()),
                password: Some("p@ss:word".to_string())
            }
        );
    }

    #[test]
    fn rejects_invalid_percent_encoded_userinfo() {
        assert!(parse_redpanda_endpoint("redpanda://user:%zz@127.0.0.1:9092").is_err());
    }

    #[test]
    fn config_subscribers_reject_kafka_listener() {
        let config = sync_config(Some("redpanda://127.0.0.1:19092"));

        assert!(!supports_config_subscriber_transport(&config));
        assert!(config_subscriber_disabled_reason(&config)
            .unwrap()
            .contains("does not expose the raw subscriber protocol"));
    }

    #[test]
    fn config_subscribers_accept_legacy_raw_listener() {
        let config = sync_config(Some("redpanda://127.0.0.1:4222"));

        assert!(supports_config_subscriber_transport(&config));
        assert!(config_subscriber_disabled_reason(&config).is_none());
    }
}
