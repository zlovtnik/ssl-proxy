//! Raw-TCP NATS subscribers for live configuration push.
//!
//! Implements three subscribers: audit window schedule updates, authorized network cache
//! invalidation, and sensor config (BPF filter, channel). They speak the NATS text protocol
//! directly over raw TCP rather than using a NATS client library to avoid pulling in a
//! heavyweight async dependency for what is essentially three SUB connections. TLS is
//! intentionally unsupported here; these subscribers require plain nats:// endpoints.
//! Each subscriber runs in its own Tokio task with a reconnect loop: on any error the
//! connection is dropped and retried after a 5-second backoff, so transient NATS restarts
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
    capture::CaptureControl,
    channel_control::set_channel,
    model::AuditContext,
};

pub const AUDIT_CONFIG_SUBJECT: &str = "wireless.audit.config";
pub const AUTHORIZED_NETWORKS_CONFIG_SUBJECT: &str = "wireless.config.authorized_networks";
pub const SENSOR_CONFIG_SUBJECT: &str = "wireless.config.sensor";
const NATS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
/// Parsed components of a `nats://[user:pass@]host:port` URL.
///
/// Credentials are percent-decoded before storage; callers that embed special characters
/// (e.g. `@`, `:`) in usernames or passwords must percent-encode them in the URL or the
/// authority split will produce incorrect user/host boundaries.
struct NatsEndpoint {
    address: String,
    user: Option<String>,
    password: Option<String>,
}

/// Spawns the audit window config subscriber with automatic reconnect loop. Any error from
/// run_subscriber_once logs a warning and retries after 5 seconds indefinitely, allowing
/// transient NATS restarts without restarting the sensor process.
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
                warn!(%error, subject = AUDIT_CONFIG_SUBJECT, "audit config subscriber disconnected");
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
                warn!(%error, subject = AUTHORIZED_NETWORKS_CONFIG_SUBJECT, "authorized network config subscriber disconnected");
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
) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = run_sensor_config_subscriber_once(
                &config,
                &location_id,
                Arc::clone(&context),
                capture_control.clone(),
            )
            .await
            {
                warn!(%error, subject = SENSOR_CONFIG_SUBJECT, "sensor config subscriber disconnected");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Reconnects on any error (connection drop, parse failure, NATS -ERR) with 5-second
/// backoff; allows transient NATS restarts without restarting the sensor process.
async fn run_subscriber_once(
    config: &SyncConfig,
    location_id: &str,
    audit_window: SharedAuditWindow,
) -> Result<(), String> {
    let Some(nats_url) = config.nats_url.as_deref() else {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        return Ok(());
    };
    if config.tls_enabled || nats_url.starts_with("tls://") {
        return Err("audit config subscriber supports plain nats:// endpoints only".to_string());
    }
    let endpoint = parse_nats_endpoint(nats_url)?;
    let stream = timeout(NATS_CONNECT_TIMEOUT, TcpStream::connect(&endpoint.address))
        .await
        .map_err(|_| {
            format!(
                "connect to NATS {} timed out after {:?}",
                endpoint.address, NATS_CONNECT_TIMEOUT
            )
        })?
        .map_err(|error| format!("connect to NATS {}: {error}", endpoint.address))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|error| format!("read NATS INFO: {error}"))?;
    if !line.starts_with("INFO ") {
        return Err(format!("expected NATS INFO banner, got: {line}"));
    }

    let user = config.username.clone().or(endpoint.user);
    let password = config.password.clone().or(endpoint.password);
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
                "CONNECT {}\r\nPING\r\nSUB {AUDIT_CONFIG_SUBJECT} 1\r\n",
                connect_options
            )
            .as_bytes(),
        )
        .await
        .map_err(|error| format!("subscribe to NATS: {error}"))?;
    info!(
        subject = AUDIT_CONFIG_SUBJECT,
        "audit config subscriber connected"
    );

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .await
            .map_err(|error| format!("read NATS frame: {error}"))?;
        if bytes == 0 {
            return Err("NATS connection closed".to_string());
        }
        let trimmed = line.trim_end();
        if trimmed == "PING" {
            write_half
                .write_all(b"PONG\r\n")
                .await
                .map_err(|error| format!("write NATS PONG: {error}"))?;
            continue;
        }
        if trimmed.starts_with("+OK") {
            continue;
        }
        if trimmed.starts_with("-ERR") {
            return Err(format!("NATS returned {trimmed}"));
        }
        if !trimmed.starts_with("MSG ") {
            continue;
        }

        let size = trimmed
            .split_whitespace()
            .last()
            .ok_or_else(|| format!("missing NATS message size: {trimmed}"))?
            .parse::<usize>()
            .map_err(|error| format!("invalid NATS message size: {error}"))?;
        let mut payload = vec![0_u8; size];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|error| format!("read NATS payload: {error}"))?;
        let mut terminator = [0_u8; 2];
        reader
            .read_exact(&mut terminator)
            .await
            .map_err(|error| format!("read NATS payload terminator: {error}"))?;
        if terminator != *b"\r\n" {
            return Err("invalid NATS payload terminator".to_string());
        }
        let payload = String::from_utf8(payload)
            .map_err(|error| format!("audit config payload is not UTF-8: {error}"))?;
        match parse_audit_window_update(&payload, location_id) {
            Ok(Some(window)) => match audit_window.write() {
                Ok(mut current) => {
                    *current = window;
                    info!(
                        subject = AUDIT_CONFIG_SUBJECT,
                        location_id, "audit window updated from NATS"
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
    run_message_loop(config, AUTHORIZED_NETWORKS_CONFIG_SUBJECT, |payload| {
        generation.fetch_add(1, Ordering::Relaxed);
        info!(
            subject = AUTHORIZED_NETWORKS_CONFIG_SUBJECT,
            payload_bytes = payload.len(),
            "authorized network cache invalidated from NATS"
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
) -> Result<(), String> {
    run_message_loop(config, SENSOR_CONFIG_SUBJECT, |payload| {
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
                "sensor channel reloaded from NATS"
            );
        }
        if let Some(bpf) = update
            .bpf
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            capture_control.apply_filter(bpf.to_string());
            info!(bpf = %bpf, "sensor BPF reloaded from NATS");
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
//todo: doc it!
async fn run_message_loop<F>(
    config: &SyncConfig,
    subject: &'static str,
    mut on_payload: F,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    let Some(nats_url) = config.nats_url.as_deref() else {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        return Ok(());
    };
    if config.tls_enabled || nats_url.starts_with("tls://") {
        return Err("config subscriber supports plain nats:// endpoints only".to_string());
    }
    let endpoint = parse_nats_endpoint(nats_url)?;
    let stream = timeout(NATS_CONNECT_TIMEOUT, TcpStream::connect(&endpoint.address))
        .await
        .map_err(|_| format!("connect to NATS {} timed out", endpoint.address))?
        .map_err(|error| format!("connect to NATS {}: {error}", endpoint.address))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|error| format!("read NATS INFO: {error}"))?;
    let user = config.username.clone().or(endpoint.user);
    let password = config.password.clone().or(endpoint.password);
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
        .write_all(format!("CONNECT {}\r\nPING\r\nSUB {subject} 1\r\n", connect_options).as_bytes())
        .await
        .map_err(|error| format!("subscribe to NATS: {error}"))?;
    info!(subject, "sensor config subscriber connected");
    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .await
            .map_err(|error| format!("read NATS frame: {error}"))?;
        if bytes == 0 {
            return Err("NATS connection closed".to_string());
        }
        let trimmed = line.trim_end();
        if trimmed == "PING" {
            write_half
                .write_all(b"PONG\r\n")
                .await
                .map_err(|error| format!("write NATS PONG: {error}"))?;
            continue;
        }
        if trimmed.starts_with("+OK") {
            continue;
        }
        if trimmed.starts_with("-ERR") {
            return Err(format!("NATS returned {trimmed}"));
        }
        if !trimmed.starts_with("MSG ") {
            continue;
        }
        let size = trimmed
            .split_whitespace()
            .last()
            .ok_or_else(|| format!("missing NATS message size: {trimmed}"))?
            .parse::<usize>()
            .map_err(|error| format!("invalid NATS message size: {error}"))?;
        let mut payload = vec![0_u8; size];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|error| format!("read NATS payload: {error}"))?;
        let mut terminator = [0_u8; 2];
        reader
            .read_exact(&mut terminator)
            .await
            .map_err(|error| format!("read NATS payload terminator: {error}"))?;
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
    let start = parse_time(update.start_time.as_deref(), "start_time")?;
    let end = parse_time(update.end_time.as_deref(), "end_time")?;
    Ok(Some(AuditWindow::from_parts(
        update.timezone,
        update.days,
        start,
        end,
    )))
}
//todo: doc it!
fn parse_time(value: Option<&str>, field: &'static str) -> Result<Option<NaiveTime>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    NaiveTime::parse_from_str(value, "%H:%M:%S")
        .or_else(|_| NaiveTime::parse_from_str(value, "%H:%M"))
        .map(Some)
        .map_err(|error| format!("invalid {field}: {error}"))
}

/// Parses nats://[user:pass@]host:port into address and credentials; uses raw TCP
/// (no TLS) to avoid heavyweight async-nats dependency for simple SUB connections.
/// Credentials are percent-decoded; callers must percent-encode special chars in userinfo.
/// Parses nats://[user:pass@]host:port URLs into address and credentials. Handles three forms:
/// nats://host:port, nats://host (port defaults to 4222), and nats://user:pass@host:port.
/// Credentials are percent-decoded; callers must percent-encode special chars (@ :) in userinfo.
fn parse_nats_endpoint(nats_url: &str) -> Result<NatsEndpoint, String> {
    let trimmed = nats_url.trim();
    let authority = trimmed
        .strip_prefix("nats://")
        .ok_or_else(|| "expected nats:// URL".to_string())?
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err("missing NATS authority".to_string());
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
        format!("{host_port}:4222")
    };
    Ok(NatsEndpoint {
        address,
        user,
        password,
    })
}

/// Decodes %XX sequences in NATS userinfo (username or password); handles @ and : chars.
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
                .ok_or_else(|| "invalid percent-encoded NATS userinfo".to_string())?;
            let low = bytes
                .get(index + 2)
                .copied()
                .and_then(hex_value)
                .ok_or_else(|| "invalid percent-encoded NATS userinfo".to_string())?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|_| "invalid UTF-8 in NATS userinfo".to_string())
}
//todo: doc it!
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
    fn parses_nats_endpoint_with_userinfo() {
        assert_eq!(
            parse_nats_endpoint("nats://user:pass@127.0.0.1:4222").unwrap(),
            NatsEndpoint {
                address: "127.0.0.1:4222".to_string(),
                user: Some("user".to_string()),
                password: Some("pass".to_string())
            }
        );
    }

    #[test]
    fn parses_nats_endpoint_with_percent_encoded_userinfo() {
        assert_eq!(
            parse_nats_endpoint("nats://user%40example:p%40ss%3Aword@127.0.0.1:4222").unwrap(),
            NatsEndpoint {
                address: "127.0.0.1:4222".to_string(),
                user: Some("user@example".to_string()),
                password: Some("p@ss:word".to_string())
            }
        );
    }

    #[test]
    fn rejects_invalid_percent_encoded_userinfo() {
        assert!(parse_nats_endpoint("nats://user:%zz@127.0.0.1:4222").is_err());
    }
}
