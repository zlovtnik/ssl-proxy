use std::{sync::Arc, time::Duration};

use chrono::NaiveTime;
use serde::Deserialize;
use ssl_proxy::config::SyncConfig;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tracing::{error, info, warn};

use crate::audit::{AuditWindow, SharedAuditWindow};

pub const AUDIT_CONFIG_SUBJECT: &str = "wireless.audit.config";
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

#[derive(Debug, Eq, PartialEq)]
struct NatsEndpoint {
    address: String,
    user: Option<String>,
    password: Option<String>,
}

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
        let payload = r#"{"location_id":"branch","timezone":"UTC","enabled":true}"#;

        assert!(parse_audit_window_update(payload, "lab").unwrap().is_none());
    }

    #[test]
    fn disabled_window_is_never_active() {
        let payload = r#"{"location_id":"lab","timezone":"UTC","enabled":false}"#;

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
