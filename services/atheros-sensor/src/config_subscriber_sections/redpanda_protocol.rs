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
    if redpanda_bootstrap_servers.starts_with("tls://")
        || redpanda_security_protocol_uses_tls(config)
    {
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
        if terminator != *b"\r\n" {
            return Err("invalid Redpanda payload terminator".to_string());
        }
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
    let address = if redpanda_host_port_has_port(host_port) {
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

fn redpanda_host_port_has_port(host_port: &str) -> bool {
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest
            .split_once(']')
            .is_some_and(|(_, after_bracket)| after_bracket.starts_with(':'));
    }
    host_port.contains(':')
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
