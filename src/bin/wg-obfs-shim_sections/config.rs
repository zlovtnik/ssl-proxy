fn parse_single_shim_process_config(
    options: &CliOptions,
) -> Result<ProcessConfig, ConfigParseOutcome> {
    let listen_addr = parse_socket_addr(
        options
            .listen_addr
            .clone()
            .or_else(|| std::env::var("WG_OBFS_SHIM_LISTEN_ADDR").ok())
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string()),
        "listen address",
    )?;
    let server_addrs = parse_server_addrs(options)?;
    let health_addr = parse_socket_addr(
        optional_value(&options.health_addr, "WG_OBFS_HEALTH_ADDR")
            .unwrap_or_else(|| DEFAULT_HEALTH_ADDR.to_string()),
        "health address",
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

    let encryption_mode = parse_encryption_mode(optional_value(
        &options.encryption_mode,
        "WG_OBFUSCATION_ENCRYPTION_MODE",
    ))?;
    let replay_protection = parse_optional_bool(
        optional_value(
            &options.replay_protection,
            "WG_OBFUSCATION_REPLAY_PROTECTION",
        ),
        "replay protection",
    )?
    .unwrap_or(matches!(encryption_mode, EncryptionMode::Aead));
    let xor_rekey_packets = parse_optional_positive_u64(
        optional_value(
            &options.xor_rekey_packets,
            "WG_OBFUSCATION_XOR_REKEY_PACKETS",
        ),
        "XOR rekey packet count",
    )?;
    let xor_rekey_secs = parse_optional_positive_u64(
        optional_value(&options.xor_rekey_secs, "WG_OBFUSCATION_XOR_REKEY_SECS"),
        "XOR rekey seconds",
    )?;

    let obfuscation = WgPacketObfuscation::new(key.into_bytes(), magic_byte)
        .with_encryption_mode(encryption_mode)
        .with_padding(parse_padding(optional_value(
            &options.padding,
            "WG_OBFUSCATION_PADDING",
        ))?)
        .with_magic_position(parse_magic_position(optional_value(
            &options.magic_position,
            "WG_OBFUSCATION_MAGIC_POSITION",
        ))?)
        .with_xor_rekey(XorRekeyPolicy::new(xor_rekey_packets, xor_rekey_secs))
        .with_replay_protection(replay_protection);

    let mut config = WgObfsShimConfig::with_server_addrs(
        listen_addr,
        server_addrs,
        obfuscation,
        Duration::from_secs(idle_timeout_secs),
    )
    .map_err(|err| ConfigParseOutcome::Error(err.to_string()))?;
    config.max_sessions = parse_optional_usize(
        optional_value(&options.max_sessions, "WG_OBFS_SHIM_MAX_SESSIONS"),
        "max sessions",
    )?;
    config.cleanup_interval = parse_optional_duration_secs(
        optional_value(
            &options.cleanup_interval_secs,
            "WG_OBFS_SHIM_CLEANUP_INTERVAL_SECS",
        ),
        "cleanup interval",
    )?;
    config.drain_timeout = parse_optional_duration_secs(
        optional_value(
            &options.drain_timeout_secs,
            "WG_OBFS_SHIM_DRAIN_TIMEOUT_SECS",
        ),
        "drain timeout",
    )?
    .unwrap_or_else(|| Duration::from_secs(DEFAULT_DRAIN_TIMEOUT_SECS));
    config.rate_limit = parse_rate_limit(&options)?;
    config.buffer_pool_capacity = parse_optional_usize(
        optional_value(
            &options.buffer_pool_capacity,
            "WG_OBFS_SHIM_BUFFER_POOL_CAPACITY",
        ),
        "buffer pool capacity",
    )?
    .unwrap_or(DEFAULT_BUFFER_POOL_CAPACITY);
    config.send_queue_capacity = parse_optional_usize(
        optional_value(
            &options.send_queue_capacity,
            "WG_OBFS_SHIM_SEND_QUEUE_CAPACITY",
        ),
        "send queue capacity",
    )?
    .unwrap_or(DEFAULT_SEND_QUEUE_CAPACITY);
    config.max_datagram_bytes = validate_max_datagram_bytes(
        parse_optional_usize(
            optional_value(
                &options.max_datagram_bytes,
                "WG_OBFUSCATION_MAX_DATAGRAM_BYTES",
            ),
            "max datagram bytes",
        )?
        .unwrap_or(DEFAULT_MAX_DATAGRAM_BYTES),
    )?;
    config.udp_socket_buffer_bytes = parse_optional_usize(
        optional_value(
            &options.udp_socket_buffer_bytes,
            "WG_UDP_SOCKET_BUFFER_BYTES",
        ),
        "UDP socket buffer bytes",
    )?
    .unwrap_or(DEFAULT_UDP_SOCKET_BUFFER_BYTES);
    config.send_jitter_max = Duration::from_millis(
        parse_optional_nonnegative_u64(
            optional_value(&options.jitter_max_ms, "WG_OBFS_SHIM_JITTER_MAX_MS"),
            "jitter max milliseconds",
        )?
        .unwrap_or(DEFAULT_JITTER_MAX_MS),
    );
    config.chaff_pps = validate_chaff_pps(
        parse_optional_nonnegative_u64(
            optional_value(&options.chaff_pps, "WG_OBFS_SHIM_CHAFF_PPS"),
            "chaff packets per second",
        )?
        .unwrap_or(DEFAULT_CHAFF_PPS),
    )?;
    config.health_addr = Some(health_addr);
    config.metrics_addr = optional_value(&options.metrics_addr, "WG_OBFS_SHIM_METRICS_ADDR")
        .map(|raw| parse_socket_addr(raw, "metrics address"))
        .transpose()?;

    Ok(ProcessConfig {
        shims: vec![config],
        health_addr,
        health_token: optional_value(&options.health_token, "WG_OBFS_HEALTH_TOKEN"),
        config_path: None,
    })
}

async fn run_health_server(
    health_addr: SocketAddr,
    health_token: Option<String>,
    handles: Vec<ShimHealthHandle>,
    shutdown: CancellationToken,
) {
    use axum::{
        extract::State,
        http::{header, HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use serde_json::json;

    struct HealthState {
        handles: Vec<ShimHealthHandle>,
        token: Option<String>,
    }

    fn authorized(headers: &HeaderMap, token: Option<&str>) -> bool {
        let Some(expected) = token else {
            return true;
        };
        let Some(provided) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().strip_prefix("Bearer "))
        else {
            return false;
        };
        constant_time_eq(provided.trim(), expected)
    }

    async fn health_handler(
        State(state): State<Arc<HealthState>>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        if !authorized(&headers, state.token.as_deref()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "unauthorized",
                })),
            );
        }

        let sessions = state
            .handles
            .iter()
            .map(ShimHealthHandle::active_sessions)
            .sum::<u64>();
        let replay_detected = state
            .handles
            .iter()
            .map(ShimHealthHandle::replay_detected)
            .sum::<u64>();
        (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "sessions": sessions,
                "replay_detected": replay_detected,
            })),
        )
    }

    let listener = match tokio::net::TcpListener::bind(health_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(%health_addr, %err, "failed to bind WireGuard shim health listener");
            return;
        }
    };
    let app = Router::new()
        .route("/health", get(health_handler))
        .with_state(Arc::new(HealthState {
            handles,
            token: health_token,
        }));

    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
    {
        warn!(%health_addr, %err, "WireGuard shim health server failed");
    }
}

fn apply_reloaded_config(
    runtimes: &[WgObfsShimRuntime],
    current: &ProcessConfig,
    reloaded: ProcessConfig,
) {
    if reloaded.health_addr != current.health_addr {
        warn!(
            current_health_addr = %current.health_addr,
            reloaded_health_addr = %reloaded.health_addr,
            "SIGHUP health address changes require process restart"
        );
    }

    let mut by_listen_addr = HashMap::new();
    for config in reloaded.shims {
        by_listen_addr.insert(config.listen_addr, config);
    }

    for runtime in runtimes {
        let current_config = runtime.config_snapshot();
        if let Some(config) = by_listen_addr.remove(&current_config.listen_addr) {
            if config.max_datagram_bytes != current_config.max_datagram_bytes {
                warn!(
                    listen_addr = %current_config.listen_addr,
                    current_max_datagram_bytes = current_config.max_datagram_bytes,
                    reloaded_max_datagram_bytes = config.max_datagram_bytes,
                    "SIGHUP max datagram changes require process restart"
                );
            }
            if config.udp_socket_buffer_bytes != current_config.udp_socket_buffer_bytes {
                warn!(
                    listen_addr = %current_config.listen_addr,
                    current_udp_socket_buffer_bytes = current_config.udp_socket_buffer_bytes,
                    reloaded_udp_socket_buffer_bytes = config.udp_socket_buffer_bytes,
                    "SIGHUP UDP socket buffer changes require process restart"
                );
            }
            runtime.update_config(config);
            info!(
                listen_addr = %current_config.listen_addr,
                "reloaded WireGuard shim config for new sessions"
            );
        } else {
            warn!(
                listen_addr = %current_config.listen_addr,
                "SIGHUP removed a shim listener; listener topology changes require process restart"
            );
        }
    }

    for listen_addr in by_listen_addr.keys() {
        warn!(
            %listen_addr,
            "SIGHUP added a shim listener; listener topology changes require process restart"
        );
    }
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, ConfigParseOutcome> {
    args.next()
        .ok_or_else(|| ConfigParseOutcome::Error(format!("missing value for {flag}")))
}

fn optional_value(cli_value: &Option<String>, env_var: &str) -> Option<String> {
    cli_value
        .clone()
        .or_else(|| std::env::var(env_var).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_socket_addr(raw: String, label: &str) -> Result<SocketAddr, ConfigParseOutcome> {
    raw.parse::<SocketAddr>().map_err(|_| {
        ConfigParseOutcome::Error(format!("invalid {label} {raw:?}; expected host:port"))
    })
}

fn parse_server_addrs(options: &CliOptions) -> Result<Vec<SocketAddr>, ConfigParseOutcome> {
    let raw_addrs = if !options.server_addrs.is_empty() {
        options.server_addrs.clone()
    } else if let Some(raw) = std::env::var("WG_OBFS_SERVER_ADDRS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        split_addr_list(&raw)
    } else if let Some(raw) = std::env::var("WG_OBFS_SERVER_ADDR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        vec![raw]
    } else {
        return Err(ConfigParseOutcome::Error(
            "missing required server address; set --server, WG_OBFS_SERVER_ADDRS, or WG_OBFS_SERVER_ADDR"
                .to_string(),
        ));
    };

    parse_socket_addr_list(raw_addrs, "server address")
}

fn split_addr_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_socket_addr_list(
    raw_addrs: Vec<String>,
    label: &str,
) -> Result<Vec<SocketAddr>, ConfigParseOutcome> {
    if raw_addrs.is_empty() {
        return Err(ConfigParseOutcome::Error(format!(
            "{label} list must contain at least one address"
        )));
    }

    raw_addrs
        .into_iter()
        .map(|raw| parse_socket_addr(raw, label))
        .collect()
}

fn load_process_config_from_file(path: &Path) -> Result<ProcessConfig, ConfigParseOutcome> {
    let raw = std::fs::read_to_string(path).map_err(|err| {
        ConfigParseOutcome::Error(format!("failed to read config file {:?}: {err}", path))
    })?;
    let parsed = toml::from_str::<TomlProcessConfig>(&raw).map_err(|err| {
        ConfigParseOutcome::Error(format!("failed to parse config file {:?}: {err}", path))
    })?;
    let health_addr = parse_socket_addr(
        parsed
            .health_addr
            .unwrap_or_else(|| DEFAULT_HEALTH_ADDR.to_string()),
        "health address",
    )?;
    if parsed.shim.is_empty() {
        return Err(ConfigParseOutcome::Error(
            "config file must contain at least one [[shim]] section".to_string(),
        ));
    }

    let mut shims = Vec::with_capacity(parsed.shim.len());
    for raw_shim in parsed.shim {
        let config = build_toml_shim_config(raw_shim, health_addr)?;
        shims.push(config);
    }

    Ok(ProcessConfig {
        shims,
        health_addr,
        health_token: normalize_optional_secret(parsed.health_token),
        config_path: Some(path.to_path_buf()),
    })
}

fn build_toml_shim_config(
    raw: TomlShimConfig,
    health_addr: SocketAddr,
) -> Result<WgObfsShimConfig, ConfigParseOutcome> {
    let listen_addr = parse_socket_addr(
        raw.listen_addr
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string()),
        "listen address",
    )?;
    let mut server_raw = raw.server_addrs.unwrap_or_default();
    if let Some(server_addr) = raw.server_addr {
        server_raw.insert(0, server_addr);
    }
    let server_addrs = parse_socket_addr_list(server_raw, "server address")?;
    let key = load_key_from_values(raw.key, raw.key_file)?.ok_or_else(|| {
        ConfigParseOutcome::Error(
            "missing required obfuscation key in config file shim section".to_string(),
        )
    })?;
    let magic_byte = match raw.magic_byte {
        Some(raw) => Some(parse_magic_byte(&raw).ok_or_else(|| {
            ConfigParseOutcome::Error(format!(
                "invalid magic byte {raw:?}; expected decimal or 0xNN"
            ))
        })?),
        None => None,
    };
    let encryption_mode = parse_encryption_mode(raw.encryption_mode)?;
    let replay_protection = raw
        .replay_protection
        .unwrap_or(matches!(encryption_mode, EncryptionMode::Aead));
    let obfuscation = WgPacketObfuscation::new(key.into_bytes(), magic_byte)
        .with_encryption_mode(encryption_mode)
        .with_padding(parse_padding(raw.padding)?)
        .with_magic_position(parse_magic_position(raw.magic_position)?)
        .with_xor_rekey(XorRekeyPolicy::new(
            raw.xor_rekey_packets,
            raw.xor_rekey_secs,
        ))
        .with_replay_protection(replay_protection);

    let mut config = WgObfsShimConfig::with_server_addrs(
        listen_addr,
        server_addrs,
        obfuscation,
        Duration::from_secs(
            raw.idle_timeout_secs
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS)
                .max(1),
        ),
    )
    .map_err(|err| ConfigParseOutcome::Error(err.to_string()))?;
    config.max_sessions = raw.max_sessions;
    config.cleanup_interval = raw
        .cleanup_interval_secs
        .map(|secs| Duration::from_secs(secs.max(1)));
    config.drain_timeout = Duration::from_secs(
        raw.drain_timeout_secs
            .unwrap_or(DEFAULT_DRAIN_TIMEOUT_SECS)
            .max(1),
    );
    config.rate_limit = match (raw.rate_limit_pps, raw.rate_limit_burst) {
        (None, None) => None,
        (Some(pps), Some(burst)) => RateLimitConfig::new(pps, burst),
        _ => {
            return Err(ConfigParseOutcome::Error(
                "rate limiting requires both packets per second and burst values".to_string(),
            ))
        }
    };
    config.buffer_pool_capacity = raw
        .buffer_pool_capacity
        .unwrap_or(DEFAULT_BUFFER_POOL_CAPACITY);
    config.send_queue_capacity = raw
        .send_queue_capacity
        .unwrap_or(DEFAULT_SEND_QUEUE_CAPACITY);
    config.max_datagram_bytes =
        validate_max_datagram_bytes(raw.max_datagram_bytes.unwrap_or(DEFAULT_MAX_DATAGRAM_BYTES))?;
    config.udp_socket_buffer_bytes = raw
        .udp_socket_buffer_bytes
        .unwrap_or(DEFAULT_UDP_SOCKET_BUFFER_BYTES);
    config.send_jitter_max =
        Duration::from_millis(raw.jitter_max_ms.unwrap_or(DEFAULT_JITTER_MAX_MS));
    config.chaff_pps = validate_chaff_pps(raw.chaff_pps.unwrap_or(DEFAULT_CHAFF_PPS))?;
    config.health_addr = Some(health_addr);
    config.metrics_addr = raw
        .metrics_addr
        .map(|raw| parse_socket_addr(raw, "metrics address"))
        .transpose()?;
    Ok(config)
}

fn normalize_optional_secret(raw: Option<String>) -> Option<String> {
    raw.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn validate_chaff_pps(value: u64) -> Result<u64, ConfigParseOutcome> {
    if value > MAX_CHAFF_PPS {
        return Err(ConfigParseOutcome::Error(format!(
            "invalid chaff packets per second {value}; expected value <= {MAX_CHAFF_PPS}"
        )));
    }
    Ok(value)
}

fn validate_max_datagram_bytes(value: usize) -> Result<usize, ConfigParseOutcome> {
    if value == 0 || value > MAX_UDP_PACKET_SIZE {
        return Err(ConfigParseOutcome::Error(format!(
            "invalid max datagram bytes {value}; expected value from 1 to {MAX_UDP_PACKET_SIZE}"
        )));
    }
    Ok(value)
}
