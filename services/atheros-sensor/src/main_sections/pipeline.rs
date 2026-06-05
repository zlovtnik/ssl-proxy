/// Initializes sensor in startup order: tracing first (so all subsequent steps are logged),
/// then device detection, then Redpanda backlog, then pcap capture, then config subscribers.
async fn init_sensor(config: &AppConfig) -> Result<SensorHandles, SensorError> {
    let audit_window: SharedAuditWindow = Arc::new(RwLock::new(config.audit_window.clone()));

    let (log_filter, _audit_window_active) =
        init_tracing(Arc::clone(&audit_window), config.audit_layer_stream);
    info!(
        rust_log = %log_filter,
        default_rust_log = DEFAULT_RUST_LOG,
        "atheros sensor logging initialized"
    );

    let device = step(
        format!(
            "detect wireless capture interface{}",
            configured_device_suffix(config.device_override.as_deref())
        ),
        detect(config.device_override.as_deref()),
    )?;
    let sensor_id = step(
        format!("read MAC address for interface {device}"),
        read_mac_address(&device),
    )?;
    info!(
        sensor_id = %sensor_id,
        interface = %device,
        "atheros sensor interface detected"
    );
    info!(
        sensor_id = %sensor_id,
        location_id = %config.location_id,
        interface = %device,
        channel = config.channel,
        reg_domain = %config.reg_domain,
        bpf = %config.bpf,
        snaplen = config.snaplen,
        pcap_timeout_ms = config.pcap_timeout_ms,
        log_idle_secs = config.log_idle_secs,
        redpanda_configured = config.sync.redpanda_bootstrap_servers.is_some(),
        redpanda_tls_enabled = config
            .sync
            .security_protocol
            .as_deref()
            .map(|protocol| protocol.to_ascii_uppercase().contains("SSL"))
            .unwrap_or(false),
        audit_window = ?audit_window_snapshot(&audit_window),
        "atheros sensor starting"
    );

    let publisher = Arc::new(ssl_proxy::transport::SyncPublisher::new(&config.sync));
    info!(
        redpanda_configured = config.sync.redpanda_bootstrap_servers.is_some(),
        redpanda_tls_enabled = config
            .sync
            .security_protocol
            .as_deref()
            .map(|protocol| protocol.to_ascii_uppercase().contains("SSL"))
            .unwrap_or(false),
        "atheros sensor publisher initialized"
    );
    let publish_client = Arc::new(SyncPublisherClient::new(Arc::clone(&publisher)));
    let publish_state = PublishState::shared_with_config(
        config.memory_backlog_size,
        config.publish_journal_path.clone(),
        config.circuit_breaker_initial_timeout_ms,
        config.circuit_breaker_max_timeout_ms,
    );
    let backlog_client: Arc<dyn PublishClient> = publish_client.clone();
    let backlog = Arc::new(step(
        "initialize Redpanda backlog",
        RedpandaBacklog::new(
            backlog_client,
            config.sync.clone(),
            Duration::from_millis(config.redpanda_request_timeout_ms),
        ),
    )?);
    let inline_request_reply_enabled = backlog.supports_inline_request_reply();
    if inline_request_reply_enabled {
        backlog.clone().spawn_health_check();
    } else if let Some(reason) = backlog.inline_request_reply_disabled_reason() {
        info!(
            %reason,
            "Redpanda inline request/reply disabled; MAC lookup, authorized network refresh, and request health check are unavailable"
        );
    }
    // Replay journal entries from previous outages
    match replay_journal(&publish_state, &*backlog).await {
        Ok(count) => {
            if count > 0 {
                info!(replayed = count, "recovered publish journal entries");
            }
        }
        Err(error) => {
            warn!(%error, "publish journal replay failed; entries remain in journal for retry")
        }
    }

    info!("atheros sensor Redpanda backlog initialized");

    let config_subscribers_enabled =
        config_subscriber::supports_config_subscriber_transport(&config.sync);
    if config_subscribers_enabled {
        config_subscriber::spawn_audit_window_config_subscriber(
            config.sync.clone(),
            config.location_id.clone(),
            Arc::clone(&audit_window),
        );
    } else if let Some(reason) = config_subscriber::config_subscriber_disabled_reason(&config.sync)
    {
        info!(%reason, "live wireless config subscribers disabled");
    }
    let authorized_config_generation = Arc::new(AtomicU64::new(0));
    if config_subscribers_enabled {
        config_subscriber::spawn_authorized_network_config_subscriber(
            config.sync.clone(),
            Arc::clone(&authorized_config_generation),
        );
    }

    step(
        format!(
            "set wireless capture channel {} on interface {device}",
            config.channel
        ),
        apply_configured_channel(&device, config.channel, set_channel),
    )?;

    let context = Arc::new(RwLock::new(AuditContext {
        sensor_id,
        location_id: config.location_id.clone(),
        interface: device.clone(),
        channel: config.channel,
        reg_domain: config.reg_domain.clone(),
    }));

    let packet_stream = step(
        format!("open pcap capture on interface {device}"),
        stream_packets(&device, config.snaplen, config.pcap_timeout_ms, &config.bpf),
    )?;
    info!(
        interface = %device,
        channel = config.channel,
        bpf = %config.bpf,
        snaplen = config.snaplen,
        pcap_timeout_ms = config.pcap_timeout_ms,
        "atheros sensor pcap capture opened"
    );

    let stats = metrics::shared_stats();
    metrics::spawn_metrics_server(
        config.metrics_port,
        Arc::clone(&stats),
        Arc::clone(&publish_state),
    );

    // Shared filter state: tracks the last-applied BPF so the hopper can skip
    // re-applying when the filter hasn't changed.
    let current_filter: SharedFilter = Arc::new(RwLock::new(config.bpf.clone()));

    if config.channel_hop_enabled {
        spawn_channel_hopper(
            device.clone(),
            config.bpf.clone(),
            config.channel_hop_interval_ms,
            Arc::clone(&context),
            packet_stream.control.clone(),
            Arc::clone(&current_filter),
            Arc::clone(&stats),
        );
    }
    if config_subscribers_enabled {
        config_subscriber::spawn_sensor_config_subscriber(
            config.sync.clone(),
            config.location_id.clone(),
            Arc::clone(&context),
            packet_stream.control.clone(),
            Arc::clone(&current_filter),
        );
    }
    // Spawn periodic memory backlog flush timer
    let flush_state = Arc::clone(&publish_state);
    let flush_backlog = Arc::clone(&backlog);
    let flush_interval = Duration::from_secs(config.memory_backlog_flush_interval_secs);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(flush_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            periodic_memory_backlog_flush(&flush_state, &*flush_backlog).await;
        }
    });

    if inline_request_reply_enabled {
        spawn_backlog_reconcile_task(
            Arc::clone(&publish_state),
            Arc::clone(&backlog),
            Arc::clone(&publish_client),
            Arc::clone(&audit_window),
        );
        spawn_backlog_prune_task(Arc::clone(&backlog));
    }

    Ok(SensorHandles {
        config: config.clone(),
        audit_window,
        device,
        context,
        current_filter,
        packets: packet_stream.packets,
        capture_control: packet_stream.control,
        backlog,
        publish_client,
        publish_state,
        stats,
        authorized_config_generation,
        inline_request_reply_enabled,
    })
}

fn spawn_backlog_reconcile_task(
    publish_state: SharedPublishState,
    backlog: Arc<RedpandaBacklog>,
    publish_client: Arc<SyncPublisherClient>,
    audit_window: SharedAuditWindow,
) {
    tokio::spawn(async move {
        let mut interval = interval_secs(BACKLOG_RECONCILE_INTERVAL_SECS);
        loop {
            interval.tick().await;
            if !backlog.is_healthy() {
                debug!("skipping backlog reconciliation while Redpanda health check is failing");
                continue;
            }
            let audit_window = audit_window_snapshot(&audit_window);
            if let Err(error) =
                reconcile_backlog(&publish_state, &*backlog, &*publish_client, &audit_window).await
            {
                warn!(%error, "backlog reconciliation failed");
            }
        }
    });
}

fn spawn_backlog_prune_task(backlog: Arc<RedpandaBacklog>) {
    tokio::spawn(async move {
        let mut interval = interval_secs(BACKLOG_PRUNE_INTERVAL_SECS);
        loop {
            interval.tick().await;
            if !backlog.is_healthy() {
                debug!("skipping backlog prune while Redpanda health check is failing");
                continue;
            }
            match backlog
                .prune_stale(BACKLOG_PRUNE_MAX_ATTEMPTS, BACKLOG_PRUNE_MAX_AGE_HOURS)
                .await
            {
                Ok(pruned) => {
                    if pruned > 0 {
                        info!(pruned, "pruned stale synced backlog entries");
                    }
                }
                Err(error) => warn!(%error, "backlog prune failed"),
            }
        }
    });
}

fn apply_configured_channel<F, E>(device: &str, channel: u8, set: F) -> Result<(), E>
where
    F: FnOnce(&str, u8) -> Result<(), E>,
{
    set(device, channel)
}
