fn bandwidth_flush_interval() -> tokio::time::Interval {
    let interval = Duration::from_secs(DEFAULT_BANDWIDTH_WINDOW_SECS as u64);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval
}

async fn publish_bandwidth_events(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    events: Vec<WirelessBandwidthEvent>,
) {
    for event in events {
        if event.threshold_exceeded {
            warn!(
                source_mac = %event.source_mac,
                destination_bssid = %event.destination_bssid,
                bytes = event.bytes,
                threshold_bytes = EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
                "wireless bandwidth threshold exceeded for external BSSID"
            );
        }
        if let Err(error) = publish_bandwidth_event(state, backlog, publisher, &event).await {
            warn!(
                %error,
                source_mac = %event.source_mac,
                destination_bssid = %event.destination_bssid,
                "wireless bandwidth event publish failed"
            );
        }
    }
}

async fn flush_probe_batch(
    backlog: &RedpandaBacklog,
    batch: ProbeFlushBatch,
) -> Result<usize, (ProbeFlushBatch, crate::backlog::BacklogError)> {
    let observations = batch.to_backlog_observations();
    let probe_count = observations.len();
    match backlog.flush_probe_batch(&observations).await {
        Ok(()) => Ok(probe_count),
        Err(error) => Err((batch, error)),
    }
}

async fn flush_probe_accumulator(
    backlog: &RedpandaBacklog,
    pipeline_state: &mut PipelineState,
    stats: &metrics::SharedStats,
) {
    for batch in pipeline_state.probe_accumulator.take_ready_batches() {
        match flush_probe_batch(backlog, batch).await {
            Ok(probe_count) => debug!(probe_count, "probe batch flushed"),
            Err((batch, error)) => {
                warn!(
                    %error,
                    probe_count = batch.len(),
                    "probe batch flush failed; reinserting for retry"
                );
                pipeline_state.probe_accumulator.restore(batch);
            }
        }
    }
    stats.set_probe_accumulator_len(pipeline_state.probe_accumulator.len());
}

/// Creates a tokio interval that ticks every N seconds, with at least 1 second minimum.
fn interval_secs(secs: u64) -> tokio::time::Interval {
    let interval = Duration::from_secs(secs.max(1));
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

/// Returns a clone of the current audit context.
fn context_snapshot(context: &SharedContext) -> AuditContext {
    context.read().unwrap().clone()
}

fn filter_snapshot(current_filter: &SharedFilter, fallback: &str) -> String {
    current_filter
        .read()
        .map(|filter| filter.clone())
        .unwrap_or_else(|_| fallback.to_string())
}

/// Spawns a background task that cycles through channels 1, 6, and 11 at the configured interval.
/// Only re-applies the BPF filter when the filter string has actually changed (detected via the
/// shared `current_filter`). The default BPF `type mgt or type data` is channel-agnostic, so
/// there is no need to re-compile it on every hop.
fn spawn_channel_hopper(
    device: String,
    bpf: String,
    interval_ms: u64,
    context: SharedContext,
    capture_control: CaptureControl,
    current_filter: Arc<RwLock<String>>,
    stats: metrics::SharedStats,
) {
    tokio::spawn(async move {
        let mut last_applied_filter = bpf.clone();
        let channels = [1_u8, 6, 11];
        let mut index = 0usize;
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms.max(100)));
        loop {
            interval.tick().await;
            let channel = channels[index % channels.len()];
            index = index.wrapping_add(1);
            match set_channel(&device, channel) {
                Ok(()) => {
                    if let Ok(mut context) = context.write() {
                        context.channel = channel;
                    }
                    stats.increment_channel_hop_count();

                    let needs_apply = current_filter
                        .read()
                        .map(|f| *f != last_applied_filter)
                        .unwrap_or(true);
                    if needs_apply {
                        if let Ok(filter) = current_filter.read() {
                            capture_control.apply_filter(filter.clone());
                            last_applied_filter = filter.clone();
                        }
                    }
                    info!(interface = %device, channel, "wireless capture channel hopped");
                }
                Err(error) => {
                    warn!(%error, interface = %device, channel, "wireless channel hop failed")
                }
            }
        }
    });
}

/// Flushes bandwidth window, writes memory backlog to the coordinator, then sleeps for
/// shutdown_grace_secs to let in-flight Redpanda publishes drain before process exit.
async fn shutdown_flush(handles: &SensorHandles, pipeline_state: &mut PipelineState) {
    let events = pipeline_state.traffic_bucket.flush_current();
    let now = Utc::now();
    let mut lags: Vec<u64> = events
        .iter()
        .filter_map(|e| {
            let window_end = chrono::DateTime::parse_from_rfc3339(&e.window_end).ok()?;
            let lag = (now - window_end.with_timezone(&chrono::Utc))
                .num_milliseconds()
                .max(0) as u64;
            Some(lag)
        })
        .collect();
    lags.sort_unstable();
    let median_lag = lags.get(lags.len() / 2).copied();
    handles.stats.set_bandwidth_window_lag_ms(median_lag);
    handles.stats.set_memory_backlog_len(
        handles.publish_state.lock().unwrap().memory_backlog_len(),
    );
    handles
        .stats
        .set_probe_accumulator_len(pipeline_state.probe_accumulator.len());
    publish_bandwidth_events(
        &handles.publish_state,
        &*handles.backlog,
        &*handles.publish_client,
        events,
    )
    .await;
    flush_probe_accumulator(&handles.backlog, pipeline_state, &handles.stats).await;
    let _ = flush_memory_backlog(&handles.publish_state, &*handles.backlog).await;
    tokio::time::sleep(Duration::from_secs(handles.config.shutdown_grace_secs)).await;
}

/// Waits for SIGTERM or Ctrl-C, then returns.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Returns a clone of the current audit window, or a default inactive window on lock failure.
fn audit_window_snapshot(audit_window: &SharedAuditWindow) -> AuditWindow {
    audit_window
        .read()
        .map(|window| window.clone())
        .unwrap_or_else(|_| AuditWindow::from_parts(None, None, None, None))
}

/// Initializes the tracing subscriber with JSON formatting and audit layer.
/// Returns the active filter string for logging.
fn init_tracing(
    audit_window: SharedAuditWindow,
    audit_layer_stream: config::AuditLayerStream,
) -> (String, Arc<AtomicBool>) {
    let audit_window_active = Arc::new(AtomicBool::new(true));

    // Spawn a background watcher that refreshes the audit window active snapshot every 5 seconds
    // so the AuditLayer does not need to acquire a read lock on every on_event() call.
    let watcher_active = Arc::clone(&audit_window_active);
    let watcher_window = Arc::clone(&audit_window);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let active = watcher_window
                .read()
                .map(|w| w.is_active_at(chrono::Utc::now()))
                .unwrap_or(true);
            watcher_active.store(active, Ordering::Release);
        }
    });

    let (filter, filter_source) = match std::env::var("RUST_LOG") {
        Ok(value) if !value.trim().is_empty() => match EnvFilter::try_new(value.trim()) {
            Ok(filter) => (filter, value.trim().to_string()),
            Err(error) => {
                eprintln!(
                    "invalid RUST_LOG={value:?}: {error}; falling back to {DEFAULT_RUST_LOG}"
                );
                (
                    EnvFilter::new(DEFAULT_RUST_LOG),
                    DEFAULT_RUST_LOG.to_string(),
                )
            }
        },
        _ => (
            EnvFilter::new(DEFAULT_RUST_LOG),
            DEFAULT_RUST_LOG.to_string(),
        ),
    };

    let otel_provider = ssl_proxy::observability::init_tracer_provider("atheros-sensor");
    let otel_layer = otel_provider.as_ref().map(|provider| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(provider.tracer("atheros-sensor"))
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .with(AuditLayer::new(
            Arc::clone(&audit_window_active),
            audit_layer_stream,
        ))
        .with(otel_layer)
        .init();

    (filter_source, audit_window_active)
}

fn log_and_publish_capture_heartbeat(handles: &SensorHandles) {
    let (backlog_len, circuit_breaker) = {
        let publish_state = handles.publish_state.lock().unwrap();
        (
            publish_state.memory_backlog_len(),
            format!("{:?}", publish_state.circuit_breaker_state),
        )
    };
    handles.stats.set_memory_backlog_len(backlog_len);
    let stats_snapshot = handles.stats.log(&handles.device, &handles.config);
    let sensor_id = handles
        .context
        .read()
        .map(|context| context.sensor_id.clone())
        .unwrap_or_else(|_| "unknown".to_string());
    let heartbeat = serde_json::json!({
        "event_type": "sensor_heartbeat",
        "observed_at": ssl_proxy::time::now_rfc3339(),
        "sensor_id": sensor_id,
        "location_id": handles.config.location_id.clone(),
        "packets_seen": stats_snapshot.packets_seen,
        "decoded_frames": stats_snapshot.decoded_frames,
        "backlog_len": stats_snapshot.memory_backlog_len,
        "circuit_breaker": circuit_breaker,
    });

    if let Err(error) = handles
        .publish_client
        .enqueue_message(SENSOR_HEARTBEAT_TOPIC, &heartbeat.to_string())
    {
        warn!(%error, "heartbeat publish failed");
    }
}

/// Creates an interval for periodic heartbeat logging, or None if disabled.
fn capture_heartbeat(idle_secs: u64) -> Option<tokio::time::Interval> {
    if idle_secs == 0 {
        return None;
    }

    let interval = Duration::from_secs(idle_secs);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Some(interval)
}

/// Awaits the next tick of the heartbeat interval, or pends forever if disabled.
async fn tick_capture_heartbeat(interval: &mut Option<tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => future::pending::<()>().await,
    }
}

/// Returns a suffix string describing the configured device override, if any.
fn configured_device_suffix(device: Option<&str>) -> String {
    device
        .map(|device| format!(" configured by ATH_SENSOR_DEVICE={device}"))
        .unwrap_or_default()
}

/// Wraps a synchronous result with a labeled error context for startup steps.
fn step<T, E>(label: impl Display, result: Result<T, E>) -> Result<T, SensorError>
where
    E: Display,
{
    result.map_err(|error| SensorError::step(label, error))
}

/// Wraps an async result with a labeled error context for startup steps.
async fn step_async<T, E, F>(label: impl Display, future: F) -> Result<T, SensorError>
where
    E: Display,
    F: std::future::Future<Output = Result<T, E>>,
{
    future
        .await
        .map_err(|error| SensorError::step(label, error))
}
