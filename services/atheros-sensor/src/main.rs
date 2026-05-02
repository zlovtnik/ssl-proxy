//! Single-threaded async event loop and sensor lifecycle.
//!
//! run_sensor drives a tokio::select! loop over five arms: incoming pcap packets, a heartbeat
//! ticker for idle logging, a bandwidth flush interval, a client inventory flush interval, and
//! a backlog prune interval. All mutable per-frame state lives in PipelineState, which is
//! owned by the loop and never shared across tasks, avoiding locks on the hot path.
//! SensorHandles bundles the shared resources that are either read-only or Arc-wrapped:
//! the Postgres backlog, the NATS publish client, the audit window, and the authorized-network
//! config generation counter. On SIGTERM or Ctrl-C, shutdown_flush drains the current bandwidth
//! window, flushes the in-memory publish backlog to Postgres, then sleeps for shutdown_grace_secs
//! to allow in-flight NATS publishes to complete before the process exits.
//!
//! # Type notes
//!
//! [`SensorHandles`]: the main loop's owned state bundle; fields are either `Clone`-cheap
//! shared handles (`Arc`, `SharedAuditWindow`) or values consumed once at startup - nothing
//! here is mutated per-packet.
//!
//! [`PipelineState`]: all per-packet mutable state (identity cache, handshake monitor,
//! traffic bucket, detector state, authorized-network cache); constructed once in `run_sensor`
//! and reset only by a process restart.
//!
//! [`CaptureStats`]: cumulative counters incremented since process startup, not windowed or
//! reset between heartbeat log lines - use the delta between two log lines for rate calculation.

mod audit;
mod backlog;
mod capture;
mod channel_control;
mod config;
mod config_subscriber;
mod detect_state;
mod device;
mod error;
mod metrics;
mod model;
mod parse;
mod publish;
mod stats;
#[cfg(test)]
mod testutil;

use std::{
    collections::HashMap,
    fmt::Display,
    future,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use lru::LruCache;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    audit::{
        AuditLayer, AuditWindow, SharedAuditWindow, TrafficBucket, WirelessBandwidthEvent,
        DEFAULT_BANDWIDTH_WINDOW_SECS, EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
    },
    backlog::{BacklogStore, PostgresBacklog},
    capture::{stream_packets, CaptureControl, CaptureError},
    channel_control::set_channel,
    config::AppConfig,
    detect_state::{
        AuthorizedNetworkCache, ClientInventory, DeauthFloodTracker, RogueApTracker, SignalTracker,
        CLIENT_INVENTORY_SUBJECT, DEAUTH_FLOOD_SUBJECT, ROGUE_AP_SUBJECT,
    },
    device::{detect, read_mac_address},
    error::SensorError,
    model::{AuditContext, EnrichedFrame, RawPacket},
    parse::{attach_context, decode_frame, to_audit_entry, HandshakeMonitor, IdentityCache},
    publish::{
        flush_memory_backlog, publish_bandwidth_event, publish_entry, publish_handshake_alert,
        publish_json, reconcile_backlog, PublishClient, PublishError, PublishState,
        SharedPublishState, SyncPublisherClient,
    },
    stats::PipelineOutcome,
};
/// Default log level filter when RUST_LOG is not set.
const DEFAULT_RUST_LOG: &str = "warn,atheros_sensor=info,ssl_proxy=info";

async fn run_healthcheck() -> Result<(), SensorError> {
    // Verify config loads correctly
    let config = step("load configuration", AppConfig::from_env())?;

    // Verify device can be detected
    let device = step(
        format!(
            "detect wireless capture interface{}",
            configured_device_suffix(config.device_override.as_deref())
        ),
        detect(config.device_override.as_deref()),
    )?;

    // Verify we can read MAC address
    let _sensor_id = step(
        format!("read MAC address for interface {device}"),
        read_mac_address(&device),
    )?;

    // Verify database connection works
    let backlog = step_async("connect to Postgres backlog", async {
        PostgresBacklog::connect(&config.database_url).await
    })
    .await?;
    let _ = step_async("query Postgres backlog", async {
        backlog.list_pending().await
    })
    .await?;

    // Verify NATS publisher initializes
    let _publisher = ssl_proxy::transport::SyncPublisher::new(&config.sync);

    println!("Healthcheck OK: configuration valid, device accessible, database connected, publisher initialized");
    Ok(())
}

/// Entry point: runs healthcheck subcommand if requested, otherwise starts the sensor.
#[tokio::main]
async fn main() {
    // Check for healthcheck subcommand
    if std::env::args().any(|arg| arg == "healthcheck") {
        if let Err(e) = run_healthcheck().await {
            eprintln!("Healthcheck FAILED: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if let Err(error) = run_sensor().await {
        eprintln!("atheros sensor failed: {error}");
        std::process::exit(1);
    }
}

/// Main sensor loop: initializes resources, then processes packets until shutdown.
async fn run_sensor() -> Result<(), SensorError> {
    let config = step("load configuration", AppConfig::from_env())?;
    let mut handles = init_sensor(&config).await?;
    let mut heartbeat = capture_heartbeat(handles.config.log_idle_secs);
    let mut pipeline_state = PipelineState::new(&handles.config);
    let mut bandwidth_flush = bandwidth_flush_interval();
    let mut inventory_flush = interval_secs(handles.config.client_inventory_flush_secs);
    let mut backlog_prune = interval_secs(6 * 60 * 60);
    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received; flushing sensor state");
                shutdown_flush(&handles, &mut pipeline_state).await;
                handles.stats.lock().unwrap().log(&handles.device, &handles.config);
                break;
            }
            packet = handles.packets.next() => {
                let Some(packet) = packet else {
                    break;
                };

                let packet = match packet {
                    Ok(packet) => {
                        handles.stats.lock().unwrap().packets_seen += 1;
                        packet
                    }
                    Err(error) => {
                        handles.stats.lock().unwrap().capture_errors += 1;
                        error!(%error, interface = %handles.device, "packet capture failed");
                        continue;
                    }
                };

                if !audit_window_snapshot(&handles.audit_window).is_active_at(packet.observed_at) {
                    handles.stats.lock().unwrap().audit_window_drops += 1;
                    debug!("audit window inactive; dropping packet");
                    continue;
                }

                let context = context_snapshot(&handles.context);
                let span = info_span!(
                    "wireless_capture",
                    sensor_id = %context.sensor_id,
                    location_id = %context.location_id,
                    interface = %context.interface
                );

                let result = process_packet(
                    packet,
                    &context,
                    &handles.config,
                    &handles.backlog,
                    &*handles.publish_client,
                    &handles.publish_state,
                    &mut pipeline_state,
                    &handles.stats,
                    &handles.authorized_config_generation,
                    &handles.capture_control,
                )
                .instrument(span)
                .await;

                match result {
                    Ok(PipelineOutcome::DecodedFrame) => handles.stats.lock().unwrap().decoded_frames += 1,
                    Ok(PipelineOutcome::UnsupportedFrame) => handles.stats.lock().unwrap().unsupported_frames += 1,
                    Err(error) => {
                        handles.stats.lock().unwrap().pipeline_errors += 1;
                        error!(%error, "wireless packet pipeline failed");
                    }
                }
            }
            _ = tick_capture_heartbeat(&mut heartbeat) => {
                handles.stats.lock().unwrap().log(&handles.device, &handles.config);
            }
            _ = bandwidth_flush.tick() => {
                let ttl = Duration::from_secs(handles.config.handshake_ttl_secs);
                pipeline_state
                    .handshake_monitor
                    .cleanup_expired(ttl, Some(&handles.capture_control));
                let bandwidth_events = pipeline_state.traffic_bucket.flush_current();
                publish_bandwidth_events(&*handles.publish_client, bandwidth_events).await;
            }
            _ = inventory_flush.tick() => {
                let snapshot = pipeline_state.client_inventory.snapshot();
                if let Err(error) = publish_json(&*handles.publish_client, "publish_client_inventory", CLIENT_INVENTORY_SUBJECT, &snapshot).await {
                    warn!(%error, "client inventory publish failed");
                }
            }
            _ = backlog_prune.tick() => {
                if let Err(error) = handles.backlog.prune_stale(handles.config.backlog_max_attempts, handles.config.backlog_max_age_hours).await {
                    warn!(%error, "backlog stale prune failed");
                }
            }
        }
    }

    Ok(())
}

/// Shared handles and resources used by the main sensor loop.
/// All fields are either cheap-to-clone Arc wrappers or read-only references.
struct SensorHandles {
    config: AppConfig,
    audit_window: SharedAuditWindow,
    device: String,
    context: SharedContext,
    packets: ReceiverStream<Result<RawPacket, CaptureError>>,
    capture_control: CaptureControl,
    backlog: Arc<PostgresBacklog>,
    publish_client: Arc<SyncPublisherClient>,
    publish_state: SharedPublishState,
    stats: metrics::SharedStats,
    authorized_config_generation: Arc<AtomicU64>,
}

/// Thread-safe shared reference to the current audit context.
type SharedContext = Arc<RwLock<AuditContext>>;

/// Mutable per-packet state owned by the main loop.
/// Never shared across tasks to avoid locks on the hot path.
struct PipelineState {
    identity_cache: IdentityCache,
    handshake_monitor: HandshakeMonitor,
    traffic_bucket: TrafficBucket,
    mac_device_cache: LruCache<String, Option<(String, Option<String>)>>,
    mac_lookup_error_cache: HashMap<String, Instant>,
    client_inventory: ClientInventory,
    signal_tracker: SignalTracker,
    rogue_ap_tracker: RogueApTracker,
    deauth_flood_tracker: DeauthFloodTracker,
    authorized_network_cache: AuthorizedNetworkCache,
    seen_authorized_config_generation: u64,
}

impl PipelineState {
    fn new(config: &AppConfig) -> Self {
        Self {
            identity_cache: IdentityCache::default(),
            handshake_monitor: HandshakeMonitor::default(),
            traffic_bucket: TrafficBucket::new(DEFAULT_BANDWIDTH_WINDOW_SECS),
            mac_device_cache: LruCache::new(
                NonZeroUsize::new(config.mac_device_cache_size).unwrap_or_else(|| {
                    NonZeroUsize::new(1).expect("fallback cache capacity must be non-zero")
                }),
            ),
            mac_lookup_error_cache: HashMap::new(),
            client_inventory: ClientInventory::default(),
            signal_tracker: SignalTracker::default(),
            rogue_ap_tracker: RogueApTracker::default(),
            deauth_flood_tracker: DeauthFloodTracker::default(),
            authorized_network_cache: AuthorizedNetworkCache::default(),
            seen_authorized_config_generation: 0,
        }
    }
}

/// Initializes sensor in startup order: tracing first (so all subsequent steps are logged),
/// then device detection, then Postgres connection, then pcap capture, then config subscribers.
async fn init_sensor(config: &AppConfig) -> Result<SensorHandles, SensorError> {
    let audit_window: SharedAuditWindow = Arc::new(RwLock::new(config.audit_window.clone()));

    let log_filter = init_tracing(Arc::clone(&audit_window), config.audit_layer_stream);
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
        nats_configured = config.sync.nats_url.is_some(),
        nats_tls_enabled = config.sync.tls_enabled,
        audit_window = ?audit_window_snapshot(&audit_window),
        "atheros sensor starting"
    );

    let publisher = Arc::new(ssl_proxy::transport::SyncPublisher::new(&config.sync));
    info!(
        nats_configured = config.sync.nats_url.is_some(),
        nats_tls_enabled = config.sync.tls_enabled,
        "atheros sensor publisher initialized"
    );
    let backlog = Arc::new(
        step_async("connect to Postgres backlog", async {
            PostgresBacklog::connect(&config.database_url).await
        })
        .await?,
    );
    info!("atheros sensor postgres backlog connected");
    let publish_client = Arc::new(SyncPublisherClient::new(Arc::clone(&publisher)));
    let publish_state = PublishState::shared();

    config_subscriber::spawn_audit_window_config_subscriber(
        config.sync.clone(),
        config.location_id.clone(),
        Arc::clone(&audit_window),
    );
    let authorized_config_generation = Arc::new(AtomicU64::new(0));
    config_subscriber::spawn_authorized_network_config_subscriber(
        config.sync.clone(),
        Arc::clone(&authorized_config_generation),
    );

    let reconcile_window = Arc::clone(&audit_window);
    let reconcile_backlog_store = Arc::clone(&backlog);
    let reconcile_client = Arc::clone(&publish_client);
    let reconcile_publish_state = Arc::clone(&publish_state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        info!("backlog reconciliation task started");
        loop {
            interval.tick().await;
            let window = audit_window_snapshot(&reconcile_window);
            if let Err(error) = reconcile_backlog(
                &reconcile_publish_state,
                &*reconcile_backlog_store,
                &*reconcile_client,
                &window,
            )
            .await
            {
                error!(%error, "backlog reconciliation failed");
            }
        }
    });

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
    if config.channel_hop_enabled {
        spawn_channel_hopper(
            device.clone(),
            config.bpf.clone(),
            config.channel_hop_interval_ms,
            Arc::clone(&context),
            packet_stream.control.clone(),
        );
    }
    config_subscriber::spawn_sensor_config_subscriber(
        config.sync.clone(),
        config.location_id.clone(),
        Arc::clone(&context),
        packet_stream.control.clone(),
    );
    let stats = metrics::shared_stats();
    metrics::spawn_metrics_server(
        config.metrics_port,
        Arc::clone(&stats),
        Arc::clone(&backlog),
    );

    Ok(SensorHandles {
        config: config.clone(),
        audit_window,
        device,
        context,
        packets: packet_stream.packets,
        capture_control: packet_stream.control,
        backlog,
        publish_client,
        publish_state,
        stats,
        authorized_config_generation,
    })
}

/// Hot path: decodes raw packet -> extracts handshake -> resolves identity -> checks
/// authorized network -> tags threats -> enriches with MAC device lookup -> observes
/// bandwidth -> publishes to NATS and Postgres ingest ledger.
async fn process_packet(
    packet: RawPacket,
    context: &AuditContext,
    config: &AppConfig,
    backlog: &PostgresBacklog,
    publish_client: &dyn PublishClient,
    publish_state: &SharedPublishState,
    pipeline: &mut PipelineState,
    stats: &metrics::SharedStats,
    authorized_config_generation: &AtomicU64,
    capture_control: &CaptureControl,
) -> Result<PipelineOutcome, SensorError> {
    // Always count raw bytes first, before any parsing attempts
    let packet_len = packet.data.len() as u64;

    let mut wifi_frame = match decode_frame(&packet) {
        Ok(frame) => frame,
        Err(error) => {
            trace!(%error, len = packet_len, "counted raw bytes for unsupported frame");
            pipeline.traffic_bucket.observe_raw(
                packet_len,
                packet.observed_at,
                &context.sensor_id,
                &context.location_id,
                &context.interface,
                context.channel,
            );
            return Ok(PipelineOutcome::UnsupportedFrame);
        }
    };

    // For successfully decoded frames we will get proper classification
    // via the existing traffic_bucket.observe() call below

    let handshake_export_dir = config
        .export_handshakes
        .then_some(config.sync.outbox_dir.as_str());
    let handshake_ttl = Duration::from_secs(config.handshake_ttl_secs);
    let handshake_alert = pipeline.handshake_monitor.observe(
        &mut wifi_frame,
        context,
        handshake_export_dir,
        Some(capture_control),
        handshake_ttl,
    );
    let resolved_identity = pipeline.identity_cache.resolve(&wifi_frame);
    let enriched: EnrichedFrame = attach_context(wifi_frame, context);
    let mut entry = to_audit_entry(enriched);
    if let Some(alert) = handshake_alert.as_ref() {
        if let Err(error) = publish_handshake_alert(publish_client, alert).await {
            warn!(%error, "handshake alert publish failed; continuing audit publish");
        }
    }
    if let Some(identity) = resolved_identity {
        entry.username = Some(identity.username);
        entry.identity_source = identity.source;
        entry.tags.extend(identity.tags);
    }
    let latest_generation = authorized_config_generation.load(Ordering::Relaxed);
    if latest_generation != pipeline.seen_authorized_config_generation {
        pipeline.authorized_network_cache.invalidate();
        pipeline.seen_authorized_config_generation = latest_generation;
    }
    if let Err(error) = pipeline
        .authorized_network_cache
        .refresh_if_needed(
            backlog,
            Duration::from_secs(config.authorized_network_cache_ttl_secs),
        )
        .await
    {
        warn!(%error, "authorized wireless network cache refresh failed");
    }
    let authorized = pipeline.authorized_network_cache.is_authorized(
        entry.ssid.as_deref(),
        entry
            .bssid
            .as_deref()
            .or(entry.destination_bssid.as_deref()),
        &entry.location_id,
    );
    let external_bssid = !authorized;
    if entry.ssid.is_some() && external_bssid {
        entry.tags.push("threat:unauthorized_bssid".to_string());
    }
    pipeline.client_inventory.observe(&entry);
    if pipeline
        .signal_tracker
        .observe(&entry, config.signal_anomaly_dbm_delta)
    {
        entry.tags.push("threat:signal_anomaly".to_string());
        entry.anomaly_reasons.push("signal_anomaly".to_string());
    }
    if let Some(alert) = pipeline
        .rogue_ap_tracker
        .observe(&entry, &pipeline.authorized_network_cache)
    {
        if let Err(error) = publish_json(
            publish_client,
            "publish_rogue_ap_alert",
            ROGUE_AP_SUBJECT,
            &alert,
        )
        .await
        {
            warn!(%error, "rogue AP alert publish failed");
        }
    }
    if let Some(alert) = pipeline.deauth_flood_tracker.observe(
        &entry,
        config.deauth_flood_threshold,
        config.deauth_flood_window_secs,
        config.deauth_flood_cooldown_secs,
    ) {
        if let Err(error) = publish_json(
            publish_client,
            "publish_deauth_flood_alert",
            DEAUTH_FLOOD_SUBJECT,
            &alert,
        )
        .await
        {
            warn!(%error, "deauth flood alert publish failed");
        }
    }
    if config.mac_device_lookup_enabled {
        if let Some(mac) = entry.source_mac.clone().or_else(|| entry.bssid.clone()) {
            let cache_key = mac.to_ascii_lowercase();
            let lookup = if let Some(cached) = pipeline.mac_device_cache.get(&cache_key) {
                cached.clone()
            } else {
                let lookup = if pipeline.mac_lookup_error_cache.get(&cache_key).is_some_and(
                    |last| last.elapsed() < Duration::from_secs(config.mac_lookup_error_ttl_secs),
                ) {
                    None
                } else {
                    match backlog.lookup_device_by_mac(&cache_key).await {
                        Ok(lookup) => lookup,
                        Err(error) => {
                            stats.lock().unwrap().mac_lookup_failures += 1;
                            pipeline
                                .mac_lookup_error_cache
                                .insert(cache_key.clone(), Instant::now());
                            warn!(%error, mac = %cache_key, "MAC device lookup failed; publishing unenriched audit entry");
                            None
                        }
                    }
                };
                if lookup.is_some() {
                    pipeline
                        .mac_device_cache
                        .put(cache_key.clone(), lookup.clone());
                }
                lookup
            };
            if let Some((device_id, username)) = lookup {
                entry.device_id = Some(device_id);
                if entry.username.is_none() {
                    entry.username = username;
                }
                if matches!(entry.identity_source.as_str(), "unknown" | "mac_observed") {
                    entry.identity_source = "device_registry".to_string();
                }
            }
        }
    }
    let bandwidth_events = match pipeline.traffic_bucket.observe(&entry, external_bssid) {
        Ok(events) => events,
        Err(error) => {
            warn!(%error, "wireless bandwidth bucket update failed; continuing audit publish");
            Vec::new()
        }
    };
    publish_bandwidth_events(publish_client, bandwidth_events).await;
    info!(
        target: "wireless_audit",
        event_type = %entry.event_type,
        frame_subtype = %entry.frame_subtype,
        bssid = ?entry.bssid,
        ssid = ?entry.ssid,
        "captured wifi frame"
    );
    match publish_entry(publish_state, backlog, publish_client, entry).await {
        Ok(()) | Err(PublishError::Queued(_)) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(PipelineOutcome::DecodedFrame)
}

fn bandwidth_flush_interval() -> tokio::time::Interval {
    let interval = Duration::from_secs(DEFAULT_BANDWIDTH_WINDOW_SECS as u64);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

async fn publish_bandwidth_events(
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
        if let Err(error) = publish_bandwidth_event(publisher, &event).await {
            warn!(
                %error,
                source_mac = %event.source_mac,
                destination_bssid = %event.destination_bssid,
                "wireless bandwidth event publish failed"
            );
        }
    }
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

/// Spawns a background task that cycles through channels 1, 6, and 11 at the configured interval.
fn spawn_channel_hopper(
    device: String,
    bpf: String,
    interval_ms: u64,
    context: SharedContext,
    capture_control: CaptureControl,
) {
    tokio::spawn(async move {
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
                    capture_control.apply_filter(bpf.clone());
                    info!(interface = %device, channel, "wireless capture channel hopped");
                }
                Err(error) => {
                    warn!(%error, interface = %device, channel, "wireless channel hop failed")
                }
            }
        }
    });
}

/// Flushes bandwidth window, writes memory backlog to Postgres, then sleeps for
/// shutdown_grace_secs to let in-flight NATS publishes drain before process exit.
async fn shutdown_flush(handles: &SensorHandles, pipeline_state: &mut PipelineState) {
    let events = pipeline_state.traffic_bucket.flush_current();
    publish_bandwidth_events(&*handles.publish_client, events).await;
    flush_memory_backlog(&handles.publish_state, &*handles.backlog).await;
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
) -> String {
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

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .with(AuditLayer::new(audit_window, audit_layer_stream))
        .init();

    filter_source
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
