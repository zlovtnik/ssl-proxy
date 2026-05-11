//! Single-threaded async event loop and sensor lifecycle.
//!
//! run_sensor drives a tokio::select! loop over incoming pcap packets, a heartbeat
//! ticker for idle logging, a bandwidth flush interval, and a client inventory flush interval.
//! All mutable per-frame state lives in PipelineState, which is
//! owned by the loop and never shared across tasks, avoiding locks on the hot path.
//! SensorHandles bundles the shared resources that are either read-only or Arc-wrapped:
//! the NATS backlog, the NATS publish client, the audit window, and the authorized-network
//! config generation counter. On SIGTERM or Ctrl-C, shutdown_flush drains the current bandwidth
//! window, flushes the in-memory publish backlog to the coordinator, then sleeps for shutdown_grace_secs
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
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use lru::LruCache;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    audit::{
        AuditLayer, AuditWindow, SharedAuditWindow, TrafficBucket, WirelessBandwidthEvent,
        DEFAULT_BANDWIDTH_WINDOW_SECS, EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
    },
    backlog::{BacklogStore, NatsBacklog, ProbeFlushObservation},
    capture::{stream_packets, CaptureControl, CaptureError},
    channel_control::set_channel,
    config::AppConfig,
    detect_state::{
        AuthorizedNetworkCache, ClientInventory, DeauthFloodTracker, PmfAttackTracker,
        RogueApTracker, SignalTracker, CLIENT_INVENTORY_SUBJECT, DEAUTH_FLOOD_SUBJECT,
        ROGUE_AP_SUBJECT,
    },
    device::{detect, read_mac_address},
    error::SensorError,
    model::{AuditContext, EnrichedFrame, RawPacket},
    parse::{attach_context, decode_frame, to_audit_entry, HandshakeMonitor, IdentityCache},
    publish::{
        flush_memory_backlog, periodic_memory_backlog_flush, publish_bandwidth_event,
        publish_entry, publish_handshake_alert, publish_json, PublishClient, PublishError,
        PublishState, SharedPublishState, SyncPublisherClient, replay_journal,
    },
    stats::PipelineOutcome,
};
/// Default log level filter when RUST_LOG is not set.
const DEFAULT_RUST_LOG: &str = "warn,atheros_sensor=info,ssl_proxy=info";
const MAC_DEVICE_CACHE_SIZE: usize = 4_096;
const MAC_LOOKUP_ERROR_TTL_SECS: u64 = 30;

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

    // Verify NATS publisher initializes
    let publisher = Arc::new(ssl_proxy::transport::SyncPublisher::new(&config.sync));
    let publish_client: Arc<dyn PublishClient> =
        Arc::new(SyncPublisherClient::new(Arc::clone(&publisher)));
    let backlog = step(
        "initialize NATS backlog",
        NatsBacklog::new(Arc::clone(&publish_client), config.sync.clone()),
    )?;
    match step_async("request coordinator backlog list over NATS", async {
        backlog.list_pending().await
    })
    .await
    {
        Ok(_) => {}
        Err(error) => {
            eprintln!("Healthcheck WARNING: coordinator backlog list failed (sensor is degraded but operational): {}", error);
        }
    }

    println!("Healthcheck OK: configuration valid, device accessible, NATS publisher initialized");
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

                let observed_at = packet.observed_at;
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
                    Ok(PipelineOutcome::DecodedFrame) => {
                        let mut stats = handles.stats.lock().unwrap();
                        stats.decoded_frames += 1;
                        let lag_ms = (Utc::now() - observed_at)
                            .num_milliseconds()
                            .max(0) as u64;
                        stats.lag_total_ms = stats.lag_total_ms.saturating_add(lag_ms);
                        stats.lag_count += 1;
                    }
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
                // Compute median (publish_time - window_end) across bandwidth events.
                let now = Utc::now();
                let mut lags: Vec<u64> = bandwidth_events
                    .iter()
                    .filter_map(|e| {
                        let window_end = chrono::DateTime::parse_from_rfc3339(&e.window_end).ok()?;
                        let lag = (now - window_end.with_timezone(&chrono::Utc)).num_milliseconds().max(0) as u64;
                        Some(lag)
                    })
                    .collect();
                lags.sort_unstable();
                let median_lag = lags.get(lags.len() / 2).copied();
                {
                    let mut stats = handles.stats.lock().unwrap();
                    stats.bandwidth_window_lag_ms = median_lag;
                    stats.memory_backlog_len = handles.publish_state.lock().unwrap().memory_backlog_len();
                }
                publish_bandwidth_events(&*handles.publish_client, bandwidth_events).await;
            }
            _ = inventory_flush.tick() => {
                // Flush client inventory snapshot
                let snapshot = pipeline_state.client_inventory.snapshot();
                if let Err(error) = publish_json(&*handles.publish_client, "publish_client_inventory", CLIENT_INVENTORY_SUBJECT, &snapshot).await {
                    warn!(%error, "client inventory publish failed");
                }

                let probes_to_flush: Vec<_> = pipeline_state.probe_accumulator.drain().collect();
                let batch = probes_to_flush
                    .iter()
                    .map(|((ssid, client_mac), obs)| ProbeFlushObservation {
                        ssid: ssid.clone(),
                        client_mac: client_mac.clone(),
                        known_bssid: obs.known_bssid.clone(),
                        first_seen: obs.first_seen,
                        last_seen: obs.last_seen,
                        probe_count: obs.probe_count,
                    })
                    .collect::<Vec<_>>();
                if let Err(error) = handles.backlog.flush_probe_batch(&batch).await {
                    warn!(%error, "probe batch publish failed; reinserting for retry");
                    for (key, obs) in probes_to_flush {
                        pipeline_state.probe_accumulator.insert(key, obs);
                    }
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
    backlog: Arc<NatsBacklog>,
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
    mac_lookup_error_cache: LruCache<String, Instant>,
    client_inventory: ClientInventory,
    signal_tracker: SignalTracker,
    rogue_ap_tracker: RogueApTracker,
    deauth_flood_tracker: DeauthFloodTracker,
    pmf_attack_tracker: PmfAttackTracker,
    authorized_network_cache: AuthorizedNetworkCache,
    seen_authorized_config_generation: u64,
    probe_accumulator: HashMap<(String, String), ProbeObservation>,
}

#[derive(Clone)]
struct ProbeObservation {
    known_bssid: Option<String>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    probe_count: u32,
}

impl PipelineState {
    fn new(_config: &AppConfig) -> Self {
        let pmf_reconnect_window_ms = std::env::var("ATH_SENSOR_PMF_RECONNECT_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(3000);

        Self {
            identity_cache: IdentityCache::default(),
            handshake_monitor: HandshakeMonitor::default(),
            traffic_bucket: TrafficBucket::new(DEFAULT_BANDWIDTH_WINDOW_SECS),
            mac_device_cache: LruCache::new(
                NonZeroUsize::new(MAC_DEVICE_CACHE_SIZE).unwrap_or_else(|| {
                    NonZeroUsize::new(1).expect("fallback cache capacity must be non-zero")
                }),
            ),
            mac_lookup_error_cache: LruCache::new(
                NonZeroUsize::new(MAC_DEVICE_CACHE_SIZE).unwrap_or_else(|| {
                    NonZeroUsize::new(1).expect("fallback cache capacity must be non-zero")
                }),
            ),
            client_inventory: ClientInventory::default(),
            signal_tracker: SignalTracker::default(),
            rogue_ap_tracker: RogueApTracker::default(),
            deauth_flood_tracker: DeauthFloodTracker::default(),
            pmf_attack_tracker: PmfAttackTracker::new(pmf_reconnect_window_ms),
            authorized_network_cache: AuthorizedNetworkCache::new(
                _config.authorized_network_cache_backoff_ms,
            ),
            seen_authorized_config_generation: 0,
            probe_accumulator: HashMap::new(),
        }
    }
}

/// Initializes sensor in startup order: tracing first (so all subsequent steps are logged),
/// then device detection, then NATS backlog, then pcap capture, then config subscribers.
async fn init_sensor(config: &AppConfig) -> Result<SensorHandles, SensorError> {
    let audit_window: SharedAuditWindow = Arc::new(RwLock::new(config.audit_window.clone()));

    let (log_filter, _audit_window_active) = init_tracing(Arc::clone(&audit_window), config.audit_layer_stream);
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
    let publish_client = Arc::new(SyncPublisherClient::new(Arc::clone(&publisher)));
    let publish_state = PublishState::shared_with_config(
        config.memory_backlog_size,
        config.publish_journal_path.clone(),
    );
    let backlog_client: Arc<dyn PublishClient> = publish_client.clone();
    let backlog = Arc::new(step(
        "initialize NATS backlog",
        NatsBacklog::new(backlog_client, config.sync.clone()),
    )?);
    backlog.clone().spawn_health_check();
    // Replay journal entries from previous outages
    match replay_journal(&publish_state, &*backlog).await {
        Ok(count) => {
            if count > 0 {
                info!(replayed = count, "recovered publish journal entries");
            }
        }
        Err(error) => warn!(%error, "publish journal replay failed; entries remain in journal for retry"),
    }

    info!("atheros sensor NATS backlog initialized");

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
    metrics::spawn_metrics_server(config.metrics_port, Arc::clone(&stats), Arc::clone(&publish_state));

    // Shared filter state: tracks the last-applied BPF so the hopper can skip
    // re-applying when the filter hasn't changed.
    let current_filter: Arc<RwLock<String>> = Arc::new(RwLock::new(config.bpf.clone()));

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
    config_subscriber::spawn_sensor_config_subscriber(
        config.sync.clone(),
        config.location_id.clone(),
        Arc::clone(&context),
        packet_stream.control.clone(),
        current_filter,
    );
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
/// bandwidth -> publishes to NATS.
async fn process_packet(
    packet: RawPacket,
    context: &AuditContext,
    config: &AppConfig,
    backlog: &NatsBacklog,
    publish_client: &dyn PublishClient,
    publish_state: &SharedPublishState,
    pipeline: &mut PipelineState,
    stats: &metrics::SharedStats,
    authorized_config_generation: &AtomicU64,
    capture_control: &CaptureControl,
) -> Result<PipelineOutcome, SensorError> {
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
    let refresh_result = pipeline
        .authorized_network_cache
        .refresh_if_needed(
            backlog,
            Duration::from_secs(config.authorized_network_cache_ttl_secs),
        )
        .await;
    if refresh_result.is_err() && pipeline.authorized_network_cache.should_log_failure(true) {
        warn!(
            error = %refresh_result.as_ref().unwrap_err(),
            "authorized wireless network cache refresh failed"
        );
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

    // Accumulate probe observations for batched flush
    if entry.frame_subtype == "probe_request" {
        if let (Some(client_mac), Some(ssid)) = (
            entry
                .source_mac
                .as_deref()
                .map(|m| m.trim().to_ascii_lowercase()),
            entry
                .ssid
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        ) {
            let observed_at = chrono::DateTime::parse_from_rfc3339(&entry.observed_at)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now);

            let key = (ssid.to_string(), client_mac.clone());
            pipeline
                .probe_accumulator
                .entry(key)
                .and_modify(|obs| {
                    if obs.known_bssid.is_none() {
                        obs.known_bssid = entry.bssid.clone();
                    }
                    obs.last_seen = observed_at;
                    obs.probe_count = obs.probe_count.saturating_add(1);
                })
                .or_insert_with(|| ProbeObservation {
                    known_bssid: entry.bssid.clone(),
                    first_seen: observed_at,
                    last_seen: observed_at,
                    probe_count: 1,
                });
        }
    }

    // Backpressure guard for probe accumulator: if the map exceeds 8192 entries,
    // drain and flush immediately rather than waiting for the next inventory_flush tick.
    const MAX_PROBE_ACCUMULATOR_SIZE: usize = 8192;
    if pipeline.probe_accumulator.len() > MAX_PROBE_ACCUMULATOR_SIZE {
        let probes_to_flush: Vec<_> = pipeline.probe_accumulator.drain().collect();
        let batch = probes_to_flush
            .iter()
            .map(|((ssid, client_mac), obs)| ProbeFlushObservation {
                ssid: ssid.clone(),
                client_mac: client_mac.clone(),
                known_bssid: obs.known_bssid.clone(),
                first_seen: obs.first_seen,
                last_seen: obs.last_seen,
                probe_count: obs.probe_count,
            })
            .collect::<Vec<_>>();
        if let Err(error) = backlog.flush_probe_batch(&batch).await {
            warn!(%error, "probe batch early flush failed; reinserting for retry");
            for (key, obs) in probes_to_flush {
                pipeline.probe_accumulator.insert(key, obs);
            }
        }
    }
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
    let mut pmf_tags = Vec::new();
    pipeline.pmf_attack_tracker.observe(&entry, &mut pmf_tags);
    entry.tags.extend(pmf_tags);
    // Backpressure guard: if the memory backlog is >80% full, skip the MAC device lookup
    // (which adds async I/O per packet) to prevent the backlog from growing further.
    let backlog_pct = {
        let ps = publish_state.lock().unwrap();
        let capacity = ps.memory_backlog_capacity().get();
        if capacity > 0 {
            ps.memory_backlog_len() * 100 / capacity
        } else {
            0
        }
    };
    let skip_mac_lookup = backlog_pct > 80;
    if skip_mac_lookup {
        if entry.identity_source == "unknown" || entry.identity_source == "mac_observed" {
            entry.identity_source = "mac_lookup_skipped_backpressure".to_string();
        }
    } else if let Some(mac) = entry.source_mac.clone().or_else(|| entry.bssid.clone()) {
        let cache_key = mac.to_ascii_lowercase();
        let lookup = if let Some(cached) = pipeline.mac_device_cache.get(&cache_key) {
            cached.clone()
        } else {
            let lookup = if pipeline
                .mac_lookup_error_cache
                .get(&cache_key)
                .is_some_and(|last| last.elapsed() < Duration::from_secs(MAC_LOOKUP_ERROR_TTL_SECS))
            {
                None
            } else {
                match backlog.lookup_device_by_mac(&cache_key).await {
                    Ok(lookup) => lookup,
                    Err(error) => {
                        stats.lock().unwrap().mac_lookup_failures += 1;
                        pipeline
                            .mac_lookup_error_cache
                            .put(cache_key.clone(), Instant::now());
                        warn!(%error, mac = %cache_key, "MAC device lookup failed; publishing unenriched audit entry");
                        None
                    }
                }
            };
            pipeline
                .mac_device_cache
                .put(cache_key.clone(), lookup.clone());
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
    } // end of skip_mac_lookup else block
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
                    stats.lock().unwrap().channel_hop_count += 1;

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
/// shutdown_grace_secs to let in-flight NATS publishes drain before process exit.
async fn shutdown_flush(handles: &SensorHandles, pipeline_state: &mut PipelineState) {
    let events = pipeline_state.traffic_bucket.flush_current();
    let now = Utc::now();
    let mut lags: Vec<u64> = events
        .iter()
        .filter_map(|e| {
            let window_end = chrono::DateTime::parse_from_rfc3339(&e.window_end).ok()?;
            let lag = (now - window_end.with_timezone(&chrono::Utc)).num_milliseconds().max(0) as u64;
            Some(lag)
        })
        .collect();
    lags.sort_unstable();
    let median_lag = lags.get(lags.len() / 2).copied();
    {
        let mut stats = handles.stats.lock().unwrap();
        stats.bandwidth_window_lag_ms = median_lag;
        stats.memory_backlog_len = handles.publish_state.lock().unwrap().memory_backlog_len();
    }
    publish_bandwidth_events(&*handles.publish_client, events).await;
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

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .with(AuditLayer::new(Arc::clone(&audit_window_active), audit_layer_stream))
        .init();

    (filter_source, audit_window_active)
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
