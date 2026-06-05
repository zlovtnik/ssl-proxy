//! Single-threaded async event loop and sensor lifecycle.
//!
//! run_sensor drives a tokio::select! loop over incoming pcap packets, a heartbeat
//! ticker for idle logging, a bandwidth flush interval, and a client inventory flush interval.
//! All mutable per-frame state lives in PipelineState, which is
//! owned by the loop and never shared across tasks, avoiding locks on the hot path.
//! SensorHandles bundles the shared resources that are either read-only or Arc-wrapped:
//! the Redpanda backlog, the Redpanda publish client, the audit window, and the authorized-network
//! config generation counter. On SIGTERM or Ctrl-C, shutdown_flush drains the current bandwidth
//! window, flushes the in-memory publish backlog to the coordinator, then sleeps for shutdown_grace_secs
//! to allow in-flight Redpanda publishes to complete before the process exits.
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
mod device_registry;
mod error;
mod metrics;
mod model;
mod parse;
mod probes;
mod publish;
mod state_key;
mod stats;
#[cfg(test)]
mod testutil;
mod timing;
mod topics;

use std::{
    fmt::Display,
    future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use chrono::Utc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    audit::{
        AuditLayer, AuditWindow, SharedAuditWindow, TrafficBucket, WirelessBandwidthEvent,
        DEFAULT_BANDWIDTH_WINDOW_SECS, EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
    },
    backlog::{BacklogStore, RedpandaBacklog},
    capture::{stream_packets, CaptureControl, CaptureError},
    channel_control::set_channel,
    config::AppConfig,
    detect_state::{
        pmf_attack_alert_from_entry, AttackTimelineCorrelator, AuthorizationStatus,
        AuthorizedNetworkCache, ClientInventory, DeauthFloodTracker, IeLayoutTracker,
        MacSequenceDeltaTracker, PmfAttackTracker, RogueApTracker, SequenceTracker, SignalTracker,
    },
    device::{detect, read_mac_address},
    device_registry::{DeviceRegistryCache, DeviceRegistryCacheDecision},
    error::SensorError,
    model::{AuditContext, EnrichedFrame, RawPacket},
    parse::{
        attach_context, decode_frame, to_audit_entry, try_decrypt_frame, HandshakeMonitor,
        IdentityCache, ParseError,
    },
    probes::{ProbeAccumulator, ProbeFlushBatch},
    publish::{
        flush_memory_backlog, periodic_memory_backlog_flush, publish_bandwidth_event,
        publish_entry, publish_handshake_alert, publish_oracle_json_durable, reconcile_backlog,
        replay_journal, PublishClient, PublishError, PublishState, SharedPublishState,
        SyncPublisherClient,
    },
    state_key::{stable_hash, DetectorRouteKey, DetectorRouter, MacAddr},
    stats::PipelineOutcome,
    timing::FrameTimingTracker,
    topics::{
        ATTACK_SEQUENCE_TOPIC, CLIENT_INVENTORY_TOPIC, DEAUTH_FLOOD_TOPIC, PMF_ATTACK_TOPIC,
        ROGUE_AP_TOPIC, SENSOR_HEARTBEAT_TOPIC, SEQUENCE_ALERT_TOPIC, SIGNAL_ANOMALY_TOPIC,
    },
};
/// Default log level filter when RUST_LOG is not set.
const DEFAULT_RUST_LOG: &str = "warn,atheros_sensor=info,ssl_proxy=info";
const MAC_DEVICE_CACHE_SIZE: usize = 4_096;
const BACKLOG_RECONCILE_INTERVAL_SECS: u64 = 60;
const BACKLOG_PRUNE_INTERVAL_SECS: u64 = 3_600;
const BACKLOG_PRUNE_MAX_ATTEMPTS: i32 = 10;
const BACKLOG_PRUNE_MAX_AGE_HOURS: i64 = 72;

fn hex_prefix(data: &[u8], n: usize) -> String {
    data.iter()
        .take(n)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn detector_route_key(entry: &crate::model::AuditEntry) -> DetectorRouteKey {
    if let Some(mac) = entry.bssid.as_deref().and_then(MacAddr::parse) {
        return DetectorRouteKey::Ap(mac);
    }
    if let Some(mac) = entry.source_mac.as_deref().and_then(MacAddr::parse) {
        return DetectorRouteKey::Client(mac);
    }
    if let Some(session_key) = entry
        .session_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return DetectorRouteKey::Session(stable_hash(session_key));
    }
    if let Some(ssid) = entry
        .ssid
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return DetectorRouteKey::Ssid(stable_hash(&ssid.to_ascii_lowercase()));
    }
    DetectorRouteKey::Unknown
}

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

    // Verify Redpanda publisher initializes
    let publisher = Arc::new(ssl_proxy::transport::SyncPublisher::new(&config.sync));
    let publish_client: Arc<dyn PublishClient> =
        Arc::new(SyncPublisherClient::new(Arc::clone(&publisher)));
    let backlog = step(
        "initialize Redpanda backlog",
        RedpandaBacklog::new(
            Arc::clone(&publish_client),
            config.sync.clone(),
            Duration::from_millis(config.redpanda_request_timeout_ms),
        ),
    )?;
    if backlog.supports_inline_request_reply() {
        match step_async("request coordinator backlog list over Redpanda", async {
            backlog.list_pending().await
        })
        .await
        {
            Ok(_) => {}
            Err(error) => {
                eprintln!("Healthcheck WARNING: coordinator backlog list failed (sensor is degraded but operational): {}", error);
            }
        }
    } else if let Some(reason) = backlog.inline_request_reply_disabled_reason() {
        eprintln!(
            "Healthcheck NOTICE: coordinator request/reply skipped for publish-only endpoint: {reason}"
        );
    }

    println!(
        "Healthcheck OK: configuration valid, device accessible, Redpanda publisher initialized"
    );
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
                    &handles.current_filter,
                    &mut pipeline_state,
                    &handles.stats,
                    &handles.authorized_config_generation,
                    &handles.capture_control,
                    handles.inline_request_reply_enabled,
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
                    Ok(PipelineOutcome::UnsupportedFrame) => {}
                    Err(error) => {
                        handles.stats.lock().unwrap().pipeline_errors += 1;
                        error!(%error, "wireless packet pipeline failed");
                    }
                }
            }
            _ = tick_capture_heartbeat(&mut heartbeat) => {
                log_and_publish_capture_heartbeat(&handles);
            }
            _ = bandwidth_flush.tick() => {
                let ttl = Duration::from_secs(handles.config.handshake_ttl_secs);
                let restore_filter = filter_snapshot(&handles.current_filter, &handles.config.bpf);
                pipeline_state
                    .handshake_monitor
                    .cleanup_expired(ttl, Some(&handles.capture_control), &restore_filter);
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
                    stats.probe_accumulator_len = pipeline_state.probe_accumulator.len();
                }
                publish_bandwidth_events(
                    &handles.publish_state,
                    &*handles.backlog,
                    &*handles.publish_client,
                    bandwidth_events,
                )
                .await;
            }
            _ = inventory_flush.tick() => {
                // Flush client inventory snapshot
                let snapshot = pipeline_state.client_inventory.snapshot();
                let observed_at = snapshot.observed_at.clone();
                let context = context_snapshot(&handles.context);
                let inventory_payload = serde_json::json!({
                    "schema_version": snapshot.schema_version,
                    "event_type": snapshot.event_type,
                    "observed_at": observed_at.clone(),
                    "sensor_id": context.sensor_id,
                    "location_id": context.location_id,
                    "clients": snapshot.clients,
                });
                if let Err(error) = publish_oracle_json_durable(
                    &handles.publish_state,
                    &*handles.backlog,
                    &*handles.publish_client,
                    "publish_client_inventory",
                    CLIENT_INVENTORY_TOPIC,
                    &inventory_payload,
                    &observed_at,
                )
                .await
                {
                    warn!(%error, "client inventory publish failed");
                }

                for batch in pipeline_state.probe_accumulator.take_ready_batches() {
                    match flush_probe_batch(&handles.backlog, batch).await {
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
                handles.stats.lock().unwrap().probe_accumulator_len =
                    pipeline_state.probe_accumulator.len();
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
    current_filter: SharedFilter,
    packets: ReceiverStream<Result<RawPacket, CaptureError>>,
    capture_control: CaptureControl,
    backlog: Arc<RedpandaBacklog>,
    publish_client: Arc<SyncPublisherClient>,
    publish_state: SharedPublishState,
    stats: metrics::SharedStats,
    authorized_config_generation: Arc<AtomicU64>,
    inline_request_reply_enabled: bool,
}

/// Thread-safe shared reference to the current audit context.
type SharedContext = Arc<RwLock<AuditContext>>;
type SharedFilter = Arc<RwLock<String>>;

/// Mutable per-packet state owned by the main loop.
/// Never shared across tasks to avoid locks on the hot path.
struct PipelineState {
    identity_cache: IdentityCache,
    handshake_monitor: HandshakeMonitor,
    traffic_bucket: TrafficBucket,
    device_registry_cache: DeviceRegistryCache,
    client_inventory: ClientInventory,
    signal_tracker: SignalTracker,
    rogue_ap_tracker: RogueApTracker,
    deauth_flood_tracker: DeauthFloodTracker,
    attack_timeline_correlator: AttackTimelineCorrelator,
    sequence_tracker: SequenceTracker,
    mac_sequence_delta_tracker: MacSequenceDeltaTracker,
    ie_layout_tracker: IeLayoutTracker,
    pmf_attack_tracker: PmfAttackTracker,
    pmf_reconnect_window_ms: i64,
    detector_router: DetectorRouter,
    next_frame_id: u64,
    authorized_network_cache: AuthorizedNetworkCache,
    seen_authorized_config_generation: u64,
    probe_accumulator: ProbeAccumulator,
    timing_tracker: FrameTimingTracker,
}

impl PipelineState {
    fn new(config: &AppConfig) -> Self {
        let pmf_reconnect_window_ms = std::env::var("ATH_SENSOR_PMF_RECONNECT_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(3000);
        let limits = config.detector_limits;

        Self {
            identity_cache: IdentityCache::new(limits),
            handshake_monitor: HandshakeMonitor::default(),
            traffic_bucket: TrafficBucket::new(DEFAULT_BANDWIDTH_WINDOW_SECS),
            device_registry_cache: DeviceRegistryCache::new(MAC_DEVICE_CACHE_SIZE),
            client_inventory: ClientInventory::new(limits),
            signal_tracker: SignalTracker::new(limits),
            rogue_ap_tracker: RogueApTracker::new(limits),
            deauth_flood_tracker: DeauthFloodTracker::new(limits),
            attack_timeline_correlator: AttackTimelineCorrelator::new(limits),
            sequence_tracker: SequenceTracker::new(limits),
            mac_sequence_delta_tracker: MacSequenceDeltaTracker::new(limits),
            ie_layout_tracker: IeLayoutTracker::new(limits),
            pmf_attack_tracker: PmfAttackTracker::new_with_limits(pmf_reconnect_window_ms, limits),
            pmf_reconnect_window_ms,
            detector_router: DetectorRouter::new(limits),
            next_frame_id: 0,
            authorized_network_cache: AuthorizedNetworkCache::new(
                config.authorized_network_cache_backoff_ms,
            ),
            seen_authorized_config_generation: 0,
            probe_accumulator: ProbeAccumulator::new_with_limits(limits),
            timing_tracker: FrameTimingTracker::default(),
        }
    }

    fn allocate_frame_id(&mut self) -> u64 {
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);
        frame_id
    }
}

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

/// Hot path: decodes raw packet -> extracts handshake -> resolves identity -> checks
/// authorized network -> tags threats -> enriches with MAC device lookup -> observes
/// bandwidth -> publishes to Redpanda.
async fn process_packet(
    packet: RawPacket,
    context: &AuditContext,
    config: &AppConfig,
    backlog: &RedpandaBacklog,
    publish_client: &dyn PublishClient,
    publish_state: &SharedPublishState,
    current_filter: &SharedFilter,
    pipeline: &mut PipelineState,
    stats: &metrics::SharedStats,
    authorized_config_generation: &AtomicU64,
    capture_control: &CaptureControl,
    inline_request_reply_enabled: bool,
) -> Result<PipelineOutcome, SensorError> {
    let packet_len = packet.data.len() as u64;

    let mut wifi_frame = match decode_frame(&packet) {
        Ok(frame) => frame,
        Err(error) => {
            trace!(
                error = %error,
                packet_len,
                first_bytes = %hex_prefix(&packet.data, 8),
                observed_at = %packet.observed_at,
                "unsupported frame -- bytes counted to raw bucket"
            );
            match &error {
                ParseError::UnsupportedControlFrame => {
                    stats.lock().unwrap().unsupported_frames += 1;
                }
                _ => {
                    stats.lock().unwrap().malformed_frames += 1;
                    debug!(
                        error = %error,
                        packet_len,
                        first_bytes = %hex_prefix(&packet.data, 8),
                        "malformed 802.11 frame dropped"
                    );
                }
            }
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
    let restore_filter = filter_snapshot(current_filter, &config.bpf);
    let handshake_alert = pipeline.handshake_monitor.observe(
        &mut wifi_frame,
        context,
        handshake_export_dir,
        Some(capture_control),
        &restore_filter,
        handshake_ttl,
    );
    let latest_generation = authorized_config_generation.load(Ordering::Relaxed);
    if latest_generation != pipeline.seen_authorized_config_generation {
        pipeline.authorized_network_cache.invalidate();
        pipeline.seen_authorized_config_generation = latest_generation;
    }
    if inline_request_reply_enabled {
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
    }
    if try_decrypt_frame(
        &mut wifi_frame,
        &pipeline.handshake_monitor,
        pipeline.authorized_network_cache.entries(),
    ) {
        debug!("protected data frame decrypted using authorized network PSK");
    }
    pipeline
        .timing_tracker
        .attach_deltas(&mut wifi_frame, config.clock_skew_anomaly_us);
    let resolved_identity = pipeline.identity_cache.resolve(&wifi_frame);
    let enriched: EnrichedFrame = attach_context(wifi_frame, context);
    let mut entry = to_audit_entry(enriched);
    let frame_id = pipeline.allocate_frame_id();
    let detector_lane = pipeline
        .detector_router
        .lane_for(detector_route_key(&entry));
    trace!(
        frame_id,
        detector_lane,
        detector_lanes = pipeline.detector_router.lanes(),
        detector_queue_capacity = pipeline.detector_router.queue_capacity(),
        "decoded frame assigned to detector route"
    );
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
    let authorization_status = pipeline.authorized_network_cache.authorization_status(
        entry.ssid.as_deref(),
        entry
            .bssid
            .as_deref()
            .or(entry.destination_bssid.as_deref()),
        &entry.location_id,
    );
    let is_authorized_network = pipeline.authorized_network_cache.is_authorized(
        entry.ssid.as_deref(),
        entry
            .bssid
            .as_deref()
            .or(entry.destination_bssid.as_deref()),
        &entry.location_id,
    );
    let external_bssid =
        authorization_status == AuthorizationStatus::Unauthorized && !is_authorized_network;
    if entry.ssid.is_some() && authorization_status == AuthorizationStatus::Unauthorized {
        entry.tags.push("threat:unauthorized_bssid".to_string());
    } else if entry.ssid.is_some() && authorization_status == AuthorizationStatus::Unknown {
        entry
            .tags
            .push("enrichment:authorized_network_unknown".to_string());
    }
    pipeline
        .ie_layout_tracker
        .observe(&mut entry, authorization_status);
    pipeline.mac_sequence_delta_tracker.observe(&mut entry);
    pipeline.client_inventory.observe(&mut entry);
    if let Some(alert) = pipeline.sequence_tracker.observe(&entry) {
        if let Err(error) = publish_oracle_json_durable(
            publish_state,
            backlog,
            publish_client,
            "publish_sequence_alert",
            SEQUENCE_ALERT_TOPIC,
            &alert,
            &alert.observed_at,
        )
        .await
        {
            warn!(%error, "sequence alert publish failed");
        }
    }

    if entry.frame_subtype == "probe_request" {
        pipeline.probe_accumulator.observe(
            &entry,
            &pipeline.client_inventory,
            &pipeline.authorized_network_cache,
        );
        stats.lock().unwrap().probe_accumulator_len = pipeline.probe_accumulator.len();
    }

    if pipeline.probe_accumulator.should_flush_early() {
        for batch in pipeline.probe_accumulator.take_ready_batches() {
            match flush_probe_batch(backlog, batch).await {
                Ok(probe_count) => debug!(probe_count, "probe batch flushed"),
                Err((batch, error)) => {
                    warn!(
                        %error,
                        probe_count = batch.len(),
                        "probe batch early flush failed; retaining priority half to prevent unbounded growth"
                    );
                    pipeline.probe_accumulator.restore_priority_half(batch);
                }
            }
            stats.lock().unwrap().probe_accumulator_len = pipeline.probe_accumulator.len();
        }
    }
    if entry
        .tags
        .iter()
        .any(|tag| tag == "threat:karma_probe_response")
    {
        if let Some(alert) = pipeline
            .attack_timeline_correlator
            .observe(&entry, "karma_probe_response")
        {
            if let Err(error) = publish_oracle_json_durable(
                publish_state,
                backlog,
                publish_client,
                "publish_attack_sequence_alert",
                ATTACK_SEQUENCE_TOPIC,
                &alert,
                &alert.observed_at,
            )
            .await
            {
                warn!(%error, "attack sequence alert publish failed");
            }
        }
    }
    if let Some(alert) = pipeline
        .signal_tracker
        .observe(&entry, config.signal_anomaly_dbm_delta)
    {
        entry.tags.push("threat:signal_anomaly".to_string());
        entry.anomaly_reasons.push("signal_anomaly".to_string());
        if let Err(error) = publish_oracle_json_durable(
            publish_state,
            backlog,
            publish_client,
            "publish_signal_anomaly_alert",
            SIGNAL_ANOMALY_TOPIC,
            &alert,
            &alert.observed_at,
        )
        .await
        {
            warn!(%error, "signal anomaly alert publish failed");
        }
    }
    if let Some(alert) = pipeline
        .rogue_ap_tracker
        .observe(&entry, &pipeline.authorized_network_cache)
    {
        if alert
            .reasons
            .iter()
            .any(|reason| reason == "bssid_spoofing")
        {
            if let Some(sequence_alert) = pipeline
                .attack_timeline_correlator
                .observe(&entry, "bssid_spoofing")
            {
                if let Err(error) = publish_oracle_json_durable(
                    publish_state,
                    backlog,
                    publish_client,
                    "publish_attack_sequence_alert",
                    ATTACK_SEQUENCE_TOPIC,
                    &sequence_alert,
                    &sequence_alert.observed_at,
                )
                .await
                {
                    warn!(%error, "attack sequence alert publish failed");
                }
            }
        }
        if let Err(error) = publish_oracle_json_durable(
            publish_state,
            backlog,
            publish_client,
            "publish_rogue_ap_alert",
            ROGUE_AP_TOPIC,
            &alert,
            &alert.observed_at,
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
        if let Err(error) = publish_oracle_json_durable(
            publish_state,
            backlog,
            publish_client,
            "publish_deauth_flood_alert",
            DEAUTH_FLOOD_TOPIC,
            &alert,
            &alert.observed_at,
        )
        .await
        {
            warn!(%error, "deauth flood alert publish failed");
        }
    }
    let mut pmf_tags = Vec::new();
    pipeline.pmf_attack_tracker.observe(&entry, &mut pmf_tags);
    for tag in &pmf_tags {
        if let Some(alert) =
            pmf_attack_alert_from_entry(&entry, tag, pipeline.pmf_reconnect_window_ms)
        {
            if let Err(error) = publish_oracle_json_durable(
                publish_state,
                backlog,
                publish_client,
                "publish_pmf_attack_alert",
                PMF_ATTACK_TOPIC,
                &alert,
                &alert.observed_at,
            )
            .await
            {
                warn!(%error, "PMF attack alert publish failed");
            }
        }
    }
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
    let skip_mac_lookup =
        backlog_pct > 80 || !config.mac_device_lookup_enabled || !inline_request_reply_enabled;
    if skip_mac_lookup {
        if entry.identity_source == "unknown" || entry.identity_source == "mac_observed" {
            entry.identity_source =
                if !config.mac_device_lookup_enabled || !inline_request_reply_enabled {
                    "mac_lookup_disabled".to_string()
                } else {
                    "mac_lookup_skipped_backpressure".to_string()
                };
        }
    } else if let Some(mac) = entry.source_mac.clone().or_else(|| entry.bssid.clone()) {
        let cache_key = mac.to_ascii_lowercase();
        let lookup = match pipeline.device_registry_cache.lookup_decision(
            &cache_key,
            Duration::from_secs(config.mac_lookup_error_ttl_secs),
        ) {
            DeviceRegistryCacheDecision::UseCached(lookup) => lookup,
            DeviceRegistryCacheDecision::SkipRecentFailure => None,
            DeviceRegistryCacheDecision::Fetch => {
                match backlog.lookup_device_by_mac(&cache_key).await {
                    Ok(lookup) => {
                        pipeline
                            .device_registry_cache
                            .remember_success(cache_key.clone(), lookup.clone());
                        lookup
                    }
                    Err(error) => {
                        stats.lock().unwrap().mac_lookup_failures += 1;
                        pipeline
                            .device_registry_cache
                            .remember_failure(cache_key.clone());
                        warn!(%error, mac = %cache_key, "MAC device lookup failed; publishing unenriched audit entry");
                        None
                    }
                }
            }
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
    // First, let the traffic bucket observe the current frame so it can
    // compute risk scores and detect low-CV burst traffic. Then obtain
    // burst MACs from the *previous* drain window for tagging.
    let bandwidth_events = match pipeline.traffic_bucket.observe(&entry, external_bssid) {
        Ok(events) => events,
        Err(error) => {
            error!(
                %error,
                frame_subtype = %entry.frame_subtype,
                observed_at = %entry.observed_at,
                sensor_id = %entry.sensor_id,
                "bandwidth bucket rejected frame -- timestamp unparseable; frame not counted"
            );
            Vec::new()
        }
    };
    let burst_macs = pipeline.traffic_bucket.take_burst_macs();
    // Tag the current frame if its source MAC had a low CV in the drained window.
    if let Some(ref src_mac) = entry.source_mac {
        let normalized = src_mac.trim().to_ascii_lowercase();
        if burst_macs.contains(&normalized)
            && !entry.tags.contains(&"threat:burst_automated".to_string())
        {
            entry.tags.push("threat:burst_automated".to_string());
        }
    }
    publish_bandwidth_events(publish_state, backlog, publish_client, bandwidth_events).await;
    info!(
        target: "wireless_audit",
        event_type = %entry.event_type,
        frame_subtype = %entry.frame_subtype,
        bssid = ?entry.bssid,
        ssid = ?entry.ssid,
        "captured wifi frame"
    );
    entry.risk_score = crate::parse::recompute_risk_score(&entry.tags);
    match publish_entry(publish_state, backlog, publish_client, entry).await {
        Ok(()) | Err(PublishError::Queued(_)) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(PipelineOutcome::DecodedFrame)
}

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
    {
        let mut stats = handles.stats.lock().unwrap();
        stats.bandwidth_window_lag_ms = median_lag;
        stats.memory_backlog_len = handles.publish_state.lock().unwrap().memory_backlog_len();
        stats.probe_accumulator_len = pipeline_state.probe_accumulator.len();
    }
    publish_bandwidth_events(
        &handles.publish_state,
        &*handles.backlog,
        &*handles.publish_client,
        events,
    )
    .await;
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
    let stats_snapshot = {
        let mut stats = handles.stats.lock().unwrap();
        stats.memory_backlog_len = backlog_len;
        stats.log(&handles.device, &handles.config);
        stats.clone()
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_channel_application_uses_configured_device_and_channel() {
        let mut called = None;

        apply_configured_channel("wlan0", 11, |device, channel| {
            called = Some((device.to_string(), channel));
            Ok::<(), ()>(())
        })
        .unwrap();

        assert_eq!(called, Some(("wlan0".to_string(), 11)));
    }
}
