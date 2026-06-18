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
    model::{AuditContext, EnrichedFrame, IdentitySource, RawPacket},
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
const DEFAULT_RUST_LOG: &str = "warn,atheros_sensor=info";
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
    let publisher = Arc::new(sync_plane::SyncPublisher::new(&config.sync));
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
                handles.stats.log(&handles.device, &handles.config);
                break;
            }
            packet = handles.packets.next() => {
                let Some(packet) = packet else {
                    info!("packet stream closed; flushing sensor state");
                    shutdown_flush(&handles, &mut pipeline_state).await;
                    handles.stats.log(&handles.device, &handles.config);
                    break;
                };

                let packet = match packet {
                    Ok(packet) => {
                        handles.stats.increment_packets_seen();
                        packet
                    }
                    Err(error) => {
                        handles.stats.increment_capture_errors();
                        error!(%error, interface = %handles.device, "packet capture failed");
                        continue;
                    }
                };

                if !audit_window_snapshot(&handles.audit_window).is_active_at(packet.observed_at) {
                    handles.stats.increment_audit_window_drops();
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
                        let lag_ms = (Utc::now() - observed_at)
                            .num_milliseconds()
                            .max(0) as u64;
                        handles.stats.increment_decoded_frames();
                        handles.stats.observe_publish_lag_ms(lag_ms);
                    }
                    Ok(PipelineOutcome::UnsupportedFrame) => {}
                    Err(error) => {
                        handles.stats.increment_pipeline_errors();
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
                    bandwidth_events,
                )
                .await;
            }
            _ = inventory_flush.tick() => {
                // Flush client inventory snapshot
                let snapshot = pipeline_state.client_inventory.snapshot();
                let stats = handles.stats.snapshot();
                let observed_at = snapshot.observed_at.clone();
                let context = context_snapshot(&handles.context);
                let bpf = filter_snapshot(&handles.current_filter, &handles.config.bpf);
                let inventory_payload = serde_json::json!({
                    "schema_version": snapshot.schema_version,
                    "event_type": snapshot.event_type,
                    "observed_at": observed_at.clone(),
                    "sensor_id": context.sensor_id,
                    "location_id": context.location_id,
                    "interface": context.interface,
                    "channel": context.channel,
                    "bpf": bpf,
                    "capture_stats": {
                        "packets_seen": stats.packets_seen,
                        "decoded_frames": stats.decoded_frames,
                        "unsupported_frames": stats.unsupported_frames,
                        "malformed_frames": stats.malformed_frames,
                        "audit_window_drops": stats.audit_window_drops,
                        "capture_errors": stats.capture_errors,
                        "pipeline_errors": stats.pipeline_errors,
                        "mac_lookup_failures": stats.mac_lookup_failures,
                        "channel_hop_count": stats.channel_hop_count,
                        "memory_backlog_len": stats.memory_backlog_len,
                        "probe_accumulator_len": stats.probe_accumulator_len,
                    },
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

                flush_probe_accumulator(&handles.backlog, &mut pipeline_state, &handles.stats).await;
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
