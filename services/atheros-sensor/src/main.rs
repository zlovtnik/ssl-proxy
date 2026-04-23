mod audit;
mod backlog;
mod capture;
mod config;
mod config_subscriber;
mod device;
mod error;
mod model;
mod parse;
mod publish;
mod stats;
#[cfg(test)]
mod testutil;

use std::{
    fmt::Display,
    future,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::Duration,
};

use lru::LruCache;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tracing::{debug, error, info, info_span, warn, Instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    audit::{
        AuditLayer, AuditWindow, SharedAuditWindow, TrafficBucket, WirelessBandwidthEvent,
        DEFAULT_BANDWIDTH_WINDOW_SECS, EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
    },
    backlog::{BacklogStore, PostgresBacklog},
    capture::{stream_packets, CaptureError},
    config::AppConfig,
    device::{detect, read_mac_address},
    error::SensorError,
    model::{AuditContext, EnrichedFrame, RawPacket},
    parse::{attach_context, decode_frame, to_audit_entry, HandshakeMonitor, IdentityCache},
    publish::{
        publish_bandwidth_event, publish_entry, publish_handshake_alert, reconcile_backlog,
        PublishClient, PublishError, PublishState, SharedPublishState, SyncPublisherClient,
    },
    stats::{CaptureStats, PipelineOutcome},
};

const DEFAULT_RUST_LOG: &str = "warn,atheros_sensor=info,ssl_proxy=info";
const HANDSHAKE_MONITOR_TTL: Duration = Duration::from_secs(10 * 60);

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

async fn run_sensor() -> Result<(), SensorError> {
    let config = step("load configuration", AppConfig::from_env())?;
    let mut handles = init_sensor(&config).await?;
    let mut heartbeat = capture_heartbeat(handles.config.log_idle_secs);
    let mut stats = CaptureStats::default();
    let mut pipeline_state = PipelineState::new(&handles.config);
    let mut bandwidth_flush = bandwidth_flush_interval();

    loop {
        tokio::select! {
            packet = handles.packets.next() => {
                let Some(packet) = packet else {
                    break;
                };

                let packet = match packet {
                    Ok(packet) => {
                        stats.packets_seen += 1;
                        packet
                    }
                    Err(error) => {
                        stats.capture_errors += 1;
                        error!(%error, interface = %handles.device, "packet capture failed");
                        continue;
                    }
                };

                if !audit_window_snapshot(&handles.audit_window).is_active_at(packet.observed_at) {
                    stats.audit_window_drops += 1;
                    debug!("audit window inactive; dropping packet");
                    continue;
                }

                let span = info_span!(
                    "wireless_capture",
                    sensor_id = %handles.context.sensor_id,
                    location_id = %handles.context.location_id,
                    interface = %handles.context.interface
                );

                let result = process_packet(
                    packet,
                    &handles.context,
                    &handles.config,
                    &handles.backlog,
                    &*handles.publish_client,
                    &handles.publish_state,
                    &mut pipeline_state,
                )
                .instrument(span)
                .await;

                match result {
                    Ok(PipelineOutcome::DecodedFrame) => stats.decoded_frames += 1,
                    Ok(PipelineOutcome::UnsupportedFrame) => stats.unsupported_frames += 1,
                    Err(error) => {
                        stats.pipeline_errors += 1;
                        error!(%error, "wireless packet pipeline failed");
                    }
                }
            }
            _ = tick_capture_heartbeat(&mut heartbeat) => {
                stats.log(&handles.device, &handles.config);
            }
            _ = bandwidth_flush.tick() => {
                pipeline_state
                    .handshake_monitor
                    .cleanup_expired(HANDSHAKE_MONITOR_TTL);
                let bandwidth_events = pipeline_state.traffic_bucket.flush_current();
                publish_bandwidth_events(&handles.backlog, &*handles.publish_client, bandwidth_events).await;
            }
        }
    }

    Ok(())
}

struct SensorHandles {
    config: AppConfig,
    audit_window: SharedAuditWindow,
    device: String,
    context: AuditContext,
    packets: ReceiverStream<Result<RawPacket, CaptureError>>,
    backlog: Arc<PostgresBacklog>,
    publish_client: Arc<SyncPublisherClient>,
    publish_state: SharedPublishState,
}

struct PipelineState {
    identity_cache: IdentityCache,
    handshake_monitor: HandshakeMonitor,
    traffic_bucket: TrafficBucket,
    mac_device_cache: LruCache<String, Option<(String, Option<String>)>>,
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
        }
    }
}

async fn init_sensor(config: &AppConfig) -> Result<SensorHandles, SensorError> {
    let audit_window: SharedAuditWindow = Arc::new(RwLock::new(config.audit_window.clone()));

    let log_filter = init_tracing(Arc::clone(&audit_window));
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

    let context = AuditContext {
        sensor_id,
        location_id: config.location_id.clone(),
        interface: device.clone(),
        channel: config.channel,
        reg_domain: config.reg_domain.clone(),
    };

    let packets = step(
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

    Ok(SensorHandles {
        config: config.clone(),
        audit_window,
        device,
        context,
        packets,
        backlog,
        publish_client,
        publish_state,
    })
}

async fn process_packet(
    packet: RawPacket,
    context: &AuditContext,
    config: &AppConfig,
    backlog: &PostgresBacklog,
    publish_client: &dyn PublishClient,
    publish_state: &SharedPublishState,
    pipeline: &mut PipelineState,
) -> Result<PipelineOutcome, SensorError> {
    let mut wifi_frame = match decode_frame(&packet) {
        Ok(frame) => frame,
        Err(error) => {
            debug!(%error, "ignoring unsupported frame");
            return Ok(PipelineOutcome::UnsupportedFrame);
        }
    };

    let handshake_alert = pipeline.handshake_monitor.observe(&mut wifi_frame, context);
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
    if config.mac_device_lookup_enabled {
        if let Some(mac) = entry.source_mac.clone().or_else(|| entry.bssid.clone()) {
            let cache_key = mac.to_ascii_lowercase();
            let lookup = if let Some(cached) = pipeline.mac_device_cache.get(&cache_key) {
                cached.clone()
            } else {
                let lookup = match backlog.lookup_device_by_mac(&cache_key).await {
                    Ok(lookup) => lookup,
                    Err(error) => {
                        warn!(%error, mac = %cache_key, "MAC device lookup failed; publishing unenriched audit entry");
                        None
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
        }
    }
    let bandwidth_events = match pipeline.traffic_bucket.observe(&entry) {
        Ok(events) => events,
        Err(error) => {
            warn!(%error, "wireless bandwidth bucket update failed; continuing audit publish");
            Vec::new()
        }
    };
    publish_bandwidth_events(backlog, publish_client, bandwidth_events).await;
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
    backlog: &PostgresBacklog,
    publisher: &dyn PublishClient,
    events: Vec<WirelessBandwidthEvent>,
) {
    for mut event in events {
        let authorized = match backlog
            .is_authorized_wireless_network(
                event.ssid.as_deref(),
                Some(event.destination_bssid.as_str()),
                &event.location_id,
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => {
                warn!(
                    %error,
                    destination_bssid = %event.destination_bssid,
                    ssid = ?event.ssid,
                    "authorized wireless network lookup failed; treating BSSID as external"
                );
                false
            }
        };
        event.external_bssid = !authorized;
        event.threshold_exceeded =
            event.external_bssid && event.bytes > EXTERNAL_BANDWIDTH_THRESHOLD_BYTES;
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

fn audit_window_snapshot(audit_window: &SharedAuditWindow) -> AuditWindow {
    audit_window
        .read()
        .map(|window| window.clone())
        .unwrap_or_else(|_| AuditWindow::from_parts(None, None, None, None))
}

fn init_tracing(audit_window: SharedAuditWindow) -> String {
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
        .with(AuditLayer::new(audit_window))
        .init();

    filter_source
}

fn capture_heartbeat(idle_secs: u64) -> Option<tokio::time::Interval> {
    if idle_secs == 0 {
        return None;
    }

    let interval = Duration::from_secs(idle_secs);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Some(interval)
}

async fn tick_capture_heartbeat(interval: &mut Option<tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => future::pending::<()>().await,
    }
}

fn configured_device_suffix(device: Option<&str>) -> String {
    device
        .map(|device| format!(" configured by ATH_SENSOR_DEVICE={device}"))
        .unwrap_or_default()
}

fn step<T, E>(label: impl Display, result: Result<T, E>) -> Result<T, SensorError>
where
    E: Display,
{
    result.map_err(|error| SensorError::step(label, error))
}

async fn step_async<T, E, F>(label: impl Display, future: F) -> Result<T, SensorError>
where
    E: Display,
    F: std::future::Future<Output = Result<T, E>>,
{
    future
        .await
        .map_err(|error| SensorError::step(label, error))
}
