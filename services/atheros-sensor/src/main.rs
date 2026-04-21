mod audit;
mod backlog;
mod capture;
mod config;
mod device;
mod model;
mod parse;
mod publish;

use std::{error::Error, fmt::Display, sync::Arc, time::Duration};

use tokio_stream::StreamExt;
use tracing::{debug, error, info, info_span, Instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    audit::AuditLayer,
    backlog::{BacklogStore, PostgresBacklog},
    capture::stream_packets,
    config::AppConfig,
    device::{detect, read_mac_address},
    model::{AuditContext, EnrichedFrame},
    parse::{attach_context, decode_frame, to_audit_entry},
    publish::{publish_entry, reconcile_backlog, SyncPublisherClient},
};

async fn run_healthcheck() -> Result<(), Box<dyn std::error::Error>> {
    // Verify config loads correctly
    let config = step("load configuration", AppConfig::from_env())?;

    // Verify device can be detected
    let device = step(
        format!(
            "detect ath9k_htc interface{}",
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

async fn run_sensor() -> Result<(), Box<dyn std::error::Error>> {
    let config = step("load configuration", AppConfig::from_env())?;
    let audit_window = config.audit_window.clone();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().json())
        .with(AuditLayer::new(audit_window.clone()))
        .init();

    let device = step(
        format!(
            "detect ath9k_htc interface{}",
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
        location_id = %config.location_id,
        interface = %device,
        channel = config.channel,
        reg_domain = %config.reg_domain,
        bpf = %config.bpf,
        snaplen = config.snaplen,
        pcap_timeout_ms = config.pcap_timeout_ms,
        nats_configured = config.sync.nats_url.is_some(),
        nats_tls_enabled = config.sync.tls_enabled,
        audit_window = ?audit_window,
        "atheros sensor starting"
    );
    let publisher = Arc::new(ssl_proxy::transport::SyncPublisher::new(&config.sync));
    let backlog = Arc::new(
        step_async("connect to Postgres backlog", async {
            PostgresBacklog::connect(&config.database_url).await
        })
        .await?,
    );
    let publish_client = Arc::new(SyncPublisherClient::new(Arc::clone(&publisher)));

    let reconcile_window = audit_window.clone();
    let reconcile_backlog_store = Arc::clone(&backlog);
    let reconcile_client = Arc::clone(&publish_client);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        info!("backlog reconciliation task started");
        loop {
            interval.tick().await;
            if let Err(error) = reconcile_backlog(
                &*reconcile_backlog_store,
                &*reconcile_client,
                &reconcile_window,
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

    let mut packets = step(
        format!("open pcap capture on interface {device}"),
        stream_packets(&device, config.snaplen, config.pcap_timeout_ms, &config.bpf),
    )?;

    while let Some(packet) = packets.next().await {
        let packet = match packet {
            Ok(packet) => packet,
            Err(error) => {
                error!(%error, interface = %device, "packet capture failed");
                continue;
            }
        };

        if !config.audit_window.is_active_at(packet.observed_at) {
            debug!("audit window inactive; dropping packet");
            continue;
        }

        let span = info_span!(
            "wireless_capture",
            sensor_id = %context.sensor_id,
            location_id = %context.location_id,
            interface = %context.interface
        );

        let result = async {
            let wifi_frame = match decode_frame(&packet) {
                Ok(frame) => frame,
                Err(error) => {
                    debug!(%error, "ignoring unsupported frame");
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
            };

            let enriched: EnrichedFrame = attach_context(wifi_frame, &context);
            let entry = to_audit_entry(enriched);
            info!(
                target: "wireless_audit",
                frame_subtype = %entry.frame_subtype,
                bssid = ?entry.bssid,
                ssid = ?entry.ssid,
                "captured wifi management frame"
            );
            publish_entry(&*backlog, &*publish_client, entry).await?;
            Ok(())
        }
        .instrument(span)
        .await;

        if let Err(error) = result {
            error!(%error, "wireless packet pipeline failed");
        }
    }

    Ok(())
}

fn configured_device_suffix(device: Option<&str>) -> String {
    device
        .map(|device| format!(" configured by ATH_SENSOR_DEVICE={device}"))
        .unwrap_or_default()
}

fn step<T, E>(label: impl Display, result: Result<T, E>) -> Result<T, Box<dyn Error>>
where
    E: Display,
{
    result.map_err(|error| boxed_error(format!("{label}: {error}")))
}

async fn step_async<T, E, F>(label: impl Display, future: F) -> Result<T, Box<dyn Error>>
where
    E: Display,
    F: std::future::Future<Output = Result<T, E>>,
{
    future
        .await
        .map_err(|error| boxed_error(format!("{label}: {error}")))
}

fn boxed_error(message: String) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message))
}
