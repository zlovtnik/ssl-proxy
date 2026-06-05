//! Redpanda-backed wireless backlog and lookup store.

use std::{
    io::Cursor,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ssl_proxy::{
    config::SyncConfig,
    sync::{ScanRequest, SYNC_SCAN_REQUEST_TOPIC},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::debug;

use super::store::{
    AuthorizedWirelessNetwork, BacklogEntry, BacklogError, BacklogStore, IngestRecord,
};
use crate::publish::PublishClient;

const BACKLOG_SAVE_TOPIC: &str = "wireless.backlog.save";
const BACKLOG_LIST_TOPIC: &str = "wireless.backlog.list";
const BACKLOG_SYNCED_TOPIC: &str = "wireless.backlog.synced";
const BACKLOG_PRUNE_TOPIC: &str = "wireless.backlog.prune";
const MAC_LOOKUP_TOPIC: &str = "wireless.mac.lookup";
const AUTHORIZED_NETWORKS_TOPIC: &str = "wireless.networks.authorized";
const PROBE_FLUSH_TOPIC: &str = "wireless.probe.flush";
static NEXT_INBOX_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct RedpandaBacklog {
    publisher: Arc<dyn PublishClient>,
    sync: SyncConfig,
    request_timeout: Duration,
    request_connection_ttl: Duration,
    tls_connector: Option<TlsConnector>,
    request_connection: Arc<Mutex<Option<CachedRequestConnection>>>,
    health_status: Arc<AtomicBool>,
    connection_generation: Arc<AtomicU64>,
}

struct CachedRequestConnection {
    reader: BufReader<Box<dyn RedpandaStream>>,
    last_used: Instant,
    next_sid: u64,
}

impl RedpandaBacklog {
    pub fn new(
        publisher: Arc<dyn PublishClient>,
        sync: SyncConfig,
        request_timeout: Duration,
    ) -> Result<Self, BacklogError> {
        let tls_client_config =
            build_tls_client_config(&sync).map_err(|message| BacklogError::Redpanda {
                operation: "initialize_redpanda_backlog",
                message,
            })?;
        let tls_connector = tls_client_config
            .as_ref()
            .map(|config| TlsConnector::from(Arc::clone(config)));
        Ok(Self {
            publisher,
            sync,
            request_timeout,
            request_connection_ttl: Duration::from_secs(10),
            tls_connector,
            request_connection: Arc::new(Mutex::new(None)),
            health_status: Arc::new(AtomicBool::new(true)),
            connection_generation: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn spawn_health_check(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                self.health_probe().await;
            }
        });
    }

    pub fn is_healthy(&self) -> bool {
        self.health_status.load(Ordering::Relaxed)
    }

    pub fn supports_inline_request_reply(&self) -> bool {
        self.sync
            .redpanda_bootstrap_servers
            .as_deref()
            .is_some_and(inline_request_reply_transport_supported)
    }

    pub fn inline_request_reply_disabled_reason(&self) -> Option<String> {
        let redpanda_bootstrap_servers = self.sync.redpanda_bootstrap_servers.as_deref()?;
        request_transport_unsupported("inline_request_reply", redpanda_bootstrap_servers)
            .map(|error| error.to_string())
    }

    async fn health_probe(&self) {
        let result = self.ping_redpanda().await;
        let healthy = result.is_ok();
        self.health_status.store(healthy, Ordering::Relaxed);
        if healthy {
            self.connection_generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn connect_request_connection(
        &self,
        operation: &'static str,
    ) -> Result<CachedRequestConnection, BacklogError> {
        let redpanda_bootstrap_servers = self
            .sync
            .redpanda_bootstrap_servers
            .as_deref()
            .ok_or_else(|| BacklogError::Disabled { operation })?;
        let endpoint = parse_redpanda_endpoint(redpanda_bootstrap_servers).map_err(|source| {
            BacklogError::Redpanda {
                operation,
                message: source,
            }
        })?;
        let tcp_stream = timeout(self.request_timeout, TcpStream::connect(&endpoint.address))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("connect {}: {source}", endpoint.address),
            })?;
        let mut stream: Box<dyn RedpandaStream> = if redpanda_tls_enabled(&self.sync, &endpoint) {
            let connector = self
                .tls_connector
                .as_ref()
                .ok_or_else(|| BacklogError::Redpanda {
                    operation,
                    message: "Redpanda TLS connector was not initialized".to_string(),
                })?;
            let tls_stream = connect_tls(connector, endpoint.host.as_str(), tcp_stream)
                .await
                .map_err(|message| BacklogError::Redpanda { operation, message })?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };
        let mut reader = BufReader::new(&mut *stream);
        let mut info_line = String::new();
        timeout(self.request_timeout, reader.read_line(&mut info_line))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("read INFO: {source}"),
            })?;
        if !info_line.starts_with("INFO ") {
            return Err(BacklogError::Redpanda {
                operation,
                message: format!(
                    "expected Redpanda INFO banner, got: {}",
                    info_line.trim_end()
                ),
            });
        }

        let connect_options = serde_json::json!({
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "verbose": false,
            "pedantic": false,
            "user": self.sync.sasl_username.as_deref(),
            "pass": self.sync.sasl_password.as_deref(),
        });
        let command = format!("CONNECT {connect_options}\r\n");
        timeout(self.request_timeout, stream.write_all(command.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("send CONNECT: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("flush CONNECT: {source}"),
            })?;
        Ok(CachedRequestConnection {
            reader: BufReader::new(stream),
            last_used: Instant::now(),
            next_sid: 1,
        })
    }

    async fn request_with_cached_connection(
        &self,
        operation: &'static str,
        topic: &'static str,
        payload: &str,
        reply_topic: &str,
    ) -> Result<String, BacklogError> {
        let maybe_connection = self.request_connection.lock().unwrap().take();

        let mut connection = if let Some(conn) = maybe_connection {
            if conn.last_used.elapsed() < self.request_connection_ttl {
                conn
            } else {
                self.connection_generation.fetch_add(1, Ordering::Relaxed);
                match self.connect_request_connection(operation).await {
                    Ok(conn) => conn,
                    Err(err) => {
                        self.health_status.store(false, Ordering::Relaxed);
                        return Err(err);
                    }
                }
            }
        } else {
            match self.connect_request_connection(operation).await {
                Ok(conn) => conn,
                Err(err) => {
                    self.health_status.store(false, Ordering::Relaxed);
                    return Err(err);
                }
            }
        };

        let result = self
            .perform_request_over_connection(
                &mut connection,
                operation,
                topic,
                payload,
                reply_topic,
            )
            .await;
        let mut guard = self.request_connection.lock().unwrap();
        match result {
            Ok(response) => {
                connection.last_used = Instant::now();
                guard.replace(connection);
                self.health_status.store(true, Ordering::Relaxed);
                Ok(response)
            }
            Err(err) => {
                if request_error_marks_redpanda_unhealthy(&err) {
                    self.health_status.store(false, Ordering::Relaxed);
                }
                guard.take();
                Err(err)
            }
        }
    }

    async fn perform_request_over_connection(
        &self,
        connection: &mut CachedRequestConnection,
        operation: &'static str,
        topic: &'static str,
        payload: &str,
        reply_topic: &str,
    ) -> Result<String, BacklogError> {
        let stream = &mut connection.reader;
        let sid = connection.next_sid;
        connection.next_sid = connection.next_sid.saturating_add(1);
        let subscribe = format!("SUB {reply_topic} {sid}\r\n");
        timeout(self.request_timeout, stream.write_all(subscribe.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("subscribe reply topic: {source}"),
            })?;

        let publish_command = format!("PUB {topic} {}\r\n", payload.len());
        timeout(
            self.request_timeout,
            stream.write_all(publish_command.as_bytes()),
        )
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Redpanda {
            operation,
            message: format!("send PUB header: {source}"),
        })?;
        timeout(self.request_timeout, stream.write_all(payload.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("send PUB payload: {source}"),
            })?;
        timeout(self.request_timeout, stream.write_all(b"\r\n"))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("finish PUB payload: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("flush request: {source}"),
            })?;

        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = timeout(self.request_timeout, stream.read_line(&mut line))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("read reply: {source}"),
                })?;
            let trimmed = line.trim_end();
            if bytes_read == 0 || trimmed.is_empty() {
                return Err(BacklogError::Redpanda {
                    operation,
                    message: "unexpected EOF while reading reply".to_string(),
                });
            }
            if trimmed == "PING" {
                timeout(
                    self.request_timeout,
                    stream.get_mut().write_all(b"PONG\r\n"),
                )
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("send PONG: {source}"),
                })?;
                timeout(self.request_timeout, stream.get_mut().flush())
                    .await
                    .map_err(|_| BacklogError::Timeout { operation })?
                    .map_err(|source| BacklogError::Redpanda {
                        operation,
                        message: format!("flush PONG: {source}"),
                    })?;
                continue;
            }
            if trimmed.starts_with("+OK") || trimmed.starts_with("INFO ") {
                continue;
            }
            if trimmed.starts_with("-ERR") {
                let unsub_command = format!("UNSUB {sid} 1\r\n");
                let _ = timeout(
                    self.request_timeout,
                    stream.write_all(unsub_command.as_bytes()),
                )
                .await;
                let _ = timeout(self.request_timeout, stream.flush()).await;
                return Err(BacklogError::Redpanda {
                    operation,
                    message: trimmed.to_string(),
                });
            }
            if !trimmed.starts_with("MSG ") {
                continue;
            }
            let parts: Vec<_> = trimmed.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let msg_topic = parts[1];
            if msg_topic != reply_topic {
                continue;
            }
            let size = parts
                .last()
                .ok_or_else(|| BacklogError::Redpanda {
                    operation,
                    message: format!("missing reply size: {trimmed}"),
                })?
                .parse::<usize>()
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("invalid reply size: {source}"),
                })?;
            let mut payload_buf = vec![0_u8; size];
            timeout(self.request_timeout, stream.read_exact(&mut payload_buf))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("read reply payload: {source}"),
                })?;
            let mut terminator = [0_u8; 2];
            timeout(self.request_timeout, stream.read_exact(&mut terminator))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("read reply terminator: {source}"),
                })?;
            if terminator != *b"\r\n" {
                return Err(BacklogError::Redpanda {
                    operation,
                    message: "invalid reply terminator".to_string(),
                });
            }
            let result = String::from_utf8(payload_buf).map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("reply is not UTF-8: {source}"),
            });
            let unsub_command = format!("UNSUB {sid} 1\r\n");
            timeout(
                self.request_timeout,
                stream.write_all(unsub_command.as_bytes()),
            )
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("send UNSUB: {source}"),
            })?;
            timeout(self.request_timeout, stream.flush())
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("flush UNSUB: {source}"),
                })?;
            return result;
        }
    }

    async fn ping_redpanda(&self) -> Result<(), BacklogError> {
        let redpanda_bootstrap_servers = self
            .sync
            .redpanda_bootstrap_servers
            .as_deref()
            .ok_or_else(|| BacklogError::Disabled {
                operation: "redpanda_health_check",
            })?;
        if let Some(error) =
            request_transport_unsupported("redpanda_health_check", redpanda_bootstrap_servers)
        {
            return Err(error);
        }
        let endpoint = parse_redpanda_endpoint(redpanda_bootstrap_servers).map_err(|source| {
            BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: source,
            }
        })?;
        let tcp_stream = timeout(self.request_timeout, TcpStream::connect(&endpoint.address))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "redpanda_health_check",
            })?
            .map_err(|source| BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("connect {}: {source}", endpoint.address),
            })?;
        let mut stream: Box<dyn RedpandaStream> = if redpanda_tls_enabled(&self.sync, &endpoint) {
            let connector = self
                .tls_connector
                .as_ref()
                .ok_or_else(|| BacklogError::Redpanda {
                    operation: "redpanda_health_check",
                    message: "Redpanda TLS connector was not initialized".to_string(),
                })?;
            let tls_stream = connect_tls(connector, endpoint.host.as_str(), tcp_stream)
                .await
                .map_err(|message| BacklogError::Redpanda {
                    operation: "redpanda_health_check",
                    message,
                })?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };
        let mut info_line = String::new();
        {
            let mut reader = BufReader::new(&mut *stream);
            timeout(self.request_timeout, reader.read_line(&mut info_line))
                .await
                .map_err(|_| BacklogError::Timeout {
                    operation: "redpanda_health_check",
                })?
                .map_err(|source| BacklogError::Redpanda {
                    operation: "redpanda_health_check",
                    message: format!("read INFO: {source}"),
                })?;
        }
        if !info_line.starts_with("INFO ") {
            return Err(BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!(
                    "expected Redpanda INFO banner, got: {}",
                    info_line.trim_end()
                ),
            });
        }
        let connect_options = serde_json::json!({
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "verbose": false,
            "pedantic": false,
            "user": self.sync.sasl_username.as_deref(),
            "pass": self.sync.sasl_password.as_deref(),
        });
        let command = format!("CONNECT {connect_options}\r\nPING\r\n");
        timeout(self.request_timeout, stream.write_all(command.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "redpanda_health_check",
            })?
            .map_err(|source| BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("send CONNECT/PING: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "redpanda_health_check",
            })?
            .map_err(|source| BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("flush CONNECT/PING: {source}"),
            })?;
        let mut reader = BufReader::new(&mut *stream);
        let mut pong_line = String::new();
        timeout(self.request_timeout, reader.read_line(&mut pong_line))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "redpanda_health_check",
            })?
            .map_err(|source| BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("read PONG: {source}"),
            })?;
        if pong_line.trim() != "PONG" {
            return Err(BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("unexpected health check response: {}", pong_line.trim_end()),
            });
        }
        Ok(())
    }

    async fn request(
        &self,
        operation: &'static str,
        topic: &'static str,
        payload: &str,
    ) -> Result<String, BacklogError> {
        let Some(redpanda_bootstrap_servers) = self.sync.redpanda_bootstrap_servers.as_deref()
        else {
            return Err(BacklogError::Disabled { operation });
        };
        if let Some(error) = request_transport_unsupported(operation, redpanda_bootstrap_servers) {
            return Err(error);
        }
        let reply_topic = next_inbox_topic();
        let payload = payload_with_reply_topic(operation, payload, &reply_topic)?;
        let started = Instant::now();
        let result = self
            .request_with_cached_connection(operation, topic, &payload, &reply_topic)
            .await;
        crate::metrics::record_redpanda_request(result.is_ok(), started.elapsed().as_millis());
        result
    }

    pub async fn lookup_device_by_mac(
        &self,
        mac: &str,
    ) -> Result<Option<(String, Option<String>)>, BacklogError> {
        #[derive(Serialize)]
        struct Request<'a> {
            operation: &'static str,
            mac: &'a str,
        }
        #[derive(Deserialize)]
        struct Response {
            device_id: Option<String>,
            username: Option<String>,
        }

        let payload = serialize(
            "lookup_device_by_mac",
            &Request {
                operation: "lookup_device_by_mac",
                mac,
            },
        )?;
        let response = self
            .request("lookup_device_by_mac", MAC_LOOKUP_TOPIC, &payload)
            .await?;
        if response.trim() == "null" || response.trim().is_empty() {
            return Ok(None);
        }
        let parsed: Response =
            serde_json::from_str(&response).map_err(|source| BacklogError::Deserialize {
                operation: "lookup_device_by_mac",
                source,
            })?;
        Ok(parsed
            .device_id
            .map(|device_id| (device_id, parsed.username)))
    }

    pub async fn list_authorized_wireless_networks(
        &self,
    ) -> Result<Vec<AuthorizedWirelessNetwork>, BacklogError> {
        let response = self
            .request(
                "list_authorized_wireless_networks",
                AUTHORIZED_NETWORKS_TOPIC,
                r#"{"operation":"list_authorized_wireless_networks"}"#,
            )
            .await?;
        parse_authorized_networks_response(&response).map_err(|source| BacklogError::Deserialize {
            operation: "list_authorized_wireless_networks",
            source,
        })
    }

    pub async fn flush_probe_batch(
        &self,
        probes: &[ProbeFlushObservation],
    ) -> Result<(), BacklogError> {
        if probes.is_empty() {
            return Ok(());
        }
        #[derive(Serialize)]
        struct Payload<'a> {
            operation: &'static str,
            observed_at: String,
            probes: &'a [ProbeFlushObservation],
        }
        let observed_at = probes
            .iter()
            .map(|probe| probe.last_seen)
            .max()
            .map(ssl_proxy::time::rfc3339_from_utc)
            .unwrap_or_else(ssl_proxy::time::now_rfc3339);
        let payload = serialize(
            "flush_probe_batch",
            &Payload {
                operation: "flush_probe_batch",
                observed_at,
                probes,
            },
        )?;
        self.publish(PROBE_FLUSH_TOPIC, &payload).await
    }

    async fn publish(&self, topic: &'static str, payload: &str) -> Result<(), BacklogError> {
        let started = Instant::now();
        let result = self
            .publisher
            .publish_message(topic, payload)
            .await
            .map_err(|source| BacklogError::Redpanda {
                operation: topic,
                message: source,
            });
        crate::metrics::record_redpanda_publish(result.is_ok(), started.elapsed().as_millis());
        result
    }
}

fn request_error_marks_redpanda_unhealthy(error: &BacklogError) -> bool {
    !matches!(
        error,
        BacklogError::Timeout { .. }
            | BacklogError::Serialize { .. }
            | BacklogError::Deserialize { .. }
            | BacklogError::Disabled { .. }
    )
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeFlushObservation {
    pub ssid: String,
    pub client_mac: String,
    pub known_bssid: Option<String>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub probe_count: u32,
}

#[async_trait]
impl BacklogStore for RedpandaBacklog {
    async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError> {
        debug!(
            dedupe_key = record.dedupe_key,
            stream_name = record.stream_name,
            observed_at = %record.observed_at,
            payload_ref = record.payload_ref,
            "publishing wireless audit ingest over Redpanda"
        );
        let request = ScanRequest {
            stream_name: record.stream_name.to_string(),
            dedupe_key: record.dedupe_key.to_string(),
            payload_ref: record.payload_ref.to_string(),
            observed_at: ssl_proxy::time::rfc3339_from_utc(record.observed_at),
        };
        let payload = serialize("record_ingest", &request)?;
        self.publish(SYNC_SCAN_REQUEST_TOPIC, &payload).await
    }

    async fn save_pending(
        &self,
        dedupe_key: &str,
        stream_name: &str,
        payload: &str,
        error: &str,
    ) -> Result<(), BacklogError> {
        #[derive(Serialize)]
        struct Message<'a> {
            operation: &'static str,
            dedupe_key: &'a str,
            stream_name: &'a str,
            payload: &'a str,
            error: &'a str,
        }
        let payload = serialize(
            "save_pending",
            &Message {
                operation: "save_pending",
                dedupe_key,
                stream_name,
                payload,
                error,
            },
        )?;
        self.publish(BACKLOG_SAVE_TOPIC, &payload).await
    }

    async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
        let response = self
            .request(
                "list_pending",
                BACKLOG_LIST_TOPIC,
                r#"{"operation":"list_pending"}"#,
            )
            .await?;
        serde_json::from_str(&response).map_err(|source| BacklogError::Deserialize {
            operation: "list_pending",
            source,
        })
    }

    async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError> {
        #[derive(Serialize)]
        struct Message<'a> {
            operation: &'static str,
            dedupe_key: &'a str,
        }
        let payload = serialize(
            "mark_synced",
            &Message {
                operation: "mark_synced",
                dedupe_key,
            },
        )?;
        self.publish(BACKLOG_SYNCED_TOPIC, &payload).await
    }

    async fn prune_stale(
        &self,
        max_attempts: i32,
        max_age_hours: i64,
    ) -> Result<u64, BacklogError> {
        #[derive(Serialize)]
        struct Message {
            operation: &'static str,
            max_attempts: i32,
            max_age_hours: i64,
        }
        #[derive(Deserialize)]
        struct PruneResult {
            pruned: u64,
        }
        let payload = serialize(
            "prune_stale",
            &Message {
                operation: "prune_stale",
                max_attempts,
                max_age_hours,
            },
        )?;
        let response = self
            .request("prune_stale", BACKLOG_PRUNE_TOPIC, &payload)
            .await?;
        let parsed: PruneResult =
            serde_json::from_str(&response).map_err(|source| BacklogError::Deserialize {
                operation: "prune_stale",
                source,
            })?;
        Ok(parsed.pruned)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AuthorizedNetworksResponse {
    Wrapped {
        #[serde(default)]
        networks: Option<Vec<AuthorizedWirelessNetwork>>,
    },
    Legacy(Vec<AuthorizedWirelessNetwork>),
}

fn parse_authorized_networks_response(
    response: &str,
) -> Result<Vec<AuthorizedWirelessNetwork>, serde_json::Error> {
    if response.trim().is_empty() || response.trim() == "null" {
        return Ok(Vec::new());
    }

    match serde_json::from_str(response)? {
        AuthorizedNetworksResponse::Wrapped { networks } => Ok(networks.unwrap_or_default()),
        AuthorizedNetworksResponse::Legacy(networks) => Ok(networks),
    }
}

fn serialize<T: Serialize>(operation: &'static str, value: &T) -> Result<String, BacklogError> {
    serde_json::to_string(value).map_err(|source| BacklogError::Serialize { operation, source })
}

fn payload_with_reply_topic(
    operation: &'static str,
    payload: &str,
    reply_topic: &str,
) -> Result<String, BacklogError> {
    let mut object: Map<String, Value> = serde_json::from_str(payload)
        .map_err(|source| BacklogError::Serialize { operation, source })?;

    object.insert(
        "reply_topic".to_string(),
        Value::String(reply_topic.to_string()),
    );

    serde_json::to_string(&object).map_err(|source| BacklogError::Serialize { operation, source })
}

fn next_inbox_topic() -> String {
    let id = NEXT_INBOX_ID.fetch_add(1, Ordering::Relaxed);
    format!("_INBOX.ssl_proxy.{}.{}", std::process::id(), id)
}

fn request_transport_unsupported(
    operation: &'static str,
    redpanda_bootstrap_servers: &str,
) -> Option<BacklogError> {
    let trimmed = redpanda_bootstrap_servers.trim();
    let without_scheme = trimmed
        .strip_prefix("tls://")
        .or_else(|| trimmed.strip_prefix("redpanda://"))
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.contains(',') {
        return Some(unsupported_request_transport_error(
            operation,
            redpanda_bootstrap_servers,
        ));
    }

    let port = redpanda_port(host_port).unwrap_or(9092);
    if port == 9092 || port == 9093 || port == 19092 {
        return Some(unsupported_request_transport_error(
            operation,
            redpanda_bootstrap_servers,
        ));
    }

    None
}

pub fn inline_request_reply_transport_supported(redpanda_bootstrap_servers: &str) -> bool {
    request_transport_unsupported("inline_request_reply", redpanda_bootstrap_servers).is_none()
}

fn unsupported_request_transport_error(
    operation: &'static str,
    redpanda_bootstrap_servers: &str,
) -> BacklogError {
    BacklogError::Redpanda {
        operation,
        message: format!(
            "Kafka Redpanda listener {redpanda_bootstrap_servers} does not support inline request/reply; skipping request"
        ),
    }
}

fn redpanda_port(host_port: &str) -> Option<u16> {
    if let Some(rest) = host_port.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest
            .get(end + 1..)
            .and_then(|tail| tail.strip_prefix(':'))
            .and_then(|port| port.parse::<u16>().ok());
    }

    host_port
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

trait RedpandaStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> RedpandaStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct RedpandaEndpoint {
    address: String,
    host: String,
    tls_enabled: bool,
}

fn parse_redpanda_endpoint(redpanda_bootstrap_servers: &str) -> Result<RedpandaEndpoint, String> {
    let trimmed = redpanda_bootstrap_servers.trim();
    let (tls_enabled, without_scheme) = if let Some(value) = trimmed.strip_prefix("tls://") {
        (true, value)
    } else if let Some(value) = trimmed.strip_prefix("redpanda://") {
        (false, value)
    } else {
        (false, trimmed)
    };
    let authority = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| "missing Redpanda authority".to_string())?;
    if authority.is_empty() {
        return Err("missing Redpanda authority".to_string());
    }
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let has_port = if host_port.starts_with('[') {
        host_port.find(']').is_some_and(|end| {
            host_port
                .get(end + 1..)
                .is_some_and(|tail| tail.starts_with(':'))
        })
    } else {
        host_port.contains(':')
    };
    let address = if has_port {
        host_port.to_string()
    } else {
        format!("{host_port}:9092")
    };
    let host = if host_port.starts_with('[') {
        let end = host_port
            .find(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        host_port[1..end].to_string()
    } else {
        host_port
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(host_port)
            .to_string()
    };
    if host.is_empty() {
        return Err("missing Redpanda host".to_string());
    }
    Ok(RedpandaEndpoint {
        address,
        host,
        tls_enabled,
    })
}

fn build_tls_client_config(sync: &SyncConfig) -> Result<Option<Arc<rustls::ClientConfig>>, String> {
    if sync.redpanda_bootstrap_servers.as_deref().is_none() {
        return Ok(None);
    }

    let tls_required = sync
        .redpanda_bootstrap_servers
        .as_deref()
        .is_some_and(|url| url.trim().starts_with("tls://"))
        || sync
            .security_protocol
            .as_deref()
            .is_some_and(|protocol| protocol.to_ascii_uppercase().contains("SSL"));
    if !tls_required {
        return Ok(None);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    let ca_cert_path = sync.ssl_ca_location.as_deref().ok_or_else(|| {
        "SYNC_REDPANDA_SSL_CA_LOCATION is required when TLS is enabled".to_string()
    })?;
    let ca_pem = std::fs::read(ca_cert_path)
        .map_err(|error| format!("read Redpanda CA certificate {ca_cert_path}: {error}"))?;
    let ca_certs = rustls_pemfile::certs(&mut Cursor::new(ca_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse Redpanda CA certificate {ca_cert_path}: {error}"))?;
    let (added, _ignored) = roots.add_parsable_certificates(ca_certs);
    if added == 0 {
        return Err(format!(
            "no trust anchors loaded from Redpanda CA certificate {ca_cert_path}"
        ));
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let client_config = if let (Some(cert_path), Some(key_path)) = (
        sync.ssl_certificate_location.as_deref(),
        sync.ssl_key_location.as_deref(),
    ) {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|error| format!("read Redpanda client certificate {cert_path}: {error}"))?;
        let certs = rustls_pemfile::certs(&mut Cursor::new(cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("parse Redpanda client certificate {cert_path}: {error}"))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|error| format!("read Redpanda client key {key_path}: {error}"))?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem))
            .map_err(|error| format!("parse Redpanda client key {key_path}: {error}"))?
            .ok_or_else(|| format!("no private key found in {key_path}"))?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|error| format!("build Redpanda TLS client auth config: {error}"))?
    } else {
        builder.with_no_client_auth()
    };

    Ok(Some(Arc::new(client_config)))
}

fn redpanda_tls_enabled(sync: &SyncConfig, endpoint: &RedpandaEndpoint) -> bool {
    endpoint.tls_enabled
        || sync
            .security_protocol
            .as_deref()
            .is_some_and(|protocol| protocol.to_ascii_uppercase().contains("SSL"))
}

async fn connect_tls(
    connector: &TlsConnector,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let server_name = host.to_string();
    let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|error| format!("invalid Redpanda TLS server name {server_name}: {error}"))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("establish Redpanda TLS session: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        inline_request_reply_transport_supported, parse_authorized_networks_response,
        parse_redpanda_endpoint, payload_with_reply_topic, request_error_marks_redpanda_unhealthy,
        request_transport_unsupported,
    };
    use crate::backlog::BacklogError;

    #[test]
    fn parses_wrapped_authorized_networks_response() {
        let parsed = parse_authorized_networks_response(
            r#"{"networks":[{"ssid":"Corp","bssid":"aa:bb:cc:dd:ee:ff","location_id":"hq","psk":"secret"}]}"#,
        )
        .expect("wrapped response should parse");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ssid.as_deref(), Some("Corp"));
        assert_eq!(parsed[0].bssid.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(parsed[0].location_id.as_deref(), Some("hq"));
        assert_eq!(parsed[0].psk.as_deref(), Some("secret"));
    }

    #[test]
    fn parses_legacy_authorized_networks_array() {
        let parsed = parse_authorized_networks_response(
            r#"[{"ssid":"Corp","bssid":null,"location_id":null,"psk":null}]"#,
        )
        .expect("legacy array should parse");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ssid.as_deref(), Some("Corp"));
        assert_eq!(parsed[0].bssid, None);
    }

    #[test]
    fn treats_empty_and_null_authorized_networks_responses_as_empty() {
        assert!(parse_authorized_networks_response("").unwrap().is_empty());
        assert!(parse_authorized_networks_response(" null ")
            .unwrap()
            .is_empty());
        assert!(parse_authorized_networks_response(r#"{"networks":null}"#)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn adds_reply_topic_to_request_payload() {
        let payload = payload_with_reply_topic(
            "list_pending",
            r#"{"operation":"list_pending"}"#,
            "_INBOX.x",
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

        assert_eq!(parsed["operation"], "list_pending");
        assert_eq!(parsed["reply_topic"], "_INBOX.x");
    }

    #[test]
    fn rejects_non_object_request_payloads() {
        let error = payload_with_reply_topic("list_pending", r#"[]"#, "_INBOX.x").unwrap_err();

        assert!(
            matches!(error, BacklogError::Serialize { .. })
                || error.to_string().contains("list_pending")
        );
    }

    #[test]
    fn request_reply_timeout_does_not_mark_redpanda_transport_unhealthy() {
        let error = BacklogError::Timeout {
            operation: "lookup_device_by_mac",
        };

        assert!(!request_error_marks_redpanda_unhealthy(&error));
    }

    #[test]
    fn kafka_listener_request_transport_fails_fast() {
        assert!(request_transport_unsupported(
            "lookup_device_by_mac",
            "redpanda://127.0.0.1:19092"
        )
        .is_some());
        assert!(!inline_request_reply_transport_supported(
            "redpanda://127.0.0.1:19092"
        ));
        assert!(
            request_transport_unsupported("lookup_device_by_mac", "redpanda://redpanda:9092")
                .is_some()
        );
        assert!(
            request_transport_unsupported("lookup_device_by_mac", "tls://redpanda:9093").is_some()
        );
        assert!(request_transport_unsupported(
            "lookup_device_by_mac",
            "redpanda://redpanda-a:9092,redpanda-b:9092"
        )
        .is_some());
    }

    #[test]
    fn non_kafka_request_transport_keeps_legacy_path_available() {
        assert!(
            request_transport_unsupported("lookup_device_by_mac", "redpanda://127.0.0.1:4222")
                .is_none()
        );
        assert!(inline_request_reply_transport_supported(
            "redpanda://127.0.0.1:4222"
        ));
    }

    #[test]
    fn transport_io_error_marks_redpanda_transport_unhealthy() {
        let error = BacklogError::Redpanda {
            operation: "lookup_device_by_mac",
            message: "unexpected EOF while reading reply".to_string(),
        };

        assert!(request_error_marks_redpanda_unhealthy(&error));
    }

    #[test]
    fn parses_host_with_default_port() {
        let endpoint = parse_redpanda_endpoint("redpanda://redpanda.internal").unwrap();
        assert_eq!(endpoint.address, "redpanda.internal:9092");
        assert_eq!(endpoint.host, "redpanda.internal");
        assert!(!endpoint.tls_enabled);
    }

    #[test]
    fn parses_tls_scheme() {
        let endpoint = parse_redpanda_endpoint("tls://redpanda.internal:4443").unwrap();
        assert_eq!(endpoint.address, "redpanda.internal:4443");
        assert_eq!(endpoint.host, "redpanda.internal");
        assert!(endpoint.tls_enabled);
    }

    #[test]
    fn parses_bracketed_ipv6_without_port() {
        let endpoint = parse_redpanda_endpoint("redpanda://[::1]").unwrap();
        assert_eq!(endpoint.address, "[::1]:9092");
        assert_eq!(endpoint.host, "::1");
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let endpoint = parse_redpanda_endpoint("redpanda://[::1]:4223").unwrap();
        assert_eq!(endpoint.address, "[::1]:4223");
        assert_eq!(endpoint.host, "::1");
    }

    #[test]
    fn ignores_userinfo_for_address_parsing() {
        let endpoint =
            parse_redpanda_endpoint("redpanda://user:pass@redpanda.internal:4224").unwrap();
        assert_eq!(endpoint.address, "redpanda.internal:4224");
        assert_eq!(endpoint.host, "redpanda.internal");
    }
}
