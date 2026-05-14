//! NATS-backed wireless backlog and lookup store.

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
use ssl_proxy::config::SyncConfig;
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

const WIRELESS_AUDIT_SUBJECT: &str = "sync.scan.request";
const BACKLOG_SAVE_SUBJECT: &str = "wireless.backlog.save";
const BACKLOG_LIST_SUBJECT: &str = "wireless.backlog.list";
const BACKLOG_SYNCED_SUBJECT: &str = "wireless.backlog.synced";
const BACKLOG_PRUNE_SUBJECT: &str = "wireless.backlog.prune";
const MAC_LOOKUP_SUBJECT: &str = "wireless.mac.lookup";
const AUTHORIZED_NETWORKS_SUBJECT: &str = "wireless.networks.authorized";
const PROBE_FLUSH_SUBJECT: &str = "wireless.probe.flush";
static NEXT_INBOX_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct NatsBacklog {
    publisher: Arc<dyn PublishClient>,
    sync: SyncConfig,
    request_timeout: Duration,
    request_connection_ttl: Duration,
    tls_client_config: Option<Arc<rustls::ClientConfig>>,
    tls_connector: Option<TlsConnector>,
    request_connection: Arc<Mutex<Option<CachedRequestConnection>>>,
    health_status: Arc<AtomicBool>,
    connection_generation: Arc<AtomicU64>,
}

struct CachedRequestConnection {
    reader: BufReader<Box<dyn NatsStream>>,
    last_used: Instant,
    next_sid: u64,
}

impl NatsBacklog {
    pub fn new(
        publisher: Arc<dyn PublishClient>,
        sync: SyncConfig,
        request_timeout: Duration,
    ) -> Result<Self, BacklogError> {
        let tls_client_config =
            build_tls_client_config(&sync).map_err(|message| BacklogError::Nats {
                operation: "initialize_nats_backlog",
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
            tls_client_config,
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

    async fn health_probe(&self) {
        let result = self.ping_nats().await;
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
        let nats_url = self
            .sync
            .nats_url
            .as_deref()
            .ok_or_else(|| BacklogError::Disabled { operation })?;
        let endpoint = parse_nats_endpoint(nats_url).map_err(|source| BacklogError::Nats {
            operation,
            message: source,
        })?;
        let tcp_stream = timeout(self.request_timeout, TcpStream::connect(&endpoint.address))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("connect {}: {source}", endpoint.address),
            })?;
        let mut stream: Box<dyn NatsStream> = if self.sync.tls_enabled || endpoint.tls_enabled {
            let connector = self
                .tls_connector
                .as_ref()
                .ok_or_else(|| BacklogError::Nats {
                    operation,
                    message: "NATS TLS connector was not initialized".to_string(),
                })?;
            let tls_stream = connect_tls(connector, &self.sync, endpoint.host.as_str(), tcp_stream)
                .await
                .map_err(|message| BacklogError::Nats { operation, message })?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };
        let mut reader = BufReader::new(&mut *stream);
        let mut info_line = String::new();
        timeout(self.request_timeout, reader.read_line(&mut info_line))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("read INFO: {source}"),
            })?;
        if !info_line.starts_with("INFO ") {
            return Err(BacklogError::Nats {
                operation,
                message: format!("expected NATS INFO banner, got: {}", info_line.trim_end()),
            });
        }

        let connect_options = serde_json::json!({
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "verbose": false,
            "pedantic": false,
            "user": self.sync.username.as_deref(),
            "pass": self.sync.password.as_deref(),
        });
        let command = format!("CONNECT {connect_options}\r\n");
        timeout(self.request_timeout, stream.write_all(command.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("send CONNECT: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
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
        subject: &'static str,
        payload: &str,
        reply_subject: &str,
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
                subject,
                payload,
                reply_subject,
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
                if request_error_marks_nats_unhealthy(&err) {
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
        subject: &'static str,
        payload: &str,
        reply_subject: &str,
    ) -> Result<String, BacklogError> {
        let stream = &mut connection.reader;
        let sid = connection.next_sid;
        connection.next_sid = connection.next_sid.saturating_add(1);
        let subscribe = format!("SUB {reply_subject} {sid}\r\n");
        timeout(self.request_timeout, stream.write_all(subscribe.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("subscribe reply subject: {source}"),
            })?;

        let publish_command = format!("PUB {subject} {}\r\n", payload.len());
        timeout(
            self.request_timeout,
            stream.write_all(publish_command.as_bytes()),
        )
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Nats {
            operation,
            message: format!("send PUB header: {source}"),
        })?;
        timeout(self.request_timeout, stream.write_all(payload.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("send PUB payload: {source}"),
            })?;
        timeout(self.request_timeout, stream.write_all(b"\r\n"))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("finish PUB payload: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("flush request: {source}"),
            })?;

        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = timeout(self.request_timeout, stream.read_line(&mut line))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Nats {
                    operation,
                    message: format!("read reply: {source}"),
                })?;
            let trimmed = line.trim_end();
            if bytes_read == 0 || trimmed.is_empty() {
                return Err(BacklogError::Nats {
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
                .map_err(|source| BacklogError::Nats {
                    operation,
                    message: format!("send PONG: {source}"),
                })?;
                timeout(self.request_timeout, stream.get_mut().flush())
                    .await
                    .map_err(|_| BacklogError::Timeout { operation })?
                    .map_err(|source| BacklogError::Nats {
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
                return Err(BacklogError::Nats {
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
            let msg_subject = parts[1];
            if msg_subject != reply_subject {
                continue;
            }
            let size = parts
                .last()
                .ok_or_else(|| BacklogError::Nats {
                    operation,
                    message: format!("missing reply size: {trimmed}"),
                })?
                .parse::<usize>()
                .map_err(|source| BacklogError::Nats {
                    operation,
                    message: format!("invalid reply size: {source}"),
                })?;
            let mut payload_buf = vec![0_u8; size];
            timeout(self.request_timeout, stream.read_exact(&mut payload_buf))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Nats {
                    operation,
                    message: format!("read reply payload: {source}"),
                })?;
            let mut terminator = [0_u8; 2];
            timeout(self.request_timeout, stream.read_exact(&mut terminator))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Nats {
                    operation,
                    message: format!("read reply terminator: {source}"),
                })?;
            if terminator != *b"\r\n" {
                return Err(BacklogError::Nats {
                    operation,
                    message: "invalid reply terminator".to_string(),
                });
            }
            let result = String::from_utf8(payload_buf).map_err(|source| BacklogError::Nats {
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
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("send UNSUB: {source}"),
            })?;
            timeout(self.request_timeout, stream.flush())
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Nats {
                    operation,
                    message: format!("flush UNSUB: {source}"),
                })?;
            return result;
        }
    }

    async fn ping_nats(&self) -> Result<(), BacklogError> {
        let nats_url = self
            .sync
            .nats_url
            .as_deref()
            .ok_or_else(|| BacklogError::Disabled {
                operation: "nats_health_check",
            })?;
        let endpoint = parse_nats_endpoint(nats_url).map_err(|source| BacklogError::Nats {
            operation: "nats_health_check",
            message: source,
        })?;
        let tcp_stream = timeout(self.request_timeout, TcpStream::connect(&endpoint.address))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "nats_health_check",
            })?
            .map_err(|source| BacklogError::Nats {
                operation: "nats_health_check",
                message: format!("connect {}: {source}", endpoint.address),
            })?;
        let mut stream: Box<dyn NatsStream> = if self.sync.tls_enabled || endpoint.tls_enabled {
            let connector = self
                .tls_connector
                .as_ref()
                .ok_or_else(|| BacklogError::Nats {
                    operation: "nats_health_check",
                    message: "NATS TLS connector was not initialized".to_string(),
                })?;
            let tls_stream = connect_tls(connector, &self.sync, endpoint.host.as_str(), tcp_stream)
                .await
                .map_err(|message| BacklogError::Nats {
                    operation: "nats_health_check",
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
                    operation: "nats_health_check",
                })?
                .map_err(|source| BacklogError::Nats {
                    operation: "nats_health_check",
                    message: format!("read INFO: {source}"),
                })?;
        }
        if !info_line.starts_with("INFO ") {
            return Err(BacklogError::Nats {
                operation: "nats_health_check",
                message: format!("expected NATS INFO banner, got: {}", info_line.trim_end()),
            });
        }
        let connect_options = serde_json::json!({
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "verbose": false,
            "pedantic": false,
            "user": self.sync.username.as_deref(),
            "pass": self.sync.password.as_deref(),
        });
        let command = format!("CONNECT {connect_options}\r\nPING\r\n");
        timeout(self.request_timeout, stream.write_all(command.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "nats_health_check",
            })?
            .map_err(|source| BacklogError::Nats {
                operation: "nats_health_check",
                message: format!("send CONNECT/PING: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "nats_health_check",
            })?
            .map_err(|source| BacklogError::Nats {
                operation: "nats_health_check",
                message: format!("flush CONNECT/PING: {source}"),
            })?;
        let mut reader = BufReader::new(&mut *stream);
        let mut pong_line = String::new();
        timeout(self.request_timeout, reader.read_line(&mut pong_line))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "nats_health_check",
            })?
            .map_err(|source| BacklogError::Nats {
                operation: "nats_health_check",
                message: format!("read PONG: {source}"),
            })?;
        if pong_line.trim() != "PONG" {
            return Err(BacklogError::Nats {
                operation: "nats_health_check",
                message: format!("unexpected health check response: {}", pong_line.trim_end()),
            });
        }
        Ok(())
    }

    async fn request(
        &self,
        operation: &'static str,
        subject: &'static str,
        payload: &str,
    ) -> Result<String, BacklogError> {
        let Some(_nats_url) = self.sync.nats_url.as_deref() else {
            return Err(BacklogError::Disabled { operation });
        };
        let reply_subject = next_inbox_subject();
        let payload = payload_with_reply_subject(operation, payload, &reply_subject)?;
        self.request_with_cached_connection(operation, subject, &payload, &reply_subject)
            .await
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
            .request("lookup_device_by_mac", MAC_LOOKUP_SUBJECT, &payload)
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
                AUTHORIZED_NETWORKS_SUBJECT,
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
            probes: &'a [ProbeFlushObservation],
        }
        let payload = serialize(
            "flush_probe_batch",
            &Payload {
                operation: "flush_probe_batch",
                probes,
            },
        )?;
        self.publish(PROBE_FLUSH_SUBJECT, &payload).await
    }

    async fn publish(&self, subject: &'static str, payload: &str) -> Result<(), BacklogError> {
        self.publisher
            .publish_message(subject, payload)
            .await
            .map_err(|source| BacklogError::Nats {
                operation: subject,
                message: source,
            })
    }
}

fn request_error_marks_nats_unhealthy(error: &BacklogError) -> bool {
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
impl BacklogStore for NatsBacklog {
    async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError> {
        debug!(
            dedupe_key = record.dedupe_key,
            stream_name = record.stream_name,
            observed_at = %record.observed_at,
            payload_ref = record.payload_ref,
            payload_sha256 = record.payload_sha256,
            producer = record.producer,
            event_kind = record.event_kind,
            "publishing wireless audit ingest over NATS"
        );
        #[derive(Serialize)]
        struct IngestEnvelope<'a> {
            dedupe_key: &'a str,
            stream_name: &'a str,
            observed_at: chrono::DateTime<chrono::Utc>,
            payload_ref: &'a str,
            payload: &'a str,
            payload_sha256: &'a str,
            producer: &'a str,
            event_kind: Option<&'a str>,
        }
        let payload = serialize(
            "record_ingest",
            &IngestEnvelope {
                dedupe_key: record.dedupe_key,
                stream_name: record.stream_name,
                observed_at: record.observed_at,
                payload_ref: record.payload_ref,
                payload: record.payload,
                payload_sha256: record.payload_sha256,
                producer: record.producer,
                event_kind: record.event_kind,
            },
        )?;
        self.publish(WIRELESS_AUDIT_SUBJECT, &payload).await
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
        self.publish(BACKLOG_SAVE_SUBJECT, &payload).await
    }

    async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
        let response = self
            .request(
                "list_pending",
                BACKLOG_LIST_SUBJECT,
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
        self.publish(BACKLOG_SYNCED_SUBJECT, &payload).await
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
            .request("prune_stale", BACKLOG_PRUNE_SUBJECT, &payload)
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

fn payload_with_reply_subject(
    operation: &'static str,
    payload: &str,
    reply_subject: &str,
) -> Result<String, BacklogError> {
    let mut object: Map<String, Value> = serde_json::from_str(payload)
        .map_err(|source| BacklogError::Serialize { operation, source })?;

    object.insert(
        "reply_subject".to_string(),
        Value::String(reply_subject.to_string()),
    );

    serde_json::to_string(&object).map_err(|source| BacklogError::Serialize { operation, source })
}

fn next_inbox_subject() -> String {
    let id = NEXT_INBOX_ID.fetch_add(1, Ordering::Relaxed);
    format!("_INBOX.ssl_proxy.{}.{}", std::process::id(), id)
}

trait NatsStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NatsStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct NatsEndpoint {
    address: String,
    host: String,
    tls_enabled: bool,
}

fn parse_nats_endpoint(nats_url: &str) -> Result<NatsEndpoint, String> {
    let trimmed = nats_url.trim();
    let (tls_enabled, without_scheme) = if let Some(value) = trimmed.strip_prefix("tls://") {
        (true, value)
    } else if let Some(value) = trimmed.strip_prefix("nats://") {
        (false, value)
    } else {
        (false, trimmed)
    };
    let authority = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| "missing NATS authority".to_string())?;
    if authority.is_empty() {
        return Err("missing NATS authority".to_string());
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
        format!("{host_port}:4222")
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
        return Err("missing NATS host".to_string());
    }
    Ok(NatsEndpoint {
        address,
        host,
        tls_enabled,
    })
}

fn build_tls_client_config(sync: &SyncConfig) -> Result<Option<Arc<rustls::ClientConfig>>, String> {
    let tls_required = sync.tls_enabled
        || sync
            .nats_url
            .as_deref()
            .is_some_and(|url| url.trim().starts_with("tls://"));
    if !tls_required {
        return Ok(None);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    let ca_cert_path = sync
        .tls_ca_cert_path
        .as_deref()
        .ok_or_else(|| "SYNC_NATS_TLS_CA_CERT_PATH is required when TLS is enabled".to_string())?;
    let ca_pem = std::fs::read(ca_cert_path)
        .map_err(|error| format!("read NATS CA certificate {ca_cert_path}: {error}"))?;
    let ca_certs = rustls_pemfile::certs(&mut Cursor::new(ca_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse NATS CA certificate {ca_cert_path}: {error}"))?;
    let (added, _ignored) = roots.add_parsable_certificates(ca_certs);
    if added == 0 {
        return Err(format!(
            "no trust anchors loaded from NATS CA certificate {ca_cert_path}"
        ));
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let client_config = if let (Some(cert_path), Some(key_path)) = (
        sync.tls_client_cert_path.as_deref(),
        sync.tls_client_key_path.as_deref(),
    ) {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|error| format!("read NATS client certificate {cert_path}: {error}"))?;
        let certs = rustls_pemfile::certs(&mut Cursor::new(cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("parse NATS client certificate {cert_path}: {error}"))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|error| format!("read NATS client key {key_path}: {error}"))?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem))
            .map_err(|error| format!("parse NATS client key {key_path}: {error}"))?
            .ok_or_else(|| format!("no private key found in {key_path}"))?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|error| format!("build NATS TLS client auth config: {error}"))?
    } else {
        builder.with_no_client_auth()
    };

    Ok(Some(Arc::new(client_config)))
}

async fn connect_tls(
    connector: &TlsConnector,
    sync: &SyncConfig,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let server_name = sync
        .tls_server_name
        .clone()
        .unwrap_or_else(|| host.to_string());
    let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|error| format!("invalid NATS TLS server name {server_name}: {error}"))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("establish NATS TLS session: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_authorized_networks_response, parse_nats_endpoint, payload_with_reply_subject,
        request_error_marks_nats_unhealthy,
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
    fn adds_reply_subject_to_request_payload() {
        let payload = payload_with_reply_subject(
            "list_pending",
            r#"{"operation":"list_pending"}"#,
            "_INBOX.x",
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

        assert_eq!(parsed["operation"], "list_pending");
        assert_eq!(parsed["reply_subject"], "_INBOX.x");
    }

    #[test]
    fn rejects_non_object_request_payloads() {
        let error = payload_with_reply_subject("list_pending", r#"[]"#, "_INBOX.x").unwrap_err();

        assert!(
            matches!(error, BacklogError::Serialize { .. })
                || error.to_string().contains("list_pending")
        );
    }

    #[test]
    fn request_reply_timeout_does_not_mark_nats_transport_unhealthy() {
        let error = BacklogError::Timeout {
            operation: "lookup_device_by_mac",
        };

        assert!(!request_error_marks_nats_unhealthy(&error));
    }

    #[test]
    fn transport_io_error_marks_nats_transport_unhealthy() {
        let error = BacklogError::Nats {
            operation: "lookup_device_by_mac",
            message: "unexpected EOF while reading reply".to_string(),
        };

        assert!(request_error_marks_nats_unhealthy(&error));
    }

    #[test]
    fn parses_host_with_default_port() {
        let endpoint = parse_nats_endpoint("nats://nats.internal").unwrap();
        assert_eq!(endpoint.address, "nats.internal:4222");
        assert_eq!(endpoint.host, "nats.internal");
        assert!(!endpoint.tls_enabled);
    }

    #[test]
    fn parses_tls_scheme() {
        let endpoint = parse_nats_endpoint("tls://nats.internal:4443").unwrap();
        assert_eq!(endpoint.address, "nats.internal:4443");
        assert_eq!(endpoint.host, "nats.internal");
        assert!(endpoint.tls_enabled);
    }

    #[test]
    fn parses_bracketed_ipv6_without_port() {
        let endpoint = parse_nats_endpoint("nats://[::1]").unwrap();
        assert_eq!(endpoint.address, "[::1]:4222");
        assert_eq!(endpoint.host, "::1");
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let endpoint = parse_nats_endpoint("nats://[::1]:4223").unwrap();
        assert_eq!(endpoint.address, "[::1]:4223");
        assert_eq!(endpoint.host, "::1");
    }

    #[test]
    fn ignores_userinfo_for_address_parsing() {
        let endpoint = parse_nats_endpoint("nats://user:pass@nats.internal:4224").unwrap();
        assert_eq!(endpoint.address, "nats.internal:4224");
        assert_eq!(endpoint.host, "nats.internal");
    }
}
