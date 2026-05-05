//! NATS-backed wireless backlog and lookup store.

use std::{io::Cursor, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
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

const WIRELESS_AUDIT_SUBJECT: &str = "wireless.audit";
const BACKLOG_SAVE_SUBJECT: &str = "wireless.backlog.save";
const BACKLOG_LIST_SUBJECT: &str = "wireless.backlog.list";
const BACKLOG_LIST_REPLY_SUBJECT: &str = "wireless.backlog.list.reply";
const BACKLOG_SYNCED_SUBJECT: &str = "wireless.backlog.synced";
const BACKLOG_PRUNE_SUBJECT: &str = "wireless.backlog.prune";
const BACKLOG_PRUNE_REPLY_SUBJECT: &str = "wireless.backlog.prune.reply";
const MAC_LOOKUP_SUBJECT: &str = "wireless.mac.lookup";
const MAC_LOOKUP_REPLY_SUBJECT: &str = "wireless.mac.lookup.reply";
const AUTHORIZED_NETWORKS_SUBJECT: &str = "wireless.networks.authorized";
const AUTHORIZED_NETWORKS_REPLY_SUBJECT: &str = "wireless.networks.authorized.reply";
const PROBE_FLUSH_SUBJECT: &str = "wireless.probe.flush";

#[derive(Clone)]
pub struct NatsBacklog {
    publisher: Arc<dyn PublishClient>,
    sync: SyncConfig,
    request_timeout: Duration,
}

impl NatsBacklog {
    pub fn new(publisher: Arc<dyn PublishClient>, sync: SyncConfig) -> Self {
        Self {
            publisher,
            sync,
            request_timeout: Duration::from_secs(5),
        }
    }

    pub async fn lookup_device_by_mac(
        &self,
        mac: &str,
    ) -> Result<Option<(String, Option<String>)>, BacklogError> {
        #[derive(Serialize)]
        struct Request<'a> {
            mac: &'a str,
        }
        #[derive(Deserialize)]
        struct Response {
            device_id: Option<String>,
            username: Option<String>,
        }

        let payload = serialize("lookup_device_by_mac", &Request { mac })?;
        let response = self
            .request(
                "lookup_device_by_mac",
                MAC_LOOKUP_SUBJECT,
                MAC_LOOKUP_REPLY_SUBJECT,
                &payload,
            )
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
                AUTHORIZED_NETWORKS_REPLY_SUBJECT,
                "{}",
            )
            .await?;
        serde_json::from_str(&response).map_err(|source| BacklogError::Deserialize {
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
            probes: &'a [ProbeFlushObservation],
        }
        let payload = serialize("flush_probe_batch", &Payload { probes })?;
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

    async fn request(
        &self,
        operation: &'static str,
        subject: &'static str,
        reply_subject: &'static str,
        payload: &str,
    ) -> Result<String, BacklogError> {
        let Some(nats_url) = self.sync.nats_url.as_deref() else {
            return Err(BacklogError::Disabled { operation });
        };
        request_once(
            &self.sync,
            nats_url,
            operation,
            subject,
            reply_subject,
            payload,
            self.request_timeout,
        )
        .await
    }
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
        self.publish(WIRELESS_AUDIT_SUBJECT, record.payload).await
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
            dedupe_key: &'a str,
            stream_name: &'a str,
            payload: &'a str,
            error: &'a str,
        }
        let payload = serialize(
            "save_pending",
            &Message {
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
                BACKLOG_LIST_REPLY_SUBJECT,
                "{}",
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
            dedupe_key: &'a str,
        }
        let payload = serialize("mark_synced", &Message { dedupe_key })?;
        self.publish(BACKLOG_SYNCED_SUBJECT, &payload).await
    }

    async fn prune_stale(
        &self,
        max_attempts: i32,
        max_age_hours: i64,
    ) -> Result<u64, BacklogError> {
        #[derive(Serialize)]
        struct Message {
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
                max_attempts,
                max_age_hours,
            },
        )?;
        let response = self
            .request(
                "prune_stale",
                BACKLOG_PRUNE_SUBJECT,
                BACKLOG_PRUNE_REPLY_SUBJECT,
                &payload,
            )
            .await?;
        let parsed: PruneResult =
            serde_json::from_str(&response).map_err(|source| BacklogError::Deserialize {
                operation: "prune_stale",
                source,
            })?;
        Ok(parsed.pruned)
    }
}

fn serialize<T: Serialize>(operation: &'static str, value: &T) -> Result<String, BacklogError> {
    serde_json::to_string(value).map_err(|source| BacklogError::Serialize { operation, source })
}

async fn request_once(
    sync: &SyncConfig,
    nats_url: &str,
    operation: &'static str,
    subject: &str,
    reply_subject: &str,
    payload: &str,
    request_timeout: Duration,
) -> Result<String, BacklogError> {
    let endpoint = parse_nats_endpoint(nats_url).map_err(|source| BacklogError::Nats {
        operation,
        message: source,
    })?;
    let tcp_stream = timeout(request_timeout, TcpStream::connect(&endpoint.address))
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Nats {
            operation,
            message: format!("connect {}: {source}", endpoint.address),
        })?;
    let stream: Box<dyn NatsStream> = if sync.tls_enabled || endpoint.tls_enabled {
        let stream = connect_tls(sync, endpoint.host.as_str(), tcp_stream)
            .await
            .map_err(|message| BacklogError::Nats { operation, message })?;
        Box::new(stream)
    } else {
        Box::new(tcp_stream)
    };
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let mut line = String::new();
    timeout(request_timeout, reader.read_line(&mut line))
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Nats {
            operation,
            message: format!("read INFO: {source}"),
        })?;
    if !line.starts_with("INFO ") {
        return Err(BacklogError::Nats {
            operation,
            message: format!("expected NATS INFO banner, got: {}", line.trim_end()),
        });
    }

    let connect_options = serde_json::json!({
        "lang": "rust",
        "version": env!("CARGO_PKG_VERSION"),
        "verbose": false,
        "pedantic": false,
        "user": sync.username.as_deref(),
        "pass": sync.password.as_deref(),
    });
    let command = format!("CONNECT {connect_options}\r\nSUB {reply_subject} 1\r\n");
    timeout(request_timeout, write_half.write_all(command.as_bytes()))
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Nats {
            operation,
            message: format!("subscribe reply subject: {source}"),
        })?;

    let publish_command = format!("PUB {subject} {reply_subject} {}\r\n", payload.len());
    timeout(
        request_timeout,
        write_half.write_all(publish_command.as_bytes()),
    )
    .await
    .map_err(|_| BacklogError::Timeout { operation })?
    .map_err(|source| BacklogError::Nats {
        operation,
        message: format!("send PUB header: {source}"),
    })?;
    timeout(request_timeout, write_half.write_all(payload.as_bytes()))
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Nats {
            operation,
            message: format!("send PUB payload: {source}"),
        })?;
    timeout(request_timeout, write_half.write_all(b"\r\n"))
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Nats {
            operation,
            message: format!("finish PUB payload: {source}"),
        })?;
    timeout(request_timeout, write_half.flush())
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Nats {
            operation,
            message: format!("flush request: {source}"),
        })?;

    loop {
        line.clear();
        timeout(request_timeout, reader.read_line(&mut line))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("read reply: {source}"),
            })?;
        let trimmed = line.trim_end();
        if trimmed == "PING" {
            timeout(request_timeout, write_half.write_all(b"PONG\r\n"))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Nats {
                    operation,
                    message: format!("send PONG: {source}"),
                })?;
            timeout(request_timeout, write_half.flush())
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
            return Err(BacklogError::Nats {
                operation,
                message: trimmed.to_string(),
            });
        }
        if !trimmed.starts_with("MSG ") {
            continue;
        }

        let size = trimmed
            .split_whitespace()
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
        let mut payload = vec![0_u8; size];
        timeout(request_timeout, reader.read_exact(&mut payload))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Nats {
                operation,
                message: format!("read reply payload: {source}"),
            })?;
        let mut terminator = [0_u8; 2];
        timeout(request_timeout, reader.read_exact(&mut terminator))
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
        return String::from_utf8(payload).map_err(|source| BacklogError::Nats {
            operation,
            message: format!("reply is not UTF-8: {source}"),
        });
    }
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

async fn connect_tls(
    sync: &SyncConfig,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
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

    let connector = TlsConnector::from(Arc::new(client_config));
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
    use super::parse_nats_endpoint;

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
