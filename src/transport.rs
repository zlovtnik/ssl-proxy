//! Thin outbound sync-plane publisher for the proxy runtime.

use std::{
    io::Cursor,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::{
    config::SyncConfig,
    sync::{
        parse_payload_ref, PublishedMessage, ScanRequest, INLINE_PAYLOAD_REF_PREFIX,
        OUTBOX_PAYLOAD_REF_PREFIX, SYNC_SCAN_REQUEST_SUBJECT,
    },
};

#[derive(Clone, Debug)]
struct SyncPublisherConfig {
    nats_url: Option<String>,
    connect_timeout: Duration,
    username: Option<String>,
    password: Option<String>,
    tls_enabled: bool,
    tls_server_name: Option<String>,
    tls_ca_cert_path: Option<String>,
    tls_client_cert_path: Option<String>,
    tls_client_key_path: Option<String>,
    inline_payload_max_bytes: usize,
    outbox_dir: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct SyncPublisherHealth {
    last_attempt_at: Option<String>,
    last_publish_at: Option<String>,
    last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyncPublisherHealthSnapshot {
    pub configured: bool,
    pub auth_enabled: bool,
    pub tls_enabled: bool,
    pub inline_payload_max_bytes: usize,
    pub outbox_dir: String,
    pub last_attempt_at: Option<String>,
    pub last_publish_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SyncPublisher {
    config: SyncPublisherConfig,
    published: Arc<Mutex<Vec<PublishedMessage>>>,
    health: Arc<Mutex<SyncPublisherHealth>>,
    publish_tx: Arc<Mutex<Option<mpsc::Sender<(String, String)>>>>,
    publish_task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NatsEndpoint {
    address: String,
    host: String,
    tls_enabled: bool,
}

#[derive(Serialize)]
struct ConnectOptions<'a> {
    verbose: bool,
    pedantic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pass: Option<&'a str>,
}

impl SyncPublisher {
    pub fn new(config: &SyncConfig) -> Self {
        let publisher_config = SyncPublisherConfig {
            nats_url: config.nats_url.clone(),
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            username: config.username.clone(),
            password: config.password.clone(),
            tls_enabled: config.tls_enabled,
            tls_server_name: config.tls_server_name.clone(),
            tls_ca_cert_path: config.tls_ca_cert_path.clone(),
            tls_client_cert_path: config.tls_client_cert_path.clone(),
            tls_client_key_path: config.tls_client_key_path.clone(),
            inline_payload_max_bytes: config.inline_payload_max_bytes,
            outbox_dir: PathBuf::from(&config.outbox_dir),
        };

        let health = Arc::new(Mutex::new(SyncPublisherHealth::default()));
        let (publish_tx, publish_task) = if tokio::runtime::Handle::try_current().is_ok() {
            let (publish_tx, mut publish_rx) = mpsc::channel::<(String, String)>(64);
            let config_clone = publisher_config.clone();
            let health_clone = Arc::clone(&health);

            let publish_task = tokio::spawn(async move {
                while let Some((subject, payload)) = publish_rx.recv().await {
                    if let Some(nats_url) = &config_clone.nats_url {
                        match publish_nats_message(&config_clone, nats_url, &subject, &payload)
                            .await
                        {
                            Ok(()) => {
                                let mut snapshot = health_clone
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                snapshot.last_publish_at = Some(chrono::Utc::now().to_rfc3339());
                                snapshot.last_error = None;
                            }
                            Err(error) => {
                                warn!(%error, %subject, "failed to publish scan request to NATS");
                                let mut snapshot = health_clone
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                snapshot.last_error = Some(error);
                            }
                        }
                    }
                }
            });

            (Some(publish_tx), Some(publish_task))
        } else {
            (None, None)
        };

        Self {
            config: publisher_config,
            published: Arc::new(Mutex::new(Vec::new())),
            health,
            publish_tx: Arc::new(Mutex::new(publish_tx)),
            publish_task: Arc::new(Mutex::new(publish_task)),
        }
    }

    /// Shutdown the publisher gracefully, awaiting all in-flight publishes to complete
    pub async fn shutdown(&self) {
        // Drop the active sender (if present) so the worker recv loop can exit.
        let sender = self
            .publish_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(sender);

        // Take and await the publisher task
        if let Some(handle) = self
            .publish_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = handle.await;
        }
    }

    pub fn publish_scan_request(&self, request: ScanRequest) {
        let payload = match serde_json::to_string(&request) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(%error, "sync publisher failed to serialize scan request");
                return;
            }
        };

        self.record(SYNC_SCAN_REQUEST_SUBJECT, &payload);

        if self.config.nats_url.is_none() {
            debug!("sync publisher disabled; recorded scan request locally");
            return;
        }

        self.record_attempt();

        let publish_tx = self
            .publish_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(publish_tx) = publish_tx else {
            let mut health = self
                .health
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            health.last_error = Some("sync publisher requires a Tokio runtime".to_string());
            warn!("sync publisher runtime unavailable; dropping scan request");
            return;
        };

        let subject = SYNC_SCAN_REQUEST_SUBJECT.to_string();
        if let Err(_) = publish_tx.try_send((subject, payload)) {
            warn!("publish queue full; dropping scan request");
        }
    }

    pub async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String> {
        self.record(subject, payload);
        self.record_attempt();

        let Some(nats_url) = &self.config.nats_url else {
            let error = "sync publisher disabled".to_string();
            let mut health = self
                .health
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            health.last_error = Some(error.clone());
            return Err(error);
        };

        debug!(
            %subject,
            payload_bytes = payload.len(),
            "sync publisher attempting NATS publish"
        );
        match publish_nats_message(&self.config, nats_url, subject, payload).await {
            Ok(()) => {
                let mut snapshot = self
                    .health
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                snapshot.last_publish_at = Some(chrono::Utc::now().to_rfc3339());
                snapshot.last_error = None;
                debug!(
                    %subject,
                    payload_bytes = payload.len(),
                    "sync publisher NATS publish succeeded"
                );
                Ok(())
            }
            Err(error) => {
                let mut snapshot = self
                    .health
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                snapshot.last_error = Some(error.clone());
                warn!(
                    %subject,
                    payload_bytes = payload.len(),
                    %error,
                    "sync publisher NATS publish failed"
                );
                Err(error)
            }
        }
    }

    pub fn payload_ref_for_event(
        &self,
        raw_payload: &str,
        observed_at: &str,
    ) -> Result<String, String> {
        if raw_payload.len() <= self.config.inline_payload_max_bytes {
            return Ok(format!(
                "{INLINE_PAYLOAD_REF_PREFIX}{}",
                URL_SAFE_NO_PAD.encode(raw_payload.as_bytes())
            ));
        }

        std::fs::create_dir_all(&self.config.outbox_dir).map_err(|error| {
            format!(
                "create sync outbox {}: {error}",
                self.config.outbox_dir.display()
            )
        })?;

        let digest = format!("{:x}", Sha256::digest(raw_payload.as_bytes()));
        let observed_token: String = observed_at
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .collect();
        let file_name = format!("{observed_token}-{digest}.json");
        let path = self.config.outbox_dir.join(&file_name);
        std::fs::write(&path, raw_payload)
            .map_err(|error| format!("write sync outbox payload {}: {error}", path.display()))?;
        Ok(format!("{OUTBOX_PAYLOAD_REF_PREFIX}{file_name}"))
    }

    pub fn resolve_payload_ref_contents(&self, payload_ref: &str) -> Result<String, String> {
        let parsed = parse_payload_ref(payload_ref)
            .ok_or_else(|| format!("unsupported payload_ref: {payload_ref}"))?;
        match parsed.kind {
            crate::sync::PayloadRefKind::Inline => URL_SAFE_NO_PAD
                .decode(parsed.locator.as_bytes())
                .map_err(|error| format!("decode inline payload_ref: {error}"))
                .and_then(|bytes| {
                    String::from_utf8(bytes)
                        .map_err(|error| format!("inline payload_ref UTF-8: {error}"))
                }),
            crate::sync::PayloadRefKind::Outbox => {
                let canonical_outbox = std::fs::canonicalize(&self.config.outbox_dir)
                    .map_err(|error| format!("canonicalize outbox directory: {error}"))?;

                let path = self.config.outbox_dir.join(parsed.locator);
                let canonical_path = std::fs::canonicalize(&path).map_err(|error| {
                    format!("canonicalize payload path {}: {error}", path.display())
                })?;

                if !canonical_path.starts_with(&canonical_outbox) {
                    return Err(format!(
                        "payload path traversal attempt blocked: {}",
                        path.display()
                    ));
                }

                std::fs::read_to_string(&canonical_path).map_err(|error| {
                    format!(
                        "read sync outbox payload {}: {error}",
                        canonical_path.display()
                    )
                })
            }
        }
    }

    pub fn health_snapshot(&self) -> SyncPublisherHealthSnapshot {
        let health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        SyncPublisherHealthSnapshot {
            configured: self.config.nats_url.is_some(),
            auth_enabled: self.config.username.is_some(),
            tls_enabled: self.config.tls_enabled
                || self
                    .config
                    .nats_url
                    .as_deref()
                    .map(|url| url.starts_with("tls://"))
                    .unwrap_or(false),
            inline_payload_max_bytes: self.config.inline_payload_max_bytes,
            outbox_dir: self.config.outbox_dir.display().to_string(),
            last_attempt_at: health.last_attempt_at,
            last_publish_at: health.last_publish_at,
            last_error: health.last_error,
        }
    }

    pub fn published_messages(&self) -> Vec<PublishedMessage> {
        self.published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn record(&self, subject: &str, payload: &str) {
        self.published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(PublishedMessage {
                subject: subject.to_string(),
                payload: payload.to_string(),
            });
    }

    fn record_attempt(&self) {
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health.last_attempt_at = Some(chrono::Utc::now().to_rfc3339());
    }
}

async fn publish_nats_message(
    config: &SyncPublisherConfig,
    nats_url: &str,
    subject: &str,
    payload: &str,
) -> Result<(), String> {
    let endpoint = parse_nats_endpoint(nats_url)?;
    debug!(
        %subject,
        nats_host = %endpoint.host,
        tls_enabled = config.tls_enabled || endpoint.tls_enabled,
        payload_bytes = payload.len(),
        "opening NATS publish session"
    );
    let tcp_stream = timeout(
        config.connect_timeout,
        TcpStream::connect(&endpoint.address),
    )
    .await
    .map_err(|_| format!("timed out connecting to {}", endpoint.address))?
    .map_err(|error| format!("connect {}: {error}", endpoint.address))?;

    if config.tls_enabled || endpoint.tls_enabled {
        let stream = connect_tls(config, endpoint.host.as_str(), tcp_stream).await?;
        drive_nats_session(stream, config, subject, payload).await
    } else {
        drive_nats_session(tcp_stream, config, subject, payload).await
    }
}

async fn drive_nats_session<S>(
    mut stream: S,
    config: &SyncPublisherConfig,
    subject: &str,
    payload: &str,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_info = read_line(&mut stream, config.connect_timeout).await?;
    if !server_info.starts_with("INFO ") {
        return Err(format!("expected NATS INFO banner, got: {server_info}"));
    }

    let connect_options = serde_json::to_string(&ConnectOptions {
        verbose: false,
        pedantic: false,
        user: config.username.as_deref(),
        pass: config.password.as_deref(),
    })
    .map_err(|error| format!("serialize NATS CONNECT options: {error}"))?;
    let connect_command = format!("CONNECT {connect_options}\r\n");
    stream
        .write_all(connect_command.as_bytes())
        .await
        .map_err(|error| format!("send CONNECT: {error}"))?;
    check_server_error(&mut stream, config.connect_timeout, "CONNECT").await?;

    let publish_command = format!("PUB {subject} {}\r\n", payload.len());
    stream
        .write_all(publish_command.as_bytes())
        .await
        .map_err(|error| format!("send PUB header: {error}"))?;
    stream
        .write_all(payload.as_bytes())
        .await
        .map_err(|error| format!("send payload: {error}"))?;
    stream
        .write_all(b"\r\n")
        .await
        .map_err(|error| format!("finish payload: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush publish: {error}"))?;
    check_server_error(&mut stream, config.connect_timeout, "PUB").await?;

    Ok(())
}

async fn connect_tls(
    config: &SyncPublisherConfig,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let mut roots = rustls::RootCertStore::empty();
    let ca_cert_path = config
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
        config.tls_client_cert_path.as_deref(),
        config.tls_client_key_path.as_deref(),
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
    let server_name = config
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
    let address = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:4222")
    };
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
        .trim_matches(['[', ']'])
        .to_string();
    if host.is_empty() {
        return Err("missing NATS host".to_string());
    }

    Ok(NatsEndpoint {
        address,
        host,
        tls_enabled,
    })
}

async fn read_line<S>(stream: &mut S, connect_timeout: Duration) -> Result<String, String>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = timeout(connect_timeout, stream.read(&mut byte))
            .await
            .map_err(|_| "timed out waiting for NATS response".to_string())?
            .map_err(|error| format!("read NATS response: {error}"))?;
        if read == 0 {
            return Err("NATS connection closed unexpectedly".to_string());
        }
        buffer.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }

    String::from_utf8(buffer)
        .map(|line| line.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|error| format!("invalid UTF-8 from NATS server: {error}"))
}

async fn check_server_error<S>(
    stream: &mut S,
    connect_timeout: Duration,
    operation: &str,
) -> Result<(), String>
where
    S: AsyncRead + Unpin,
{
    match timeout(Duration::from_millis(100), stream.read_u8()).await {
        Ok(Ok(first_byte)) => {
            let mut buffer = vec![first_byte];
            loop {
                let mut byte = [0u8; 1];
                let read = timeout(connect_timeout, stream.read(&mut byte))
                    .await
                    .map_err(|_| format!("timed out reading NATS response after {operation}"))?
                    .map_err(|error| format!("read NATS response after {operation}: {error}"))?;
                if read == 0 {
                    break;
                }
                buffer.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            let line = String::from_utf8(buffer)
                .map_err(|error| format!("invalid NATS response after {operation}: {error}"))?;
            if line.starts_with("-ERR") {
                return Err(format!("NATS {operation} failed: {}", line.trim()));
            }
            Ok(())
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(format!("NATS connection closed after {operation}"))
        }
        Ok(Err(error)) => Err(format!("read NATS response after {operation}: {error}")),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{parse_nats_endpoint, SyncPublisher};
    use crate::{
        config::Config,
        sync::{
            parse_payload_ref, ScanRequest, INLINE_PAYLOAD_REF_PREFIX, OUTBOX_PAYLOAD_REF_PREFIX,
        },
    };

    #[test]
    fn parse_nats_defaults_port() {
        let endpoint = parse_nats_endpoint("nats://localhost").unwrap();
        assert_eq!(endpoint.address, "localhost:4222");
        assert_eq!(endpoint.host, "localhost");
        assert!(!endpoint.tls_enabled);
    }

    #[test]
    fn parse_nats_supports_tls_scheme() {
        let endpoint = parse_nats_endpoint("tls://nats.example.internal:4443").unwrap();
        assert_eq!(endpoint.address, "nats.example.internal:4443");
        assert_eq!(endpoint.host, "nats.example.internal");
        assert!(endpoint.tls_enabled);
    }

    #[test]
    fn publisher_records_messages_without_network() {
        let publisher = SyncPublisher::new(&Config::default().sync);
        publisher.publish_scan_request(ScanRequest {
            stream_name: "proxy.events".to_string(),
            dedupe_key: "abc".to_string(),
            payload_ref: "inline://payload".to_string(),
            observed_at: "2026-04-17T00:00:00Z".to_string(),
        });

        let messages = publisher.published_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].subject, crate::sync::SYNC_SCAN_REQUEST_SUBJECT);
        assert!(messages[0]
            .payload
            .contains("\"stream_name\":\"proxy.events\""));
    }

    #[test]
    fn publisher_uses_inline_payload_ref_below_limit() {
        let publisher = SyncPublisher::new(&Config::default().sync);
        let payload_ref = publisher
            .payload_ref_for_event("{\"small\":true}", "2026-04-17T00:00:00Z")
            .unwrap();
        assert!(payload_ref.starts_with(INLINE_PAYLOAD_REF_PREFIX));
        assert_eq!(
            publisher
                .resolve_payload_ref_contents(&payload_ref)
                .unwrap(),
            "{\"small\":true}"
        );
    }

    #[test]
    fn publisher_spools_large_payload_ref_to_outbox() {
        let mut config = Config::default();
        config.sync.inline_payload_max_bytes = 8;
        config.sync.outbox_dir = std::env::temp_dir()
            .join(format!("boringtun-sync-outbox-{}", std::process::id()))
            .display()
            .to_string();
        let publisher = SyncPublisher::new(&config.sync);
        let payload_ref = publisher
            .payload_ref_for_event("{\"large\":true}", "2026-04-17T00:00:00Z")
            .unwrap();
        assert!(payload_ref.starts_with(OUTBOX_PAYLOAD_REF_PREFIX));
        assert_eq!(
            publisher
                .resolve_payload_ref_contents(&payload_ref)
                .unwrap(),
            "{\"large\":true}"
        );
        if let Some(parsed) = parse_payload_ref(&payload_ref) {
            let path = Path::new(&config.sync.outbox_dir).join(parsed.locator);
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_dir_all(&config.sync.outbox_dir);
    }
}
