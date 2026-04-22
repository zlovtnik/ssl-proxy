//! Thin outbound sync-plane publisher for the proxy runtime.

use std::{
    io::Cursor,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    runtime::RuntimeFlavor,
    sync::{mpsc, oneshot},
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

pub const ENQUEUE_TIMEOUT_ERROR: &str = "sync publisher enqueue timed out";

#[derive(Clone, Debug)]
struct SyncPublisherConfig {
    nats_url: Option<String>,
    connect_timeout: Duration,
    publish_timeout: Duration,
    queue_capacity: usize,
    enqueue_timeout: Duration,
    username: Option<String>,
    password: Option<String>,
    tls_enabled: bool,
    tls_server_name: Option<String>,
    tls_ca_cert_path: Option<String>,
    tls_client_cert_path: Option<String>,
    tls_client_key_path: Option<String>,
    inline_payload_max_bytes: usize,
    outbox_dir: PathBuf,
    publish_spool_dir: PathBuf,
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
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub queue_available: usize,
    pub spool_dir: String,
    pub spool_pending: usize,
    pub spooled_total: u64,
    pub enqueue_timeouts_total: u64,
    pub last_attempt_at: Option<String>,
    pub last_publish_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
struct SyncPublisherCounters {
    spooled_total: AtomicU64,
    enqueue_timeouts_total: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct SyncPublisher {
    config: SyncPublisherConfig,
    published: Arc<Mutex<Vec<PublishedMessage>>>,
    health: Arc<Mutex<SyncPublisherHealth>>,
    counters: Arc<SyncPublisherCounters>,
    publish_tx: Arc<Mutex<Option<PublishQueueSender>>>,
    publish_task: Arc<Mutex<Option<PublishTaskHandle>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NatsEndpoint {
    address: String,
    host: String,
    tls_enabled: bool,
}

struct PublishQueueMessage {
    subject: String,
    payload: String,
    response_tx: Option<oneshot::Sender<Result<(), String>>>,
}
type PublishQueueSender = mpsc::Sender<PublishQueueMessage>;
type PublishTaskHandle = JoinHandle<()>;

enum EnqueueError {
    Timeout,
    Closed,
}

#[derive(Deserialize, Serialize)]
struct PublishSpoolEnvelope {
    subject: String,
    payload: String,
    created_at: String,
}

trait NatsStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NatsStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct NatsPublishSession {
    stream: Box<dyn NatsStream>,
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
            publish_timeout: Duration::from_millis(config.publish_timeout_ms),
            queue_capacity: config.publish_queue_capacity,
            enqueue_timeout: Duration::from_millis(config.publish_enqueue_timeout_ms),
            username: config.username.clone(),
            password: config.password.clone(),
            tls_enabled: config.tls_enabled,
            tls_server_name: config.tls_server_name.clone(),
            tls_ca_cert_path: config.tls_ca_cert_path.clone(),
            tls_client_cert_path: config.tls_client_cert_path.clone(),
            tls_client_key_path: config.tls_client_key_path.clone(),
            inline_payload_max_bytes: config.inline_payload_max_bytes,
            outbox_dir: PathBuf::from(&config.outbox_dir),
            publish_spool_dir: PathBuf::from(&config.publish_spool_dir),
        };

        let health = Arc::new(Mutex::new(SyncPublisherHealth::default()));
        let counters = Arc::new(SyncPublisherCounters::default());
        let (publish_tx, publish_task) = if tokio::runtime::Handle::try_current().is_ok() {
            let (publish_tx, mut publish_rx) =
                mpsc::channel::<PublishQueueMessage>(publisher_config.queue_capacity);
            let config_clone = publisher_config.clone();
            let health_clone = Arc::clone(&health);

            let publish_task = tokio::spawn(async move {
                run_publish_worker(config_clone, health_clone, &mut publish_rx).await;
            });

            (Some(publish_tx), Some(publish_task))
        } else {
            (None, None)
        };

        Self {
            config: publisher_config,
            published: Arc::new(Mutex::new(Vec::new())),
            health,
            counters,
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
        let handle = {
            self.publish_task
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        };
        if let Some(handle) = handle {
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

        if let Err(error) = self.enqueue_message(SYNC_SCAN_REQUEST_SUBJECT, &payload) {
            warn!(%error, "dropping scan request");
        }
    }

    pub fn enqueue_message(&self, subject: &str, payload: &str) -> Result<(), String> {
        self.record(subject, payload);
        self.record_attempt();

        if self.config.nats_url.is_none() {
            let error = "sync publisher disabled".to_string();
            self.record_error(error.clone());
            return Err(error);
        }

        let message = PublishQueueMessage {
            subject: subject.to_string(),
            payload: payload.to_string(),
            response_tx: None,
        };
        let publish_tx = match self.queue_sender() {
            Ok(publish_tx) => publish_tx,
            Err(error) => {
                warn!(%error, %subject, "sync publisher queue unavailable; spooling publish");
                return self.spool_publish(subject, payload);
            }
        };

        match self.enqueue_with_timeout(&publish_tx, message) {
            Ok(()) => Ok(()),
            Err(EnqueueError::Timeout) => {
                self.counters
                    .enqueue_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
                self.record_error(ENQUEUE_TIMEOUT_ERROR.to_string());
                warn!(
                    %subject,
                    timeout_ms = self.config.enqueue_timeout.as_millis(),
                    "sync publisher enqueue timed out; spooling publish"
                );
                self.spool_publish(subject, payload)
            }
            Err(EnqueueError::Closed) => {
                let error = "sync publisher queue closed".to_string();
                self.record_error(error.clone());
                warn!(%subject, "sync publisher queue closed; spooling publish");
                self.spool_publish(subject, payload)
                    .map_err(|spool_error| format!("{error}; spool failed: {spool_error}"))
            }
        }
    }

    pub async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String> {
        self.record(subject, payload);
        self.record_attempt();

        if self.config.nats_url.is_none() {
            let error = "sync publisher disabled".to_string();
            self.record_error(error.clone());
            return Err(error);
        }

        debug!(
            %subject,
            payload_bytes = payload.len(),
            "sync publisher queueing acknowledged NATS publish"
        );
        let publish_tx = self.queue_sender()?;
        let (response_tx, response_rx) = oneshot::channel();
        publish_tx
            .send(PublishQueueMessage {
                subject: subject.to_string(),
                payload: payload.to_string(),
                response_tx: Some(response_tx),
            })
            .await
            .map_err(|_| {
                let error = "sync publisher queue closed".to_string();
                self.record_error(error.clone());
                error
            })?;

        response_rx.await.map_err(|_| {
            let error = "sync publisher response channel closed".to_string();
            self.record_error(error.clone());
            error
        })?
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
        let (queue_available, queue_capacity) = self
            .publish_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|sender| (sender.capacity(), sender.max_capacity()))
            .unwrap_or((0, self.config.queue_capacity));
        let queue_depth = queue_capacity.saturating_sub(queue_available);
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
            queue_capacity,
            queue_depth,
            queue_available,
            spool_dir: self.config.publish_spool_dir.display().to_string(),
            spool_pending: count_spool_pending(&self.config.publish_spool_dir),
            spooled_total: self.counters.spooled_total.load(Ordering::Relaxed),
            enqueue_timeouts_total: self.counters.enqueue_timeouts_total.load(Ordering::Relaxed),
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

    fn queue_sender(&self) -> Result<PublishQueueSender, String> {
        self.publish_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| {
                let error = "sync publisher requires a Tokio runtime".to_string();
                self.record_error(error.clone());
                error
            })
    }

    fn record_error(&self, error: String) {
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health.last_error = Some(error);
    }

    fn enqueue_with_timeout(
        &self,
        publish_tx: &PublishQueueSender,
        message: PublishQueueMessage,
    ) -> Result<(), EnqueueError> {
        if self.config.enqueue_timeout.is_zero() {
            return publish_tx.try_send(message).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => EnqueueError::Timeout,
                mpsc::error::TrySendError::Closed(_) => EnqueueError::Closed,
            });
        }

        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        timeout(self.config.enqueue_timeout, publish_tx.send(message))
                            .await
                            .map_err(|_| EnqueueError::Timeout)?
                            .map_err(|_| EnqueueError::Closed)
                    })
                })
            }
            Ok(_) => publish_tx.try_send(message).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => EnqueueError::Timeout,
                mpsc::error::TrySendError::Closed(_) => EnqueueError::Closed,
            }),
            Err(_) => publish_tx.try_send(message).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => EnqueueError::Timeout,
                mpsc::error::TrySendError::Closed(_) => EnqueueError::Closed,
            }),
        }
    }

    fn spool_publish(&self, subject: &str, payload: &str) -> Result<(), String> {
        write_spool_envelope(&self.config.publish_spool_dir, subject, payload)?;
        self.counters.spooled_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn write_spool_envelope(spool_dir: &Path, subject: &str, payload: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(spool_dir)
        .map_err(|error| format!("create sync publish spool {}: {error}", spool_dir.display()))?;
    let created_at = chrono::Utc::now().to_rfc3339();
    let token = chrono::Utc::now().format("%Y%m%dT%H%M%S%fZ").to_string();
    let id = uuid::Uuid::new_v4().simple();
    let tmp_path = spool_dir.join(format!("{token}-{id}.tmp"));
    let final_path = spool_dir.join(format!("{token}-{id}.json"));
    let envelope = PublishSpoolEnvelope {
        subject: subject.to_string(),
        payload: payload.to_string(),
        created_at,
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| format!("serialize sync publish spool envelope: {error}"))?;
    std::fs::write(&tmp_path, bytes).map_err(|error| {
        format!(
            "write sync publish spool envelope {}: {error}",
            tmp_path.display()
        )
    })?;
    std::fs::rename(&tmp_path, &final_path).map_err(|error| {
        let _ = std::fs::remove_file(&tmp_path);
        format!(
            "commit sync publish spool envelope {}: {error}",
            final_path.display()
        )
    })?;
    Ok(final_path)
}

fn count_spool_pending(spool_dir: &Path) -> usize {
    std::fs::read_dir(spool_dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .count()
        })
        .unwrap_or(0)
}

fn list_spool_envelopes(spool_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(spool_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "read sync publish spool {}: {error}",
                spool_dir.display()
            ));
        }
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn read_spool_envelope(path: &Path) -> Result<PublishSpoolEnvelope, String> {
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "read sync publish spool envelope {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "decode sync publish spool envelope {}: {error}",
            path.display()
        )
    })
}

async fn run_publish_worker(
    config: SyncPublisherConfig,
    health: Arc<Mutex<SyncPublisherHealth>>,
    publish_rx: &mut mpsc::Receiver<PublishQueueMessage>,
) {
    let mut session = None;

    loop {
        let _ = drain_spooled_messages(&config, &health, &mut session).await;

        let Some(message) = publish_rx.recv().await else {
            let _ = drain_spooled_messages(&config, &health, &mut session).await;
            break;
        };

        let result = publish_with_session(
            &config,
            &health,
            &mut session,
            &message.subject,
            &message.payload,
            "queued",
        )
        .await;

        if let Some(response_tx) = message.response_tx {
            let _ = response_tx.send(result);
        }
    }
}

async fn drain_spooled_messages(
    config: &SyncPublisherConfig,
    health: &Arc<Mutex<SyncPublisherHealth>>,
    session: &mut Option<NatsPublishSession>,
) -> Result<(), String> {
    let paths = match list_spool_envelopes(&config.publish_spool_dir) {
        Ok(paths) => paths,
        Err(error) => {
            record_worker_error(health, error.clone());
            return Err(error);
        }
    };

    for path in paths {
        let envelope = match read_spool_envelope(&path) {
            Ok(envelope) => envelope,
            Err(error) => {
                record_worker_error(health, error.clone());
                return Err(error);
            }
        };
        publish_with_session(
            config,
            health,
            session,
            &envelope.subject,
            &envelope.payload,
            "spooled",
        )
        .await?;
        std::fs::remove_file(&path).map_err(|error| {
            let message = format!(
                "delete sync publish spool envelope {}: {error}",
                path.display()
            );
            record_worker_error(health, message.clone());
            message
        })?;
    }

    Ok(())
}

async fn publish_with_session(
    config: &SyncPublisherConfig,
    health: &Arc<Mutex<SyncPublisherHealth>>,
    session: &mut Option<NatsPublishSession>,
    subject: &str,
    payload: &str,
    source: &str,
) -> Result<(), String> {
    let result = async {
        if session.is_none() {
            let Some(nats_url) = &config.nats_url else {
                return Err("sync publisher disabled".to_string());
            };
            *session = Some(open_nats_publish_session(config, nats_url).await?);
        }

        let publish_result = session
            .as_mut()
            .expect("session is initialized above")
            .publish(config, subject, payload)
            .await;
        if publish_result.is_err() {
            *session = None;
        }
        publish_result
    }
    .await;

    match &result {
        Ok(()) => {
            let mut snapshot = health
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            snapshot.last_publish_at = Some(chrono::Utc::now().to_rfc3339());
            snapshot.last_error = None;
            debug!(
                %subject,
                source,
                payload_bytes = payload.len(),
                "sync publisher NATS publish succeeded"
            );
        }
        Err(error) => {
            warn!(
                %error,
                %subject,
                source,
                payload_bytes = payload.len(),
                "sync publisher NATS publish failed"
            );
            record_worker_error(health, error.clone());
        }
    }

    result
}

fn record_worker_error(health: &Arc<Mutex<SyncPublisherHealth>>, error: String) {
    let mut snapshot = health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    snapshot.last_error = Some(error);
}

async fn open_nats_publish_session(
    config: &SyncPublisherConfig,
    nats_url: &str,
) -> Result<NatsPublishSession, String> {
    let endpoint = parse_nats_endpoint(nats_url)?;
    debug!(
        nats_host = %endpoint.host,
        tls_enabled = config.tls_enabled || endpoint.tls_enabled,
        "opening persistent NATS publish session"
    );
    let tcp_stream = timeout(
        config.connect_timeout,
        TcpStream::connect(&endpoint.address),
    )
    .await
    .map_err(|_| format!("timed out connecting to {}", endpoint.address))?
    .map_err(|error| format!("connect {}: {error}", endpoint.address))?;

    let stream: Box<dyn NatsStream> = if config.tls_enabled || endpoint.tls_enabled {
        let stream = connect_tls(config, endpoint.host.as_str(), tcp_stream).await?;
        Box::new(stream)
    } else {
        Box::new(tcp_stream)
    };

    let mut session = NatsPublishSession { stream };
    let server_info = read_line(&mut session.stream, config.connect_timeout).await?;
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
    session
        .stream
        .write_all(connect_command.as_bytes())
        .await
        .map_err(|error| format!("send CONNECT: {error}"))?;
    check_server_error(&mut session.stream, config.connect_timeout, "CONNECT").await?;

    Ok(session)
}

impl NatsPublishSession {
    async fn publish(
        &mut self,
        config: &SyncPublisherConfig,
        subject: &str,
        payload: &str,
    ) -> Result<(), String> {
        let inbox = format!("_INBOX.{}", uuid::Uuid::new_v4().simple());
        let sid = uuid::Uuid::new_v4().simple().to_string();
        let subscribe_command = format!("SUB {inbox} {sid}\r\nUNSUB {sid} 1\r\n");
        timeout(
            config.publish_timeout,
            self.stream.write_all(subscribe_command.as_bytes()),
        )
        .await
        .map_err(|_| "timed out sending JetStream ack SUB".to_string())?
        .map_err(|error| format!("send JetStream ack SUB: {error}"))?;

        // Publish directly to the stream-bound subject with a reply inbox.
        // JetStream returns a PubAck on the reply subject for request-style publishes.
        let publish_command = format!("PUB {subject} {inbox} {}\r\n", payload.len());
        timeout(
            config.publish_timeout,
            self.stream.write_all(publish_command.as_bytes()),
        )
        .await
        .map_err(|_| "timed out sending PUB header".to_string())?
        .map_err(|error| format!("send PUB header: {error}"))?;
        timeout(
            config.publish_timeout,
            self.stream.write_all(payload.as_bytes()),
        )
        .await
        .map_err(|_| "timed out sending payload".to_string())?
        .map_err(|error| format!("send payload: {error}"))?;
        timeout(config.publish_timeout, self.stream.write_all(b"\r\n"))
            .await
            .map_err(|_| "timed out finishing payload".to_string())?
            .map_err(|error| format!("finish payload: {error}"))?;
        timeout(config.publish_timeout, self.stream.flush())
            .await
            .map_err(|_| "timed out flushing publish".to_string())?
            .map_err(|error| format!("flush publish: {error}"))?;

        let mut ack_attempts = 0usize;
        const MAX_ACK_ATTEMPTS: usize = 32;
        let ack = loop {
            if ack_attempts >= MAX_ACK_ATTEMPTS {
                return Err(format!(
                    "too many non-MSG responses while waiting for JetStream ack ({MAX_ACK_ATTEMPTS})"
                ));
            }
            ack_attempts += 1;
            let line = read_line(&mut self.stream, config.publish_timeout).await?;
            if line == "PING" {
                timeout(config.publish_timeout, self.stream.write_all(b"PONG\r\n"))
                    .await
                    .map_err(|_| "timed out sending PONG".to_string())?
                    .map_err(|error| format!("send PONG: {error}"))?;
                continue;
            }
            if line.starts_with("INFO") || line == "+OK" {
                continue;
            }
            if line.starts_with("-ERR") {
                return Err(format!("NATS returned error: {line}"));
            }
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.first().copied() == Some("MSG") {
                let Some(size_token) = parts.last() else {
                    return Err(format!("missing NATS MSG size: {line}"));
                };
                let size = size_token
                    .parse::<usize>()
                    .map_err(|error| format!("invalid NATS MSG size {size_token}: {error}"))?;
                let mut payload = vec![0u8; size];
                timeout(config.publish_timeout, self.stream.read_exact(&mut payload))
                    .await
                    .map_err(|_| "timed out reading NATS MSG payload".to_string())?
                    .map_err(|error| format!("read NATS MSG payload: {error}"))?;
                let mut terminator = [0u8; 2];
                timeout(
                    config.publish_timeout,
                    self.stream.read_exact(&mut terminator),
                )
                .await
                .map_err(|_| "timed out reading NATS MSG terminator".to_string())?
                .map_err(|error| format!("read NATS MSG terminator: {error}"))?;
                if terminator != *b"\r\n" {
                    return Err("invalid NATS MSG terminator".to_string());
                }
                break String::from_utf8(payload)
                    .map_err(|error| format!("NATS MSG payload UTF-8: {error}"))?;
            } else {
                return Err(format!("expected NATS MSG or PING, got: {line}"));
            }
        };
        match serde_json::from_str::<serde_json::Value>(&ack) {
            Ok(value) => {
                if value.get("error").is_some_and(|error| !error.is_null()) {
                    return Err(format!("JetStream publish failed: {ack}"));
                }
            }
            Err(error) => {
                debug!(%error, ack = %ack, "JetStream ack payload is not JSON");
            }
        }

        Ok(())
    }
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
    use std::{
        path::Path,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{
        io::{duplex, AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::{
        count_spool_pending, drain_spooled_messages, parse_nats_endpoint, read_spool_envelope,
        write_spool_envelope, NatsPublishSession, SyncPublisher, SyncPublisherConfig,
        SyncPublisherHealth,
    };
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
    fn enqueue_message_records_disabled_publisher_without_network() {
        let publisher = SyncPublisher::new(&Config::default().sync);

        let error = publisher
            .enqueue_message("wireless.audit", "{}")
            .unwrap_err();

        assert_eq!(error, "sync publisher disabled");
        let messages = publisher.published_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].subject, "wireless.audit");
    }

    #[tokio::test]
    async fn enqueue_message_spools_when_queue_stays_full() {
        let spool = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.sync.nats_url = Some("nats://127.0.0.1:4222".to_string());
        config.sync.publish_enqueue_timeout_ms = 1;
        config.sync.publish_spool_dir = spool.path().display().to_string();
        let publisher = SyncPublisher::new(&config.sync);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        *publisher.publish_tx.lock().unwrap() = Some(tx);

        publisher.enqueue_message("wireless.audit", "{}").unwrap();
        publisher.enqueue_message("wireless.audit", "{}").unwrap();

        assert_eq!(count_spool_pending(spool.path()), 1);
        let path = super::list_spool_envelopes(spool.path()).unwrap().remove(0);
        let envelope = read_spool_envelope(&path).unwrap();
        assert_eq!(envelope.subject, "wireless.audit");
        assert_eq!(envelope.payload, "{}");
        let snapshot = publisher.health_snapshot();
        assert_eq!(snapshot.queue_capacity, 1);
        assert_eq!(snapshot.queue_depth, 1);
        assert_eq!(snapshot.spool_pending, 1);
        assert_eq!(snapshot.spooled_total, 1);
        assert_eq!(snapshot.enqueue_timeouts_total, 1);
        publisher.shutdown().await;
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

    #[tokio::test]
    async fn persistent_session_publish_uses_ack_inbox_and_unsub() {
        let (client, mut server) = duplex(4096);
        let mut session = NatsPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            nats_url: Some("nats://127.0.0.1:4222".to_string()),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: std::env::temp_dir().join("ssl-proxy-sync-test-spool"),
        };

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = server.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\nhello\r\n".len())
                    .any(|window| window == b"\r\nhello\r\n")
                {
                    break;
                }
            }
            let text = String::from_utf8(received).unwrap();
            assert!(text.contains("SUB _INBOX."));
            assert!(text.contains("UNSUB "));
            assert!(text.contains("PUB wireless.audit _INBOX."));
            server
                .write_all(b"MSG _INBOX.test 1 2\r\n{}\r\n")
                .await
                .unwrap();
        });

        session
            .publish(&config, "wireless.audit", "hello")
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn persistent_session_publish_fails_after_too_many_non_msg_responses() {
        let (client, mut server) = duplex(4096);
        let mut session = NatsPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            nats_url: Some("nats://127.0.0.1:4222".to_string()),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: std::env::temp_dir().join("ssl-proxy-sync-test-spool"),
        };

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = server.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\nhello\r\n".len())
                    .any(|window| window == b"\r\nhello\r\n")
                {
                    break;
                }
            }
            for _ in 0..40 {
                server.write_all(b"+OK\r\n").await.unwrap();
            }
        });

        let error = session
            .publish(&config, "wireless.audit", "hello")
            .await
            .unwrap_err();
        assert!(error.contains("too many non-MSG responses"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn persistent_session_publish_rejects_json_error_ack() {
        let (client, mut server) = duplex(4096);
        let mut session = NatsPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            nats_url: Some("nats://127.0.0.1:4222".to_string()),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: std::env::temp_dir().join("ssl-proxy-sync-test-spool"),
        };

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = server.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\nhello\r\n".len())
                    .any(|window| window == b"\r\nhello\r\n")
                {
                    break;
                }
            }
            let ack = r#"{"error":{"code":500}}"#;
            let frame = format!("MSG _INBOX.test 1 {}\r\n{}\r\n", ack.len(), ack);
            server.write_all(frame.as_bytes()).await.unwrap();
        });

        let error = session
            .publish(&config, "wireless.audit", "hello")
            .await
            .unwrap_err();
        assert!(error.contains("JetStream publish failed"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn persistent_session_publish_allows_non_json_ack_with_error_word() {
        let (client, mut server) = duplex(4096);
        let mut session = NatsPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            nats_url: Some("nats://127.0.0.1:4222".to_string()),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: std::env::temp_dir().join("ssl-proxy-sync-test-spool"),
        };

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = server.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\nhello\r\n".len())
                    .any(|window| window == b"\r\nhello\r\n")
                {
                    break;
                }
            }
            let ack = "error: transient";
            let frame = format!("MSG _INBOX.test 1 {}\r\n{}\r\n", ack.len(), ack);
            server.write_all(frame.as_bytes()).await.unwrap();
        });

        session
            .publish(&config, "wireless.audit", "hello")
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn worker_publishes_spooled_envelope_and_deletes_file() {
        let spool = tempfile::tempdir().unwrap();
        write_spool_envelope(spool.path(), "wireless.audit", "hello").unwrap();
        let (url, server_task) = spawn_mock_nats("hello", r#"{}"#).await;
        let config = test_publisher_config(url, spool.path());
        let health = Arc::new(Mutex::new(SyncPublisherHealth::default()));
        let mut session = None;

        drain_spooled_messages(&config, &health, &mut session)
            .await
            .unwrap();

        assert_eq!(count_spool_pending(spool.path()), 0);
        let received = String::from_utf8(server_task.await.unwrap()).unwrap();
        assert!(received.contains("PUB wireless.audit _INBOX."));
    }

    #[tokio::test]
    async fn worker_leaves_spooled_envelope_when_publish_fails() {
        let spool = tempfile::tempdir().unwrap();
        write_spool_envelope(spool.path(), "wireless.audit", "hello").unwrap();
        let (url, server_task) = spawn_mock_nats("hello", r#"{"error":{"code":500}}"#).await;
        let config = test_publisher_config(url, spool.path());
        let health = Arc::new(Mutex::new(SyncPublisherHealth::default()));
        let mut session = None;

        let error = drain_spooled_messages(&config, &health, &mut session)
            .await
            .unwrap_err();

        assert!(error.contains("JetStream publish failed"));
        assert_eq!(count_spool_pending(spool.path()), 1);
        let _ = server_task.await.unwrap();
    }

    fn test_publisher_config(nats_url: String, spool_dir: &Path) -> SyncPublisherConfig {
        SyncPublisherConfig {
            nats_url: Some(nats_url),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: spool_dir.to_path_buf(),
        }
    }

    async fn spawn_mock_nats(
        expected_payload: &'static str,
        ack_payload: &'static str,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"INFO {}\r\n").await.unwrap();
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"CONNECT ".len())
                    .any(|window| window == b"CONNECT ")
                {
                    break;
                }
            }
            stream.write_all(b"+OK\r\n").await.unwrap();
            let expected_frame = format!("\r\n{expected_payload}\r\n");
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(expected_frame.as_bytes().len())
                    .any(|window| window == expected_frame.as_bytes())
                {
                    break;
                }
            }
            let frame = format!(
                "MSG _INBOX.test 1 {}\r\n{}\r\n",
                ack_payload.len(),
                ack_payload
            );
            stream.write_all(frame.as_bytes()).await.unwrap();
            received
        });

        (format!("nats://{address}"), task)
    }
}
