//! Thin outbound sync-plane publisher for the proxy runtime.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    ClientConfig,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    runtime::RuntimeFlavor,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, warn};

use crate::{
    config::SyncConfig,
    sync::{
        parse_payload_ref, PublishedMessage, ScanRequest, INLINE_PAYLOAD_REF_PREFIX,
        OUTBOX_PAYLOAD_REF_PREFIX, SYNC_SCAN_REQUEST_TOPIC,
    },
};

pub const ENQUEUE_TIMEOUT_ERROR: &str = "sync publisher enqueue timed out";

#[derive(Clone, Debug)]
struct SyncPublisherConfig {
    redpanda_bootstrap_servers: Option<String>,
    connect_timeout: Duration,
    publish_timeout: Duration,
    queue_capacity: usize,
    enqueue_timeout: Duration,
    security_protocol: Option<String>,
    sasl_mechanisms: Option<String>,
    sasl_username: Option<String>,
    sasl_password: Option<String>,
    ssl_ca_location: Option<String>,
    ssl_certificate_location: Option<String>,
    ssl_key_location: Option<String>,
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

struct PublishQueueMessage {
    topic: String,
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
    topic: String,
    payload: String,
    created_at: String,
}

impl SyncPublisher {
    pub fn new(config: &SyncConfig) -> Self {
        let publisher_config = SyncPublisherConfig {
            redpanda_bootstrap_servers: config.redpanda_bootstrap_servers.clone(),
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            publish_timeout: Duration::from_millis(config.publish_timeout_ms),
            queue_capacity: config.publish_queue_capacity,
            enqueue_timeout: Duration::from_millis(config.publish_enqueue_timeout_ms),
            security_protocol: config.security_protocol.clone(),
            sasl_mechanisms: config.sasl_mechanisms.clone(),
            sasl_username: config.sasl_username.clone(),
            sasl_password: config.sasl_password.clone(),
            ssl_ca_location: config.ssl_ca_location.clone(),
            ssl_certificate_location: config.ssl_certificate_location.clone(),
            ssl_key_location: config.ssl_key_location.clone(),
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

        if let Err(error) = self.enqueue_message(SYNC_SCAN_REQUEST_TOPIC, &payload) {
            warn!(
                %error,
                dedupe_key = request.dedupe_key,
                stream_name = request.stream_name,
                "sync publisher failed to enqueue scan request — event may not reach Oracle"
            );
        } else {
            debug!(
                target: "sync",
                dedupe_key = request.dedupe_key,
                stream_name = request.stream_name,
                payload_ref = request.payload_ref,
                "scan request enqueued for Redpanda publish"
            );
        }
    }

    pub fn publish_payload_audit(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.enqueue_message(topic, payload)
    }

    pub fn enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.record(topic, payload);
        self.record_attempt();

        if self.config.redpanda_bootstrap_servers.is_none() {
            let error = "sync publisher disabled".to_string();
            self.record_error(error.clone());
            return Err(error);
        }

        let message = PublishQueueMessage {
            topic: topic.to_string(),
            payload: payload.to_string(),
            response_tx: None,
        };
        let publish_tx = match self.queue_sender() {
            Ok(publish_tx) => publish_tx,
            Err(error) => {
                warn!(%error, %topic, "sync publisher queue unavailable; spooling publish");
                return self.spool_publish(topic, payload);
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
                    %topic,
                    timeout_ms = self.config.enqueue_timeout.as_millis(),
                    "sync publisher enqueue timed out; spooling publish"
                );
                self.spool_publish(topic, payload)
            }
            Err(EnqueueError::Closed) => {
                let error = "sync publisher queue closed".to_string();
                self.record_error(error.clone());
                warn!(%topic, "sync publisher queue closed; spooling publish");
                self.spool_publish(topic, payload)
                    .map_err(|spool_error| format!("{error}; spool failed: {spool_error}"))
            }
        }
    }

    pub fn try_enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.record(topic, payload);
        self.record_attempt();

        if self.config.redpanda_bootstrap_servers.is_none() {
            let error = "sync publisher disabled".to_string();
            self.record_error(error.clone());
            return Err(error);
        }

        let message = PublishQueueMessage {
            topic: topic.to_string(),
            payload: payload.to_string(),
            response_tx: None,
        };
        let publish_tx = self.queue_sender()?;

        match self.enqueue_with_timeout(&publish_tx, message) {
            Ok(()) => Ok(()),
            Err(EnqueueError::Timeout) => {
                self.counters
                    .enqueue_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
                self.record_error(ENQUEUE_TIMEOUT_ERROR.to_string());
                debug!(
                    %topic,
                    timeout_ms = self.config.enqueue_timeout.as_millis(),
                    "sync publisher enqueue timed out; caller should apply backpressure"
                );
                Err(ENQUEUE_TIMEOUT_ERROR.to_string())
            }
            Err(EnqueueError::Closed) => {
                let error = "sync publisher queue closed".to_string();
                self.record_error(error.clone());
                Err(error)
            }
        }
    }

    pub async fn publish_message(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.record(topic, payload);
        self.record_attempt();

        if self.config.redpanda_bootstrap_servers.is_none() {
            let error = "sync publisher disabled".to_string();
            self.record_error(error.clone());
            return Err(error);
        }

        debug!(
            %topic,
            payload_bytes = payload.len(),
            "sync publisher queueing acknowledged Redpanda publish"
        );
        let publish_tx = self.queue_sender()?;
        let (response_tx, response_rx) = oneshot::channel();
        publish_tx
            .send(PublishQueueMessage {
                topic: topic.to_string(),
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
        validate_json_payload(raw_payload)?;

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
        let contents = match parsed.kind {
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
        }?;
        validate_json_payload(&contents)?;
        Ok(contents)
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
            configured: self.config.redpanda_bootstrap_servers.is_some(),
            auth_enabled: self.config.sasl_username.is_some(),
            tls_enabled: self
                .config
                .security_protocol
                .as_deref()
                .map(|protocol| protocol.to_ascii_uppercase().contains("SSL"))
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

    fn record(&self, topic: &str, payload: &str) {
        self.published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(PublishedMessage {
                topic: topic.to_string(),
                payload: payload.to_string(),
            });
    }

    fn record_attempt(&self) {
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health.last_attempt_at = Some(crate::time::now_rfc3339());
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

    fn spool_publish(&self, topic: &str, payload: &str) -> Result<(), String> {
        write_spool_envelope(&self.config.publish_spool_dir, topic, payload)?;
        self.counters.spooled_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn validate_json_payload(raw_payload: &str) -> Result<(), String> {
    serde_json::from_str::<serde_json::Value>(raw_payload)
        .map(|_| ())
        .map_err(|error| format!("sync payload must be valid JSON: {error}"))
}

fn write_spool_envelope(spool_dir: &Path, topic: &str, payload: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(spool_dir)
        .map_err(|error| format!("create sync publish spool {}: {error}", spool_dir.display()))?;
    let created_at = crate::time::now_rfc3339();
    let token = crate::time::file_token_now();
    let id = uuid::Uuid::new_v4().simple();
    let tmp_path = spool_dir.join(format!("{token}-{id}.tmp"));
    let final_path = spool_dir.join(format!("{token}-{id}.json"));
    let envelope = PublishSpoolEnvelope {
        topic: topic.to_string(),
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
    let mut producer = build_redpanda_producer(&config)
        .map_err(|error| {
            record_worker_error(&health, error.clone());
            error
        })
        .ok();

    loop {
        let _ = drain_spooled_messages(&config, &health, &mut producer).await;

        let Some(message) = publish_rx.recv().await else {
            let _ = drain_spooled_messages(&config, &health, &mut producer).await;
            break;
        };

        let result = publish_with_producer(
            &config,
            &health,
            &mut producer,
            &message.topic,
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
    producer: &mut Option<FutureProducer>,
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
        publish_with_producer(
            config,
            health,
            producer,
            &envelope.topic,
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

async fn publish_with_producer(
    config: &SyncPublisherConfig,
    health: &Arc<Mutex<SyncPublisherHealth>>,
    producer: &mut Option<FutureProducer>,
    topic: &str,
    payload: &str,
    source: &str,
) -> Result<(), String> {
    let result = async {
        if producer.is_none() {
            *producer = Some(build_redpanda_producer(config)?);
        }

        let producer_ref = producer.as_ref().expect("producer is initialized above");
        let record = FutureRecord::to(topic).payload(payload).key("");
        producer_ref
            .send(record, config.publish_timeout)
            .await
            .map(|_| ())
            .map_err(|(error, _)| format!("publish Redpanda topic {topic}: {error}"))
    }
    .await;

    match &result {
        Ok(()) => {
            let mut snapshot = health
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            snapshot.last_publish_at = Some(crate::time::now_rfc3339());
            snapshot.last_error = None;
            debug!(
                %topic,
                source,
                payload_bytes = payload.len(),
                "sync publisher Redpanda publish succeeded"
            );
        }
        Err(error) => {
            warn!(
                %error,
                %topic,
                source,
                payload_bytes = payload.len(),
                "sync publisher Redpanda publish failed"
            );
            *producer = None;
            record_worker_error(health, error.clone());
        }
    }

    result
}

fn build_redpanda_producer(config: &SyncPublisherConfig) -> Result<FutureProducer, String> {
    let bootstrap_servers = config
        .redpanda_bootstrap_servers
        .as_deref()
        .ok_or_else(|| "sync publisher disabled".to_string())?;
    let bootstrap_servers = rdkafka_bootstrap_servers(bootstrap_servers);

    let mut client_config = ClientConfig::new();
    client_config
        .set("bootstrap.servers", &bootstrap_servers)
        .set(
            "message.timeout.ms",
            config.publish_timeout.as_millis().to_string(),
        )
        .set(
            "socket.timeout.ms",
            config.connect_timeout.as_millis().to_string(),
        );

    if let Some(value) = &config.security_protocol {
        client_config.set("security.protocol", value);
    }
    if let Some(value) = &config.sasl_mechanisms {
        client_config.set("sasl.mechanisms", value);
    }
    if let Some(value) = &config.sasl_username {
        client_config.set("sasl.username", value);
    }
    if let Some(value) = &config.sasl_password {
        client_config.set("sasl.password", value);
    }
    if let Some(value) = &config.ssl_ca_location {
        client_config.set("ssl.ca.location", value);
    }
    if let Some(value) = &config.ssl_certificate_location {
        client_config.set("ssl.certificate.location", value);
    }
    if let Some(value) = &config.ssl_key_location {
        client_config.set("ssl.key.location", value);
    }

    client_config
        .create()
        .map_err(|error| format!("create Redpanda producer: {error}"))
}

fn rdkafka_bootstrap_servers(redpanda_bootstrap_servers: &str) -> String {
    let trimmed = redpanda_bootstrap_servers.trim();
    let authority = trimmed
        .strip_prefix("redpanda://")
        .unwrap_or(trimmed)
        .split('/')
        .next()
        .unwrap_or_default();

    authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .to_string()
}

#[cfg(test)]
mod rdkafka_bootstrap_tests {
    use super::rdkafka_bootstrap_servers;

    #[test]
    fn keeps_plain_bootstrap_servers() {
        assert_eq!(
            rdkafka_bootstrap_servers("127.0.0.1:9092"),
            "127.0.0.1:9092"
        );
    }

    #[test]
    fn strips_redpanda_scheme_for_librdkafka() {
        assert_eq!(
            rdkafka_bootstrap_servers("redpanda://127.0.0.1:19092"),
            "127.0.0.1:19092"
        );
    }

    #[test]
    fn strips_url_userinfo_for_librdkafka() {
        assert_eq!(
            rdkafka_bootstrap_servers("redpanda://user:pass@redpanda:9092"),
            "redpanda:9092"
        );
    }
}

fn record_worker_error(health: &Arc<Mutex<SyncPublisherHealth>>, error: String) {
    let mut snapshot = health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    snapshot.last_error = Some(error);
}

#[cfg(test)]
mod payload_ref_tests {
    use std::path::Path;

    use super::SyncPublisher;
    use crate::{config::Config, sync::parse_payload_ref};

    #[test]
    fn inline_payload_ref_decodes_to_valid_json() {
        let publisher = SyncPublisher::new(&Config::default().sync);
        let payload_ref = publisher
            .payload_ref_for_event("{\"small\":true}", "2026-04-17T00:00:00Z")
            .unwrap();

        let contents = publisher
            .resolve_payload_ref_contents(&payload_ref)
            .unwrap();
        serde_json::from_str::<serde_json::Value>(&contents).unwrap();
        assert_eq!(contents, "{\"small\":true}");
    }

    #[test]
    fn outbox_payload_ref_file_contains_valid_json() {
        let outbox = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.sync.inline_payload_max_bytes = 1;
        config.sync.outbox_dir = outbox.path().display().to_string();
        let publisher = SyncPublisher::new(&config.sync);
        let payload_ref = publisher
            .payload_ref_for_event(
                "{\"large\":true,\"payload\":\"readable\"}",
                "2026-04-17T00:00:00Z",
            )
            .unwrap();

        let parsed = parse_payload_ref(&payload_ref).unwrap();
        let path = Path::new(&config.sync.outbox_dir).join(parsed.locator);
        let file_contents = std::fs::read_to_string(path).unwrap();
        serde_json::from_str::<serde_json::Value>(&file_contents).unwrap();
        assert_eq!(
            publisher
                .resolve_payload_ref_contents(&payload_ref)
                .unwrap(),
            file_contents
        );
    }

    #[test]
    fn payload_ref_for_event_rejects_non_json_payloads() {
        let publisher = SyncPublisher::new(&Config::default().sync);
        let error = publisher
            .payload_ref_for_event("not json", "2026-04-17T00:00:00Z")
            .unwrap_err();

        assert!(error.contains("valid JSON"));
    }
}

#[cfg(all(test, any()))]
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
        count_spool_pending, drain_spooled_messages, parse_redpanda_endpoint, read_spool_envelope,
        write_spool_envelope, RedpandaPublishSession, SyncPublisher, SyncPublisherConfig,
        SyncPublisherHealth, ENQUEUE_TIMEOUT_ERROR,
    };
    use crate::{
        config::Config,
        sync::{
            parse_payload_ref, ScanRequest, INLINE_PAYLOAD_REF_PREFIX, OUTBOX_PAYLOAD_REF_PREFIX,
        },
    };

    #[test]
    fn parse_redpanda_defaults_port() {
        let endpoint = parse_redpanda_endpoint("redpanda://localhost").unwrap();
        assert_eq!(endpoint.address, "localhost:9092");
        assert_eq!(endpoint.host, "localhost");
        assert!(!endpoint.tls_enabled);
    }

    #[test]
    fn parse_redpanda_supports_tls_scheme() {
        let endpoint = parse_redpanda_endpoint("tls://redpanda.example.internal:4443").unwrap();
        assert_eq!(endpoint.address, "redpanda.example.internal:4443");
        assert_eq!(endpoint.host, "redpanda.example.internal");
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
        assert_eq!(messages[0].topic, crate::sync::SYNC_SCAN_REQUEST_TOPIC);
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
        assert_eq!(messages[0].topic, "wireless.audit");
    }

    #[test]
    fn publish_payload_audit_records_disabled_publisher_without_network() {
        let publisher = SyncPublisher::new(&Config::default().sync);

        let error = publisher
            .publish_payload_audit(crate::sync::PAYLOAD_AUDIT_TOPIC, "{}")
            .unwrap_err();

        assert_eq!(error, "sync publisher disabled");
        let messages = publisher.published_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, crate::sync::PAYLOAD_AUDIT_TOPIC);
        assert_eq!(messages[0].payload, "{}");
    }

    #[tokio::test]
    async fn enqueue_message_spools_when_queue_stays_full() {
        let spool = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.sync.redpanda_bootstrap_servers = Some("127.0.0.1:9092".to_string());
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
        assert_eq!(envelope.topic, "wireless.audit");
        assert_eq!(envelope.payload, "{}");
        let snapshot = publisher.health_snapshot();
        assert_eq!(snapshot.queue_capacity, 1);
        assert_eq!(snapshot.queue_depth, 1);
        assert_eq!(snapshot.spool_pending, 1);
        assert_eq!(snapshot.spooled_total, 1);
        assert_eq!(snapshot.enqueue_timeouts_total, 1);
        publisher.shutdown().await;
    }

    #[tokio::test]
    async fn try_enqueue_message_reports_timeout_without_spooling() {
        let spool = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.sync.redpanda_bootstrap_servers = Some("127.0.0.1:9092".to_string());
        config.sync.publish_enqueue_timeout_ms = 1;
        config.sync.publish_spool_dir = spool.path().display().to_string();
        let publisher = SyncPublisher::new(&config.sync);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        *publisher.publish_tx.lock().unwrap() = Some(tx);

        publisher
            .try_enqueue_message("wireless.audit", "{}")
            .unwrap();
        let error = publisher
            .try_enqueue_message("wireless.audit", "{}")
            .unwrap_err();

        assert_eq!(error, ENQUEUE_TIMEOUT_ERROR);
        assert_eq!(count_spool_pending(spool.path()), 0);
        let snapshot = publisher.health_snapshot();
        assert_eq!(snapshot.queue_capacity, 1);
        assert_eq!(snapshot.queue_depth, 1);
        assert_eq!(snapshot.spooled_total, 0);
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
        let mut session = RedpandaPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
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
        let mut session = RedpandaPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
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
        let mut session = RedpandaPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
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
        assert!(error.contains("Redpanda publish failed"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn persistent_session_publish_allows_non_json_ack_with_error_word() {
        let (client, mut server) = duplex(4096);
        let mut session = RedpandaPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
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
        let (url, server_task) = spawn_mock_redpanda("hello", r#"{}"#).await;
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
        let (url, server_task) = spawn_mock_redpanda("hello", r#"{"error":{"code":500}}"#).await;
        let config = test_publisher_config(url, spool.path());
        let health = Arc::new(Mutex::new(SyncPublisherHealth::default()));
        let mut session = None;

        let error = drain_spooled_messages(&config, &health, &mut session)
            .await
            .unwrap_err();

        assert!(error.contains("Redpanda publish failed"));
        assert_eq!(count_spool_pending(spool.path()), 1);
        let _ = server_task.await.unwrap();
    }

    fn test_publisher_config(
        redpanda_bootstrap_servers: String,
        spool_dir: &Path,
    ) -> SyncPublisherConfig {
        SyncPublisherConfig {
            redpanda_bootstrap_servers: Some(redpanda_bootstrap_servers),
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

    async fn spawn_mock_redpanda(
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

        (format!("redpanda://{address}"), task)
    }
}
