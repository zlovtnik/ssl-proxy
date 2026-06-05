use lru::LruCache;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ssl_proxy::{
    sync::{ScanRequest, SYNC_SCAN_REQUEST_TOPIC},
    transport::ENQUEUE_TIMEOUT_ERROR,
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::{
    audit::{AuditWindow, WirelessBandwidthEvent, BANDWIDTH_TOPIC},
    backlog::{BacklogError, BacklogFailureStage, BacklogStore, IngestRecord},
    model::{AuditEntry, HandshakeAlert},
};

pub const WIRELESS_AUDIT_TOPIC: &str = "wireless.audit";
pub const HANDSHAKE_ALERT_TOPIC: &str = "wifi.alert.handshake";

/// Errors that can occur during audit entry publishing.
#[derive(Debug, Error)]
pub enum PublishError {
    #[error("serialize audit entry: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("backlog persistence failed: {0}")]
    Backlog(#[from] BacklogError),
    #[error("publish failed: {0}")]
    Publish(String),
    #[error("publish failed and audit entry queued in memory: {0}")]
    Queued(String),
}

/// Trait for publishing audit entries and alerts to Redpanda.
#[async_trait]
pub trait PublishClient: Send + Sync {
    fn enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String>;
    async fn publish_message(&self, topic: &str, payload: &str) -> Result<(), String>;
    fn payload_ref_for_event(&self, raw_payload: &str, observed_at: &str)
        -> Result<String, String>;
}

/// Wrapper around ssl_proxy::transport::SyncPublisher implementing PublishClient trait.
pub struct SyncPublisherClient {
    publisher: Arc<ssl_proxy::transport::SyncPublisher>,
}

impl SyncPublisherClient {
    pub fn new(publisher: Arc<ssl_proxy::transport::SyncPublisher>) -> Self {
        Self { publisher }
    }
}

#[async_trait]
impl PublishClient for SyncPublisherClient {
    fn enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.publisher.try_enqueue_message(topic, payload)
    }

    async fn publish_message(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.publisher.publish_message(topic, payload).await
    }

    fn payload_ref_for_event(
        &self,
        raw_payload: &str,
        observed_at: &str,
    ) -> Result<String, String> {
        self.publisher
            .payload_ref_for_event(raw_payload, observed_at)
    }
}

const CIRCUIT_BREAKER_INITIAL_TIMEOUT_MS: u64 = 10_000;
const CIRCUIT_BREAKER_MAX_TIMEOUT_MS: u64 = 320_000;
const DEFAULT_MEMORY_BACKLOG_SIZE: usize = 1024;
const MAX_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

type MemoryBacklogEntry = (String, String, String, BacklogFailureStage);
pub type SharedPublishState = Arc<Mutex<PublishState>>;

/// Circuit breaker state machine: closed (healthy), open (failing), half-open (probing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Mutable publish state shared across the pipeline via [`SharedPublishState`].
pub struct PublishState {
    pub circuit_breaker_state: CircuitBreakerState,
    circuit_breaker_opened_at: Option<Instant>,
    circuit_breaker_failure_count: u32,
    circuit_breaker_initial_timeout_ms: u64,
    circuit_breaker_max_timeout_ms: u64,
    circuit_open_last_warn_bucket: Option<u64>,
    memory_backlog: LruCache<String, MemoryBacklogEntry>,
    memory_backlog_capacity: NonZeroUsize,
    journal_path: Option<PathBuf>,
}

impl Default for PublishState {
    fn default() -> Self {
        Self {
            circuit_breaker_state: CircuitBreakerState::Closed,
            circuit_breaker_opened_at: None,
            circuit_breaker_failure_count: 0,
            circuit_breaker_initial_timeout_ms: CIRCUIT_BREAKER_INITIAL_TIMEOUT_MS,
            circuit_breaker_max_timeout_ms: CIRCUIT_BREAKER_MAX_TIMEOUT_MS,
            circuit_open_last_warn_bucket: None,
            memory_backlog: LruCache::new(NonZeroUsize::new(DEFAULT_MEMORY_BACKLOG_SIZE).unwrap()),
            memory_backlog_capacity: NonZeroUsize::new(DEFAULT_MEMORY_BACKLOG_SIZE).unwrap(),
            journal_path: None,
        }
    }
}

impl PublishState {
    #[cfg(test)]
    pub fn shared() -> SharedPublishState {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn shared_with_config(
        capacity: NonZeroUsize,
        journal_path: Option<PathBuf>,
        circuit_breaker_initial_timeout_ms: u64,
        circuit_breaker_max_timeout_ms: u64,
    ) -> SharedPublishState {
        let initial_timeout = circuit_breaker_initial_timeout_ms.max(1);
        let max_timeout = circuit_breaker_max_timeout_ms.max(initial_timeout);
        Arc::new(Mutex::new(Self {
            circuit_breaker_state: CircuitBreakerState::Closed,
            circuit_breaker_opened_at: None,
            circuit_breaker_failure_count: 0,
            circuit_breaker_initial_timeout_ms: initial_timeout,
            circuit_breaker_max_timeout_ms: max_timeout,
            circuit_open_last_warn_bucket: None,
            memory_backlog: LruCache::new(capacity),
            memory_backlog_capacity: capacity,
            journal_path,
        }))
    }

    fn drain_memory_backlog(&mut self) -> Vec<(String, MemoryBacklogEntry)> {
        let mut entries = Vec::with_capacity(self.memory_backlog.len());
        while let Some(entry) = self.memory_backlog.pop_lru() {
            entries.push(entry);
        }
        entries
    }

    fn put_memory_backlog(
        &mut self,
        dedupe_key: String,
        stream_name: String,
        payload: &str,
        error: &str,
        failure_stage: BacklogFailureStage,
    ) -> usize {
        if let Some((evicted_key, (evicted_stream, _, _, _))) = self.memory_backlog.push(
            dedupe_key,
            (
                stream_name,
                payload.to_string(),
                error.to_string(),
                failure_stage,
            ),
        ) {
            error!(
                evicted_dedupe_key = %evicted_key,
                evicted_stream_name = %evicted_stream,
                memory_backlog_capacity = self.memory_backlog_capacity.get(),
                circuit_breaker = ?self.circuit_breaker_state,
                circuit_open_ms = self
                    .circuit_breaker_opened_at
                    .map(|opened_at| opened_at.elapsed().as_millis() as u64),
                "memory backlog eviction -- oldest audit entry lost; Redpanda likely unreachable"
            );
        }
        self.memory_backlog.len()
    }

    fn journal_append(
        &self,
        dedupe_key: &str,
        stream_name: &str,
        payload: &str,
        error: &str,
        failure_stage: BacklogFailureStage,
    ) {
        let Some(ref journal_path) = self.journal_path else {
            return;
        };
        let entry = serde_json::json!({
            "dedupe_key": dedupe_key,
            "stream_name": stream_name,
            "payload": payload,
            "error": error,
            "failure_stage": failure_stage.as_str(),
            "timestamp": ssl_proxy::time::now_rfc3339(),
        });
        let line = serde_json::to_string(&entry).unwrap_or_default();
        let pending_bytes = line.as_bytes().len() as u64 + 1; // +1 for trailing newline
        let existing_size = std::fs::metadata(journal_path)
            .map(|m| m.len())
            .unwrap_or(0);
        if pending_bytes > MAX_JOURNAL_BYTES || existing_size + pending_bytes > MAX_JOURNAL_BYTES {
            warn!(
                journal_path = %journal_path.display(),
                size_bytes = existing_size,
                pending_bytes,
                "publish journal would exceed 32 MB limit; skipping append to prevent disk fill"
            );
            return;
        }
        if let Some(parent) = journal_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal_path)
            .and_then(|mut file| file.write_all(format!("{}\n", line).as_bytes()))
        {
            warn!(%e, journal_path = %journal_path.display(), "failed to append to publish journal");
        }
    }

    fn journal_remove(&self, dedupe_key: &str) {
        let Some(ref journal_path) = self.journal_path else {
            return;
        };
        let content = match std::fs::read_to_string(journal_path) {
            Ok(content) => content,
            Err(_) => return,
        };
        let mut removed = false;
        let remaining: Vec<&str> = content
            .lines()
            .filter(|line| {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) {
                    let keep =
                        parsed.get("dedupe_key").and_then(|value| value.as_str()) != Some(dedupe_key);
                    removed |= !keep;
                    keep
                } else {
                    true
                }
            })
            .collect();
        if !removed {
            return;
        }
        let retained = if remaining.is_empty() {
            String::new()
        } else {
            format!("{}\n", remaining.join("\n"))
        };
        if let Some(parent) = journal_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file_name = journal_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("publish-journal");
        let temp_path = journal_path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
        if std::fs::write(&temp_path, retained.as_bytes()).is_err() {
            return;
        }
        if std::fs::rename(&temp_path, journal_path).is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
    }

    fn circuit_breaker_timeout(&self) -> Duration {
        let exponent = self.circuit_breaker_failure_count.saturating_sub(1).min(63);
        let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let ms = self
            .circuit_breaker_initial_timeout_ms
            .saturating_mul(multiplier)
            .min(self.circuit_breaker_max_timeout_ms);
        Duration::from_millis(ms)
    }

    pub fn memory_backlog_len(&self) -> usize {
        self.memory_backlog.len()
    }

    pub fn memory_backlog_capacity(&self) -> NonZeroUsize {
        self.memory_backlog_capacity
    }

    pub fn journal_bytes(&self) -> u64 {
        self.journal_path
            .as_ref()
            .and_then(|path| std::fs::metadata(path).ok())
            .map(|meta| meta.len())
            .unwrap_or(0)
    }
}

struct PreparedPublish {
    request_payload: String,
    stream_name: String,
    dedupe_key: String,
    payload_ref: String,
    observed_at: DateTime<Utc>,
}

/// Two-phase write: publish the live wireless audit topic, then enqueue one Oracle scan request.
pub async fn publish_entry(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    entry: AuditEntry,
) -> Result<(), PublishError> {
    parse_observed_at_timestamp(&entry.observed_at)?;
    let payload = serde_json::to_string(&entry)?;
    let dedupe_key = dedupe_key(&payload);
    debug!(
        dedupe_key = %dedupe_key,
        observed_at = %entry.observed_at,
        sensor_id = %entry.sensor_id,
        frame_subtype = %entry.frame_subtype,
        payload_bytes = payload.len(),
        "publishing wireless audit entry"
    );

    let prepared = match prepare_publish(
        publisher,
        WIRELESS_AUDIT_TOPIC,
        &payload,
        &dedupe_key,
        &entry.observed_at,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            persist_publish_failure(
                state,
                backlog,
                WIRELESS_AUDIT_TOPIC,
                &dedupe_key,
                payload,
                error,
                BacklogFailureStage::PrePublish,
            )
            .await?;
            return Ok(());
        }
    };

    if let Err(error) = queue_publish_with_backpressure(
        publisher,
        "publish_wireless_audit_topic",
        WIRELESS_AUDIT_TOPIC,
        &payload,
        &dedupe_key,
    )
    .await
    {
        persist_publish_failure(
            state,
            backlog,
            WIRELESS_AUDIT_TOPIC,
            &dedupe_key,
            payload,
            error,
            BacklogFailureStage::PrePublish,
        )
        .await?;
        return Ok(());
    }

    let drained = flush_memory_backlog(state, backlog).await;
    if drained {
        close_backlog_circuit_breaker(state);
    }

    if let Err(error) = backlog
        .record_ingest(IngestRecord {
            dedupe_key: &prepared.dedupe_key,
            stream_name: &prepared.stream_name,
            observed_at: prepared.observed_at,
            payload_ref: &prepared.payload_ref,
        })
        .await
        .map_err(|error| error.to_string())
    {
        persist_publish_failure(
            state,
            backlog,
            WIRELESS_AUDIT_TOPIC,
            &dedupe_key,
            payload,
            error,
            BacklogFailureStage::PostPublish,
        )
        .await?;
    }

    Ok(())
}

/// Publishes a handshake alert to the HANDSHAKE_ALERT_TOPIC.
pub async fn publish_handshake_alert(
    publisher: &dyn PublishClient,
    alert: &HandshakeAlert,
) -> Result<(), PublishError> {
    let payload = serde_json::to_string(alert)?;
    let key = sha256_hex(&payload);
    queue_publish_with_backpressure(
        publisher,
        "publish_handshake_alert",
        HANDSHAKE_ALERT_TOPIC,
        &payload,
        &key,
    )
    .await
    .map_err(PublishError::Publish)?;
    debug!(
        dedupe_key = %key,
        topic = HANDSHAKE_ALERT_TOPIC,
        payload_bytes = payload.len(),
        "queued handshake alert"
    );
    Ok(())
}

/// Publishes a wireless bandwidth event to the BANDWIDTH_TOPIC.
pub async fn publish_bandwidth_event(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    event: &WirelessBandwidthEvent,
) -> Result<(), PublishError> {
    let mut event = event.clone();
    event.published_at = Some(ssl_proxy::time::now_rfc3339());
    publish_oracle_json_durable(
        state,
        backlog,
        publisher,
        "publish_bandwidth_event",
        BANDWIDTH_TOPIC,
        &event,
        &event.window_end,
    )
    .await?;
    let payload = serde_json::to_string(&event)?;
    let key = sha256_hex(&payload);
    debug!(
        dedupe_key = %key,
        topic = BANDWIDTH_TOPIC,
        payload_bytes = payload.len(),
        "queued wireless bandwidth event"
    );
    Ok(())
}

/// Publishes a live Redpanda event and the matching Oracle scan request.
pub async fn publish_oracle_json_durable<T: serde::Serialize>(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    operation: &'static str,
    stream_name: &str,
    value: &T,
    observed_at: &str,
) -> Result<(), PublishError> {
    let payload = serde_json::to_string(value)?;
    publish_oracle_payload_durable(
        state,
        backlog,
        publisher,
        operation,
        stream_name,
        &payload,
        observed_at,
    )
    .await
}
