//! Two-tier persistence strategy for wireless audit event publishing.
//!
//! Implements a dual-path publish pipeline: primary path publishes to Redpanda; fallback path
//! asks the coordinator to save audit_backlog retry rows. When Redpanda
//! is unavailable, a circuit breaker opens and events are queued in an in-memory backlog until
//! connectivity is restored. The circuit breaker uses exponential backoff, with automatic
//! re-probing after the backoff timeout elapses. When the memory backlog cannot be flushed,
//! entries are persisted to a local JSONL journal file for durability across process restarts.

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
    backlog::{BacklogError, BacklogStore},
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
const DEFAULT_JOURNAL_PATH: &str = "/tmp/atheros-sensor-publish-journal.jsonl";

type MemoryBacklogEntry = (String, String, String, String);
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
            memory_backlog: LruCache::new(NonZeroUsize::new(DEFAULT_MEMORY_BACKLOG_SIZE).unwrap()),
            memory_backlog_capacity: NonZeroUsize::new(DEFAULT_MEMORY_BACKLOG_SIZE).unwrap(),
            journal_path: None,
        }
    }
}

impl PublishState {
    pub fn shared() -> SharedPublishState {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn shared_with_config(
        capacity: NonZeroUsize,
        journal_path: Option<PathBuf>,
    ) -> SharedPublishState {
        Arc::new(Mutex::new(Self {
            circuit_breaker_state: CircuitBreakerState::Closed,
            circuit_breaker_opened_at: None,
            circuit_breaker_failure_count: 0,
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
    ) -> usize {
        if let Some((evicted_key, (evicted_stream, _, _, _))) = self.memory_backlog.push(
            dedupe_key,
            (
                stream_name,
                payload.to_string(),
                error.to_string(),
                String::new(),
            ),
        ) {
            warn!(
                evicted_dedupe_key = %evicted_key,
                evicted_stream_name = %evicted_stream,
                memory_backlog_capacity = self.memory_backlog_capacity.get(),
                "memory backlog full; evicted oldest entry"
            );
        }
        self.memory_backlog.len()
    }

    fn journal_append(&self, dedupe_key: &str, stream_name: &str, payload: &str, error: &str) {
        let Some(ref journal_path) = self.journal_path else {
            return;
        };
        if let Some(parent) = journal_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let entry = serde_json::json!({
            "dedupe_key": dedupe_key,
            "stream_name": stream_name,
            "payload": payload,
            "error": error,
            "timestamp": ssl_proxy::time::now_rfc3339(),
        });
        let line = serde_json::to_string(&entry).unwrap_or_default();
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal_path)
            .and_then(|mut file| file.write_all(format!("{}\n", line).as_bytes()))
        {
            warn!(%e, journal_path = %journal_path.display(), "failed to append to publish journal");
        }
    }

    fn circuit_breaker_timeout(&self) -> Duration {
        let exponent = self.circuit_breaker_failure_count.saturating_sub(1).min(63);
        let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let ms = CIRCUIT_BREAKER_INITIAL_TIMEOUT_MS
            .saturating_mul(multiplier)
            .min(CIRCUIT_BREAKER_MAX_TIMEOUT_MS);
        Duration::from_millis(ms)
    }

    pub fn memory_backlog_len(&self) -> usize {
        self.memory_backlog.len()
    }

    pub fn memory_backlog_capacity(&self) -> NonZeroUsize {
        self.memory_backlog_capacity
    }
}

struct PreparedPublish {
    request_payload: String,
}

/// Two-phase write: publish the live wireless audit topic, then enqueue one Oracle scan request.
pub async fn publish_entry(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    entry: AuditEntry,
) -> Result<(), PublishError> {
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
            persist_publish_failure(state, backlog, WIRELESS_AUDIT_TOPIC, &dedupe_key, payload, error).await?;
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
        persist_publish_failure(state, backlog, WIRELESS_AUDIT_TOPIC, &dedupe_key, payload, error).await?;
        return Ok(());
    }

    let drained = flush_memory_backlog(state, backlog).await;
    if drained {
        close_backlog_circuit_breaker(state);
    }

    if let Err(error) = enqueue_prepared_publish(publisher, &dedupe_key, &prepared).await {
        persist_publish_failure(state, backlog, WIRELESS_AUDIT_TOPIC, &dedupe_key, payload, error).await?;
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
    publisher: &dyn PublishClient,
    event: &WirelessBandwidthEvent,
) -> Result<(), PublishError> {
    let mut event = event.clone();
    event.published_at = Some(ssl_proxy::time::now_rfc3339());
    publish_oracle_json(
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
pub async fn publish_oracle_json<T: serde::Serialize>(
    publisher: &dyn PublishClient,
    operation: &'static str,
    stream_name: &str,
    value: &T,
    observed_at: &str,
) -> Result<(), PublishError> {
    let payload = serde_json::to_string(value)?;
    publish_oracle_payload(publisher, operation, stream_name, &payload, observed_at).await
}

pub async fn publish_oracle_payload(
    publisher: &dyn PublishClient,
    operation: &'static str,
    stream_name: &str,
    payload: &str,
    observed_at: &str,
) -> Result<(), PublishError> {
    let key = sha256_hex(payload);
    let prepared = prepare_publish(publisher, stream_name, payload, &key, observed_at)
        .map_err(PublishError::Publish)?;
    queue_publish_with_backpressure(publisher, operation, stream_name, payload, &key)
        .await
        .map_err(PublishError::Publish)?;
    enqueue_prepared_publish(publisher, &key, &prepared)
        .await
        .map_err(PublishError::Publish)?;
    debug!(
        dedupe_key = %key,
        topic = stream_name,
        payload_bytes = payload.len(),
        "queued wireless Oracle-bound event"
    );
    Ok(())
}

/// Publishes a generic JSON-serializable value to the specified Redpanda topic.
pub async fn publish_json<T: serde::Serialize>(
    publisher: &dyn PublishClient,
    operation: &'static str,
    topic: &str,
    value: &T,
) -> Result<(), PublishError> {
    let payload = serde_json::to_string(value)?;
    let key = sha256_hex(&payload);
    queue_publish_with_backpressure(publisher, operation, topic, &payload, &key)
        .await
        .map_err(PublishError::Publish)?;
    debug!(
        dedupe_key = %key,
        topic,
        payload_bytes = payload.len(),
        "queued wireless JSON event"
    );
    Ok(())
}

/// Persists a failed publish attempt to the backlog store.
async fn persist_publish_failure(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    stream_name: &str,
    dedupe_key: &str,
    payload: String,
    error: String,
) -> Result<(), PublishError> {
    if circuit_breaker_is_open(state, stream_name, dedupe_key, &payload, &error) {
        return Err(PublishError::Queued(error));
    }

    if let Err(backlog_err) = backlog
        .save_pending(dedupe_key, stream_name, &payload, &error)
        .await
    {
        queue_in_memory_after_backlog_failure(
            state,
            dedupe_key.to_string(),
            stream_name.to_string(),
            payload,
            error.clone(),
            backlog_err,
        );
        return Err(PublishError::Queued(error));
    }

    warn!(
        dedupe_key,
        publish_error = %error,
        "publish enqueue failed; audit entry sent to coordinator backlog"
    );
    Ok(())
}

/// Checks if the coordinator backlog circuit breaker is open.
fn circuit_breaker_is_open(
    state: &SharedPublishState,
    stream_name: &str,
    dedupe_key: &str,
    payload: &str,
    error: &str,
) -> bool {
    let mut state = state.lock().unwrap();
    match state.circuit_breaker_state {
        CircuitBreakerState::Closed => false,
        CircuitBreakerState::Open => {
            if let Some(opened_at) = state.circuit_breaker_opened_at {
                let timeout = state.circuit_breaker_timeout();
                if opened_at.elapsed() < timeout {
                    let memory_backlog_entries = state.put_memory_backlog(
                        dedupe_key.to_string(),
                        stream_name.to_string(),
                        payload,
                        error,
                    );
                    state.journal_append(dedupe_key, stream_name, payload, error);
                    warn!(
                        dedupe_key,
                        publish_error = %error,
                        memory_backlog_entries,
                        circuit_open_for_ms = opened_at.elapsed().as_millis() as u64,
                        circuit_breaker_timeout_ms = timeout.as_millis() as u64,
                        failure_count = state.circuit_breaker_failure_count,
                        "backlog circuit breaker open; queued audit entry in memory"
                    );
                    return true;
                }
            }
            state.circuit_breaker_state = CircuitBreakerState::HalfOpen;
            state.circuit_breaker_opened_at = None;
            info!(
                dedupe_key,
                "backlog circuit breaker probe starting (half-open)"
            );
            false
        }
        CircuitBreakerState::HalfOpen => false,
    }
}

/// Queues an entry in the in-memory backlog after a backlog publish failure.
fn queue_in_memory_after_backlog_failure(
    state: &SharedPublishState,
    dedupe_key: String,
    stream_name: String,
    payload: String,
    error: String,
    backlog_err: BacklogError,
) {
    let mut s = state.lock().unwrap();
    if s.circuit_breaker_state == CircuitBreakerState::Closed
        || s.circuit_breaker_state == CircuitBreakerState::HalfOpen
    {
        s.circuit_breaker_state = CircuitBreakerState::Open;
        s.circuit_breaker_opened_at = Some(Instant::now());
        s.circuit_breaker_failure_count = s.circuit_breaker_failure_count.saturating_add(1);
        error!(
            dedupe_key = %dedupe_key,
            publish_error = %error,
            %backlog_err,
            circuit_breaker_timeout_ms = s.circuit_breaker_timeout().as_millis() as u64,
            failure_count = s.circuit_breaker_failure_count,
            "backlog publish failed; opening circuit breaker"
        );
    }

    let payload_ref = payload.clone();
    let error_ref = error.clone();
    let memory_backlog_entries = s.put_memory_backlog(
        dedupe_key.clone(),
        stream_name.clone(),
        &payload_ref,
        &error_ref,
    );
    s.journal_append(
        &dedupe_key,
        &stream_name,
        &payload_ref,
        &backlog_err.to_string(),
    );
    warn!(
        dedupe_key = %dedupe_key,
        memory_backlog_entries,
        "queued audit entry in memory backlog after backlog publish failure"
    );
}

/// Flushes memory backlog to the coordinator.
pub(crate) async fn flush_memory_backlog(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
) -> bool {
    let memory_entries = state.lock().unwrap().drain_memory_backlog();
    if !memory_entries.is_empty() {
        info!(
            memory_backlog_entries = memory_entries.len(),
            "flushing memory backlog to coordinator"
        );
    }
    let mut memory_entries = memory_entries.into_iter();
    let mut all_succeeded = true;
    while let Some((key, (stream, payload, err, _))) = memory_entries.next() {
        if let Err(backlog_err) = backlog.save_pending(&key, &stream, &payload, &err).await {
            error!(
                dedupe_key = %key,
                stream_name = %stream,
                %backlog_err,
                "failed to flush memory backlog entry to coordinator"
            );
            queue_in_memory_after_backlog_failure(state, key, stream, payload, err, backlog_err);
            for (remaining_key, (remaining_stream, remaining_payload, remaining_err, _)) in
                memory_entries
            {
                state.lock().unwrap().put_memory_backlog(
                    remaining_key,
                    remaining_stream,
                    &remaining_payload,
                    &remaining_err,
                );
            }
            return false;
        }
        let journal_path = state.lock().unwrap().journal_path.clone();
        if let Some(ref jp) = journal_path {
            remove_journal_entry(jp, &key);
        }
        all_succeeded = true;
    }
    all_succeeded
}

fn remove_journal_entry(journal_path: &std::path::Path, dedupe_key: &str) {
    let content = match std::fs::read_to_string(journal_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let remaining: Vec<&str> = content
        .lines()
        .filter(|line| {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) {
                parsed.get("dedupe_key").and_then(|v| v.as_str()) != Some(dedupe_key)
            } else {
                true
            }
        })
        .collect();
    if remaining.len() < content.lines().count() {
        let _ = std::fs::write(journal_path, remaining.join("\n") + "\n");
    }
}

/// Loads journal entries from disk and replays them through the backlog.
pub async fn replay_journal(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
) -> Result<u64, PublishError> {
    let journal_path = {
        let s = state.lock().unwrap();
        s.journal_path.clone()
    };
    let Some(ref journal_path) = journal_path else {
        return Ok(0);
    };
    let content = match std::fs::read_to_string(journal_path) {
        Ok(c) if !c.trim().is_empty() => c,
        _ => return Ok(0),
    };
    let mut replayed = 0u64;
    for line in content.lines() {
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let dedupe_key = parsed["dedupe_key"].as_str().unwrap_or("").to_string();
        let stream_name = parsed["stream_name"]
            .as_str()
            .unwrap_or("wireless.audit")
            .to_string();
        let payload = parsed["payload"].as_str().unwrap_or("").to_string();
        let error = parsed["error"].as_str().unwrap_or("").to_string();
        if dedupe_key.is_empty() || payload.is_empty() {
            continue;
        }
        match backlog
            .save_pending(&dedupe_key, &stream_name, &payload, &error)
            .await
        {
            Ok(()) => {
                replayed += 1;
                info!(%dedupe_key, %stream_name, "replayed journal entry to coordinator backlog");
            }
            Err(e) => {
                warn!(%dedupe_key, %stream_name, %e, "failed to replay journal entry; will retry via memory flush");
                let mut s = state.lock().unwrap();
                s.put_memory_backlog(dedupe_key, stream_name, &payload, &error);
            }
        }
    }
    if replayed > 0 {
        let _ = std::fs::write(journal_path, "");
        info!(replayed, "publish journal replayed and cleared");
    }
    Ok(replayed)
}

/// Closes the backlog circuit breaker after a successful write.
fn close_backlog_circuit_breaker(state: &SharedPublishState) {
    let mut s = state.lock().unwrap();
    if s.circuit_breaker_state != CircuitBreakerState::Closed {
        s.circuit_breaker_state = CircuitBreakerState::Closed;
        s.circuit_breaker_opened_at = None;
        s.circuit_breaker_failure_count = 0;
        info!("backlog circuit breaker closed, backlog resumed");
    }
}

/// Retries pending backlog entries that fall within the audit window.
pub async fn reconcile_backlog(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    audit_window: &AuditWindow,
) -> Result<(), PublishError> {
    let pending = backlog.list_pending().await?;
    debug!(
        pending_count = pending.len(),
        "starting backlog reconciliation"
    );
    for entry in pending {
        let observed_at = match extract_observed_at(&entry.payload) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    %error,
                    "skipping backlog entry with malformed observed_at"
                );
                continue;
            }
        };
        let observed_at_dt = match parse_observed_at_timestamp(&observed_at) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    observed_at = %observed_at,
                    %error,
                    "skipping backlog entry with invalid observed_at timestamp"
                );
                continue;
            }
        };
        if !audit_window.is_active_at(observed_at_dt) {
            debug!(
                dedupe_key = %entry.dedupe_key,
                stream_name = %entry.stream_name,
                observed_at = %observed_at,
                "skipping backlog entry outside audit window"
            );
            continue;
        }

        let prepared =
            match prepare_publish(publisher, &entry.stream_name, &entry.payload, &entry.dedupe_key, &observed_at) {
                Ok(prepared) => prepared,
                Err(error) => {
                    warn!(
                        dedupe_key = %entry.dedupe_key,
                        stream_name = %entry.stream_name,
                        attempt_count = entry.attempt_count,
                        %error,
                        "backlog entry publish preparation failed"
                    );
                    continue;
                }
            };
        if let Err(error) = enqueue_prepared_publish(publisher, &entry.dedupe_key, &prepared).await
        {
            warn!(
                dedupe_key = %entry.dedupe_key,
                stream_name = %entry.stream_name,
                attempt_count = entry.attempt_count,
                %error,
                "backlog entry publish retry enqueue failed"
            );
            if let Err(persist_err) = persist_publish_failure(
                state,
                backlog,
                &entry.stream_name,
                &entry.dedupe_key,
                entry.payload.clone(),
                error,
            )
            .await
            {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    attempt_count = entry.attempt_count,
                    persist_error = %persist_err,
                    "failed to persist backlog entry after publish retry enqueue failure"
                );
            }
            continue;
        }
        backlog.mark_synced(&entry.dedupe_key).await?;
        info!(
            dedupe_key = %entry.dedupe_key,
            stream_name = %entry.stream_name,
            attempt_count = entry.attempt_count,
            "backlog entry reconciled"
        );
    }
    Ok(())
}

fn prepare_publish(
    publisher: &dyn PublishClient,
    stream_name: &str,
    payload: &str,
    dedupe_key: &str,
    observed_at: &str,
) -> Result<PreparedPublish, String> {
    let payload_ref = publisher.payload_ref_for_event(payload, observed_at)?;
    let request = ScanRequest {
        stream_name: stream_name.to_string(),
        dedupe_key: dedupe_key.to_string(),
        payload_ref: payload_ref.clone(),
        observed_at: observed_at.to_string(),
    };
    let request_payload = serde_json::to_string(&request)
        .map_err(|error| format!("serialize scan request: {error}"))?;
    Ok(PreparedPublish {
        request_payload,
    })
}

async fn enqueue_prepared_publish(
    publisher: &dyn PublishClient,
    dedupe_key: &str,
    prepared: &PreparedPublish,
) -> Result<(), String> {
    queue_publish_with_backpressure(
        publisher,
        "publish_scan_request",
        SYNC_SCAN_REQUEST_TOPIC,
        &prepared.request_payload,
        dedupe_key,
    )
    .await?;
    debug!(
        dedupe_key,
        topic = SYNC_SCAN_REQUEST_TOPIC,
        payload_bytes = prepared.request_payload.len(),
        "queued scan request"
    );
    Ok(())
}

async fn queue_publish_with_backpressure(
    publisher: &dyn PublishClient,
    stage: &str,
    topic: &str,
    payload: &str,
    dedupe_key: &str,
) -> Result<(), String> {
    match publisher.enqueue_message(topic, payload) {
        Ok(()) => Ok(()),
        Err(error) if error == ENQUEUE_TIMEOUT_ERROR => {
            debug!(
                dedupe_key,
                topic,
                payload_bytes = payload.len(),
                "sync publisher queue full; retrying with backpressure"
            );
            publisher
                .publish_message(topic, payload)
                .await
                .map_err(|error| {
                    format!("stage={stage} topic={topic} dedupe_key={dedupe_key}: {error}")
                })
        }
        Err(error) => Err(format!(
            "stage={stage} topic={topic} dedupe_key={dedupe_key}: {error}"
        )),
    }
}

fn extract_observed_at(payload: &str) -> Result<String, PublishError> {
    let parsed: serde_json::Value = serde_json::from_str(payload)?;
    let observed_at = parsed
        .get("observed_at")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| PublishError::Publish("missing observed_at".to_string()))?;
    Ok(observed_at.to_string())
}

fn parse_observed_at_timestamp(observed_at: &str) -> Result<DateTime<Utc>, PublishError> {
    DateTime::parse_from_rfc3339(observed_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            PublishError::Publish(format!(
                "invalid observed_at timestamp {observed_at:?}: {error}"
            ))
        })
}

fn dedupe_key(payload: &str) -> String {
    sha256_hex(payload)
}

fn sha256_hex(payload: &str) -> String {
    ssl_proxy::sha256_hex(&[payload.as_bytes()])
}

/// Periodic drain of memory backlog — runs regardless of circuit breaker state.
pub async fn periodic_memory_backlog_flush(state: &SharedPublishState, backlog: &dyn BacklogStore) {
    let backlog_len = state.lock().unwrap().memory_backlog.len();
    if backlog_len == 0 {
        return;
    }
    info!(
        memory_backlog_entries = backlog_len,
        "periodic memory backlog drain"
    );
    let drained = flush_memory_backlog(state, backlog).await;
    if drained {
        close_backlog_circuit_breaker(state);
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use chrono::NaiveTime;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use super::*;
    use serde_json::json;

    use crate::{
        audit::AuditWindow,
        backlog::{BacklogEntry, BacklogError, IngestRecord},
    };

    struct MemoryPublisher {
        fail: bool,
        published: Arc<Mutex<Vec<(String, String)>>>,
    }

    #[async_trait]
    impl PublishClient for MemoryPublisher {
        fn enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
            if self.fail {
                return Err("redpanda unavailable".to_string());
            }
            self.published
                .lock()
                .unwrap()
                .push((topic.to_string(), payload.to_string()));
            Ok(())
        }

        async fn publish_message(&self, topic: &str, payload: &str) -> Result<(), String> {
            self.enqueue_message(topic, payload)
        }

        fn payload_ref_for_event(
            &self,
            raw_payload: &str,
            _observed_at: &str,
        ) -> Result<String, String> {
            Ok(format!(
                "inline://json/{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_payload)
            ))
        }
    }

    #[derive(Default)]
    struct MemoryBacklog {
        rows: Mutex<Vec<BacklogEntry>>,
        ingest_rows: Mutex<Vec<(String, DateTime<Utc>)>>,
    }

    #[async_trait]
    impl BacklogStore for MemoryBacklog {
        async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError> {
            self.ingest_rows
                .lock()
                .unwrap()
                .push((record.dedupe_key.to_string(), record.observed_at));
            Ok(())
        }

        async fn save_pending(
            &self,
            dedupe_key: &str,
            stream_name: &str,
            payload: &str,
            _error: &str,
        ) -> Result<(), BacklogError> {
            self.rows.lock().unwrap().push(BacklogEntry {
                dedupe_key: dedupe_key.to_string(),
                stream_name: stream_name.to_string(),
                payload: payload.to_string(),
                attempt_count: 1,
            });
            Ok(())
        }

        async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
            Ok(self.rows.lock().unwrap().clone())
        }

        async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError> {
            self.rows
                .lock()
                .unwrap()
                .retain(|entry| entry.dedupe_key != dedupe_key);
            Ok(())
        }

        async fn prune_stale(
            &self,
            _max_attempts: i32,
            _max_age_hours: i64,
        ) -> Result<u64, BacklogError> {
            Ok(0)
        }
    }

    struct FailingBacklog;

    #[async_trait]
    impl BacklogStore for FailingBacklog {
        async fn record_ingest(&self, _record: IngestRecord<'_>) -> Result<(), BacklogError> {
            Err(BacklogError::Redpanda {
                operation: "record_ingest",
                message: "unavailable".to_string(),
            })
        }

        async fn save_pending(
            &self,
            _dedupe_key: &str,
            _stream_name: &str,
            _payload: &str,
            _error: &str,
        ) -> Result<(), BacklogError> {
            Err(BacklogError::Redpanda {
                operation: "save_pending",
                message: "unavailable".to_string(),
            })
        }

        async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
            Ok(Vec::new())
        }

        async fn mark_synced(&self, _dedupe_key: &str) -> Result<(), BacklogError> {
            Ok(())
        }

        async fn prune_stale(
            &self,
            _max_attempts: i32,
            _max_age_hours: i64,
        ) -> Result<u64, BacklogError> {
            Ok(0)
        }
    }

    struct SelectiveIngestFailBacklog {
        rows: Mutex<Vec<BacklogEntry>>,
        ingest_rows: Mutex<Vec<String>>,
        failing_keys: HashSet<String>,
    }

    impl SelectiveIngestFailBacklog {
        fn new(failing_keys: impl IntoIterator<Item = String>) -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                ingest_rows: Mutex::new(Vec::new()),
                failing_keys: failing_keys.into_iter().collect(),
            }
        }
    }

    #[async_trait]
    impl BacklogStore for SelectiveIngestFailBacklog {
        async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError> {
            if self.failing_keys.contains(record.dedupe_key) {
                return Err(BacklogError::Redpanda {
                    operation: "record_ingest",
                    message: "ingest ledger unavailable".to_string(),
                });
            }

            self.ingest_rows
                .lock()
                .unwrap()
                .push(record.dedupe_key.to_string());
            Ok(())
        }

        async fn save_pending(
            &self,
            dedupe_key: &str,
            stream_name: &str,
            payload: &str,
            _error: &str,
        ) -> Result<(), BacklogError> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(existing) = rows.iter_mut().find(|row| row.dedupe_key == dedupe_key) {
                existing.stream_name = stream_name.to_string();
                existing.payload = payload.to_string();
                existing.attempt_count += 1;
                return Ok(());
            }

            rows.push(BacklogEntry {
                dedupe_key: dedupe_key.to_string(),
                stream_name: stream_name.to_string(),
                payload: payload.to_string(),
                attempt_count: 1,
            });
            Ok(())
        }

        async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
            Ok(self.rows.lock().unwrap().clone())
        }

        async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError> {
            self.rows
                .lock()
                .unwrap()
                .retain(|entry| entry.dedupe_key != dedupe_key);
            Ok(())
        }

        async fn prune_stale(
            &self,
            _max_attempts: i32,
            _max_age_hours: i64,
        ) -> Result<u64, BacklogError> {
            Ok(0)
        }
    }

    fn test_state() -> SharedPublishState {
        PublishState::shared()
    }

    fn entry() -> AuditEntry {
        serde_json::from_value(json!({
            "event_type": "wifi_management_frame",
            "observed_at": "2026-04-20T12:00:00Z",
            "sensor_id": "00:11:22:33:44:55",
            "location_id": "North-Wing-Entry",
            "interface": "wlan0",
            "channel": 6,
            "bssid": "10:20:30:40:50:60",
            "source_mac": "10:20:30:40:50:60",
            "destination_mac": "ff:ff:ff:ff:ff:ff",
            "ssid": "CorpWiFi",
            "frame_subtype": "beacon",
            "signal_dbm": -42,
            "sequence_number": 1,
            "raw_len": 44,
            "tags": ["wifi", "management"],
            "device_id": null,
            "username": null,
            "identity_source": "unknown"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn successful_publish_emits_both_topics() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();

        publish_entry(&state, &backlog, &publisher, entry())
            .await
            .unwrap();

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, SYNC_SCAN_REQUEST_TOPIC);
        assert!(backlog.rows.lock().unwrap().is_empty());
        let ingest_rows = backlog.ingest_rows.lock().unwrap();
        assert_eq!(ingest_rows.len(), 1);
        assert_eq!(
            ingest_rows[0].1,
            DateTime::parse_from_rfc3339("2026-04-20T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[tokio::test]
    async fn publishes_handshake_alert_topic() {
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let alert = HandshakeAlert {
            schema_version: 1,
            observed_at: "2026-04-20T12:00:00Z".to_string(),
            sensor_id: "sensor-1".to_string(),
            location_id: "lab".to_string(),
            interface: "wlan0".to_string(),
            bssid: "10:20:30:40:50:60".to_string(),
            client_mac: "aa:bb:cc:dd:ee:01".to_string(),
            signal_dbm: Some(-42),
            pmkid: None,
        };

        publish_handshake_alert(&publisher, &alert).await.unwrap();

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, HANDSHAKE_ALERT_TOPIC);
        assert!(published[0]
            .1
            .contains("\"client_mac\":\"aa:bb:cc:dd:ee:01\""));
    }

    #[tokio::test]
    async fn publishes_bandwidth_event_topic() {
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let event = WirelessBandwidthEvent {
            schema_version: 1,
            event_type: "wireless_bandwidth_window".to_string(),
            window_start: "2026-04-20T12:00:00Z".to_string(),
            window_end: "2026-04-20T12:01:00Z".to_string(),
            sensor_id: "sensor-1".to_string(),
            location_id: "lab".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            source_mac: "aa:bb:cc:dd:ee:01".to_string(),
            destination_bssid: "10:20:30:40:50:60".to_string(),
            ssid: Some("CorpWiFi".to_string()),
            bytes: 1024,
            frame_count: 2,
            retry_count: 1,
            more_data_count: 1,
            power_save_count: 0,
            strongest_signal_dbm: Some(-42),
            external_bssid: true,
            threshold_exceeded: false,
            frame_size_histogram: crate::audit::FrameSizeHistogram {
                under_100: 0,
                range_100_500: 1,
                range_500_1000: 1,
                range_1000_1500: 0,
            },
            inter_arrival_p50_ms: Some(500),
            wall_clock_delta_ms: None,
            window_is_partial: false,
            published_at: None,
        };

        publish_bandwidth_event(&publisher, &event).await.unwrap();

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, BANDWIDTH_TOPIC);
        assert!(published[0]
            .1
            .contains("\"event_type\":\"wireless_bandwidth_window\""));
    }

    #[tokio::test]
    async fn failed_publish_is_saved_to_backlog_without_pipeline_error() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();

        publish_entry(&state, &backlog, &publisher, entry())
            .await
            .unwrap();
        assert_eq!(backlog.rows.lock().unwrap().len(), 1);
        assert_eq!(backlog.ingest_rows.lock().unwrap().len(), 1);
    }

    struct QueueFullOnEnqueuePublisher {
        published: Arc<Mutex<Vec<(String, String)>>>,
        queue_full_remaining: Mutex<usize>,
    }

    #[async_trait]
    impl PublishClient for QueueFullOnEnqueuePublisher {
        fn enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
            let mut queue_full_remaining = self.queue_full_remaining.lock().unwrap();
            if *queue_full_remaining > 0 {
                *queue_full_remaining -= 1;
                return Err(ENQUEUE_TIMEOUT_ERROR.to_string());
            }
            self.published
                .lock()
                .unwrap()
                .push((topic.to_string(), payload.to_string()));
            Ok(())
        }

        async fn publish_message(&self, topic: &str, payload: &str) -> Result<(), String> {
            self.published
                .lock()
                .unwrap()
                .push((topic.to_string(), payload.to_string()));
            Ok(())
        }

        fn payload_ref_for_event(
            &self,
            raw_payload: &str,
            _observed_at: &str,
        ) -> Result<String, String> {
            Ok(format!(
                "inline://json/{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_payload)
            ))
        }
    }

    #[tokio::test]
    async fn queue_full_is_retried_with_backpressure_before_backlog_fallback() {
        let state = test_state();
        let publisher = QueueFullOnEnqueuePublisher {
            published: Arc::new(Mutex::new(Vec::new())),
            queue_full_remaining: Mutex::new(1),
        };
        let backlog = MemoryBacklog::default();

        publish_entry(&state, &backlog, &publisher, entry())
            .await
            .unwrap();

        assert!(backlog.rows.lock().unwrap().is_empty());
        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, SYNC_SCAN_REQUEST_TOPIC);
    }

    #[tokio::test]
    async fn invalid_observed_at_is_rejected_before_side_effects() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();
        let mut event = entry();
        event.observed_at = "not-a-timestamp".to_string();

        let error = publish_entry(&state, &backlog, &publisher, event)
            .await
            .unwrap_err();

        assert!(
            matches!(error, PublishError::Publish(message) if message.contains("invalid observed_at timestamp"))
        );
        assert!(publisher.published.lock().unwrap().is_empty());
        assert!(backlog.rows.lock().unwrap().is_empty());
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
        assert!(state.lock().unwrap().memory_backlog.is_empty());
    }

    #[tokio::test]
    async fn failed_publish_queued_in_memory_returns_queued() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        let error = publish_entry(&state, &FailingBacklog, &publisher, entry())
            .await
            .unwrap_err();

        assert!(matches!(error, PublishError::Queued(_)));
        assert_eq!(state.lock().unwrap().memory_backlog.len(), 1);
    }

    #[tokio::test]
    async fn flush_memory_backlog_opens_circuit_breaker_when_save_pending_fails() {
        let state = test_state();
        let payload = "{\"event_type\":\"wifi_management_frame\"}".to_string();
        let error = "redpanda unavailable".to_string();

        state.lock().unwrap().put_memory_backlog(
            "dedupe-1".to_string(),
            "wireless.audit".to_string(),
            &payload,
            &error,
        );

        flush_memory_backlog(&state, &FailingBacklog).await;

        assert_eq!(state.lock().unwrap().memory_backlog.len(), 1);
        assert_eq!(
            state.lock().unwrap().circuit_breaker_state,
            CircuitBreakerState::Open
        );
    }

    #[tokio::test]
    async fn reconciliation_retries_and_clears_backlog() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        let event = entry();
        let payload = serde_json::to_string(&event).unwrap();
        let key = dedupe_key(&payload);
        backlog
            .save_pending(&key, "wireless.audit", &payload, "redpanda unavailable")
            .await
            .unwrap();

        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        assert!(backlog.rows.lock().unwrap().is_empty());
        assert_eq!(publisher.published.lock().unwrap().len(), 1);
        assert_eq!(backlog.ingest_rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn reconciliation_enqueue_failure_keeps_backlog_entry_pending() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        let event = entry();
        let payload = serde_json::to_string(&event).unwrap();
        let key = dedupe_key(&payload);
        backlog
            .save_pending(&key, "wireless.audit", &payload, "redpanda unavailable")
            .await
            .unwrap();

        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        let rows = backlog.rows.lock().unwrap().clone();
        assert!(!rows.is_empty());
        assert!(rows.iter().any(|row| row.dedupe_key == key));
        assert_eq!(backlog.ingest_rows.lock().unwrap().len(), 1);
        assert!(publisher.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reconciliation_ingest_failure_is_persisted_and_processing_continues() {
        let state = test_state();

        let mut first = entry();
        first.sequence_number = Some(1);
        let first_payload = serde_json::to_string(&first).unwrap();
        let first_key = dedupe_key(&first_payload);

        let mut second = entry();
        second.sequence_number = Some(2);
        let second_payload = serde_json::to_string(&second).unwrap();
        let second_key = dedupe_key(&second_payload);

        let backlog = SelectiveIngestFailBacklog::new([first_key.clone()]);
        backlog
            .save_pending(
                &first_key,
                "wireless.audit",
                &first_payload,
                "redpanda unavailable",
            )
            .await
            .unwrap();
        backlog
            .save_pending(
                &second_key,
                "wireless.audit",
                &second_payload,
                "redpanda unavailable",
            )
            .await
            .unwrap();

        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        let pending = backlog.rows.lock().unwrap().clone();
        assert!(pending.iter().any(|row| row.dedupe_key == first_key));
        assert!(!pending.iter().any(|row| row.dedupe_key == second_key));

        let ingested = backlog.ingest_rows.lock().unwrap().clone();
        assert_eq!(ingested, vec![second_key]);

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
    }

    #[tokio::test]
    async fn reconciliation_skips_malformed_backlog_payload() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        backlog
            .save_pending("bad", "wireless.audit", "{}", "redpanda unavailable")
            .await
            .unwrap();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        assert_eq!(backlog.rows.lock().unwrap().len(), 1);
        assert!(publisher.published.lock().unwrap().is_empty());
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reconciliation_skips_entries_outside_audit_window() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        let event = entry();
        let payload = serde_json::to_string(&event).unwrap();
        let key = dedupe_key(&payload);
        backlog
            .save_pending(&key, "wireless.audit", &payload, "redpanda unavailable")
            .await
            .unwrap();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(
                None,
                None,
                Some(NaiveTime::from_hms_opt(0, 0, 0).unwrap()),
                Some(NaiveTime::from_hms_opt(0, 1, 0).unwrap()),
            ),
        )
        .await
        .unwrap();

        assert_eq!(backlog.rows.lock().unwrap().len(), 1);
        assert!(publisher.published.lock().unwrap().is_empty());
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
    }
}
