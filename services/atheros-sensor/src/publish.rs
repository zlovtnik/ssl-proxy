//! Two-tier persistence strategy for wireless audit event publishing.
//!
//! Implements a dual-path publish pipeline: primary path publishes to NATS; fallback path
//! asks the coordinator to save audit_backlog retry rows. When NATS
//! is unavailable, a circuit breaker opens and events are queued in an in-memory LRU (128
//! entries) until connectivity is restored. The circuit breaker closes automatically after
//! CIRCUIT_BREAKER_TIMEOUT (10s) when a coordinator publish succeeds.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ssl_proxy::{
    sync::{ScanRequest, SYNC_SCAN_REQUEST_SUBJECT},
    transport::ENQUEUE_TIMEOUT_ERROR,
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::{
    audit::{AuditWindow, WirelessBandwidthEvent, BANDWIDTH_SUBJECT},
    backlog::{BacklogError, BacklogStore, IngestRecord},
    model::{AuditEntry, HandshakeAlert},
};

pub const HANDSHAKE_ALERT_SUBJECT: &str = "wifi.alert.handshake";

/// Errors that can occur during audit entry publishing.
///
/// Covers serialization failures, backlog persistence failures, and NATS publish failures.
/// PublishError::Queued is not a pipeline error—it signals that the entry was retained
/// in memory or coordinator backlog for later retry.
#[derive(Debug, Error)]
pub enum PublishError {
    /// Fired when `serde_json::to_string` fails to serialize an `AuditEntry` or alert struct.
    #[error("serialize audit entry: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Fired when both the NATS enqueue and the coordinator backlog fallback fail, leaving the
    /// event with no durable storage path.
    #[error("backlog persistence failed: {0}")]
    Backlog(#[from] BacklogError),
    /// Fired when the NATS publish fails and no fallback path is available (e.g. invalid
    /// `observed_at` timestamp rejected before any side effects).
    #[error("publish failed: {0}")]
    Publish(String),
    /// Fired when the NATS publish fails but the entry was successfully queued in the
    /// in-memory LRU backlog; the pipeline continues without data loss.
    #[error("publish failed and audit entry queued in memory: {0}")]
    Queued(String),
}

/// Trait for publishing audit entries and alerts to NATS. Three methods:
/// enqueue_message is non-blocking (fails fast on queue full), publish_message is async and
/// blocks on backpressure, payload_ref_for_event produces the outbox reference (inline base64
/// or file path) used in the scan request based on payload size vs SYNC_INLINE_PAYLOAD_MAX_BYTES.
#[async_trait]
pub trait PublishClient: Send + Sync {
    fn enqueue_message(&self, subject: &str, payload: &str) -> Result<(), String>;
    async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String>;
    fn payload_ref_for_event(&self, raw_payload: &str, observed_at: &str)
        -> Result<String, String>;
}
/// Wrapper around ssl_proxy::transport::SyncPublisher implementing PublishClient trait.
///
/// Provides non-blocking enqueue, blocking publish with backpressure, and payload_ref
/// generation (inline base64 or outbox file path) for the sync pipeline.
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
    fn enqueue_message(&self, subject: &str, payload: &str) -> Result<(), String> {
        self.publisher.try_enqueue_message(subject, payload)
    }

    async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String> {
        self.publisher.publish_message(subject, payload).await
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

const CIRCUIT_BREAKER_TIMEOUT: Duration = Duration::from_secs(10);
const MEMORY_BACKLOG_SIZE: NonZeroUsize = NonZeroUsize::new(128).unwrap();

type MemoryBacklogEntry = (String, String, String);
pub type SharedPublishState = Arc<Mutex<PublishState>>;

/// Mutable publish state shared across the pipeline via [`SharedPublishState`].
///
/// `circuit_breaker` is `None` when coordinator backlog publish is healthy (circuit closed) and
/// `Some(Instant)` recording when the breaker opened; it resets to `None` after
/// `CIRCUIT_BREAKER_TIMEOUT` elapses and a probe write succeeds.
/// `memory_backlog` is the LRU that absorbs entries while the breaker is open.
pub struct PublishState {
    circuit_breaker: Option<Instant>,
    memory_backlog: LruCache<String, MemoryBacklogEntry>,
}

impl Default for PublishState {
    fn default() -> Self {
        Self {
            circuit_breaker: None,
            memory_backlog: LruCache::new(MEMORY_BACKLOG_SIZE),
        }
    }
}

impl PublishState {
    pub fn shared() -> SharedPublishState {
        Arc::new(Mutex::new(Self::default()))
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
        payload: String,
        error: String,
    ) -> usize {
        if let Some((evicted_key, (evicted_stream, _, _))) = self
            .memory_backlog
            .push(dedupe_key, (stream_name, payload, error))
        {
            warn!(
                evicted_dedupe_key = %evicted_key,
                evicted_stream_name = %evicted_stream,
                memory_backlog_size = MEMORY_BACKLOG_SIZE.get(),
                "memory backlog full; evicted oldest entry"
            );
        }
        self.memory_backlog.len()
    }
}
/// Prepared publish bundle containing payload reference, scan request, and SHA256 hash.
///
/// Generated by prepare_publish before the two-phase write (ingest ledger + NATS).
struct PreparedPublish {
    payload_ref: String,
    request_payload: String,
    payload_sha256: String,
}

/// Two-phase write: publishes the wireless audit payload through the backlog boundary, then
/// enqueues the scan request to NATS.
/// Returns PublishError::Queued when publish fails but entry is retained in memory backlog;
/// this is not a pipeline error and processing continues.
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

    let observed_at_dt = parse_observed_at_timestamp(&entry.observed_at)?;

    let prepared = match prepare_publish(publisher, &payload, &dedupe_key, &entry.observed_at) {
        Ok(prepared) => prepared,
        Err(error) => {
            persist_publish_failure(state, backlog, &dedupe_key, payload, error).await?;
            return Ok(());
        }
    };

    if let Err(backlog_err) = backlog
        .record_ingest(IngestRecord {
            dedupe_key: &dedupe_key,
            stream_name: "wireless.audit",
            observed_at: observed_at_dt,
            payload_ref: &prepared.payload_ref,
            payload: &payload,
            payload_sha256: &prepared.payload_sha256,
            producer: "atheros-sensor",
            event_kind: Some(&entry.event_type),
        })
        .await
    {
        let error = format!("record sync ingest ledger: {backlog_err}");
        queue_in_memory_after_backlog_failure(
            state,
            dedupe_key,
            payload,
            error.clone(),
            backlog_err,
        );
        return Err(PublishError::Queued(error));
    }

    let drained = flush_memory_backlog(state, backlog).await;
    if drained {
        close_backlog_circuit_breaker(state);
    }

    if let Err(error) = enqueue_prepared_publish(publisher, &payload, &dedupe_key, &prepared).await
    {
        persist_publish_failure(state, backlog, &dedupe_key, payload, error).await?;
    }

    Ok(())
}
/// Publishes a handshake alert to the HANDSHAKE_ALERT_SUBJECT.
///
/// Serializes the alert to JSON, computes a SHA256 dedupe key, and enqueues the message
/// with backpressure handling. Returns PublishError::Publish on failure.
pub async fn publish_handshake_alert(
    publisher: &dyn PublishClient,
    alert: &HandshakeAlert,
) -> Result<(), PublishError> {
    let payload = serde_json::to_string(alert)?;
    let key = sha256_hex(&payload);
    queue_publish_with_backpressure(
        publisher,
        "publish_handshake_alert",
        HANDSHAKE_ALERT_SUBJECT,
        &payload,
        &key,
    )
    .await
    .map_err(PublishError::Publish)?;
    debug!(
        dedupe_key = %key,
        subject = HANDSHAKE_ALERT_SUBJECT,
        payload_bytes = payload.len(),
        "queued handshake alert"
    );
    Ok(())
}
/// Publishes a wireless bandwidth event to the BANDWIDTH_SUBJECT.
///
/// Serializes the event to JSON, computes a SHA256 dedupe key, and enqueues the message
/// with backpressure handling. Returns PublishError::Publish on failure.
pub async fn publish_bandwidth_event(
    publisher: &dyn PublishClient,
    event: &WirelessBandwidthEvent,
) -> Result<(), PublishError> {
    let payload = serde_json::to_string(event)?;
    let key = sha256_hex(&payload);
    queue_publish_with_backpressure(
        publisher,
        "publish_bandwidth_event",
        BANDWIDTH_SUBJECT,
        &payload,
        &key,
    )
    .await
    .map_err(PublishError::Publish)?;
    debug!(
        dedupe_key = %key,
        subject = BANDWIDTH_SUBJECT,
        payload_bytes = payload.len(),
        "queued wireless bandwidth event"
    );
    Ok(())
}
/// Publishes a generic JSON-serializable value to the specified NATS subject.
///
/// Serializes the value to JSON, computes a SHA256 dedupe key, and enqueues the message
/// with backpressure handling. Returns PublishError::Publish on failure.
pub async fn publish_json<T: serde::Serialize>(
    publisher: &dyn PublishClient,
    operation: &'static str,
    subject: &str,
    value: &T,
) -> Result<(), PublishError> {
    let payload = serde_json::to_string(value)?;
    let key = sha256_hex(&payload);
    queue_publish_with_backpressure(publisher, operation, subject, &payload, &key)
        .await
        .map_err(PublishError::Publish)?;
    debug!(
        dedupe_key = %key,
        subject,
        payload_bytes = payload.len(),
        "queued wireless JSON event"
    );
    Ok(())
}
/// Persists a failed publish attempt to the backlog store.
///
/// Checks the circuit breaker state first; if open, queues in memory. Otherwise attempts
/// to save to the coordinator backlog. On backlog failure, opens the circuit breaker and queues
/// in memory. Returns PublishError::Queued when the entry is retained in memory.
async fn persist_publish_failure(
    state: &SharedPublishState,
    backlog: &dyn BacklogStore,
    dedupe_key: &str,
    payload: String,
    error: String,
) -> Result<(), PublishError> {
    if circuit_breaker_is_open(state, dedupe_key, &payload, &error) {
        return Err(PublishError::Queued(error));
    }

    if let Err(backlog_err) = backlog
        .save_pending(dedupe_key, "wireless.audit", &payload, &error)
        .await
    {
        queue_in_memory_after_backlog_failure(
            state,
            dedupe_key.to_string(),
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
///
/// Returns true if the breaker is open and within the timeout window, queuing the entry
/// in memory. Returns false if the breaker is closed or the timeout has elapsed, allowing
/// a probe write to the coordinator.
fn circuit_breaker_is_open(
    state: &SharedPublishState,
    dedupe_key: &str,
    payload: &str,
    error: &str,
) -> bool {
    let mut state = state.lock().unwrap();
    if let Some(opened_at) = state.circuit_breaker {
        if opened_at.elapsed() < CIRCUIT_BREAKER_TIMEOUT {
            let memory_backlog_entries = state.put_memory_backlog(
                dedupe_key.to_string(),
                "wireless.audit".to_string(),
                payload.to_string(),
                error.to_string(),
            );
            warn!(
                dedupe_key,
                publish_error = %error,
                memory_backlog_entries,
                circuit_open_for_ms = opened_at.elapsed().as_millis() as u64,
                "backlog circuit breaker open; queued audit entry in memory"
            );
            return true;
        }

        state.circuit_breaker = None;
        info!(dedupe_key, "backlog circuit breaker probe starting");
    }
    false
}

/// Queues an entry in the in-memory LRU backlog after a backlog publish failure.
///
/// Opens the circuit breaker if not already open, then adds the entry to the memory backlog.
/// Logs the circuit breaker state change and the memory queue operation.
fn queue_in_memory_after_backlog_failure(
    state: &SharedPublishState,
    dedupe_key: String,
    payload: String,
    error: String,
    backlog_err: BacklogError,
) {
    let mut state = state.lock().unwrap();
    if state.circuit_breaker.is_none() {
        state.circuit_breaker = Some(Instant::now());
        error!(
            dedupe_key = %dedupe_key,
            publish_error = %error,
            %backlog_err,
            circuit_breaker_timeout_ms = CIRCUIT_BREAKER_TIMEOUT.as_millis() as u64,
            "backlog publish failed; opening circuit breaker"
        );
    }

    let memory_backlog_entries = state.put_memory_backlog(
        dedupe_key.clone(),
        "wireless.audit".to_string(),
        payload,
        error,
    );
    warn!(
        dedupe_key = %dedupe_key,
        memory_backlog_entries,
        "queued audit entry in memory backlog after backlog publish failure"
    );
}

/// Flushes memory backlog to the coordinator; on save_pending failure, re-opens the circuit
/// breaker and re-queues the failed entry plus all remaining entries back into memory.
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
    while let Some((key, (stream, payload, err))) = memory_entries.next() {
        if let Err(backlog_err) = backlog.save_pending(&key, &stream, &payload, &err).await {
            error!(
                dedupe_key = %key,
                stream_name = %stream,
                %backlog_err,
                "failed to flush memory backlog entry to coordinator"
            );
            queue_in_memory_after_backlog_failure(state, key, payload, err, backlog_err);
            for (key, (stream, payload, err)) in memory_entries {
                state
                    .lock()
                    .unwrap()
                    .put_memory_backlog(key, stream, payload, err);
            }
            return false;
        }
    }
    true
}
/// Closes the backlog circuit breaker after a successful write.
///
/// Resets the circuit breaker state to None, allowing normal backlog operations to resume.
/// Logs the state change when the breaker transitions from open to closed.
fn close_backlog_circuit_breaker(state: &SharedPublishState) {
    let mut state = state.lock().unwrap();
    if state.circuit_breaker.is_some() {
        state.circuit_breaker = None;
        tracing::info!("backlog circuit breaker closed, backlog resumed");
    }
}

/// Retries pending backlog entries that fall within the audit window; skips entries outside
/// the window but leaves them pending. Ingest ledger failure keeps the entry in audit_backlog
/// for future retry, preventing data loss when the primary ledger is unavailable.
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
            match prepare_publish(publisher, &entry.payload, &entry.dedupe_key, &observed_at) {
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
        let event_kind = serde_json::from_str::<serde_json::Value>(&entry.payload)
            .ok()
            .and_then(|payload| {
                payload
                    .get("event_type")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            });
        if let Err(backlog_err) = backlog
            .record_ingest(IngestRecord {
                dedupe_key: &entry.dedupe_key,
                stream_name: &entry.stream_name,
                observed_at: observed_at_dt,
                payload_ref: &prepared.payload_ref,
                payload: &entry.payload,
                payload_sha256: &prepared.payload_sha256,
                producer: "atheros-sensor",
                event_kind: event_kind.as_deref(),
            })
            .await
        {
            let error = format!("record sync ingest ledger: {backlog_err}");
            warn!(
                dedupe_key = %entry.dedupe_key,
                stream_name = %entry.stream_name,
                attempt_count = entry.attempt_count,
                backlog_error = %backlog_err,
                "backlog entry ingest ledger record failed"
            );
            if let Err(persist_err) = persist_publish_failure(
                state,
                backlog,
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
                    "failed to persist backlog entry after ingest ledger failure"
                );
            }
            continue;
        }

        if let Err(error) =
            enqueue_prepared_publish(publisher, &entry.payload, &entry.dedupe_key, &prepared).await
        {
            warn!(
                dedupe_key = %entry.dedupe_key,
                stream_name = %entry.stream_name,
                attempt_count = entry.attempt_count,
                %error,
                "backlog entry publish retry enqueue failed after ingest ledger record"
            );
            if let Err(persist_err) = persist_publish_failure(
                state,
                backlog,
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

/// Prepares a publish by generating payload_ref (URL-safe base64 inline ref or outbox file path
/// depending on payload size vs SYNC_INLINE_PAYLOAD_MAX_BYTES), serializing the ScanRequest, and
/// computing the payload SHA256 hash.
fn prepare_publish(
    publisher: &dyn PublishClient,
    payload: &str,
    dedupe_key: &str,
    observed_at: &str,
) -> Result<PreparedPublish, String> {
    let payload_ref = publisher.payload_ref_for_event(payload, observed_at)?;
    let request = ScanRequest {
        stream_name: "wireless.audit".to_string(),
        dedupe_key: dedupe_key.to_string(),
        payload_ref: payload_ref.clone(),
        observed_at: observed_at.to_string(),
    };
    let request_payload = serde_json::to_string(&request)
        .map_err(|error| format!("serialize scan request: {error}"))?;
    Ok(PreparedPublish {
        payload_ref,
        request_payload,
        payload_sha256: sha256_hex(payload),
    })
}
/// Enqueues the scan request to NATS.
///
/// The wireless audit payload is published by `BacklogStore::record_ingest`.
async fn enqueue_prepared_publish(
    publisher: &dyn PublishClient,
    _payload: &str,
    dedupe_key: &str,
    prepared: &PreparedPublish,
) -> Result<(), String> {
    queue_publish_with_backpressure(
        publisher,
        "publish_scan_request",
        SYNC_SCAN_REQUEST_SUBJECT,
        &prepared.request_payload,
        dedupe_key,
    )
    .await?;
    debug!(
        dedupe_key,
        subject = SYNC_SCAN_REQUEST_SUBJECT,
        payload_bytes = prepared.request_payload.len(),
        "queued scan request"
    );
    Ok(())
}
/// Attempts non-blocking enqueue first, falling back to blocking publish on queue full.
///
/// Tries enqueue_message first; on ENQUEUE_TIMEOUT_ERROR, retries with publish_message
/// which blocks until queue space is available. Returns formatted error with context.
async fn queue_publish_with_backpressure(
    publisher: &dyn PublishClient,
    stage: &str,
    subject: &str,
    payload: &str,
    dedupe_key: &str,
) -> Result<(), String> {
    match publisher.enqueue_message(subject, payload) {
        Ok(()) => Ok(()),
        Err(error) if error == ENQUEUE_TIMEOUT_ERROR => {
            debug!(
                dedupe_key,
                subject,
                payload_bytes = payload.len(),
                "sync publisher queue full; retrying with backpressure"
            );
            publisher
                .publish_message(subject, payload)
                .await
                .map_err(|error| {
                    format!("stage={stage} subject={subject} dedupe_key={dedupe_key}: {error}")
                })
        }
        Err(error) => Err(format!(
            "stage={stage} subject={subject} dedupe_key={dedupe_key}: {error}"
        )),
    }
}
/// Extracts the observed_at timestamp string from a JSON payload.
///
/// Parses the payload as JSON and returns the observed_at field value. Returns
/// PublishError::Publish if the field is missing, empty, or the JSON is invalid.
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
/// Parses an RFC3339 timestamp string into a DateTime<Utc>.
///
/// Returns PublishError::Publish with a formatted error message if the timestamp
/// cannot be parsed as a valid RFC3339 datetime.
fn parse_observed_at_timestamp(observed_at: &str) -> Result<DateTime<Utc>, PublishError> {
    DateTime::parse_from_rfc3339(observed_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            PublishError::Publish(format!(
                "invalid observed_at timestamp {observed_at:?}: {error}"
            ))
        })
}
/// Computes a SHA256-based deduplication key from a payload string.
///
/// Returns the hex-encoded SHA256 hash of the payload bytes, used as a unique
/// identifier for deduplication across the publish pipeline.
fn dedupe_key(payload: &str) -> String {
    sha256_hex(payload)
}
/// Computes hex-encoded SHA256 hash of a payload string.
///
/// Used for deduplication keys and payload integrity verification.
fn sha256_hex(payload: &str) -> String {
    ssl_proxy::sha256_hex(&[payload.as_bytes()])
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
        backlog::{BacklogEntry, BacklogError},
    };

    struct MemoryPublisher {
        fail: bool,
        published: Arc<Mutex<Vec<(String, String)>>>,
    }

    #[async_trait]
    impl PublishClient for MemoryPublisher {
        fn enqueue_message(&self, subject: &str, payload: &str) -> Result<(), String> {
            if self.fail {
                return Err("nats unavailable".to_string());
            }
            self.published
                .lock()
                .unwrap()
                .push((subject.to_string(), payload.to_string()));
            Ok(())
        }

        async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String> {
            self.enqueue_message(subject, payload)
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
            Err(BacklogError::Nats {
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
            Err(BacklogError::Nats {
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
                return Err(BacklogError::Nats {
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
    async fn successful_publish_emits_both_subjects() {
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
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].0, SYNC_SCAN_REQUEST_SUBJECT);
        assert_eq!(published[1].0, "wireless.audit");
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
    async fn publishes_handshake_alert_subject() {
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
        assert_eq!(published[0].0, HANDSHAKE_ALERT_SUBJECT);
        assert!(published[0]
            .1
            .contains("\"client_mac\":\"aa:bb:cc:dd:ee:01\""));
    }

    #[tokio::test]
    async fn publishes_bandwidth_event_subject() {
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
        };

        publish_bandwidth_event(&publisher, &event).await.unwrap();

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, BANDWIDTH_SUBJECT);
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
        fn enqueue_message(&self, subject: &str, payload: &str) -> Result<(), String> {
            let mut queue_full_remaining = self.queue_full_remaining.lock().unwrap();
            if *queue_full_remaining > 0 {
                *queue_full_remaining -= 1;
                return Err(ENQUEUE_TIMEOUT_ERROR.to_string());
            }
            self.published
                .lock()
                .unwrap()
                .push((subject.to_string(), payload.to_string()));
            Ok(())
        }

        async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String> {
            self.published
                .lock()
                .unwrap()
                .push((subject.to_string(), payload.to_string()));
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
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].0, SYNC_SCAN_REQUEST_SUBJECT);
        assert_eq!(published[1].0, "wireless.audit");
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

        state.lock().unwrap().put_memory_backlog(
            "dedupe-1".to_string(),
            "wireless.audit".to_string(),
            "{\"event_type\":\"wifi_management_frame\"}".to_string(),
            "nats unavailable".to_string(),
        );

        flush_memory_backlog(&state, &FailingBacklog).await;

        assert_eq!(state.lock().unwrap().memory_backlog.len(), 1);
        assert!(state.lock().unwrap().circuit_breaker.is_some());
    }

    #[tokio::test]
    async fn reconciliation_retries_and_clears_backlog() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        let event = entry();
        let payload = serde_json::to_string(&event).unwrap();
        let key = dedupe_key(&payload);
        backlog
            .save_pending(&key, "wireless.audit", &payload, "nats unavailable")
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
        assert_eq!(publisher.published.lock().unwrap().len(), 2);
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
            .save_pending(&key, "wireless.audit", &payload, "nats unavailable")
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
                "nats unavailable",
            )
            .await
            .unwrap();
        backlog
            .save_pending(
                &second_key,
                "wireless.audit",
                &second_payload,
                "nats unavailable",
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
        assert_eq!(published.len(), 2);
    }

    #[tokio::test]
    async fn reconciliation_skips_malformed_backlog_payload() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        backlog
            .save_pending("bad", "wireless.audit", "{}", "nats unavailable")
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
            .save_pending(&key, "wireless.audit", &payload, "nats unavailable")
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
