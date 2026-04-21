use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use ssl_proxy::sync::{ScanRequest, SYNC_SCAN_REQUEST_SUBJECT};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::{
    audit::AuditWindow,
    backlog::{BacklogError, BacklogStore},
    model::AuditEntry,
};

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

#[async_trait]
pub trait PublishClient: Send + Sync {
    async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String>;
    fn payload_ref_for_event(&self, raw_payload: &str, observed_at: &str)
        -> Result<String, String>;
}

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

static CIRCUIT_BREAKER: Mutex<Option<Instant>> = Mutex::new(None);
const CIRCUIT_BREAKER_TIMEOUT: Duration = Duration::from_secs(10);
const MEMORY_BACKLOG_SIZE: NonZeroUsize = NonZeroUsize::new(128).unwrap();

lazy_static::lazy_static! {
    static ref MEMORY_BACKLOG: Mutex<LruCache<String, (String, String, String)>> = Mutex::new(LruCache::new(MEMORY_BACKLOG_SIZE));
}

/// Publishes an audit entry and persists failed publishes to durable backlog.
///
/// Returns [`PublishError::Queued`] when the publish failed and the entry could
/// only be retained in the in-memory backlog.
pub async fn publish_entry(
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

    // First attempt normal publish
    match publish_payload(publisher, &payload, &dedupe_key, &entry.observed_at).await {
        Ok(_) => {
            // Try to flush any memory backlog entries now that we're healthy
            let memory_entries = drain_memory_backlog();
            if !memory_entries.is_empty() {
                info!(
                    memory_backlog_entries = memory_entries.len(),
                    "flushing memory backlog to postgres"
                );
            }
            let mut memory_entries = memory_entries.into_iter();
            while let Some((key, (stream, payload, err))) = memory_entries.next() {
                if let Err(backlog_err) = backlog.save_pending(&key, &stream, &payload, &err).await
                {
                    error!(
                        dedupe_key = %key,
                        stream_name = %stream,
                        %backlog_err,
                        "failed to flush memory backlog entry to postgres"
                    );
                    put_memory_backlog(key, stream, payload, err);
                    for (key, (stream, payload, err)) in memory_entries {
                        put_memory_backlog(key, stream, payload, err);
                    }
                    break;
                }
            }

            // Close circuit breaker if it was open
            let mut cb = CIRCUIT_BREAKER.lock().unwrap();
            if cb.is_some() {
                *cb = None;
                tracing::info!("postgres circuit breaker closed, backlog resumed");
            }

            Ok(())
        }
        Err(error) => {
            // Check circuit breaker state
            {
                let mut cb = CIRCUIT_BREAKER.lock().unwrap();
                if let Some(opened_at) = *cb {
                    if opened_at.elapsed() < CIRCUIT_BREAKER_TIMEOUT {
                        // Circuit is open - store in memory only, do not hit postgres
                        let memory_backlog_entries = put_memory_backlog(
                            dedupe_key.clone(),
                            "wireless.audit".to_string(),
                            payload,
                            error.clone(),
                        );
                        warn!(
                            dedupe_key = %dedupe_key,
                            publish_error = %error,
                            memory_backlog_entries,
                            circuit_open_for_ms = opened_at.elapsed().as_millis() as u64,
                            "postgres backlog circuit breaker open; queued audit entry in memory"
                        );
                        return Err(PublishError::Queued(error));
                    } else {
                        // Circuit timeout expired, reset it
                        *cb = None;
                        info!(
                            dedupe_key = %dedupe_key,
                            "postgres backlog circuit breaker probe starting"
                        );
                    }
                }
            }

            // Attempt to persist to postgres backlog
            if let Err(backlog_err) = backlog
                .save_pending(&dedupe_key, "wireless.audit", &payload, &error)
                .await
            {
                // Backlog failed - open circuit breaker
                let mut cb = CIRCUIT_BREAKER.lock().unwrap();
                if cb.is_none() {
                    *cb = Some(Instant::now());
                    error!(
                        dedupe_key = %dedupe_key,
                        publish_error = %error,
                        %backlog_err,
                        circuit_breaker_timeout_ms = CIRCUIT_BREAKER_TIMEOUT.as_millis() as u64,
                        "postgres backlog failed; opening circuit breaker"
                    );
                }

                // Fallback to memory backlog
                let memory_backlog_entries = put_memory_backlog(
                    dedupe_key.clone(),
                    "wireless.audit".to_string(),
                    payload,
                    error.clone(),
                );
                warn!(
                    dedupe_key = %dedupe_key,
                    memory_backlog_entries,
                    "queued audit entry in memory backlog after postgres failure"
                );
                return Err(PublishError::Queued(error));
            } else {
                warn!(
                    dedupe_key = %dedupe_key,
                    publish_error = %error,
                    "publish failed; audit entry persisted to postgres backlog"
                );
            }

            Err(PublishError::Publish(error))
        }
    }
}

pub async fn reconcile_backlog(
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
        let observed_at_dt = match chrono::DateTime::parse_from_rfc3339(&observed_at) {
            Ok(value) => value.with_timezone(&chrono::Utc),
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

        match publish_payload(publisher, &entry.payload, &entry.dedupe_key, &observed_at).await {
            Ok(()) => {
                backlog.mark_synced(&entry.dedupe_key).await?;
                info!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    attempt_count = entry.attempt_count,
                    "backlog entry reconciled"
                );
            }
            Err(error) => {
                warn!(
                    dedupe_key = %entry.dedupe_key,
                    stream_name = %entry.stream_name,
                    attempt_count = entry.attempt_count,
                    %error,
                    "backlog entry publish retry failed"
                );
            }
        }
    }
    Ok(())
}

async fn publish_payload(
    publisher: &dyn PublishClient,
    payload: &str,
    dedupe_key: &str,
    observed_at: &str,
) -> Result<(), String> {
    publisher
        .publish_message("wireless.audit", payload)
        .await
        .map_err(|error| {
            format!("stage=publish_audit subject=wireless.audit dedupe_key={dedupe_key}: {error}")
        })?;
    debug!(
        dedupe_key,
        subject = "wireless.audit",
        payload_bytes = payload.len(),
        "published audit payload"
    );
    let payload_ref = publisher.payload_ref_for_event(payload, observed_at)?;
    let request = ScanRequest {
        stream_name: "wireless.audit".to_string(),
        dedupe_key: dedupe_key.to_string(),
        payload_ref,
        observed_at: observed_at.to_string(),
    };
    let request_payload = serde_json::to_string(&request)
        .map_err(|error| format!("serialize scan request: {error}"))?;
    publisher
        .publish_message(SYNC_SCAN_REQUEST_SUBJECT, &request_payload)
        .await
        .map_err(|error| {
            format!(
                "stage=publish_scan_request subject={SYNC_SCAN_REQUEST_SUBJECT} dedupe_key={dedupe_key}: {error}"
            )
        })?;
    debug!(
        dedupe_key,
        subject = SYNC_SCAN_REQUEST_SUBJECT,
        payload_bytes = request_payload.len(),
        "published scan request"
    );
    Ok(())
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

fn dedupe_key(payload: &str) -> String {
    format!("{:x}", Sha256::digest(payload.as_bytes()))
}

fn drain_memory_backlog() -> Vec<(String, (String, String, String))> {
    let mut backlog = MEMORY_BACKLOG.lock().unwrap();
    let mut entries = Vec::with_capacity(backlog.len());
    while let Some(entry) = backlog.pop_lru() {
        entries.push(entry);
    }
    entries
}

fn put_memory_backlog(
    dedupe_key: String,
    stream_name: String,
    payload: String,
    error: String,
) -> usize {
    let mut backlog = MEMORY_BACKLOG.lock().unwrap();
    if let Some((evicted_key, (evicted_stream, _, _))) =
        backlog.push(dedupe_key, (stream_name, payload, error))
    {
        warn!(
            evicted_dedupe_key = %evicted_key,
            evicted_stream_name = %evicted_stream,
            memory_backlog_size = MEMORY_BACKLOG_SIZE.get(),
            "memory backlog full; evicted oldest entry"
        );
    }
    backlog.len()
}

#[cfg(test)]
mod tests {
    use base64::Engine;

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
        async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String> {
            if self.fail {
                return Err("nats unavailable".to_string());
            }
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

    #[derive(Default)]
    struct MemoryBacklog {
        rows: Mutex<Vec<BacklogEntry>>,
    }

    #[async_trait]
    impl BacklogStore for MemoryBacklog {
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
    }

    struct FailingBacklog;

    #[async_trait]
    impl BacklogStore for FailingBacklog {
        async fn save_pending(
            &self,
            _dedupe_key: &str,
            _stream_name: &str,
            _payload: &str,
            _error: &str,
        ) -> Result<(), BacklogError> {
            Err(BacklogError::InvalidDatabaseUrl("unavailable".to_string()))
        }

        async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
            Ok(Vec::new())
        }

        async fn mark_synced(&self, _dedupe_key: &str) -> Result<(), BacklogError> {
            Ok(())
        }
    }

    fn clear_memory_state() {
        MEMORY_BACKLOG.lock().unwrap().clear();
        *CIRCUIT_BREAKER.lock().unwrap() = None;
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
            "tags": ["wifi", "management"]
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn successful_publish_emits_both_subjects() {
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();

        publish_entry(&backlog, &publisher, entry()).await.unwrap();

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].0, "wireless.audit");
        assert_eq!(published[1].0, SYNC_SCAN_REQUEST_SUBJECT);
        assert!(backlog.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_publish_is_saved_to_backlog() {
        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();

        assert!(publish_entry(&backlog, &publisher, entry()).await.is_err());
        assert_eq!(backlog.rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failed_publish_queued_in_memory_returns_queued() {
        clear_memory_state();
        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        let error = publish_entry(&FailingBacklog, &publisher, entry())
            .await
            .unwrap_err();

        assert!(matches!(error, PublishError::Queued(_)));
        assert_eq!(MEMORY_BACKLOG.lock().unwrap().len(), 1);
        clear_memory_state();
    }

    #[tokio::test]
    async fn reconciliation_retries_and_clears_backlog() {
        let failing = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();
        let event = entry();
        let payload = serde_json::to_string(&event).unwrap();
        let key = dedupe_key(&payload);
        backlog
            .save_pending(&key, "wireless.audit", &payload, "nats unavailable")
            .await
            .unwrap();

        let succeeding = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        reconcile_backlog(
            &backlog,
            &succeeding,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        assert!(backlog.rows.lock().unwrap().is_empty());
        assert_eq!(succeeding.published.lock().unwrap().len(), 2);
        assert!(failing.published.lock().unwrap().is_empty());
    }
}
