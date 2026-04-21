use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use ssl_proxy::sync::{ScanRequest, SYNC_SCAN_REQUEST_SUBJECT};
use thiserror::Error;

use crate::{
    audit::AuditWindow,
    backlog::{BacklogEntry, BacklogError, BacklogStore},
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
}

#[async_trait]
pub trait PublishClient: Send + Sync {
    async fn publish_message(&self, subject: &str, payload: &str) -> Result<(), String>;
    fn payload_ref_for_event(&self, raw_payload: &str, observed_at: &str) -> Result<String, String>;
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

    fn payload_ref_for_event(&self, raw_payload: &str, observed_at: &str) -> Result<String, String> {
        self.publisher.payload_ref_for_event(raw_payload, observed_at)
    }
}

pub async fn publish_entry(
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    entry: AuditEntry,
) -> Result<(), PublishError> {
    let payload = serde_json::to_string(&entry)?;
    let dedupe_key = dedupe_key(&payload);
    if let Err(error) = publish_payload(publisher, &payload, &dedupe_key, &entry.observed_at).await {
        backlog
            .save_pending(&dedupe_key, "wireless.audit", &payload, &error)
            .await?;
        return Err(PublishError::Publish(error));
    }
    Ok(())
}

pub async fn reconcile_backlog(
    backlog: &dyn BacklogStore,
    publisher: &dyn PublishClient,
    audit_window: &AuditWindow,
) -> Result<(), PublishError> {
    let pending = backlog.list_pending().await?;
    for entry in pending {
        let observed_at = extract_observed_at(&entry.payload)?;
        if !audit_window.is_active_at(
            chrono::DateTime::parse_from_rfc3339(&observed_at)
                .map_err(|error| PublishError::Publish(error.to_string()))?
                .with_timezone(&chrono::Utc),
        ) {
            continue;
        }

        if publish_payload(publisher, &entry.payload, &entry.dedupe_key, &observed_at)
            .await
            .is_ok()
        {
            backlog.mark_synced(&entry.dedupe_key).await?;
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
    publisher.publish_message("wireless.audit", payload).await?;
    let payload_ref = publisher.payload_ref_for_event(payload, observed_at)?;
    let request = ScanRequest {
        stream_name: "wireless.audit".to_string(),
        dedupe_key: dedupe_key.to_string(),
        payload_ref,
        observed_at: observed_at.to_string(),
    };
    let request_payload =
        serde_json::to_string(&request).map_err(|error| format!("serialize scan request: {error}"))?;
    publisher
        .publish_message(SYNC_SCAN_REQUEST_SUBJECT, &request_payload)
        .await
}

fn extract_observed_at(payload: &str) -> Result<String, PublishError> {
    let parsed: serde_json::Value = serde_json::from_str(payload)?;
    Ok(parsed
        .get("observed_at")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string())
}

fn dedupe_key(payload: &str) -> String {
    format!("{:x}", Sha256::digest(payload.as_bytes()))
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::{audit::AuditWindow, backlog::BacklogError};

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

        fn payload_ref_for_event(&self, raw_payload: &str, _observed_at: &str) -> Result<String, String> {
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
