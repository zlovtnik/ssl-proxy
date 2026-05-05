//! BacklogStore trait contract for wireless NATS persistence.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
pub struct BacklogEntry {
    pub dedupe_key: String,
    pub stream_name: String,
    pub payload: String,
    pub attempt_count: i32,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
pub struct AuthorizedWirelessNetwork {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub location_id: Option<String>,
    pub psk: Option<String>,
}

impl std::fmt::Debug for AuthorizedWirelessNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedWirelessNetwork")
            .field("ssid", &self.ssid)
            .field("bssid", &self.bssid)
            .field("location_id", &self.location_id)
            .field("psk", &self.psk.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct IngestRecord<'a> {
    pub dedupe_key: &'a str,
    pub stream_name: &'a str,
    pub observed_at: DateTime<Utc>,
    pub payload_ref: &'a str,
    pub payload: &'a str,
    pub payload_sha256: &'a str,
    pub producer: &'a str,
    pub event_kind: Option<&'a str>,
}

#[derive(Debug, Error)]
pub enum BacklogError {
    #[error("nats {operation} failed: {message}")]
    Nats {
        operation: &'static str,
        message: String,
    },
    #[error("serialize {operation} payload failed: {source}")]
    Serialize {
        operation: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("deserialize {operation} response failed: {source}")]
    Deserialize {
        operation: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("nats request {operation} timed out")]
    Timeout { operation: &'static str },
    #[error("nats request {operation} unsupported when SYNC_NATS_URL is unset")]
    Disabled { operation: &'static str },
}

#[async_trait]
pub trait BacklogStore: Send + Sync {
    async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError>;

    async fn save_pending(
        &self,
        dedupe_key: &str,
        stream_name: &str,
        payload: &str,
        error: &str,
    ) -> Result<(), BacklogError>;

    async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError>;

    async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError>;

    async fn prune_stale(&self, max_attempts: i32, max_age_hours: i64)
        -> Result<u64, BacklogError>;
}
