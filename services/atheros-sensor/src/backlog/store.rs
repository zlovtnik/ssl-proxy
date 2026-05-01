//! BacklogStore trait contract for persistence abstraction.
//!
//! Defines the interface for recording ingested events, saving pending retries, and managing
//! backlog lifecycle. This trait exists for testability (mock implementations) and swap-ability
//! (Postgres, in-memory, or future stores) without coupling the pipeline to a specific backend.
//!
//! # Type notes
//!
//! [`BacklogEntry`]: a row in the `audit_backlog` fallback table; used when the primary
//! publish path fails and the event must be retried later.
//!
//! [`IngestRecord`]: a row written to the `sync_scan_ingest` ledger on every successful
//! publish attempt; it is the authoritative record that an event was handed off to the
//! sync pipeline, distinct from the backlog which only exists for failed deliveries.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct BacklogEntry {
    pub dedupe_key: String,
    #[allow(dead_code)]
    pub stream_name: String,
    pub payload: String,
    #[allow(dead_code)]
    pub attempt_count: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedWirelessNetwork {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub location_id: Option<String>,
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
    /// Fired when a Postgres query or command fails after the connection is established.
    #[error("postgres {operation} failed: {source}")]
    Postgres {
        operation: &'static str,
        #[source]
        source: tokio_postgres::Error,
    },
    /// Fired when the deadpool connection pool cannot check out a connection (pool exhausted
    /// or timed out), distinct from a query-level failure.
    #[error("postgres pool checkout for {operation} failed: {source}")]
    Pool {
        operation: &'static str,
        #[source]
        source: deadpool_postgres::PoolError,
    },
    /// Fired when the DATABASE_URL string cannot be parsed as a valid Postgres connection string.
    #[error("invalid postgres database url: {0}")]
    InvalidDatabaseUrl(String),
    /// Fired when deadpool fails to build the connection pool from the parsed config.
    #[error("failed to build postgres connection pool: {0}")]
    PoolBuild(String),
    /// Fired when a backlog payload cannot be deserialized into the expected JSON shape
    /// during an ingest ledger write.
    #[error("invalid ingest payload for {operation} dedupe_key={dedupe_key}: {source}")]
    InvalidIngestPayload {
        operation: &'static str,
        dedupe_key: String,
        #[source]
        source: serde_json::Error,
    },
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
