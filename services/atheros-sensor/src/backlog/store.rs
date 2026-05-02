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

/// Fallback retry record for failed sync publishes.
///
/// Represents a row in the `audit_backlog` table. When the primary publish path fails,
/// the event is saved here for later retry. This is distinct from [`IngestRecord`],
/// which tracks successful handoffs to the sync pipeline.
#[derive(Clone, Debug)]
pub struct BacklogEntry {
    /// Unique identifier for deduplication across retries.
    pub dedupe_key: String,
    /// NATS stream name where this event should be published.
    #[allow(dead_code)]
    pub stream_name: String,
    /// JSON payload to be published.
    pub payload: String,
    /// Number of retry attempts made for this entry.
    #[allow(dead_code)]
    pub attempt_count: i32,
}

/// Wireless identity context for device claims.
///
/// Represents an authorized wireless network configuration used to validate
/// device claims against known network identities. Loaded from the
/// `authorized_wireless_networks` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedWirelessNetwork {
    /// Network SSID (Service Set Identifier).
    pub ssid: Option<String>,
    /// Basic Service Set Identifier (MAC address of access point).
    pub bssid: Option<String>,
    /// Associated location identifier for this network.
    pub location_id: Option<String>,
    /// Pre-shared key for WPA2/WPA3 decryption.
    pub psk: Option<String>,
}

/// Authoritative sync ledger entry.
///
/// Written to the `sync_scan_ingest` table on every successful publish attempt.
/// This is the authoritative record that an event was handed off to the sync pipeline,
/// distinct from [`BacklogEntry`] which only exists for failed deliveries.
#[derive(Clone, Debug)]
pub struct IngestRecord<'a> {
    /// Unique identifier for deduplication.
    pub dedupe_key: &'a str,
    /// NATS stream name where this event was published.
    pub stream_name: &'a str,
    /// Timestamp when the event was observed.
    pub observed_at: DateTime<Utc>,
    /// Reference identifier for the payload (e.g., file path or message ID).
    pub payload_ref: &'a str,
    /// JSON payload that was published.
    pub payload: &'a str,
    /// SHA-256 hash of the payload for integrity verification.
    pub payload_sha256: &'a str,
    /// Identifier of the service that produced this event.
    pub producer: &'a str,
    /// Optional event type classification.
    pub event_kind: Option<&'a str>,
}

/// Errors that can occur during backlog store operations.
///
/// Covers database connection failures, query errors, and data validation issues.
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

/// Persistence interface for backlog and ingest ledger operations.
///
/// Defines the contract for recording ingested events, saving pending retries,
/// and managing backlog lifecycle. Implementations must be thread-safe (`Send + Sync`).
///
/// # Implementations
///
/// - `PostgresBacklog`: Production implementation using PostgreSQL
/// - Mock implementations for testing
#[async_trait]
pub trait BacklogStore: Send + Sync {
    /// Records a successful ingest event to the sync ledger.
    ///
    /// Writes or updates a row in the `sync_scan_ingest` table with upsert semantics.
    /// On dedupe_key collision, all wireless columns and payload fields are updated.
    ///
    /// IMPORTANT: This provides pre-enqueue durability only. It records that the event
    /// was handed off to the sync pipeline, but does not guarantee downstream delivery
    /// or processing. The event may still fail in subsequent pipeline stages.
    ///
    /// # Parameters
    ///
    /// - `record`: The ingest record containing event metadata and payload
    ///
    /// # Errors
    ///
    /// Returns `BacklogError::Postgres` on database query failures,
    /// `BacklogError::Pool` on connection pool exhaustion, or
    /// `BacklogError::InvalidIngestPayload` if the payload cannot be parsed as JSON.
    async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError>;

    /// Saves a failed publish attempt to the backlog for retry.
    ///
    /// Inserts or updates a row in the `audit_backlog` table. On dedupe_key collision,
    /// increments the attempt count and updates the error message.
    ///
    /// # Parameters
    ///
    /// - `dedupe_key`: Unique identifier for this event
    /// - `stream_name`: NATS stream name where this should be published
    /// - `payload`: JSON payload to be published
    /// - `error`: Error message from the failed publish attempt
    ///
    /// # Errors
    ///
    /// Returns `BacklogError::Postgres` on database query failures or
    /// `BacklogError::Pool` on connection pool exhaustion.
    async fn save_pending(
        &self,
        dedupe_key: &str,
        stream_name: &str,
        payload: &str,
        error: &str,
    ) -> Result<(), BacklogError>;

    /// Retrieves all pending backlog entries awaiting retry.
    ///
    /// Returns entries with status='pending' ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns `BacklogError::Postgres` on database query failures or
    /// `BacklogError::Pool` on connection pool exhaustion.
    async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError>;

    /// Marks a backlog entry as successfully synced.
    ///
    /// Updates the status to 'synced' and records the sync timestamp.
    ///
    /// # Parameters
    ///
    /// - `dedupe_key`: Unique identifier of the entry to mark as synced
    ///
    /// # Errors
    ///
    /// Returns `BacklogError::Postgres` on database query failures or
    /// `BacklogError::Pool` on connection pool exhaustion.
    async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError>;

    /// Removes stale backlog entries that have exceeded retry limits.
    ///
    /// Deletes entries that have either exceeded the maximum attempt count
    /// or are older than the specified age threshold.
    ///
    /// # Parameters
    ///
    /// - `max_attempts`: Maximum number of retry attempts before pruning
    /// - `max_age_hours`: Maximum age in hours before pruning
    ///
    /// # Returns
    ///
    /// The number of entries deleted.
    ///
    /// # Errors
    ///
    /// Returns `BacklogError::Postgres` on database query failures or
    /// `BacklogError::Pool` on connection pool exhaustion.
    async fn prune_stale(&self, max_attempts: i32, max_age_hours: i64)
        -> Result<u64, BacklogError>;
}
