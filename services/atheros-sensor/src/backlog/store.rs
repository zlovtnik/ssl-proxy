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
    #[error("postgres {operation} failed: {source}")]
    Postgres {
        operation: &'static str,
        #[source]
        source: tokio_postgres::Error,
    },
    #[error("postgres pool checkout for {operation} failed: {source}")]
    Pool {
        operation: &'static str,
        #[source]
        source: deadpool_postgres::PoolError,
    },
    #[error("invalid postgres database url: {0}")]
    InvalidDatabaseUrl(String),
    #[error("failed to build postgres connection pool: {0}")]
    PoolBuild(String),
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
}
