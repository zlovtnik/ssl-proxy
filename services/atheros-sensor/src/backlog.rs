use async_trait::async_trait;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use std::str::FromStr;
use thiserror::Error;
use tokio_postgres::NoTls;

#[derive(Clone, Debug)]
pub struct BacklogEntry {
    pub dedupe_key: String,
    #[allow(dead_code)]
    pub stream_name: String,
    pub payload: String,
    #[allow(dead_code)]
    pub attempt_count: i32,
}

#[derive(Debug, Error)]
pub enum BacklogError {
    #[error("postgres error: {0}")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("postgres connection pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
    #[error("invalid postgres database url: {0}")]
    InvalidDatabaseUrl(String),
    #[error("failed to build postgres connection pool: {0}")]
    PoolBuild(String),
}

#[async_trait]
pub trait BacklogStore: Send + Sync {
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

pub struct PostgresBacklog {
    pool: Pool,
}

impl PostgresBacklog {
    pub async fn connect(database_url: &str) -> Result<Self, BacklogError> {
        let config = tokio_postgres::Config::from_str(database_url)
            .map_err(|error| BacklogError::InvalidDatabaseUrl(error.to_string()))?;
        let manager = Manager::from_config(
            config,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(2)
            .wait_timeout(Some(std::time::Duration::from_millis(500)))
            .create_timeout(Some(std::time::Duration::from_secs(2)))
            .recycle_timeout(Some(std::time::Duration::from_secs(1)))
            .build()
            .map_err(|error| BacklogError::PoolBuild(error.to_string()))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl BacklogStore for PostgresBacklog {
    async fn save_pending(
        &self,
        dedupe_key: &str,
        stream_name: &str,
        payload: &str,
        error: &str,
    ) -> Result<(), BacklogError> {
        let client = self.pool.get().await?;
        client
            .execute(
                "insert into audit_backlog (dedupe_key, stream_name, payload, status, attempt_count, last_error, created_at, updated_at)
                 values ($1, $2, $3, 'pending', 1, $4, now(), now())
                 on conflict (dedupe_key)
                 do update set
                    status = 'pending',
                    payload = excluded.payload,
                    stream_name = excluded.stream_name,
                    attempt_count = audit_backlog.attempt_count + 1,
                    last_error = excluded.last_error,
                    updated_at = now()",
                &[&dedupe_key, &stream_name, &payload, &error],
            )
            .await?;
        Ok(())
    }

    async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "select dedupe_key, stream_name, payload, attempt_count
                 from audit_backlog
                 where status = 'pending'
                 order by updated_at asc
                 limit 100",
                &[],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| BacklogEntry {
                dedupe_key: row.get(0),
                stream_name: row.get(1),
                payload: row.get(2),
                attempt_count: row.get(3),
            })
            .collect())
    }

    async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError> {
        let client = self.pool.get().await?;
        client
            .execute(
                "update audit_backlog
                 set status = 'synced', updated_at = now(), last_error = null
                 where dedupe_key = $1",
                &[&dedupe_key],
            )
            .await?;
        Ok(())
    }
}
