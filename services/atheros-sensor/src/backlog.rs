use async_trait::async_trait;
use deadpool_postgres::{Client, Manager, ManagerConfig, Pool, RecyclingMethod};
use std::str::FromStr;
use thiserror::Error;
use tokio_postgres::{config::Host, Config as PostgresConfig, NoTls};
use tracing::{debug, error, info, warn};

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
        let config = PostgresConfig::from_str(database_url)
            .map_err(|error| BacklogError::InvalidDatabaseUrl(error.to_string()))?;
        let target = database_target(&config);
        let manager = Manager::from_config(
            config,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(2)
            .build()
            .map_err(|error| BacklogError::PoolBuild(error.to_string()))?;
        info!(
            postgres_target = %target,
            pool_max_size = 2,
            "postgres backlog pool initialized"
        );
        Ok(Self { pool })
    }

    async fn client(&self, operation: &'static str) -> Result<Client, BacklogError> {
        let before = self.pool.status();
        match self.pool.get().await {
            Ok(client) => {
                let after = self.pool.status();
                debug!(
                    operation,
                    pool_max_size = after.max_size,
                    pool_size = after.size,
                    pool_available = after.available,
                    pool_waiting = after.waiting,
                    "postgres backlog pool checkout succeeded"
                );
                Ok(client)
            }
            Err(source) => {
                let after = self.pool.status();
                error!(
                    operation,
                    error = %source,
                    error_debug = ?source,
                    pool_max_size = after.max_size,
                    pool_size = after.size,
                    pool_available = after.available,
                    pool_waiting = after.waiting,
                    pool_max_size_before = before.max_size,
                    pool_size_before = before.size,
                    pool_available_before = before.available,
                    pool_waiting_before = before.waiting,
                    "postgres backlog pool checkout failed"
                );
                Err(BacklogError::Pool { operation, source })
            }
        }
    }

    fn log_postgres_error(&self, operation: &'static str, source: &tokio_postgres::Error) {
        let status = self.pool.status();
        let db_error = source.as_db_error();
        error!(
            operation,
            error = %source,
            error_debug = ?source,
            postgres_closed = source.is_closed(),
            pg_code = db_error.map(|error| error.code().code()).unwrap_or(""),
            pg_severity = db_error.map(|error| error.severity()).unwrap_or(""),
            pg_message = db_error.map(|error| error.message()).unwrap_or(""),
            pg_detail = ?db_error.and_then(|error| error.detail()),
            pg_hint = ?db_error.and_then(|error| error.hint()),
            pg_schema = ?db_error.and_then(|error| error.schema()),
            pg_table = ?db_error.and_then(|error| error.table()),
            pg_column = ?db_error.and_then(|error| error.column()),
            pg_constraint = ?db_error.and_then(|error| error.constraint()),
            pool_max_size = status.max_size,
            pool_size = status.size,
            pool_available = status.available,
            pool_waiting = status.waiting,
            "postgres backlog operation failed"
        );
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
        let operation = "save_pending";
        let client = self.client(operation).await?;
        let rows_affected = match client
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
            .await
        {
            Ok(rows_affected) => rows_affected,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };
        debug!(
            dedupe_key,
            stream_name,
            payload_bytes = payload.len(),
            rows_affected,
            "postgres backlog pending row saved"
        );
        Ok(())
    }

    async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
        let operation = "list_pending";
        let client = self.client(operation).await?;
        let rows = match client
            .query(
                "select dedupe_key, stream_name, payload, attempt_count
                 from audit_backlog
                 where status = 'pending'
                 order by updated_at asc
                 limit 100",
                &[],
            )
            .await
        {
            Ok(rows) => rows,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };
        let entries: Vec<_> = rows
            .into_iter()
            .map(|row| BacklogEntry {
                dedupe_key: row.get(0),
                stream_name: row.get(1),
                payload: row.get(2),
                attempt_count: row.get(3),
            })
            .collect();
        debug!(
            pending_count = entries.len(),
            "postgres backlog pending rows loaded"
        );
        Ok(entries)
    }

    async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError> {
        let operation = "mark_synced";
        let client = self.client(operation).await?;
        let rows_affected = match client
            .execute(
                "update audit_backlog
                 set status = 'synced', updated_at = now(), last_error = null
                 where dedupe_key = $1",
                &[&dedupe_key],
            )
            .await
        {
            Ok(rows_affected) => rows_affected,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };
        if rows_affected == 0 {
            warn!(dedupe_key, "postgres backlog mark_synced matched no rows");
        } else {
            debug!(
                dedupe_key,
                rows_affected, "postgres backlog row marked synced"
            );
        }
        Ok(())
    }
}

fn database_target(config: &PostgresConfig) -> String {
    let hosts = config.get_hosts();
    let ports = config.get_ports();
    let host = hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            let port = ports.get(index).copied().unwrap_or(5432);
            match host {
                Host::Tcp(host) => format!("{host}:{port}"),
                Host::Unix(path) => path.display().to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    let dbname = config.get_dbname().unwrap_or("<default>");
    let user = config.get_user().unwrap_or("<default>");
    format!("host={host}; dbname={dbname}; user={user}")
}
