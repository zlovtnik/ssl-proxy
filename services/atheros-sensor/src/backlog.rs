use async_trait::async_trait;
use chrono::{DateTime, Utc};
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

    pub async fn lookup_device_by_mac(
        &self,
        mac: &str,
    ) -> Result<Option<(String, Option<String>)>, BacklogError> {
        let operation = "lookup_device_by_mac";
        let client = self.client(operation).await?;
        let table_exists = match client
            .query_one("select to_regclass('public.devices') is not null", &[])
            .await
        {
            Ok(row) => row.get::<_, bool>(0),
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };
        if !table_exists {
            debug!("postgres devices table is absent; skipping MAC device lookup");
            return Ok(None);
        }

        let normalized_mac = mac.trim().to_ascii_lowercase();
        let row = match client
            .query_opt(
                "select device_id, username
                   from devices
                  where lower(mac_hint) = $1
                  limit 1",
                &[&normalized_mac],
            )
            .await
        {
            Ok(row) => row,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };

        Ok(row.map(|row| (row.get::<_, String>(0), row.get::<_, Option<String>>(1))))
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
    async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError> {
        let operation = "record_ingest";
        let client = self.client(operation).await?;
        let payload: serde_json::Value =
            serde_json::from_str(record.payload).map_err(|source| {
                BacklogError::InvalidIngestPayload {
                    operation,
                    dedupe_key: record.dedupe_key.to_string(),
                    source,
                }
            })?;
        let payload_json = tokio_postgres::types::Json(&payload);
        let wireless = WirelessIngestColumns::from_payload(record.stream_name, &payload);
        let rows_affected = match client
            .execute(
                "insert into sync_scan_ingest
                   (dedupe_key, stream_name, observed_at, payload_ref, payload, payload_sha256,
                    status, attempt_count, producer, event_kind, security_flags, wps_device_name,
                    wps_manufacturer, wps_model_name, device_fingerprint, handshake_captured,
                    created_at, updated_at)
                 values ($1, $2, $3, $4, $5::jsonb, $6,
                    'pending', 0, $7, $8, $9, $10, $11, $12, $13, $14, now(), now())
                 on conflict (dedupe_key)
                 do update set
                    payload_ref = excluded.payload_ref,
                    payload = excluded.payload,
                    payload_sha256 = excluded.payload_sha256,
                    producer = excluded.producer,
                    event_kind = excluded.event_kind,
                    security_flags = excluded.security_flags,
                    wps_device_name = excluded.wps_device_name,
                    wps_manufacturer = excluded.wps_manufacturer,
                    wps_model_name = excluded.wps_model_name,
                    device_fingerprint = excluded.device_fingerprint,
                    handshake_captured = excluded.handshake_captured,
                    updated_at = now()",
                &[
                    &record.dedupe_key,
                    &record.stream_name,
                    &record.observed_at,
                    &record.payload_ref,
                    &payload_json,
                    &record.payload_sha256,
                    &record.producer,
                    &record.event_kind,
                    &wireless.security_flags,
                    &wireless.wps_device_name,
                    &wireless.wps_manufacturer,
                    &wireless.wps_model_name,
                    &wireless.device_fingerprint,
                    &wireless.handshake_captured,
                ],
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
            dedupe_key = record.dedupe_key,
            stream_name = record.stream_name,
            payload_bytes = record.payload.len(),
            rows_affected,
            "sync scan ingest row recorded"
        );
        Ok(())
    }

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

#[derive(Clone, Debug, Default)]
struct WirelessIngestColumns {
    security_flags: i32,
    wps_device_name: Option<String>,
    wps_manufacturer: Option<String>,
    wps_model_name: Option<String>,
    device_fingerprint: Option<String>,
    handshake_captured: bool,
}

impl WirelessIngestColumns {
    fn from_payload(stream_name: &str, payload: &serde_json::Value) -> Self {
        if stream_name != "wireless.audit" {
            return Self::default();
        }

        Self {
            security_flags: payload
                .get("security_flags")
                .and_then(|value| value.as_u64())
                .and_then(|value| i32::try_from(value).ok())
                .unwrap_or(0),
            wps_device_name: payload_string(payload, "wps_device_name"),
            wps_manufacturer: payload_string(payload, "wps_manufacturer"),
            wps_model_name: payload_string(payload, "wps_model_name"),
            device_fingerprint: payload_string(payload, "device_fingerprint"),
            handshake_captured: payload
                .get("handshake_captured")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
        }
    }
}

fn payload_string(payload: &serde_json::Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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

#[cfg(test)]
mod tests {
    use super::WirelessIngestColumns;

    use chrono::{DateTime, Utc};
    use tokio_postgres::types::{Json, ToSql, Type};

    #[test]
    fn chrono_utc_datetime_binds_to_postgres_timestamptz() {
        assert!(<DateTime<Utc> as ToSql>::accepts(&Type::TIMESTAMPTZ));
        assert!(!<&str as ToSql>::accepts(&Type::TIMESTAMPTZ));
    }

    #[test]
    fn json_wrapper_binds_to_postgres_jsonb() {
        assert!(<Json<serde_json::Value> as ToSql>::accepts(&Type::JSONB));
        assert!(!<&str as ToSql>::accepts(&Type::JSONB));
    }

    #[test]
    fn extracts_wireless_ingest_columns_from_payload() {
        let payload = serde_json::json!({
            "security_flags": 26,
            "wps_device_name": "Lobby AP",
            "wps_manufacturer": "Acme",
            "wps_model_name": "Model 7",
            "device_fingerprint": "0123456789abcdef",
            "handshake_captured": true
        });

        let columns = WirelessIngestColumns::from_payload("wireless.audit", &payload);

        assert_eq!(columns.security_flags, 26);
        assert_eq!(columns.wps_device_name.as_deref(), Some("Lobby AP"));
        assert_eq!(columns.wps_manufacturer.as_deref(), Some("Acme"));
        assert_eq!(columns.wps_model_name.as_deref(), Some("Model 7"));
        assert_eq!(
            columns.device_fingerprint.as_deref(),
            Some("0123456789abcdef")
        );
        assert!(columns.handshake_captured);
    }
}
