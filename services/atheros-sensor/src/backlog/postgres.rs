use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::{Client, Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio::time::interval;
use tokio_postgres::{Config as PostgresConfig, NoTls};
use tracing::{debug, error, info, warn};

use super::{
    pool_diag::database_target,
    store::{BacklogEntry, BacklogError, BacklogStore, IngestRecord},
    wireless_columns::WirelessIngestColumns,
};

#[derive(Clone)]
pub struct BatchConfig {
    pub max_size: usize,
    pub flush_interval: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_size: 100,
            flush_interval: Duration::from_millis(500),
        }
    }
}

#[derive(Clone, Debug)]
struct IngestBufferEntry {
    dedupe_key: String,
    stream_name: String,
    observed_at: DateTime<Utc>,
    payload_ref: String,
    payload: serde_json::Value,
    payload_sha256: String,
    producer: String,
    event_kind: Option<String>,
    wireless: WirelessIngestColumns,
}

pub struct PostgresBacklog {
    pool: Pool,
    batch: Arc<Mutex<Vec<IngestBufferEntry>>>,
    batch_config: BatchConfig,
}

impl PostgresBacklog {
    pub async fn connect(
        database_url: &str,
        pool_size: usize,
        batch_config: BatchConfig,
    ) -> Result<Self, BacklogError> {
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
            .max_size(pool_size)
            .build()
            .map_err(|error| BacklogError::PoolBuild(error.to_string()))?;
        info!(
            postgres_target = %target,
            pool_max_size = pool_size,
            batch_max_size = batch_config.max_size,
            batch_flush_ms = batch_config.flush_interval.as_millis(),
            "postgres backlog pool initialized"
        );
        Ok(Self {
            pool,
            batch: Arc::new(Mutex::new(Vec::with_capacity(batch_config.max_size))),
            batch_config,
        })
    }

    pub fn spawn_flush_task(self: Arc<Self>) {
        let flush_interval = self.batch_config.flush_interval;
        let backlog = Arc::clone(&self);
        tokio::spawn(async move {
            let mut tick = interval(flush_interval);
            loop {
                tick.tick().await;
                if let Err(error) = backlog.flush().await {
                    error!(%error, "postgres backlog periodic flush failed");
                }
            }
        });
    }

    pub async fn flush(&self) -> Result<usize, BacklogError> {
        let batch = {
            let mut guard = self.batch.lock().unwrap();
            if guard.is_empty() {
                return Ok(0);
            }
            std::mem::take(&mut *guard)
        };

        let operation = "flush_batch";
        let client = self.client(operation).await?;
        let count = batch.len();

        // Build multi-row INSERT ... ON CONFLICT
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        let mut values_clauses = Vec::with_capacity(count);

        for (idx, entry) in batch.iter().enumerate() {
            let base = idx * 25;
            let mut parts: Vec<String> = Vec::with_capacity(29);
            parts.push(format!("${}", base + 1));   // dedupe_key
            parts.push(format!("${}", base + 2));   // stream_name
            parts.push(format!("${}", base + 3));   // observed_at
            parts.push(format!("${}", base + 4));   // payload_ref
            parts.push(format!("${}::jsonb", base + 5)); // payload
            parts.push(format!("${}", base + 6));   // payload_sha256
            parts.push("'pending'".to_string());     // status
            parts.push("0".to_string());             // attempt_count
            parts.push(format!("${}", base + 7));   // producer
            parts.push(format!("${}", base + 8));   // event_kind
            parts.push(format!("${}", base + 9));   // source_mac
            parts.push(format!("${}", base + 10));  // bssid
            parts.push(format!("${}", base + 11));  // destination_bssid
            parts.push(format!("${}", base + 12));  // ssid
            parts.push(format!("${}", base + 13));  // signal_dbm
            parts.push(format!("${}", base + 14));  // raw_len
            parts.push(format!("${}", base + 15));  // frame_control_flags
            parts.push(format!("${}", base + 16));  // more_data
            parts.push(format!("${}", base + 17));  // retry
            parts.push(format!("${}", base + 18));  // power_save
            parts.push(format!("${}", base + 19));  // protected
            parts.push(format!("${}", base + 20));  // security_flags
            parts.push(format!("${}", base + 21));  // wps_device_name
            parts.push(format!("${}", base + 22));  // wps_manufacturer
            parts.push(format!("${}", base + 23));  // wps_model_name
            parts.push(format!("${}", base + 24));  // device_fingerprint
            parts.push(format!("${}", base + 25));  // handshake_captured
            parts.push("now()".to_string());         // created_at
            parts.push("now()".to_string());         // updated_at
            values_clauses.push(format!("({})", parts.join(", ")));
            params.push(&entry.dedupe_key);
            params.push(&entry.stream_name);
            params.push(&entry.observed_at);
            params.push(&entry.payload_ref);
            params.push(&entry.payload);
            params.push(&entry.payload_sha256);
            params.push(&entry.producer);
            params.push(&entry.event_kind);
            params.push(&entry.wireless.source_mac);
            params.push(&entry.wireless.bssid);
            params.push(&entry.wireless.destination_bssid);
            params.push(&entry.wireless.ssid);
            params.push(&entry.wireless.signal_dbm);
            params.push(&entry.wireless.raw_len);
            params.push(&entry.wireless.frame_control_flags);
            params.push(&entry.wireless.more_data);
            params.push(&entry.wireless.retry);
            params.push(&entry.wireless.power_save);
            params.push(&entry.wireless.protected);
            params.push(&entry.wireless.security_flags);
            params.push(&entry.wireless.wps_device_name);
            params.push(&entry.wireless.wps_manufacturer);
            params.push(&entry.wireless.wps_model_name);
            params.push(&entry.wireless.device_fingerprint);
            params.push(&entry.wireless.handshake_captured);
        }

        if values_clauses.is_empty() {
            return Ok(0);
        }

        let sql = format!(
            "insert into sync_scan_ingest
               (dedupe_key, stream_name, observed_at, payload_ref, payload, payload_sha256,
                status, attempt_count, producer, event_kind, source_mac, bssid,
                destination_bssid, ssid, signal_dbm, raw_len, frame_control_flags, more_data,
                retry, power_save, protected, security_flags, wps_device_name,
                wps_manufacturer, wps_model_name, device_fingerprint, handshake_captured,
                created_at, updated_at)
             values {}
             on conflict (dedupe_key)
             do update set
                payload_ref = excluded.payload_ref,
                payload = excluded.payload,
                payload_sha256 = excluded.payload_sha256,
                producer = excluded.producer,
                event_kind = excluded.event_kind,
                source_mac = excluded.source_mac,
                bssid = excluded.bssid,
                destination_bssid = excluded.destination_bssid,
                ssid = excluded.ssid,
                signal_dbm = excluded.signal_dbm,
                raw_len = excluded.raw_len,
                frame_control_flags = excluded.frame_control_flags,
                more_data = excluded.more_data,
                retry = excluded.retry,
                power_save = excluded.power_save,
                protected = excluded.protected,
                security_flags = excluded.security_flags,
                wps_device_name = excluded.wps_device_name,
                wps_manufacturer = excluded.wps_manufacturer,
                wps_model_name = excluded.wps_model_name,
                device_fingerprint = excluded.device_fingerprint,
                handshake_captured = excluded.handshake_captured,
                updated_at = now()",
            values_clauses.join(", ")
        );

        let rows_affected = match client.execute(&sql, &params).await {
            Ok(rows) => rows,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };

        debug!(
            batch_count = count,
            rows_affected,
            "postgres backlog batch flushed"
        );
        Ok(count)
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
        let stmt = match client
            .prepare(
                "select device_id, username from devices where lower(mac_hint) = $1 limit 1",
            )
            .await
        {
            Ok(stmt) => stmt,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };
        let row = match client.query_opt(&stmt, &[&normalized_mac]).await {
            Ok(row) => row,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };

        Ok(row.map(|row| (row.get::<_, String>(0), row.get::<_, Option<String>>(1))))
    }

    pub async fn is_authorized_wireless_network(
        &self,
        ssid: Option<&str>,
        bssid: Option<&str>,
        location_id: &str,
    ) -> Result<bool, BacklogError> {
        let operation = "is_authorized_wireless_network";
        let client = self.client(operation).await?;
        let table_exists = match client
            .query_one(
                "select to_regclass('public.authorized_wireless_networks') is not null",
                &[],
            )
            .await
        {
            Ok(row) => row.get::<_, bool>(0),
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };
        if !table_exists {
            return Ok(false);
        }

        let normalized_ssid = ssid
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let normalized_bssid = bssid
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase());
        let normalized_location = location_id.trim();

        let stmt = match client
            .prepare(
                "select exists (
                   select 1
                     from authorized_wireless_networks
                    where enabled
                      and (location_id is null or location_id = $3)
                      and (ssid is null or ($1::text is not null and lower(ssid) = lower($1)))
                      and (bssid is null or ($2::text is not null and lower(bssid) = lower($2)))
                      and (ssid is not null or bssid is not null)
                    limit 1
                 )",
            )
            .await
        {
            Ok(stmt) => stmt,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };

        let row = match client
            .query_one(&stmt, &[&normalized_ssid, &normalized_bssid, &normalized_location])
            .await
        {
            Ok(row) => row,
            Err(source) => {
                self.log_postgres_error(operation, &source);
                return Err(BacklogError::Postgres { operation, source });
            }
        };

        Ok(row.get::<_, bool>(0))
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
        let payload: serde_json::Value = serde_json::from_str(record.payload).map_err(|source| {
            BacklogError::InvalidIngestPayload {
                operation: "record_ingest",
                dedupe_key: record.dedupe_key.to_string(),
                source,
            }
        })?;
        let wireless = WirelessIngestColumns::from_payload(record.stream_name, &payload);

        let entry = IngestBufferEntry {
            dedupe_key: record.dedupe_key.to_string(),
            stream_name: record.stream_name.to_string(),
            observed_at: record.observed_at,
            payload_ref: record.payload_ref.to_string(),
            payload,
            payload_sha256: record.payload_sha256.to_string(),
            producer: record.producer.to_string(),
            event_kind: record.event_kind.map(|s| s.to_string()),
            wireless,
        };

        let should_flush = {
            let mut guard = self.batch.lock().unwrap();
            guard.push(entry);
            guard.len() >= self.batch_config.max_size
        };

        if should_flush {
            self.flush().await?;
        }

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
                 limit 1000",
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
