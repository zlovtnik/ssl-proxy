use std::str::FromStr;

use async_trait::async_trait;
use deadpool_postgres::{Client, Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::{Config as PostgresConfig, NoTls};
use tracing::{debug, error, info, warn};

use super::{
    pool_diag::database_target,
    store::{BacklogEntry, BacklogError, BacklogStore, IngestRecord},
    wireless_columns::WirelessIngestColumns,
};

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
        let row = match client
            .query_one(
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
                &[&normalized_ssid, &normalized_bssid, &normalized_location],
            )
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
                    status, attempt_count, producer, event_kind, source_mac, bssid,
                    destination_bssid, ssid, signal_dbm, raw_len, frame_control_flags, more_data,
                    retry, power_save, protected, security_flags, wps_device_name,
                    wps_manufacturer, wps_model_name, device_fingerprint, handshake_captured,
                    created_at, updated_at)
                 values ($1, $2, $3, $4, $5::jsonb, $6,
                    'pending', 0, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                    $17, $18, $19, $20, $21, $22, $23, $24, $25, now(), now())
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
                &[
                    &record.dedupe_key,
                    &record.stream_name,
                    &record.observed_at,
                    &record.payload_ref,
                    &payload_json,
                    &record.payload_sha256,
                    &record.producer,
                    &record.event_kind,
                    &wireless.source_mac,
                    &wireless.bssid,
                    &wireless.destination_bssid,
                    &wireless.ssid,
                    &wireless.signal_dbm,
                    &wireless.raw_len,
                    &wireless.frame_control_flags,
                    &wireless.more_data,
                    &wireless.retry,
                    &wireless.power_save,
                    &wireless.protected,
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
