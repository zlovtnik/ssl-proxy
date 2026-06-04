use std::{fs, time::Duration};

use oracle::Connection;
use r2d2_oracle::OracleConnectionManager;

use super::proxy_db::{insert_event_batch_transaction, is_proxy_events_batch_row_duplicate};
use super::proxy_types::{BlockedEventInsert, ProxyEventInsert};
use super::sink_trait::ProxyEventSink;
use super::types::OracleConnection;
use super::wireless_db_alerts::{
    insert_wireless_deauth_flood_transaction, insert_wireless_pmf_attack_transaction,
    insert_wireless_rogue_ap_transaction, insert_wireless_signal_anomaly_transaction,
};
use super::wireless_db_bandwidth::insert_wireless_bandwidth_transaction;
use super::wireless_db_frames::insert_wireless_audit_frames_transaction;
use super::wireless_db_inventory::{
    insert_wireless_client_inventory_transaction, insert_wireless_probe_requests_transaction,
};
use super::wireless_types::{
    WirelessAuditFrameInsert, WirelessBandwidthInsert, WirelessClientInventoryInsert,
    WirelessDeauthFloodInsert, WirelessPmfAttackInsert, WirelessProbeRequestInsert,
    WirelessRogueApInsert, WirelessSignalAnomalyInsert,
};

pub struct OracleProxyEventSink {
    connection: OracleConnection,
}

impl OracleProxyEventSink {
    pub fn connect_from_env() -> Result<Self, String> {
        let connect_string = crate::env::required_env("ORACLE_CONN")?;
        let user = crate::env::required_env("ORACLE_USER")?;
        let password_file = crate::env::required_env("ORACLE_PASS_FILE")?;
        let password = fs::read_to_string(&password_file)
            .map_err(|error| format!("read Oracle password file {password_file}: {error}"))?;
        let password = password.trim_end_matches(['\r', '\n']);
        let start = std::time::Instant::now();
        let span = oracle_span("oracle.connect_direct");
        let connection = span
            .in_scope(|| Connection::connect(user.as_str(), password, connect_string.as_str()))
            .map_err(|error| {
                span.record("status", "error");
                format!(
                    "connect Oracle {connect_string}: {}",
                    crate::log::error_chain(&error)
                )
            })?;
        let duration_ms = start.elapsed().as_millis();
        span.record("status", "ok");
        crate::metrics::record_oracle_call("oracle.connect_direct", true, duration_ms);
        eprintln!(
            "service=oracle-worker event=connection_acquired pool=false duration_ms={}",
            duration_ms
        );
        Ok(Self {
            connection: OracleConnection::Direct(connection),
        })
    }

    pub fn connect_from_pool(pool: &r2d2::Pool<OracleConnectionManager>) -> Result<Self, String> {
        let start = std::time::Instant::now();
        let span = oracle_span("oracle.pool_acquire");
        let connection = span.in_scope(|| pool.get()).map_err(|error| {
            span.record("status", "error");
            crate::metrics::record_oracle_call(
                "oracle.pool_acquire",
                false,
                start.elapsed().as_millis(),
            );
            format!(
                "get Oracle connection from pool (pool_size={} idle={} state={:?}): {}",
                pool.max_size(),
                pool.state().idle_connections,
                pool.state(),
                crate::log::error_chain(&error)
            )
        })?;
        span.record("status", "ok");
        let timeout_secs = crate::env::env_or_default("ORACLE_STATEMENT_TIMEOUT_SECS", "30")
            .parse()
            .unwrap_or(30u64);
        connection
            .set_call_timeout(Some(Duration::from_secs(timeout_secs)))
            .map_err(|error| {
                format!(
                    "set Oracle call timeout to {timeout_secs}s: {}",
                    crate::log::error_chain(&error)
                )
            })?;
        let duration_ms = start.elapsed().as_millis();
        crate::metrics::record_oracle_call("oracle.pool_acquire", true, duration_ms);
        eprintln!(
            "service=oracle-worker event=connection_acquired pool=true duration_ms={}",
            duration_ms
        );
        Ok(Self {
            connection: OracleConnection::Pooled(connection),
        })
    }

    pub fn ping(&self) -> Result<(), String> {
        self.connection
            .ping()
            .map_err(|error| format!("ping Oracle: {}", crate::log::error_chain(&error)))
    }
}

impl ProxyEventSink for OracleProxyEventSink {
    fn insert_proxy_events(
        &mut self,
        batch_id: &str,
        rows: &[ProxyEventInsert],
        blocked_rows: &[BlockedEventInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_proxy_events", || {
            insert_event_batch_transaction(&self.connection, batch_id, rows, blocked_rows)
        });
        if let Err(error) = result {
            let _ = self.connection.rollback();
            if is_proxy_events_batch_row_duplicate(&error) {
                let retry_result = record_call("oracle.insert_proxy_events_retry", || {
                    insert_event_batch_transaction(&self.connection, batch_id, rows, blocked_rows)
                });
                if retry_result.is_err() {
                    let _ = self.connection.rollback();
                }
                return retry_result;
            }
            return Err(error);
        }
        result
    }

    fn insert_wireless_audit_frames(
        &mut self,
        batch_id: &str,
        rows: &[WirelessAuditFrameInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_wireless_audit_frames", || {
            insert_wireless_audit_frames_transaction(&self.connection, batch_id, rows)
        });
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_bandwidth(
        &mut self,
        batch_id: &str,
        rows: &[WirelessBandwidthInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_wireless_bandwidth", || {
            insert_wireless_bandwidth_transaction(&self.connection, batch_id, rows)
        });
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_rogue_ap(
        &mut self,
        batch_id: &str,
        rows: &[WirelessRogueApInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_wireless_rogue_ap", || {
            insert_wireless_rogue_ap_transaction(&self.connection, batch_id, rows)
        });
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_deauth_flood(
        &mut self,
        batch_id: &str,
        rows: &[WirelessDeauthFloodInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_wireless_deauth_flood", || {
            insert_wireless_deauth_flood_transaction(&self.connection, batch_id, rows)
        });
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_signal_anomaly(
        &mut self,
        batch_id: &str,
        rows: &[WirelessSignalAnomalyInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_wireless_signal_anomaly", || {
            insert_wireless_signal_anomaly_transaction(&self.connection, batch_id, rows)
        });
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_pmf_attack(
        &mut self,
        batch_id: &str,
        rows: &[WirelessPmfAttackInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_wireless_pmf_attack", || {
            insert_wireless_pmf_attack_transaction(&self.connection, batch_id, rows)
        });
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_client_inventory(
        &mut self,
        _batch_id: &str,
        rows: &[WirelessClientInventoryInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_wireless_client_inventory", || {
            insert_wireless_client_inventory_transaction(&self.connection, rows)
        });
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }

    fn insert_wireless_probe_requests(
        &mut self,
        batch_id: &str,
        rows: &[WirelessProbeRequestInsert],
    ) -> Result<u64, String> {
        let result = record_call("oracle.insert_wireless_probe_requests", || {
            insert_wireless_probe_requests_transaction(&self.connection, batch_id, rows)
        });
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }
}

fn record_call<T>(operation: &str, call: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let started = std::time::Instant::now();
    let span = oracle_span(operation);
    let result = span.in_scope(call);
    span.record("status", if result.is_ok() { "ok" } else { "error" });
    crate::metrics::record_oracle_call(operation, result.is_ok(), started.elapsed().as_millis());
    result
}

fn oracle_span(operation: &str) -> tracing::Span {
    tracing::info_span!(
        "db.client.operation",
        "db.system" = "oracle",
        "db.operation" = operation,
        "db.name" = "oracle",
        status = tracing::field::Empty
    )
}

pub fn check_oracle_connection_from_env() -> Result<(), String> {
    OracleProxyEventSink::connect_from_env()?.ping()
}
