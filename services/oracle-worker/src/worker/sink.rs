use std::fs;

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
        let connection = Connection::connect(user.as_str(), password, connect_string.as_str())
            .map_err(|error| {
                format!(
                    "connect Oracle {connect_string}: {}",
                    crate::log::error_chain(&error)
                )
            })?;
        let duration_ms = start.elapsed().as_millis();
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
        let connection = pool.get().map_err(|error| {
            format!(
                "get Oracle connection from pool (pool_size={} idle={} state={:?}): {}",
                pool.max_size(),
                pool.state().idle_connections,
                pool.state(),
                crate::log::error_chain(&error)
            )
        })?;
        let duration_ms = start.elapsed().as_millis();
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
        let result = insert_event_batch_transaction(&self.connection, batch_id, rows, blocked_rows);
        if let Err(error) = result {
            let _ = self.connection.rollback();
            if is_proxy_events_batch_row_duplicate(&error) {
                let retry_result =
                    insert_event_batch_transaction(&self.connection, batch_id, rows, blocked_rows);
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
        let result = insert_wireless_audit_frames_transaction(&self.connection, batch_id, rows);
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
        let result = insert_wireless_bandwidth_transaction(&self.connection, batch_id, rows);
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
        let result = insert_wireless_rogue_ap_transaction(&self.connection, batch_id, rows);
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
        let result = insert_wireless_deauth_flood_transaction(&self.connection, batch_id, rows);
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
        let result = insert_wireless_signal_anomaly_transaction(&self.connection, batch_id, rows);
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
        let result = insert_wireless_pmf_attack_transaction(&self.connection, batch_id, rows);
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
        let result = insert_wireless_client_inventory_transaction(&self.connection, rows);
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
        let result = insert_wireless_probe_requests_transaction(&self.connection, batch_id, rows);
        if result.is_err() {
            let _ = self.connection.rollback();
        }
        result
    }
}

pub fn check_oracle_connection_from_env() -> Result<(), String> {
    OracleProxyEventSink::connect_from_env()?.ping()
}
