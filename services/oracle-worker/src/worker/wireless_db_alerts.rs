use oracle::{sql_type::ToSql, Connection};

use crate::log::error_chain;

use super::wireless_types::{
    WirelessDeauthFloodInsert, WirelessPmfAttackInsert, WirelessRogueApInsert,
    WirelessSignalAnomalyInsert,
};

pub(crate) fn insert_wireless_rogue_ap_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessRogueApInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_ALERT_ROGUE_AP tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 DETECTED_AT, :4 SENSOR_ID,
                   :5 LOCATION_ID, :6 INTERFACE, :7 CHANNEL, :8 ROGUE_BSSID,
                   :9 SSID, :10 SIGNAL_DBM, :11 SSID_IMPERSONATION, :12 RAW_JSON
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID, INTERFACE,
            CHANNEL, ROGUE_BSSID, SSID, SIGNAL_DBM, SSID_IMPERSONATION, RAW_JSON
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT, src.SENSOR_ID,
            src.LOCATION_ID, src.INTERFACE, src.CHANNEL, src.ROGUE_BSSID,
            src.SSID, src.SIGNAL_DBM, src.SSID_IMPERSONATION, src.RAW_JSON
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 12] = [
            &batch_id,
            &row.row_sequence,
            &row.detected_at,
            &row.sensor_id,
            &row.location_id,
            &row.interface,
            &row.channel,
            &row.rogue_bssid,
            &row.ssid,
            &row.signal_dbm,
            &row.ssid_impersonation,
            &row.raw_json,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_ALERT_ROGUE_AP row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WL_ALERT_ROGUE_AP batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

pub(crate) fn insert_wireless_deauth_flood_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessDeauthFloodInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_ALERT_DEAUTH_FLOOD tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 DETECTED_AT, :4 SENSOR_ID,
                   :5 LOCATION_ID, :6 INTERFACE, :7 CHANNEL, :8 ATTACKER_MAC,
                   :9 TARGET_BSSID, :10 TARGET_SSID, :11 DEAUTH_COUNT,
                   :12 WINDOW_SECS, :13 THRESHOLD, :14 SIGNAL_DBM, :15 RAW_JSON
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID, INTERFACE,
            CHANNEL, ATTACKER_MAC, TARGET_BSSID, TARGET_SSID, DEAUTH_COUNT,
            WINDOW_SECS, THRESHOLD, SIGNAL_DBM, RAW_JSON
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT, src.SENSOR_ID,
            src.LOCATION_ID, src.INTERFACE, src.CHANNEL, src.ATTACKER_MAC,
            src.TARGET_BSSID, src.TARGET_SSID, src.DEAUTH_COUNT, src.WINDOW_SECS,
            src.THRESHOLD, src.SIGNAL_DBM, src.RAW_JSON
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 15] = [
            &batch_id,
            &row.row_sequence,
            &row.detected_at,
            &row.sensor_id,
            &row.location_id,
            &row.interface,
            &row.channel,
            &row.attacker_mac,
            &row.target_bssid,
            &row.target_ssid,
            &row.deauth_count,
            &row.window_secs,
            &row.threshold,
            &row.signal_dbm,
            &row.raw_json,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_ALERT_DEAUTH_FLOOD row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection.commit().map_err(|error| {
        format!(
            "commit WL_ALERT_DEAUTH_FLOOD batch: {}",
            error_chain(&error)
        )
    })?;
    Ok(rows.len() as u64)
}

pub(crate) fn insert_wireless_signal_anomaly_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessSignalAnomalyInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_ALERT_SIGNAL_ANOMALY tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 DETECTED_AT, :4 SENSOR_ID,
                   :5 LOCATION_ID, :6 SOURCE_MAC, :7 BSSID, :8 SSID, :9 CHANNEL,
                   :10 BASELINE_DBM, :11 OBSERVED_DBM, :12 DBM_DELTA,
                   :13 CONFIGURED_DELTA
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID, SOURCE_MAC,
            BSSID, SSID, CHANNEL, BASELINE_DBM, OBSERVED_DBM, DBM_DELTA, CONFIGURED_DELTA
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT, src.SENSOR_ID,
            src.LOCATION_ID, src.SOURCE_MAC, src.BSSID, src.SSID, src.CHANNEL,
            src.BASELINE_DBM, src.OBSERVED_DBM, src.DBM_DELTA, src.CONFIGURED_DELTA
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 13] = [
            &batch_id,
            &row.row_sequence,
            &row.detected_at,
            &row.sensor_id,
            &row.location_id,
            &row.source_mac,
            &row.bssid,
            &row.ssid,
            &row.channel,
            &row.baseline_dbm,
            &row.observed_dbm,
            &row.dbm_delta,
            &row.configured_delta,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_ALERT_SIGNAL_ANOMALY row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection.commit().map_err(|error| {
        format!(
            "commit WL_ALERT_SIGNAL_ANOMALY batch: {}",
            error_chain(&error)
        )
    })?;
    Ok(rows.len() as u64)
}

pub(crate) fn insert_wireless_pmf_attack_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessPmfAttackInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_ALERT_PMF_ATTACK tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 DETECTED_AT, :4 SENSOR_ID,
                   :5 LOCATION_ID, :6 TARGET_MAC, :7 TARGET_BSSID, :8 SSID,
                   :9 CHANNEL, :10 ATTACK_TAG, :11 RECONNECT_WINDOW_MS
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID, TARGET_MAC,
            TARGET_BSSID, SSID, CHANNEL, ATTACK_TAG, RECONNECT_WINDOW_MS
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT, src.SENSOR_ID,
            src.LOCATION_ID, src.TARGET_MAC, src.TARGET_BSSID, src.SSID,
            src.CHANNEL, src.ATTACK_TAG, src.RECONNECT_WINDOW_MS
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 11] = [
            &batch_id,
            &row.row_sequence,
            &row.detected_at,
            &row.sensor_id,
            &row.location_id,
            &row.target_mac,
            &row.target_bssid,
            &row.ssid,
            &row.channel,
            &row.attack_tag,
            &row.reconnect_window_ms,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_ALERT_PMF_ATTACK row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WL_ALERT_PMF_ATTACK batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}
