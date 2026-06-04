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
        merge into WIRELESS_ALERTS tgt
        using (
            select 'rogue_ap' ALERT_TYPE, :1 BATCH_ID, :2 ROW_SEQUENCE,
                   :3 DETECTED_AT, :4 SENSOR_ID, :5 LOCATION_ID, :6 INTERFACE,
                   :7 CHANNEL, :8 ROGUE_BSSID, :9 SSID, :10 SIGNAL_DBM,
                   json_object(
                       'ssid_impersonation' value :11
                       returning clob
                   ) DETAILS_JSON,
                   :12 RAW_JSON
            from dual
        ) src
        on (
            tgt.ALERT_TYPE = src.ALERT_TYPE
            and tgt.BATCH_ID = src.BATCH_ID
            and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE
        )
        when matched then update set
            tgt.DETECTED_AT = src.DETECTED_AT,
            tgt.SENSOR_ID = src.SENSOR_ID,
            tgt.LOCATION_ID = src.LOCATION_ID,
            tgt.INTERFACE = src.INTERFACE,
            tgt.CHANNEL = src.CHANNEL,
            tgt.PRIMARY_MAC = src.ROGUE_BSSID,
            tgt.SSID = src.SSID,
            tgt.SIGNAL_DBM = src.SIGNAL_DBM,
            tgt.DETAILS_JSON = src.DETAILS_JSON,
            tgt.RAW_JSON = src.RAW_JSON,
            tgt.UPDATED_AT = SYSTIMESTAMP
        when not matched then insert (
            ALERT_TYPE, BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID,
            INTERFACE, CHANNEL, PRIMARY_MAC, SSID, SIGNAL_DBM, DETAILS_JSON, RAW_JSON
        ) values (
            src.ALERT_TYPE, src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT,
            src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL,
            src.ROGUE_BSSID, src.SSID, src.SIGNAL_DBM, src.DETAILS_JSON,
            src.RAW_JSON
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
                "merge WIRELESS_ALERTS rogue_ap row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection.commit().map_err(|error| {
        format!(
            "commit WIRELESS_ALERTS rogue_ap batch: {}",
            error_chain(&error)
        )
    })?;
    Ok(rows.len() as u64)
}

pub(crate) fn insert_wireless_deauth_flood_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessDeauthFloodInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WIRELESS_ALERTS tgt
        using (
            select 'deauth_flood' ALERT_TYPE, :1 BATCH_ID, :2 ROW_SEQUENCE,
                   :3 DETECTED_AT, :4 SENSOR_ID, :5 LOCATION_ID, :6 INTERFACE,
                   :7 CHANNEL, :8 ATTACKER_MAC, :9 TARGET_BSSID, :10 TARGET_SSID,
                   :11 DEAUTH_COUNT, :12 WINDOW_SECS, :13 THRESHOLD,
                   :14 SIGNAL_DBM,
                   json_object(
                       'deauth_count' value :11,
                       'window_secs' value :12,
                       'threshold' value :13
                       returning clob
                   ) DETAILS_JSON,
                   :15 RAW_JSON
            from dual
        ) src
        on (
            tgt.ALERT_TYPE = src.ALERT_TYPE
            and tgt.BATCH_ID = src.BATCH_ID
            and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE
        )
        when matched then update set
            tgt.DETECTED_AT = src.DETECTED_AT,
            tgt.SENSOR_ID = src.SENSOR_ID,
            tgt.LOCATION_ID = src.LOCATION_ID,
            tgt.INTERFACE = src.INTERFACE,
            tgt.CHANNEL = src.CHANNEL,
            tgt.PRIMARY_MAC = src.ATTACKER_MAC,
            tgt.SECONDARY_MAC = src.TARGET_BSSID,
            tgt.SSID = src.TARGET_SSID,
            tgt.SIGNAL_DBM = src.SIGNAL_DBM,
            tgt.DETAILS_JSON = src.DETAILS_JSON,
            tgt.RAW_JSON = src.RAW_JSON,
            tgt.UPDATED_AT = SYSTIMESTAMP
        when not matched then insert (
            ALERT_TYPE, BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID,
            INTERFACE, CHANNEL, PRIMARY_MAC, SECONDARY_MAC, SSID, SIGNAL_DBM,
            DETAILS_JSON, RAW_JSON
        ) values (
            src.ALERT_TYPE, src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT,
            src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL,
            src.ATTACKER_MAC, src.TARGET_BSSID, src.TARGET_SSID, src.SIGNAL_DBM,
            src.DETAILS_JSON, src.RAW_JSON
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
                "merge WIRELESS_ALERTS deauth_flood row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection.commit().map_err(|error| {
        format!(
            "commit WIRELESS_ALERTS deauth_flood batch: {}",
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
        merge into WIRELESS_ALERTS tgt
        using (
            select 'signal_anomaly' ALERT_TYPE, :1 BATCH_ID, :2 ROW_SEQUENCE,
                   :3 DETECTED_AT, :4 SENSOR_ID, :5 LOCATION_ID, :6 SOURCE_MAC,
                   :7 BSSID, :8 SSID, :9 CHANNEL, :10 BASELINE_DBM,
                   :11 OBSERVED_DBM, :12 DBM_DELTA, :13 CONFIGURED_DELTA,
                   json_object(
                       'baseline_dbm' value :10,
                       'observed_dbm' value :11,
                       'dbm_delta' value :12,
                       'configured_delta' value :13
                       returning clob
                   ) DETAILS_JSON
            from dual
        ) src
        on (
            tgt.ALERT_TYPE = src.ALERT_TYPE
            and tgt.BATCH_ID = src.BATCH_ID
            and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE
        )
        when matched then update set
            tgt.DETECTED_AT = src.DETECTED_AT,
            tgt.SENSOR_ID = src.SENSOR_ID,
            tgt.LOCATION_ID = src.LOCATION_ID,
            tgt.CHANNEL = src.CHANNEL,
            tgt.PRIMARY_MAC = src.SOURCE_MAC,
            tgt.SECONDARY_MAC = src.BSSID,
            tgt.SSID = src.SSID,
            tgt.SIGNAL_DBM = src.OBSERVED_DBM,
            tgt.DETAILS_JSON = src.DETAILS_JSON,
            tgt.UPDATED_AT = SYSTIMESTAMP
        when not matched then insert (
            ALERT_TYPE, BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID,
            CHANNEL, PRIMARY_MAC, SECONDARY_MAC, SSID, SIGNAL_DBM, DETAILS_JSON
        ) values (
            src.ALERT_TYPE, src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT,
            src.SENSOR_ID, src.LOCATION_ID, src.CHANNEL, src.SOURCE_MAC,
            src.BSSID, src.SSID, src.OBSERVED_DBM, src.DETAILS_JSON
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
                "merge WIRELESS_ALERTS signal_anomaly row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection.commit().map_err(|error| {
        format!(
            "commit WIRELESS_ALERTS signal_anomaly batch: {}",
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
        merge into WIRELESS_ALERTS tgt
        using (
            select 'pmf_attack' ALERT_TYPE, :1 BATCH_ID, :2 ROW_SEQUENCE,
                   :3 DETECTED_AT, :4 SENSOR_ID, :5 LOCATION_ID, :6 TARGET_MAC,
                   :7 TARGET_BSSID, :8 SSID, :9 CHANNEL, :10 ATTACK_TAG,
                   :11 RECONNECT_WINDOW_MS,
                   json_object(
                       'attack_tag' value :10,
                       'reconnect_window_ms' value :11
                       returning clob
                   ) DETAILS_JSON
            from dual
        ) src
        on (
            tgt.ALERT_TYPE = src.ALERT_TYPE
            and tgt.BATCH_ID = src.BATCH_ID
            and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE
        )
        when matched then update set
            tgt.DETECTED_AT = src.DETECTED_AT,
            tgt.SENSOR_ID = src.SENSOR_ID,
            tgt.LOCATION_ID = src.LOCATION_ID,
            tgt.CHANNEL = src.CHANNEL,
            tgt.PRIMARY_MAC = src.TARGET_MAC,
            tgt.SECONDARY_MAC = src.TARGET_BSSID,
            tgt.SSID = src.SSID,
            tgt.DETAILS_JSON = src.DETAILS_JSON,
            tgt.UPDATED_AT = SYSTIMESTAMP
        when not matched then insert (
            ALERT_TYPE, BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID,
            CHANNEL, PRIMARY_MAC, SECONDARY_MAC, SSID, DETAILS_JSON
        ) values (
            src.ALERT_TYPE, src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT,
            src.SENSOR_ID, src.LOCATION_ID, src.CHANNEL, src.TARGET_MAC,
            src.TARGET_BSSID, src.SSID, src.DETAILS_JSON
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
                "merge WIRELESS_ALERTS pmf_attack row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection.commit().map_err(|error| {
        format!(
            "commit WIRELESS_ALERTS pmf_attack batch: {}",
            error_chain(&error)
        )
    })?;
    Ok(rows.len() as u64)
}
