use oracle::{sql_type::ToSql, Connection};

use crate::log::error_chain;

use super::wireless_types::WirelessAuditFrameInsert;

pub(crate) fn insert_wireless_audit_frames_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessAuditFrameInsert],
) -> Result<u64, String> {
    if rows.is_empty() {
        return Ok(0);
    }
    let first = rows
        .iter()
        .min_by_key(|row| row.observed_at)
        .ok_or_else(|| "wireless audit batch unexpectedly empty".to_string())?;
    let sensor_params: [&dyn ToSql; 5] = [
        &first.sensor_id,
        &first.location_id,
        &first.interface,
        &first.reg_domain,
        &first.observed_at,
    ];
    connection
        .execute(
            "BEGIN WIRELESS_UPSERT_SENSOR(:1, :2, :3, :4, :5); END;",
            &sensor_params,
        )
        .map_err(|error| format!("call WIRELESS_UPSERT_SENSOR: {}", error_chain(&error)))?;

    const SQL: &str = r#"
        merge into WIRELESS_AUDIT_FRAMES tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 EVENT_TYPE, :4 OBSERVED_AT,
                   :5 SENSOR_ID, :6 LOCATION_ID, :7 INTERFACE, :8 CHANNEL,
                   :9 FRAME_TYPE, :10 FRAME_SUBTYPE, :11 BSSID, :12 SOURCE_MAC,
                   :13 DESTINATION_MAC, :14 TRANSMITTER_MAC, :15 RECEIVER_MAC,
                   :16 DESTINATION_BSSID, :17 SSID, :18 SIGNAL_DBM,
                   :19 SEQUENCE_NUMBER, :20 RAW_LEN, :21 IS_RETRY,
                   :22 IS_MORE_DATA, :23 IS_POWER_SAVE, :24 IS_PROTECTED,
                   :25 IS_TO_DS, :26 IS_FROM_DS, :27 IS_HANDSHAKE,
                   :28 SECURITY_FLAGS, :29 DEVICE_ID, :30 USERNAME,
                   :31 IDENTITY_SOURCE, :32 TAGS, :33 ANOMALY_REASONS,
                   :34 RAW_JSON
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, EVENT_TYPE, OBSERVED_AT, SENSOR_ID, LOCATION_ID,
            INTERFACE, CHANNEL, FRAME_TYPE, FRAME_SUBTYPE, BSSID, SOURCE_MAC,
            DESTINATION_MAC, TRANSMITTER_MAC, RECEIVER_MAC, DESTINATION_BSSID, SSID,
            SIGNAL_DBM, SEQUENCE_NUMBER, RAW_LEN, IS_RETRY, IS_MORE_DATA,
            IS_POWER_SAVE, IS_PROTECTED, IS_TO_DS, IS_FROM_DS, IS_HANDSHAKE,
            SECURITY_FLAGS, DEVICE_ID, USERNAME, IDENTITY_SOURCE, TAGS,
            ANOMALY_REASONS, RAW_JSON
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.EVENT_TYPE, src.OBSERVED_AT,
            src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL,
            src.FRAME_TYPE, src.FRAME_SUBTYPE, src.BSSID, src.SOURCE_MAC,
            src.DESTINATION_MAC, src.TRANSMITTER_MAC, src.RECEIVER_MAC,
            src.DESTINATION_BSSID, src.SSID, src.SIGNAL_DBM, src.SEQUENCE_NUMBER,
            src.RAW_LEN, src.IS_RETRY, src.IS_MORE_DATA, src.IS_POWER_SAVE,
            src.IS_PROTECTED, src.IS_TO_DS, src.IS_FROM_DS, src.IS_HANDSHAKE,
            src.SECURITY_FLAGS, src.DEVICE_ID, src.USERNAME, src.IDENTITY_SOURCE,
            src.TAGS, src.ANOMALY_REASONS, src.RAW_JSON
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 34] = [
            &batch_id,
            &row.row_sequence,
            &row.event_type,
            &row.observed_at,
            &row.sensor_id,
            &row.location_id,
            &row.interface,
            &row.channel,
            &row.frame_type,
            &row.frame_subtype,
            &row.bssid,
            &row.source_mac,
            &row.destination_mac,
            &row.transmitter_mac,
            &row.receiver_mac,
            &row.destination_bssid,
            &row.ssid,
            &row.signal_dbm,
            &row.sequence_number,
            &row.raw_len,
            &row.is_retry,
            &row.is_more_data,
            &row.is_power_save,
            &row.is_protected,
            &row.is_to_ds,
            &row.is_from_ds,
            &row.is_handshake,
            &row.security_flags,
            &row.device_id,
            &row.username,
            &row.identity_source,
            &row.tags,
            &row.anomaly_reasons,
            &row.raw_json,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WIRELESS_AUDIT_FRAMES row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WIRELESS_AUDIT_FRAMES batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}
