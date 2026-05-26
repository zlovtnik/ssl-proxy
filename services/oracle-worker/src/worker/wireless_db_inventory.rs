use oracle::{sql_type::ToSql, Connection};

use crate::log::error_chain;

use super::wireless_types::{WirelessClientInventoryInsert, WirelessProbeRequestInsert};

pub(crate) fn insert_wireless_client_inventory_transaction(
    connection: &Connection,
    rows: &[WirelessClientInventoryInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WIRELESS_CLIENT_INVENTORY tgt
        using (
            select :1 SENSOR_ID, :2 LOCATION_ID, :3 SNAPSHOT_AT, :4 CLIENT_MAC,
                   :5 BSSID, :6 SSID, :7 DEVICE_ID, :8 USERNAME, :9 IDENTITY_SOURCE,
                   :10 LAST_SEEN, :11 FIRST_SEEN, :12 SIGNAL_DBM, :13 IS_AUTHORIZED
            from dual
        ) src
        on (
            tgt.SENSOR_ID = src.SENSOR_ID
            and tgt.SNAPSHOT_AT = src.SNAPSHOT_AT
            and tgt.CLIENT_MAC = src.CLIENT_MAC
        )
        when matched then update set
            tgt.LOCATION_ID = src.LOCATION_ID,
            tgt.BSSID = src.BSSID,
            tgt.SSID = src.SSID,
            tgt.DEVICE_ID = src.DEVICE_ID,
            tgt.USERNAME = src.USERNAME,
            tgt.IDENTITY_SOURCE = src.IDENTITY_SOURCE,
            tgt.LAST_SEEN = src.LAST_SEEN,
            tgt.FIRST_SEEN = src.FIRST_SEEN,
            tgt.SIGNAL_DBM = src.SIGNAL_DBM,
            tgt.IS_AUTHORIZED = src.IS_AUTHORIZED
        when not matched then insert (
            SENSOR_ID, LOCATION_ID, SNAPSHOT_AT, CLIENT_MAC, BSSID, SSID,
            DEVICE_ID, USERNAME, IDENTITY_SOURCE, LAST_SEEN, FIRST_SEEN,
            SIGNAL_DBM, IS_AUTHORIZED
        ) values (
            src.SENSOR_ID, src.LOCATION_ID, src.SNAPSHOT_AT, src.CLIENT_MAC,
            src.BSSID, src.SSID, src.DEVICE_ID, src.USERNAME, src.IDENTITY_SOURCE,
            src.LAST_SEEN, src.FIRST_SEEN, src.SIGNAL_DBM, src.IS_AUTHORIZED
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 13] = [
            &row.sensor_id,
            &row.location_id,
            &row.snapshot_at,
            &row.client_mac,
            &row.bssid,
            &row.ssid,
            &row.device_id,
            &row.username,
            &row.identity_source,
            &row.last_seen,
            &row.first_seen,
            &row.signal_dbm,
            &row.is_authorized,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WIRELESS_CLIENT_INVENTORY client_mac={}: {}",
                row.client_mac,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WIRELESS_CLIENT_INVENTORY batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

pub(crate) fn insert_wireless_probe_requests_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessProbeRequestInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WIRELESS_PROBE_REQUESTS tgt
        using (
            select :1 BATCH_ID, :2 CLIENT_MAC, :3 SSID, :4 KNOWN_BSSID,
                   :5 FIRST_SEEN, :6 LAST_SEEN, :7 PROBE_COUNT
            from dual
        ) src
        on (
            tgt.BATCH_ID = src.BATCH_ID
            and tgt.CLIENT_MAC = src.CLIENT_MAC
            and tgt.SSID = src.SSID
        )
        when matched then update set
            tgt.KNOWN_BSSID = src.KNOWN_BSSID,
            tgt.FIRST_SEEN = src.FIRST_SEEN,
            tgt.LAST_SEEN = src.LAST_SEEN,
            tgt.PROBE_COUNT = src.PROBE_COUNT
        when not matched then insert (
            BATCH_ID, CLIENT_MAC, SSID, KNOWN_BSSID, FIRST_SEEN, LAST_SEEN, PROBE_COUNT
        ) values (
            src.BATCH_ID, src.CLIENT_MAC, src.SSID, src.KNOWN_BSSID,
            src.FIRST_SEEN, src.LAST_SEEN, src.PROBE_COUNT
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 7] = [
            &batch_id,
            &row.client_mac,
            &row.ssid,
            &row.known_bssid,
            &row.first_seen,
            &row.last_seen,
            &row.probe_count,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WIRELESS_PROBE_REQUESTS row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .commit()
        .map_err(|error| format!("commit WIRELESS_PROBE_REQUESTS batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}
