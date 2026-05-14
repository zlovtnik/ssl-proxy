use oracle::{sql_type::ToSql, Connection};

use crate::log::error_chain;

use super::wireless_types::WirelessBandwidthInsert;

pub(crate) fn insert_wireless_bandwidth_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[WirelessBandwidthInsert],
) -> Result<u64, String> {
    const SQL: &str = r#"
        merge into WL_BW_WINDOWS tgt
        using (
            select :1 BATCH_ID, :2 ROW_SEQUENCE, :3 SCHEMA_VERSION, :4 WINDOW_START,
                   :5 WINDOW_END, :6 SENSOR_ID, :7 LOCATION_ID, :8 INTERFACE,
                   :9 CHANNEL, :10 SOURCE_MAC, :11 DESTINATION_BSSID, :12 SSID,
                   :13 BYTES, :14 FRAME_COUNT, :15 RETRY_COUNT, :16 MORE_DATA_COUNT,
                   :17 POWER_SAVE_COUNT, :18 STRONGEST_SIGNAL_DBM, :19 HIST_UNDER_100,
                   :20 HIST_100_500, :21 HIST_500_1000, :22 HIST_1000_1500,
                   :23 INTER_ARRIVAL_P50_MS, :24 EXTERNAL_BSSID, :25 THRESHOLD_EXCEEDED,
                   :26 WALL_CLOCK_DELTA_MS, :27 WINDOW_IS_PARTIAL, :28 PUBLISHED_AT
            from dual
        ) src
        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
        when not matched then insert (
            BATCH_ID, ROW_SEQUENCE, SCHEMA_VERSION, WINDOW_START, WINDOW_END,
            SENSOR_ID, LOCATION_ID, INTERFACE, CHANNEL, SOURCE_MAC, DESTINATION_BSSID,
            SSID, BYTES, FRAME_COUNT, RETRY_COUNT, MORE_DATA_COUNT, POWER_SAVE_COUNT,
            STRONGEST_SIGNAL_DBM, HIST_UNDER_100, HIST_100_500, HIST_500_1000,
            HIST_1000_1500, INTER_ARRIVAL_P50_MS, EXTERNAL_BSSID, THRESHOLD_EXCEEDED,
            WALL_CLOCK_DELTA_MS, WINDOW_IS_PARTIAL, PUBLISHED_AT
        ) values (
            src.BATCH_ID, src.ROW_SEQUENCE, src.SCHEMA_VERSION, src.WINDOW_START,
            src.WINDOW_END, src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL,
            src.SOURCE_MAC, src.DESTINATION_BSSID, src.SSID, src.BYTES, src.FRAME_COUNT,
            src.RETRY_COUNT, src.MORE_DATA_COUNT, src.POWER_SAVE_COUNT,
            src.STRONGEST_SIGNAL_DBM, src.HIST_UNDER_100, src.HIST_100_500,
            src.HIST_500_1000, src.HIST_1000_1500, src.INTER_ARRIVAL_P50_MS,
            src.EXTERNAL_BSSID, src.THRESHOLD_EXCEEDED, src.WALL_CLOCK_DELTA_MS,
            src.WINDOW_IS_PARTIAL, src.PUBLISHED_AT
        )
    "#;
    for row in rows {
        let params: [&dyn ToSql; 28] = [
            &batch_id,
            &row.row_sequence,
            &row.schema_version,
            &row.window_start,
            &row.window_end,
            &row.sensor_id,
            &row.location_id,
            &row.interface,
            &row.channel,
            &row.source_mac,
            &row.destination_bssid,
            &row.ssid,
            &row.bytes,
            &row.frame_count,
            &row.retry_count,
            &row.more_data_count,
            &row.power_save_count,
            &row.strongest_signal_dbm,
            &row.hist_under_100,
            &row.hist_100_500,
            &row.hist_500_1000,
            &row.hist_1000_1500,
            &row.inter_arrival_p50_ms,
            &row.external_bssid,
            &row.threshold_exceeded,
            &row.wall_clock_delta_ms,
            &row.window_is_partial,
            &row.published_at,
        ];
        connection.execute(SQL, &params).map_err(|error| {
            format!(
                "merge WL_BW_WINDOWS row_sequence={}: {}",
                row.row_sequence,
                error_chain(&error)
            )
        })?;
    }
    connection
        .execute("BEGIN WL_BW_MERGE_ALERTS(:1); END;", &[&batch_id])
        .map_err(|error| format!("call WL_BW_MERGE_ALERTS: {}", error_chain(&error)))?;
    connection
        .commit()
        .map_err(|error| format!("commit WL_BW_WINDOWS batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}
