use super::json_value::*;
use super::types::SinkTarget;
use super::wireless_types::{WirelessAuditFrameInsert, WirelessBandwidthInsert};

pub(crate) fn wireless_audit_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessAuditFrameInsert>, String> {
    if target != SinkTarget::WirelessAuditFrames {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| wireless_audit_row_from_value(index, row))
        .collect()
}

fn wireless_audit_row_from_value(
    index: usize,
    row: &serde_json::Value,
) -> Result<WirelessAuditFrameInsert, String> {
    let raw_json = raw_json(row, "wireless.audit row")?;
    Ok(WirelessAuditFrameInsert {
        row_sequence: row_sequence(index, "wireless.audit")?,
        event_type: required_string(row, "event_type", "wireless.audit")?,
        observed_at: required_timestamp(row, "observed_at", "wireless.audit")?,
        sensor_id: required_string(row, "sensor_id", "wireless.audit")?,
        location_id: required_string(row, "location_id", "wireless.audit")?,
        interface: required_string(row, "interface", "wireless.audit")?,
        channel: required_i64(row, "channel", "wireless.audit")?,
        frame_type: optional_string(row, "frame_type"),
        frame_subtype: required_string(row, "frame_subtype", "wireless.audit")?,
        bssid: optional_string(row, "bssid"),
        source_mac: optional_string(row, "source_mac"),
        destination_mac: optional_string(row, "destination_mac"),
        transmitter_mac: optional_string(row, "transmitter_mac"),
        receiver_mac: optional_string(row, "receiver_mac"),
        destination_bssid: optional_string(row, "destination_bssid"),
        ssid: optional_string(row, "ssid"),
        signal_dbm: optional_i64(row, "signal_dbm"),
        sequence_number: optional_i64(row, "sequence_number"),
        raw_len: required_i64(row, "raw_len", "wireless.audit")?,
        is_retry: bool_flag(row, "retry"),
        is_more_data: bool_flag(row, "more_data"),
        is_power_save: bool_flag(row, "power_save"),
        is_protected: bool_flag(row, "protected"),
        is_to_ds: bool_flag(row, "to_ds"),
        is_from_ds: bool_flag(row, "from_ds"),
        is_handshake: bool_flag(row, "handshake_captured"),
        security_flags: optional_i64(row, "security_flags").unwrap_or(0),
        device_id: optional_string(row, "device_id"),
        username: optional_string(row, "username"),
        identity_source: optional_string(row, "identity_source")
            .unwrap_or_else(|| "unknown".to_string()),
        tags: json_array_string(row, "tags")?,
        anomaly_reasons: json_array_string(row, "anomaly_reasons")?,
        raw_json,
        reg_domain: optional_string(row, "reg_domain"),
    })
}

pub(crate) fn wireless_bandwidth_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessBandwidthInsert>, String> {
    if target != SinkTarget::WirelessBandwidth {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| wireless_bandwidth_row_from_value(index, row))
        .collect()
}

fn wireless_bandwidth_row_from_value(
    index: usize,
    row: &serde_json::Value,
) -> Result<WirelessBandwidthInsert, String> {
    Ok(WirelessBandwidthInsert {
        row_sequence: row_sequence(index, "audit.wireless.bandwidth")?,
        schema_version: optional_i64(row, "schema_version").unwrap_or(1),
        window_start: required_timestamp(row, "window_start", "audit.wireless.bandwidth")?,
        window_end: required_timestamp(row, "window_end", "audit.wireless.bandwidth")?,
        sensor_id: required_string(row, "sensor_id", "audit.wireless.bandwidth")?,
        location_id: required_string(row, "location_id", "audit.wireless.bandwidth")?,
        interface: required_string(row, "interface", "audit.wireless.bandwidth")?,
        channel: required_i64(row, "channel", "audit.wireless.bandwidth")?,
        source_mac: required_string(row, "source_mac", "audit.wireless.bandwidth")?,
        destination_bssid: required_string(row, "destination_bssid", "audit.wireless.bandwidth")?,
        ssid: optional_string(row, "ssid"),
        bytes: required_i64(row, "bytes", "audit.wireless.bandwidth")?,
        frame_count: required_i64(row, "frame_count", "audit.wireless.bandwidth")?,
        retry_count: optional_i64(row, "retry_count").unwrap_or(0),
        more_data_count: optional_i64(row, "more_data_count").unwrap_or(0),
        power_save_count: optional_i64(row, "power_save_count").unwrap_or(0),
        strongest_signal_dbm: optional_i64(row, "strongest_signal_dbm"),
        hist_under_100: nested_i64(row, "frame_size_histogram", "under_100").unwrap_or(0),
        hist_100_500: nested_i64(row, "frame_size_histogram", "range_100_500").unwrap_or(0),
        hist_500_1000: nested_i64(row, "frame_size_histogram", "range_500_1000").unwrap_or(0),
        hist_1000_1500: nested_i64(row, "frame_size_histogram", "range_1000_1500").unwrap_or(0),
        inter_arrival_p50_ms: optional_i64(row, "inter_arrival_p50_ms"),
        external_bssid: bool_flag(row, "external_bssid"),
        threshold_exceeded: bool_flag(row, "threshold_exceeded"),
        wall_clock_delta_ms: optional_i64(row, "wall_clock_delta_ms"),
        window_is_partial: bool_flag(row, "window_is_partial"),
        published_at: optional_timestamp(row, "published_at")?,
    })
}
