use super::json_value::*;
use super::types::SinkTarget;
use super::wireless_types::{
    WirelessClientInventoryInsert, WirelessDeauthFloodInsert, WirelessPmfAttackInsert,
    WirelessProbeRequestInsert, WirelessRogueApInsert, WirelessSignalAnomalyInsert,
};

pub(crate) fn wireless_rogue_ap_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessRogueApInsert>, String> {
    if target != SinkTarget::WirelessRogueAp {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| wireless_rogue_ap_row_from_value(index, row))
        .collect()
}

fn wireless_rogue_ap_row_from_value(
    index: usize,
    row: &serde_json::Value,
) -> Result<WirelessRogueApInsert, String> {
    let raw_json = raw_json(row, "wireless rogue AP row")?;
    let reasons = row.get("reasons").and_then(serde_json::Value::as_array);
    let ssid_impersonation = bool_flag(row, "ssid_impersonation")
        | i64::from(reasons.is_some_and(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|reason| matches!(reason, "ssid_impersonation" | "bssid_spoofing"))
        }));
    Ok(WirelessRogueApInsert {
        row_sequence: row_sequence(index, "wireless.alert.rogue_ap")?,
        detected_at: timestamp_alias(row, "detected_at", "observed_at", "wireless.alert.rogue_ap")?,
        sensor_id: required_string(row, "sensor_id", "wireless.alert.rogue_ap")?,
        location_id: required_string(row, "location_id", "wireless.alert.rogue_ap")?,
        interface: required_string(row, "interface", "wireless.alert.rogue_ap")?,
        channel: required_i64(row, "channel", "wireless.alert.rogue_ap")?,
        rogue_bssid: string_alias(row, "rogue_bssid", "bssid", "wireless.alert.rogue_ap")?,
        ssid: optional_string(row, "ssid"),
        signal_dbm: optional_i64(row, "signal_dbm"),
        ssid_impersonation,
        raw_json,
    })
}

pub(crate) fn wireless_deauth_flood_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessDeauthFloodInsert>, String> {
    if target != SinkTarget::WirelessDeauthFlood {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| wireless_deauth_flood_row_from_value(index, row))
        .collect()
}

fn wireless_deauth_flood_row_from_value(
    index: usize,
    row: &serde_json::Value,
) -> Result<WirelessDeauthFloodInsert, String> {
    let raw_json = raw_json(row, "wireless deauth flood row")?;
    Ok(WirelessDeauthFloodInsert {
        row_sequence: row_sequence(index, "wireless.alert.deauth_flood")?,
        detected_at: timestamp_alias(
            row,
            "detected_at",
            "observed_at",
            "wireless.alert.deauth_flood",
        )?,
        sensor_id: required_string(row, "sensor_id", "wireless.alert.deauth_flood")?,
        location_id: required_string(row, "location_id", "wireless.alert.deauth_flood")?,
        interface: required_string(row, "interface", "wireless.alert.deauth_flood")?,
        channel: optional_i64(row, "channel").unwrap_or(0),
        attacker_mac: optional_string(row, "attacker_mac")
            .or_else(|| optional_string(row, "source_mac")),
        target_bssid: optional_string(row, "target_bssid")
            .or_else(|| optional_string(row, "bssid")),
        target_ssid: optional_string(row, "target_ssid").or_else(|| optional_string(row, "ssid")),
        deauth_count: i64_alias(
            row,
            "deauth_count",
            "frame_count",
            "wireless.alert.deauth_flood",
        )?,
        window_secs: required_i64(row, "window_secs", "wireless.alert.deauth_flood")?,
        threshold: optional_i64(row, "threshold").unwrap_or(0),
        signal_dbm: optional_i64(row, "signal_dbm"),
        raw_json,
    })
}

pub(crate) fn wireless_signal_anomaly_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessSignalAnomalyInsert>, String> {
    if target != SinkTarget::WirelessSignalAnomaly {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(WirelessSignalAnomalyInsert {
                row_sequence: row_sequence(index, "wireless.alert.signal_anomaly")?,
                detected_at: timestamp_alias(
                    row,
                    "detected_at",
                    "observed_at",
                    "wireless.alert.signal_anomaly",
                )?,
                sensor_id: required_string(row, "sensor_id", "wireless.alert.signal_anomaly")?,
                location_id: required_string(row, "location_id", "wireless.alert.signal_anomaly")?,
                source_mac: required_string(row, "source_mac", "wireless.alert.signal_anomaly")?,
                bssid: optional_string(row, "bssid"),
                ssid: optional_string(row, "ssid"),
                channel: required_i64(row, "channel", "wireless.alert.signal_anomaly")?,
                baseline_dbm: required_i64(row, "baseline_dbm", "wireless.alert.signal_anomaly")?,
                observed_dbm: required_i64(row, "observed_dbm", "wireless.alert.signal_anomaly")?,
                dbm_delta: required_i64(row, "dbm_delta", "wireless.alert.signal_anomaly")?.abs(),
                configured_delta: required_i64(
                    row,
                    "configured_delta",
                    "wireless.alert.signal_anomaly",
                )?,
            })
        })
        .collect()
}

pub(crate) fn wireless_pmf_attack_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessPmfAttackInsert>, String> {
    if target != SinkTarget::WirelessPmfAttack {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(WirelessPmfAttackInsert {
                row_sequence: row_sequence(index, "wireless.alert.pmf_attack")?,
                detected_at: timestamp_alias(
                    row,
                    "detected_at",
                    "observed_at",
                    "wireless.alert.pmf_attack",
                )?,
                sensor_id: required_string(row, "sensor_id", "wireless.alert.pmf_attack")?,
                location_id: required_string(row, "location_id", "wireless.alert.pmf_attack")?,
                target_mac: string_alias(
                    row,
                    "target_mac",
                    "source_mac",
                    "wireless.alert.pmf_attack",
                )?,
                target_bssid: optional_string(row, "target_bssid")
                    .or_else(|| optional_string(row, "bssid")),
                ssid: optional_string(row, "ssid"),
                channel: optional_i64(row, "channel"),
                attack_tag: required_string(row, "attack_tag", "wireless.alert.pmf_attack")?,
                reconnect_window_ms: optional_i64(row, "reconnect_window_ms"),
            })
        })
        .collect()
}

pub(crate) fn wireless_client_inventory_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessClientInventoryInsert>, String> {
    if target != SinkTarget::WirelessClientInventory {
        return Ok(Vec::new());
    }
    rows.iter()
        .map(|row| {
            Ok(WirelessClientInventoryInsert {
                sensor_id: required_string(row, "sensor_id", "wireless.client.inventory")?,
                location_id: required_string(row, "location_id", "wireless.client.inventory")?,
                snapshot_at: required_timestamp(row, "snapshot_at", "wireless.client.inventory")?,
                client_mac: string_alias(
                    row,
                    "client_mac",
                    "source_mac",
                    "wireless.client.inventory",
                )?,
                bssid: optional_string(row, "bssid"),
                ssid: optional_string(row, "ssid"),
                device_id: optional_string(row, "device_id"),
                username: optional_string(row, "username"),
                identity_source: optional_string(row, "identity_source"),
                last_seen: required_timestamp(row, "last_seen", "wireless.client.inventory")?,
                first_seen: required_timestamp(row, "first_seen", "wireless.client.inventory")?,
                signal_dbm: optional_i64(row, "signal_dbm")
                    .or_else(|| optional_i64(row, "last_signal_dbm")),
                is_authorized: bool_flag(row, "is_authorized"),
            })
        })
        .collect()
}

pub(crate) fn wireless_probe_request_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<WirelessProbeRequestInsert>, String> {
    if target != SinkTarget::WirelessProbeRequests {
        return Ok(Vec::new());
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(WirelessProbeRequestInsert {
                row_sequence: row_sequence(index, "wireless.probe.flush")?,
                client_mac: required_string(row, "client_mac", "wireless.probe.flush")?,
                ssid: required_string(row, "ssid", "wireless.probe.flush")?,
                known_bssid: optional_string(row, "known_bssid"),
                first_seen: required_timestamp(row, "first_seen", "wireless.probe.flush")?,
                last_seen: required_timestamp(row, "last_seen", "wireless.probe.flush")?,
                probe_count: required_i64(row, "probe_count", "wireless.probe.flush")?,
            })
        })
        .collect()
}
