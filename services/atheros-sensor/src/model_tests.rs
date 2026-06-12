use serde_json::json;

use super::{AuditEntry, IdentitySource};

#[test]
fn audit_entry_defaults_identity_source_when_missing() {
    let parsed: AuditEntry = serde_json::from_value(json!({
        "event_type": "wifi_management_frame",
        "observed_at": "2026-04-20T12:00:00Z",
        "sensor_id": "00:11:22:33:44:55",
        "location_id": "North-Wing-Entry",
        "interface": "wlan0",
        "channel": 6,
        "bssid": "10:20:30:40:50:60",
        "source_mac": "10:20:30:40:50:60",
        "destination_mac": "ff:ff:ff:ff:ff:ff",
        "ssid": "CorpWiFi",
        "frame_subtype": "beacon",
        "signal_dbm": -42,
        "sequence_number": 1,
        "raw_len": 44,
        "tags": ["wifi", "management"],
        "device_id": null,
        "username": null
    }))
    .unwrap();

    assert_eq!(parsed.schema_version, 1);
    assert_eq!(parsed.identity_source, IdentitySource::Unknown);
}

#[test]
fn audit_entry_unknown_identity_source_deserializes_to_unknown() {
    let parsed: AuditEntry = serde_json::from_value(json!({
        "event_type": "wifi_management_frame",
        "observed_at": "2026-04-20T12:00:00Z",
        "sensor_id": "00:11:22:33:44:55",
        "location_id": "North-Wing-Entry",
        "interface": "wlan0",
        "channel": 6,
        "bssid": "10:20:30:40:50:60",
        "source_mac": "10:20:30:40:50:60",
        "destination_mac": "ff:ff:ff:ff:ff:ff",
        "ssid": "CorpWiFi",
        "frame_subtype": "beacon",
        "signal_dbm": -42,
        "sequence_number": 1,
        "raw_len": 44,
        "tags": ["wifi", "management"],
        "device_id": null,
        "username": null,
        "identity_source": "future_source"
    }))
    .unwrap();

    assert_eq!(parsed.identity_source, IdentitySource::Unknown);
}
