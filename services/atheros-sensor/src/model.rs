use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Clone, Debug)]
pub struct RawPacket {
    pub observed_at: DateTime<Utc>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct WifiFrame {
    pub observed_at: DateTime<Utc>,
    pub event_type: String,
    pub bssid: Option<String>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub ssid: Option<String>,
    pub frame_subtype: String,
    pub signal_dbm: Option<i8>,
    pub sequence_number: Option<u16>,
    pub raw_len: usize,
    pub tags: Vec<String>,
    pub username_hint: Option<String>,
    pub identity_source_hint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuditContext {
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: u8,
    pub reg_domain: String,
}

#[derive(Clone, Debug)]
pub struct EnrichedFrame {
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: u8,
    pub reg_domain: String,
    pub frame: WifiFrame,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEntry {
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: u8,
    pub bssid: Option<String>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub ssid: Option<String>,
    pub frame_subtype: String,
    pub signal_dbm: Option<i8>,
    pub sequence_number: Option<u16>,
    pub raw_len: usize,
    pub tags: Vec<String>,
    #[serde(serialize_with = "serialize_option_as_null")]
    pub device_id: Option<String>,
    pub username: Option<String>,
    #[serde(default = "default_identity_source")]
    pub identity_source: String,
}

fn default_identity_source() -> String {
    "unknown".to_string()
}

fn serialize_option_as_null<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.serialize(serializer)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::AuditEntry;

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

        assert_eq!(parsed.identity_source, "unknown");
    }
}
