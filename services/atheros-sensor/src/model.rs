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
    pub destination_bssid: Option<String>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub transmitter_mac: Option<String>,
    pub receiver_mac: Option<String>,
    pub ssid: Option<String>,
    pub frame_subtype: String,
    pub tsft: Option<u64>,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub frequency_mhz: Option<u16>,
    pub channel_flags: Option<u16>,
    pub data_rate_kbps: Option<u32>,
    pub antenna_id: Option<u8>,
    pub sequence_number: Option<u16>,
    pub duration_id: u16,
    pub frame_control_flags: u16,
    pub more_data: bool,
    pub retry: bool,
    pub power_save: bool,
    pub protected: bool,
    pub to_ds: bool,
    pub from_ds: bool,
    pub raw_len: usize,
    pub raw_frame: Option<String>,
    pub tags: Vec<String>,
    pub security_flags: u32,
    pub wps_device_name: Option<String>,
    pub wps_manufacturer: Option<String>,
    pub wps_model_name: Option<String>,
    pub device_fingerprint: Option<String>,
    pub handshake_captured: bool,
    pub eapol_key_message: Option<u8>,
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
    pub destination_bssid: Option<String>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub transmitter_mac: Option<String>,
    pub receiver_mac: Option<String>,
    pub ssid: Option<String>,
    pub frame_subtype: String,
    pub tsft: Option<u64>,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub frequency_mhz: Option<u16>,
    pub channel_flags: Option<u16>,
    pub data_rate_kbps: Option<u32>,
    pub antenna_id: Option<u8>,
    pub sequence_number: Option<u16>,
    pub duration_id: Option<u16>,
    pub frame_control_flags: Option<u16>,
    pub more_data: Option<bool>,
    pub retry: Option<bool>,
    pub power_save: Option<bool>,
    pub protected: Option<bool>,
    pub to_ds: Option<bool>,
    pub from_ds: Option<bool>,
    pub raw_len: usize,
    pub raw_frame: Option<String>,
    pub tags: Vec<String>,
    #[serde(default)]
    pub security_flags: u32,
    pub wps_device_name: Option<String>,
    pub wps_manufacturer: Option<String>,
    pub wps_model_name: Option<String>,
    pub device_fingerprint: Option<String>,
    #[serde(default)]
    pub handshake_captured: bool,
    #[serde(serialize_with = "serialize_option_as_null")]
    pub device_id: Option<String>,
    pub username: Option<String>,
    #[serde(default = "default_identity_source")]
    pub identity_source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandshakeAlert {
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub bssid: String,
    pub client_mac: String,
    pub signal_dbm: Option<i8>,
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
