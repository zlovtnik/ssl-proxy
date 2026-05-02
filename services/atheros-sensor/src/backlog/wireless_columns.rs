//! Projection layer for wireless-specific columns in sync_scan_ingest.
//!
//! Extracts wireless audit fields (MAC addresses, SSID, signal strength, frame flags) from
//! JSON payloads only when stream_name == "wireless.audit". All other streams get zero/null
//! values, allowing the same table schema to handle multiple event types without bloat.

/// Projection layer for wireless-specific columns in sync_scan_ingest.
///
/// All fields default to zero/false/None when stream_name != "wireless.audit", allowing
/// the same table schema to handle multiple event types without bloat. String fields are
/// sanitized to remove control characters and null bytes before insertion.
#[derive(Clone, Debug, Default)]
pub(super) struct WirelessIngestColumns {
    /// Source MAC address (maps to `source_mac` column).
    pub(super) source_mac: Option<String>,
    /// Basic Service Set Identifier / access point MAC (maps to `bssid` column).
    pub(super) bssid: Option<String>,
    /// Destination BSSID from frame header (maps to `destination_bssid` column).
    pub(super) destination_bssid: Option<String>,
    /// Network SSID (maps to `ssid` column).
    pub(super) ssid: Option<String>,
    /// Signal strength in dBm (maps to `signal_dbm` column).
    pub(super) signal_dbm: Option<i32>,
    /// Raw frame length in bytes (maps to `raw_len` column).
    pub(super) raw_len: i32,
    /// 802.11 frame control flags bitmap (maps to `frame_control_flags` column).
    pub(super) frame_control_flags: i32,
    /// More Data flag from frame control (maps to `more_data` column).
    pub(super) more_data: bool,
    /// Retry flag from frame control (maps to `retry` column).
    pub(super) retry: bool,
    /// Power Save flag from frame control (maps to `power_save` column).
    pub(super) power_save: bool,
    /// Protected Frame flag from frame control (maps to `protected` column).
    pub(super) protected: bool,
    /// Security capabilities bitmap (maps to `security_flags` column).
    pub(super) security_flags: i32,
    /// WPS device name from beacon/probe (maps to `wps_device_name` column).
    pub(super) wps_device_name: Option<String>,
    /// WPS manufacturer from beacon/probe (maps to `wps_manufacturer` column).
    pub(super) wps_manufacturer: Option<String>,
    /// WPS model name from beacon/probe (maps to `wps_model_name` column).
    pub(super) wps_model_name: Option<String>,
    /// Device fingerprint hash (maps to `device_fingerprint` column).
    pub(super) device_fingerprint: Option<String>,
    /// Probe request fingerprint hash (maps to `probe_fingerprint` column).
    pub(super) probe_fingerprint: Option<String>,
    /// Vendor name from OUI lookup (maps to `vendor_name` column).
    pub(super) vendor_name: Option<String>,
    /// Whether a WPA handshake was captured (maps to `handshake_captured` column).
    pub(super) handshake_captured: bool,
}

impl WirelessIngestColumns {
    /// Extracts wireless columns from JSON payload only when stream_name == "wireless.audit".
    /// All other streams get default (zero/null) values. The destination_bssid field falls back
    /// to bssid when not present.
    pub(super) fn from_payload(stream_name: &str, payload: &serde_json::Value) -> Self {
        if stream_name != "wireless.audit" {
            return Self::default();
        }

        Self {
            source_mac: payload_string(payload, "source_mac"),
            bssid: payload_string(payload, "bssid"),
            destination_bssid: payload_string(payload, "destination_bssid")
                .or_else(|| payload_string(payload, "bssid")),
            ssid: payload_string(payload, "ssid"),
            signal_dbm: payload_i32(payload, "signal_dbm"),
            raw_len: payload_i32(payload, "raw_len").unwrap_or(0),
            frame_control_flags: payload_i32(payload, "frame_control_flags").unwrap_or(0),
            more_data: payload_bool(payload, "more_data"),
            retry: payload_bool(payload, "retry"),
            power_save: payload_bool(payload, "power_save"),
            protected: payload_bool(payload, "protected"),
            security_flags: payload
                .get("security_flags")
                .and_then(|value| value.as_u64())
                .and_then(|value| i32::try_from(value).ok())
                .unwrap_or(0),
            wps_device_name: payload_string(payload, "wps_device_name"),
            wps_manufacturer: payload_string(payload, "wps_manufacturer"),
            wps_model_name: payload_string(payload, "wps_model_name"),
            device_fingerprint: payload_string(payload, "device_fingerprint"),
            probe_fingerprint: payload_string(payload, "probe_fingerprint"),
            vendor_name: payload_string(payload, "vendor_name"),
            handshake_captured: payload
                .get("handshake_captured")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
        }
    }
}

/// Extracts an i32 from a JSON value, accepting either a number or a string that parses as i64.
/// Returns None if the key is missing, the value is not a number/string, or the parsed value
/// does not fit in i32 range.
fn payload_i32(payload: &serde_json::Value, key: &str) -> Option<i32> {
    payload
        .get(key)
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|raw| raw.parse::<i64>().ok()))
        })
        .and_then(|value| i32::try_from(value).ok())
}

/// Extracts a bool from a JSON value, accepting either a boolean or a string that parses as bool.
/// Returns false if the key is missing or the value cannot be interpreted as a boolean.
fn payload_bool(payload: &serde_json::Value, key: &str) -> bool {
    payload
        .get(key)
        .and_then(|value| {
            value
                .as_bool()
                .or_else(|| value.as_str().and_then(|raw| raw.parse::<bool>().ok()))
        })
        .unwrap_or(false)
}

/// Removes control characters (except whitespace) and null bytes from a string to prevent
/// Postgres TEXT encoding errors. Whitespace characters (space, tab, newline) are preserved.
fn sanitize_string(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .filter(|&c| c != '\0')
        .collect()
}

/// Extracts a sanitized, trimmed string from a JSON value.
/// Returns None if the key is missing, the value is not a string, or the result is empty
/// after sanitization and trimming. Sanitization removes control characters and null bytes.
fn payload_string(payload: &serde_json::Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(|value| value.as_str())
        .map(sanitize_string)
        .map(|s| s.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::WirelessIngestColumns;

    use chrono::{DateTime, Utc};
    use tokio_postgres::types::{Json, ToSql, Type};

    #[test]
    fn chrono_utc_datetime_binds_to_postgres_timestamptz() {
        assert!(<DateTime<Utc> as ToSql>::accepts(&Type::TIMESTAMPTZ));
        assert!(!<&str as ToSql>::accepts(&Type::TIMESTAMPTZ));
    }

    #[test]
    fn json_wrapper_binds_to_postgres_jsonb() {
        assert!(<Json<serde_json::Value> as ToSql>::accepts(&Type::JSONB));
        assert!(!<&str as ToSql>::accepts(&Type::JSONB));
    }

    #[test]
    fn extracts_wireless_ingest_columns_from_payload() {
        let payload = serde_json::json!({
            "source_mac": "aa:bb:cc:dd:ee:01",
            "bssid": "10:20:30:40:50:60",
            "destination_bssid": "10:20:30:40:50:60",
            "ssid": "CorpWiFi",
            "signal_dbm": -42,
            "raw_len": 1440,
            "frame_control_flags": 30984,
            "more_data": true,
            "retry": true,
            "power_save": true,
            "protected": true,
            "security_flags": 26,
            "wps_device_name": "Lobby AP",
            "wps_manufacturer": "Acme",
            "wps_model_name": "Model 7",
            "device_fingerprint": "0123456789abcdef",
            "handshake_captured": true
        });

        let columns = WirelessIngestColumns::from_payload("wireless.audit", &payload);

        assert_eq!(columns.source_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(columns.bssid.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(
            columns.destination_bssid.as_deref(),
            Some("10:20:30:40:50:60")
        );
        assert_eq!(columns.ssid.as_deref(), Some("CorpWiFi"));
        assert_eq!(columns.signal_dbm, Some(-42));
        assert_eq!(columns.raw_len, 1440);
        assert_eq!(columns.frame_control_flags, 30984);
        assert!(columns.more_data);
        assert!(columns.retry);
        assert!(columns.power_save);
        assert!(columns.protected);
        assert_eq!(columns.security_flags, 26);
        assert_eq!(columns.wps_device_name.as_deref(), Some("Lobby AP"));
        assert_eq!(columns.wps_manufacturer.as_deref(), Some("Acme"));
        assert_eq!(columns.wps_model_name.as_deref(), Some("Model 7"));
        assert_eq!(
            columns.device_fingerprint.as_deref(),
            Some("0123456789abcdef")
        );
        assert!(columns.handshake_captured);
    }
}
