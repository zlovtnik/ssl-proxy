use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessAuditFrameInsert {
    pub row_sequence: i64,
    pub event_type: String,
    pub observed_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: i64,
    pub frame_type: Option<String>,
    pub frame_subtype: String,
    pub bssid: Option<String>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub transmitter_mac: Option<String>,
    pub receiver_mac: Option<String>,
    pub destination_bssid: Option<String>,
    pub ssid: Option<String>,
    pub signal_dbm: Option<i64>,
    pub sequence_number: Option<i64>,
    pub raw_len: i64,
    pub is_retry: i64,
    pub is_more_data: i64,
    pub is_power_save: i64,
    pub is_protected: i64,
    pub is_to_ds: i64,
    pub is_from_ds: i64,
    pub is_handshake: i64,
    pub security_flags: i64,
    pub device_id: Option<String>,
    pub username: Option<String>,
    pub identity_source: String,
    pub tags: String,
    pub anomaly_reasons: String,
    pub raw_json: String,
    pub reg_domain: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessBandwidthInsert {
    pub row_sequence: i64,
    pub schema_version: i64,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: i64,
    pub source_mac: String,
    pub destination_bssid: String,
    pub ssid: Option<String>,
    pub bytes: i64,
    pub frame_count: i64,
    pub retry_count: i64,
    pub more_data_count: i64,
    pub power_save_count: i64,
    pub strongest_signal_dbm: Option<i64>,
    pub hist_under_100: i64,
    pub hist_100_500: i64,
    pub hist_500_1000: i64,
    pub hist_1000_1500: i64,
    pub inter_arrival_p50_ms: Option<i64>,
    pub external_bssid: i64,
    pub threshold_exceeded: i64,
    pub wall_clock_delta_ms: Option<i64>,
    pub window_is_partial: i64,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessRogueApInsert {
    pub row_sequence: i64,
    pub detected_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: i64,
    pub rogue_bssid: String,
    pub ssid: Option<String>,
    pub signal_dbm: Option<i64>,
    pub ssid_impersonation: i64,
    pub raw_json: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessDeauthFloodInsert {
    pub row_sequence: i64,
    pub detected_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: i64,
    pub attacker_mac: Option<String>,
    pub target_bssid: Option<String>,
    pub target_ssid: Option<String>,
    pub deauth_count: i64,
    pub window_secs: i64,
    pub threshold: i64,
    pub signal_dbm: Option<i64>,
    pub raw_json: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessSignalAnomalyInsert {
    pub row_sequence: i64,
    pub detected_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub source_mac: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: i64,
    pub baseline_dbm: i64,
    pub observed_dbm: i64,
    pub dbm_delta: i64,
    pub configured_delta: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessPmfAttackInsert {
    pub row_sequence: i64,
    pub detected_at: DateTime<Utc>,
    pub sensor_id: String,
    pub location_id: String,
    pub target_mac: String,
    pub target_bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: Option<i64>,
    pub attack_tag: String,
    pub reconnect_window_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessClientInventoryInsert {
    pub sensor_id: String,
    pub location_id: String,
    pub snapshot_at: DateTime<Utc>,
    pub client_mac: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub device_id: Option<String>,
    pub username: Option<String>,
    pub identity_source: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    pub signal_dbm: Option<i64>,
    pub is_authorized: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WirelessProbeRequestInsert {
    pub row_sequence: i64,
    pub client_mac: String,
    pub ssid: String,
    pub known_bssid: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub probe_count: i64,
}
