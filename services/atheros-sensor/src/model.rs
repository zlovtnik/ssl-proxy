//! Three-tier model for wireless frame data.
//!
//! RawPacket is bytes off the wire with a capture timestamp, before any parsing.
//! WifiFrame is the fully parsed and decoded representation: radiotap metadata, 802.11 MAC
//! fields, all optional protocol layers (QoS, LLC/SNAP, IP, transport, application), correlation
//! keys, and anomaly flags. It is the internal working type throughout the parse pipeline.
//! AuditEntry is the serialized, published form: a flat JSON-friendly struct with all fields
//! optional where absent, enriched with sensor_id, location_id, device identity, and tags
//! before being published to Redpanda.
//!
//! # Type notes
//!
//! [`AuditEntry`]: the wire-format event published to Redpanda;
//! `schema_version` is always 2 for frames produced by this sensor (the serde default of 1
//! applies only when deserializing legacy payloads), and `identity_source` defaults to
//! `"unknown"` when the field is absent from a deserialized payload.
//!
//! [`WifiFrame`]: the parsed intermediate that flows through the pipeline; it carries both
//! flat convenience fields (e.g. `bssid`, `signal_dbm`) and the fully-typed nested layer
//! structs (`mac`, `rf`, `correlation`, `anomalies`) so callers can choose their access style.
//!
//! [`AuditContext`]: a snapshot of sensor identity (sensor ID, location, interface, channel,
//! regulatory domain) captured once at startup and threaded into every parse and publish call.
//!
//! [`MacLayer`]: the 802.11 MAC header fields serialized as a sub-object in `AuditEntry`;
//! `adjacent_mac_hint` is non-None when two address fields share the first five octets and
//! differ in the last by 1-4, a common AP/client interface adjacency indicator.
//!
//! [`RfLayer`]: the radiotap physical-layer fields serialized as a sub-object in `AuditEntry`;
//! `signal_status` is `"present"`, `"stripped"`, or `"absent"` and reflects whether the
//! radiotap header included a signal field at all.
//!
//! [`CorrelationLayer`]: deduplication and session-tracking keys serialized as a sub-object;
//! `frame_fingerprint` is a SHA-256 content hash and `session_key` is `source_mac|bssid`.
//!
//! [`AnomalyLayer`]: per-frame anomaly flags serialized as a sub-object; `reasons` is the
//! human-readable list of triggered heuristics (e.g. `"large_frame"`, `"retransmit_suspect"`).

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};

pub const WIRELESS_AUDIT_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    MacObserved,
    DeviceRegistry,
    EapIdentity,
    EapIdentityCache,
    ObservedIdentity,
    EvilTwinDetection,
    DeauthFloodDetection,
    MacLookupDisabled,
    MacLookupSkippedBackpressure,
    #[default]
    #[serde(other)]
    Unknown,
}

impl IdentitySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::MacObserved => "mac_observed",
            Self::DeviceRegistry => "device_registry",
            Self::EapIdentity => "eap_identity",
            Self::EapIdentityCache => "eap_identity_cache",
            Self::ObservedIdentity => "observed_identity",
            Self::EvilTwinDetection => "evil_twin_detection",
            Self::DeauthFloodDetection => "deauth_flood_detection",
            Self::MacLookupDisabled => "mac_lookup_disabled",
            Self::MacLookupSkippedBackpressure => "mac_lookup_skipped_backpressure",
        }
    }

    pub fn is_mac_lookup_pending(self) -> bool {
        matches!(self, Self::Unknown | Self::MacObserved)
    }
}

impl fmt::Display for IdentitySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MacLayer {
    pub frame_type: String,
    pub frame_subtype: String,
    pub to_ds: bool,
    pub from_ds: bool,
    pub protected: bool,
    pub retry: bool,
    pub more_data: bool,
    pub power_save: bool,
    pub sequence_number: Option<u16>,
    pub fragment_number: Option<u8>,
    pub bssid: Option<String>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub transmitter_mac: Option<String>,
    pub receiver_mac: Option<String>,
    pub adjacent_mac_hint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QosLayer {
    pub tid: u8,
    pub eosp: bool,
    pub ack_policy: u8,
    pub ack_policy_label: String,
    pub amsdu: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChannelFlagsLayer {
    pub raw: u16,
    pub labels: Vec<String>,
    pub is_2ghz: bool,
    pub is_5ghz: bool,
    pub ofdm: bool,
    pub cck: bool,
    pub dynamic_cck_ofdm: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RfLayer {
    pub tsft: Option<u64>,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub frequency_mhz: Option<u16>,
    pub channel_number: Option<u16>,
    pub channel_flags: Option<ChannelFlagsLayer>,
    pub data_rate_kbps: Option<u32>,
    pub antenna_id: Option<u8>,
    pub raw_len: usize,
    pub signal_status: String,
    #[serde(default)]
    pub vht_known: Option<u16>,
    #[serde(default)]
    pub vht_flags: Option<u8>,
    #[serde(default)]
    pub vht_bandwidth: Option<u8>,
    #[serde(default)]
    pub he_data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LlcSnapLayer {
    pub dsap: u8,
    pub ssap: u8,
    pub control: u8,
    pub oui: String,
    pub ethertype: u16,
    pub ethertype_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv4Layer {
    pub src_ip: String,
    pub dst_ip: String,
    pub ttl: u8,
    pub protocol: u8,
    pub protocol_name: String,
    pub header_len: u8,
    pub total_len: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransportLayer {
    pub protocol: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub length: Option<u16>,
    pub checksum: Option<u16>,
    pub tcp_flags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsLayer {
    pub query_names: Vec<String>,
    pub answer_names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DhcpLayer {
    pub message_type: Option<u8>,
    pub requested_ip: Option<String>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SsdpLayer {
    pub message_type: String,
    pub st: Option<String>,
    pub mx: Option<String>,
    pub usn: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApplicationLayer {
    pub protocol: Option<String>,
    pub ssdp: Option<SsdpLayer>,
    pub mdns: Option<DnsLayer>,
    pub dhcp: Option<DhcpLayer>,
    pub dns: Option<DnsLayer>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CorrelationLayer {
    pub session_key: Option<String>,
    pub retransmit_key: Option<String>,
    pub frame_fingerprint: String,
    pub payload_visibility: String,
    pub tsft_delta_us: Option<i64>,
    pub wall_clock_delta_ms: Option<i64>,
    #[serde(default)]
    pub sequence_delta: Option<u16>,
    #[serde(default)]
    pub sequence_gap_missing_frames: Option<u16>,
    #[serde(default)]
    pub clock_skew_delta_us: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnomalyLayer {
    pub large_frame: bool,
    pub mixed_encryption: Option<bool>,
    pub dedupe_or_replay_suspect: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RawPacket {
    pub observed_at: DateTime<Utc>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct WifiFrame {
    pub schema_version: u32,
    pub observed_at: DateTime<Utc>,
    pub event_type: String,
    pub frame_type: String,
    pub frame_type_raw: u8,
    pub frame_subtype_raw: u8,
    pub frame_control: u16,
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
    pub vht_known: Option<u16>,
    pub vht_flags: Option<u8>,
    pub vht_bandwidth: Option<u8>,
    pub he_data: Option<Vec<u8>>,
    pub sequence_number: Option<u16>,
    pub fragment_number: Option<u8>,
    pub channel_number: Option<u16>,
    pub signal_status: String,
    pub adjacent_mac_hint: Option<String>,
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
    pub band: String,
    pub tags: Vec<String>,
    pub risk_score: Option<f32>,
    pub security_flags: u32,
    pub rsn_capabilities: Option<u16>,
    pub weak_cipher_advertised: Option<bool>,
    pub wps_device_name: Option<String>,
    pub wps_manufacturer: Option<String>,
    pub wps_model_name: Option<String>,
    pub device_fingerprint: Option<String>,
    pub probe_fingerprint: Option<String>,
    pub ie_layout_hash: Option<String>,
    pub vendor_name: Option<String>,
    pub handshake_captured: bool,
    pub eapol_key_message: Option<u8>,
    pub pmkid: Option<String>,
    pub username_hint: Option<String>,
    pub identity_source_hint: Option<IdentitySource>,
    pub qos_tid: Option<u8>,
    pub qos_eosp: Option<bool>,
    pub qos_ack_policy: Option<u8>,
    pub qos_ack_policy_label: Option<String>,
    pub qos_amsdu: Option<bool>,
    pub llc_oui: Option<String>,
    pub ethertype: Option<u16>,
    pub ethertype_name: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ip_ttl: Option<u8>,
    pub ip_protocol: Option<u8>,
    pub ip_protocol_name: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport_protocol: Option<String>,
    pub transport_length: Option<u16>,
    pub transport_checksum: Option<u16>,
    pub app_protocol: Option<String>,
    pub ssdp_message_type: Option<String>,
    pub ssdp_st: Option<String>,
    pub ssdp_mx: Option<String>,
    pub ssdp_usn: Option<String>,
    pub dhcp_requested_ip: Option<String>,
    pub dhcp_hostname: Option<String>,
    pub dhcp_vendor_class: Option<String>,
    pub dns_query_name: Option<String>,
    pub mdns_name: Option<String>,
    pub session_key: Option<String>,
    pub retransmit_key: Option<String>,
    pub frame_fingerprint: String,
    pub payload_visibility: String,
    pub tsft_delta_us: Option<i64>,
    pub wall_clock_delta_ms: Option<i64>,
    pub sequence_delta: Option<u16>,
    pub sequence_gap_missing_frames: Option<u16>,
    pub clock_skew_delta_us: Option<i64>,
    pub large_frame: bool,
    pub mixed_encryption: Option<bool>,
    pub dedupe_or_replay_suspect: bool,
    pub anomaly_reasons: Vec<String>,
    pub mac: MacLayer,
    pub rf: RfLayer,
    pub qos: Option<QosLayer>,
    pub llc_snap: Option<LlcSnapLayer>,
    pub network: Option<Ipv4Layer>,
    pub transport: Option<TransportLayer>,
    pub application: Option<ApplicationLayer>,
    pub correlation: CorrelationLayer,
    pub anomalies: AnomalyLayer,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuditEntry {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: u8,
    #[serde(default = "default_band")]
    pub band: String,
    pub frame_type: Option<String>,
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
    pub vht_known: Option<u16>,
    pub vht_flags: Option<u8>,
    pub vht_bandwidth: Option<u8>,
    pub he_data: Option<Vec<u8>>,
    pub sequence_number: Option<u16>,
    pub fragment_number: Option<u8>,
    pub channel_number: Option<u16>,
    pub signal_status: Option<String>,
    pub adjacent_mac_hint: Option<String>,
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
    pub risk_score: Option<f32>,
    #[serde(default)]
    pub security_flags: u32,
    #[serde(default)]
    pub rsn_capabilities: Option<u16>,
    #[serde(default)]
    pub weak_cipher_advertised: Option<bool>,
    pub wps_device_name: Option<String>,
    pub wps_manufacturer: Option<String>,
    pub wps_model_name: Option<String>,
    pub device_fingerprint: Option<String>,
    pub probe_fingerprint: Option<String>,
    #[serde(default)]
    pub ie_layout_hash: Option<String>,
    pub vendor_name: Option<String>,
    #[serde(default)]
    pub handshake_captured: bool,
    pub qos_tid: Option<u8>,
    pub qos_eosp: Option<bool>,
    pub qos_ack_policy: Option<u8>,
    pub qos_ack_policy_label: Option<String>,
    pub qos_amsdu: Option<bool>,
    pub llc_oui: Option<String>,
    pub ethertype: Option<u16>,
    pub ethertype_name: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ip_ttl: Option<u8>,
    pub ip_protocol: Option<u8>,
    pub ip_protocol_name: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport_protocol: Option<String>,
    pub transport_length: Option<u16>,
    pub transport_checksum: Option<u16>,
    pub app_protocol: Option<String>,
    pub ssdp_message_type: Option<String>,
    pub ssdp_st: Option<String>,
    pub ssdp_mx: Option<String>,
    pub ssdp_usn: Option<String>,
    pub dhcp_requested_ip: Option<String>,
    pub dhcp_hostname: Option<String>,
    pub dhcp_vendor_class: Option<String>,
    pub dns_query_name: Option<String>,
    pub mdns_name: Option<String>,
    pub session_key: Option<String>,
    pub retransmit_key: Option<String>,
    pub frame_fingerprint: Option<String>,
    pub payload_visibility: Option<String>,
    pub tsft_delta_us: Option<i64>,
    pub wall_clock_delta_ms: Option<i64>,
    #[serde(default)]
    pub sequence_delta: Option<u16>,
    #[serde(default)]
    pub sequence_gap_missing_frames: Option<u16>,
    #[serde(default)]
    pub clock_skew_delta_us: Option<i64>,
    pub large_frame: Option<bool>,
    pub mixed_encryption: Option<bool>,
    pub dedupe_or_replay_suspect: Option<bool>,
    #[serde(default)]
    pub anomaly_reasons: Vec<String>,
    pub mac: Option<MacLayer>,
    pub rf: Option<RfLayer>,
    pub qos: Option<QosLayer>,
    pub llc_snap: Option<LlcSnapLayer>,
    pub network: Option<Ipv4Layer>,
    pub transport: Option<TransportLayer>,
    pub application: Option<ApplicationLayer>,
    pub correlation: Option<CorrelationLayer>,
    pub anomalies: Option<AnomalyLayer>,
    #[serde(serialize_with = "serialize_option_as_null")]
    pub device_id: Option<String>,
    pub username: Option<String>,
    #[serde(default)]
    pub identity_source: IdentitySource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandshakeAlert {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub bssid: String,
    pub client_mac: String,
    pub signal_dbm: Option<i8>,
    pub pmkid: Option<String>,
}

fn default_schema_version() -> u32 {
    1
}

fn default_band() -> String {
    "unknown".to_string()
}

fn serialize_option_as_null<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.serialize(serializer)
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
