use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::AuditEntry;

pub const BANDWIDTH_SUBJECT: &str = "audit.wireless.bandwidth";
pub const DEFAULT_BANDWIDTH_WINDOW_SECS: i64 = 60;
pub const EXTERNAL_BANDWIDTH_THRESHOLD_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WirelessBandwidthEvent {
    pub event_type: String,
    pub window_start: String,
    pub window_end: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub channel: u8,
    pub source_mac: String,
    pub destination_bssid: String,
    pub ssid: Option<String>,
    pub bytes: u64,
    pub frame_count: u64,
    pub retry_count: u64,
    pub more_data_count: u64,
    pub power_save_count: u64,
    pub strongest_signal_dbm: Option<i8>,
    pub external_bssid: bool,
    pub threshold_exceeded: bool,
}

#[derive(Debug, Error)]
pub enum TrafficBucketError {
    #[error("invalid observed_at timestamp {observed_at:?}: {source}")]
    InvalidObservedAt {
        observed_at: String,
        source: chrono::ParseError,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TrafficKey {
    sensor_id: String,
    location_id: String,
    interface: String,
    channel: u8,
    source_mac: String,
    destination_bssid: String,
    ssid: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct TrafficCounters {
    bytes: u64,
    frame_count: u64,
    retry_count: u64,
    more_data_count: u64,
    power_save_count: u64,
    strongest_signal_dbm: Option<i8>,
}

#[derive(Clone, Debug)]
pub struct TrafficBucket {
    window: Duration,
    window_start: Option<DateTime<Utc>>,
    entries: HashMap<TrafficKey, TrafficCounters>,
}

impl TrafficBucket {
    pub fn new(window_secs: i64) -> Self {
        Self {
            window: Duration::seconds(window_secs.max(1)),
            window_start: None,
            entries: HashMap::new(),
        }
    }

    pub fn observe_raw(&mut self, bytes: u64, observed_at: DateTime<Utc>) -> Vec<WirelessBandwidthEvent> {
        let flushed = self.flush_if_elapsed(observed_at);

        if self.window_start.is_none() {
            self.window_start = Some(observed_at);
        }

        // Count raw bytes against unknown bucket for unsupported frames
        let key = TrafficKey {
            sensor_id: "unknown".to_string(),
            location_id: "unknown".to_string(),
            interface: "unknown".to_string(),
            channel: 0,
            source_mac: "unknown".to_string(),
            destination_bssid: "unknown".to_string(),
            ssid: None,
        };

        let counters = self.entries.entry(key).or_default();
        counters.bytes = counters.bytes.saturating_add(bytes);
        counters.frame_count = counters.frame_count.saturating_add(1);

        flushed
    }

    pub fn observe(
        &mut self,
        entry: &AuditEntry,
    ) -> Result<Vec<WirelessBandwidthEvent>, TrafficBucketError> {
        let observed_at = DateTime::parse_from_rfc3339(&entry.observed_at).map_err(|source| {
            TrafficBucketError::InvalidObservedAt {
                observed_at: entry.observed_at.clone(),
                source,
            }
        })?;
        let observed_at = observed_at.with_timezone(&Utc);
        let flushed = self.flush_if_elapsed(observed_at);
        if !is_bandwidth_candidate(entry) {
            return Ok(flushed);
        }

        if self.window_start.is_none() {
            self.window_start = Some(observed_at);
        }

        let Some(source_mac) = entry.source_mac.as_deref().map(normalize_mac) else {
            return Ok(flushed);
        };
        let Some(destination_bssid) = entry
            .destination_bssid
            .as_deref()
            .or(entry.bssid.as_deref())
            .map(normalize_mac)
        else {
            return Ok(flushed);
        };
        let key = TrafficKey {
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            interface: entry.interface.clone(),
            channel: entry.channel,
            source_mac,
            destination_bssid,
            ssid: entry.ssid.clone(),
        };
        let counters = self.entries.entry(key).or_default();
        counters.bytes = counters.bytes.saturating_add(entry.raw_len as u64);
        counters.frame_count = counters.frame_count.saturating_add(1);
        if entry.retry.unwrap_or(false) {
            counters.retry_count = counters.retry_count.saturating_add(1);
        }
        if entry.more_data.unwrap_or(false) {
            counters.more_data_count = counters.more_data_count.saturating_add(1);
        }
        if entry.power_save.unwrap_or(false) {
            counters.power_save_count = counters.power_save_count.saturating_add(1);
        }
        if let Some(signal) = entry.signal_dbm {
            counters.strongest_signal_dbm = Some(
                counters
                    .strongest_signal_dbm
                    .map(|current| current.max(signal))
                    .unwrap_or(signal),
            );
        }
        Ok(flushed)
    }

    pub fn flush_current(&mut self) -> Vec<WirelessBandwidthEvent> {
        let Some(window_start) = self.window_start.take() else {
            return Vec::new();
        };
        self.drain_window(window_start)
    }

    fn flush_if_elapsed(&mut self, observed_at: DateTime<Utc>) -> Vec<WirelessBandwidthEvent> {
        let Some(window_start) = self.window_start else {
            self.window_start = Some(observed_at);
            return Vec::new();
        };
        if observed_at < window_start + self.window {
            return Vec::new();
        }
        self.window_start = Some(observed_at);
        self.drain_window(window_start)
    }

    fn drain_window(&mut self, window_start: DateTime<Utc>) -> Vec<WirelessBandwidthEvent> {
        let window_end = window_start + self.window;
        let mut events = Vec::with_capacity(self.entries.len());
        for (key, counters) in self.entries.drain() {
            events.push(WirelessBandwidthEvent {
                event_type: "wireless_bandwidth_window".to_string(),
                window_start: window_start.to_rfc3339(),
                window_end: window_end.to_rfc3339(),
                sensor_id: key.sensor_id,
                location_id: key.location_id,
                interface: key.interface,
                channel: key.channel,
                source_mac: key.source_mac,
                destination_bssid: key.destination_bssid,
                ssid: key.ssid,
                bytes: counters.bytes,
                frame_count: counters.frame_count,
                retry_count: counters.retry_count,
                more_data_count: counters.more_data_count,
                power_save_count: counters.power_save_count,
                strongest_signal_dbm: counters.strongest_signal_dbm,
                external_bssid: false,
                threshold_exceeded: false,
            });
        }
        events
    }
}

fn is_bandwidth_candidate(entry: &AuditEntry) -> bool {
    entry.event_type == "wifi_data_frame"
        && entry.protected.unwrap_or(false)
        && entry.raw_len > 0
        && entry.source_mac.is_some()
        && (entry.destination_bssid.is_some() || entry.bssid.is_some())
}

fn normalize_mac(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
