//! Sliding-window traffic accumulator for bandwidth monitoring.
//!
//! Aggregates protected WiFi data frames into time-bucketed summaries keyed by
//! (sensor, location, interface, channel, source_mac, destination_bssid, ssid).
//! EXTERNAL_BANDWIDTH_THRESHOLD_BYTES triggers alerts when external BSSID traffic
//! exceeds 500 MB per window, indicating potential rogue AP or data exfiltration.
//!
//! [`TrafficBucket`]: accumulates frame counters for the current window; when an observation
//! arrives whose timestamp falls at or past `window_start + window`, the old window is
//! flushed and returned as events before the new observation is recorded — so the flush is
//! driven by the next incoming frame, not a timer.
//!
//! [`WirelessBandwidthEvent`]: the flushed summary for one (source_mac, destination_bssid)
//! pair; `external_bssid` is true when the BSSID is not in the authorized network list, and
//! `threshold_exceeded` is the actionable field that signals a potential exfiltration event.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::AuditEntry;

pub const BANDWIDTH_SUBJECT: &str = "audit.wireless.bandwidth";
pub const DEFAULT_BANDWIDTH_WINDOW_SECS: i64 = 60;
pub const EXTERNAL_BANDWIDTH_THRESHOLD_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FrameSizeHistogram {
    pub under_100: u64,
    pub range_100_500: u64,
    pub range_500_1000: u64,
    pub range_1000_1500: u64,
}

impl Default for FrameSizeHistogram {
    fn default() -> Self {
        Self {
            under_100: 0,
            range_100_500: 0,
            range_500_1000: 0,
            range_1000_1500: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WirelessBandwidthEvent {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
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
    #[serde(default)]
    pub frame_size_histogram: FrameSizeHistogram,
    pub inter_arrival_p50_ms: Option<u64>,
}

fn default_schema_version() -> u32 {
    1
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
    external_bssid: bool,
}

#[derive(Clone, Debug, Default)]
struct TrafficCounters {
    bytes: u64,
    frame_count: u64,
    retry_count: u64,
    more_data_count: u64,
    power_save_count: u64,
    strongest_signal_dbm: Option<i8>,
    histogram: [u64; 4],
    arrival_times_ms: Vec<i64>,
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

    /// Counts raw bytes for frames that cannot be parsed into structured audit entries.
    /// Uses a fixed "unknown" key for source_mac and destination_bssid since the frame
    /// structure is unsupported and no MAC addresses can be extracted.
    pub fn observe_raw(
        &mut self,
        bytes: u64,
        observed_at: DateTime<Utc>,
        sensor_id: &str,
        location_id: &str,
        interface: &str,
        channel: u8,
    ) -> Vec<WirelessBandwidthEvent> {
        let flushed = self.flush_if_elapsed(observed_at);

        if self.window_start.is_none() {
            self.window_start = Some(observed_at);
        }

        // Count raw bytes against unknown bucket for unsupported frames
        let key = TrafficKey {
            sensor_id: sensor_id.to_string(),
            location_id: location_id.to_string(),
            interface: interface.to_string(),
            channel,
            source_mac: "unknown".to_string(),
            destination_bssid: "unknown".to_string(),
            ssid: None,
            external_bssid: false,
        };

        let counters = self.entries.entry(key).or_default();
        counters.bytes = counters.bytes.saturating_add(bytes);
        counters.frame_count = counters.frame_count.saturating_add(1);

        flushed
    }

    /// Accumulates frame counters for the current window; when the observation timestamp
    /// reaches or exceeds window_start + window, the old window is flushed and returned
    /// before recording the new observation — flush is driven by incoming frames, not a timer.
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        external_bssid: bool,
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
            external_bssid,
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
        let size = entry.raw_len as u64;
        match size {
            0..=99 => counters.histogram[0] += 1,
            100..=499 => counters.histogram[1] += 1,
            500..=999 => counters.histogram[2] += 1,
            1000..=1499 => counters.histogram[3] += 1,
            _ => {}
        }
        counters.arrival_times_ms.push(observed_at.timestamp_millis());
        Ok(flushed)
    }

    pub fn flush_current(&mut self) -> Vec<WirelessBandwidthEvent> {
        let Some(window_start) = self.window_start.take() else {
            return Vec::new();
        };
        self.drain_window(window_start)
    }

    /// Checks if the current observation falls at or past the window boundary; if so,
    /// advances the window and drains all accumulated counters into events.
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

    /// Drains all accumulated counters into bandwidth events and clears the entries map.
    fn drain_window(&mut self, window_start: DateTime<Utc>) -> Vec<WirelessBandwidthEvent> {
        let window_end = window_start + self.window;
        let mut events = Vec::with_capacity(self.entries.len());
        for (key, counters) in self.entries.drain() {
            let inter_arrival_p50_ms = calculate_p50_inter_arrival(&counters.arrival_times_ms);
            events.push(WirelessBandwidthEvent {
                schema_version: 1,
                event_type: "wireless_bandwidth_window".to_string(),
                window_start: ssl_proxy::time::rfc3339_from_utc(window_start),
                window_end: ssl_proxy::time::rfc3339_from_utc(window_end),
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
                external_bssid: key.external_bssid,
                threshold_exceeded: key.external_bssid
                    && counters.bytes > EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
                frame_size_histogram: FrameSizeHistogram {
                    under_100: counters.histogram[0],
                    range_100_500: counters.histogram[1],
                    range_500_1000: counters.histogram[2],
                    range_1000_1500: counters.histogram[3],
                },
                inter_arrival_p50_ms,
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

fn calculate_p50_inter_arrival(times_ms: &[i64]) -> Option<u64> {
    if times_ms.len() < 2 {
        return None;
    }
    let mut sorted_times = times_ms.to_vec();
    sorted_times.sort_unstable();
    let mut intervals: Vec<u64> = sorted_times
        .windows(2)
        .filter_map(|w| {
            let delta = w[1] - w[0];
            if delta >= 0 {
                Some(delta as u64)
            } else {
                None
            }
        })
        .collect();
    if intervals.is_empty() {
        return None;
    }
    intervals.sort_unstable();
    Some(intervals[intervals.len() / 2])
}
