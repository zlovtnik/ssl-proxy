//! Sliding-window traffic accumulator for bandwidth monitoring.
//!
//! Aggregates protected WiFi data frames into time-bucketed summaries keyed by
//! (sensor, location, interface, channel, source_mac, destination_bssid, ssid).
//! EXTERNAL_BANDWIDTH_THRESHOLD_BYTES triggers alerts when external BSSID traffic
//! exceeds 500 MB per window, indicating potential rogue AP or data exfiltration.
//!
//! [`TrafficBucket`]: accumulates frame counters for the current window; a
//! wall-clock [`Instant`] drives the flush decision, while the frame-level
//! `observed_at` timestamp is used only for window attribution in the emitted
//! event. This decouples flush timing from potentially-skewed or replayed frame
//! timestamps.
//!
//! [`WirelessBandwidthEvent`]: the flushed summary for one (source_mac, destination_bssid)
//! pair; `external_bssid` is true when the BSSID is not in the authorized network list, and
//! `threshold_exceeded` is the actionable field that signals a potential exfiltration event.
//! `wall_clock_delta_ms` reports how far behind the frame timestamp is from wall clock,
//! giving operators a per-window health signal. `window_is_partial` is true when the flush
//! was triggered by the periodic timer rather than by an incoming frame crossing the boundary.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::model::AuditEntry;

pub const BANDWIDTH_TOPIC: &str = "audit.wireless.bandwidth";
pub const DEFAULT_BANDWIDTH_WINDOW_SECS: i64 = 60;
pub const EXTERNAL_BANDWIDTH_THRESHOLD_BYTES: u64 = 500 * 1024 * 1024;
const DEFAULT_TRAFFIC_BUCKET_MAX_ENTRIES: usize = 65_536;
const ARRIVAL_RESERVOIR_SIZE: usize = 1024;

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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
    #[serde(default)]
    pub inter_arrival_p50_ms: Option<u64>,
    /// Coefficient of variation (CV) of inter-arrival times = stddev / mean.
    /// Higher values indicate burstier traffic patterns. None when < 2 samples.
    #[serde(default)]
    pub inter_arrival_cv: Option<f64>,
    /// Milliseconds between wall-clock time and the frame timestamp at flush time.
    /// Positive values mean the frame timestamp is behind wall clock (the common case
    /// for backlog or delayed processing). This gives operators a per-window health
    /// signal showing sensor lag.
    #[serde(default)]
    pub wall_clock_delta_ms: Option<i64>,
    /// True when the flush was triggered by the periodic timer (`flush_current`)
    /// rather than by an incoming frame crossing the window boundary. Partial
    /// windows occur during idle periods and at shutdown.
    #[serde(default)]
    pub window_is_partial: bool,
    /// Highest risk score seen in this traffic window.
    #[serde(default)]
    pub max_risk_score: Option<f32>,
    /// RFC3339 wall-clock timestamp at the moment this event was serialized
    /// and enqueued for publish. Allows downstream consumers to compute
    /// `published_at - window_end` as a drift metric per event.
    #[serde(default)]
    pub published_at: Option<String>,
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

#[derive(Clone, Debug)]
struct TrafficCounters {
    bytes: u64,
    frame_count: u64,
    retry_count: u64,
    more_data_count: u64,
    power_save_count: u64,
    strongest_signal_dbm: Option<i8>,
    histogram: [u64; 4],
    arrival_times_ms: Vec<i64>,
    arrival_reservoir_size: usize,
    max_risk_score: Option<f32>,
}

impl Default for TrafficCounters {
    fn default() -> Self {
        Self {
            bytes: 0,
            frame_count: 0,
            retry_count: 0,
            more_data_count: 0,
            power_save_count: 0,
            strongest_signal_dbm: None,
            histogram: [0; 4],
            arrival_times_ms: Vec::new(),
            arrival_reservoir_size: ARRIVAL_RESERVOIR_SIZE,
            max_risk_score: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrafficBucket {
    window: Duration,
    /// Frame-time start of the current window (used for attribution in emitted events).
    window_start: Option<DateTime<Utc>>,
    /// Wall-clock start of the current window (used for flush decision).
    wall_clock_start: Option<Instant>,
    entries: HashMap<TrafficKey, TrafficCounters>,
    max_entries: usize,
    /// Source MACs from the most recent drain that had inter_arrival_cv < 0.05,
    /// indicating automated (non-human) burst traffic. Cleared on each drain.
    burst_macs: HashSet<String>,
}

impl TrafficBucket {
    pub fn new(window_secs: i64) -> Self {
        Self::with_entry_limit(window_secs, DEFAULT_TRAFFIC_BUCKET_MAX_ENTRIES)
    }

    fn with_entry_limit(window_secs: i64, max_entries: usize) -> Self {
        Self {
            window: Duration::seconds(window_secs.max(1)),
            window_start: None,
            wall_clock_start: None,
            entries: HashMap::new(),
            max_entries: max_entries.max(1),
            burst_macs: HashSet::new(),
        }
    }

    /// Returns the set of source MACs that exhibited low inter-arrival CV (< 0.05)
    /// in the most recent drain, indicating automated burst traffic. Clears the
    /// set after returning so each burst set is consumed exactly once.
    pub fn take_burst_macs(&mut self) -> HashSet<String> {
        std::mem::take(&mut self.burst_macs)
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
            self.wall_clock_start = Some(Instant::now());
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
        self.enforce_entry_limit();

        flushed
    }

    /// Accumulates frame counters for the current window; when the wall-clock elapsed
    /// time reaches or exceeds the window duration, the old window is flushed and
    /// returned before recording the new observation. The frame `observed_at` timestamp
    /// is used only for window attribution, not for the flush decision.
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
            self.wall_clock_start = Some(Instant::now());
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
        if let Some(score) = entry.risk_score {
            counters.max_risk_score = Some(match counters.max_risk_score {
                Some(current) => current.max(score),
                None => score,
            });
        }
        let size = entry.raw_len as u64;
        match size {
            0..=99 => counters.histogram[0] += 1,
            100..=499 => counters.histogram[1] += 1,
            500..=999 => counters.histogram[2] += 1,
            1000..=1500 => counters.histogram[3] += 1,
            _ => {}
        }
        counters
            .arrival_times_ms
            .push(observed_at.timestamp_millis());
        if counters.arrival_times_ms.len() > counters.arrival_reservoir_size {
            let drop_idx = fastrand::usize(..counters.arrival_times_ms.len());
            counters.arrival_times_ms.swap_remove(drop_idx);
        }
        self.enforce_entry_limit();
        Ok(flushed)
    }

    /// Timer-triggered flush: drains the current window unconditionally and resets
    /// both wall-clock and frame-time starts. Sets `window_is_partial = true` since
    /// this is not driven by an incoming frame crossing the boundary.
    pub fn flush_current(&mut self) -> Vec<WirelessBandwidthEvent> {
        let Some(window_start) = self.window_start.take() else {
            return Vec::new();
        };
        let _ = self.wall_clock_start.take();
        let wall_clock_delta_ms = (Utc::now() - window_start).num_milliseconds();
        self.drain_window(window_start, wall_clock_delta_ms, true)
    }

    /// Checks if the wall-clock elapsed time has reached the window duration; if so,
    /// advances both the wall-clock and frame-time starts, then drains all accumulated
    /// counters into events. The `observed_at` parameter is used for attribution
    /// (setting the new `window_start`), but the flush decision is based on wall clock.
    fn flush_if_elapsed(&mut self, observed_at: DateTime<Utc>) -> Vec<WirelessBandwidthEvent> {
        let Some(window_start) = self.window_start else {
            self.window_start = Some(observed_at);
            self.wall_clock_start = Some(Instant::now());
            return Vec::new();
        };
        let Some(wall_clock_start) = self.wall_clock_start else {
            // Should not happen if window_start is Some, but be defensive.
            self.window_start = Some(observed_at);
            self.wall_clock_start = Some(Instant::now());
            return Vec::new();
        };

        // Convert chrono::Duration to std::time::Duration for comparison.
        let window_std = match self.window.to_std() {
            Ok(d) => d,
            Err(_) => {
                // Negative or zero duration should not happen (new() clamps to >= 1),
                // but if it does, treat as elapsed.
                let delta = (Utc::now() - window_start).num_milliseconds();
                self.window_start = Some(observed_at);
                self.wall_clock_start = Some(Instant::now());
                return self.drain_window(window_start, delta, false);
            }
        };

        if wall_clock_start.elapsed() >= window_std {
            let delta = (Utc::now() - window_start).num_milliseconds();
            self.window_start = Some(observed_at);
            self.wall_clock_start = Some(Instant::now());
            self.drain_window(window_start, delta, false)
        } else {
            Vec::new()
        }
    }

    /// Drains all accumulated counters into bandwidth events and clears the entries map.
    fn drain_window(
        &mut self,
        window_start: DateTime<Utc>,
        wall_clock_delta_ms: i64,
        window_is_partial: bool,
    ) -> Vec<WirelessBandwidthEvent> {
        let window_end = window_start + self.window;
        // Cap at Utc::now() to avoid future timestamps from clock skew.
        let window_end = window_end.min(Utc::now());
        self.burst_macs.clear();
        let mut events = Vec::with_capacity(self.entries.len());
        for (key, counters) in self.entries.drain() {
            let inter_arrival_p50_ms = calculate_p50_inter_arrival(&counters.arrival_times_ms);
            let inter_arrival_cv = calculate_inter_arrival_cv(&counters.arrival_times_ms);
            // Track source MACs with very low CV - they indicate automated burst traffic.
            if let Some(cv) = inter_arrival_cv {
                if cv < 0.05 {
                    self.burst_macs.insert(key.source_mac.clone());
                }
            }
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
                inter_arrival_cv,
                wall_clock_delta_ms: Some(wall_clock_delta_ms),
                window_is_partial,
                max_risk_score: counters.max_risk_score,
                published_at: None,
            });
        }
        events
    }

    fn enforce_entry_limit(&mut self) {
        if self.entries.len() <= self.max_entries {
            return;
        }

        warn!(
            entry_count = self.entries.len(),
            limit = self.max_entries,
            "traffic bucket entry limit reached; entry dropped"
        );
        if let Some(drop_key) = self.entries.keys().next().cloned() {
            self.entries.remove(&drop_key);
        }
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

/// Computes the coefficient of variation (CV = stddev / mean) of inter-arrival
/// intervals from a reservoir of arrival timestamps (millisecond epoch values).
/// Returns `None` when there are fewer than 2 timestamps.
fn calculate_inter_arrival_cv(times_ms: &[i64]) -> Option<f64> {
    if times_ms.len() < 2 {
        return None;
    }
    let mut sorted = times_ms.to_vec();
    sorted.sort_unstable();
    let intervals: Vec<u64> = sorted
        .windows(2)
        .filter_map(|w| {
            let delta = w[1] - w[0];
            if delta >= 0 { Some(delta as u64) } else { None }
        })
        .collect();
    if intervals.len() < 2 {
        return None;
    }
    let n = intervals.len() as f64;
    let sum: u64 = intervals.iter().sum();
    let mean = sum as f64 / n;
    if mean <= 0.0 {
        return None;
    }
    let variance = intervals.iter().map(|v| {
        let diff = *v as f64 - mean;
        diff * diff
    }).sum::<f64>() / n;
    let stddev = variance.sqrt();
    Some(stddev / mean)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    /// Helper: creates a bandwidth AuditEntry at a given offset from a base time.
    fn bandwidth_entry(
        base: DateTime<Utc>,
        offset_secs: i64,
        raw_len: usize,
        signal_dbm: i8,
    ) -> AuditEntry {
        let observed_at = base + chrono::Duration::seconds(offset_secs);
        serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "event_type": "wifi_data_frame",
            "observed_at": ssl_proxy::time::rfc3339_from_utc(observed_at),
            "sensor_id": "sensor-1",
            "location_id": "lab",
            "interface": "wlan0",
            "channel": 6,
            "frame_type": "data",
            "bssid": "10:20:30:40:50:60",
            "destination_bssid": "10:20:30:40:50:60",
            "source_mac": "AA:BB:CC:DD:EE:01",
            "destination_mac": "22:33:44:55:66:77",
            "transmitter_mac": "aa:bb:cc:dd:ee:01",
            "receiver_mac": "10:20:30:40:50:60",
            "ssid": "CorpWiFi",
            "frame_subtype": "data",
            "signal_dbm": signal_dbm,
            "sequence_number": 1,
            "raw_len": raw_len,
            "frame_control_flags": 0x7908,
            "more_data": true,
            "retry": true,
            "power_save": true,
            "protected": true,
            "to_ds": true,
            "from_ds": false,
            "tags": ["wifi", "data"],
            "security_flags": 0,
            "handshake_captured": false,
            "anomaly_reasons": [],
            "device_id": null,
            "username": null,
            "identity_source": "mac_observed"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn traffic_bucket_flushes_protected_data_frames_by_bssid() {
        // Use a short window (1 second) so wall clock advances quickly with real time.
        let mut bucket = TrafficBucket::new(1);
        let base = Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap();

        // First observation at t=0 — opens window, no flush.
        assert!(bucket
            .observe(&bandwidth_entry(base, 0, 100, -52), false)
            .unwrap()
            .is_empty());

        // Second observation just after (t=0.1s simulated) — too soon for 1s wall-clock window.
        assert!(bucket
            .observe(&bandwidth_entry(base, 0, 125, -47), false)
            .unwrap()
            .is_empty());

        // Wait real time for wall clock to cross the 1s window.
        tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;

        // Third observation — wall clock has elapsed >1s, so flush.
        let events = bucket
            .observe(&bandwidth_entry(base, 2, 75, -60), false)
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(events[0].destination_bssid, "10:20:30:40:50:60");
        assert_eq!(events[0].ssid.as_deref(), Some("CorpWiFi"));
        assert_eq!(events[0].bytes, 225);
        assert_eq!(events[0].frame_count, 2);
        assert_eq!(events[0].retry_count, 2);
        assert_eq!(events[0].more_data_count, 2);
        assert_eq!(events[0].power_save_count, 2);
        assert_eq!(events[0].strongest_signal_dbm, Some(-47));
        // Frame-driven flush: window_is_partial should be false.
        assert!(!events[0].window_is_partial);
        // wall_clock_delta_ms should be present and non-negative.
        assert!(events[0].wall_clock_delta_ms.is_some());

        // Timer-triggered flush for remaining entries (the observation at t=2).
        let remaining = bucket.flush_current();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].bytes, 75);
        // Timer-driven flush: window_is_partial should be true.
        assert!(remaining[0].window_is_partial);
    }

    #[test]
    fn observe_raw_uses_wall_clock_for_flush() {
        let mut bucket = TrafficBucket::new(10);
        let observed_at = Utc::now();

        // First raw observation opens the window.
        let events = bucket.observe_raw(100, observed_at, "s1", "loc1", "wlan0", 6);
        assert!(events.is_empty());

        // Just after, with same timestamp — no flush because wall clock hasn't advanced.
        let events = bucket.observe_raw(200, observed_at, "s1", "loc1", "wlan0", 6);
        assert!(events.is_empty());

        // Verify counters accumulated.
        assert!(bucket.entries.values().any(|c| c.bytes >= 300));
    }

    #[test]
    fn flush_current_returns_partial_window() {
        let mut bucket = TrafficBucket::new(60);
        let observed_at = Utc::now();

        // Add some data.
        let events = bucket.observe_raw(500, observed_at, "s1", "loc1", "wlan0", 6);
        assert!(events.is_empty());

        // Timer-triggered flush.
        let events = bucket.flush_current();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].bytes, 500);
        assert!(events[0].window_is_partial);
        assert!(events[0].wall_clock_delta_ms.is_some());
    }

    #[test]
    fn empty_flush_current_returns_empty() {
        let mut bucket = TrafficBucket::new(60);
        assert!(bucket.flush_current().is_empty());
    }

    #[test]
    fn traffic_bucket_enforces_entry_limit() {
        let mut bucket = TrafficBucket::with_entry_limit(60, 2);
        let base = Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap();

        for index in 0..3 {
            let mut entry = bandwidth_entry(base, index, 100, -42);
            entry.source_mac = Some(format!("aa:bb:cc:dd:ee:{index:02x}"));
            assert!(bucket.observe(&entry, false).unwrap().is_empty());
        }

        assert!(bucket.entries.len() <= 2);
    }

    #[test]
    fn traffic_bucket_caps_arrival_time_samples() {
        let mut bucket = TrafficBucket::new(60);
        let base = Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap();

        for index in 0..1200 {
            assert!(bucket
                .observe(&bandwidth_entry(base, index, 100, -42), false)
                .unwrap()
                .is_empty());
        }

        let sample_len = bucket
            .entries
            .values()
            .map(|counters| counters.arrival_times_ms.len())
            .max()
            .unwrap_or_default();
        assert!(sample_len <= ARRIVAL_RESERVOIR_SIZE);
    }
}