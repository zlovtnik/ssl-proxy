use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Instant;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::{
    model::AuditEntry,
    state_key::{MacAddr, SsidKey},
};

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
    source_mac: TrafficMac,
    destination_bssid: TrafficMac,
    ssid: Option<SsidKey>,
    external_bssid: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum TrafficMac {
    Known(MacAddr),
    Unknown,
}

impl TrafficMac {
    fn parse(value: &str) -> Option<Self> {
        MacAddr::parse(value).map(Self::Known)
    }

    fn unknown() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for TrafficMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(mac) => write!(f, "{mac}"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

#[derive(Clone, Debug)]
struct TrafficCounters {
    ssid: Option<String>,
    bytes: u64,
    frame_count: u64,
    retry_count: u64,
    more_data_count: u64,
    power_save_count: u64,
    strongest_signal_dbm: Option<i8>,
    histogram: [u64; 4],
    arrival_times_ms: Vec<i64>,
    arrival_samples_seen: u64,
    arrival_reservoir_size: usize,
    max_risk_score: Option<f32>,
}

impl Default for TrafficCounters {
    fn default() -> Self {
        Self {
            ssid: None,
            bytes: 0,
            frame_count: 0,
            retry_count: 0,
            more_data_count: 0,
            power_save_count: 0,
            strongest_signal_dbm: None,
            histogram: [0; 4],
            arrival_times_ms: Vec::new(),
            arrival_samples_seen: 0,
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
