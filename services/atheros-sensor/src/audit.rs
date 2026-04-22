use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Datelike, Duration, NaiveTime, Utc, Weekday};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tracing::{Event, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

use crate::model::AuditEntry;

pub const BANDWIDTH_SUBJECT: &str = "audit.wireless.bandwidth";
pub const DEFAULT_BANDWIDTH_WINDOW_SECS: i64 = 60;
pub const EXTERNAL_BANDWIDTH_THRESHOLD_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct AuditWindow {
    timezone: Option<Tz>,
    days: Option<HashSet<Weekday>>,
    start: Option<NaiveTime>,
    end: Option<NaiveTime>,
}

pub type SharedAuditWindow = Arc<RwLock<AuditWindow>>;

impl AuditWindow {
    pub fn from_parts(
        timezone: Option<String>,
        days: Option<String>,
        start: Option<NaiveTime>,
        end: Option<NaiveTime>,
    ) -> Self {
        Self {
            timezone: timezone.and_then(|value| value.parse::<Tz>().ok()),
            days: days.map(|value| parse_days(&value)),
            start,
            end,
        }
    }

    pub fn is_active_at(&self, instant: DateTime<Utc>) -> bool {
        if self.timezone.is_none()
            && self.days.is_none()
            && self.start.is_none()
            && self.end.is_none()
        {
            return true;
        }

        let localized = match self.timezone {
            Some(timezone) => instant.with_timezone(&timezone),
            None => instant.with_timezone(&chrono_tz::UTC),
        };
        if let Some(days) = &self.days {
            if !days.contains(&localized.weekday()) {
                return false;
            }
        }

        match (self.start, self.end) {
            (Some(start), Some(end)) if start <= end => {
                let current = localized.time();
                current >= start && current <= end
            }
            (Some(start), Some(end)) => {
                let current = localized.time();
                current >= start || current <= end
            }
            _ => true,
        }
    }
}

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

pub struct AuditLayer {
    window: SharedAuditWindow,
}

impl AuditLayer {
    pub fn new(window: SharedAuditWindow) -> Self {
        Self { window }
    }
}

impl<S> Layer<S> for AuditLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let now = Utc::now();
        let active = self
            .window
            .read()
            .map(|window| window.is_active_at(now))
            .unwrap_or(true);
        if !active {
            return;
        }
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        eprintln!(
            "{}",
            json!({
                "type": "audit_trace",
                "time": now.to_rfc3339(),
                "target": event.metadata().target(),
                "level": event.metadata().level().as_str(),
                "fields": visitor.fields,
            })
        );
    }
}

#[derive(Default)]
struct EventVisitor {
    fields: serde_json::Map<String, serde_json::Value>,
}

impl tracing::field::Visit for EventVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::String(format!("{value:?}")),
        );
    }
}

fn parse_days(value: &str) -> HashSet<Weekday> {
    value
        .split(',')
        .filter_map(|token| match token.trim().to_ascii_lowercase().as_str() {
            "mon" | "monday" => Some(Weekday::Mon),
            "tue" | "tuesday" => Some(Weekday::Tue),
            "wed" | "wednesday" => Some(Weekday::Wed),
            "thu" | "thursday" => Some(Weekday::Thu),
            "fri" | "friday" => Some(Weekday::Fri),
            "sat" | "saturday" => Some(Weekday::Sat),
            "sun" | "sunday" => Some(Weekday::Sun),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{AuditWindow, TrafficBucket};
    use crate::model::AuditEntry;

    #[test]
    fn audit_window_defaults_to_always_on() {
        let window = AuditWindow::from_parts(None, None, None, None);
        assert!(window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap()));
    }

    #[test]
    fn audit_window_applies_days_and_hours() {
        let window = AuditWindow::from_parts(
            Some("America/New_York".to_string()),
            Some("mon,fri".to_string()),
            Some(chrono::NaiveTime::from_hms_opt(9, 0, 0).unwrap()),
            Some(chrono::NaiveTime::from_hms_opt(17, 0, 0).unwrap()),
        );

        assert!(window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 16, 0, 0).unwrap()));
        assert!(!window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 21, 16, 0, 0).unwrap()));
        assert!(!window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 1, 0, 0).unwrap()));
    }

    #[test]
    fn traffic_bucket_flushes_protected_data_frames_by_bssid() {
        let mut bucket = TrafficBucket::new(60);
        assert!(bucket
            .observe(&bandwidth_entry(0, 100, -52))
            .unwrap()
            .is_empty());
        assert!(bucket
            .observe(&bandwidth_entry(30, 125, -47))
            .unwrap()
            .is_empty());

        let events = bucket.observe(&bandwidth_entry(61, 75, -60)).unwrap();

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

        let remaining = bucket.flush_current();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].bytes, 75);
    }

    fn bandwidth_entry(offset_secs: i64, raw_len: usize, signal_dbm: i8) -> AuditEntry {
        let observed_at = Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap()
            + chrono::Duration::seconds(offset_secs);
        AuditEntry {
            event_type: "wifi_data_frame".to_string(),
            observed_at: observed_at.to_rfc3339(),
            sensor_id: "sensor-1".to_string(),
            location_id: "lab".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            bssid: Some("10:20:30:40:50:60".to_string()),
            destination_bssid: Some("10:20:30:40:50:60".to_string()),
            source_mac: Some("AA:BB:CC:DD:EE:01".to_string()),
            destination_mac: Some("22:33:44:55:66:77".to_string()),
            transmitter_mac: Some("aa:bb:cc:dd:ee:01".to_string()),
            receiver_mac: Some("10:20:30:40:50:60".to_string()),
            ssid: Some("CorpWiFi".to_string()),
            frame_subtype: "data".to_string(),
            tsft: None,
            signal_dbm: Some(signal_dbm),
            noise_dbm: None,
            frequency_mhz: None,
            channel_flags: None,
            data_rate_kbps: None,
            antenna_id: None,
            sequence_number: Some(1),
            duration_id: Some(0),
            frame_control_flags: Some(0x7908),
            more_data: Some(true),
            retry: Some(true),
            power_save: Some(true),
            protected: Some(true),
            to_ds: Some(true),
            from_ds: Some(false),
            raw_len,
            raw_frame: None,
            tags: vec!["wifi".to_string(), "data".to_string()],
            security_flags: 0,
            wps_device_name: None,
            wps_manufacturer: None,
            wps_model_name: None,
            device_fingerprint: None,
            handshake_captured: false,
            device_id: None,
            username: None,
            identity_source: "mac_observed".to_string(),
        }
    }
}
