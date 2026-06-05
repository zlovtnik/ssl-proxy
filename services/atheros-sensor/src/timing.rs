//! Per-session frame timing deltas for wireless frame correlation.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::model::WifiFrame;

const TIMING_TRACKER_MAX_SESSIONS: usize = 4_096;
const TIMING_TRACKER_MAX_AGE_SECS: i64 = 3_600;

#[derive(Default)]
pub struct FrameTimingTracker {
    last_by_session: HashMap<String, LastFrameTiming>,
    last_by_ap: HashMap<String, LastFrameTiming>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LastFrameTiming {
    observed_at: DateTime<Utc>,
    tsft: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameTimingDelta {
    tsft_delta_us: i64,
    wall_clock_delta_ms: i64,
}

impl FrameTimingTracker {
    pub fn attach_deltas(&mut self, frame: &mut WifiFrame, clock_skew_anomaly_threshold_us: i64) {
        let delta = self.compute_session_delta(frame);
        frame.tsft_delta_us = delta.map(|delta| delta.tsft_delta_us);
        frame.wall_clock_delta_ms = delta.map(|delta| delta.wall_clock_delta_ms);
        frame.correlation.tsft_delta_us = frame.tsft_delta_us;
        frame.correlation.wall_clock_delta_ms = frame.wall_clock_delta_ms;

        let clock_skew_delta_us = self.compute_ap_delta(frame).and_then(|delta| {
            delta
                .wall_clock_delta_ms
                .checked_mul(1_000)?
                .checked_sub(delta.tsft_delta_us)
        });
        frame.clock_skew_delta_us = clock_skew_delta_us;
        frame.correlation.clock_skew_delta_us = clock_skew_delta_us;
        if clock_skew_anomaly_threshold_us > 0
            && clock_skew_delta_us
                .is_some_and(|delta| delta.abs() > clock_skew_anomaly_threshold_us)
        {
            push_unique(&mut frame.tags, "anomaly:clock_skew_anomaly");
            push_unique(&mut frame.anomaly_reasons, "clock_skew_anomaly");
            push_unique(&mut frame.anomalies.reasons, "clock_skew_anomaly");
        }
    }

    fn compute_session_delta(&mut self, frame: &WifiFrame) -> Option<FrameTimingDelta> {
        let session_key = frame
            .session_key
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty())?;
        let current_tsft = frame.tsft?;
        let current_observed_at = frame.observed_at;

        let delta = self
            .last_by_session
            .get(session_key)
            .and_then(|previous| timing_delta(previous, current_tsft, current_observed_at));

        let should_update = self
            .last_by_session
            .get(session_key)
            .map(|previous| current_observed_at >= previous.observed_at)
            .unwrap_or(true);
        if should_update {
            self.last_by_session.insert(
                session_key.to_string(),
                LastFrameTiming {
                    observed_at: current_observed_at,
                    tsft: current_tsft,
                },
            );
        }
        self.prune(current_observed_at);

        delta
    }

    fn compute_ap_delta(&mut self, frame: &WifiFrame) -> Option<FrameTimingDelta> {
        if !matches!(frame.frame_subtype.as_str(), "beacon" | "probe_response") {
            return None;
        }
        let bssid = frame
            .bssid
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty())?;
        let current_tsft = frame.tsft?;
        let current_observed_at = frame.observed_at;

        let delta = self
            .last_by_ap
            .get(bssid)
            .and_then(|previous| timing_delta(previous, current_tsft, current_observed_at));

        let should_update = self
            .last_by_ap
            .get(bssid)
            .map(|previous| current_observed_at >= previous.observed_at)
            .unwrap_or(true);
        if should_update {
            self.last_by_ap.insert(
                bssid.to_string(),
                LastFrameTiming {
                    observed_at: current_observed_at,
                    tsft: current_tsft,
                },
            );
        }

        delta
    }

    fn prune(&mut self, observed_at: DateTime<Utc>) {
        let cutoff = observed_at - chrono::Duration::seconds(TIMING_TRACKER_MAX_AGE_SECS);
        self.last_by_session
            .retain(|_, timing| timing.observed_at >= cutoff);
        self.last_by_ap
            .retain(|_, timing| timing.observed_at >= cutoff);

        if self.last_by_session.len() > TIMING_TRACKER_MAX_SESSIONS {
            let mut entries: Vec<(String, DateTime<Utc>)> = self
                .last_by_session
                .iter()
                .map(|(key, timing)| (key.clone(), timing.observed_at))
                .collect();
            entries.sort_by_key(|(_, observed_at)| *observed_at);
            let to_remove: Vec<String> = entries
                .into_iter()
                .take(self.last_by_session.len() - TIMING_TRACKER_MAX_SESSIONS)
                .map(|(key, _)| key)
                .collect();
            for key in to_remove {
                self.last_by_session.remove(&key);
            }
        }

        if self.last_by_ap.len() <= TIMING_TRACKER_MAX_SESSIONS {
            return;
        }
        let mut entries: Vec<(String, DateTime<Utc>)> = self
            .last_by_ap
            .iter()
            .map(|(key, timing)| (key.clone(), timing.observed_at))
            .collect();
        entries.sort_by_key(|(_, observed_at)| *observed_at);
        let to_remove: Vec<String> = entries
            .into_iter()
            .take(self.last_by_ap.len() - TIMING_TRACKER_MAX_SESSIONS)
            .map(|(key, _)| key)
            .collect();
        for key in to_remove {
            self.last_by_ap.remove(&key);
        }
    }
}

fn timing_delta(
    previous: &LastFrameTiming,
    current_tsft: u64,
    current_observed_at: DateTime<Utc>,
) -> Option<FrameTimingDelta> {
    let tsft_delta_us = current_tsft.checked_sub(previous.tsft)?;
    let tsft_delta_us = i64::try_from(tsft_delta_us).ok()?;
    let wall_clock_delta_ms = (current_observed_at - previous.observed_at).num_milliseconds();
    if wall_clock_delta_ms < 0 {
        return None;
    }
    Some(FrameTimingDelta {
        tsft_delta_us,
        wall_clock_delta_ms,
    })
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{AuditContext, RawPacket},
        parse::{attach_context, decode_frame, to_audit_entry},
    };

    fn observed_at(offset_ms: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-31T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
            + chrono::Duration::milliseconds(offset_ms)
    }

    fn timing_frame(
        session_key: Option<&str>,
        tsft: Option<u64>,
        observed_at: DateTime<Utc>,
    ) -> WifiFrame {
        let packet = RawPacket {
            observed_at,
            data: crate::testutil::tsft_antenna_radiotap_beacon_frame(),
        };
        let mut frame = decode_frame(&packet).expect("test frame should decode");
        let session_key = session_key.map(str::to_string);
        frame.session_key = session_key.clone();
        frame.correlation.session_key = session_key;
        frame.tsft = tsft;
        frame.rf.tsft = tsft;
        frame.tsft_delta_us = None;
        frame.wall_clock_delta_ms = None;
        frame.clock_skew_delta_us = None;
        frame.correlation.tsft_delta_us = None;
        frame.correlation.wall_clock_delta_ms = None;
        frame.correlation.clock_skew_delta_us = None;
        frame
    }

    #[test]
    fn timing_tracker_first_frame_yields_null_deltas() {
        let mut tracker = FrameTimingTracker::default();
        let mut frame = timing_frame(Some("session-1"), Some(1_000), observed_at(0));

        tracker.attach_deltas(&mut frame, 250_000);

        assert_eq!(frame.tsft_delta_us, None);
        assert_eq!(frame.wall_clock_delta_ms, None);
        assert_eq!(frame.clock_skew_delta_us, None);
        assert_eq!(frame.correlation.tsft_delta_us, None);
        assert_eq!(frame.correlation.wall_clock_delta_ms, None);
        assert_eq!(frame.correlation.clock_skew_delta_us, None);
        assert_eq!(
            tracker.last_by_session.get("session-1"),
            Some(&LastFrameTiming {
                observed_at: observed_at(0),
                tsft: 1_000,
            })
        );
    }

    #[test]
    fn timing_tracker_second_frame_populates_flat_and_nested_deltas() {
        let mut tracker = FrameTimingTracker::default();
        let mut first = timing_frame(Some("session-1"), Some(1_000), observed_at(0));
        let mut second = timing_frame(Some("session-1"), Some(2_500), observed_at(2_000));

        tracker.attach_deltas(&mut first, 250_000);
        tracker.attach_deltas(&mut second, 250_000);

        assert_eq!(second.tsft_delta_us, Some(1_500));
        assert_eq!(second.wall_clock_delta_ms, Some(2_000));
        assert_eq!(second.clock_skew_delta_us, Some(1_998_500));
        assert_eq!(second.correlation.tsft_delta_us, Some(1_500));
        assert_eq!(second.correlation.wall_clock_delta_ms, Some(2_000));
        assert_eq!(second.correlation.clock_skew_delta_us, Some(1_998_500));
        assert!(second
            .tags
            .contains(&"anomaly:clock_skew_anomaly".to_string()));
    }

    #[test]
    fn timing_tracker_is_partitioned_by_session() {
        let mut tracker = FrameTimingTracker::default();
        let mut session_one_first = timing_frame(Some("session-1"), Some(1_000), observed_at(0));
        let mut session_two_first =
            timing_frame(Some("session-2"), Some(5_000), observed_at(1_000));
        let mut session_one_second =
            timing_frame(Some("session-1"), Some(1_300), observed_at(2_000));

        tracker.attach_deltas(&mut session_one_first, 0);
        tracker.attach_deltas(&mut session_two_first, 0);
        tracker.attach_deltas(&mut session_one_second, 0);

        assert_eq!(session_two_first.tsft_delta_us, None);
        assert_eq!(session_two_first.wall_clock_delta_ms, None);
        assert_eq!(session_one_second.tsft_delta_us, Some(300));
        assert_eq!(session_one_second.wall_clock_delta_ms, Some(2_000));
    }

    #[test]
    fn timing_tracker_ignores_missing_and_decreasing_tsft_safely() {
        let mut tracker = FrameTimingTracker::default();
        let mut first = timing_frame(Some("session-1"), Some(1_000), observed_at(0));
        let mut missing = timing_frame(Some("session-1"), None, observed_at(1_000));
        let mut decreasing = timing_frame(Some("session-1"), Some(900), observed_at(2_000));
        let mut recovered = timing_frame(Some("session-1"), Some(1_200), observed_at(3_000));

        tracker.attach_deltas(&mut first, 0);
        tracker.attach_deltas(&mut missing, 0);
        tracker.attach_deltas(&mut decreasing, 0);
        tracker.attach_deltas(&mut recovered, 0);

        assert_eq!(missing.tsft_delta_us, None);
        assert_eq!(missing.wall_clock_delta_ms, None);
        assert_eq!(decreasing.tsft_delta_us, None);
        assert_eq!(decreasing.wall_clock_delta_ms, None);
        assert_eq!(recovered.tsft_delta_us, Some(300));
        assert_eq!(recovered.wall_clock_delta_ms, Some(1_000));
    }

    #[test]
    fn audit_entry_serializes_flat_and_nested_timing_deltas() {
        let mut tracker = FrameTimingTracker::default();
        let mut first = timing_frame(Some("session-1"), Some(1_000), observed_at(0));
        let mut second = timing_frame(Some("session-1"), Some(2_500), observed_at(2_000));
        let context = AuditContext {
            sensor_id: "00:11:22:33:44:55".to_string(),
            location_id: "lab".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };

        tracker.attach_deltas(&mut first, 0);
        tracker.attach_deltas(&mut second, 0);
        let entry = to_audit_entry(attach_context(second, &context));
        let value = serde_json::to_value(entry).unwrap();

        assert_eq!(value["tsft_delta_us"], serde_json::json!(1_500));
        assert_eq!(value["wall_clock_delta_ms"], serde_json::json!(2_000));
        assert_eq!(value["clock_skew_delta_us"], serde_json::json!(1_998_500));
        assert_eq!(
            value["correlation"]["tsft_delta_us"],
            serde_json::json!(1_500)
        );
        assert_eq!(
            value["correlation"]["wall_clock_delta_ms"],
            serde_json::json!(2_000)
        );
        assert_eq!(
            value["correlation"]["clock_skew_delta_us"],
            serde_json::json!(1_998_500)
        );
    }
}
