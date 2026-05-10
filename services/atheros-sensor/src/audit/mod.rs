//! Audit subsystem for compliance monitoring of wireless traffic.
//!
//! This module implements a three-piece architecture: (1) bandwidth bucketing that aggregates
//! protected data frames into time-windowed summaries, (2) a tracing_subscriber layer that
//! mirrors log events to stdout/stderr during active audit windows, and (3) a schedule gate
//! that filters audit activity by timezone, weekday, and time range.

mod bandwidth;
mod layer;
mod window;

#[doc(inline)]
#[allow(unused_imports)]
pub use bandwidth::TrafficBucketError;
#[doc(inline)]
pub use bandwidth::{
    FrameSizeHistogram, TrafficBucket, WirelessBandwidthEvent, BANDWIDTH_SUBJECT,
    DEFAULT_BANDWIDTH_WINDOW_SECS, EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
};
#[doc(inline)]
pub use layer::AuditLayer;
#[doc(inline)]
pub use window::{AuditWindow, SharedAuditWindow};

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::AuditWindow;

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

}
