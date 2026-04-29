mod bandwidth;
mod layer;
mod window;

#[allow(unused_imports)]
pub use bandwidth::TrafficBucketError;
pub use bandwidth::{
    TrafficBucket, WirelessBandwidthEvent, BANDWIDTH_SUBJECT, DEFAULT_BANDWIDTH_WINDOW_SECS,
    EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
};
pub use layer::AuditLayer;
pub use window::{AuditWindow, SharedAuditWindow};

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

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
        serde_json::from_value(json!({
            "schema_version": 2,
            "event_type": "wifi_data_frame",
            "observed_at": observed_at.to_rfc3339(),
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
}
