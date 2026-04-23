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
