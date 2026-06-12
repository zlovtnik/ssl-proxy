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
fn traffic_bucket_counts_candidate_frames_with_unparseable_macs() {
    let mut bucket = TrafficBucket::new(60);
    let base = Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap();
    let mut entry = bandwidth_entry(base, 0, 100, -42);
    entry.source_mac = Some("not-a-mac".to_string());
    entry.destination_bssid = Some("also-not-a-mac".to_string());
    entry.bssid = Some("still-not-a-mac".to_string());

    assert!(bucket.observe(&entry, false).unwrap().is_empty());

    let events = bucket.flush_current();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].source_mac, "unknown");
    assert_eq!(events[0].destination_bssid, "unknown");
    assert_eq!(events[0].bytes, 100);
    assert_eq!(events[0].frame_count, 1);
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
