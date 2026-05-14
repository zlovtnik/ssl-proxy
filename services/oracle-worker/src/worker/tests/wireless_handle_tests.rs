use crate::worker::{handle_load_with_sink, OracleLoad};

use super::support::{inline_payload, RecordingSink};

#[test]
fn routes_wireless_audit_loads_to_frame_sink() {
    let mut sink = RecordingSink::default();
    let result = handle_load_with_sink(
        OracleLoad {
            job_id: "job-2".to_string(),
            batch_id: "batch-2".to_string(),
            batch_no: 0,
            stream_name: "wireless.audit".to_string(),
            payload_ref: inline_payload(
                r#"{"event_type":"wifi_management_frame","observed_at":"2026-04-21T00:00:00Z","sensor_id":"aa:bb:cc:dd:ee:ff","location_id":"lab","interface":"wlan0","channel":6,"frame_type":"management","frame_subtype":"beacon","bssid":"10:20:30:40:50:60","ssid":"corp","signal_dbm":-42,"sequence_number":7,"raw_len":128,"retry":true,"more_data":false,"power_save":false,"protected":true,"to_ds":false,"from_ds":false,"handshake_captured":false,"security_flags":2,"identity_source":"unknown","tags":["threat:signal_anomaly"],"anomaly_reasons":["signal_anomaly"]}"#,
            ),
            cursor_start: "20".to_string(),
            cursor_end: "21".to_string(),
            attempt: 1,
        },
        &mut sink,
    );

    assert_eq!(result.status, "success");
    assert_eq!(result.row_count, 1);
    assert_eq!(sink.wireless_audit_rows.len(), 1);
    assert_eq!(sink.wireless_audit_rows[0].sensor_id, "aa:bb:cc:dd:ee:ff");
    assert_eq!(sink.wireless_audit_rows[0].is_retry, 1);
    assert_eq!(
        sink.wireless_audit_rows[0].tags,
        r#"["threat:signal_anomaly"]"#
    );
}

#[test]
fn routes_wireless_bandwidth_loads_to_bandwidth_sink() {
    let mut sink = RecordingSink::default();
    let result = handle_load_with_sink(
        OracleLoad {
            job_id: "job-bw".to_string(),
            batch_id: "batch-bw".to_string(),
            batch_no: 0,
            stream_name: "audit.wireless.bandwidth".to_string(),
            payload_ref: inline_payload(
                r#"{"schema_version":1,"event_type":"wireless_bandwidth_window","window_start":"2026-04-21T00:00:00Z","window_end":"2026-04-21T00:01:00Z","sensor_id":"aa:bb:cc:dd:ee:ff","location_id":"lab","interface":"wlan0","channel":6,"source_mac":"aa:bb:cc:dd:ee:01","destination_bssid":"10:20:30:40:50:60","ssid":"corp","bytes":524288001,"frame_count":9,"retry_count":1,"more_data_count":2,"power_save_count":3,"strongest_signal_dbm":-40,"external_bssid":true,"threshold_exceeded":true,"frame_size_histogram":{"under_100":1,"range_100_500":2,"range_500_1000":3,"range_1000_1500":4},"inter_arrival_p50_ms":17,"wall_clock_delta_ms":50,"window_is_partial":false,"published_at":"2026-04-21T00:01:01Z"}"#,
            ),
            cursor_start: "1".to_string(),
            cursor_end: "2".to_string(),
            attempt: 1,
        },
        &mut sink,
    );

    assert_eq!(result.status, "success");
    assert_eq!(sink.wireless_bandwidth_rows.len(), 1);
    assert_eq!(sink.wireless_bandwidth_rows[0].threshold_exceeded, 1);
    assert_eq!(sink.wireless_bandwidth_rows[0].hist_1000_1500, 4);
}

#[test]
fn routes_wireless_alert_and_inventory_targets() {
    let cases = [
        (
            "wireless.alert.rogue_ap",
            r#"{"event_type":"wireless_rogue_ap","observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor","location_id":"lab","interface":"wlan0","channel":6,"bssid":"aa:bb:cc:dd:ee:01","ssid":"corp","reasons":["bssid_spoofing"]}"#,
        ),
        (
            "wireless.alert.deauth_flood",
            r#"{"event_type":"wireless_deauth_flood","observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor","location_id":"lab","interface":"wlan0","bssid":"aa:bb:cc:dd:ee:02","frame_count":20,"window_secs":30}"#,
        ),
        (
            "wireless.alert.signal_anomaly",
            r#"{"observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor","location_id":"lab","source_mac":"aa:bb:cc:dd:ee:03","channel":6,"baseline_dbm":-80,"observed_dbm":-40,"dbm_delta":40,"configured_delta":25}"#,
        ),
        (
            "wireless.alert.pmf_attack",
            r#"{"observed_at":"2026-04-21T00:00:00Z","sensor_id":"sensor","location_id":"lab","target_mac":"aa:bb:cc:dd:ee:04","channel":6,"attack_tag":"threat:pmf_deauth_attack","reconnect_window_ms":3000}"#,
        ),
        (
            "wireless.client.inventory",
            r#"{"sensor_id":"sensor","location_id":"lab","observed_at":"2026-04-21T00:00:00Z","clients":[{"source_mac":"aa:bb:cc:dd:ee:05","first_seen":"2026-04-20T00:00:00Z","last_seen":"2026-04-21T00:00:00Z","last_signal_dbm":-50}]}"#,
        ),
        (
            "wireless.probe.flush",
            r#"{"operation":"flush_probe_batch","probes":[{"ssid":"corp","client_mac":"aa:bb:cc:dd:ee:06","known_bssid":"10:20:30:40:50:60","first_seen":"2026-04-21T00:00:00Z","last_seen":"2026-04-21T00:01:00Z","probe_count":3}]}"#,
        ),
    ];

    for (subject, payload) in cases {
        let mut sink = RecordingSink::default();
        let result = handle_load_with_sink(
            OracleLoad {
                job_id: format!("job-{subject}"),
                batch_id: format!("batch-{subject}"),
                batch_no: 0,
                stream_name: subject.to_string(),
                payload_ref: inline_payload(payload),
                cursor_start: "1".to_string(),
                cursor_end: "2".to_string(),
                attempt: 1,
            },
            &mut sink,
        );
        assert_eq!(result.status, "success", "{subject}");
        assert_eq!(result.row_count, 1, "{subject}");
    }
}
