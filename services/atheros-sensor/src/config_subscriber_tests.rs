use chrono::{TimeZone, Utc};

use super::*;

fn sync_config(redpanda_bootstrap_servers: Option<&str>) -> SyncConfig {
    SyncConfig {
        redpanda_bootstrap_servers: redpanda_bootstrap_servers.map(str::to_string),
        connect_timeout_ms: 2_000,
        publish_timeout_ms: 2_000,
        publish_queue_capacity: 8_192,
        publish_enqueue_timeout_ms: 25,
        security_protocol: None,
        sasl_mechanisms: None,
        sasl_username: None,
        sasl_password: None,
        ssl_ca_location: None,
        ssl_certificate_location: None,
        ssl_key_location: None,
        inline_payload_max_bytes: 65_535,
        outbox_dir: "/tmp/atheros-sensor-sync-outbox".to_string(),
        publish_spool_dir: "/tmp/atheros-sensor-sync-outbox/publish-spool".to_string(),
    }
}

#[test]
fn parses_matching_audit_window_config() {
    let payload = r#"{"location_id":"lab","timezone":"America/New_York","days":"mon","start_time":"09:00","end_time":"17:00","enabled":true}"#;

    let window = parse_audit_window_update(payload, "lab").unwrap().unwrap();

    assert!(window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 16, 0, 0).unwrap()));
    assert!(!window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 21, 16, 0, 0).unwrap()));
}

#[test]
fn ignores_other_locations() {
    let payload = r#"{"location_id":"branch","timezone":"America/New_York","enabled":true}"#;

    assert!(parse_audit_window_update(payload, "lab").unwrap().is_none());
}

#[test]
fn disabled_window_is_never_active() {
    let payload = r#"{"location_id":"lab","timezone":"America/New_York","enabled":false}"#;

    let window = parse_audit_window_update(payload, "lab").unwrap().unwrap();

    assert!(!window.is_active_at(Utc.with_ymd_and_hms(2026, 4, 20, 16, 0, 0).unwrap()));
}

#[test]
fn parses_redpanda_endpoint_with_userinfo() {
    assert_eq!(
        parse_redpanda_endpoint("redpanda://user:pass@127.0.0.1:9092").unwrap(),
        RedpandaEndpoint {
            address: "127.0.0.1:9092".to_string(),
            user: Some("user".to_string()),
            password: Some("pass".to_string())
        }
    );
}

#[test]
fn parses_redpanda_endpoint_with_percent_encoded_userinfo() {
    assert_eq!(
        parse_redpanda_endpoint("redpanda://user%40example:p%40ss%3Aword@127.0.0.1:9092").unwrap(),
        RedpandaEndpoint {
            address: "127.0.0.1:9092".to_string(),
            user: Some("user@example".to_string()),
            password: Some("p@ss:word".to_string())
        }
    );
}

#[test]
fn rejects_invalid_percent_encoded_userinfo() {
    assert!(parse_redpanda_endpoint("redpanda://user:%zz@127.0.0.1:9092").is_err());
}

#[test]
fn config_subscribers_reject_kafka_listener() {
    let config = sync_config(Some("redpanda://127.0.0.1:19092"));

    assert!(!supports_config_subscriber_transport(&config));
    assert!(config_subscriber_disabled_reason(&config)
        .unwrap()
        .contains("does not expose the raw subscriber protocol"));
}

#[test]
fn config_subscribers_accept_legacy_raw_listener() {
    let config = sync_config(Some("redpanda://127.0.0.1:4222"));

    assert!(supports_config_subscriber_transport(&config));
    assert!(config_subscriber_disabled_reason(&config).is_none());
}
