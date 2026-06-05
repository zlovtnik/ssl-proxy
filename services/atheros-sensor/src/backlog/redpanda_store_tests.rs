use super::{
    inline_request_reply_transport_supported, parse_authorized_networks_response,
    parse_redpanda_endpoint, payload_with_reply_topic, request_error_marks_redpanda_unhealthy,
    request_transport_unsupported,
};
use crate::backlog::BacklogError;

#[test]
fn parses_wrapped_authorized_networks_response() {
    let parsed = parse_authorized_networks_response(
            r#"{"networks":[{"ssid":"Corp","bssid":"aa:bb:cc:dd:ee:ff","location_id":"hq","psk":"secret"}]}"#,
        )
        .expect("wrapped response should parse");

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].ssid.as_deref(), Some("Corp"));
    assert_eq!(parsed[0].bssid.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    assert_eq!(parsed[0].location_id.as_deref(), Some("hq"));
    assert_eq!(parsed[0].psk.as_deref(), Some("secret"));
}

#[test]
fn parses_legacy_authorized_networks_array() {
    let parsed = parse_authorized_networks_response(
        r#"[{"ssid":"Corp","bssid":null,"location_id":null,"psk":null}]"#,
    )
    .expect("legacy array should parse");

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].ssid.as_deref(), Some("Corp"));
    assert_eq!(parsed[0].bssid, None);
}

#[test]
fn treats_empty_and_null_authorized_networks_responses_as_empty() {
    assert!(parse_authorized_networks_response("").unwrap().is_empty());
    assert!(parse_authorized_networks_response(" null ")
        .unwrap()
        .is_empty());
    assert!(parse_authorized_networks_response(r#"{"networks":null}"#)
        .unwrap()
        .is_empty());
}

#[test]
fn adds_reply_topic_to_request_payload() {
    let payload = payload_with_reply_topic(
        "list_pending",
        r#"{"operation":"list_pending"}"#,
        "_INBOX.x",
    )
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(parsed["operation"], "list_pending");
    assert_eq!(parsed["reply_topic"], "_INBOX.x");
}

#[test]
fn rejects_non_object_request_payloads() {
    let error = payload_with_reply_topic("list_pending", r#"[]"#, "_INBOX.x").unwrap_err();

    assert!(
        matches!(error, BacklogError::Serialize { .. })
            || error.to_string().contains("list_pending")
    );
}

#[test]
fn request_reply_timeout_does_not_mark_redpanda_transport_unhealthy() {
    let error = BacklogError::Timeout {
        operation: "lookup_device_by_mac",
    };

    assert!(!request_error_marks_redpanda_unhealthy(&error));
}

#[test]
fn kafka_listener_request_transport_fails_fast() {
    assert!(
        request_transport_unsupported("lookup_device_by_mac", "redpanda://127.0.0.1:19092")
            .is_some()
    );
    assert!(!inline_request_reply_transport_supported(
        "redpanda://127.0.0.1:19092"
    ));
    assert!(
        request_transport_unsupported("lookup_device_by_mac", "redpanda://redpanda:9092").is_some()
    );
    assert!(request_transport_unsupported("lookup_device_by_mac", "tls://redpanda:9093").is_some());
    assert!(request_transport_unsupported(
        "lookup_device_by_mac",
        "redpanda://redpanda-a:9092,redpanda-b:9092"
    )
    .is_some());
}

#[test]
fn non_kafka_request_transport_keeps_legacy_path_available() {
    assert!(
        request_transport_unsupported("lookup_device_by_mac", "redpanda://127.0.0.1:4222")
            .is_none()
    );
    assert!(inline_request_reply_transport_supported(
        "redpanda://127.0.0.1:4222"
    ));
}

#[test]
fn transport_io_error_marks_redpanda_transport_unhealthy() {
    let error = BacklogError::Redpanda {
        operation: "lookup_device_by_mac",
        message: "unexpected EOF while reading reply".to_string(),
    };

    assert!(request_error_marks_redpanda_unhealthy(&error));
}

#[test]
fn parses_host_with_default_port() {
    let endpoint = parse_redpanda_endpoint("redpanda://redpanda.internal").unwrap();
    assert_eq!(endpoint.address, "redpanda.internal:9092");
    assert_eq!(endpoint.host, "redpanda.internal");
    assert!(!endpoint.tls_enabled);
}

#[test]
fn parses_tls_scheme() {
    let endpoint = parse_redpanda_endpoint("tls://redpanda.internal:4443").unwrap();
    assert_eq!(endpoint.address, "redpanda.internal:4443");
    assert_eq!(endpoint.host, "redpanda.internal");
    assert!(endpoint.tls_enabled);
}

#[test]
fn parses_bracketed_ipv6_without_port() {
    let endpoint = parse_redpanda_endpoint("redpanda://[::1]").unwrap();
    assert_eq!(endpoint.address, "[::1]:9092");
    assert_eq!(endpoint.host, "::1");
}

#[test]
fn parses_bracketed_ipv6_with_port() {
    let endpoint = parse_redpanda_endpoint("redpanda://[::1]:4223").unwrap();
    assert_eq!(endpoint.address, "[::1]:4223");
    assert_eq!(endpoint.host, "::1");
}

#[test]
fn ignores_userinfo_for_address_parsing() {
    let endpoint = parse_redpanda_endpoint("redpanda://user:pass@redpanda.internal:4224").unwrap();
    assert_eq!(endpoint.address, "redpanda.internal:4224");
    assert_eq!(endpoint.host, "redpanda.internal");
}
