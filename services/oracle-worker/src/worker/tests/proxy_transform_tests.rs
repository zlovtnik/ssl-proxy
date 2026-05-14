use crate::worker::{
    normalized_identity_source, proxy_event_rows_from_payload, resolve_payload, SinkTarget,
};

use super::support::proxy_payload;

#[test]
fn maps_proxy_payload_rows_for_oracle_insert() {
    let rows = proxy_event_rows_from_payload(
        SinkTarget::ProxyEvents,
        &resolve_payload(&proxy_payload()).unwrap(),
    )
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "tunnel_open");
    assert_eq!(rows[0].host, "example.com");
    assert_eq!(rows[0].peer_ip.as_deref(), Some("10.0.0.2"));
    assert_eq!(rows[0].bytes_up, 0);
    assert_eq!(rows[0].status_code, None);
    assert!(rows[0].raw_json.contains("\"type\":\"tunnel_open\""));
}

#[test]
fn normalizes_missing_identity_source_to_unknown() {
    assert_eq!(normalized_identity_source(None), "unknown");
    assert_eq!(normalized_identity_source(Some("registered")), "registered");
}
