//! Proxy-owned sync-plane publishing policy.

pub const PAYLOAD_AUDIT_TOPIC: &str = "proxy.payload_audit";

pub fn should_publish_scan_request(event: &str) -> bool {
    matches!(
        event,
        "block"
            | "http_blocked"
            | "session.blocked"
            | "http_proxied"
            | "http_error"
            | "tunnel_open"
            | "tunnel_close"
    )
}

pub fn should_publish_payload_audit(topic: &str) -> bool {
    topic == PAYLOAD_AUDIT_TOPIC
}

#[cfg(test)]
mod tests {
    use super::{should_publish_payload_audit, should_publish_scan_request, PAYLOAD_AUDIT_TOPIC};

    #[test]
    fn publish_filter_allows_only_proxy_sink_events() {
        assert!(should_publish_scan_request("block"));
        assert!(should_publish_scan_request("http_blocked"));
        assert!(should_publish_scan_request("session.blocked"));
        assert!(should_publish_scan_request("http_proxied"));
        assert!(should_publish_scan_request("http_error"));
        assert!(should_publish_scan_request("tunnel_open"));
        assert!(should_publish_scan_request("tunnel_close"));
        assert!(!should_publish_scan_request("stats_live"));
    }

    #[test]
    fn payload_audit_topic_filter_matches_constant() {
        assert_eq!(PAYLOAD_AUDIT_TOPIC, "proxy.payload_audit");
        assert!(should_publish_payload_audit(PAYLOAD_AUDIT_TOPIC));
        assert!(!should_publish_payload_audit(
            sync_plane::SYNC_SCAN_REQUEST_TOPIC
        ));
    }
}
