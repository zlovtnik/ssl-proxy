//! Shared sync-plane contracts used by the proxy, coordinator, and worker.

use serde::{Deserialize, Serialize};

pub const SYNC_SCAN_REQUEST_SUBJECT: &str = "sync.scan.request";
pub const INLINE_PAYLOAD_REF_PREFIX: &str = "inline://json/";
pub const OUTBOX_PAYLOAD_REF_PREFIX: &str = "outbox://";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanRequest {
    pub stream_name: String,
    pub dedupe_key: String,
    pub payload_ref: String,
    pub observed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedMessage {
    pub subject: String,
    pub payload: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadRefKind {
    Inline,
    Outbox,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedPayloadRef<'a> {
    pub kind: PayloadRefKind,
    pub locator: &'a str,
}

pub fn parse_payload_ref(payload_ref: &str) -> Option<ParsedPayloadRef<'_>> {
    payload_ref
        .strip_prefix(INLINE_PAYLOAD_REF_PREFIX)
        .map(|locator| ParsedPayloadRef {
            kind: PayloadRefKind::Inline,
            locator,
        })
        .or_else(|| {
            payload_ref
                .strip_prefix(OUTBOX_PAYLOAD_REF_PREFIX)
                .map(|locator| ParsedPayloadRef {
                    kind: PayloadRefKind::Outbox,
                    locator,
                })
        })
}

pub fn should_publish_scan_request(event: &str) -> bool {
    matches!(
        event,
        "block" | "http_proxied" | "http_error" | "tunnel_open" | "tunnel_close"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        parse_payload_ref, should_publish_scan_request, PayloadRefKind, INLINE_PAYLOAD_REF_PREFIX,
        OUTBOX_PAYLOAD_REF_PREFIX,
    };

    #[test]
    fn parses_inline_and_outbox_payload_refs() {
        let inline = format!("{INLINE_PAYLOAD_REF_PREFIX}eyJrZXkiOiJ2YWx1ZSJ9");
        let outbox = format!("{OUTBOX_PAYLOAD_REF_PREFIX}20260417T000000Z-deadbeef.json");

        let parsed_inline = parse_payload_ref(&inline).unwrap();
        assert_eq!(parsed_inline.kind, PayloadRefKind::Inline);
        assert_eq!(parsed_inline.locator, "eyJrZXkiOiJ2YWx1ZSJ9");

        let parsed_outbox = parse_payload_ref(&outbox).unwrap();
        assert_eq!(parsed_outbox.kind, PayloadRefKind::Outbox);
        assert_eq!(parsed_outbox.locator, "20260417T000000Z-deadbeef.json");
    }

    #[test]
    fn publish_filter_allows_only_sink_events() {
        assert!(should_publish_scan_request("block"));
        assert!(should_publish_scan_request("http_proxied"));
        assert!(should_publish_scan_request("http_error"));
        assert!(should_publish_scan_request("tunnel_open"));
        assert!(should_publish_scan_request("tunnel_close"));
        assert!(!should_publish_scan_request("stats_live"));
    }
}
