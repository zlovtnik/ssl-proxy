//! Shared sync-plane wire contracts.

use serde::{Deserialize, Serialize};

pub const SYNC_SCAN_REQUEST_TOPIC: &str = "sync.scan.request";
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
    pub topic: String,
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

#[cfg(test)]
mod tests {
    use super::{
        parse_payload_ref, PayloadRefKind, INLINE_PAYLOAD_REF_PREFIX, OUTBOX_PAYLOAD_REF_PREFIX,
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
}
