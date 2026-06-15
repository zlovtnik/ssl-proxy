//! Neutral sync-plane contracts and publisher runtime shared by repo services.

mod config;
mod contract;
mod publisher;
mod time;

pub use config::SyncConfig;
pub use contract::{
    parse_payload_ref, ParsedPayloadRef, PayloadRefKind, PublishedMessage, ScanRequest,
    INLINE_PAYLOAD_REF_PREFIX, OUTBOX_PAYLOAD_REF_PREFIX, SYNC_SCAN_REQUEST_TOPIC,
};
pub use publisher::{SyncPublisher, SyncPublisherHealthSnapshot, ENQUEUE_TIMEOUT_ERROR};
