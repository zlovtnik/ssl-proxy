//! Two-tier persistence strategy for wireless audit event publishing.
//!
//! Implements a dual-path publish pipeline: primary path publishes to Redpanda; fallback path
//! asks the coordinator to save sync_backlog retry rows. When Redpanda
//! is unavailable, a circuit breaker opens and events are queued in an in-memory backlog until
//! connectivity is restored. The circuit breaker uses exponential backoff, with automatic
//! re-probing after the backoff timeout elapses. When the memory backlog cannot be flushed,
//! entries are persisted to a local JSONL journal file for durability across process restarts.

#[cfg(test)]
#[path = "publish_tests.rs"]
mod tests;

include!("publish_sections/state.rs");
include!("publish_sections/durable_publish.rs");
include!("publish_sections/backlog.rs");
