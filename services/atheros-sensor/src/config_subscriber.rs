//! Raw-TCP Redpanda subscribers for live configuration push.
//!
//! Implements three subscribers: audit window schedule updates, authorized network cache
//! invalidation, and sensor config (BPF filter, channel). They speak the Redpanda text protocol
//! directly over raw TCP rather than using a Redpanda client library to avoid pulling in a
//! heavyweight async dependency for what is essentially three SUB connections. TLS is
//! intentionally unsupported here; these subscribers require plain redpanda:// endpoints.
//! Each subscriber runs in its own Tokio task with a reconnect loop: on any error the
//! connection is dropped and retried after a 5-second backoff, so transient Redpanda restarts
//! or network blips are recovered automatically without restarting the sensor process.

#[cfg(test)]
#[path = "config_subscriber_tests.rs"]
mod tests;

include!("config_subscriber_sections/subscribers.rs");
include!("config_subscriber_sections/redpanda_protocol.rs");
