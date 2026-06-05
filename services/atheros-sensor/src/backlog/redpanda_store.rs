//! Redpanda-backed wireless backlog and lookup store.

#[cfg(test)]
#[path = "redpanda_store_tests.rs"]
mod tests;

include!("redpanda_store_sections/connection.rs");
include!("redpanda_store_sections/requests.rs");
include!("redpanda_store_sections/backlog_store.rs");
include!("redpanda_store_sections/transport.rs");
