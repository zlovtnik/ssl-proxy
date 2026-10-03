//! Generic outbound sync-plane publisher.

include!("publisher_sections/types.rs");
include!("publisher_sections/publisher.rs");
include!("publisher_sections/tls.rs");
include!("publisher_sections/test_harness.rs");

#[cfg(test)]
#[path = "publisher_sections/retention_tests.rs"]
mod retention_tests;
