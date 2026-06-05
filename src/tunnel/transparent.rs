//! Transparent proxy tunnel flow.
//!
//! This module handles raw TCP connections redirected by iptables, extracting
//! the original destination, optional TLS metadata, and then either blocking,
//! bypassing, or proxying the connection. It does not own CONNECT handling.

#[cfg(test)]
#[path = "transparent_tests.rs"]
mod tests;

include!("transparent_sections/listener.rs");
include!("transparent_sections/decisions.rs");
include!("transparent_sections/proxying.rs");
