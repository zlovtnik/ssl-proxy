//! Obfuscated WireGuard UDP relay.
//!
//! This relay fronts the public WireGuard UDP port, removes the configured
//! XOR-plus-magic-byte wrapping from inbound packets, forwards plaintext
//! packets to the local kernel WireGuard listener, and applies the inverse
//! transform to replies before sending them back to the client.

#[cfg(test)]
#[path = "wg_relay_tests.rs"]
mod tests;

include!("wg_relay_sections/runtime.rs");
include!("wg_relay_sections/session_io.rs");
