//! Shared WireGuard UDP packet obfuscation helpers.
//!
//! This module is intentionally separate from `obfuscation.rs`, which handles
//! HTTP header normalization. These helpers operate on raw WireGuard UDP
//! datagrams for the server relay and the Linux client shim.

#[cfg(test)]
#[path = "wg_packet_obfuscation_tests.rs"]
mod tests;

include!("wg_packet_obfuscation_sections/types.rs");
include!("wg_packet_obfuscation_sections/encode_decode.rs");
include!("wg_packet_obfuscation_sections/frame_crypto.rs");
