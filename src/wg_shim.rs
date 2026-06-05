//! Linux WireGuard obfuscation shim.
//!
//! The shim listens locally for plaintext WireGuard UDP packets from a client
//! and forwards them to the real server endpoint using the shared WireGuard
//! packet obfuscation codec.

#[cfg(test)]
#[path = "wg_shim_tests.rs"]
mod tests;

include!("wg_shim_sections/config_metrics.rs");
include!("wg_shim_sections/sessions.rs");
include!("wg_shim_sections/runtime.rs");
include!("wg_shim_sections/networking.rs");
