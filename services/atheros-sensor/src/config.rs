//! Environment-variable-only configuration model.
//!
//! All settings are read from environment variables at startup via AppConfig::from_env; there is
//! no config file. Secrets support a file-fallback pattern: read_secret checks the plain variable
//! first, then falls back to reading the path named by the _FILE variant, enabling Docker secrets
//! mounts without exposing values in the environment. ATH_SENSOR_REQUIRE_HOST_ENDPOINTS is a
//! deployment guard that rejects Docker service hostnames ("redpanda") in Redpanda endpoints,
//! enforcing host-network-mode endpoints when the sensor runs outside Docker.
//!
//! # AppConfig field mutability
//!
//! Fields that can be updated at runtime via a Redpanda push (no restart required):
//! `bpf` (BPF filter), `channel` (via `wireless.config.sensor`), and the `audit_window`
//! schedule (via `wireless.audit.config`).
//!
//! All other fields - including `snaplen`, `pcap_timeout_ms`,
//! `log_idle_secs`, and all metrics settings - are
//! read once at startup and require a process restart to change.

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

include!("config_sections/env.rs");
include!("config_sections/parsing.rs");
