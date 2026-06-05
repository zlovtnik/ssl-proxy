//! Runtime configuration loaded from environment variables.
//!
//! Call `Config::from_env()` once at startup. All fields are validated before
//! `Ok` is returned; invalid configurations produce `ConfigError` instead of
//! panicking. Sensitive fields remain redacted in `Debug`.

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

include!("config_sections/types.rs");
include!("config_sections/env_core.rs");
include!("config_sections/sync_tls.rs");
include!("config_sections/parsing.rs");
