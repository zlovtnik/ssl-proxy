//! Runtime configuration loaded from environment variables.
//!
//! Call `Config::from_env()` once at startup. All fields are validated before
//! `Ok` is returned; invalid configurations produce `ConfigError` instead of
//! panicking. Sensitive fields remain redacted in `Debug`.

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

#[path = "config_sections/env_core.rs"]
mod env_core;
#[path = "config_sections/parsing.rs"]
mod parsing;
#[path = "config_sections/sync_tls.rs"]
mod sync_tls;
#[path = "config_sections/types.rs"]
mod types;

#[cfg(test)]
pub(crate) use parsing::read_secret;
pub use sync_plane::SyncConfig;
pub use types::*;
