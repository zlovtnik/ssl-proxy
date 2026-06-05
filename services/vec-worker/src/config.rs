//! Runtime configuration loaded from environment variables.
//!
//! Call `Config::from_env()` once at startup. All fields are validated before
//! `Ok` is returned; invalid configurations produce a `WorkerError` instead of panicking.

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

include!("config_sections/env.rs");
include!("config_sections/debug.rs");
