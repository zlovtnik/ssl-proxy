//! Shared application state used by proxy, tunnel, polling, and dashboard handlers.

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;

include!("state_sections/models.rs");
include!("state_sections/app_state.rs");
include!("state_sections/recording.rs");
