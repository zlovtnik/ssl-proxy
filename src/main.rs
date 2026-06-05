#![warn(clippy::unwrap_used)]

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

include!("main_sections/startup.rs");
include!("main_sections/listeners.rs");
