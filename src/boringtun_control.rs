//! Native BoringTun userspace control helpers and CLI plumbing.

#[cfg(test)]
#[path = "boringtun_control_tests.rs"]
mod tests;

include!("boringtun_control_sections/uapi.rs");
include!("boringtun_control_sections/key_codec.rs");
