#[cfg(test)]
#[path = "wg-obfs-shim_tests/mod.rs"]
mod tests;

include!("wg-obfs-shim_sections/cli.rs");
include!("wg-obfs-shim_sections/config.rs");
include!("wg-obfs-shim_sections/launch.rs");
