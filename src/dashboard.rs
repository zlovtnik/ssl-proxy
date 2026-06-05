//! Admin API handlers for health, stats, hosts, and devices.
//!
//! This module serves health/readiness endpoints, host statistics snapshots, and
//! broadcast tasks for live stats. It does not proxy client traffic itself.

include!("dashboard_sections/health_hosts.rs");
include!("dashboard_sections/devices_stats.rs");
