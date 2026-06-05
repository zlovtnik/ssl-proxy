//! Alert generation — periodic checks that produce structured alerts in `vec_alerts`.
//!
//! Each function queries a database view or table, compares against thresholds, and
//! inserts rows into `vec_alerts`. These functions are called periodically from the
//! main worker loop.

#[cfg(test)]
#[path = "alerts_tests.rs"]
mod tests;

include!("alerts_sections/models.rs");
include!("alerts_sections/audit_alerts.rs");
include!("alerts_sections/reporting.rs");
