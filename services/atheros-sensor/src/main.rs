//! Single-threaded async event loop and sensor lifecycle.
//!
//! run_sensor drives a tokio::select! loop over incoming pcap packets, a heartbeat
//! ticker for idle logging, a bandwidth flush interval, and a client inventory flush interval.
//! All mutable per-frame state lives in PipelineState, which is
//! owned by the loop and never shared across tasks, avoiding locks on the hot path.
//! SensorHandles bundles the shared resources that are either read-only or Arc-wrapped:
//! the Redpanda backlog, the Redpanda publish client, the audit window, and the authorized-network
//! config generation counter. On SIGTERM or Ctrl-C, shutdown_flush drains the current bandwidth
//! window, flushes the in-memory publish backlog to the coordinator, then sleeps for shutdown_grace_secs
//! to allow in-flight Redpanda publishes to complete before the process exits.
//!
//! # Type notes
//!
//! [`SensorHandles`]: the main loop's owned state bundle; fields are either `Clone`-cheap
//! shared handles (`Arc`, `SharedAuditWindow`) or values consumed once at startup - nothing
//! here is mutated per-packet.
//!
//! [`PipelineState`]: all per-packet mutable state (identity cache, handshake monitor,
//! traffic bucket, detector state, authorized-network cache); constructed once in `run_sensor`
//! and reset only by a process restart.
//!
//! [`CaptureStats`]: cumulative counters incremented since process startup, not windowed or
//! reset between heartbeat log lines - use the delta between two log lines for rate calculation.

mod audit;
mod backlog;
mod capture;
mod channel_control;
mod config;
mod config_subscriber;
mod detect_state;
mod device;
mod device_registry;
mod digest;
mod error;
mod metrics;
mod model;
mod observability;
mod parse;
mod probes;
mod publish;
mod state_key;
mod stats;
#[cfg(test)]
mod testutil;
mod timing;
mod topics;

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

include!("main_sections/lifecycle.rs");
include!("main_sections/pipeline.rs");
include!("main_sections/detectors.rs");
include!("main_sections/publishing.rs");
