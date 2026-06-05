//! Worker orchestration — real database and embedding provider calls.
//!
//! # Span hierarchy during a single pass
//!
//! ```text
//! run_forever (worker_name, model, dimensions)
//! ├── run_once (drain_batches, rows_leased, rows_completed, rows_failed on exit)
//! │   ├── prepare_chunk (prepare_ms)
//! │   ├── embed_chunk (embed_ms)
//! │   └── complete_chunk (complete_ms)
//! └── run_once ...
//! ```

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;

include!("worker_sections/run_loop.rs");
include!("worker_sections/preparation.rs");
include!("worker_sections/embedding.rs");
include!("worker_sections/alert_sweeps.rs");
