//! Database layer — pure async functions for job leasing, embedding upsert,
//! worker-state heartbeats, and lease reaping.
//!
//! Every function is a free-standing `pub async fn` that takes `&PgPool` plus
//! its required data.  No structs with methods — just functions.
//!
//! # Types
//!
//! * [`EmbeddingJob`] — row returned by `vec_lease_embedding_jobs()`
//! * [`EmbeddingInput`] — bundles text + metadata for `upsert_embedding`
//! * [`WorkerStateParams`] — input parameters for `mark_worker_state`

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "db_tests.rs"]
mod tests;

include!("db_sections/jobs.rs");
include!("db_sections/embeddings.rs");
