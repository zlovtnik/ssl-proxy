//! Two-tier persistence strategy for audit event ingestion.
//!
//! Postgres is the primary store (sync_scan_ingest ledger + audit_backlog fallback table).
//! When Postgres is unavailable, the pipeline falls back to an in-memory LRU circuit-breaker
//! that buffers events until connectivity is restored, preventing data loss during transient failures.

mod pool_diag;
mod postgres;
mod store;
mod wireless_columns;

pub use postgres::PostgresBacklog;
#[allow(unused_imports)]
pub use store::{AuthorizedWirelessNetwork, BacklogEntry, IngestRecord};
pub use store::{BacklogError, BacklogStore};
