//! Redpanda-backed persistence boundary for audit event ingestion.

mod redpanda_store;
mod store;

#[doc(inline)]
pub use redpanda_store::{ProbeFlushObservation, RedpandaBacklog};
#[doc(inline)]
#[allow(unused_imports)]
pub use store::{AuthorizedWirelessNetwork, BacklogEntry, IngestRecord};
#[doc(inline)]
pub use store::{BacklogError, BacklogStore};
