//! NATS-backed persistence boundary for audit event ingestion.

mod nats_store;
mod store;

#[doc(inline)]
pub use nats_store::{NatsBacklog, ProbeFlushObservation};
#[doc(inline)]
#[allow(unused_imports)]
pub use store::{AuthorizedWirelessNetwork, BacklogEntry, IngestRecord};
#[doc(inline)]
pub use store::{BacklogError, BacklogStore};
