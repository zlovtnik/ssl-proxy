//! TCP tunnel handling for explicit CONNECT and transparent proxy flows.
//!
//! This module owns the TCP-side proxy paths, including TLS fingerprint peeking,
//! upstream dialing, traffic classification, and tarpitting. It does not handle
//! plain HTTP proxying; that remains in `proxy.rs`.

pub(crate) mod audit_event;
mod classify;
mod connect;
mod dial;
mod socket_tuning;
mod tarpit;
pub(crate) mod tls;
mod transparent;

#[cfg(feature = "quic")]
pub(crate) use classify::classify;
pub use connect::handle;
#[cfg(feature = "quic")]
pub(crate) use dial::dial_upstream_with_resolver;
#[cfg(feature = "quic")]
pub(crate) use dial::parse_host_port;
pub use tarpit::tarpit_semaphore;
pub use transparent::handle_transparent;
