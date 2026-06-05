//! QUIC/HTTP3 explicit proxy listener.
//!
//! This module accepts HTTP/3 CONNECT requests over QUIC and proxies the
//! resulting tunnel to the upstream destination. It does not handle admin
//! traffic or non-CONNECT HTTP methods beyond returning `405`.

include!("quic_sections/listener.rs");
include!("quic_sections/requests.rs");
