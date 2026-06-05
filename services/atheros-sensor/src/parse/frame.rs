//! Main parse entry point and model transformation steps.
//!
//! decode_frame is the primary entry point: it takes a RawPacket, strips the radiotap header,
//! validates the 802.11 frame type (control frames are rejected), then orchestrates all
//! sub-module calls (addresses, IE metadata, EAPOL, QoS, payload decap, correlation keys,
//! channel/band derivation) to produce a fully populated WifiFrame. Control frames (type 1)
//! return UnsupportedControlFrame; only management (0) and data (2) frames are decoded.
//! attach_context is the sensor enrichment step: it wraps a WifiFrame with the runtime
//! AuditContext (sensor_id, location_id, interface, channel, reg_domain) to produce an
//! EnrichedFrame without copying any frame data.
//! to_audit_entry is the serialization-ready flattening step: it moves all fields from
//! EnrichedFrame into the flat AuditEntry struct, appends channel/reg_domain/threat tags,
//! resolves the identity_source string, and sets device_id to None pending MAC lookup.

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;

include!("frame_sections/decode.rs");
include!("frame_sections/audit_entry.rs");
