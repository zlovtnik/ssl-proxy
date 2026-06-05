//! Parse pipeline for raw 802.11 radiotap captures.
//!
//! Each frame passes through a fixed sequence of sub-modules:
//! radiotap strips the radiotap header and extracts RF metadata (signal, frequency, data rate);
//! frame decodes the 802.11 MAC header, frame type, subtype, and control flags;
//! addresses resolves addr1-addr4 to named roles (bssid, source, destination, transmitter,
//! receiver) based on the DS-bit combination;
//! ie parses Information Elements from management frames (SSID, RSN, WPS, vendor IEs) and
//! computes security_flags;
//! eapol detects EAPOL key frames and extracts the PMKID for handshake capture;
//! qos extracts QoS TID, EOSP, and ack-policy from QoS data frames;
//! decap strips LLC/SNAP and decapsulates the payload into IP/transport/application layers;
//! correlation builds session_key, retransmit_key, frame_fingerprint, and adjacent_mac_hint;
//! tags applies anomaly and threat tags (large_frame, mixed_encryption, dedupe_or_replay_suspect).

mod addresses;
mod channel;
mod correlation;
mod crypto;
mod decap;
mod decrypt;
mod eapol;
mod frame;
mod handshake;
mod identity;
mod ie;
mod oui;
mod qos;
mod radiotap;
mod tags;
mod text;

#[doc(inline)]
pub use decrypt::try_decrypt_frame;
#[doc(inline)]
#[allow(unused_imports)]
pub use frame::ParseError;
#[doc(inline)]
pub use frame::{attach_context, decode_frame, recompute_risk_score, to_audit_entry};
#[doc(inline)]
pub use handshake::HandshakeMonitor;
#[doc(inline)]
#[allow(unused_imports)]
pub use identity::{IdentityCache, ResolvedIdentity};
#[doc(inline)]
#[allow(unused_imports)]
pub use ie::{
    IEIterator, InformationElement, RSN_CAP_PMF_CAPABLE, RSN_CAP_PMF_REQUIRED,
    SECURITY_PMF_REQUIRED, SECURITY_RSN_WPA2, SECURITY_WPA, SECURITY_WPA3, SECURITY_WPS,
};
#[doc(inline)]
#[allow(unused_imports)]
pub use oui::oui_lookup;
#[doc(inline)]
#[allow(unused_imports)]
pub use radiotap::{strip_radiotap, RadiotapMetadata};
