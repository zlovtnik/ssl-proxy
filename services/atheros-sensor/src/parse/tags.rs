//! Tag accumulation utilities for WiFi frame classification.
//!
//! Tags are accumulated into a Vec<String> during frame parsing to classify both structural
//! properties (direction, signal strength) and threat indicators (Karma attacks, evil twins,
//! deauth frames). Structural tags describe normal frame characteristics; threat tags flag
//! suspicious patterns requiring security review.

use crate::model::WifiFrame;

use super::ie::{SECURITY_PMF_CAPABLE, SECURITY_PMF_REQUIRED, SECURITY_WPA3};

/// Pushes a tag into the vector only if it does not already exist, ensuring deduplication.
/// No-op if the tag is already present.
pub(super) fn push_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|existing| existing == tag) {
        tags.push(tag.to_string());
    }
}

/// Returns true if bit 2 of the first octet is set, indicating a locally administered MAC
/// address. This is the primary indicator of MAC randomization used by modern devices for
/// privacy. Format expected: colon-separated hex string (e.g., "02:00:00:00:00:00").
pub(super) fn is_locally_administered_mac(mac: &str) -> bool {
    mac.get(..2)
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        .map(|octet| octet & 0x02 != 0)
        .unwrap_or(false)
}

/// Returns a direction tag based on the ToDS and FromDS bits in the 802.11 frame control field.
/// - (0,0) => "direction:intra_bss" (ad-hoc or direct client-to-client)
/// - (1,0) => "direction:to_ds" (client sending to AP)
/// - (0,1) => "direction:from_ds" (AP sending to client)
/// - (1,1) => "direction:wds" (wireless distribution system bridge)
pub(super) fn data_direction_tag(frame_control: u16) -> &'static str {
    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;
    match (to_ds, from_ds) {
        (false, false) => "direction:intra_bss",
        (true, false) => "direction:to_ds",
        (false, true) => "direction:from_ds",
        (true, true) => "direction:wds",
    }
}

/// Tags probe responses sent to locally administered (randomized) MAC addresses as potential
/// Karma attack indicators. Karma APs respond to probe requests from randomized MACs, which
/// legitimate APs typically ignore. Adds both "threat:karma_probe_response" and
/// "identity:randomized_mac" tags when detected.
pub(super) fn tag_probe_response_destination(
    destination_mac: Option<&str>,
    tags: &mut Vec<String>,
) {
    if destination_mac.is_some_and(is_locally_administered_mac) {
        push_tag(tags, "threat:karma_probe_response");
        push_tag(tags, "identity:randomized_mac");
    }
}

/// Applies all threat and audit tags to a parsed frame. Executed after structural tags are
/// applied. Checks performed in order:
/// 1. SSID contains suspicious keywords ("setup", "wifi", "spectrumsetup") => potential_evil_twin
/// 2. Probe response to randomized MAC => randomized_mac_target
/// 3. Deauth or disassociation frame => deauth_frame
/// 4. WPA3 without PMF advertised => pmf_downgrade_suspect
/// 5. Weak RSN cipher suite advertised => weak_cipher_advertised
/// 6. Signal strength tier (strong/medium/weak/very_weak) based on dBm
pub(super) fn add_audit_threat_tags(frame: &WifiFrame, tags: &mut Vec<String>) {
    if let Some(ssid) = frame.ssid.as_deref() {
        let ssid_lower = ssid.to_ascii_lowercase();
        if ssid_lower.contains("setup")
            || ssid_lower.contains("wifi")
            || ssid_lower.starts_with("spectrumsetup")
        {
            push_tag(tags, "threat:potential_evil_twin");
        }
    }
    if frame.frame_subtype == "probe_response"
        && frame
            .destination_mac
            .as_deref()
            .is_some_and(is_locally_administered_mac)
    {
        push_tag(tags, "identity:randomized_mac_target");
    }
    if matches!(
        frame.frame_subtype.as_str(),
        "deauthentication" | "disassociation"
    ) {
        push_tag(tags, "threat:deauth_frame");
    }
    if frame.security_flags & SECURITY_WPA3 != 0
        && frame.security_flags & (SECURITY_PMF_REQUIRED | SECURITY_PMF_CAPABLE) == 0
        && frame.rsn_capabilities.is_some()
    {
        push_tag(tags, "threat:pmf_downgrade_suspect");
    }
    if frame.weak_cipher_advertised == Some(true) {
        push_tag(tags, "threat:weak_cipher_advertised");
    }
    if let Some(dbm) = frame.signal_dbm {
        push_tag(tags, signal_tier_tag(dbm));
    }
}

fn signal_tier_tag(dbm: i8) -> &'static str {
    match dbm {
        -50..=0 => "signal:strong",
        -70..=-51 => "signal:medium",
        -85..=-71 => "signal:weak",
        _ => "signal:very_weak",
    }
}
