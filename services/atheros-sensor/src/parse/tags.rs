use crate::model::WifiFrame;

pub(super) fn push_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|existing| existing == tag) {
        tags.push(tag.to_string());
    }
}

pub(super) fn is_locally_administered_mac(mac: &str) -> bool {
    mac.get(..2)
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        .map(|octet| octet & 0x02 != 0)
        .unwrap_or(false)
}

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

pub(super) fn tag_probe_response_destination(
    destination_mac: Option<&str>,
    tags: &mut Vec<String>,
) {
    if destination_mac.is_some_and(is_locally_administered_mac) {
        push_tag(tags, "threat:karma_probe_response");
        push_tag(tags, "identity:randomized_mac");
    }
}

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
