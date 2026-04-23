use sha2::{Digest, Sha256};

use super::addresses::MacAddresses;

pub(super) fn adjacent_mac_hint(addresses: &MacAddresses) -> Option<String> {
    let values = [
        addresses.bssid.as_deref(),
        addresses.source_mac.as_deref(),
        addresses.destination_mac.as_deref(),
        addresses.transmitter_mac.as_deref(),
        addresses.receiver_mac.as_deref(),
    ];
    let mut hints = Vec::new();
    for left in 0..values.len() {
        for right in left + 1..values.len() {
            let Some(lhs) = values[left] else {
                continue;
            };
            let Some(rhs) = values[right] else {
                continue;
            };
            if are_adjacent_macs(lhs, rhs) {
                hints.push(format!("{lhs}~{rhs}"));
            }
        }
    }
    if hints.is_empty() {
        None
    } else {
        hints.sort();
        hints.dedup();
        Some(hints.join(","))
    }
}

pub(super) fn session_key(
    source_mac: Option<&str>,
    destination_bssid: Option<&str>,
    destination_mac: Option<&str>,
) -> Option<String> {
    let source_mac = normalize_mac(source_mac?)?;
    let peer = normalize_mac(destination_bssid.or(destination_mac)?)?;
    Some(format!("{source_mac}|{peer}"))
}

pub(super) fn retransmit_key(
    transmitter_mac: Option<&str>,
    receiver_mac: Option<&str>,
    sequence_number: Option<u16>,
    fragment_number: Option<u8>,
) -> Option<String> {
    Some(format!(
        "{}|{}|{}|{}",
        normalize_mac(transmitter_mac?)?,
        normalize_mac(receiver_mac?)?,
        sequence_number?,
        fragment_number?
    ))
}

pub(super) fn frame_fingerprint(
    frame_control: u16,
    frame_subtype: &str,
    addresses: &MacAddresses,
    frame_bytes: &[u8],
) -> String {
    let normalized = format!(
        "{frame_control:04x}|{frame_subtype}|{}|{}|{}|{}|{}",
        addresses.bssid.as_deref().and_then(normalize_mac).unwrap_or(""),
        addresses
            .source_mac
            .as_deref()
            .and_then(normalize_mac)
            .unwrap_or(""),
        addresses
            .destination_mac
            .as_deref()
            .and_then(normalize_mac)
            .unwrap_or(""),
        addresses
            .transmitter_mac
            .as_deref()
            .and_then(normalize_mac)
            .unwrap_or(""),
        addresses
            .receiver_mac
            .as_deref()
            .and_then(normalize_mac)
            .unwrap_or("")
    );
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hasher.update(frame_bytes);
    format!("{:x}", hasher.finalize())
}

fn are_adjacent_macs(lhs: &str, rhs: &str) -> bool {
    let lhs = parse_mac(lhs);
    let rhs = parse_mac(rhs);
    let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
        return false;
    };
    if lhs[..5] != rhs[..5] {
        return false;
    }
    let diff = lhs[5].abs_diff(rhs[5]);
    (1..=4).contains(&diff)
}

fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for (index, part) in parts.iter().enumerate() {
        out[index] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(out)
}

fn normalize_mac(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}
