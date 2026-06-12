//! Correlation key generation for deduplication and session tracking.
//!
//! Three keys are produced per frame:
//! session_key identifies a client-AP pair as "source_mac|bssid" (falling back to
//! destination_mac when no bssid is present), used to group frames into logical sessions;
//! retransmit_key is "transmitter|receiver|seq|frag" and identifies duplicate or retransmitted
//! frames for dedup detection;
//! frame_fingerprint is a SHA-256 hash over a pipe-delimited string of normalized frame_control,
//! subtype, and all five MAC address roles, concatenated with the raw frame bytes, producing a
//! content-addressed identity for exact-match replay detection.
//! adjacent_mac_hint scans all five address fields for MAC pairs that share the first five octets
//! and differ in the last by 1-4, a common indicator of AP/client interface adjacency.

use super::addresses::MacAddresses;
/// Detects MAC address pairs that differ only in the last octet by 1-4.
///
/// Scans all five address fields for pairs sharing the first five octets,
/// indicating potential AP/client interface adjacency. Returns a comma-separated
/// list of adjacent pairs in "mac1~mac2" format, sorted and deduplicated.
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
/// Generates a session key identifying a client–AP pair as "source_mac|peer".
///
/// Uses `destination_bssid` as peer, falling back to `destination_mac` if absent.
/// Returns `None` if `source_mac` or peer is missing or empty.
pub(super) fn session_key(
    source_mac: Option<&str>,
    destination_bssid: Option<&str>,
    destination_mac: Option<&str>,
) -> Option<String> {
    let source_mac = normalize_mac(source_mac?)?;
    let peer = normalize_mac(destination_bssid.or(destination_mac)?)?;
    Some(format!("{source_mac}|{peer}"))
}
/// Generates a retransmit key as "transmitter|receiver|seq|frag".
///
/// Used for duplicate and retransmission detection. Returns `None` if any
/// required field is missing.
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
/// Generates a SHA-256 content-addressed fingerprint for exact-match replay detection.
///
/// Hashes a normalized string of frame_control, subtype, all five MAC addresses,
/// concatenated with raw frame bytes. Returns a hex-encoded digest.
pub(super) fn frame_fingerprint(
    frame_control: u16,
    frame_subtype: &str,
    addresses: &MacAddresses,
    frame_bytes: &[u8],
) -> String {
    let normalized = format!(
        "{frame_control:04x}|{frame_subtype}|{}|{}|{}|{}|{}",
        addresses
            .bssid
            .as_deref()
            .and_then(normalize_mac)
            .unwrap_or(""),
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
    ssl_proxy::sha256_hex(&[normalized.as_bytes(), frame_bytes])
}
/// Returns `true` if two MAC addresses share the first five octets and differ
/// in the last octet by 1-4.
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
/// Parses a colon-separated MAC address string into a 6-byte array.
///
/// Returns `None` if the format is invalid or any octet fails to parse as hex.
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
/// Returns `None` if the MAC address string is empty, otherwise returns the input.
fn normalize_mac(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}
