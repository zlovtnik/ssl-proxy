//! OUI (Organizationally Unique Identifier) vendor lookup from MAC addresses.
//!
//! Loads the Wireshark manuf database at runtime into a HashMap for fast lookups.
//! oui_lookup extracts the first 3 octets from a MAC address string and returns the vendor
//! name if found. The manuf file is embedded at compile time and parsed on first use.

use std::collections::HashMap;
use std::sync::OnceLock;

static OUI_MAP: OnceLock<HashMap<[u8; 3], &'static str>> = OnceLock::new();

const MANUF_DATA: &str = include_str!("../../data/manuf");

/// Initializes the OUI map by parsing the embedded manuf file.
/// Only parses 24-bit (3-byte) OUI entries, skipping 28-bit and 36-bit entries.
fn init_oui_map() -> HashMap<[u8; 3], &'static str> {
    let mut map = HashMap::new();

    for line in MANUF_DATA.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        // Parse MAC prefix (first column)
        let mac_str = parts[0];
        let octets: Vec<&str> = mac_str.split(':').collect();

        // Only process 24-bit OUIs (3 octets)
        if octets.len() != 3 {
            continue;
        }

        let mut oui = [0u8; 3];
        let mut valid = true;
        for (i, octet_str) in octets.iter().enumerate() {
            if let Ok(octet) = u8::from_str_radix(octet_str, 16) {
                oui[i] = octet;
            } else {
                valid = false;
                break;
            }
        }

        if !valid {
            continue;
        }

        // Use the full vendor name (third column onwards) if available, else short name
        let vendor = if parts.len() >= 3 {
            // Join all parts from index 2 onwards for full vendor name
            parts[2..].join(" ")
        } else {
            parts[1].to_string()
        };

        // Leak the string to get 'static lifetime
        let vendor_static: &'static str = Box::leak(vendor.into_boxed_str());
        map.insert(oui, vendor_static);
    }

    map
}

/// Looks up the vendor name for a MAC address by extracting its OUI (first 3 octets).
/// Returns None if the MAC address is malformed or the OUI is not in the database.
///
/// # Examples
///
/// ```
/// use atheros_sensor::parse::oui_lookup;
///
/// assert_eq!(oui_lookup("00:00:01:40:50:60"), Some("Xerox Corporation"));
/// assert_eq!(oui_lookup("invalid"), None);
/// ```
pub fn oui_lookup(mac: &str) -> Option<&'static str> {
    let octets = parse_mac_prefix(mac)?;
    let map = OUI_MAP.get_or_init(init_oui_map);
    map.get(&octets).copied()
}

/// Parses the first 3 octets from a MAC address string in colon-separated format.
/// Returns None if the MAC address is malformed or too short.
fn parse_mac_prefix(mac: &str) -> Option<[u8; 3]> {
    let parts: Vec<&str> = mac.split(':').take(3).collect();
    if parts.len() < 3 {
        return None;
    }

    let mut octets = [0u8; 3];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mac_prefix() {
        assert_eq!(
            parse_mac_prefix("10:20:30:40:50:60"),
            Some([0x10, 0x20, 0x30])
        );
        assert_eq!(
            parse_mac_prefix("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc])
        );
        assert_eq!(parse_mac_prefix("invalid"), None);
        assert_eq!(parse_mac_prefix("10:20"), None);
    }

    #[test]
    fn looks_up_oui() {
        // Test with known Xerox OUI
        let result = oui_lookup("00:00:01:00:00:00");
        assert!(result.is_some());
        assert!(result.unwrap().contains("Xerox"));

        assert_eq!(oui_lookup("invalid"), None);
    }

    #[test]
    fn initializes_map_once() {
        let _ = oui_lookup("00:00:01:00:00:00");
        let _ = oui_lookup("00:00:02:00:00:00");
        // Map should be initialized only once
    }
}
