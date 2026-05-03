//! CCMP decryption integration for protected data frames.

use crate::{
    backlog::AuthorizedWirelessNetwork,
    model::WifiFrame,
    parse::{crypto, handshake::HandshakeMonitor},
};

/// Attempts to decrypt a protected data frame using stored handshake state and authorized PSK.
/// Returns true if decryption succeeded and payload_visibility was updated to "decrypted".
pub fn try_decrypt_frame(
    frame: &mut WifiFrame,
    handshake_monitor: &HandshakeMonitor,
    authorized_networks: &[AuthorizedWirelessNetwork],
) -> bool {
    if !frame.protected || frame.frame_type_raw != 2 {
        return false;
    }
    
    let bssid = match frame.bssid.as_ref() {
        Some(b) => b,
        None => return false,
    };
    
    let client_mac = if frame.to_ds && !frame.from_ds {
        frame.source_mac.as_ref()
    } else if frame.from_ds && !frame.to_ds {
        frame.destination_mac.as_ref()
    } else {
        frame.source_mac.as_ref().or(frame.destination_mac.as_ref())
    };
    
    let client_mac = match client_mac {
        Some(c) => c,
        None => return false,
    };
    
    let ssid = frame.ssid.as_ref();
    let psk = match find_matching_psk(ssid, Some(bssid), authorized_networks) {
        Some(p) => p,
        None => return false,
    };
    
    let (anonce, snonce) = match get_nonces(handshake_monitor, bssid, client_mac) {
        Some(n) => n,
        None => return false,
    };
    
    let bssid_bytes = match crypto::parse_mac(bssid) {
        Some(b) => b,
        None => return false,
    };
    let client_mac_bytes = match crypto::parse_mac(client_mac) {
        Some(c) => c,
        None => return false,
    };
    
    let (_kck, _kek, tk) = crypto::derive_ptk(
        &psk,
        ssid.map_or("", |v| v),
        &anonce,
        &snonce,
        &bssid_bytes,
        &client_mac_bytes,
    );
    
    let raw_frame = match frame.raw_frame.as_ref() {
        Some(r) => r.as_bytes(),
        None => return false,
    };
    let (header, encrypted_payload) = match extract_header_and_payload(raw_frame, frame) {
        Some(h) => h,
        None => return false,
    };
    
    let _plaintext = match crypto::ccmp_decrypt(&tk, header, encrypted_payload) {
        Some(p) => p,
        None => return false,
    };
    
    frame.payload_visibility = "decrypted".to_string();
    true
}

fn find_matching_psk(
    ssid: Option<&String>,
    bssid: Option<&String>,
    networks: &[AuthorizedWirelessNetwork],
) -> Option<String> {
    for network in networks {
        if network.psk.is_none() {
            continue;
        }
        
        let ssid_match = match (&network.ssid, ssid) {
            (Some(net_ssid), Some(frame_ssid)) => {
                net_ssid.to_lowercase() == frame_ssid.to_lowercase()
            }
            (None, _) => true,
            _ => false,
        };
        
        let bssid_match = match (&network.bssid, bssid) {
            (Some(net_bssid), Some(frame_bssid)) => {
                net_bssid.to_lowercase() == frame_bssid.to_lowercase()
            }
            (None, _) => true,
            _ => false,
        };
        
        if ssid_match && bssid_match {
            return network.psk.clone();
        }
    }
    None
}

fn extract_header_and_payload<'a>(
    raw_frame: &'a [u8],
    frame: &WifiFrame,
) -> Option<(&'a [u8], &'a [u8])> {
    let fc = frame.frame_control;
    let subtype = frame.frame_subtype_raw;
    
    let to_ds = fc & (1 << 8) != 0;
    let from_ds = fc & (1 << 9) != 0;
    
    let mut offset = 24usize;
    if to_ds && from_ds {
        offset += 6;
    }
    
    if subtype & 0x08 != 0 {
        offset += 2;
        if fc & (1 << 15) != 0 {
            offset += 4;
        }
    }
    
    if raw_frame.len() <= offset {
        return None;
    }
    
    let header = &raw_frame[..offset];
    let payload = &raw_frame[offset..];
    
    Some((header, payload))
}

fn get_nonces(
    handshake_monitor: &HandshakeMonitor,
    bssid: &str,
    client_mac: &str,
) -> Option<([u8; 32], [u8; 32])> {
    let key = format!(
        "{}|{}",
        bssid.to_ascii_lowercase(),
        client_mac.to_ascii_lowercase()
    );
    let state = handshake_monitor.states.get(&key)?;
    let anonce = state.anonce?;
    let snonce = state.snonce?;
    Some((anonce, snonce))
}
