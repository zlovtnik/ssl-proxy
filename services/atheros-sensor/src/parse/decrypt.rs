//! CCMP decryption integration for protected data frames.

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::{
    backlog::AuthorizedWirelessNetwork,
    model::WifiFrame,
    parse::{
        crypto,
        decap::{analyze_decrypted_payload, PayloadAnalysis},
        handshake::HandshakeMonitor,
        tags::push_tag,
    },
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
    let (psk, ptk_ssid) = match find_matching_psk(ssid, Some(bssid), authorized_networks) {
        Some(match_) => match_,
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
        &ptk_ssid,
        &anonce,
        &snonce,
        &bssid_bytes,
        &client_mac_bytes,
    );

    let raw_frame = match frame
        .raw_frame
        .as_ref()
        .and_then(|raw| STANDARD.decode(raw).ok())
    {
        Some(bytes) => bytes,
        None => return false,
    };
    let (header, encrypted_payload) = match extract_header_and_payload(&raw_frame, frame) {
        Some(h) => h,
        None => return false,
    };

    let plaintext = match crypto::ccmp_decrypt(&tk, header, encrypted_payload) {
        Some(p) => p,
        None => return false,
    };

    apply_decrypted_payload(frame, analyze_decrypted_payload(&plaintext));
    true
}

fn find_matching_psk(
    ssid: Option<&String>,
    bssid: Option<&String>,
    networks: &[AuthorizedWirelessNetwork],
) -> Option<(String, String)> {
    for network in networks {
        let Some(psk) = network.psk.as_ref() else {
            continue;
        };
        if network.ssid.is_none() && network.bssid.is_none() {
            continue;
        }

        let bssid_match = match (&network.bssid, bssid) {
            (Some(net_bssid), Some(frame_bssid)) => net_bssid.eq_ignore_ascii_case(frame_bssid),
            (None, _) => true,
            _ => false,
        };
        if !bssid_match {
            continue;
        }

        let ssid_match = match (&network.ssid, ssid) {
            (Some(net_ssid), Some(frame_ssid)) => net_ssid.eq_ignore_ascii_case(frame_ssid),
            (Some(_), None) if network.bssid.is_some() => true,
            (None, _) => true,
            _ => false,
        };

        if ssid_match {
            let ptk_ssid = ssid.cloned().or_else(|| network.ssid.clone())?;
            return Some((psk.clone(), ptk_ssid));
        }
    }
    None
}

fn apply_decrypted_payload(frame: &mut WifiFrame, analysis: PayloadAnalysis) {
    let network_seen = analysis.network.is_some();
    let app_protocol_tag = analysis
        .app_protocol
        .as_ref()
        .map(|protocol| format!("app:{protocol}"));
    let ethertype_tag = analysis
        .ethertype_name
        .as_ref()
        .map(|ethertype| format!("ethertype:{ethertype}"));

    frame.llc_snap = analysis.llc_snap;
    frame.network = analysis.network;
    frame.transport = analysis.transport;
    frame.application = analysis.application;
    frame.llc_oui = analysis.llc_oui;
    frame.ethertype = analysis.ethertype;
    frame.ethertype_name = analysis.ethertype_name;
    frame.src_ip = analysis.src_ip;
    frame.dst_ip = analysis.dst_ip;
    frame.ip_ttl = analysis.ip_ttl;
    frame.ip_protocol = analysis.ip_protocol;
    frame.ip_protocol_name = analysis.ip_protocol_name;
    frame.src_port = analysis.src_port;
    frame.dst_port = analysis.dst_port;
    frame.transport_protocol = analysis.transport_protocol;
    frame.transport_length = analysis.transport_length;
    frame.transport_checksum = analysis.transport_checksum;
    frame.app_protocol = analysis.app_protocol;
    frame.ssdp_message_type = analysis.ssdp_message_type;
    frame.ssdp_st = analysis.ssdp_st;
    frame.ssdp_mx = analysis.ssdp_mx;
    frame.ssdp_usn = analysis.ssdp_usn;
    frame.dhcp_requested_ip = analysis.dhcp_requested_ip;
    frame.dhcp_hostname = analysis.dhcp_hostname;
    frame.dhcp_vendor_class = analysis.dhcp_vendor_class;
    frame.dns_query_name = analysis.dns_query_name;
    frame.mdns_name = analysis.mdns_name;
    frame.payload_visibility = "decrypted".to_string();
    frame.correlation.payload_visibility = "decrypted".to_string();

    push_tag(&mut frame.tags, "payload:decrypted");
    if network_seen {
        push_tag(&mut frame.tags, "network:ipv4");
    }
    if let Some(tag) = app_protocol_tag {
        push_tag(&mut frame.tags, &tag);
    }
    if let Some(tag) = ethertype_tag {
        push_tag(&mut frame.tags, &tag);
    }
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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::{
        model::RawPacket,
        parse::decode_frame,
        testutil::{
            build_frame, data_to_distribution_radiotap_frame, dns_query_payload,
            llc_snap_ipv4_udp_payload, AP, CLIENT, DISTRIBUTION_DST,
        },
    };

    #[test]
    fn decrypted_payload_updates_existing_metadata_without_plaintext_export() {
        let mut frame = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(Vec::new()),
        })
        .unwrap();
        let original_raw_frame = frame.raw_frame.clone();
        let plaintext = llc_snap_ipv4_udp_payload(
            [192, 168, 1, 20],
            [1, 1, 1, 1],
            55_000,
            53,
            &dns_query_payload("printer.local"),
        );

        apply_decrypted_payload(&mut frame, analyze_decrypted_payload(&plaintext));

        assert_eq!(frame.payload_visibility, "decrypted");
        assert_eq!(frame.correlation.payload_visibility, "decrypted");
        assert_eq!(frame.app_protocol.as_deref(), Some("dns"));
        assert_eq!(frame.dns_query_name.as_deref(), Some("printer.local"));
        assert!(frame.tags.contains(&"payload:decrypted".to_string()));
        assert_eq!(frame.raw_frame, original_raw_frame);
    }

    #[test]
    fn protected_frame_decrypt_fails_closed_without_handshake_nonces() {
        let mut frame = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x08, 0x41, AP, CLIENT, DISTRIBUTION_DST, None, vec![0; 32]),
        })
        .unwrap();
        let networks = vec![AuthorizedWirelessNetwork {
            ssid: Some("CorpWiFi".to_string()),
            bssid: Some("10:20:30:40:50:60".to_string()),
            location_id: None,
            psk: Some("correct horse battery staple".to_string()),
        }];

        assert!(!try_decrypt_frame(
            &mut frame,
            &HandshakeMonitor::default(),
            &networks
        ));
        assert_eq!(frame.payload_visibility, "ciphertext");
        assert_eq!(frame.app_protocol, None);
    }

    #[test]
    fn psk_match_uses_authorized_ssid_when_data_frame_has_none() {
        let networks = vec![AuthorizedWirelessNetwork {
            ssid: Some("CorpWiFi".to_string()),
            bssid: Some("10:20:30:40:50:60".to_string()),
            location_id: None,
            psk: Some("secret".to_string()),
        }];

        let matched = find_matching_psk(None, Some(&"10:20:30:40:50:60".to_string()), &networks)
            .expect("BSSID match should use stored SSID for PTK derivation");

        assert_eq!(matched.0, "secret");
        assert_eq!(matched.1, "CorpWiFi");
    }
}
