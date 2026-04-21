use std::collections::HashMap;

use ieee80211::GenericFrame;
use thiserror::Error;

use crate::model::{AuditContext, AuditEntry, EnrichedFrame, RawPacket, WifiFrame};

const LLC_SNAP_EAPOL_PREFIX: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("frame too short for radiotap header")]
    MissingRadiotap,
    #[error("frame too short for 802.11 frame header")]
    MissingFrameHeader,
    #[error("unsupported control frame")]
    UnsupportedControlFrame,
    #[error("ieee80211 parser rejected frame")]
    Invalid80211,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedIdentity {
    pub username: String,
    pub source: String,
}

#[derive(Default)]
pub struct IdentityCache {
    mac_to_username: HashMap<String, String>,
}

impl IdentityCache {
    pub fn resolve(&mut self, frame: &WifiFrame) -> Option<ResolvedIdentity> {
        if let Some(username) = frame.username_hint.clone() {
            if let Some(mac) = frame.source_mac.as_ref() {
                self.mac_to_username
                    .insert(mac.to_ascii_lowercase(), username.clone());
            }
            return Some(ResolvedIdentity {
                username,
                source: frame
                    .identity_source_hint
                    .clone()
                    .unwrap_or_else(|| "observed_identity".to_string()),
            });
        }

        for candidate in [frame.source_mac.as_ref(), frame.destination_mac.as_ref()] {
            let Some(candidate) = candidate else {
                continue;
            };
            let key = candidate.to_ascii_lowercase();
            if let Some(username) = self.mac_to_username.get(&key) {
                return Some(ResolvedIdentity {
                    username: username.clone(),
                    source: "eap_identity_cache".to_string(),
                });
            }
        }

        None
    }
}

pub fn decode_frame(packet: &RawPacket) -> Result<WifiFrame, ParseError> {
    let (signal_dbm, frame_bytes) = strip_radiotap(&packet.data)?;
    if frame_bytes.len() < 24 {
        return Err(ParseError::MissingFrameHeader);
    }

    let frame_control = u16::from_le_bytes([frame_bytes[0], frame_bytes[1]]);
    let frame_type = ((frame_control >> 2) & 0x3) as u8;
    if frame_type == 1 {
        return Err(ParseError::UnsupportedControlFrame);
    }
    if !matches!(frame_type, 0 | 2) {
        return Err(ParseError::Invalid80211);
    }

    let _validated = GenericFrame::new(frame_bytes, false).map_err(|_| ParseError::Invalid80211)?;

    let subtype = ((frame_control >> 4) & 0x0f) as u8;
    let frame_subtype = frame_subtype_name(frame_type, subtype).to_string();
    let (bssid, source_mac, destination_mac) = parse_addresses(frame_type, frame_control, frame_bytes)?;
    let sequence_number = Some(u16::from_le_bytes([frame_bytes[22], frame_bytes[23]]) >> 4);
    let ssid = extract_ssid(frame_type, subtype, frame_bytes);
    let username_hint = extract_eap_identity(frame_type, frame_control, subtype, frame_bytes);
    let identity_source_hint = username_hint
        .as_ref()
        .map(|_| "eap_identity".to_string());

    let mut tags = vec![
        "wifi".to_string(),
        frame_type_name(frame_type).to_string(),
        format!("frame_type:{}", frame_type_name(frame_type)),
    ];
    if frame_type == 2 {
        tags.push(data_direction_tag(frame_control).to_string());
    }
    if frame_control & (1 << 11) != 0 {
        tags.push("retry".to_string());
    }
    if frame_control & (1 << 14) != 0 {
        tags.push("protected".to_string());
    }
    if let (Some(src), Some(dst)) = (source_mac.as_ref(), destination_mac.as_ref()) {
        tags.push(format!("flow:{src}>{dst}"));
    }
    if username_hint.is_some() {
        tags.push("eapol".to_string());
        tags.push("identity:eap_response".to_string());
    }

    Ok(WifiFrame {
        observed_at: packet.observed_at,
        event_type: match frame_type {
            0 => "wifi_management_frame".to_string(),
            2 => "wifi_data_frame".to_string(),
            _ => "wifi_frame".to_string(),
        },
        bssid,
        source_mac,
        destination_mac,
        ssid,
        frame_subtype,
        signal_dbm,
        sequence_number,
        raw_len: frame_bytes.len(),
        tags,
        username_hint,
        identity_source_hint,
    })
}

pub fn attach_context(frame: WifiFrame, context: &AuditContext) -> EnrichedFrame {
    EnrichedFrame {
        sensor_id: context.sensor_id.clone(),
        location_id: context.location_id.clone(),
        interface: context.interface.clone(),
        channel: context.channel,
        reg_domain: context.reg_domain.clone(),
        frame,
    }
}

pub fn to_audit_entry(enriched: EnrichedFrame) -> AuditEntry {
    let frame = enriched.frame;
    let mut tags = frame.tags;
    tags.push(format!("channel:{}", enriched.channel));
    tags.push(format!("reg_domain:{}", enriched.reg_domain));
    let username = frame.username_hint;
    let identity_source = match (username.as_ref(), frame.identity_source_hint) {
        (Some(_), Some(source)) => source,
        (Some(_), None) => "observed_identity".to_string(),
        (None, _) => "unknown".to_string(),
    };

    AuditEntry {
        event_type: frame.event_type,
        observed_at: frame.observed_at.to_rfc3339(),
        sensor_id: enriched.sensor_id,
        location_id: enriched.location_id,
        interface: enriched.interface,
        channel: enriched.channel,
        bssid: frame.bssid,
        source_mac: frame.source_mac,
        destination_mac: frame.destination_mac,
        ssid: frame.ssid,
        frame_subtype: frame.frame_subtype,
        signal_dbm: frame.signal_dbm,
        sequence_number: frame.sequence_number,
        raw_len: frame.raw_len,
        tags,
        device_id: None,
        username,
        identity_source,
    }
}

pub fn strip_radiotap(bytes: &[u8]) -> Result<(Option<i8>, &[u8]), ParseError> {
    if bytes.len() < 8 {
        return Err(ParseError::MissingRadiotap);
    }

    let length = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if length > bytes.len() {
        return Err(ParseError::MissingRadiotap);
    }

    let mut offset = 4usize;
    let mut present_words = Vec::new();
    loop {
        if offset + 4 > bytes.len() {
            return Err(ParseError::MissingRadiotap);
        }
        let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        present_words.push(word);
        offset += 4;
        if word & (1 << 31) == 0 {
            break;
        }
    }

    let mut cursor = offset;
    let mut signal_dbm = None;
    let present = present_words.first().copied().unwrap_or_default();
    for bit in 0..15 {
        if present & (1 << bit) == 0 {
            continue;
        }
        let (align, size) = radiotap_field_layout(bit);
        cursor = align_offset(cursor, align);
        if cursor + size > length {
            break;
        }
        if bit == 5 {
            signal_dbm = Some(bytes[cursor] as i8);
        }
        cursor += size;
    }

    Ok((signal_dbm, &bytes[length..]))
}

fn parse_addresses(
    frame_type: u8,
    frame_control: u16,
    frame_bytes: &[u8],
) -> Result<(Option<String>, Option<String>, Option<String>), ParseError> {
    let addr1 = format_mac(&frame_bytes[4..10]);
    let addr2 = format_mac(&frame_bytes[10..16]);
    let addr3 = format_mac(&frame_bytes[16..22]);
    if frame_type == 0 {
        return Ok((Some(addr3), Some(addr2), Some(addr1)));
    }

    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;
    match (to_ds, from_ds) {
        (false, false) => Ok((Some(addr3), Some(addr2), Some(addr1))),
        (true, false) => Ok((Some(addr1), Some(addr2), Some(addr3))),
        (false, true) => Ok((Some(addr2), Some(addr3), Some(addr1))),
        (true, true) => {
            if frame_bytes.len() < 30 {
                return Err(ParseError::MissingFrameHeader);
            }
            let addr4 = format_mac(&frame_bytes[24..30]);
            Ok((None, Some(addr4), Some(addr3)))
        }
    }
}

fn radiotap_field_layout(bit: usize) -> (usize, usize) {
    match bit {
        0 => (8, 8),
        1 => (1, 1),
        2 => (1, 1),
        3 => (2, 4),
        4 => (2, 2),
        5 => (1, 1),
        6 => (1, 1),
        7 => (2, 2),
        8 => (2, 2),
        9 => (2, 2),
        10 => (1, 1),
        11 => (1, 1),
        12 => (1, 1),
        13 => (1, 1),
        14 => (2, 2),
        _ => (1, 0),
    }
}

fn align_offset(offset: usize, align: usize) -> usize {
    if align <= 1 {
        offset
    } else {
        (offset + (align - 1)) & !(align - 1)
    }
}

fn frame_type_name(frame_type: u8) -> &'static str {
    match frame_type {
        0 => "management",
        1 => "control",
        2 => "data",
        _ => "unknown",
    }
}

fn frame_subtype_name(frame_type: u8, subtype: u8) -> &'static str {
    match frame_type {
        0 => match subtype {
            0 => "association_request",
            1 => "association_response",
            4 => "probe_request",
            5 => "probe_response",
            8 => "beacon",
            10 => "disassociation",
            11 => "authentication",
            12 => "deauthentication",
            _ => "other_management",
        },
        2 => match subtype {
            0 => "data",
            4 => "null_data",
            8 => "qos_data",
            12 => "qos_null",
            _ => "other_data",
        },
        _ => "unknown",
    }
}

fn data_direction_tag(frame_control: u16) -> &'static str {
    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;
    match (to_ds, from_ds) {
        (false, false) => "direction:intra_bss",
        (true, false) => "direction:to_ds",
        (false, true) => "direction:from_ds",
        (true, true) => "direction:wds",
    }
}

fn extract_ssid(frame_type: u8, subtype: u8, frame_bytes: &[u8]) -> Option<String> {
    if frame_type != 0 {
        return None;
    }

    let body_offset = 24usize;
    let ie_offset = match subtype {
        8 | 5 => body_offset + 12,
        4 => body_offset,
        _ => return None,
    };
    if frame_bytes.len() <= ie_offset + 2 {
        return None;
    }
    let mut offset = ie_offset;
    while offset + 2 <= frame_bytes.len() {
        let element_id = frame_bytes[offset];
        let length = frame_bytes[offset + 1] as usize;
        offset += 2;
        if offset + length > frame_bytes.len() {
            return None;
        }
        if element_id == 0 {
            return String::from_utf8(frame_bytes[offset..offset + length].to_vec()).ok();
        }
        offset += length;
    }
    None
}

fn extract_eap_identity(
    frame_type: u8,
    frame_control: u16,
    subtype: u8,
    frame_bytes: &[u8],
) -> Option<String> {
    if frame_type != 2 {
        return None;
    }
    let payload_offset = data_payload_offset(frame_control, subtype, frame_bytes)?;
    let llc_prefix = frame_bytes.get(payload_offset..payload_offset + 8)?;
    if llc_prefix != LLC_SNAP_EAPOL_PREFIX {
        return None;
    }

    let eapol = frame_bytes.get(payload_offset + 8..)?;
    if eapol.len() < 4 {
        return None;
    }
    if eapol[1] != 0 {
        return None;
    }
    let eapol_len = u16::from_be_bytes([eapol[2], eapol[3]]) as usize;
    if eapol_len < 5 || eapol.len() < 4 + eapol_len {
        return None;
    }

    let eap = &eapol[4..4 + eapol_len];
    if eap[0] != 2 {
        return None;
    }
    let eap_packet_len = u16::from_be_bytes([eap[2], eap[3]]) as usize;
    if eap_packet_len < 5 || eap_packet_len > eap.len() {
        return None;
    }
    if eap[4] != 1 {
        return None;
    }

    normalize_identity(&eap[5..eap_packet_len])
}

fn data_payload_offset(frame_control: u16, subtype: u8, frame_bytes: &[u8]) -> Option<usize> {
    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;

    let mut offset = 24usize;
    if to_ds && from_ds {
        offset += 6;
    }

    if subtype & 0x08 != 0 {
        offset += 2;
        if frame_control & (1 << 15) != 0 {
            offset += 4;
        }
    }

    if frame_bytes.len() < offset {
        None
    } else {
        Some(offset)
    }
}

fn normalize_identity(bytes: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(bytes).ok()?;
    let value = value.trim_matches(char::from(0)).trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
pub mod tests {
    use chrono::Utc;
    use serde_json::Value;

    use super::*;
    use crate::model::AuditContext;

    const BROADCAST: [u8; 6] = [0xff; 6];
    const AP: [u8; 6] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
    const CLIENT: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    const DISTRIBUTION_DST: [u8; 6] = [0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

    #[test]
    fn strips_radiotap_and_extracts_signal() {
        let frame = beacon_radiotap_frame();
        let (signal, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(signal, Some(-42));
        assert!(payload.len() > 24);
    }

    #[test]
    fn parses_beacon_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: beacon_radiotap_frame(),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.frame_subtype, "beacon");
        assert_eq!(frame.ssid.as_deref(), Some("CorpWiFi"));
        assert_eq!(frame.destination_mac.as_deref(), Some("ff:ff:ff:ff:ff:ff"));
    }

    #[test]
    fn parses_probe_request_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: probe_request_radiotap_frame(),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.frame_subtype, "probe_request");
        assert_eq!(frame.ssid.as_deref(), Some("CorpWiFi"));
    }

    #[test]
    fn parses_probe_response_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: probe_response_radiotap_frame(),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.frame_subtype, "probe_response");
        assert_eq!(frame.ssid.as_deref(), Some("CorpWiFi"));
    }

    #[test]
    fn parses_data_frame_with_distribution_system_destination() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(vec![0xaa, 0xbb]),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.event_type, "wifi_data_frame");
        assert_eq!(frame.frame_subtype, "data");
        assert_eq!(frame.source_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(frame.destination_mac.as_deref(), Some("22:33:44:55:66:77"));
        assert_eq!(frame.bssid.as_deref(), Some("10:20:30:40:50:60"));
        assert!(frame.tags.contains(&"direction:to_ds".to_string()));
    }

    #[test]
    fn parses_eap_identity_and_resolves_username_cache() {
        let mut cache = IdentityCache::default();
        let identity_packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(eap_identity_payload("alice@corp.example")),
        };
        let identity_frame = decode_frame(&identity_packet).unwrap();
        assert_eq!(
            identity_frame.username_hint.as_deref(),
            Some("alice@corp.example")
        );
        assert!(identity_frame.tags.contains(&"eapol".to_string()));

        let resolved = cache.resolve(&identity_frame).unwrap();
        assert_eq!(resolved.username, "alice@corp.example");
        assert_eq!(resolved.source, "eap_identity");

        let followup_packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(vec![0x01, 0x02, 0x03]),
        };
        let followup_frame = decode_frame(&followup_packet).unwrap();
        let cached = cache.resolve(&followup_frame).unwrap();
        assert_eq!(cached.username, "alice@corp.example");
        assert_eq!(cached.source, "eap_identity_cache");
    }

    #[test]
    fn rejects_control_frames() {
        let mut bytes = beacon_radiotap_frame();
        bytes[10] = 0x84;
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: bytes,
        };
        assert!(matches!(
            decode_frame(&packet),
            Err(ParseError::UnsupportedControlFrame)
        ));
    }

    #[test]
    fn rejects_malformed_radiotap() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: vec![0, 0, 32, 0],
        };
        assert!(matches!(
            decode_frame(&packet),
            Err(ParseError::MissingRadiotap)
        ));
    }

    #[test]
    fn serializes_audit_entry() {
        let context = AuditContext {
            sensor_id: "00:11:22:33:44:55".to_string(),
            location_id: "North-Wing-Entry".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: beacon_radiotap_frame(),
        };
        let entry = to_audit_entry(attach_context(decode_frame(&packet).unwrap(), &context));
        let value = serde_json::to_value(entry).unwrap();
        assert_eq!(
            value["event_type"],
            Value::String("wifi_management_frame".to_string())
        );
        assert_eq!(value["channel"], Value::Number(6u64.into()));
        assert_eq!(value["username"], Value::Null);
    }

    pub fn beacon_radiotap_frame() -> Vec<u8> {
        build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body())
    }

    pub fn probe_request_radiotap_frame() -> Vec<u8> {
        build_frame(0x40, 0x00, BROADCAST, CLIENT, BROADCAST, None, ssid_ie())
    }

    pub fn probe_response_radiotap_frame() -> Vec<u8> {
        build_frame(0x50, 0x00, CLIENT, AP, AP, None, beacon_body())
    }

    fn data_to_distribution_radiotap_frame(payload: Vec<u8>) -> Vec<u8> {
        build_frame(0x08, 0x01, AP, CLIENT, DISTRIBUTION_DST, None, payload)
    }

    fn build_frame(
        frame_control_first: u8,
        frame_control_second: u8,
        addr1: [u8; 6],
        addr2: [u8; 6],
        addr3: [u8; 6],
        addr4: Option<[u8; 6]>,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut bytes = vec![
            0x00,
            0x00,
            0x0a,
            0x00,
            0x20,
            0x00,
            0x00,
            0x00,
            0xd6,
            0x00,
            frame_control_first,
            frame_control_second,
            0x00,
            0x00,
        ];
        bytes.extend_from_slice(&addr1);
        bytes.extend_from_slice(&addr2);
        bytes.extend_from_slice(&addr3);
        bytes.extend_from_slice(&[0x10, 0x00]);
        if let Some(addr4) = addr4 {
            bytes.extend_from_slice(&addr4);
        }
        bytes.extend_from_slice(&body);
        bytes
    }

    fn beacon_body() -> Vec<u8> {
        let mut body = vec![0; 8];
        body.extend_from_slice(&100u16.to_le_bytes());
        body.extend_from_slice(&0x0431u16.to_le_bytes());
        body.extend_from_slice(&ssid_ie());
        body
    }

    fn ssid_ie() -> Vec<u8> {
        let mut ie = vec![0x00, 0x08];
        ie.extend_from_slice(b"CorpWiFi");
        ie
    }

    fn eap_identity_payload(identity: &str) -> Vec<u8> {
        let identity_bytes = identity.as_bytes();
        let eap_len = 5 + identity_bytes.len();
        let mut eap = vec![0x02, 0x01];
        eap.extend_from_slice(&(eap_len as u16).to_be_bytes());
        eap.push(0x01);
        eap.extend_from_slice(identity_bytes);

        let mut payload = LLC_SNAP_EAPOL_PREFIX.to_vec();
        payload.push(0x02);
        payload.push(0x00);
        payload.extend_from_slice(&(eap.len() as u16).to_be_bytes());
        payload.extend_from_slice(&eap);
        payload
    }
}
