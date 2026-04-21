use ieee80211::GenericFrame;
use thiserror::Error;

use crate::model::{AuditContext, AuditEntry, EnrichedFrame, RawPacket, WifiFrame};

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("frame too short for radiotap header")]
    MissingRadiotap,
    #[error("frame too short for 802.11 management header")]
    MissingManagementHeader,
    #[error("unsupported non-management frame")]
    NonManagementFrame,
    #[error("ieee80211 parser rejected frame")]
    Invalid80211,
}

pub fn decode_frame(packet: &RawPacket) -> Result<WifiFrame, ParseError> {
    let (signal_dbm, frame_bytes) = strip_radiotap(&packet.data)?;
    if frame_bytes.len() < 24 {
        return Err(ParseError::MissingManagementHeader);
    }
    let _validated = GenericFrame::new(frame_bytes, false).map_err(|_| ParseError::Invalid80211)?;

    let frame_control = u16::from_le_bytes([frame_bytes[0], frame_bytes[1]]);
    let frame_type = (frame_control >> 2) & 0x3;
    if frame_type != 0 {
        return Err(ParseError::NonManagementFrame);
    }

    let subtype = ((frame_control >> 4) & 0x0f) as u8;
    let frame_subtype = subtype_name(subtype).to_string();
    let destination_mac = Some(format_mac(&frame_bytes[4..10]));
    let source_mac = Some(format_mac(&frame_bytes[10..16]));
    let bssid = Some(format_mac(&frame_bytes[16..22]));
    let sequence_number = Some(u16::from_le_bytes([frame_bytes[22], frame_bytes[23]]) >> 4);
    let ssid = extract_ssid(subtype, frame_bytes);

    Ok(WifiFrame {
        observed_at: packet.observed_at,
        bssid,
        source_mac,
        destination_mac,
        ssid,
        frame_subtype,
        signal_dbm,
        sequence_number,
        raw_len: frame_bytes.len(),
        tags: vec!["wifi".to_string(), "management".to_string()],
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
    let mut tags = enriched.frame.tags.clone();
    tags.push(format!("channel:{}", enriched.channel));
    tags.push(format!("reg_domain:{}", enriched.reg_domain));

    AuditEntry {
        event_type: "wifi_management_frame".to_string(),
        observed_at: enriched.frame.observed_at.to_rfc3339(),
        sensor_id: enriched.sensor_id,
        location_id: enriched.location_id,
        interface: enriched.interface,
        channel: enriched.channel,
        bssid: enriched.frame.bssid,
        source_mac: enriched.frame.source_mac,
        destination_mac: enriched.frame.destination_mac,
        ssid: enriched.frame.ssid,
        frame_subtype: enriched.frame.frame_subtype,
        signal_dbm: enriched.frame.signal_dbm,
        sequence_number: enriched.frame.sequence_number,
        raw_len: enriched.frame.raw_len,
        tags,
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

fn subtype_name(subtype: u8) -> &'static str {
    match subtype {
        0 => "association_request",
        1 => "association_response",
        4 => "probe_request",
        5 => "probe_response",
        8 => "beacon",
        10 => "disassociation",
        11 => "authentication",
        12 => "deauthentication",
        _ => "other_management",
    }
}

fn extract_ssid(subtype: u8, frame_bytes: &[u8]) -> Option<String> {
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
    fn rejects_non_management_frames() {
        let mut bytes = beacon_radiotap_frame();
        bytes[10] = 0x08;
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: bytes,
        };
        assert!(matches!(decode_frame(&packet), Err(ParseError::NonManagementFrame)));
    }

    #[test]
    fn rejects_malformed_radiotap() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: vec![0, 0, 32, 0],
        };
        assert!(matches!(decode_frame(&packet), Err(ParseError::MissingRadiotap)));
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
        assert_eq!(value["event_type"], Value::String("wifi_management_frame".to_string()));
        assert_eq!(value["channel"], Value::Number(6u64.into()));
    }

    pub fn beacon_radiotap_frame() -> Vec<u8> {
        build_frame(0x80, beacon_body())
    }

    pub fn probe_request_radiotap_frame() -> Vec<u8> {
        build_frame(0x40, ssid_ie())
    }

    pub fn probe_response_radiotap_frame() -> Vec<u8> {
        build_frame(0x50, beacon_body())
    }

    fn build_frame(frame_control_first: u8, body: Vec<u8>) -> Vec<u8> {
        let mut bytes = vec![
            0x00, 0x00, 0x0a, 0x00, 0x20, 0x00, 0x00, 0x00, 0xd6, 0x00, frame_control_first, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x10, 0x00,
        ];
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
}
