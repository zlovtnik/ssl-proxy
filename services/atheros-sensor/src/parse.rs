use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use ieee80211::GenericFrame;
use lru::LruCache;
use thiserror::Error;

use base64::{engine::general_purpose::STANDARD, Engine};

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
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RadiotapMetadata {
    pub tsft: Option<u64>,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub frequency_mhz: Option<u16>,
    pub channel_flags: Option<u16>,
    pub data_rate_kbps: Option<u32>,
    pub antenna_id: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MacAddresses {
    bssid: Option<String>,
    source_mac: Option<String>,
    destination_mac: Option<String>,
    transmitter_mac: Option<String>,
    receiver_mac: Option<String>,
}

pub struct IdentityCache {
    mac_to_username: LruCache<String, String>,
    ssid_to_bssids: LruCache<String, Vec<String>>,
    deauth_counts: LruCache<String, (u32, Instant)>,
}

impl Default for IdentityCache {
    fn default() -> Self {
        Self {
            mac_to_username: LruCache::new(
                NonZeroUsize::new(4_096).expect("identity cache capacity must be non-zero"),
            ),
            ssid_to_bssids: LruCache::new(
                NonZeroUsize::new(4_096).expect("ssid cache capacity must be non-zero"),
            ),
            deauth_counts: LruCache::new(
                NonZeroUsize::new(4_096).expect("deauth cache capacity must be non-zero"),
            ),
        }
    }
}

impl IdentityCache {
    pub fn resolve(&mut self, frame: &WifiFrame) -> Option<ResolvedIdentity> {
        let mut threat_tags = Vec::new();
        let mut detection_identity = None;

        if matches!(frame.frame_subtype.as_str(), "beacon" | "probe_response") {
            if let (Some(ssid), Some(bssid)) = (frame.ssid.as_ref(), frame.bssid.as_ref()) {
                let known_key = ssid.to_ascii_lowercase();
                let bssid_key = bssid.to_ascii_lowercase();
                if let Some(known) = self.ssid_to_bssids.get_mut(&known_key) {
                    let already_seen = known
                        .iter()
                        .any(|known_bssid| known_bssid.eq_ignore_ascii_case(&bssid_key));
                    if !already_seen && !known.is_empty() {
                        push_tag(&mut threat_tags, "threat:potential_evil_twin");
                        detection_identity = Some(ResolvedIdentity {
                            username: format!("SUSPECT_EVIL_TWIN:{bssid}"),
                            source: "evil_twin_detection".to_string(),
                            tags: threat_tags.clone(),
                        });
                    }
                    if !already_seen {
                        known.push(bssid_key);
                    }
                } else {
                    self.ssid_to_bssids.put(known_key, vec![bssid_key]);
                }
            }
        }

        if matches!(
            frame.frame_subtype.as_str(),
            "deauthentication" | "disassociation"
        ) {
            if let Some(bssid) = frame.bssid.as_ref() {
                let bssid_key = bssid.to_ascii_lowercase();
                if let Some(entry) = self.deauth_counts.get_mut(&bssid_key) {
                    if entry.1.elapsed() > Duration::from_secs(10) {
                        *entry = (1, Instant::now());
                    } else {
                        entry.0 += 1;
                        if entry.0 > 5 {
                            push_tag(&mut threat_tags, "threat:deauth_flood");
                            detection_identity = Some(ResolvedIdentity {
                                username: format!("SUSPECT_DEAUTH_FLOOD:{bssid}"),
                                source: "deauth_flood_detection".to_string(),
                                tags: threat_tags.clone(),
                            });
                        }
                    }
                } else {
                    self.deauth_counts.put(bssid_key, (1, Instant::now()));
                }
            }
        }

        if let Some(username) = frame.username_hint.clone() {
            if let Some(mac) = frame.source_mac.as_ref() {
                self.mac_to_username
                    .put(mac.to_ascii_lowercase(), username.clone());
            }
            return Some(ResolvedIdentity {
                username,
                source: frame
                    .identity_source_hint
                    .clone()
                    .unwrap_or_else(|| "observed_identity".to_string()),
                tags: threat_tags,
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
                    tags: threat_tags,
                });
            }
        }

        detection_identity
    }
}

pub fn decode_frame(packet: &RawPacket) -> Result<WifiFrame, ParseError> {
    let (radiotap, frame_bytes) = strip_radiotap(&packet.data)?;
    if frame_bytes.len() < 24 {
        return Err(ParseError::MissingFrameHeader);
    }

    let frame_control = u16::from_le_bytes([frame_bytes[0], frame_bytes[1]]);
    let duration_id = u16::from_le_bytes([frame_bytes[2], frame_bytes[3]]);
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
    let addresses = parse_addresses(frame_type, frame_control, frame_bytes)?;
    let sequence_number = Some(u16::from_le_bytes([frame_bytes[22], frame_bytes[23]]) >> 4);
    let ssid = extract_ssid(frame_type, subtype, frame_bytes);
    let username_hint = extract_eap_identity(frame_type, frame_control, subtype, frame_bytes);
    let identity_source_hint = username_hint.as_ref().map(|_| "eap_identity".to_string());
    let retry = frame_control & (1 << 11) != 0;
    let power_save = frame_control & (1 << 12) != 0;
    let protected = frame_control & (1 << 14) != 0;
    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;

    let mut tags = vec![
        "wifi".to_string(),
        frame_type_name(frame_type).to_string(),
        format!("frame_type:{}", frame_type_name(frame_type)),
    ];
    if frame_type == 2 {
        tags.push(data_direction_tag(frame_control).to_string());
    }
    if retry {
        tags.push("retry".to_string());
    }
    if power_save {
        tags.push("power_save".to_string());
    }
    if protected {
        tags.push("protected".to_string());
    }
    if let (Some(src), Some(dst)) = (
        addresses.source_mac.as_ref(),
        addresses.destination_mac.as_ref(),
    ) {
        tags.push(format!("flow:{src}>{dst}"));
    }
    if username_hint.is_some() {
        tags.push("eapol".to_string());
        tags.push("identity:eap_response".to_string());
    }
    if frame_subtype == "probe_response" {
        if let Some(dst) = addresses.destination_mac.as_deref() {
            if is_locally_administered_mac(dst) {
                push_tag(&mut tags, "threat:karma_probe_response");
                push_tag(&mut tags, "identity:randomized_mac");
            }
        }
    }

    Ok(WifiFrame {
        observed_at: packet.observed_at,
        event_type: match frame_type {
            0 => "wifi_management_frame".to_string(),
            2 => "wifi_data_frame".to_string(),
            _ => "wifi_frame".to_string(),
        },
        bssid: addresses.bssid,
        source_mac: addresses.source_mac,
        destination_mac: addresses.destination_mac,
        transmitter_mac: addresses.transmitter_mac,
        receiver_mac: addresses.receiver_mac,
        ssid,
        frame_subtype,
        tsft: radiotap.tsft,
        signal_dbm: radiotap.signal_dbm,
        noise_dbm: radiotap.noise_dbm,
        frequency_mhz: radiotap.frequency_mhz,
        channel_flags: radiotap.channel_flags,
        data_rate_kbps: radiotap.data_rate_kbps,
        antenna_id: radiotap.antenna_id,
        sequence_number,
        duration_id,
        retry,
        power_save,
        protected,
        to_ds,
        from_ds,
        raw_len: frame_bytes.len(),
        raw_frame: Some(STANDARD.encode(frame_bytes)),
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
        (None, _) if frame.source_mac.is_some() || frame.bssid.is_some() => {
            "mac_observed".to_string()
        }
        (None, _) => "unknown".to_string(),
    };
    if let Some(ssid) = frame.ssid.as_deref() {
        let ssid_lower = ssid.to_ascii_lowercase();
        if ssid_lower.contains("setup")
            || ssid_lower.contains("wifi")
            || ssid_lower.starts_with("spectrumsetup")
        {
            push_tag(&mut tags, "threat:potential_evil_twin");
        }
    }
    if frame.frame_subtype == "probe_response" {
        if let Some(dst) = frame.destination_mac.as_deref() {
            if is_locally_administered_mac(dst) {
                push_tag(&mut tags, "identity:randomized_mac_target");
            }
        }
    }
    if matches!(
        frame.frame_subtype.as_str(),
        "deauthentication" | "disassociation"
    ) {
        push_tag(&mut tags, "threat:deauth_frame");
    }
    if let Some(dbm) = frame.signal_dbm {
        let tier = match dbm {
            -50..=0 => "signal:strong",
            -70..=-51 => "signal:medium",
            -85..=-71 => "signal:weak",
            _ => "signal:very_weak",
        };
        push_tag(&mut tags, tier);
    }

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
        transmitter_mac: frame.transmitter_mac,
        receiver_mac: frame.receiver_mac,
        ssid: frame.ssid,
        frame_subtype: frame.frame_subtype,
        tsft: frame.tsft,
        signal_dbm: frame.signal_dbm,
        noise_dbm: frame.noise_dbm,
        frequency_mhz: frame.frequency_mhz,
        channel_flags: frame.channel_flags,
        data_rate_kbps: frame.data_rate_kbps,
        antenna_id: frame.antenna_id,
        sequence_number: frame.sequence_number,
        duration_id: Some(frame.duration_id),
        retry: Some(frame.retry),
        power_save: Some(frame.power_save),
        protected: Some(frame.protected),
        to_ds: Some(frame.to_ds),
        from_ds: Some(frame.from_ds),
        raw_len: frame.raw_len,
        raw_frame: frame.raw_frame,
        tags,
        device_id: None,
        username,
        identity_source,
    }
}

fn push_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|existing| existing == tag) {
        tags.push(tag.to_string());
    }
}

fn is_locally_administered_mac(mac: &str) -> bool {
    mac.get(..2)
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        .map(|octet| octet & 0x02 != 0)
        .unwrap_or(false)
}

pub fn strip_radiotap(bytes: &[u8]) -> Result<(RadiotapMetadata, &[u8]), ParseError> {
    if bytes.len() < 8 {
        return Err(ParseError::MissingRadiotap);
    }

    let length = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if length > bytes.len() {
        return Err(ParseError::MissingRadiotap);
    }

    let mut present_offset = 4usize;
    loop {
        if present_offset + 4 > length {
            return Err(ParseError::MissingRadiotap);
        }
        let word = read_present_word(bytes, present_offset);
        present_offset += 4;
        if word & (1 << 31) == 0 {
            break;
        }
    }

    let mut cursor = present_offset;
    let mut metadata = RadiotapMetadata::default();
    let mut word_offset = 4usize;
    let mut word_index = 0usize;
    loop {
        let word = read_present_word(bytes, word_offset);
        for bit in 0..31 {
            if word & (1 << bit) == 0 {
                continue;
            }
            let global_bit = word_index * 32 + bit;
            let Some((align, size)) = radiotap_field_layout(global_bit) else {
                continue;
            };
            cursor = align_offset(cursor, align);
            if cursor + size > length {
                return Err(ParseError::MissingRadiotap);
            }
            match global_bit {
                0 => {
                    metadata.tsft = Some(u64::from_le_bytes(
                        bytes[cursor..cursor + 8].try_into().unwrap(),
                    ));
                }
                2 => metadata.data_rate_kbps = Some(u32::from(bytes[cursor]) * 500),
                3 => {
                    metadata.frequency_mhz =
                        Some(u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]));
                    metadata.channel_flags =
                        Some(u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]));
                }
                5 => metadata.signal_dbm = Some(bytes[cursor] as i8),
                6 => metadata.noise_dbm = Some(bytes[cursor] as i8),
                11 => metadata.antenna_id = Some(bytes[cursor]),
                _ => {}
            }
            cursor += size;
        }
        if word & (1 << 31) == 0 {
            break;
        }
        word_offset += 4;
        word_index += 1;
        if word_offset + 4 > present_offset {
            return Err(ParseError::MissingRadiotap);
        }
    }

    Ok((metadata, &bytes[length..]))
}

fn read_present_word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn parse_addresses(
    frame_type: u8,
    frame_control: u16,
    frame_bytes: &[u8],
) -> Result<MacAddresses, ParseError> {
    let addr1 = format_mac(&frame_bytes[4..10]);
    let addr2 = format_mac(&frame_bytes[10..16]);
    let addr3 = format_mac(&frame_bytes[16..22]);
    let receiver_mac = Some(addr1.clone());
    let transmitter_mac = Some(addr2.clone());
    if frame_type == 0 {
        return Ok(MacAddresses {
            bssid: Some(addr3),
            source_mac: Some(addr2),
            destination_mac: Some(addr1),
            transmitter_mac,
            receiver_mac,
        });
    }

    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;
    match (to_ds, from_ds) {
        (false, false) => Ok(MacAddresses {
            bssid: Some(addr3),
            source_mac: Some(addr2),
            destination_mac: Some(addr1),
            transmitter_mac,
            receiver_mac,
        }),
        (true, false) => Ok(MacAddresses {
            bssid: Some(addr1),
            source_mac: Some(addr2),
            destination_mac: Some(addr3),
            transmitter_mac,
            receiver_mac,
        }),
        (false, true) => Ok(MacAddresses {
            bssid: Some(addr2),
            source_mac: Some(addr3),
            destination_mac: Some(addr1),
            transmitter_mac,
            receiver_mac,
        }),
        (true, true) => {
            if frame_bytes.len() < 30 {
                return Err(ParseError::MissingFrameHeader);
            }
            let addr4 = format_mac(&frame_bytes[24..30]);
            Ok(MacAddresses {
                bssid: None,
                source_mac: Some(addr4),
                destination_mac: Some(addr3),
                transmitter_mac,
                receiver_mac,
            })
        }
    }
}

fn radiotap_field_layout(bit: usize) -> Option<(usize, usize)> {
    match bit {
        0 => Some((8, 8)),
        1 => Some((1, 1)),
        2 => Some((1, 1)),
        3 => Some((2, 4)),
        4 => Some((2, 2)),
        5 => Some((1, 1)),
        6 => Some((1, 1)),
        7 => Some((2, 2)),
        8 => Some((2, 2)),
        9 => Some((2, 2)),
        10 => Some((1, 1)),
        11 => Some((1, 1)),
        12 => Some((1, 1)),
        13 => Some((1, 1)),
        14 => Some((2, 2)),
        _ => None,
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
    const AP2: [u8; 6] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x61];
    const CLIENT: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    const DISTRIBUTION_DST: [u8; 6] = [0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

    #[test]
    fn strips_radiotap_and_extracts_signal() {
        let frame = beacon_radiotap_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert_eq!(metadata.noise_dbm, None);
        assert_eq!(metadata.frequency_mhz, None);
        assert_eq!(metadata.channel_flags, None);
        assert_eq!(metadata.data_rate_kbps, None);
        assert!(payload.len() > 24);
    }

    #[test]
    fn strips_radiotap_and_extracts_rf_metadata() {
        let frame = detailed_radiotap_beacon_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.tsft, None);
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert_eq!(metadata.noise_dbm, Some(-95));
        assert_eq!(metadata.frequency_mhz, Some(2437));
        assert_eq!(metadata.channel_flags, Some(0x00a0));
        assert_eq!(metadata.data_rate_kbps, Some(6_000));
        assert_eq!(metadata.antenna_id, None);
        assert!(payload.len() > 24);
    }

    #[test]
    fn strips_radiotap_and_extracts_tsft_and_antenna() {
        let frame = tsft_antenna_radiotap_beacon_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.tsft, Some(0x0102_0304_0506_0708));
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert_eq!(metadata.noise_dbm, Some(-95));
        assert_eq!(metadata.frequency_mhz, Some(2437));
        assert_eq!(metadata.channel_flags, Some(0x00a0));
        assert_eq!(metadata.data_rate_kbps, Some(6_000));
        assert_eq!(metadata.antenna_id, Some(3));
        assert!(payload.len() > 24);
    }

    #[test]
    fn strips_radiotap_with_extended_present_mask() {
        let frame = extended_mask_radiotap_beacon_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert!(payload.len() > 24);
    }

    #[test]
    fn parses_beacon_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: detailed_radiotap_beacon_frame(),
        };
        let (_, payload) = strip_radiotap(&packet.data).unwrap();
        let expected_raw_frame = STANDARD.encode(payload);
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.frame_subtype, "beacon");
        assert_eq!(frame.ssid.as_deref(), Some("CorpWiFi"));
        assert_eq!(frame.source_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(frame.destination_mac.as_deref(), Some("ff:ff:ff:ff:ff:ff"));
        assert_eq!(frame.transmitter_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(frame.receiver_mac.as_deref(), Some("ff:ff:ff:ff:ff:ff"));
        assert_eq!(frame.signal_dbm, Some(-42));
        assert_eq!(frame.noise_dbm, Some(-95));
        assert_eq!(frame.frequency_mhz, Some(2437));
        assert_eq!(frame.channel_flags, Some(0x00a0));
        assert_eq!(frame.data_rate_kbps, Some(6_000));
        assert_eq!(frame.raw_len, payload.len());
        assert_eq!(
            frame.raw_frame.as_deref(),
            Some(expected_raw_frame.as_str())
        );
    }

    #[test]
    fn parses_tsft_and_antenna_into_wifi_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: tsft_antenna_radiotap_beacon_frame(),
        };

        let frame = decode_frame(&packet).unwrap();

        assert_eq!(frame.tsft, Some(0x0102_0304_0506_0708));
        assert_eq!(frame.antenna_id, Some(3));
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
        assert!(frame
            .tags
            .contains(&"threat:karma_probe_response".to_string()));
        assert!(frame.tags.contains(&"identity:randomized_mac".to_string()));
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
        assert_eq!(frame.transmitter_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(frame.receiver_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert!(frame.to_ds);
        assert!(!frame.from_ds);
        assert!(frame.tags.contains(&"direction:to_ds".to_string()));
    }

    #[test]
    fn parses_data_frame_from_distribution_system() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: data_from_distribution_radiotap_frame(vec![0xaa, 0xbb]),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.source_mac.as_deref(), Some("22:33:44:55:66:77"));
        assert_eq!(frame.destination_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(frame.bssid.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(frame.transmitter_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(frame.receiver_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert!(!frame.to_ds);
        assert!(frame.from_ds);
        assert!(frame.tags.contains(&"direction:from_ds".to_string()));
    }

    #[test]
    fn parses_wds_address_roles() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: build_frame(
                0x08,
                0x03,
                AP,
                CLIENT,
                DISTRIBUTION_DST,
                Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                vec![0xaa, 0xbb],
            ),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.bssid, None);
        assert_eq!(frame.source_mac.as_deref(), Some("de:ad:be:ef:00:01"));
        assert_eq!(frame.destination_mac.as_deref(), Some("22:33:44:55:66:77"));
        assert_eq!(frame.transmitter_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(frame.receiver_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert!(frame.to_ds);
        assert!(frame.from_ds);
        assert!(frame.tags.contains(&"direction:wds".to_string()));
    }

    #[test]
    fn parses_frame_control_flags() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x08, 0x59, AP, CLIENT, DISTRIBUTION_DST, None, vec![0xaa]),
        };
        let frame = decode_frame(&packet).unwrap();
        assert!(frame.to_ds);
        assert!(!frame.from_ds);
        assert!(frame.retry);
        assert!(frame.power_save);
        assert!(frame.protected);
        assert_eq!(frame.duration_id, 0);
        assert!(frame.tags.contains(&"retry".to_string()));
        assert!(frame.tags.contains(&"power_save".to_string()));
        assert!(frame.tags.contains(&"protected".to_string()));
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

        let packet = RawPacket {
            observed_at: Utc::now(),
            data: vec![0, 0, 8, 0, 0x20, 0, 0, 0],
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
        let (_, payload) = strip_radiotap(&packet.data).unwrap();
        let expected_raw_frame = STANDARD.encode(payload);
        let entry = to_audit_entry(attach_context(decode_frame(&packet).unwrap(), &context));
        let value = serde_json::to_value(entry).unwrap();
        assert_eq!(
            value["event_type"],
            Value::String("wifi_management_frame".to_string())
        );
        assert_eq!(value["channel"], Value::Number(6u64.into()));
        assert_eq!(
            value["transmitter_mac"],
            Value::String("10:20:30:40:50:60".to_string())
        );
        assert_eq!(
            value["receiver_mac"],
            Value::String("ff:ff:ff:ff:ff:ff".to_string())
        );
        assert_eq!(value["signal_dbm"], Value::Number((-42).into()));
        assert_eq!(value["tsft"], Value::Null);
        assert_eq!(value["antenna_id"], Value::Null);
        assert_eq!(value["duration_id"], Value::Number(0u64.into()));
        assert_eq!(value["retry"], Value::Bool(false));
        assert_eq!(value["power_save"], Value::Bool(false));
        assert_eq!(value["protected"], Value::Bool(false));
        assert_eq!(value["to_ds"], Value::Bool(false));
        assert_eq!(value["from_ds"], Value::Bool(false));
        assert_eq!(value["raw_frame"], Value::String(expected_raw_frame));
        assert_eq!(value["username"], Value::Null);
        assert_eq!(
            value["identity_source"],
            Value::String("mac_observed".to_string())
        );
        assert!(value["device_id"].is_null());
        let tags = value["tags"].as_array().unwrap();
        assert!(tags.contains(&Value::String("signal:strong".to_string())));
        assert!(tags.contains(&Value::String("threat:potential_evil_twin".to_string())));
    }

    #[test]
    fn serializes_tsft_and_antenna_in_audit_entry() {
        let context = AuditContext {
            sensor_id: "00:11:22:33:44:55".to_string(),
            location_id: "North-Wing-Entry".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: tsft_antenna_radiotap_beacon_frame(),
        };
        let entry = to_audit_entry(attach_context(decode_frame(&packet).unwrap(), &context));
        let value = serde_json::to_value(entry).unwrap();

        assert_eq!(
            value["tsft"],
            Value::Number(0x0102_0304_0506_0708u64.into())
        );
        assert_eq!(value["antenna_id"], Value::Number(3u64.into()));
    }

    #[test]
    fn detects_new_bssid_for_known_ssid() {
        let mut cache = IdentityCache::default();
        let first = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: beacon_radiotap_frame(),
        })
        .unwrap();
        assert!(cache.resolve(&first).is_none());

        let second = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x80, 0x00, BROADCAST, AP2, AP2, None, beacon_body()),
        })
        .unwrap();
        let resolved = cache.resolve(&second).unwrap();
        assert_eq!(resolved.source, "evil_twin_detection");
        assert!(resolved
            .tags
            .contains(&"threat:potential_evil_twin".to_string()));
    }

    pub fn beacon_radiotap_frame() -> Vec<u8> {
        build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body())
    }

    fn detailed_radiotap_beacon_frame() -> Vec<u8> {
        let frame = build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body());
        let mut bytes = detailed_radiotap_header();
        bytes.extend_from_slice(&frame[10..]);
        bytes
    }

    fn tsft_antenna_radiotap_beacon_frame() -> Vec<u8> {
        let frame = build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body());
        let mut bytes = tsft_antenna_radiotap_header();
        bytes.extend_from_slice(&frame[10..]);
        bytes
    }

    fn extended_mask_radiotap_beacon_frame() -> Vec<u8> {
        let frame = build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body());
        let mut bytes = extended_mask_radiotap_header();
        bytes.extend_from_slice(&frame[10..]);
        bytes
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

    fn data_from_distribution_radiotap_frame(payload: Vec<u8>) -> Vec<u8> {
        build_frame(0x08, 0x02, CLIENT, AP, DISTRIBUTION_DST, None, payload)
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

    fn detailed_radiotap_header() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x10, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x85, 0x09, 0xa0, 0x00,
            0xd6, 0xa1,
        ]
    }

    fn tsft_antenna_radiotap_header() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x19, 0x00, 0x6d, 0x08, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01, 0x0c, 0x00, 0x85, 0x09, 0xa0, 0x00, 0xd6, 0xa1, 0x03,
        ]
    }

    fn extended_mask_radiotap_header() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xd6,
        ]
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
