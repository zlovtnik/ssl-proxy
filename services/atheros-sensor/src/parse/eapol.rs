use crate::model::WifiFrame;

pub(super) const LLC_SNAP_EAPOL_PREFIX: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EapolKeyObservation {
    pub(super) message: u8,
    pub(super) bssid: String,
    pub(super) client_mac: String,
}

pub(super) fn extract_eap_identity(
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

pub(super) fn extract_eapol_key_message(
    frame_type: u8,
    frame_control: u16,
    subtype: u8,
    frame_bytes: &[u8],
) -> Option<u8> {
    if frame_type != 2 {
        return None;
    }
    let payload_offset = data_payload_offset(frame_control, subtype, frame_bytes)?;
    let llc_prefix = frame_bytes.get(payload_offset..payload_offset + 8)?;
    if llc_prefix != LLC_SNAP_EAPOL_PREFIX {
        return None;
    }

    let eapol = frame_bytes.get(payload_offset + 8..)?;
    if eapol.len() < 7 || eapol[1] != 3 {
        return None;
    }
    let eapol_len = u16::from_be_bytes([eapol[2], eapol[3]]) as usize;
    if eapol_len < 3 || eapol.len() < 4 + eapol_len {
        return None;
    }

    let key_info = u16::from_be_bytes([eapol[5], eapol[6]]);
    let ack = key_info & 0x0080 != 0;
    let mic = key_info & 0x0100 != 0;
    let install = key_info & 0x0040 != 0;
    let secure = key_info & 0x0200 != 0;
    match (ack, mic, install, secure) {
        (true, false, _, _) => Some(1),
        (false, true, false, false) => Some(2),
        (true, true, true, _) => Some(3),
        (false, true, false, true) => Some(4),
        _ => None,
    }
}

pub(super) fn eapol_key_observation(frame: &WifiFrame) -> Option<EapolKeyObservation> {
    let message = frame.eapol_key_message?;
    let bssid = frame.bssid.clone()?;
    let client_mac = if frame.to_ds && !frame.from_ds {
        frame.source_mac.clone()
    } else if frame.from_ds && !frame.to_ds {
        frame.destination_mac.clone()
    } else {
        frame
            .source_mac
            .clone()
            .or_else(|| frame.destination_mac.clone())
    }?;
    Some(EapolKeyObservation {
        message,
        bssid,
        client_mac,
    })
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
