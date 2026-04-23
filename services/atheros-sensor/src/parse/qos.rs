use crate::model::QosLayer;

pub(super) fn parse_qos_control(
    frame_type: u8,
    subtype: u8,
    frame_control: u16,
    frame_bytes: &[u8],
) -> Option<QosLayer> {
    if frame_type != 2 || subtype & 0x08 == 0 {
        return None;
    }

    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;
    let mut offset = 24usize;
    if to_ds && from_ds {
        offset += 6;
    }
    let bytes = frame_bytes.get(offset..offset + 2)?;
    let qos_control = u16::from_le_bytes([bytes[0], bytes[1]]);
    let ack_policy = ((qos_control >> 5) & 0x03) as u8;

    Some(QosLayer {
        tid: (qos_control & 0x0f) as u8,
        eosp: qos_control & 0x10 != 0,
        ack_policy,
        ack_policy_label: ack_policy_label(ack_policy).to_string(),
        amsdu: qos_control & 0x80 != 0,
    })
}

fn ack_policy_label(policy: u8) -> &'static str {
    match policy {
        0 => "normal",
        1 => "no_ack",
        2 => "no_explicit_ack",
        3 => "block_ack",
        _ => "unknown",
    }
}
