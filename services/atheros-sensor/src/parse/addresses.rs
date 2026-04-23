use super::frame::ParseError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MacAddresses {
    pub(super) bssid: Option<String>,
    pub(super) source_mac: Option<String>,
    pub(super) destination_mac: Option<String>,
    pub(super) transmitter_mac: Option<String>,
    pub(super) receiver_mac: Option<String>,
}

pub(super) fn parse_addresses(
    frame_type: u8,
    frame_control: u16,
    frame_bytes: &[u8],
) -> Result<MacAddresses, ParseError> {
    if frame_bytes.len() < 22 {
        return Err(ParseError::MissingFrameHeader);
    }

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

pub(super) fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
