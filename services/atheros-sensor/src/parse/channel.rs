//! Frequency-to-channel conversion and channel flags decoding.
//!
//! frequency_to_channel maps radiotap frequency values to 802.11 channel numbers:
//! 2.4 GHz channels 1-13 via (freq - 2412) / 5 + 1, channel 14 at 2484 MHz,
//! and 5 GHz channels via (freq - 5000) / 5. decode_channel_flags unpacks the
//! radiotap channel flags bitmask into named booleans (2ghz, 5ghz, cck, ofdm,
//! dynamic_cck_ofdm) and a human-readable labels vec for the AuditEntry.

use crate::model::ChannelFlagsLayer;

/// Maps radiotap frequency values to 802.11 channel numbers. Covers three frequency bands:
/// 2.4 GHz channels 1-13 (2412-2472 MHz), channel 14 (2484 MHz), and 5 GHz channels
/// (5000-5895 MHz). 6 GHz (UNII-5 through UNII-8) is not yet mapped.
pub(super) fn frequency_to_channel(frequency_mhz: Option<u16>) -> Option<u16> {
    let frequency_mhz = frequency_mhz?;
    match frequency_mhz {
        2412..=2472 => Some(((frequency_mhz - 2412) / 5) + 1),
        2484 => Some(14),
        5000..=5895 => Some((frequency_mhz - 5000) / 5),
        _ => None,
    }
}

/// Decodes the radiotap channel flags bitmask into named booleans and a labels vector.
/// When the dynamic_cck_ofdm flag (bit 10, 0x0400) is set, both cck and ofdm are forced
/// to true regardless of their individual bits, overriding the standard flag interpretation.
pub(super) fn decode_channel_flags(raw: Option<u16>) -> Option<ChannelFlagsLayer> {
    let raw = raw?;
    let dynamic_cck_ofdm = raw & 0x0400 != 0;
    let mut labels = Vec::new();
    let is_2ghz = raw & 0x0080 != 0;
    let is_5ghz = raw & 0x0100 != 0;
    let mut cck = raw & 0x0020 != 0;
    let mut ofdm = raw & 0x0040 != 0;
    if dynamic_cck_ofdm {
        cck = true;
        ofdm = true;
    }
    if is_2ghz {
        labels.push("2ghz".to_string());
    }
    if is_5ghz {
        labels.push("5ghz".to_string());
    }
    if cck {
        labels.push("cck".to_string());
    }
    if ofdm {
        labels.push("ofdm".to_string());
    }
    if dynamic_cck_ofdm {
        labels.push("dynamic_cck_ofdm".to_string());
    }

    Some(ChannelFlagsLayer {
        raw,
        labels,
        is_2ghz,
        is_5ghz,
        ofdm,
        cck,
        dynamic_cck_ofdm,
    })
}
