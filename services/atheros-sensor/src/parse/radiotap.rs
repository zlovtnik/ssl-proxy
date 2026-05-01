//! Radiotap header parsing for 802.11 physical-layer metadata.
//!
//! strip_radiotap validates the radiotap header, walks the present-word bitmap to locate
//! each field, and returns a RadiotapMetadata alongside the remaining 802.11 frame bytes.
//!
//! [`RadiotapMetadata`]: physical-layer fields extracted from the radiotap header;
//! `signal_present` is `true` only when the radiotap present-word bit 5 (dBm signal) was
//! set, distinguishing a genuine zero-dBm reading from a stripped or absent signal field —
//! the `signal_status` string in `RfLayer` is derived from this flag.

use super::frame::ParseError;

/// Physical-layer metadata extracted from the radiotap header. The signal_present field is
/// distinct from signal_dbm.is_some(): it is set only when the RSSI field (bit 5) was actually
/// present in the radiotap header, not stripped by a driver. The signal_status string in
/// RfLayer is derived from this flag.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RadiotapMetadata {
    pub tsft: Option<u64>,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub frequency_mhz: Option<u16>,
    pub channel_flags: Option<u16>,
    pub data_rate_kbps: Option<u32>,
    pub antenna_id: Option<u8>,
    pub vht_known: Option<u16>,
    pub vht_flags: Option<u8>,
    pub vht_bandwidth: Option<u8>,
    pub he_data: Option<Vec<u8>>,
    pub signal_present: bool,
}

/// Walks the extended present-word bitmap (bit 31 set means another word follows) and
/// skips vendor namespace fields (bit 30) by reading the 2-byte length at offset +4.
/// Strips the radiotap header and returns extracted metadata alongside the remaining 802.11
/// frame bytes. Walks the extended present-word bitmap (bit 31 set means another word follows)
/// and skips vendor namespace fields (bit 30) by reading the 2-byte length at offset +4.
/// Returns a zero-copy borrow of the original slice.
pub fn strip_radiotap(bytes: &[u8]) -> Result<(RadiotapMetadata, &[u8]), ParseError> {
    if bytes.len() < 8 {
        return Err(ParseError::MissingRadiotap);
    }

    let length = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if length > bytes.len() {
        return Err(ParseError::MissingRadiotap);
    }

    let mut present_offset = 4usize;
    let mut present_words = Vec::new();
    loop {
        if present_offset + 4 > length {
            return Err(ParseError::MissingRadiotap);
        }
        let word = read_present_word(bytes, present_offset);
        present_words.push(word);
        present_offset += 4;
        if word & (1 << 31) == 0 {
            break;
        }
    }

    let metadata = parse_metadata(bytes, length, present_offset, &present_words)?;
    Ok((metadata, &bytes[length..]))
}

/// Dispatches each present-word bit to the corresponding field parser. Bit 28 (TLV namespace)
/// returns early rather than panicking, halting metadata parsing before variable-length fields.
fn parse_metadata(
    bytes: &[u8],
    length: usize,
    present_offset: usize,
    present_words: &[u32],
) -> Result<RadiotapMetadata, ParseError> {
    let mut cursor = present_offset;
    let mut metadata = RadiotapMetadata::default();
    for (word_index, word) in present_words.iter().copied().enumerate() {
        for bit in 0..31 {
            if word & (1 << bit) == 0 {
                continue;
            }
            let global_bit = word_index * 32 + bit;
            if global_bit == 30 {
                cursor = skip_vendor_namespace(bytes, length, cursor)?;
                continue;
            }
            let Some((align, size)) = field_layout(global_bit) else {
                return Ok(metadata);
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
                5 => {
                    metadata.signal_dbm = Some(bytes[cursor] as i8);
                    metadata.signal_present = true;
                }
                6 => metadata.noise_dbm = Some(bytes[cursor] as i8),
                11 => metadata.antenna_id = Some(bytes[cursor]),
                21 => {
                    metadata.vht_known =
                        Some(u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]));
                    metadata.vht_flags = Some(bytes[cursor + 2]);
                    metadata.vht_bandwidth = Some(bytes[cursor + 3]);
                }
                23 => metadata.he_data = Some(bytes[cursor..cursor + size].to_vec()),
                _ => {}
            }
            cursor += size;
        }
    }

    Ok(metadata)
}

fn skip_vendor_namespace(bytes: &[u8], length: usize, cursor: usize) -> Result<usize, ParseError> {
    if cursor + 6 > length {
        return Err(ParseError::MissingRadiotap);
    }
    let skip_len = u16::from_le_bytes([bytes[cursor + 4], bytes[cursor + 5]]) as usize;
    let next = cursor + 6 + skip_len;
    if next > length {
        return Err(ParseError::MissingRadiotap);
    }
    Ok(next)
}

fn read_present_word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// Returns (align, size) for each radiotap field bit. Returning None halts metadata parsing,
/// used for bit 28 (TLV namespace) to stop before variable-length fields.
fn field_layout(bit: usize) -> Option<(usize, usize)> {
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
        15 => Some((2, 2)),
        16 => Some((1, 1)),
        17 => Some((1, 1)),
        18 => Some((4, 8)),
        19 => Some((1, 3)),
        20 => Some((4, 8)),
        21 => Some((2, 12)),
        22 => Some((8, 12)),
        23 => Some((2, 12)),
        24 => Some((2, 12)),
        25 => Some((2, 6)),
        26 => Some((1, 1)),
        27 => Some((2, 4)),
        // 28 is a variable-length TLV namespace. Stop metadata parsing before it.
        28 => None,
        // 29 is the radiotap namespace marker and carries no field data.
        29 => Some((1, 0)),
        30 => Some((1, 0)),
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
