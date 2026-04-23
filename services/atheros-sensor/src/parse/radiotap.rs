use super::frame::ParseError;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RadiotapMetadata {
    pub tsft: Option<u64>,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub frequency_mhz: Option<u16>,
    pub channel_flags: Option<u16>,
    pub data_rate_kbps: Option<u32>,
    pub antenna_id: Option<u8>,
    pub signal_present: bool,
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
                _ => {}
            }
            cursor += size;
        }
    }

    Ok(metadata)
}

fn read_present_word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

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
        // 30 is a vendor namespace with a variable skip length. Stop before it.
        30 => None,
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
