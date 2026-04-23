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
            let (align, size) = field_layout(global_bit)
                .ok_or(ParseError::UnsupportedRadiotapField { bit: global_bit })?;
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
