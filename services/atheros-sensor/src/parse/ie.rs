const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const WPS_ATTR_DEVICE_NAME: u16 = 0x1011;
const WPS_ATTR_MANUFACTURER: u16 = 0x1021;
const WPS_ATTR_MODEL_NAME: u16 = 0x1023;

pub const SECURITY_WPA: u32 = 0x01;
pub const SECURITY_RSN_WPA2: u32 = 0x02;
pub const SECURITY_WPA3: u32 = 0x04;
pub const SECURITY_WPS: u32 = 0x08;
pub const SECURITY_PMF_REQUIRED: u32 = 0x10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InformationElement<'a> {
    pub id: u8,
    pub len: usize,
    pub data: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct IEIterator<'a> {
    frame: &'a [u8],
    offset: usize,
}

impl<'a> IEIterator<'a> {
    pub fn new(frame: &'a [u8], ie_start: usize) -> Self {
        Self {
            frame,
            offset: ie_start.min(frame.len()),
        }
    }
}

impl<'a> Iterator for IEIterator<'a> {
    type Item = InformationElement<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + 2 > self.frame.len() {
            return None;
        }

        let id = self.frame[self.offset];
        let len = self.frame[self.offset + 1] as usize;
        self.offset += 2;
        if self.offset + len > self.frame.len() {
            self.offset = self.frame.len();
            return None;
        }

        let data = &self.frame[self.offset..self.offset + len];
        self.offset += len;
        Some(InformationElement { id, len, data })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct IEMetadata {
    pub(super) security_flags: u32,
    pub(super) wps_device_name: Option<String>,
    pub(super) wps_manufacturer: Option<String>,
    pub(super) wps_model_name: Option<String>,
    pub(super) device_fingerprint: Option<String>,
}

fn ie_start_offset(frame_type: u8, subtype: u8) -> Option<usize> {
    if frame_type != 0 {
        return None;
    }

    let body_offset = 24usize;
    match subtype {
        0 => Some(body_offset + 4),
        4 => Some(body_offset),
        5 | 8 => Some(body_offset + 12),
        _ => None,
    }
}

pub(super) fn extract_ssid(frame_type: u8, subtype: u8, frame_bytes: &[u8]) -> Option<String> {
    let ie_offset = ie_start_offset(frame_type, subtype)?;
    IEIterator::new(frame_bytes, ie_offset)
        .find(|element| element.id == 0)
        .and_then(|element| String::from_utf8(element.data.to_vec()).ok())
}

pub(super) fn extract_ie_metadata(frame_type: u8, subtype: u8, frame_bytes: &[u8]) -> IEMetadata {
    let Some(ie_offset) = ie_start_offset(frame_type, subtype) else {
        return IEMetadata::default();
    };

    let mut metadata = IEMetadata::default();
    let mut fingerprint = FNV_OFFSET_BASIS;
    let mut saw_ie = false;
    for element in IEIterator::new(frame_bytes, ie_offset) {
        saw_ie = true;
        fingerprint ^= u64::from(element.id);
        fingerprint = fingerprint.wrapping_mul(FNV_PRIME);

        match element.id {
            48 => parse_rsn(element.data, &mut metadata),
            221 => parse_vendor_ie(element.data, &mut metadata),
            _ => {}
        }
    }

    if saw_ie {
        metadata.device_fingerprint = Some(format!("{fingerprint:016x}"));
    }
    metadata
}

fn parse_rsn(data: &[u8], metadata: &mut IEMetadata) {
    metadata.security_flags |= SECURITY_RSN_WPA2;
    if data.len() < 8 {
        return;
    }

    let mut offset = 2usize;
    offset += 4;
    if offset + 2 > data.len() {
        return;
    }
    let pairwise_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + pairwise_count.saturating_mul(4);
    if offset + 2 > data.len() {
        return;
    }
    let akm_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    for _ in 0..akm_count {
        if offset + 4 > data.len() {
            return;
        }
        if data[offset..offset + 3] == [0x00, 0x0f, 0xac] && matches!(data[offset + 3], 8 | 9) {
            metadata.security_flags |= SECURITY_WPA3;
        }
        offset += 4;
    }
    if offset + 2 <= data.len() {
        let capabilities = u16::from_le_bytes([data[offset], data[offset + 1]]);
        if capabilities & 0x0040 != 0 {
            metadata.security_flags |= SECURITY_PMF_REQUIRED;
        }
    }
}

fn parse_vendor_ie(data: &[u8], metadata: &mut IEMetadata) {
    if data.len() < 4 || data[..3] != [0x00, 0x50, 0xf2] {
        return;
    }

    match data[3] {
        1 => metadata.security_flags |= SECURITY_WPA,
        4 => {
            metadata.security_flags |= SECURITY_WPS;
            parse_wps_attributes(&data[4..], metadata);
        }
        _ => {}
    }
}

fn parse_wps_attributes(mut data: &[u8], metadata: &mut IEMetadata) {
    while data.len() >= 4 {
        let attr = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        data = &data[4..];
        if len > data.len() {
            break;
        }
        let value = &data[..len];
        match attr {
            WPS_ATTR_DEVICE_NAME => metadata.wps_device_name = parse_wps_string(value),
            WPS_ATTR_MANUFACTURER => metadata.wps_manufacturer = parse_wps_string(value),
            WPS_ATTR_MODEL_NAME => metadata.wps_model_name = parse_wps_string(value),
            _ => {}
        }
        data = &data[len..];
    }
}

fn parse_wps_string(value: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(value)
        .ok()?
        .trim_matches(char::from(0))
        .trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
