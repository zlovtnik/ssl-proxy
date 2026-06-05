use std::{
    fmt,
    hash::{Hash, Hasher},
    num::NonZeroUsize,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetectorLimits {
    pub mac_state_capacity: usize,
    pub ssid_state_capacity: usize,
    pub session_state_capacity: usize,
    pub client_probe_ssid_capacity: usize,
    pub pipeline_workers: usize,
    pub pipeline_queue_capacity: usize,
}

impl Default for DetectorLimits {
    fn default() -> Self {
        Self {
            mac_state_capacity: 100_000,
            ssid_state_capacity: 16_384,
            session_state_capacity: 65_536,
            client_probe_ssid_capacity: 64,
            pipeline_workers: 1,
            pipeline_queue_capacity: 1_024,
        }
    }
}

impl DetectorLimits {
    pub fn clamp(self) -> Self {
        Self {
            mac_state_capacity: self.mac_state_capacity.max(1),
            ssid_state_capacity: self.ssid_state_capacity.max(1),
            session_state_capacity: self.session_state_capacity.max(1),
            client_probe_ssid_capacity: self.client_probe_ssid_capacity.max(1),
            pipeline_workers: self.pipeline_workers.max(1),
            pipeline_queue_capacity: self.pipeline_queue_capacity.max(1),
        }
    }

    pub fn mac_capacity(self) -> NonZeroUsize {
        nonzero(self.mac_state_capacity)
    }

    pub fn ssid_capacity(self) -> NonZeroUsize {
        nonzero(self.ssid_state_capacity)
    }

    pub fn session_capacity(self) -> NonZeroUsize {
        nonzero(self.session_state_capacity)
    }

    pub fn probe_ssid_capacity(self) -> usize {
        self.client_probe_ssid_capacity.max(1)
    }
}

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value.max(1)).expect("capacity is clamped to non-zero")
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub fn parse(value: &str) -> Option<Self> {
        let mut bytes = [0u8; 6];
        let mut high_nibble: Option<u8> = None;
        let mut byte_index = 0usize;

        for raw in value.as_bytes().iter().copied() {
            let Some(nibble) = hex_value(raw) else {
                if matches!(raw, b':' | b'-' | b'.' | b' ' | b'\t' | b'\n' | b'\r') {
                    continue;
                }
                return None;
            };

            if let Some(high) = high_nibble.take() {
                if byte_index >= bytes.len() {
                    return None;
                }
                bytes[byte_index] = (high << 4) | nibble;
                byte_index += 1;
            } else {
                high_nibble = Some(nibble);
            }
        }

        if high_nibble.is_some() || byte_index != bytes.len() {
            return None;
        }

        Some(Self(bytes))
    }

    pub fn bytes(self) -> [u8; 6] {
        self.0
    }

    pub fn oui(self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Hash for MacAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsidKey(Box<str>);

impl SsidKey {
    pub fn new(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }
        Some(Self(normalized.into_boxed_str()))
    }
}

impl fmt::Display for SsidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum FrameSubtype {
    AssociationRequest,
    ReassociationRequest,
    Authentication,
    Deauthentication,
    Disassociation,
    Beacon,
    ProbeRequest,
    ProbeResponse,
    Other(Box<str>),
}

impl FrameSubtype {
    pub fn parse(value: &str) -> Self {
        match value {
            "association_request" => Self::AssociationRequest,
            "reassociation_request" => Self::ReassociationRequest,
            "authentication" => Self::Authentication,
            "deauthentication" => Self::Deauthentication,
            "disassociation" => Self::Disassociation,
            "beacon" => Self::Beacon,
            "probe_request" => Self::ProbeRequest,
            "probe_response" => Self::ProbeResponse,
            other => Self::Other(other.into()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::AssociationRequest => "association_request",
            Self::ReassociationRequest => "reassociation_request",
            Self::Authentication => "authentication",
            Self::Deauthentication => "deauthentication",
            Self::Disassociation => "disassociation",
            Self::Beacon => "beacon",
            Self::ProbeRequest => "probe_request",
            Self::ProbeResponse => "probe_response",
            Self::Other(value) => value,
        }
    }

    pub fn token(&self) -> String {
        self.as_str().replace('-', "_").to_ascii_uppercase()
    }

    pub fn is_ap_observation(&self) -> bool {
        matches!(self, Self::Beacon | Self::ProbeResponse)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DetectorRouteKey {
    Ap(MacAddr),
    Client(MacAddr),
    Session(u64),
    Ssid(u64),
    Unknown,
}

#[derive(Clone, Debug)]
pub struct DetectorRouter {
    lanes: usize,
    queue_capacity: usize,
}

impl DetectorRouter {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            lanes: limits.pipeline_workers,
            queue_capacity: limits.pipeline_queue_capacity,
        }
    }

    pub fn lanes(&self) -> usize {
        self.lanes
    }

    pub fn queue_capacity(&self) -> usize {
        self.queue_capacity
    }

    pub fn lane_for(&self, key: DetectorRouteKey) -> usize {
        if self.lanes <= 1 {
            return 0;
        }
        let hash = match key {
            DetectorRouteKey::Ap(mac) | DetectorRouteKey::Client(mac) => hash_u64(&mac.bytes()),
            DetectorRouteKey::Session(hash) | DetectorRouteKey::Ssid(hash) => hash,
            DetectorRouteKey::Unknown => 0,
        };
        (hash as usize) % self.lanes
    }
}

pub fn stable_hash(value: &str) -> u64 {
    hash_u64(value.as_bytes())
}

fn hash_u64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn mac_addr_parses_common_formats_and_renders_canonical() {
        for input in [
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "aabb.ccdd.eeff",
            "aabbccddeeff",
        ] {
            let mac = MacAddr::parse(input).expect("valid mac");
            assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
            assert_eq!(mac.oui(), [0xaa, 0xbb, 0xcc]);
        }
    }

    #[test]
    fn mac_addr_rejects_malformed_values() {
        assert!(MacAddr::parse("aa:bb:cc").is_none());
        assert!(MacAddr::parse("aa:bb:cc:dd:ee:gg").is_none());
        assert!(MacAddr::parse("aa:bb:cc:dd:ee:ff:00").is_none());
    }

    #[test]
    fn ssid_key_normalizes_for_hashing() {
        let left = SsidKey::new(" CorpWiFi ").unwrap();
        let right = SsidKey::new("corpwifi").unwrap();
        let mut keys = HashSet::new();
        keys.insert(left);
        keys.insert(right);

        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn detector_router_keeps_same_key_on_same_lane() {
        let router = DetectorRouter::new(DetectorLimits {
            pipeline_workers: 8,
            ..DetectorLimits::default()
        });
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        assert_eq!(
            router.lane_for(DetectorRouteKey::Ap(mac)),
            router.lane_for(DetectorRouteKey::Ap(mac))
        );
        assert!(router.lane_for(DetectorRouteKey::Ap(mac)) < router.lanes());
    }
}
