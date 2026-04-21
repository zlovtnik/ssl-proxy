//! Shared WireGuard UDP packet obfuscation helpers.
//!
//! This module is intentionally separate from `obfuscation.rs`, which handles
//! HTTP header normalization. These helpers operate on raw WireGuard UDP
//! datagrams for the server relay and the Linux client shim.

/// Maximum supported UDP datagram size.
pub const MAX_UDP_PACKET_SIZE: usize = 65_535;

/// Shared packet obfuscation settings for WireGuard UDP transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgPacketObfuscation {
    pub key: Vec<u8>,
    pub magic_byte: Option<u8>,
}

impl WgPacketObfuscation {
    /// Construct packet obfuscation settings.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty.
    pub fn new(key: impl Into<Vec<u8>>, magic_byte: Option<u8>) -> Self {
        let key = key.into();
        assert!(!key.is_empty(), "obfuscation key must not be empty");
        Self { key, magic_byte }
    }
}

/// Failure modes when decoding an obfuscated WireGuard packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDecodeError {
    MagicByteMismatch,
    EmptyPayload,
}

/// Encode a plaintext WireGuard packet using XOR and an optional leading marker.
pub fn encode_packet(packet: &[u8], settings: &WgPacketObfuscation) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(packet.len() + usize::from(settings.magic_byte.is_some()));
    if let Some(magic_byte) = settings.magic_byte {
        encoded.push(magic_byte);
    }
    encoded.extend_from_slice(packet);

    let payload = if settings.magic_byte.is_some() {
        &mut encoded[1..]
    } else {
        &mut encoded[..]
    };
    apply_xor_mask(payload, &settings.key);
    encoded
}

/// Decode an obfuscated WireGuard packet back to plaintext.
pub fn decode_packet(
    packet: &[u8],
    settings: &WgPacketObfuscation,
) -> Result<Vec<u8>, PacketDecodeError> {
    let payload = if let Some(magic_byte) = settings.magic_byte {
        match packet.split_first() {
            Some((actual, payload)) if *actual == magic_byte => payload,
            _ => return Err(PacketDecodeError::MagicByteMismatch),
        }
    } else {
        packet
    };

    if payload.is_empty() {
        return Err(PacketDecodeError::EmptyPayload);
    }

    let mut decoded = payload.to_vec();
    apply_xor_mask(&mut decoded, &settings.key);
    Ok(decoded)
}

/// Parse a magic byte from decimal or `0xNN` input.
pub fn parse_magic_byte(raw: &str) -> Option<u8> {
    let trimmed = raw.trim();
    if let Some(value) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if value.is_empty() {
            return None;
        }
        u8::from_str_radix(value, 16).ok()
    } else {
        trimmed.parse::<u8>().ok()
    }
}

fn apply_xor_mask(packet: &mut [u8], key: &[u8]) {
    debug_assert!(!key.is_empty(), "obfuscation key must not be empty");
    for (index, byte) in packet.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_settings(magic_byte: Option<u8>) -> WgPacketObfuscation {
        WgPacketObfuscation::new(b"test-obfuscation-key".to_vec(), magic_byte)
    }

    #[test]
    fn xor_round_trips_without_magic_byte() {
        let settings = test_settings(None);
        let packet = b"wireguard-data-packet";

        let encoded = encode_packet(packet, &settings);
        assert_ne!(encoded, packet);

        let decoded = decode_packet(&encoded, &settings).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn xor_round_trips_with_magic_byte() {
        let settings = test_settings(Some(0xAA));
        let packet = b"wireguard-handshake-initiation";

        let encoded = encode_packet(packet, &settings);
        assert_eq!(encoded.first().copied(), Some(0xAA));
        assert_ne!(&encoded[1..], packet);

        let decoded = decode_packet(&encoded, &settings).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    #[should_panic(expected = "obfuscation key must not be empty")]
    fn constructor_rejects_empty_key() {
        let _ = WgPacketObfuscation::new(Vec::<u8>::new(), None);
    }

    #[test]
    fn decode_rejects_missing_magic_byte() {
        let settings = test_settings(Some(0xAA));

        assert_eq!(
            decode_packet(b"plain-wireguard", &settings),
            Err(PacketDecodeError::MagicByteMismatch)
        );
    }

    #[test]
    fn decode_rejects_empty_payload_after_magic_byte() {
        let settings = test_settings(Some(0xAA));

        assert_eq!(
            decode_packet(&[0xAA], &settings),
            Err(PacketDecodeError::EmptyPayload)
        );
    }

    #[test]
    fn parse_magic_byte_accepts_hex_and_decimal() {
        assert_eq!(parse_magic_byte("0xAA"), Some(0xAA));
        assert_eq!(parse_magic_byte("170"), Some(170));
    }

    #[test]
    fn parse_magic_byte_rejects_invalid_input() {
        assert_eq!(parse_magic_byte("0xGG"), None);
        assert_eq!(parse_magic_byte(""), None);
    }
}
