use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum supported UDP datagram size.
pub const MAX_UDP_PACKET_SIZE: usize = 65_535;

const FRAME_VERSION: u8 = 1;
const FRAME_FLAG_AEAD: u8 = 0b0000_0001;
const FRAME_FLAG_PADDING: u8 = 0b0000_0010;
const FRAME_FLAG_REKEY: u8 = 0b0000_0100;
const FRAME_FLAG_RANDOMIZED_MAGIC: u8 = 0b0000_1000;
const FRAME_SALT_LEN: usize = 16;
const FRAME_COUNTER_LEN: usize = 8;
const FRAME_EPOCH_LEN: usize = 4;
const FRAME_MARKER_ZONE_LEN: usize = 8;
const FRAME_HEADER_LEN: usize =
    3 + FRAME_SALT_LEN + FRAME_COUNTER_LEN + FRAME_EPOCH_LEN + FRAME_MARKER_ZONE_LEN;
const AEAD_TAG_LEN: usize = 16;
const BODY_LEN_FIELD_LEN: usize = 2;

pub const FRAMED_HEADER_LEN: usize = FRAME_HEADER_LEN;
pub const FRAMED_BODY_LEN_FIELD_LEN: usize = BODY_LEN_FIELD_LEN;
pub const AEAD_TAG_LEN_BYTES: usize = AEAD_TAG_LEN;

/// Packet confidentiality/integrity mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EncryptionMode {
    /// XOR obfuscation.
    ///
    /// Legacy non-framed packets use the configured key directly as the XOR
    /// mask. Framed XOR packets derive the mask from the in-band frame salt,
    /// packet direction, and rekey epoch so framed mode has per-session key
    /// diversification even when no rekey policy is configured.
    #[default]
    Xor,
    Aead,
}

/// Optional framed packet padding policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PacketPadding {
    #[default]
    None,
    PowerOfTwo,
    FixedMtu(usize),
    RandomBucket(Vec<usize>),
}

/// Encoded datagram length bounds for a plaintext WireGuard UDP payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedPacketLenBounds {
    pub plaintext_len: usize,
    pub min_encoded_len: usize,
    pub max_encoded_len: usize,
    pub unpadded_encoded_len: usize,
}

impl EncodedPacketLenBounds {
    pub fn min_overhead_len(&self) -> usize {
        self.min_encoded_len.saturating_sub(self.plaintext_len)
    }

    pub fn max_overhead_len(&self) -> usize {
        self.max_encoded_len.saturating_sub(self.plaintext_len)
    }
}

/// Placement policy for the obfuscation marker in framed packets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MagicPositionMode {
    #[default]
    Fixed,
    Randomized,
}

/// Optional XOR re-keying schedule for framed XOR packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorRekeyPolicy {
    pub every_packets: Option<u64>,
    pub every_secs: Option<u64>,
}

impl XorRekeyPolicy {
    pub fn new(every_packets: Option<u64>, every_secs: Option<u64>) -> Option<Self> {
        let every_packets = every_packets.filter(|value| *value > 0);
        let every_secs = every_secs.filter(|value| *value > 0);
        (every_packets.is_some() || every_secs.is_some()).then_some(Self {
            every_packets,
            every_secs,
        })
    }
}

/// Shared packet obfuscation settings for WireGuard UDP transport.
#[derive(Clone, PartialEq, Eq)]
pub struct WgPacketObfuscation {
    pub key: Zeroizing<Vec<u8>>,
    pub magic_byte: Option<u8>,
    pub encryption_mode: EncryptionMode,
    pub padding: PacketPadding,
    pub magic_position: MagicPositionMode,
    pub xor_rekey: Option<XorRekeyPolicy>,
    pub replay_protection: bool,
}

impl std::fmt::Debug for WgPacketObfuscation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPacketObfuscation")
            .field("key", &"[REDACTED]")
            .field("magic_byte", &self.magic_byte)
            .field("encryption_mode", &self.encryption_mode)
            .field("padding", &self.padding)
            .field("magic_position", &self.magic_position)
            .field("xor_rekey", &self.xor_rekey)
            .field("replay_protection", &self.replay_protection)
            .finish()
    }
}

impl WgPacketObfuscation {
    /// Construct legacy-compatible packet obfuscation settings.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty.
    pub fn new(key: impl Into<Vec<u8>>, magic_byte: Option<u8>) -> Self {
        let key = key.into();
        assert!(!key.is_empty(), "obfuscation key must not be empty");
        Self {
            key: Zeroizing::new(key),
            magic_byte,
            encryption_mode: EncryptionMode::Xor,
            padding: PacketPadding::None,
            magic_position: MagicPositionMode::Fixed,
            xor_rekey: None,
            replay_protection: false,
        }
    }

    pub fn with_encryption_mode(mut self, mode: EncryptionMode) -> Self {
        self.encryption_mode = mode;
        if matches!(mode, EncryptionMode::Aead) {
            self.replay_protection = true;
        }
        self
    }

    pub fn with_padding(mut self, padding: PacketPadding) -> Self {
        self.padding = padding;
        self
    }

    pub fn with_magic_position(mut self, mode: MagicPositionMode) -> Self {
        self.magic_position = mode;
        self
    }

    pub fn with_xor_rekey(mut self, policy: Option<XorRekeyPolicy>) -> Self {
        self.xor_rekey = policy;
        self
    }

    pub fn with_replay_protection(mut self, enabled: bool) -> Self {
        self.replay_protection = enabled;
        self
    }

    pub fn uses_framed_encoding(&self) -> bool {
        !matches!(self.encryption_mode, EncryptionMode::Xor)
            || !matches!(&self.padding, PacketPadding::None)
            || !matches!(self.magic_position, MagicPositionMode::Fixed)
            || self.xor_rekey.is_some()
            || self.replay_protection
    }

    pub fn encoded_len_bounds(
        &self,
        packet_len: usize,
    ) -> Result<EncodedPacketLenBounds, PacketEncodeError> {
        encoded_packet_len_bounds(packet_len, self)
    }
}

/// Direction label used for framed key derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDirection {
    ClientToServer,
    ServerToClient,
    Bidirectional,
}

impl PacketDirection {
    fn as_label(self) -> &'static [u8] {
        match self {
            Self::ClientToServer => b"client_to_server",
            Self::ServerToClient => b"server_to_client",
            Self::Bidirectional => b"bidirectional",
        }
    }
}

/// Per-session encode state for framed packets.
///
/// The session salt is the only encoder state the decoder depends on. It is
/// written into every framed packet header, so a peer can decode the frame
/// without holding a matching `PacketEncodeState`.
#[derive(Debug)]
pub struct PacketEncodeState {
    session_salt: Zeroizing<[u8; FRAME_SALT_LEN]>,
    next_counter: AtomicU64,
    started_at_millis: u64,
}

impl PacketEncodeState {
    pub fn new(started_at_millis: u64) -> Self {
        let mut session_salt = [0u8; FRAME_SALT_LEN];
        OsRng.fill_bytes(&mut session_salt);
        Self {
            session_salt: Zeroizing::new(session_salt),
            next_counter: AtomicU64::new(0),
            started_at_millis,
        }
    }

    pub fn with_salt(session_salt: [u8; FRAME_SALT_LEN], started_at_millis: u64) -> Self {
        Self {
            session_salt: Zeroizing::new(session_salt),
            next_counter: AtomicU64::new(0),
            started_at_millis,
        }
    }

    pub fn session_salt(&self) -> [u8; FRAME_SALT_LEN] {
        *self.session_salt
    }

    fn next_packet_counter(&self) -> u64 {
        self.next_counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// Sliding replay window for framed packet counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

const _: () = assert!(u64::BITS == 64);

impl ReplayWindow {
    pub fn check_and_update(&mut self, counter: u64) -> Result<(), PacketDecodeError> {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.bitmap = 1;
            return Ok(());
        };

        if counter > highest {
            let shift = counter - highest;
            self.bitmap = self
                .bitmap
                .checked_shl(u32::try_from(shift).unwrap_or(u32::MAX))
                .map(|bitmap| bitmap | 1)
                .unwrap_or(1);
            self.highest = Some(counter);
            return Ok(());
        }

        let offset = highest - counter;
        if offset >= 64 {
            return Err(PacketDecodeError::ReplayDetected);
        }

        let bit = 1u64 << offset;
        if self.bitmap & bit != 0 {
            return Err(PacketDecodeError::ReplayDetected);
        }

        self.bitmap |= bit;
        Ok(())
    }
}

/// Failure modes when encoding an obfuscated WireGuard packet.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PacketEncodeError {
    #[error("packet length {packet_len} exceeds available buffer {buffer_len}")]
    PacketTooLarge {
        packet_len: usize,
        buffer_len: usize,
    },
    #[error("encoded packet length {encoded_len} exceeds available buffer {buffer_len}")]
    EncodedPacketTooLarge {
        encoded_len: usize,
        buffer_len: usize,
    },
    #[error("fixed MTU {mtu} is smaller than required encoded length {required}")]
    FixedMtuTooSmall { mtu: usize, required: usize },
    #[error("AEAD encryption failed")]
    AeadEncrypt,
}

pub fn encoded_packet_len_bounds(
    packet_len: usize,
    settings: &WgPacketObfuscation,
) -> Result<EncodedPacketLenBounds, PacketEncodeError> {
    if !settings.uses_framed_encoding() {
        let marker_len = usize::from(settings.magic_byte.is_some());
        let encoded_len =
            packet_len
                .checked_add(marker_len)
                .ok_or(PacketEncodeError::EncodedPacketTooLarge {
                    encoded_len: usize::MAX,
                    buffer_len: MAX_UDP_PACKET_SIZE,
                })?;
        if encoded_len > MAX_UDP_PACKET_SIZE {
            return Err(PacketEncodeError::EncodedPacketTooLarge {
                encoded_len,
                buffer_len: MAX_UDP_PACKET_SIZE,
            });
        }
        return Ok(EncodedPacketLenBounds {
            plaintext_len: packet_len,
            min_encoded_len: encoded_len,
            max_encoded_len: encoded_len,
            unpadded_encoded_len: encoded_len,
        });
    }

    if packet_len > u16::MAX as usize {
        return Err(PacketEncodeError::PacketTooLarge {
            packet_len,
            buffer_len: u16::MAX as usize,
        });
    }

    let tag_len = match settings.encryption_mode {
        EncryptionMode::Xor => 0,
        EncryptionMode::Aead => AEAD_TAG_LEN,
    };
    let body_base_len = BODY_LEN_FIELD_LEN + packet_len;
    let unpadded_encoded_len = FRAME_HEADER_LEN + body_base_len + tag_len;
    let (min_encoded_len, max_encoded_len) =
        encoded_len_range_for_padding(&settings.padding, body_base_len, tag_len)?;
    if max_encoded_len > MAX_UDP_PACKET_SIZE {
        return Err(PacketEncodeError::EncodedPacketTooLarge {
            encoded_len: max_encoded_len,
            buffer_len: MAX_UDP_PACKET_SIZE,
        });
    }

    Ok(EncodedPacketLenBounds {
        plaintext_len: packet_len,
        min_encoded_len,
        max_encoded_len,
        unpadded_encoded_len,
    })
}

fn encoded_len_range_for_padding(
    padding: &PacketPadding,
    body_base_len: usize,
    tag_len: usize,
) -> Result<(usize, usize), PacketEncodeError> {
    let required = FRAME_HEADER_LEN + body_base_len + tag_len;
    match padding {
        PacketPadding::None => Ok((required, required)),
        PacketPadding::PowerOfTwo => {
            let encoded_len = FRAME_HEADER_LEN + body_base_len.next_power_of_two() + tag_len;
            Ok((encoded_len, encoded_len))
        }
        PacketPadding::FixedMtu(mtu) => {
            if *mtu < required {
                Err(PacketEncodeError::FixedMtuTooSmall {
                    mtu: *mtu,
                    required,
                })
            } else {
                Ok((*mtu, *mtu))
            }
        }
        PacketPadding::RandomBucket(mtus) => {
            let mut valid = mtus.iter().copied().filter(|mtu| *mtu >= required);
            let Some(first) = valid.next() else {
                let mtu = mtus.iter().copied().max().unwrap_or(0);
                return Err(PacketEncodeError::FixedMtuTooSmall { mtu, required });
            };
            let (min, max) = valid.fold((first, first), |(min, max), mtu| {
                (min.min(mtu), max.max(mtu))
            });
            Ok((min, max))
        }
    }
}

/// Failure modes when decoding an obfuscated WireGuard packet.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PacketDecodeError {
    #[error("obfuscation magic byte missing or invalid")]
    MagicByteMismatch,
    #[error("obfuscation payload is empty")]
    EmptyPayload,
    #[error("obfuscation chaff frame")]
    ChaffFrame,
    #[error("encoded packet is too short: got {actual}, need at least {minimum}")]
    PacketTooShort { actual: usize, minimum: usize },
    #[error("encoded packet is too large: got {actual}, maximum {maximum}")]
    PacketTooLarge { actual: usize, maximum: usize },
    #[error("AEAD authentication failed")]
    AuthFailed,
    #[error("packet replay detected")]
    ReplayDetected,
    #[error("packet padding is invalid")]
    InvalidPadding,
    #[error("unsupported packet frame version {0}")]
    UnsupportedVersion(u8),
    #[error("packet frame mode does not match local obfuscation settings")]
    UnsupportedMode,
}

impl PacketDecodeError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MagicByteMismatch => "magic_byte_mismatch",
            Self::EmptyPayload => "empty_payload",
            Self::ChaffFrame => "chaff_frame",
            Self::PacketTooShort { .. } => "packet_too_short",
            Self::PacketTooLarge { .. } => "packet_too_large",
            Self::AuthFailed => "auth_failed",
            Self::ReplayDetected => "replay_detected",
            Self::InvalidPadding => "invalid_padding",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::UnsupportedMode => "unsupported_mode",
        }
    }
}

/// Encode a plaintext WireGuard packet using the configured obfuscation mode.
pub fn encode_packet(packet: &[u8], settings: &WgPacketObfuscation) -> Vec<u8> {
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..packet.len()].copy_from_slice(packet);
    let state = PacketEncodeState::new(0);
    let len = encode_packet_in_place(
        &mut encoded,
        packet.len(),
        settings,
        &state,
        PacketDirection::Bidirectional,
        0,
    )
    .expect("packet must fit in MAX_UDP_PACKET_SIZE");
    encoded.truncate(len);
    encoded
}

/// Decode an obfuscated WireGuard packet back to plaintext.
pub fn decode_packet(
    packet: &[u8],
    settings: &WgPacketObfuscation,
) -> Result<Vec<u8>, PacketDecodeError> {
    if packet.len() > MAX_UDP_PACKET_SIZE {
        return Err(PacketDecodeError::PacketTooLarge {
            actual: packet.len(),
            maximum: MAX_UDP_PACKET_SIZE,
        });
    }

    let mut decoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    decoded[..packet.len()].copy_from_slice(packet);
    let len = decode_packet_in_place(
        &mut decoded,
        packet.len(),
        settings,
        None,
        PacketDirection::Bidirectional,
    )?;
    decoded.truncate(len);
    Ok(decoded)
}

/// Encode a packet in place. The plaintext packet must start at `buffer[..packet_len]`.
pub fn encode_packet_in_place(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    state: &PacketEncodeState,
    direction: PacketDirection,
    now_millis: u64,
) -> Result<usize, PacketEncodeError> {
    if packet_len > buffer.len() {
        return Err(PacketEncodeError::PacketTooLarge {
            packet_len,
            buffer_len: buffer.len(),
        });
    }

    if !settings.uses_framed_encoding() {
        return encode_legacy_xor_in_place(buffer, packet_len, settings);
    }

    encode_framed_in_place(buffer, packet_len, settings, state, direction, now_millis)
}

/// Decode a packet in place, moving plaintext to `buffer[..returned_len]`.
pub fn decode_packet_in_place(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    replay_window: Option<&mut ReplayWindow>,
    direction: PacketDirection,
) -> Result<usize, PacketDecodeError> {
    if packet_len == 0 {
        return Err(PacketDecodeError::PacketTooShort {
            actual: 0,
            minimum: 1,
        });
    }
    if packet_len > buffer.len() {
        return Err(PacketDecodeError::PacketTooShort {
            actual: buffer.len(),
            minimum: packet_len,
        });
    }

    if !settings.uses_framed_encoding() {
        return decode_legacy_xor_in_place(buffer, packet_len, settings);
    }

    decode_framed_in_place(buffer, packet_len, settings, replay_window, direction)
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
