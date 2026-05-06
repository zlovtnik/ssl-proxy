//! Shared WireGuard UDP packet obfuscation helpers.
//!
//! This module is intentionally separate from `obfuscation.rs`, which handles
//! HTTP header normalization. These helpers operate on raw WireGuard UDP
//! datagrams for the server relay and the Linux client shim.

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

/// Packet confidentiality/integrity mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EncryptionMode {
    #[default]
    Xor,
    Aead,
}

/// Optional framed packet padding policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PacketPadding {
    #[default]
    None,
    PowerOfTwo,
    FixedMtu(usize),
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgPacketObfuscation {
    pub key: Vec<u8>,
    pub magic_byte: Option<u8>,
    pub encryption_mode: EncryptionMode,
    pub padding: PacketPadding,
    pub magic_position: MagicPositionMode,
    pub xor_rekey: Option<XorRekeyPolicy>,
    pub replay_protection: bool,
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
            key,
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
            || !matches!(self.padding, PacketPadding::None)
            || !matches!(self.magic_position, MagicPositionMode::Fixed)
            || self.xor_rekey.is_some()
            || self.replay_protection
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
#[derive(Debug)]
pub struct PacketEncodeState {
    session_salt: [u8; FRAME_SALT_LEN],
    next_counter: AtomicU64,
    started_at_millis: u64,
}

impl PacketEncodeState {
    pub fn new(started_at_millis: u64) -> Self {
        let mut session_salt = [0u8; FRAME_SALT_LEN];
        OsRng.fill_bytes(&mut session_salt);
        Self {
            session_salt,
            next_counter: AtomicU64::new(0),
            started_at_millis,
        }
    }

    pub fn with_salt(session_salt: [u8; FRAME_SALT_LEN], started_at_millis: u64) -> Self {
        Self {
            session_salt,
            next_counter: AtomicU64::new(0),
            started_at_millis,
        }
    }

    pub fn session_salt(&self) -> [u8; FRAME_SALT_LEN] {
        self.session_salt
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

impl ReplayWindow {
    pub fn check_and_update(&mut self, counter: u64) -> Result<(), PacketDecodeError> {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.bitmap = 1;
            return Ok(());
        };

        if counter > highest {
            let shift = counter - highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
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

/// Failure modes when decoding an obfuscated WireGuard packet.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PacketDecodeError {
    #[error("obfuscation magic byte missing or invalid")]
    MagicByteMismatch,
    #[error("obfuscation payload is empty")]
    EmptyPayload,
    #[error("encoded packet is too short: got {actual}, need at least {minimum}")]
    PacketTooShort { actual: usize, minimum: usize },
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
            Self::PacketTooShort { .. } => "packet_too_short",
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
        return Err(PacketDecodeError::PacketTooShort {
            actual: packet.len(),
            minimum: MAX_UDP_PACKET_SIZE,
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

fn encode_legacy_xor_in_place(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
) -> Result<usize, PacketEncodeError> {
    let marker_len = usize::from(settings.magic_byte.is_some());
    let encoded_len = packet_len + marker_len;
    if encoded_len > buffer.len() {
        return Err(PacketEncodeError::EncodedPacketTooLarge {
            encoded_len,
            buffer_len: buffer.len(),
        });
    }

    if let Some(magic_byte) = settings.magic_byte {
        buffer.copy_within(0..packet_len, 1);
        buffer[0] = magic_byte;
        apply_xor_mask(&mut buffer[1..encoded_len], &settings.key);
    } else {
        apply_xor_mask(&mut buffer[..packet_len], &settings.key);
    }

    Ok(encoded_len)
}

fn decode_legacy_xor_in_place(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
) -> Result<usize, PacketDecodeError> {
    let payload = if let Some(magic_byte) = settings.magic_byte {
        match buffer.first().copied() {
            Some(actual) if actual == magic_byte => &mut buffer[1..packet_len],
            _ => return Err(PacketDecodeError::MagicByteMismatch),
        }
    } else {
        &mut buffer[..packet_len]
    };

    if payload.is_empty() {
        return Err(PacketDecodeError::EmptyPayload);
    }

    apply_xor_mask(payload, &settings.key);
    let payload_len = payload.len();
    if settings.magic_byte.is_some() {
        buffer.copy_within(1..packet_len, 0);
    }
    Ok(payload_len)
}

fn encode_framed_in_place(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    state: &PacketEncodeState,
    direction: PacketDirection,
    now_millis: u64,
) -> Result<usize, PacketEncodeError> {
    if packet_len > u16::MAX as usize {
        return Err(PacketEncodeError::PacketTooLarge {
            packet_len,
            buffer_len: u16::MAX as usize,
        });
    }

    let counter = state.next_packet_counter();
    let epoch = rekey_epoch(settings, state, counter, now_millis);
    let tag_len = tag_len(settings.encryption_mode);
    let body_base_len = BODY_LEN_FIELD_LEN + packet_len;
    let body_len = padded_body_len(settings.padding, body_base_len, tag_len)?;
    let encoded_len = FRAME_HEADER_LEN + body_len + tag_len;
    if encoded_len > buffer.len() || encoded_len > MAX_UDP_PACKET_SIZE {
        return Err(PacketEncodeError::EncodedPacketTooLarge {
            encoded_len,
            buffer_len: buffer.len().min(MAX_UDP_PACKET_SIZE),
        });
    }

    let body_start = FRAME_HEADER_LEN;
    let payload_start = body_start + BODY_LEN_FIELD_LEN;
    buffer.copy_within(0..packet_len, payload_start);
    buffer[body_start..body_start + BODY_LEN_FIELD_LEN]
        .copy_from_slice(&(packet_len as u16).to_be_bytes());
    buffer[payload_start + packet_len..body_start + body_len].fill(0);

    write_frame_header(buffer, settings, state.session_salt, counter, epoch);

    match settings.encryption_mode {
        EncryptionMode::Xor => {
            let mask = framed_xor_mask(settings, &state.session_salt, direction, epoch);
            apply_xor_mask(&mut buffer[body_start..body_start + body_len], &mask);
        }
        EncryptionMode::Aead => {
            let key = derive_key(settings, &state.session_salt, direction, epoch, b"aead");
            let cipher = XChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| PacketEncodeError::AeadEncrypt)?;
            let nonce = frame_nonce(&state.session_salt, counter);
            let (header, body_and_tag) = buffer[..encoded_len].split_at_mut(FRAME_HEADER_LEN);
            let (body, tag_out) = body_and_tag.split_at_mut(body_len);
            let tag = cipher
                .encrypt_in_place_detached(XNonce::from_slice(&nonce), header, body)
                .map_err(|_| PacketEncodeError::AeadEncrypt)?;
            tag_out[..AEAD_TAG_LEN].copy_from_slice(&tag);
        }
    }

    Ok(encoded_len)
}

fn decode_framed_in_place(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    replay_window: Option<&mut ReplayWindow>,
    direction: PacketDirection,
) -> Result<usize, PacketDecodeError> {
    if packet_len < FRAME_HEADER_LEN + BODY_LEN_FIELD_LEN {
        return Err(PacketDecodeError::PacketTooShort {
            actual: packet_len,
            minimum: FRAME_HEADER_LEN + BODY_LEN_FIELD_LEN,
        });
    }

    let version = buffer[0];
    if version != FRAME_VERSION {
        return Err(PacketDecodeError::UnsupportedVersion(version));
    }

    let flags = buffer[1];
    let frame_mode = if flags & FRAME_FLAG_AEAD != 0 {
        EncryptionMode::Aead
    } else {
        EncryptionMode::Xor
    };
    if frame_mode != settings.encryption_mode {
        return Err(PacketDecodeError::UnsupportedMode);
    }

    let salt = read_salt(buffer);
    let counter = read_u64_at(buffer, 19);
    let epoch = read_u32_at(buffer, 27);
    validate_marker(buffer, settings, &salt, counter, flags)?;

    let tag_len = tag_len(frame_mode);
    if packet_len < FRAME_HEADER_LEN + tag_len + BODY_LEN_FIELD_LEN {
        return Err(PacketDecodeError::PacketTooShort {
            actual: packet_len,
            minimum: FRAME_HEADER_LEN + tag_len + BODY_LEN_FIELD_LEN,
        });
    }

    let body_start = FRAME_HEADER_LEN;
    let body_end = packet_len - tag_len;
    match frame_mode {
        EncryptionMode::Xor => {
            let mask = framed_xor_mask(settings, &salt, direction, epoch);
            apply_xor_mask(&mut buffer[body_start..body_end], &mask);
        }
        EncryptionMode::Aead => {
            let key = derive_key(settings, &salt, direction, epoch, b"aead");
            let cipher = XChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| PacketDecodeError::AuthFailed)?;
            let nonce = frame_nonce(&salt, counter);
            let (header, body_and_tag) = buffer[..packet_len].split_at_mut(FRAME_HEADER_LEN);
            let (body, tag_bytes) = body_and_tag.split_at_mut(body_end - body_start);
            cipher
                .decrypt_in_place_detached(
                    XNonce::from_slice(&nonce),
                    header,
                    body,
                    Tag::from_slice(&tag_bytes[..AEAD_TAG_LEN]),
                )
                .map_err(|_| PacketDecodeError::AuthFailed)?;
        }
    }

    if settings.replay_protection {
        if let Some(window) = replay_window {
            window.check_and_update(counter)?;
        }
    }

    let original_len = u16::from_be_bytes([buffer[body_start], buffer[body_start + 1]]) as usize;
    if original_len == 0 {
        return Err(PacketDecodeError::EmptyPayload);
    }

    let payload_start = body_start + BODY_LEN_FIELD_LEN;
    if payload_start + original_len > body_end {
        return Err(PacketDecodeError::InvalidPadding);
    }
    if buffer[payload_start + original_len..body_end]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(PacketDecodeError::InvalidPadding);
    }

    buffer.copy_within(payload_start..payload_start + original_len, 0);
    Ok(original_len)
}

fn write_frame_header(
    buffer: &mut [u8],
    settings: &WgPacketObfuscation,
    salt: [u8; FRAME_SALT_LEN],
    counter: u64,
    epoch: u32,
) {
    buffer[0] = FRAME_VERSION;
    buffer[1] = frame_flags(settings);
    let marker_position = marker_position(settings, &salt, counter, buffer[1]);
    buffer[2] = (marker_position as u8) ^ marker_mask(settings, &salt, counter);
    buffer[3..19].copy_from_slice(&salt);
    buffer[19..27].copy_from_slice(&counter.to_be_bytes());
    buffer[27..31].copy_from_slice(&epoch.to_be_bytes());
    fill_marker_zone(
        &mut buffer[31..39],
        settings,
        &salt,
        counter,
        marker_position,
    );
}

fn frame_flags(settings: &WgPacketObfuscation) -> u8 {
    let mut flags = 0;
    if matches!(settings.encryption_mode, EncryptionMode::Aead) {
        flags |= FRAME_FLAG_AEAD;
    }
    if !matches!(settings.padding, PacketPadding::None) {
        flags |= FRAME_FLAG_PADDING;
    }
    if settings.xor_rekey.is_some() {
        flags |= FRAME_FLAG_REKEY;
    }
    if matches!(settings.magic_position, MagicPositionMode::Randomized) {
        flags |= FRAME_FLAG_RANDOMIZED_MAGIC;
    }
    flags
}

fn validate_marker(
    buffer: &[u8],
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    counter: u64,
    flags: u8,
) -> Result<(), PacketDecodeError> {
    let actual_position = (buffer[2] ^ marker_mask(settings, salt, counter)) as usize & 0b111;
    let expected = marker_position(settings, salt, counter, flags);
    if actual_position != expected {
        return Err(PacketDecodeError::MagicByteMismatch);
    }

    if let Some(magic_byte) = settings.magic_byte {
        let zone = &buffer[31..39];
        if zone[actual_position] != magic_byte {
            return Err(PacketDecodeError::MagicByteMismatch);
        }
    }
    Ok(())
}

fn fill_marker_zone(
    zone: &mut [u8],
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    counter: u64,
    marker_position: usize,
) {
    for (index, byte) in zone.iter_mut().enumerate() {
        let key_byte = settings.key[(index + counter as usize) % settings.key.len()];
        *byte = key_byte ^ salt[index % salt.len()] ^ (counter as u8);
    }
    if let Some(magic_byte) = settings.magic_byte {
        zone[marker_position] = magic_byte;
    }
}

fn marker_position(
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    counter: u64,
    flags: u8,
) -> usize {
    if flags & FRAME_FLAG_RANDOMIZED_MAGIC == 0
        || matches!(settings.magic_position, MagicPositionMode::Fixed)
    {
        0
    } else {
        ((settings.key[0] as u64 ^ salt[0] as u64 ^ counter) & 0b111) as usize
    }
}

fn marker_mask(settings: &WgPacketObfuscation, salt: &[u8; FRAME_SALT_LEN], counter: u64) -> u8 {
    (settings.key[settings.key.len().saturating_sub(1)] ^ salt[1] ^ (counter as u8)) & 0b111
}

fn padded_body_len(
    padding: PacketPadding,
    body_base_len: usize,
    tag_len: usize,
) -> Result<usize, PacketEncodeError> {
    match padding {
        PacketPadding::None => Ok(body_base_len),
        PacketPadding::PowerOfTwo => Ok(body_base_len.next_power_of_two()),
        PacketPadding::FixedMtu(mtu) => {
            let required = FRAME_HEADER_LEN + body_base_len + tag_len;
            if mtu < required {
                Err(PacketEncodeError::FixedMtuTooSmall { mtu, required })
            } else {
                Ok(mtu - FRAME_HEADER_LEN - tag_len)
            }
        }
    }
}

fn tag_len(mode: EncryptionMode) -> usize {
    match mode {
        EncryptionMode::Xor => 0,
        EncryptionMode::Aead => AEAD_TAG_LEN,
    }
}

fn rekey_epoch(
    settings: &WgPacketObfuscation,
    state: &PacketEncodeState,
    counter: u64,
    now_millis: u64,
) -> u32 {
    let Some(policy) = settings.xor_rekey else {
        return 0;
    };

    let packet_epoch = policy
        .every_packets
        .map(|every| counter / every)
        .unwrap_or(0);
    let time_epoch = policy
        .every_secs
        .map(|every| {
            let elapsed = now_millis.saturating_sub(state.started_at_millis);
            elapsed / Duration::from_secs(every).as_millis() as u64
        })
        .unwrap_or(0);

    packet_epoch.max(time_epoch).min(u32::MAX as u64) as u32
}

fn framed_xor_mask(
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    direction: PacketDirection,
    epoch: u32,
) -> Vec<u8> {
    if settings.xor_rekey.is_some() {
        derive_key(settings, salt, direction, epoch, b"xor").to_vec()
    } else {
        settings.key.clone()
    }
}

fn derive_key(
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    direction: PacketDirection,
    epoch: u32,
    purpose: &[u8],
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), &settings.key);
    let mut key = [0u8; 32];
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"ssl-proxy/wg-obfs/v1/");
    info.extend_from_slice(purpose);
    info.push(b'/');
    info.extend_from_slice(direction.as_label());
    info.push(b'/');
    info.extend_from_slice(&epoch.to_be_bytes());
    hk.expand(&info, &mut key)
        .expect("32-byte HKDF output is valid for SHA-256");
    key
}

fn frame_nonce(salt: &[u8; FRAME_SALT_LEN], counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..FRAME_SALT_LEN].copy_from_slice(salt);
    nonce[FRAME_SALT_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn read_salt(buffer: &[u8]) -> [u8; FRAME_SALT_LEN] {
    let mut salt = [0u8; FRAME_SALT_LEN];
    salt.copy_from_slice(&buffer[3..19]);
    salt
}

fn read_u64_at(buffer: &[u8], start: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buffer[start..start + 8]);
    u64::from_be_bytes(bytes)
}

fn read_u32_at(buffer: &[u8], start: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buffer[start..start + 4]);
    u32::from_be_bytes(bytes)
}

fn apply_xor_mask(packet: &mut [u8], key: &[u8]) {
    debug_assert!(!key.is_empty(), "obfuscation key must not be empty");
    for (index, byte) in packet.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn test_settings(magic_byte: Option<u8>) -> WgPacketObfuscation {
        WgPacketObfuscation::new(b"test-obfuscation-key".to_vec(), magic_byte)
    }

    fn fixed_state() -> PacketEncodeState {
        PacketEncodeState::with_salt(*b"0123456789abcdef", 0)
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

    proptest! {
        #[test]
        fn legacy_xor_roundtrip_without_magic_for_arbitrary_inputs(
            key in prop::collection::vec(any::<u8>(), 1..64),
            packet in prop::collection::vec(any::<u8>(), 1..4096),
        ) {
            let settings = WgPacketObfuscation::new(key, None);

            let encoded = encode_packet(&packet, &settings);
            let decoded = decode_packet(&encoded, &settings).unwrap();
            prop_assert_eq!(&decoded, &packet);

            let reencoded = encode_packet(&decoded, &settings);
            prop_assert_eq!(reencoded, encoded);
        }

        #[test]
        fn legacy_xor_roundtrip_with_magic_for_arbitrary_inputs(
            key in prop::collection::vec(any::<u8>(), 1..64),
            magic_byte in any::<u8>(),
            packet in prop::collection::vec(any::<u8>(), 1..4096),
        ) {
            let settings = WgPacketObfuscation::new(key, Some(magic_byte));

            let encoded = encode_packet(&packet, &settings);
            let decoded = decode_packet(&encoded, &settings).unwrap();
            prop_assert_eq!(&decoded, &packet);

            let reencoded = encode_packet(&decoded, &settings);
            prop_assert_eq!(reencoded, encoded);
        }
    }

    #[test]
    fn legacy_xor_round_trips_max_udp_packet_without_magic_byte() {
        let settings = test_settings(None);
        let packet = vec![0xA5; MAX_UDP_PACKET_SIZE];

        let encoded = encode_packet(&packet, &settings);
        let decoded = decode_packet(&encoded, &settings).unwrap();

        assert_eq!(decoded, packet);
    }

    #[test]
    fn legacy_xor_round_trips_max_udp_packet_with_magic_byte_overhead() {
        let settings = test_settings(Some(0xAA));
        let packet = vec![0x5A; MAX_UDP_PACKET_SIZE - 1];

        let encoded = encode_packet(&packet, &settings);
        assert_eq!(encoded.len(), MAX_UDP_PACKET_SIZE);
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
    fn decode_rejects_zero_length_before_payload_branching() {
        let settings = test_settings(None);

        assert_eq!(
            decode_packet(&[], &settings),
            Err(PacketDecodeError::PacketTooShort {
                actual: 0,
                minimum: 1
            })
        );
    }

    #[test]
    fn aead_round_trips_with_replay_window() {
        let settings = test_settings(Some(0xAA))
            .with_encryption_mode(EncryptionMode::Aead)
            .with_magic_position(MagicPositionMode::Randomized);
        let state = fixed_state();
        let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
        encoded[..11].copy_from_slice(b"hello-aead!");

        let len = encode_packet_in_place(
            &mut encoded,
            11,
            &settings,
            &state,
            PacketDirection::ClientToServer,
            0,
        )
        .unwrap();
        let mut replay = ReplayWindow::default();
        let decoded_len = decode_packet_in_place(
            &mut encoded,
            len,
            &settings,
            Some(&mut replay),
            PacketDirection::ClientToServer,
        )
        .unwrap();

        assert_eq!(&encoded[..decoded_len], b"hello-aead!");
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let settings = test_settings(Some(0xAA)).with_encryption_mode(EncryptionMode::Aead);
        let state = fixed_state();
        let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
        encoded[..6].copy_from_slice(b"secret");

        let len = encode_packet_in_place(
            &mut encoded,
            6,
            &settings,
            &state,
            PacketDirection::ClientToServer,
            0,
        )
        .unwrap();
        encoded[len - AEAD_TAG_LEN - 1] ^= 0x40;

        assert_eq!(
            decode_packet_in_place(
                &mut encoded,
                len,
                &settings,
                None,
                PacketDirection::ClientToServer,
            ),
            Err(PacketDecodeError::AuthFailed)
        );
    }

    #[test]
    fn replay_window_rejects_duplicate_counter() {
        let settings = test_settings(Some(0xAA)).with_encryption_mode(EncryptionMode::Aead);
        let state = fixed_state();
        let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
        encoded[..6].copy_from_slice(b"replay");

        let len = encode_packet_in_place(
            &mut encoded,
            6,
            &settings,
            &state,
            PacketDirection::ClientToServer,
            0,
        )
        .unwrap();
        let original = encoded[..len].to_vec();
        let mut replay = ReplayWindow::default();
        assert!(decode_packet_in_place(
            &mut encoded,
            len,
            &settings,
            Some(&mut replay),
            PacketDirection::ClientToServer,
        )
        .is_ok());

        encoded[..len].copy_from_slice(&original);
        assert_eq!(
            decode_packet_in_place(
                &mut encoded,
                len,
                &settings,
                Some(&mut replay),
                PacketDirection::ClientToServer,
            ),
            Err(PacketDecodeError::ReplayDetected)
        );
    }

    #[test]
    fn randomized_magic_position_moves_marker_in_frame_zone() {
        let settings = test_settings(Some(0xAA))
            .with_replay_protection(true)
            .with_magic_position(MagicPositionMode::Randomized);
        let state = fixed_state();
        let mut first = vec![0u8; MAX_UDP_PACKET_SIZE];
        let mut second = vec![0u8; MAX_UDP_PACKET_SIZE];
        first[..4].copy_from_slice(b"same");
        second[..4].copy_from_slice(b"same");

        let first_len = encode_packet_in_place(
            &mut first,
            4,
            &settings,
            &state,
            PacketDirection::Bidirectional,
            0,
        )
        .unwrap();
        let second_len = encode_packet_in_place(
            &mut second,
            4,
            &settings,
            &state,
            PacketDirection::Bidirectional,
            0,
        )
        .unwrap();

        assert_ne!(&first[31..39], &second[31..39]);
        assert!(decode_packet(&first[..first_len], &settings).is_ok());
        assert!(decode_packet(&second[..second_len], &settings).is_ok());
    }

    #[test]
    fn padding_round_trips_and_rejects_modified_padding() {
        let settings = test_settings(Some(0xAA))
            .with_padding(PacketPadding::PowerOfTwo)
            .with_replay_protection(true);
        let state = fixed_state();
        let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
        encoded[..7].copy_from_slice(b"padding");

        let len = encode_packet_in_place(
            &mut encoded,
            7,
            &settings,
            &state,
            PacketDirection::Bidirectional,
            0,
        )
        .unwrap();
        let clean = encoded[..len].to_vec();
        let decoded = decode_packet(&clean, &settings).unwrap();
        assert_eq!(decoded, b"padding");

        encoded[..len].copy_from_slice(&clean);
        encoded[len - 1] ^= 0x01;
        assert_eq!(
            decode_packet(&encoded[..len], &settings),
            Err(PacketDecodeError::InvalidPadding)
        );
    }

    #[test]
    fn xor_rekey_round_trips_across_packet_epochs() {
        let settings = test_settings(Some(0xAA)).with_xor_rekey(XorRekeyPolicy::new(Some(1), None));
        let state = fixed_state();
        let mut first = vec![0u8; MAX_UDP_PACKET_SIZE];
        let mut second = vec![0u8; MAX_UDP_PACKET_SIZE];
        first[..5].copy_from_slice(b"epoch");
        second[..5].copy_from_slice(b"epoch");

        let first_len = encode_packet_in_place(
            &mut first,
            5,
            &settings,
            &state,
            PacketDirection::Bidirectional,
            0,
        )
        .unwrap();
        let second_len = encode_packet_in_place(
            &mut second,
            5,
            &settings,
            &state,
            PacketDirection::Bidirectional,
            0,
        )
        .unwrap();

        assert_ne!(&first[..first_len], &second[..second_len]);
        assert_eq!(
            decode_packet(&first[..first_len], &settings).unwrap(),
            b"epoch"
        );
        assert_eq!(
            decode_packet(&second[..second_len], &settings).unwrap(),
            b"epoch"
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
