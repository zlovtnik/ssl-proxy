// This file is include!'d into the same module as types.rs, so it shares
// types.rs imports and constants. No imports are declared here.

use chacha20::{cipher::StreamCipher, ChaCha20, Key, KeyIvInit, Nonce};

const FRAME_TAG_LEN: usize = 4;

/// Encode a plaintext packet that was received after reserved header space.
///
/// The returned range identifies the encoded datagram without moving the
/// plaintext payload. Callers must reserve `packet_encode_headroom(settings)`
/// bytes before `packet_start`.
pub(crate) fn encode_packet_in_place_with_headroom(
    buffer: &mut [u8],
    packet_start: usize,
    packet_len: usize,
    settings: &WgPacketObfuscation,
    state: &PacketEncodeState,
    direction: PacketDirection,
) -> Result<Range<usize>, PacketEncodeError> {
    let headroom = packet_encode_headroom(settings);
    if packet_start < headroom || packet_start.saturating_add(packet_len) > buffer.len() {
        return Err(PacketEncodeError::PacketTooLarge {
            packet_len,
            buffer_len: buffer.len().saturating_sub(packet_start),
        });
    }
    let encoded_start = packet_start - headroom;

    let encoded_len = encode_framed_prepositioned(
        &mut buffer[encoded_start..],
        packet_len,
        settings,
        state,
        direction,
    )?;
    Ok(encoded_start..encoded_start + encoded_len)
}

/// Headroom before the plaintext payload so the framed header and length
/// field can be prepended without moving the payload.
///
/// The AEAD tag is appended after the body, so it does not consume headroom.
pub(crate) fn packet_encode_headroom(settings: &WgPacketObfuscation) -> usize {
    let _ = settings;
    FRAME_HEADER_LEN + BODY_LEN_FIELD_LEN
}

fn encode_framed_in_place(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    state: &PacketEncodeState,
    direction: PacketDirection,
) -> Result<usize, PacketEncodeError> {
    let payload_start = FRAME_HEADER_LEN + BODY_LEN_FIELD_LEN;
    if payload_start.saturating_add(packet_len) > buffer.len() {
        return Err(PacketEncodeError::EncodedPacketTooLarge {
            encoded_len: payload_start.saturating_add(packet_len),
            buffer_len: buffer.len(),
        });
    }
    buffer.copy_within(0..packet_len, payload_start);
    encode_framed_prepositioned(buffer, packet_len, settings, state, direction)
}

fn encode_framed_prepositioned(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    state: &PacketEncodeState,
    direction: PacketDirection,
) -> Result<usize, PacketEncodeError> {
    if packet_len > u16::MAX as usize {
        return Err(PacketEncodeError::PacketTooLarge {
            packet_len,
            buffer_len: u16::MAX as usize,
        });
    }

    let counter = state.next_packet_counter();
    let tag_len = tag_len(settings.encryption_mode);
    let body_base_len = BODY_LEN_FIELD_LEN + packet_len;
    let body_len = padded_body_len(&settings.padding, body_base_len, tag_len)?;
    let encoded_len = FRAME_HEADER_LEN + body_len + tag_len;
    if encoded_len > buffer.len() || encoded_len > MAX_UDP_PACKET_SIZE {
        return Err(PacketEncodeError::EncodedPacketTooLarge {
            encoded_len,
            buffer_len: buffer.len().min(MAX_UDP_PACKET_SIZE),
        });
    }

    let body_start = FRAME_HEADER_LEN;
    let payload_start = body_start + BODY_LEN_FIELD_LEN;
    buffer[body_start..body_start + BODY_LEN_FIELD_LEN]
        .copy_from_slice(&(packet_len as u16).to_be_bytes());
    buffer[payload_start + packet_len..body_start + body_len].fill(0);

    let session_salt = state.session_salt();
    write_frame_header(buffer, settings, &session_salt, counter, direction)?;

    match settings.encryption_mode {
        EncryptionMode::Xor => {
            let mut cipher = framed_xor_cipher(settings, &session_salt, counter, direction)?;
            cipher.apply_keystream(&mut buffer[body_start..body_start + body_len]);
        }
        EncryptionMode::Aead => {
            let cipher = {
                let key = derive_key(settings, &session_salt, direction, b"aead")?;
                XChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|_| PacketEncodeError::AeadEncrypt)?
            };
            let nonce = frame_nonce(&session_salt, counter);
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

fn decode_framed_in_place_view(
    buffer: &mut [u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    replay_window: &mut SessionReplayWindow,
    direction: PacketDirection,
) -> Result<Range<usize>, PacketDecodeError> {
    let (salt, counter, frame_mode) =
        parse_framed_header(buffer, packet_len, settings, direction)?;
    let salt = Zeroizing::new(salt);

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
            let mut cipher = framed_xor_cipher(settings, &salt, counter, direction)
                .map_err(|_| PacketDecodeError::KeyDerivation)?;
            cipher.apply_keystream(&mut buffer[body_start..body_end]);
        }
        EncryptionMode::Aead => {
            let cipher = {
                let key = derive_key(settings, &salt, direction, b"aead")
                    .map_err(|_| PacketDecodeError::KeyDerivation)?;
                XChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|_| PacketDecodeError::AuthFailed)?
            };
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

    replay_window.check_and_update(&salt, counter)?;

    let original_len = u16::from_be_bytes([buffer[body_start], buffer[body_start + 1]]) as usize;
    if original_len == 0 {
        return Err(PacketDecodeError::ChaffFrame);
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

    Ok(payload_start..payload_start + original_len)
}

/// Parse and validate a framed packet's header.
///
/// The header tag is a truncated keyed MAC over the salt, masked counter,
/// flags, and version, so sessions are only created for peers who know the
/// configured obfuscation key. Raw key bytes never appear on the wire.
fn parse_framed_header(
    buffer: &[u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    direction: PacketDirection,
) -> Result<([u8; FRAME_SALT_LEN], u64, EncryptionMode), PacketDecodeError> {
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
    let encoded_counter = read_u64_at(buffer, 18);
    let counter = encoded_counter
        ^ frame_counter_mask(settings, &salt)
        .map_err(|_| PacketDecodeError::KeyDerivation)?;

    let expected_tag = header_tag(settings, &salt, encoded_counter, flags, direction)
        .map_err(|_| PacketDecodeError::KeyDerivation)?;
    if !constant_time_eq(&buffer[26..26 + FRAME_TAG_LEN], &expected_tag) {
        return Err(PacketDecodeError::HeaderTagMismatch);
    }

    Ok((salt, counter, frame_mode))
}

/// Validate a framed packet's header without decrypting or mutating the body.
///
/// Cheap pre-session check for UDP hot paths: only version, mode, and the
/// keyed header tag are verified; session creation may proceed safely
/// because the tag cannot be forged without the obfuscation key.
pub fn validate_framed_header(
    buffer: &[u8],
    packet_len: usize,
    settings: &WgPacketObfuscation,
    direction: PacketDirection,
) -> Result<(), PacketDecodeError> {
    if packet_len > buffer.len() {
        return Err(PacketDecodeError::PacketTooShort {
            actual: buffer.len(),
            minimum: packet_len,
        });
    }
    parse_framed_header(buffer, packet_len, settings, direction).map(|_| ())
}

fn write_frame_header(
    buffer: &mut [u8],
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    counter: u64,
    direction: PacketDirection,
) -> Result<(), PacketEncodeError> {
    buffer[0] = FRAME_VERSION;
    buffer[1] = frame_flags(settings);
    buffer[2..18].copy_from_slice(salt);
    let encoded_counter = counter ^ frame_counter_mask(settings, salt)?;
    buffer[18..26].copy_from_slice(&encoded_counter.to_be_bytes());
    let tag = header_tag(settings, salt, encoded_counter, buffer[1], direction)?;
    buffer[26..30].copy_from_slice(&tag);
    Ok(())
}

fn frame_flags(settings: &WgPacketObfuscation) -> u8 {
    let mut flags = 0;
    if matches!(settings.encryption_mode, EncryptionMode::Aead) {
        flags |= FRAME_FLAG_AEAD;
    }
    if !matches!(&settings.padding, PacketPadding::None) {
        flags |= FRAME_FLAG_PADDING;
    }
    flags
}

/// Truncated keyed MAC binding the frame header to the configured key.
///
/// HKDF-SHA256 with the obfuscation key as IKM and the covered header
/// fields (salt, masked counter, flags, version) as the HKDF salt produces
/// the four on-wire tag bytes, domain-separated per direction. The tag is
/// compared in constant time. A passive observer learns nothing about the
/// key, and a forger without the key has a 2^-32 chance per attempt of
/// producing a valid tag.
fn header_tag(
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    encoded_counter: u64,
    flags: u8,
    direction: PacketDirection,
) -> Result<[u8; FRAME_TAG_LEN], PacketEncodeError> {
    let mut hkdf_salt = [0u8; FRAME_SALT_LEN + 8 + 1 + 1];
    hkdf_salt[..FRAME_SALT_LEN].copy_from_slice(salt);
    hkdf_salt[FRAME_SALT_LEN..FRAME_SALT_LEN + 8]
        .copy_from_slice(&encoded_counter.to_be_bytes());
    hkdf_salt[FRAME_SALT_LEN + 8] = flags;
    hkdf_salt[FRAME_SALT_LEN + 9] = FRAME_VERSION;

    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), settings.key.as_slice());
    let mut expanded = [0u8; 32];
    let mut info = Vec::with_capacity(48);
    info.extend_from_slice(b"ssl-proxy/wg-obfs/v2/header-tag/");
    info.extend_from_slice(direction.as_label());
    hk.expand(&info, &mut expanded)
        .map_err(|_| PacketEncodeError::KeyDerivation)?;
    let mut tag = [0u8; FRAME_TAG_LEN];
    tag.copy_from_slice(&expanded[..FRAME_TAG_LEN]);
    Ok(tag)
}

fn frame_counter_mask(
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
) -> Result<u64, PacketEncodeError> {
    let key = derive_key(settings, salt, PacketDirection::Bidirectional, b"counter")?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&key[..8]);
    Ok(u64::from_be_bytes(bytes))
}

/// Per-frame ChaCha20 keystream for framed XOR mode.
///
/// The key is HKDF-derived per direction and the nonce binds the frame
/// counter, so no two frames in a session ever share keystream bytes;
/// reusing a mask across frames would expose a many-time pad under
/// known-plaintext WireGuard headers.
fn framed_xor_cipher(
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    counter: u64,
    direction: PacketDirection,
) -> Result<ChaCha20, PacketEncodeError> {
    let key = derive_key(settings, salt, direction, b"xor")?;
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_be_bytes());
    nonce[8..12].copy_from_slice(&salt[..4]);
    let key: &Key = key.as_slice().try_into().map_err(|_| PacketEncodeError::KeyDerivation)?;
    let nonce: &Nonce = nonce.as_slice().try_into().map_err(|_| PacketEncodeError::KeyDerivation)?;
    Ok(ChaCha20::new(key, nonce))
}

fn frame_nonce(salt: &[u8; FRAME_SALT_LEN], counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..FRAME_SALT_LEN].copy_from_slice(salt);
    nonce[FRAME_SALT_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn derive_key(
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    direction: PacketDirection,
    purpose: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PacketEncodeError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), settings.key.as_slice());
    let mut key = [0u8; 32];
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"ssl-proxy/wg-obfs/v2/");
    info.extend_from_slice(purpose);
    info.push(b'/');
    info.extend_from_slice(direction.as_label());
    hk.expand(&info, &mut key)
        .map_err(|_| PacketEncodeError::KeyDerivation)?;
    Ok(Zeroizing::new(key))
}

fn padded_body_len(
    padding: &PacketPadding,
    body_base_len: usize,
    tag_len: usize,
) -> Result<usize, PacketEncodeError> {
    match padding {
        PacketPadding::None => Ok(body_base_len),
        PacketPadding::PowerOfTwo => Ok(body_base_len.next_power_of_two()),
        PacketPadding::FixedMtu(mtu) => fixed_mtu_body_len(*mtu, body_base_len, tag_len),
        PacketPadding::RandomBucket(mtus) => {
            let required = FRAME_HEADER_LEN + body_base_len + tag_len;
            let valid = mtus
                .iter()
                .copied()
                .filter(|mtu| *mtu >= required)
                .collect::<Vec<_>>();
            if valid.is_empty() {
                let mtu = mtus.iter().copied().max().unwrap_or(0);
                Err(PacketEncodeError::FixedMtuTooSmall { mtu, required })
            } else {
                let index = random_index(valid.len());
                fixed_mtu_body_len(valid[index], body_base_len, tag_len)
            }
        }
    }
}

fn fixed_mtu_body_len(
    mtu: usize,
    body_base_len: usize,
    tag_len: usize,
) -> Result<usize, PacketEncodeError> {
    let required = FRAME_HEADER_LEN + body_base_len + tag_len;
    if mtu < required {
        Err(PacketEncodeError::FixedMtuTooSmall { mtu, required })
    } else {
        Ok(mtu - FRAME_HEADER_LEN - tag_len)
    }
}

fn random_index(len: usize) -> usize {
    debug_assert!(len > 0);
    (OsRng.next_u64() as usize) % len
}

fn read_salt(buffer: &[u8]) -> [u8; FRAME_SALT_LEN] {
    let mut salt = [0u8; FRAME_SALT_LEN];
    salt.copy_from_slice(&buffer[2..18]);
    salt
}

fn read_u64_at(buffer: &[u8], start: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buffer[start..start + 8]);
    u64::from_be_bytes(bytes)
}
