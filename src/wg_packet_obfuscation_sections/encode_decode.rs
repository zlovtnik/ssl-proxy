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
    // Decoders treat the frame flag as the claimed wire format and require it
    // to match local policy. Accepting a mismatch would silently validate the
    // marker in a different position mode than the peer announced.
    let frame_randomized = flags & FRAME_FLAG_RANDOMIZED_MAGIC != 0;
    let settings_randomized = matches!(settings.magic_position, MagicPositionMode::Randomized);
    if frame_randomized != settings_randomized {
        return Err(PacketDecodeError::UnsupportedMode);
    }

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
    if flags & FRAME_FLAG_RANDOMIZED_MAGIC == 0 {
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

/// Return the framed XOR mask.
///
/// This path always derives the mask from the configured key and the frame
/// salt. Legacy non-framed XOR remains the only mode that uses the raw key
/// bytes directly as the repeating XOR mask.
fn framed_xor_mask(
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    direction: PacketDirection,
    epoch: u32,
) -> Vec<u8> {
    derive_key(settings, salt, direction, epoch, b"xor").to_vec()
}

pub(crate) fn cleanup_interval(idle_timeout: Duration) -> Duration {
    let half = idle_timeout / 2;
    if half.is_zero() {
        Duration::from_millis(1)
    } else {
        half.min(Duration::from_secs(5))
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
