use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use proptest::prelude::*;

use super::*;

fn test_settings(magic_byte: Option<u8>) -> WgPacketObfuscation {
    WgPacketObfuscation::new(b"test-obfuscation-key".to_vec(), magic_byte).unwrap()
}

fn fixed_state() -> PacketEncodeState {
    PacketEncodeState::with_salt(*b"0123456789abcdef", 0)
}

#[test]
fn encoded_len_bounds_cover_legacy_xor_modes() {
    let no_magic = test_settings(None);
    let with_magic = test_settings(Some(0xAA));

    assert_eq!(
        encoded_packet_len_bounds(100, &no_magic).unwrap(),
        EncodedPacketLenBounds {
            plaintext_len: 100,
            min_encoded_len: 100,
            max_encoded_len: 100,
            unpadded_encoded_len: 100,
        }
    );
    assert_eq!(
        encoded_packet_len_bounds(100, &with_magic).unwrap(),
        EncodedPacketLenBounds {
            plaintext_len: 100,
            min_encoded_len: 101,
            max_encoded_len: 101,
            unpadded_encoded_len: 101,
        }
    );
}

#[test]
fn encoded_len_bounds_cover_framed_xor_and_aead() {
    let framed_xor = test_settings(Some(0xAA)).with_replay_protection(true);
    let framed_aead = test_settings(Some(0xAA))
        .with_encryption_mode(EncryptionMode::Aead)
        .with_replay_protection(true);

    let xor = encoded_packet_len_bounds(100, &framed_xor).unwrap();
    assert_eq!(
        xor.min_encoded_len,
        FRAMED_HEADER_LEN + FRAMED_BODY_LEN_FIELD_LEN + 100
    );
    assert_eq!(
        xor.max_overhead_len(),
        FRAMED_HEADER_LEN + FRAMED_BODY_LEN_FIELD_LEN
    );

    let aead = encoded_packet_len_bounds(100, &framed_aead).unwrap();
    assert_eq!(
        aead.min_encoded_len,
        FRAMED_HEADER_LEN + FRAMED_BODY_LEN_FIELD_LEN + 100 + AEAD_TAG_LEN_BYTES
    );
    assert_eq!(
        aead.max_overhead_len(),
        FRAMED_HEADER_LEN + FRAMED_BODY_LEN_FIELD_LEN + AEAD_TAG_LEN_BYTES
    );
}

#[test]
fn encoded_len_bounds_cover_padding_modes() {
    let fixed = test_settings(Some(0xAA))
        .with_padding(PacketPadding::FixedMtu(1200))
        .with_replay_protection(true);
    let random = test_settings(Some(0xAA))
        .with_padding(PacketPadding::RandomBucket(vec![200, 512, 1400]))
        .with_replay_protection(true);
    let power_two = test_settings(Some(0xAA))
        .with_padding(PacketPadding::PowerOfTwo)
        .with_replay_protection(true);

    assert_eq!(
        encoded_packet_len_bounds(100, &fixed)
            .unwrap()
            .max_encoded_len,
        1200
    );
    assert_eq!(
        encoded_packet_len_bounds(100, &random).unwrap(),
        EncodedPacketLenBounds {
            plaintext_len: 100,
            min_encoded_len: 200,
            max_encoded_len: 1400,
            unpadded_encoded_len: FRAMED_HEADER_LEN + FRAMED_BODY_LEN_FIELD_LEN + 100,
        }
    );
    assert_eq!(
        encoded_packet_len_bounds(100, &power_two)
            .unwrap()
            .max_encoded_len,
        FRAMED_HEADER_LEN + (FRAMED_BODY_LEN_FIELD_LEN + 100).next_power_of_two()
    );
}

#[test]
fn encoded_len_bounds_reject_too_small_fixed_mtu() {
    let settings = test_settings(Some(0xAA))
        .with_padding(PacketPadding::FixedMtu(64))
        .with_replay_protection(true);

    assert_eq!(
        encoded_packet_len_bounds(100, &settings),
        Err(PacketEncodeError::FixedMtuTooSmall {
            mtu: 64,
            required: FRAMED_HEADER_LEN + FRAMED_BODY_LEN_FIELD_LEN + 100,
        })
    );
}

#[test]
fn xor_round_trips_without_magic_byte() {
    let settings = test_settings(None);
    let packet = b"wireguard-data-packet";

    let encoded = encode_packet(packet, &settings).unwrap();
    assert!(encoded.len() >= packet.len());

    let decoded = decode_packet(&encoded, &settings).unwrap();
    assert_eq!(decoded, packet);
}

#[test]
fn xor_round_trips_with_magic_byte() {
    let settings = test_settings(Some(0xAA));
    let packet = vec![0x42u8; 100];

    let encoded = encode_packet(&packet, &settings).unwrap();
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
        let settings = WgPacketObfuscation::new(key, None).unwrap();

        let encoded = encode_packet(&packet, &settings).unwrap();
        let decoded = decode_packet(&encoded, &settings).unwrap();
        prop_assert_eq!(&decoded, &packet);

        let reencoded = encode_packet(&decoded, &settings).unwrap();
        prop_assert_eq!(reencoded, encoded);
    }

    #[test]
    fn legacy_xor_roundtrip_with_magic_for_arbitrary_inputs(
        key in prop::collection::vec(any::<u8>(), 1..64),
        magic_byte in any::<u8>(),
        packet in prop::collection::vec(any::<u8>(), 1..4096),
    ) {
        let settings = WgPacketObfuscation::new(key, Some(magic_byte)).unwrap();

        let encoded = encode_packet(&packet, &settings).unwrap();
        let decoded = decode_packet(&encoded, &settings).unwrap();
        prop_assert_eq!(&decoded, &packet);

        let reencoded = encode_packet(&decoded, &settings).unwrap();
        prop_assert_eq!(reencoded, encoded);
    }
}

#[test]
fn legacy_xor_round_trips_max_udp_packet_without_magic_byte() {
    let settings = test_settings(None);
    let packet = vec![0xA5; MAX_UDP_PACKET_SIZE];

    let encoded = encode_packet(&packet, &settings).unwrap();
    let decoded = decode_packet(&encoded, &settings).unwrap();

    assert_eq!(decoded, packet);
}

#[test]
fn legacy_xor_round_trips_max_udp_packet_with_magic_byte_overhead() {
    let settings = test_settings(Some(0xAA));
    let packet = vec![0x5A; MAX_UDP_PACKET_SIZE - 1];

    let encoded = encode_packet(&packet, &settings).unwrap();
    assert_eq!(encoded.len(), MAX_UDP_PACKET_SIZE);
    let decoded = decode_packet(&encoded, &settings).unwrap();

    assert_eq!(decoded, packet);
}

#[test]
fn constructor_rejects_empty_key() {
    assert_eq!(
        WgPacketObfuscation::new(Vec::<u8>::new(), None),
        Err(WgPacketObfuscationError::EmptyKey)
    );
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
fn decode_in_place_rejects_packet_len_larger_than_buffer() {
    let settings = test_settings(None);
    let mut packet = vec![0u8; 4];

    assert_eq!(
        decode_packet_in_place(
            &mut packet,
            8,
            &settings,
            None,
            PacketDirection::Bidirectional,
        ),
        Err(PacketDecodeError::PacketTooShort {
            actual: 4,
            minimum: 8
        })
    );
}

#[test]
fn validate_framed_header_rejects_packet_len_larger_than_buffer() {
    let settings = test_settings(Some(0xAA));
    let packet = vec![0u8; FRAME_HEADER_LEN + BODY_LEN_FIELD_LEN];
    let packet_len = packet.len() + 1;

    assert_eq!(
        validate_framed_header(&packet, packet_len, &settings),
        Err(PacketDecodeError::PacketTooShort {
            actual: packet.len(),
            minimum: packet_len,
        })
    );
}

#[test]
fn decode_rejects_oversized_packet_as_too_large() {
    let settings = test_settings(None);
    let packet = vec![0u8; MAX_UDP_PACKET_SIZE + 1];

    assert_eq!(
        decode_packet(&packet, &settings),
        Err(PacketDecodeError::PacketTooLarge {
            actual: MAX_UDP_PACKET_SIZE + 1,
            maximum: MAX_UDP_PACKET_SIZE,
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
fn randomized_magic_flag_must_match_local_position_mode() {
    let encode_settings = test_settings(Some(0xAA))
        .with_replay_protection(true)
        .with_magic_position(MagicPositionMode::Randomized);
    let decode_settings = test_settings(Some(0xAA)).with_replay_protection(true);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..4].copy_from_slice(b"mode");

    let len = encode_packet_in_place(
        &mut encoded,
        4,
        &encode_settings,
        &state,
        PacketDirection::Bidirectional,
        0,
    )
    .unwrap();

    assert_eq!(
        decode_packet_in_place(
            &mut encoded,
            len,
            &decode_settings,
            None,
            PacketDirection::Bidirectional,
        ),
        Err(PacketDecodeError::UnsupportedMode)
    );
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
fn framed_xor_without_rekey_uses_salt_derived_mask() {
    let settings = test_settings(Some(0xAA)).with_replay_protection(true);
    let salt = *b"0123456789abcdef";

    let mask = framed_xor_mask(&settings, &salt, PacketDirection::Bidirectional, 0).unwrap();

    assert_ne!(&mask[..], settings.key.as_slice());
    assert_eq!(mask.len(), 32);
}

#[test]
fn framed_header_masks_counter_field() {
    let settings = test_settings(Some(0xAA)).with_replay_protection(true);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..7].copy_from_slice(b"counter");

    let len = encode_packet_in_place(
        &mut encoded,
        7,
        &settings,
        &state,
        PacketDirection::Bidirectional,
        0,
    )
    .unwrap();
    let first_counter = u64::from_be_bytes(encoded[19..27].try_into().unwrap());

    assert_ne!(first_counter, 0);
    assert_eq!(
        decode_packet(&encoded[..len], &settings).unwrap(),
        b"counter"
    );
}

#[test]
fn framed_decoder_accepts_legacy_clear_counter_header() {
    let settings = test_settings(Some(0xAA)).with_replay_protection(true);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..6].copy_from_slice(b"legacy");

    let len = encode_legacy_clear_counter_frame_in_place(
        &mut encoded,
        6,
        &settings,
        &state,
        PacketDirection::Bidirectional,
        0,
    )
    .unwrap();

    assert_eq!(u64::from_be_bytes(encoded[19..27].try_into().unwrap()), 0);
    validate_framed_header(&encoded[..len], len, &settings).unwrap();
    assert_eq!(
        decode_packet(&encoded[..len], &settings).unwrap(),
        b"legacy"
    );
}

#[test]
fn aead_decoder_accepts_legacy_clear_counter_header() {
    let settings = test_settings(Some(0xAA))
        .with_encryption_mode(EncryptionMode::Aead)
        .with_magic_position(MagicPositionMode::Randomized)
        .with_replay_protection(true);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..11].copy_from_slice(b"legacy-aead");

    let len = encode_legacy_clear_counter_frame_in_place(
        &mut encoded,
        11,
        &settings,
        &state,
        PacketDirection::ClientToServer,
        0,
    )
    .unwrap();

    assert_eq!(u64::from_be_bytes(encoded[19..27].try_into().unwrap()), 0);
    let mut replay = ReplayWindow::default();
    let decoded_len = decode_packet_in_place(
        &mut encoded,
        len,
        &settings,
        Some(&mut replay),
        PacketDirection::ClientToServer,
    )
    .unwrap();

    assert_eq!(&encoded[..decoded_len], b"legacy-aead");
}

#[test]
fn random_bucket_padding_uses_configured_mtu() {
    let settings = test_settings(Some(0xAA))
        .with_padding(PacketPadding::RandomBucket(vec![64, 96]))
        .with_replay_protection(true);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..6].copy_from_slice(b"bucket");

    let len = encode_packet_in_place(
        &mut encoded,
        6,
        &settings,
        &state,
        PacketDirection::Bidirectional,
        0,
    )
    .unwrap();

    assert!([64, 96].contains(&len));
    assert_eq!(
        decode_packet(&encoded[..len], &settings).unwrap(),
        b"bucket"
    );
}

#[test]
fn framed_zero_payload_decodes_as_chaff() {
    let settings = test_settings(Some(0xAA)).with_replay_protection(true);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];

    let len = encode_packet_in_place(
        &mut encoded,
        0,
        &settings,
        &state,
        PacketDirection::Bidirectional,
        0,
    )
    .unwrap();

    assert_eq!(
        decode_packet(&encoded[..len], &settings),
        Err(PacketDecodeError::ChaffFrame)
    );
}

#[test]
fn framed_decode_uses_in_band_salt_without_encode_state() {
    let settings = test_settings(Some(0xAA)).with_replay_protection(true);
    let state = PacketEncodeState::with_salt(*b"fedcba9876543210", 0);
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..8].copy_from_slice(b"salt-key");

    let len = encode_packet_in_place(
        &mut encoded,
        8,
        &settings,
        &state,
        PacketDirection::Bidirectional,
        0,
    )
    .unwrap();

    assert_eq!(
        decode_packet(&encoded[..len], &settings).unwrap(),
        b"salt-key"
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

fn encode_legacy_clear_counter_frame_in_place(
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
    buffer.copy_within(0..packet_len, payload_start);
    buffer[body_start..body_start + BODY_LEN_FIELD_LEN]
        .copy_from_slice(&(packet_len as u16).to_be_bytes());
    buffer[payload_start + packet_len..body_start + body_len].fill(0);

    write_legacy_clear_counter_frame_header(buffer, settings, &state.session_salt, counter, epoch);

    match settings.encryption_mode {
        EncryptionMode::Xor => {
            let mask = framed_xor_mask(settings, &state.session_salt, direction, epoch)?;
            apply_xor_mask(&mut buffer[body_start..body_start + body_len], &*mask);
        }
        EncryptionMode::Aead => {
            let cipher = {
                let key = derive_key(settings, &state.session_salt, direction, epoch, b"aead")?;
                XChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|_| PacketEncodeError::AeadEncrypt)?
            };
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

fn write_legacy_clear_counter_frame_header(
    buffer: &mut [u8],
    settings: &WgPacketObfuscation,
    salt: &[u8; FRAME_SALT_LEN],
    counter: u64,
    epoch: u32,
) {
    buffer[0] = FRAME_VERSION;
    buffer[1] = frame_flags(settings);
    let marker_position = marker_position(settings, salt, counter, buffer[1]);
    buffer[2] = (marker_position as u8) ^ marker_mask(settings, salt, counter);
    buffer[3..19].copy_from_slice(salt);
    buffer[19..27].copy_from_slice(&counter.to_be_bytes());
    buffer[27..31].copy_from_slice(&epoch.to_be_bytes());
    fill_marker_zone(
        &mut buffer[31..39],
        settings,
        salt,
        counter,
        marker_position,
    );
}

#[test]
fn legacy_hot_path_preserves_payload_offset_without_copying() {
    let settings = WgPacketObfuscation::new(b"offset-key".to_vec(), Some(0xAA)).unwrap();
    let packet = b"wireguard-payload";
    let packet_start = packet_encode_headroom(&settings);
    let mut buffer = vec![0_u8; 128];
    buffer[packet_start..packet_start + packet.len()].copy_from_slice(packet);

    let encoded = encode_packet_in_place_with_headroom(
        &mut buffer,
        packet_start,
        packet.len(),
        &settings,
        &PacketEncodeState::new(0),
        PacketDirection::ClientToServer,
        0,
    )
    .unwrap();
    assert_eq!(encoded.start, 0);

    let decoded = decode_packet_in_place_view(
        &mut buffer,
        encoded.len(),
        &settings,
        None,
        PacketDirection::ClientToServer,
    )
    .unwrap();
    assert_eq!(decoded.start, packet_start);
    assert_eq!(&buffer[decoded], packet);
}

#[test]
fn framed_aead_hot_path_preserves_payload_offset_without_copying() {
    let settings = WgPacketObfuscation::new(b"offset-aead-key".to_vec(), Some(0xAA)).unwrap()
        .with_encryption_mode(EncryptionMode::Aead)
        .with_replay_protection(true);
    let packet = b"framed-wireguard-payload";
    let packet_start = packet_encode_headroom(&settings);
    let mut buffer = vec![0_u8; 256];
    buffer[packet_start..packet_start + packet.len()].copy_from_slice(packet);

    let encoded = encode_packet_in_place_with_headroom(
        &mut buffer,
        packet_start,
        packet.len(),
        &settings,
        &PacketEncodeState::new(0),
        PacketDirection::ClientToServer,
        0,
    )
    .unwrap();
    let mut replay = ReplayWindow::default();
    let decoded = decode_packet_in_place_view(
        &mut buffer,
        encoded.len(),
        &settings,
        Some(&mut replay),
        PacketDirection::ClientToServer,
    )
    .unwrap();

    assert_eq!(decoded.start, packet_start);
    assert_eq!(&buffer[decoded], packet);
}
