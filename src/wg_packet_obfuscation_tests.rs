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

    let mask = framed_xor_mask(&settings, &salt, PacketDirection::Bidirectional, 0);

    assert_ne!(mask, settings.key);
    assert_eq!(mask.len(), 32);
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
