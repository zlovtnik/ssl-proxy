use proptest::prelude::*;

use super::*;

fn test_settings() -> WgPacketObfuscation {
    WgPacketObfuscation::new(b"test-obfuscation-key-32-bytes-aaaaaa".to_vec()).unwrap()
}

fn fixed_state() -> PacketEncodeState {
    PacketEncodeState::with_salt(*b"0123456789abcdef")
}

#[test]
fn constructor_rejects_empty_key() {
    assert_eq!(
        WgPacketObfuscation::new(Vec::<u8>::new()),
        Err(WgPacketObfuscationError::EmptyKey)
    );
}

#[test]
fn constructor_rejects_short_keys() {
    assert_eq!(
        WgPacketObfuscation::new(b"short".to_vec()),
        Err(WgPacketObfuscationError::KeyTooShort {
            len: 5,
            min: MIN_OBFUSCATION_KEY_LEN,
        })
    );
}

#[test]
fn aead_is_the_default_mode() {
    let settings = test_settings();
    assert_eq!(settings.encryption_mode, EncryptionMode::Aead);
}

#[test]
fn encoded_len_bounds_cover_xor_and_aead_overhead() {
    let framed_xor = test_settings().with_encryption_mode(EncryptionMode::Xor);
    let framed_aead = test_settings();

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
    let fixed = test_settings().with_padding(PacketPadding::FixedMtu(1200));
    let random = test_settings().with_padding(PacketPadding::RandomBucket(vec![200, 512, 1400]));
    let power_two = test_settings().with_padding(PacketPadding::PowerOfTwo);

    assert_eq!(
        encoded_packet_len_bounds(100, &fixed).unwrap().max_encoded_len,
        1200
    );
    assert_eq!(
        encoded_packet_len_bounds(100, &random).unwrap(),
        EncodedPacketLenBounds {
            plaintext_len: 100,
            min_encoded_len: 200,
            max_encoded_len: 1400,
            unpadded_encoded_len: FRAMED_HEADER_LEN + FRAMED_BODY_LEN_FIELD_LEN + 100 + AEAD_TAG_LEN_BYTES,
        }
    );
    assert_eq!(
        encoded_packet_len_bounds(100, &power_two)
            .unwrap()
            .max_encoded_len,
        FRAMED_HEADER_LEN + AEAD_TAG_LEN_BYTES
            + (FRAMED_BODY_LEN_FIELD_LEN + 100).next_power_of_two()
    );
}

#[test]
fn encoded_len_bounds_reject_too_small_fixed_mtu() {
    let settings = test_settings().with_padding(PacketPadding::FixedMtu(64));

    assert_eq!(
        encoded_packet_len_bounds(100, &settings),
        Err(PacketEncodeError::FixedMtuTooSmall {
            mtu: 64,
            required: FRAMED_HEADER_LEN + AEAD_TAG_LEN_BYTES + FRAMED_BODY_LEN_FIELD_LEN + 100,
        })
    );
}

#[test]
fn aead_round_trips_with_replay_window() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..11].copy_from_slice(b"hello-aead!");

    let len = encode_packet_in_place(
        &mut encoded,
        11,
        &settings,
        &state,
        PacketDirection::ClientToServer,
    )
    .unwrap();
    let mut replay = SessionReplayWindow::default();
    let decoded_len = decode_packet_in_place(
        &mut encoded,
        len,
        &settings,
        &mut replay,
        PacketDirection::ClientToServer,
    )
    .unwrap();

    assert_eq!(&encoded[..decoded_len], b"hello-aead!");
}

#[test]
fn xor_mode_round_trips_with_replay_window() {
    let settings = test_settings().with_encryption_mode(EncryptionMode::Xor);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..9].copy_from_slice(b"xor-frame");

    let len = encode_packet_in_place(
        &mut encoded,
        9,
        &settings,
        &state,
        PacketDirection::ClientToServer,
    )
    .unwrap();
    let mut replay = SessionReplayWindow::default();
    let decoded_len = decode_packet_in_place(
        &mut encoded,
        len,
        &settings,
        &mut replay,
        PacketDirection::ClientToServer,
    )
    .unwrap();

    assert_eq!(&encoded[..decoded_len], b"xor-frame");
}

#[test]
fn aead_rejects_tampered_ciphertext() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..6].copy_from_slice(b"secret");

    let len = encode_packet_in_place(
        &mut encoded,
        6,
        &settings,
        &state,
        PacketDirection::ClientToServer,
    )
    .unwrap();
    encoded[len - AEAD_TAG_LEN - 1] ^= 0x40;

    let mut replay = SessionReplayWindow::default();
    assert_eq!(
        decode_packet_in_place(
            &mut encoded,
            len,
            &settings,
            &mut replay,
            PacketDirection::ClientToServer,
        ),
        Err(PacketDecodeError::AuthFailed)
    );
}

#[test]
fn replay_window_rejects_duplicate_counter() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..6].copy_from_slice(b"replay");

    let len = encode_packet_in_place(
        &mut encoded,
        6,
        &settings,
        &state,
        PacketDirection::ClientToServer,
    )
    .unwrap();
    let original = encoded[..len].to_vec();
    let mut replay = SessionReplayWindow::default();
    assert!(decode_packet_in_place(
        &mut encoded,
        len,
        &settings,
        &mut replay,
        PacketDirection::ClientToServer,
    )
    .is_ok());

    encoded[..len].copy_from_slice(&original);
    assert_eq!(
        decode_packet_in_place(
            &mut encoded,
            len,
            &settings,
            &mut replay,
            PacketDirection::ClientToServer,
        ),
        Err(PacketDecodeError::ReplayDetected)
    );
}

#[test]
fn salt_change_resets_replay_window_so_restarts_are_not_replays() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..8].copy_from_slice(b"restart!");

    let len = encode_packet_in_place(
        &mut encoded,
        8,
        &settings,
        &state,
        PacketDirection::ClientToServer,
    )
    .unwrap();
    let mut replay = SessionReplayWindow::default();
    decode_packet_in_place(
        &mut encoded,
        len,
        &settings,
        &mut replay,
        PacketDirection::ClientToServer,
    )
    .unwrap();

    // Advance the same window far past counter 0, then simulate a peer
    // restart: a fresh salt makes counter 0 legitimate again.
    for counter in 1..200u64 {
        replay
            .check_and_update(&[0u8; FRAME_SALT_LEN], counter)
            .unwrap();
    }
    assert_eq!(
        replay.check_and_update(&[0u8; FRAME_SALT_LEN], 0),
        Err(PacketDecodeError::ReplayDetected)
    );
    replay
        .check_and_update(&[9u8; FRAME_SALT_LEN], 0)
        .unwrap();
}

#[test]
fn header_tag_rejects_forged_headers() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..7].copy_from_slice(b"forgery");

    let len = encode_packet_in_place(
        &mut encoded,
        6,
        &settings,
        &state,
        PacketDirection::ClientToServer,
    )
    .unwrap();

    // Flip one header tag byte: validation must fail without creating state.
    let mut forged = encoded[..len].to_vec();
    forged[26] ^= 0x01;
    assert_eq!(
        validate_framed_header(
            &forged,
            len,
            &settings,
            PacketDirection::ClientToServer,
        ),
        Err(PacketDecodeError::HeaderTagMismatch)
    );

    // Flip one salt byte: the tag no longer matches the covered header.
    let mut forged = encoded[..len].to_vec();
    forged[2] ^= 0x01;
    assert_eq!(
        validate_framed_header(
            &forged,
            len,
            &settings,
            PacketDirection::ClientToServer,
        ),
        Err(PacketDecodeError::HeaderTagMismatch)
    );

    // Flip the masked counter: the tag no longer matches.
    let mut forged = encoded[..len].to_vec();
    forged[18] ^= 0x01;
    assert_eq!(
        validate_framed_header(
            &forged,
            len,
            &settings,
            PacketDirection::ClientToServer,
        ),
        Err(PacketDecodeError::HeaderTagMismatch)
    );
}

#[test]
fn header_tag_is_direction_bound() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..9].copy_from_slice(b"direction");

    let len = encode_packet_in_place(
        &mut encoded,
        10,
        &settings,
        &state,
        PacketDirection::ClientToServer,
    )
    .unwrap();

    // A client-to-server frame reflected back must fail tag validation in
    // the server-to-client direction.
    assert_eq!(
        validate_framed_header(
            &encoded[..len],
            len,
            &settings,
            PacketDirection::ServerToClient,
        ),
        Err(PacketDecodeError::HeaderTagMismatch)
    );
    assert_eq!(
        validate_framed_header(
            &encoded[..len],
            len,
            &settings,
            PacketDirection::ClientToServer,
        ),
        Ok(())
    );
}

#[test]
fn header_bytes_do_not_leak_raw_key_bytes() {
    // The v1 marker zone XORed raw key bytes with the cleartext salt; a
    // passive observer could recover the whole configured key. The v2
    // header must not be a function of key bytes that is invertible without
    // the key: flipping key bits must change the header unpredictably and
    // no header byte may equal a plain key byte for all frames.
    let mut key_material = vec![0u8; 32];
    for (index, byte) in key_material.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let settings_a = WgPacketObfuscation::new(key_material.clone()).unwrap();
    let settings_b = WgPacketObfuscation::new({
        let mut other = key_material.clone();
        other[0] ^= 0x01;
        other
    })
    .unwrap();

    let state = fixed_state();
    let packet = b"leakage-probe";
    let mut encoded_a = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded_a[..packet.len()].copy_from_slice(packet);
    let len_a = encode_packet_in_place(
        &mut encoded_a,
        packet.len(),
        &settings_a,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();

    let mut encoded_b = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded_b[..packet.len()].copy_from_slice(packet);
    let len_b = encode_packet_in_place(
        &mut encoded_b,
        packet.len(),
        &settings_b,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();

    // A single key-bit flip must change the on-wire header tag (position
    // 26..30): the tag is a keyed MAC over the header, not raw key bytes.
    assert_ne!(&encoded_a[26..30], &encoded_b[26..30]);

    // No header byte may be directly recoverable key material: the header
    // bytes must differ from the raw key slice for this deterministic salt.
    let header_a = &encoded_a[2..30];
    for window in key_material.windows(28) {
        assert_ne!(
            header_a,
            window,
            "v2 header must not embed raw contiguous key bytes"
        );
    }

    let _ = len_a;
    let _ = len_b;
}

#[test]
fn keystream_never_repeats_across_frames() {
    // Two frames carrying the same plaintext in the same session/direction
    // must not produce the same ciphertext bytes under XOR mode, or a
    // passive observer could XOR the frames together to cancel the mask.
    let settings = test_settings().with_encryption_mode(EncryptionMode::Xor);
    let state = fixed_state();
    let packet = vec![0x5Au8; 128];

    let mut first = vec![0u8; MAX_UDP_PACKET_SIZE];
    first[..packet.len()].copy_from_slice(&packet);
    let first_len = encode_packet_in_place(
        &mut first,
        packet.len(),
        &settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();

    let mut second = vec![0u8; MAX_UDP_PACKET_SIZE];
    second[..packet.len()].copy_from_slice(&packet);
    let second_len = encode_packet_in_place(
        &mut second,
        packet.len(),
        &settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();

    let first_body = &first[FRAMED_HEADER_LEN..first_len];
    let second_body = &second[FRAMED_HEADER_LEN..second_len];
    assert_eq!(first_body.len(), second_body.len());
    assert_ne!(
        first_body, second_body,
        "same-plaintext frames must not reuse keystream bytes"
    );

    // XOR of the two bodies must not be all zeros (mask cancellation).
    let cancelation: Vec<u8> = first_body
        .iter()
        .zip(second_body.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    assert!(
        cancelation.iter().any(|byte| *byte != 0),
        "keystream reuse would cancel identical plaintexts"
    );
}

#[test]
fn decode_rejects_zero_length_before_payload_branching() {
    let settings = test_settings();

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
    let settings = test_settings();
    let mut packet = vec![0u8; 4];

    assert_eq!(
        decode_packet_in_place(
            &mut packet,
            8,
            &settings,
            &mut SessionReplayWindow::default(),
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
    let settings = test_settings();
    let packet = vec![0u8; FRAMED_HEADER_LEN + FRAMED_BODY_LEN_FIELD_LEN];
    let packet_len = packet.len() + 1;

    assert_eq!(
        validate_framed_header(&packet, packet_len, &settings, PacketDirection::Bidirectional),
        Err(PacketDecodeError::PacketTooShort {
            actual: packet.len(),
            minimum: packet_len,
        })
    );
}

#[test]
fn decode_rejects_oversized_packet_as_too_large() {
    let settings = test_settings();
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
fn decode_rejects_unsupported_version() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..6].copy_from_slice(b"versio");

    let len = encode_packet_in_place(
        &mut encoded,
        6,
        &settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();
    encoded[0] = 1;

    assert_eq!(
        decode_packet(&encoded[..len], &settings),
        Err(PacketDecodeError::UnsupportedVersion(1))
    );
}

#[test]
fn decode_rejects_mode_mismatch() {
    let aead_settings = test_settings();
    let xor_settings = test_settings().with_encryption_mode(EncryptionMode::Xor);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..8].copy_from_slice(b"modemate");

    let len = encode_packet_in_place(
        &mut encoded,
        8,
        &aead_settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();

    assert_eq!(
        decode_packet(&encoded[..len], &xor_settings),
        Err(PacketDecodeError::UnsupportedMode)
    );
}

#[test]
fn padding_round_trips_and_rejects_modified_padding() {
    let settings = test_settings().with_padding(PacketPadding::PowerOfTwo);
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..7].copy_from_slice(b"padding");

    let len = encode_packet_in_place(
        &mut encoded,
        7,
        &settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();
    let clean = encoded[..len].to_vec();
    let decoded = decode_packet(&clean, &settings).unwrap();
    assert_eq!(decoded, b"padding");

    encoded[..len].copy_from_slice(&clean);
    encoded[len - 1] ^= 0x01;
    // AEAD covers the padded body and tag, so tampering any byte fails
    // authentication before padding is even inspected.
    assert_eq!(
        decode_packet(&encoded[..len], &settings),
        Err(PacketDecodeError::AuthFailed)
    );
}

#[test]
fn random_bucket_padding_uses_configured_mtu() {
    let settings = test_settings().with_padding(PacketPadding::RandomBucket(vec![256, 384]));
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..6].copy_from_slice(b"bucket");

    let len = encode_packet_in_place(
        &mut encoded,
        6,
        &settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();

    assert!(len == 256 || len == 384);
    assert_eq!(
        decode_packet(&encoded[..len], &settings).unwrap(),
        b"bucket"
    );
}

#[test]
fn framed_zero_payload_decodes_as_chaff() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];

    let len = encode_packet_in_place(
        &mut encoded,
        0,
        &settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();

    assert_eq!(
        decode_packet(&encoded[..len], &settings),
        Err(PacketDecodeError::ChaffFrame)
    );
}

#[test]
fn framed_decode_uses_in_band_salt_without_encode_state() {
    let settings = test_settings();
    let state = PacketEncodeState::with_salt(*b"fedcba9876543210");
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..8].copy_from_slice(b"salt-key");

    let len = encode_packet_in_place(
        &mut encoded,
        8,
        &settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();

    assert_eq!(
        decode_packet(&encoded[..len], &settings).unwrap(),
        b"salt-key"
    );
}

#[test]
fn direction_bound_keys_prevent_cross_direction_decoding() {
    let settings = test_settings();
    let state = fixed_state();
    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..9].copy_from_slice(b"crosswise");

    let len = encode_packet_in_place(
        &mut encoded,
        9,
        &settings,
        &state,
        PacketDirection::ClientToServer,
    )
    .unwrap();

    assert_eq!(
        decode_packet_in_place(
            &mut encoded,
            len,
            &settings,
            &mut SessionReplayWindow::default(),
            PacketDirection::ServerToClient,
        ),
        Err(PacketDecodeError::HeaderTagMismatch)
    );
}

#[test]
fn hot_path_preserves_payload_offset_without_copying() {
    let settings = test_settings();
    let packet = b"framed-wireguard-payload";
    let packet_start = packet_encode_headroom(&settings);
    let mut buffer = vec![0_u8; 256];
    buffer[packet_start..packet_start + packet.len()].copy_from_slice(packet);

    let encoded = encode_packet_in_place_with_headroom(
        &mut buffer,
        packet_start,
        packet.len(),
        &settings,
        &PacketEncodeState::new(),
        PacketDirection::ClientToServer,
    )
    .unwrap();
    let mut replay = SessionReplayWindow::default();
    let decoded = decode_packet_in_place_view(
        &mut buffer,
        encoded.len(),
        &settings,
        &mut replay,
        PacketDirection::ClientToServer,
    )
    .unwrap();

    assert_eq!(decoded.start, packet_start);
    assert_eq!(&buffer[decoded], packet);
}

#[test]
fn max_udp_sized_packet_round_trips() {
    let settings = test_settings();
    let state = fixed_state();
    let packet = vec![0xA5u8; MAX_UDP_PACKET_SIZE - FRAMED_HEADER_LEN - FRAMED_BODY_LEN_FIELD_LEN - AEAD_TAG_LEN_BYTES];

    let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
    encoded[..packet.len()].copy_from_slice(&packet);
    let len = encode_packet_in_place(
        &mut encoded,
        packet.len(),
        &settings,
        &state,
        PacketDirection::Bidirectional,
    )
    .unwrap();
    assert_eq!(len, MAX_UDP_PACKET_SIZE);

    assert_eq!(
        decode_packet(&encoded[..len], &settings).unwrap(),
        packet
    );
}

proptest! {
    #[test]
    fn aead_roundtrip_for_arbitrary_packets(
        packet in prop::collection::vec(any::<u8>(), 1..4096),
    ) {
        let settings = test_settings();
        let state = PacketEncodeState::new();

        let mut encoded = vec![0u8; MAX_UDP_PACKET_SIZE];
        encoded[..packet.len()].copy_from_slice(&packet);
        let len = encode_packet_in_place(
            &mut encoded,
            packet.len(),
            &settings,
            &state,
            PacketDirection::ClientToServer,
        )?;
        let mut replay = SessionReplayWindow::default();
        let decoded_len = decode_packet_in_place(
            &mut encoded,
            len,
            &settings,
            &mut replay,
            PacketDirection::ClientToServer,
        )?;
        prop_assert_eq!(&encoded[..decoded_len], &packet[..]);
    }
}