use super::{consume_tls_prefix, parse_tls_info, parse_tls_info_status, ParseTlsInfoStatus};

fn crafted_client_hello() -> Vec<u8> {
    let sni = b"example.com";
    let mut sni_ext = vec![0x00, 0x00];
    let mut sni_data = Vec::new();
    sni_data.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
    sni_data.push(0x00);
    sni_data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(sni);
    sni_ext.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_data);

    let alpn = b"h2";
    let mut alpn_ext = vec![0x00, 0x10];
    let mut alpn_data = Vec::new();
    alpn_data.extend_from_slice(&((alpn.len() + 1) as u16).to_be_bytes());
    alpn_data.push(alpn.len() as u8);
    alpn_data.extend_from_slice(alpn);
    alpn_ext.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
    alpn_ext.extend_from_slice(&alpn_data);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
    body.extend_from_slice(&[0x01, 0x00]);
    let extensions_len = (sni_ext.len() + alpn_ext.len()) as u16;
    body.extend_from_slice(&extensions_len.to_be_bytes());
    body.extend_from_slice(&sni_ext);
    body.extend_from_slice(&alpn_ext);

    let mut handshake = vec![0x01];
    handshake.push(((body.len() >> 16) & 0xff) as u8);
    handshake.push(((body.len() >> 8) & 0xff) as u8);
    handshake.push((body.len() & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Verifies that a crafted TLS ClientHello is parsed into the expected `TlsInfo` fields.
///
/// # Examples
///
/// ```
/// let client_hello: &[u8] = &[
///     0x16, // ContentType: Handshake
///     0x03, 0x03, // TLS 1.2
///     0x00, 0x4d, // Record length
///     0x01, // HandshakeType: ClientHello
///     0x00, 0x00, 0x49, // Handshake length
///     0x03, 0x03, // Client version TLS 1.2
///     // Random (32 bytes)
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, // Session ID length
///     0x00, 0x04, // Cipher suites length (2 suites)
///     0x13, 0x01, // TLS_AES_256_GCM_SHA384
///     0x13, 0x02, // TLS_CHACHA20_POLY1305_SHA256
///     0x01, // Compression methods length
///     0x00, // NULL compression
///     0x00, 0x1d, // Extensions length
///     // SNI extension
///     0x00, 0x00, // Extension type: SNI
///     0x00, 0x10, // Extension length
///     0x00, 0x0e, // Server name list length
///     0x00, // Name type: host_name
///     0x00, 0x0b, // Name length
///     b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
///     // ALPN extension
///     0x00, 0x10, // Extension type: ALPN
///     0x00, 0x05, // Extension length
///     0x00, 0x03, // Protocol list length
///     0x02, // Protocol length
///     b'h', b'2',
/// ];
///
/// let info = parse_tls_info(client_hello);
///
/// assert_eq!(info.sni, Some("example.com".to_string()));
/// assert_eq!(info.alpn, Some("h2".to_string()));
/// assert_eq!(info.tls_ver, Some("TLS1.2".to_string()));
/// assert_eq!(info.cipher_suites_count, Some(2));
/// assert!(info.ja3_lite.is_some());
/// ```
#[test]
fn parses_crafted_client_hello() {
    let client_hello = crafted_client_hello();

    let info = parse_tls_info(&client_hello);

    assert_eq!(info.sni, Some("example.com".to_string()));
    assert_eq!(info.alpn, Some("h2".to_string()));
    assert_eq!(info.tls_ver, Some("TLS1.2".to_string()));
    assert_eq!(info.cipher_suites_count, Some(2));
    assert!(info.ja3_lite.is_some());
    assert!(info.ja4.is_some());
    assert_eq!(info.evidence()["ja4_evidence"]["status"], "available");
}

fn ja4_client_hello(ciphers: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for cipher in ciphers {
        body.extend_from_slice(&cipher.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);
    let mut extension_bytes = Vec::new();
    for (kind, data) in extensions {
        extension_bytes.extend_from_slice(&kind.to_be_bytes());
        extension_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extension_bytes.extend_from_slice(data);
    }
    body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&extension_bytes);
    let mut handshake = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn ja4_matches_pinned_foxio_specification_vector() {
    // FoxIO-LLC/ja4@c6469a7b, technical_details/JA4.md example.
    let ciphers = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let mut extensions: Vec<(u16, Vec<u8>)> = [
        0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
        0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
    ]
    .into_iter()
    .map(|kind| (kind, Vec::new()))
    .collect();
    for (kind, data) in &mut extensions {
        *data = match kind {
            0 => vec![0, 4, 0, 0, 1, b'a'],
            16 => vec![0, 3, 2, b'h', b'2'],
            43 => vec![2, 3, 4],
            13 => vec![0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1],
            _ => Vec::new(),
        };
    }
    let expected = "t13d1516h2_8daaf6152771_e5627efa2ab1";
    let record = ja4_client_hello(&ciphers, &extensions);
    let info = parse_tls_info(&record);
    assert_eq!(info.ja4.as_deref(), Some(expected));
    let legacy = info.ja3_lite.clone();
    extensions.reverse();
    let mut reordered_ciphers = ciphers.to_vec();
    reordered_ciphers.reverse();
    let reordered = parse_tls_info(&ja4_client_hello(&reordered_ciphers, &extensions));
    assert_eq!(reordered.ja4.as_deref(), Some(expected));
    assert_ne!(reordered.ja3_lite, legacy);

    extensions.push((0x2a2a, vec![0, 1]));
    reordered_ciphers.push(0x1a1a);
    assert_eq!(
        parse_tls_info(&ja4_client_hello(&reordered_ciphers, &extensions)).ja4,
        info.ja4
    );
    let (_, signatures) = extensions.iter_mut().find(|(kind, _)| *kind == 13).unwrap();
    // Change algorithm order while preserving each algorithm's two bytes.
    signatures.swap(2, 4);
    signatures.swap(3, 5);
    assert_ne!(
        parse_tls_info(&ja4_client_hello(&ciphers, &extensions)).ja4,
        info.ja4
    );
}

#[test]
fn ja4_absent_sni_and_alpn_and_binary_alpn_follow_specification() {
    let ciphers = [0x1301];
    let plain = parse_tls_info(&ja4_client_hello(&ciphers, &[]));
    assert!(plain.ja4.as_deref().unwrap().starts_with("t12i010000_"));
    assert!(plain.ja4.as_deref().unwrap().ends_with("_000000000000"));
    for (value, code) in [
        (vec![b'h', b'2'], "h2"),
        (b"http/1.1".to_vec(), "h1"),
        (vec![b'x'], "xx"),
        (vec![0xab], "ab"),
        (vec![0x20, 0x61], "21"),
        (vec![0x30, 0xab, 0xcd, 0x31], "01"),
        (vec![], "00"),
    ] {
        let mut data = vec![0, (value.len() + 1) as u8, value.len() as u8];
        data.extend_from_slice(&value);
        let result = parse_tls_info(&ja4_client_hello(&ciphers, &[(16, data)]));
        assert!(result
            .ja4
            .as_deref()
            .unwrap()
            .starts_with(&format!("t12i0101{code}_")));
    }
}

#[test]
fn ja4_rejects_invalid_required_inputs_without_relabeling_legacy_values() {
    let ciphers = [0x1301];
    let unsupported = [
        vec![(43, vec![3, 3, 4, 3])],          // odd supported-version vector
        vec![(43, vec![2, 0x2a, 0x2a])],       // GREASE-only versions
        vec![(13, vec![0, 3, 4, 3, 4])],       // odd signature vector
        vec![(16, vec![0, 3, 5, b'h', b'2'])], // truncated ALPN value
        vec![(0, vec![0, 4, 0, 0, 5, b'a'])],  // truncated SNI
        vec![(43, vec![2, 3, 4]), (43, vec![2, 3, 3])],
    ];
    for extensions in unsupported {
        let result = parse_tls_info(&ja4_client_hello(&ciphers, &extensions));
        assert!(result.ja4.is_none());
        assert_eq!(result.evidence()["ja4_evidence"]["status"], "unavailable");
        assert!(result.evidence()["ja4_evidence"]["fingerprint"].is_null());
    }
    let record = crafted_client_hello();
    for end in 0..record.len() {
        assert!(parse_tls_info(&record[..end]).ja4.is_none());
    }
    let legacy = super::TlsInfo {
        parse_status: "parsed",
        ja3_lite: Some("771,4865-4866,0-16,29-23,0".to_string()),
        ..Default::default()
    };
    assert!(legacy.evidence()["ja4_evidence"]["fingerprint"].is_null());
}

#[test]
fn ja4_ignores_grease_in_version_and_signature_lists_and_retains_scsv() {
    let baseline = ja4_client_hello(
        &[0x1301, 0x00ff, 0x5600, 0xfe00],
        &[(43, vec![2, 3, 4]), (13, vec![0, 4, 4, 3, 8, 4])],
    );
    let greased = ja4_client_hello(
        &[0x1301, 0x00ff, 0x5600, 0xfe00, 0x0a0a],
        &[
            (43, vec![4, 0x2a, 0x2a, 3, 4]),
            (13, vec![0, 6, 4, 3, 0x3a, 0x3a, 8, 4]),
            (0x4a4a, vec![]),
        ],
    );
    let original = parse_tls_info(&baseline);
    assert!(original.ja4.as_deref().unwrap().starts_with("t13i040200_"));
    assert_eq!(original.ja4, parse_tls_info(&greased).ja4);
    // 0x1a2a is not a GREASE value despite sharing GREASE low nibbles.
    let reserved = parse_tls_info(&ja4_client_hello(&[0x1301, 0x1a2a], &[]));
    assert!(reserved.ja4.as_deref().unwrap().starts_with("t12i020000_"));
}

#[test]
fn parses_fragmented_client_hello_across_tls_records() {
    let client_hello = crafted_client_hello();
    let payload = &client_hello[5..];
    let split_at = 24;
    let first = &payload[..split_at];
    let second = &payload[split_at..];

    let mut fragmented = Vec::new();
    fragmented.extend_from_slice(&[0x16, 0x03, 0x03]);
    fragmented.extend_from_slice(&(first.len() as u16).to_be_bytes());
    fragmented.extend_from_slice(first);
    fragmented.extend_from_slice(&[0x16, 0x03, 0x03]);
    fragmented.extend_from_slice(&(second.len() as u16).to_be_bytes());
    fragmented.extend_from_slice(second);

    let info = parse_tls_info(&fragmented);
    assert_eq!(info.sni.as_deref(), Some("example.com"));
    assert_eq!(info.alpn.as_deref(), Some("h2"));
    assert_eq!(info.cipher_suites_count, Some(2));
}

#[test]
fn offered_version_uses_handshake_and_supported_versions() {
    for (versions, expected) in [
        (None, Some("TLS1.2")),
        (Some(vec![4, 3, 3, 3, 4]), Some("TLS1.3")),
        (Some(vec![4, 3, 2, 3, 1]), Some("TLS1.1")),
        (Some(vec![4, 0x0a, 0x0a, 3, 3]), Some("TLS1.2")),
        (Some(vec![2, 0x0a, 0x0a]), None),
        (Some(vec![3, 3, 4, 3]), None),
    ] {
        let mut hello = crafted_client_hello();
        hello[2] = 1;
        if let Some(versions) = versions {
            let extension_len = u16::from_be_bytes([hello[52], hello[53]]) as usize;
            let mut extension = vec![0, 43];
            extension.extend_from_slice(&(versions.len() as u16).to_be_bytes());
            extension.extend_from_slice(&versions);
            hello[52..54]
                .copy_from_slice(&((extension_len + extension.len()) as u16).to_be_bytes());
            hello.extend_from_slice(&extension);
            let record_len = hello.len() - 5;
            hello[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
            let handshake_len = hello.len() - 9;
            hello[6..9].copy_from_slice(&(handshake_len as u32).to_be_bytes()[1..]);
        }
        let info = parse_tls_info(&hello);
        assert_eq!(info.parse_status, "parsed");
        assert_eq!(info.offered_version.as_deref(), expected);
    }
}

#[test]
fn handles_invalid_input() {
    let info = parse_tls_info(&[]);
    assert_eq!(info.sni, None);
    assert_eq!(info.alpn, None);
    assert_eq!(info.tls_ver, None);

    let info = parse_tls_info(&[0x17, 0x03, 0x03, 0x00, 0x00]);
    assert_eq!(info.tls_ver, None);
}

#[test]
fn marks_partial_client_hello_as_incomplete() {
    let client_hello = crafted_client_hello();
    let partial = &client_hello[..12];
    assert!(matches!(
        parse_tls_info_status(partial),
        ParseTlsInfoStatus::Incomplete
    ));
    assert_eq!(parse_tls_info(partial).sni, None);
}

#[tokio::test]
async fn consumes_tls_prefix_without_dropping_bytes() {
    let client_hello = crafted_client_hello();
    let (mut client, mut server) = tokio::io::duplex(16_384);
    let expected = client_hello.clone();

    let writer = tokio::spawn(async move {
        tokio::io::AsyncWriteExt::write_all(&mut client, &client_hello)
            .await
            .unwrap();
    });

    let prefix = consume_tls_prefix(&mut server).await.unwrap();
    writer.await.unwrap();

    assert_eq!(prefix.bytes, expected);
    assert_eq!(prefix.tls.sni.as_deref(), Some("example.com"));
    assert_eq!(prefix.tls.alpn.as_deref(), Some("h2"));
}

#[tokio::test]
async fn consumes_non_tls_prefix_with_empty_metadata() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    let writer = tokio::spawn(async move {
        tokio::io::AsyncWriteExt::write_all(&mut client, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
    });

    let prefix = consume_tls_prefix(&mut server).await.unwrap();
    writer.await.unwrap();

    assert_eq!(prefix.bytes, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(prefix.tls.sni, None);
    assert_eq!(prefix.tls.ja3_lite, None);
}
