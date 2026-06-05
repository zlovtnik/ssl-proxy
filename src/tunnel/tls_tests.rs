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
