//! TLS ClientHello inspection helpers for tunnel traffic.
//!
//! These helpers inspect the first bytes of a TLS handshake without consuming
//! the stream, extracting lightweight fingerprint fields used for heuristics
//! and audit output. They do not terminate TLS or modify the connection.

use std::fmt::Write;
use std::time::{Duration, Instant};

/// Hold parsed TLS fingerprint details for a prospective tunnel.
///
/// Future work: a fragmented-ClientHello parser can replace this bounded peek
/// path once the cutover contract is stable. For now the proxy keeps the
/// simpler low-overhead preview model.
#[derive(Clone, Debug, Default)]
pub(crate) struct TlsInfo {
    pub(crate) sni: Option<String>,
    pub(crate) alpn: Option<String>,
    pub(crate) tls_ver: Option<String>,
    pub(crate) cipher_suites_count: Option<u8>,
    pub(crate) ja3_lite: Option<String>,
}

#[derive(Debug)]
enum ParseTlsInfoStatus {
    Complete(TlsInfo),
    Incomplete,
    Invalid,
}

/// Peek at the initial bytes of a TCP stream and extract TLS ClientHello metadata without consuming the stream.
///
/// Attempts to read up to 512 bytes from `stream` using a 500ms timeout; if bytes are available before the timeout,
/// the bytes are parsed for ClientHello-derived fields (SNI, ALPN, TLS version, cipher-suites count, and a compact
/// `ja3_lite` fingerprint). The underlying stream is not advanced by this operation; on timeout, read error, or
/// parse failure the returned `TlsInfo` may have fields set to `None`.
///
/// # Returns
///
/// `TlsInfo` containing any successfully extracted metadata: `sni`, `alpn`, `tls_ver`, `cipher_suites_count`,
/// and `ja3_lite`. Fields are `None` when the corresponding information is absent or could not be parsed.
///
/// # Examples
///
/// ```no_run
/// # async fn example(mut stream: tokio::net::TcpStream) {
/// let info = crate::tunnel::tls::peek_tls_info(&mut stream).await;
/// println!("{:?}", info);
/// # }
/// ```
pub(crate) async fn peek_tls_info(stream: &mut tokio::net::TcpStream) -> TlsInfo {
    const MAX_PEEK_BYTES: usize = 8192;
    const INITIAL_PEEK_BYTES: usize = 512;
    const TOTAL_TIMEOUT: Duration = Duration::from_millis(500);
    const RETRY_INTERVAL: Duration = Duration::from_millis(25);

    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let mut peek_bytes = INITIAL_PEEK_BYTES;
    loop {
        let mut buf = vec![0u8; peek_bytes];
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return TlsInfo::default();
        };
        let n = tokio::time::timeout(remaining, stream.peek(&mut buf))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0);
        if n == 0 {
            return TlsInfo::default();
        }

        match parse_tls_info_status(&buf[..n]) {
            ParseTlsInfoStatus::Complete(info) => return info,
            ParseTlsInfoStatus::Invalid => return TlsInfo::default(),
            ParseTlsInfoStatus::Incomplete => {
                if peek_bytes < MAX_PEEK_BYTES {
                    peek_bytes = (peek_bytes * 2).min(MAX_PEEK_BYTES);
                }
                if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                    if remaining > RETRY_INTERVAL {
                        tokio::time::sleep(RETRY_INTERVAL).await;
                        continue;
                    }
                }
                return TlsInfo::default();
            }
        }
    }
}

/// Parse ClientHello metadata from a TLS record without panicking.
#[cfg(test)]
pub(crate) fn parse_tls_info(buf: &[u8]) -> TlsInfo {
    match parse_tls_info_status(buf) {
        ParseTlsInfoStatus::Complete(info) => info,
        ParseTlsInfoStatus::Incomplete | ParseTlsInfoStatus::Invalid => TlsInfo::default(),
    }
}

fn parse_tls_info_status(buf: &[u8]) -> ParseTlsInfoStatus {
    let mut info = TlsInfo::default();
    if buf.len() < 5 {
        return ParseTlsInfoStatus::Incomplete;
    }

    let mut pos = 0usize;
    let mut handshake = Vec::new();
    while pos + 5 <= buf.len() {
        let content_type = buf[pos];
        let version = (buf[pos + 1], buf[pos + 2]);
        let record_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        let available_end = (pos + 5 + record_len).min(buf.len());
        if content_type != 22 {
            return if handshake.is_empty() {
                ParseTlsInfoStatus::Invalid
            } else {
                ParseTlsInfoStatus::Incomplete
            };
        }
        if info.tls_ver.is_none() {
            info.tls_ver = record_tls_version(version);
        }
        handshake.extend_from_slice(&buf[pos + 5..available_end]);
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return ParseTlsInfoStatus::Invalid;
            }
            let client_hello_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            let total_len = 4 + client_hello_len;
            if handshake.len() >= total_len {
                return parse_client_hello(&handshake[..total_len], info);
            }
        }
        if available_end < pos + 5 + record_len {
            return ParseTlsInfoStatus::Incomplete;
        }
        pos += 5 + record_len;
    }

    ParseTlsInfoStatus::Incomplete
}

fn parse_client_hello(hs: &[u8], mut info: TlsInfo) -> ParseTlsInfoStatus {
    if hs.first() != Some(&1) || hs.len() < 6 {
        return ParseTlsInfoStatus::Invalid;
    }

    let mut pos = 4 + 2 + 32;
    let sid_len = match hs.get(pos) {
        Some(&v) => v as usize,
        None => return ParseTlsInfoStatus::Incomplete,
    };
    pos += 1 + sid_len;
    let cs_len = match hs.get(pos..pos + 2) {
        Some(s) => u16::from_be_bytes([s[0], s[1]]) as usize,
        None => return ParseTlsInfoStatus::Incomplete,
    };
    info.cipher_suites_count = Some((cs_len / 2).min(255) as u8);
    let cs_start = pos + 2;
    let cs_end = cs_start + cs_len;
    pos += 2 + cs_len;
    let cm_len = match hs.get(pos) {
        Some(&v) => v as usize,
        None => return ParseTlsInfoStatus::Incomplete,
    };
    pos += 1 + cm_len;
    if pos + 2 > hs.len() {
        return ParseTlsInfoStatus::Incomplete;
    }
    let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(hs.len());

    let mut ext_types: Vec<u16> = Vec::new();
    let mut curves: Vec<u16> = Vec::new();
    let mut point_fmts: Vec<u8> = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        let ext_data = match hs.get(pos..pos + ext_len) {
            Some(s) => s,
            None => return ParseTlsInfoStatus::Incomplete,
        };
        if ext_type & 0x0f0f != 0x0a0a {
            ext_types.push(ext_type);
        }
        match ext_type {
            0 if ext_len >= 5 => {
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                if ext_data.len() >= 5 + name_len {
                    info.sni = String::from_utf8(ext_data[5..5 + name_len].to_vec()).ok();
                }
            }
            16 if ext_len >= 4 => {
                let proto_len = ext_data[2] as usize;
                if ext_data.len() >= 3 + proto_len {
                    info.alpn = String::from_utf8(ext_data[3..3 + proto_len].to_vec()).ok();
                }
            }
            43 if ext_len >= 3 => {
                let list_len = ext_data[0] as usize;
                let mut i = 1;
                while i + 2 <= (1 + list_len).min(ext_data.len()) {
                    if ext_data[i] == 0x03 && ext_data[i + 1] == 0x04 {
                        info.tls_ver = Some("TLS1.3".into());
                        break;
                    }
                    i += 2;
                }
            }
            10 if ext_len >= 4 => {
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut i = 2;
                while i + 2 <= (2 + list_len).min(ext_data.len()) {
                    let g = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
                    if g & 0x0f0f != 0x0a0a {
                        curves.push(g);
                    }
                    i += 2;
                }
            }
            11 if ext_len >= 2 => {
                let list_len = ext_data[0] as usize;
                for &b in ext_data.get(1..1 + list_len).unwrap_or(&[]) {
                    point_fmts.push(b);
                }
            }
            _ => {}
        }
        pos += ext_len;
    }

    let tls_ver_num: u16 = match info.tls_ver.as_deref() {
        Some("TLS1.3") => 772,
        Some("TLS1.2") => 771,
        Some("TLS1.0") => 769,
        _ => 0,
    };
    let cs_nums: Vec<u16> = hs
        .get(cs_start..cs_end)
        .unwrap_or(&[])
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&v| v & 0x0f0f != 0x0a0a)
        .collect();

    let mut ja3 = String::with_capacity(128);
    append_joined_u16(&mut ja3, &[tls_ver_num]);
    ja3.push(',');
    append_joined_u16(&mut ja3, &cs_nums);
    ja3.push(',');
    append_joined_u16(&mut ja3, &ext_types);
    ja3.push(',');
    append_joined_u16(&mut ja3, &curves);
    ja3.push(',');
    append_joined_u8(&mut ja3, &point_fmts);
    info.ja3_lite = Some(ja3);
    ParseTlsInfoStatus::Complete(info)
}

fn record_tls_version(version: (u8, u8)) -> Option<String> {
    match version {
        (3, 4) => Some("TLS1.3".into()),
        (3, 3) => Some("TLS1.2".into()),
        (3, 1) => Some("TLS1.0".into()),
        _ => None,
    }
}

/// Append u16 values to `out`, joining them with `-`.
///
/// The values are formatted in decimal and appended in order.
///
/// # Examples
///
/// ```
/// let mut s = String::new();
/// append_joined_u16(&mut s, &[256, 65535, 0]);
/// assert_eq!(s, "256-65535-0");
/// ```
fn append_joined_u16(out: &mut String, values: &[u16]) {
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push('-');
        }
        let _ = write!(out, "{value}");
    }
}

/// Appends the decimal representations of `values` to `out`, separated by `-`.
///
/// # Examples
///
/// ```
/// let mut s = String::new();
/// append_joined_u8(&mut s, &[1, 2, 3]);
/// assert_eq!(s, "1-2-3");
/// ```
fn append_joined_u8(out: &mut String, values: &[u8]) {
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push('-');
        }
        let _ = write!(out, "{value}");
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_tls_info, parse_tls_info_status, ParseTlsInfoStatus};

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
}
