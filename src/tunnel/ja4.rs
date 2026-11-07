//! Independent TCP JA4 implementation from complete ClientHello inputs.
//!
//! Specification: FoxIO-LLC/ja4 technical_details/JA4.md at
//! c6469a7b0dbf8fe963810162429fbfd9d1acc4d5 (JA4 TLS client only).
//! https://github.com/FoxIO-LLC/ja4/blob/c6469a7b0dbf8fe963810162429fbfd9d1acc4d5/technical_details/JA4.md
//! Upstream JA4 is BSD-3-Clause; this independently written implementation does
//! not implement any of the separately licensed JA4+ methods.
//! https://github.com/FoxIO-LLC/ja4/blob/c6469a7b0dbf8fe963810162429fbfd9d1acc4d5/LICENSE-JA4

use sha2::{Digest, Sha256};

pub(super) const SPECIFICATION_REVISION: &str =
    "foxio-ja4-c6469a7b0dbf8fe963810162429fbfd9d1acc4d5";

fn grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value.to_be_bytes()[0] == value.to_be_bytes()[1]
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    let value = input.get(..count)?;
    *input = &input[count..];
    Some(value)
}

fn word(input: &mut &[u8]) -> Option<u16> {
    let value = take(input, 2)?;
    Some(u16::from_be_bytes([value[0], value[1]]))
}

fn words(input: &[u8]) -> Option<Vec<u16>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    Some(
        input
            .chunks_exact(2)
            .map(|value| u16::from_be_bytes([value[0], value[1]]))
            .filter(|value| !grease(*value))
            .collect(),
    )
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))[..12].to_string()
}

fn alpn_code(value: &[u8]) -> String {
    match (value.first(), value.last()) {
        (Some(first), Some(last))
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() =>
        {
            format!("{}{}", char::from(*first), char::from(*last))
        }
        (Some(first), Some(last)) => format!("{:x}{:x}", first >> 4, last & 15),
        _ => "00".to_string(),
    }
}

/// Return no fingerprint unless all required vector boundaries are valid.
/// TCP only: QUIC/DTLS and handshakes beyond the producer's 8 KiB budget are
/// deliberately unavailable. Cipher/extension order is sorted; signatures
/// retain wire order. Raw input never escapes into the audit evidence.
pub(super) fn fingerprint(handshake: &[u8]) -> Option<String> {
    if handshake.len() > 8192 || handshake.first() != Some(&1) {
        return None;
    }
    let header = handshake.get(1..4)?;
    let length =
        (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    if length + 4 != handshake.len() {
        return None;
    }
    let mut body = &handshake[4..];
    let mut version = word(&mut body)?;
    take(&mut body, 32)?;
    let session_length = usize::from(take(&mut body, 1)?[0]);
    if session_length > 32 {
        return None;
    }
    take(&mut body, session_length)?;
    let cipher_length = usize::from(word(&mut body)?);
    if cipher_length == 0 {
        return None;
    }
    let mut ciphers = words(take(&mut body, cipher_length)?)?;
    let compression_length = usize::from(take(&mut body, 1)?[0]);
    if compression_length == 0 {
        return None;
    }
    take(&mut body, compression_length)?;
    let mut extensions = Vec::new();
    let mut signatures = Vec::new();
    let mut alpn = "00".to_string();
    if !body.is_empty() {
        let extension_length = usize::from(word(&mut body)?);
        if extension_length != body.len() {
            return None;
        }
        while !body.is_empty() {
            let kind = word(&mut body)?;
            let length = usize::from(word(&mut body)?);
            let mut data = take(&mut body, length)?;
            if grease(kind) {
                continue;
            }
            // Duplicate extensions are invalid, including SNI and ALPN.
            if extensions.contains(&kind) {
                return None;
            }
            extensions.push(kind);
            match kind {
                0 => {
                    let length = usize::from(word(&mut data)?);
                    if length == 0 || length != data.len() {
                        return None;
                    }
                    while !data.is_empty() {
                        take(&mut data, 1)?;
                        let length = usize::from(word(&mut data)?);
                        if length == 0 {
                            return None;
                        }
                        take(&mut data, length)?;
                    }
                }
                16 => {
                    let length = usize::from(word(&mut data)?);
                    if length != data.len() {
                        return None;
                    }
                    let mut first = true;
                    while !data.is_empty() {
                        let length = usize::from(take(&mut data, 1)?[0]);
                        let protocol = take(&mut data, length)?;
                        if first {
                            alpn = alpn_code(protocol);
                            first = false;
                        }
                    }
                }
                43 => {
                    let length = usize::from(take(&mut data, 1)?[0]);
                    if length == 0 || length != data.len() {
                        return None;
                    }
                    version = words(data)?.into_iter().max()?;
                }
                13 => {
                    let length = usize::from(word(&mut data)?);
                    if length == 0 || length != data.len() {
                        return None;
                    }
                    signatures = words(data)?;
                }
                _ => {}
            }
        }
    }
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };
    let prefix = format!(
        "t{version}{}{:02}{:02}{alpn}",
        if extensions.contains(&0) { 'd' } else { 'i' },
        ciphers.len().min(99),
        extensions.len().min(99)
    );
    ciphers.sort_unstable();
    let cipher_hash = if ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        hash(&hex_list(&ciphers))
    };
    extensions.retain(|kind| *kind != 0 && *kind != 16);
    extensions.sort_unstable();
    let extension_hash = if extensions.is_empty() {
        "000000000000".to_string()
    } else {
        let mut value = hex_list(&extensions);
        if !signatures.is_empty() {
            value.push('_');
            value.push_str(&hex_list(&signatures));
        }
        hash(&value)
    };
    Some(format!("{prefix}_{cipher_hash}_{extension_hash}"))
}
