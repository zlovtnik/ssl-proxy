//! UTF-8 decode helpers shared by SSID, WPS, and application-layer parsers.

/// Decodes UTF-8 bytes and strips embedded NUL characters (postgres rejects embedded NULs in text columns).
pub(super) fn utf8_text(bytes: &[u8]) -> Option<String> {
    sanitize_text(std::str::from_utf8(bytes).ok()?)
}

/// Strips NUL bytes, trims whitespace, and returns None for empty strings; single point where empty strings become None.
pub(super) fn sanitize_text(value: &str) -> Option<String> {
    let value = value.replace('\0', "");
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
