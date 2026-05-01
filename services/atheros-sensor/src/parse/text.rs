pub(super) fn utf8_text(bytes: &[u8]) -> Option<String> {
    sanitize_text(std::str::from_utf8(bytes).ok()?)
}

pub(super) fn sanitize_text(value: &str) -> Option<String> {
    let value = value.replace('\0', "");
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
