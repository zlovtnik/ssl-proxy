//! Shared byte-level payload redaction helpers for audit previews.

/// Redact known sensitive patterns from captured payload bytes in place.
pub(crate) fn redact_sensitive_data(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }

    fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
        if needle.is_empty() || start >= haystack.len() || needle.len() > haystack.len() {
            return None;
        }
        haystack[start..]
            .windows(needle.len())
            .position(|window| window == needle)
            .map(|index| start + index)
    }

    fn mask_range(buf: &mut [u8], start: usize, delimiters: &[u8]) {
        let mut idx = start;
        while idx < buf.len() && !delimiters.contains(&buf[idx]) {
            buf[idx] = b'*';
            idx += 1;
        }
    }

    fn next_line_start(buf: &[u8], pos: usize) -> usize {
        buf[pos..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| pos + offset + 1)
            .unwrap_or(buf.len())
    }

    fn at_header_line_start(buf: &[u8], pos: usize) -> bool {
        pos == 0 || (pos >= 1 && buf[pos - 1] == b'\n')
    }

    fn at_body_key_boundary(buf: &[u8], pos: usize) -> bool {
        pos == 0
            || matches!(
                buf[pos - 1],
                b'?' | b'&' | b';' | b'\r' | b'\n' | b' ' | b'\t' | b'{' | b',' | b'['
            )
    }

    let lower: Vec<u8> = buf.iter().map(|byte| byte.to_ascii_lowercase()).collect();

    for key in [
        &b"authorization"[..],
        &b"cookie"[..],
        &b"set-cookie"[..],
        &b"x-api-key"[..],
        &b"proxy-authorization"[..],
        &b"x-auth-token"[..],
    ] {
        let mut search_from = 0usize;
        while let Some(pos) = find_bytes(&lower, key, search_from) {
            let line_end = next_line_start(&lower, pos);
            let sep = pos + key.len();
            if at_header_line_start(&lower, pos) && sep < lower.len() && lower[sep] == b':' {
                let mut value_start = sep + 1;
                while value_start < buf.len() && matches!(buf[value_start], b' ' | b'\t') {
                    value_start += 1;
                }
                if key == b"cookie" || key == b"set-cookie" {
                    mask_range(buf, value_start, b"\r\n");
                } else {
                    mask_range(buf, value_start, b"\r\n;&\t");
                }
            }
            search_from = line_end.max(pos + 1);
        }
    }

    let mut search_from = 0usize;
    while let Some(pos) = find_bytes(&lower, b"bearer ", search_from) {
        mask_range(buf, pos + "bearer ".len(), b"\r\n;& \t\"'},");
        search_from = pos + "bearer ".len();
    }

    for key in [
        &b"password="[..],
        &b"pass="[..],
        &b"token="[..],
        &b"secret="[..],
        &b"api_key="[..],
        &b"apikey="[..],
    ] {
        let mut form_search_from = 0usize;
        while let Some(pos) = find_bytes(&lower, key, form_search_from) {
            if at_body_key_boundary(&lower, pos) {
                mask_range(buf, pos + key.len(), b"\r\n&; \t\"'}");
            }
            form_search_from = pos + key.len();
        }
    }

    for key in [
        &b"\"password\":"[..],
        &b"\"token\":"[..],
        &b"\"secret\":"[..],
        &b"\"api_key\":"[..],
        &b"\"apikey\":"[..],
    ] {
        let mut json_search_from = 0usize;
        while let Some(pos) = find_bytes(&lower, key, json_search_from) {
            if at_body_key_boundary(&lower, pos) {
                let mut value_start = pos + key.len();
                while value_start < buf.len() && matches!(buf[value_start], b' ' | b'\t') {
                    value_start += 1;
                }
                if value_start < buf.len() && buf[value_start] == b'"' {
                    let mut idx = value_start + 1;
                    while idx < buf.len() {
                        if buf[idx] == b'\\' && idx + 1 < buf.len() {
                            buf[idx] = b'*';
                            buf[idx + 1] = b'*';
                            idx += 2;
                        } else if buf[idx] == b'"' {
                            break;
                        } else {
                            buf[idx] = b'*';
                            idx += 1;
                        }
                    }
                } else {
                    mask_range(buf, value_start, b"\r\n,} \t");
                }
            }
            json_search_from = pos + key.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive_data;

    #[test]
    fn redacts_sensitive_headers_only_at_line_start() {
        let mut payload = b"X-Not-Authorization: keep\r\nAuthorization: Bearer secret\r\n".to_vec();
        redact_sensitive_data(&mut payload);
        let redacted = String::from_utf8(payload).unwrap();

        assert!(redacted.contains("X-Not-Authorization: keep"));
        assert!(redacted.contains("Authorization: *************"));
        assert!(!redacted.contains("Bearer secret"));
    }

    #[test]
    fn redacts_added_header_form_and_json_keys() {
        let mut payload = br#"Proxy-Authorization: Basic pxcred
x-auth-token: xheadervalue
password=formpassword&token=formtoken&secret=formsecret&api_key=formapikey&apikey=formapikey2
{"password":"json-password","token":"json-token-value","secret":false}"#
            .to_vec();
        redact_sensitive_data(&mut payload);
        let redacted = String::from_utf8(payload).unwrap();

        for secret in [
            "pxcred",
            "xheadervalue",
            "formpassword",
            "formtoken",
            "formsecret",
            "formapikey",
            "formapikey2",
            "json-password",
            "json-token-value",
            "false",
        ] {
            assert!(!redacted.contains(secret));
        }
    }

    #[test]
    fn redacts_json_string_values_with_escaped_quotes() {
        let mut payload = br#"{"token":"alpha \"quoted\" omega","safe":"keep"}"#.to_vec();
        redact_sensitive_data(&mut payload);
        let redacted = String::from_utf8(payload).unwrap();

        assert!(!redacted.contains("alpha"));
        assert!(!redacted.contains("quoted"));
        assert!(!redacted.contains("omega"));
        assert!(redacted.contains(r#""safe":"keep""#));
    }

    #[test]
    fn redacts_cookie_multi_pairs() {
        let mut payload = b"Cookie: a=1; b=2; c=three\r\nOther-Header: value\r\n".to_vec();
        redact_sensitive_data(&mut payload);
        let redacted = String::from_utf8(payload).unwrap();

        assert!(!redacted.contains("a=1"));
        assert!(!redacted.contains("b=2"));
        assert!(!redacted.contains("c=three"));
        assert!(redacted.contains("Cookie:"));
        assert!(redacted.contains("Other-Header: value"));
        assert!(!redacted.contains('='));
        assert!(!redacted.contains("1"));
        assert!(!redacted.contains("2"));
        assert!(!redacted.contains("three"));
    }
}
