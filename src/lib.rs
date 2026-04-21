//! Library exports for integration tests and shared module access.
//!
//! The production binary lives in `main.rs`, but integration tests import the
//! same modules through this library target.

use base64::Engine;

pub mod blocklist;
pub mod boringtun_control;
pub mod config;
pub mod dashboard;
pub mod events;
pub mod forensic;
pub mod identity;
pub mod obfuscation;
pub mod proxy;
#[cfg(feature = "quic")]
pub mod quic;
pub mod security;
pub mod state;
pub mod sync;
pub mod transport;
pub mod tunnel;
pub mod wg_packet_obfuscation;
pub mod wg_relay;
pub mod wg_shim;
pub mod wg_stats;

/// Compares two strings for equality in constant time.
///
/// Performs a length check and then compares the byte slices using a constant-time
/// comparison; returns `true` only if `a` and `b` have the same length and identical bytes.
///
/// # Examples
///
/// ```
/// use ssl_proxy::constant_time_eq;
///
/// assert!(constant_time_eq("secret", "secret"));
/// assert!(!constant_time_eq("secret", "Secret"));
/// ```
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Validate the `Proxy-Authorization` header using Basic auth credentials.
///
/// Checks that the request contains a `Proxy-Authorization` header with a case-insensitive `Basic ` prefix, base64-decodes the remainder, parses the decoded value as `username:password`, and compares both parts against the provided `username` and `password` using a constant-time comparison.
///
/// # Returns
/// `true` if the header is present, decodes to `username:password`, and both username and password match the provided values; `false` otherwise.
///
/// # Examples
///
/// ```
/// use axum::http::Request;
/// use ssl_proxy::check_proxy_auth;
///
/// let req = Request::builder()
///     .header("proxy-authorization", "Basic dXNlcjpwYXNz") // "user:pass"
///     .body(())
///     .unwrap();
///
/// assert!(check_proxy_auth(&req, "user", "pass"));
/// ```
pub fn check_proxy_auth<B>(req: &axum::http::Request<B>, username: &str, password: &str) -> bool {
    let header = match req
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return false,
    };
    let encoded = if header.len() >= 6 && header.as_bytes()[..6].eq_ignore_ascii_case(b"basic ") {
        // Safe: if first 6 bytes match "basic " (ASCII), byte 6 is at character boundary
        &header[6..]
    } else {
        return false;
    };
    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (user, pass) = match decoded_str.split_once(':') {
        Some(pair) => pair,
        None => return false,
    };
    let user_ok = constant_time_eq(user, username);
    let pass_ok = constant_time_eq(pass, password);
    user_ok & pass_ok
}

#[cfg(test)]
mod tests {
    use axum::http::{header::HeaderValue, Request};
    use base64::Engine;

    use super::{check_proxy_auth, constant_time_eq};

    #[test]
    fn constant_time_eq_matches_equal_strings() {
        assert!(constant_time_eq("same-value", "same-value"));
    }

    #[test]
    fn constant_time_eq_rejects_same_prefix_with_different_lengths() {
        assert!(!constant_time_eq("prefix", "prefix-suffix"));
    }

    #[test]
    fn constant_time_eq_handles_long_inputs() {
        let a = "a".repeat(300);
        let b = "a".repeat(300);
        let c = format!("{}b", "a".repeat(299));

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn check_proxy_auth_missing_header_returns_false() {
        let req = Request::builder().body(()).unwrap();
        assert!(!check_proxy_auth(&req, "user", "pass"));
    }

    #[test]
    fn check_proxy_auth_accepts_case_insensitive_basic_prefix() {
        let header = format!(
            "basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:pass")
        );
        let req = Request::builder()
            .header(
                "proxy-authorization",
                HeaderValue::from_str(&header).unwrap(),
            )
            .body(())
            .unwrap();

        assert!(check_proxy_auth(&req, "user", "pass"));
    }

    #[test]
    fn check_proxy_auth_rejects_invalid_base64() {
        let req = Request::builder()
            .header("proxy-authorization", "Basic not-base64!!")
            .body(())
            .unwrap();

        assert!(!check_proxy_auth(&req, "user", "pass"));
    }

    #[test]
    fn check_proxy_auth_rejects_wrong_credentials() {
        let header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:pass")
        );
        let req = Request::builder()
            .header(
                "proxy-authorization",
                HeaderValue::from_str(&header).unwrap(),
            )
            .body(())
            .unwrap();

        assert!(!check_proxy_auth(&req, "other", "pass"));
    }

    #[test]
    fn check_proxy_auth_allows_passwords_with_colons() {
        let header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:pa:ss")
        );
        let req = Request::builder()
            .header(
                "proxy-authorization",
                HeaderValue::from_str(&header).unwrap(),
            )
            .body(())
            .unwrap();

        assert!(check_proxy_auth(&req, "user", "pa:ss"));
    }
}
