//! Traffic obfuscation for Fox-family domains.
//!
//! This module classifies outbound hostnames into a `Profile` and normalizes
//! request and response headers to reduce proxy fingerprinting. It does not
//! modify request bodies or TLS payloads.

use crate::config::ObfuscationConfig;

/// Hardcoded seed domains for obfuscation profiles.
pub const FOX_DOMAINS: &[(&str, &str)] = &[
    ("foxnews.com", "fox-news"),
    ("*.foxnews.com", "fox-news"),
    ("foxsports.com", "fox-sports"),
    ("*.foxsports.com", "fox-sports"),
    ("fox.com", "fox-general"),
    ("*.fox.com", "fox-general"),
    ("foxbusiness.com", "fox-general"),
    ("*.foxbusiness.com", "fox-general"),
    ("fox-cdn.com", "fox-cdn"),
    ("*.akamaized.net", "fox-cdn"),
    ("fxnetworks.com", "fx-network"),
    ("*.fxnetworks.com", "fx-network"),
];

/// Obfuscation profile for traffic normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    FoxNews,
    FoxSports,
    FoxGeneral,
    FoxCdn,
    FxNetwork,
    None,
}

impl Profile {
    /// Get the configured profile name string for this `Profile` variant.
    ///
    /// # Returns
    ///
    /// The configured profile name string for the variant (e.g., `"fox-news"`, `"fx-network"`, `"none"`).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(Profile::FoxNews.as_str(), "fox-news");
    /// assert_eq!(Profile::None.as_str(), "none");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::FoxNews => "fox-news",
            Profile::FoxSports => "fox-sports",
            Profile::FoxGeneral => "fox-general",
            Profile::FoxCdn => "fox-cdn",
            Profile::FxNetwork => "fx-network",
            Profile::None => "none",
        }
    }

    /// Maps a profile-name string to its corresponding `Profile` variant.
    ///
    /// Recognized input values are: `"fox-news"`, `"fox-sports"`, `"fox-general"`,
    /// `"fox-cdn"`, and `"fx-network"`.
    ///
    /// # Returns
    ///
    /// `Some(Profile)` for a recognized profile name, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = Profile::from_name("fox-news");
    /// assert_eq!(p, Some(Profile::FoxNews));
    ///
    /// let none = Profile::from_name("none");
    /// assert_eq!(none, Some(Profile::None));
    ///
    /// let unknown = Profile::from_name("unknown");
    /// assert_eq!(unknown, None);
    /// ```
    pub(crate) fn from_name(value: &str) -> Option<Self> {
        match value {
            "fox-news" => Some(Profile::FoxNews),
            "fox-sports" => Some(Profile::FoxSports),
            "fox-general" => Some(Profile::FoxGeneral),
            "fox-cdn" => Some(Profile::FoxCdn),
            "fx-network" => Some(Profile::FxNetwork),
            "none" => Some(Profile::None),
            _ => None,
        }
    }
}

/// Determine the obfuscation profile for a hostname using the provided configuration.
///
/// The hostname is normalized (ASCII lowercase, trailing `.` removed) and matched
/// against `config.domain_map`. Exact matches and wildcard keys of the form
/// `".example.com"` are checked while progressively stripping leftmost labels
/// (e.g., `a.b.example.com` → `b.example.com` → `example.com`). If `config.enabled`
/// is `false` or no match is found, `Profile::None` is returned.
///
/// # Parameters
///
/// - `hostname` — the DNS name to classify (may include subdomains and a trailing dot).
/// - `config` — obfuscation configuration containing `enabled` and `domain_map`.
///
/// # Returns
///
/// `Profile::None` when obfuscation is disabled or no mapping applies; otherwise the
/// `Profile` associated with the first matching domain or wildcard key.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
///
/// let mut map = HashMap::new();
/// map.insert("foxnews.com".to_string(), crate::obfuscation::Profile::FoxNews);
/// let cfg = crate::obfuscation::ObfuscationConfig {
///     enabled: true,
///     domain_map: map,
///     fox_ua_override: String::new(),
/// };
///
/// let p = crate::obfuscation::classify_obfuscation("www.foxnews.com", &cfg);
/// assert_eq!(p, crate::obfuscation::Profile::FoxNews);
/// ```
pub fn classify_obfuscation(hostname: &str, config: &ObfuscationConfig) -> Profile {
    if !config.enabled {
        return Profile::None;
    }

    let normalized = hostname.to_ascii_lowercase();
    let normalized = normalized.trim_end_matches('.');
    let mut domain = normalized;

    loop {
        if let Some(profile) = config.domain_map.get(domain) {
            return *profile;
        }

        let wildcard_key = format!(".{}", domain);
        if let Some(profile) = config.domain_map.get(&wildcard_key) {
            return *profile;
        }

        match domain.find('.') {
            Some(idx) => domain = &domain[idx + 1..],
            None => return Profile::None,
        }
    }
}

/// Apply request header obfuscation for Fox-family profiles.
///
/// Removes proxy/privacy-related request headers and sets the `user-agent` header
/// to a Fox-compatible value. If `config.fox_ua_override` is non-empty and is a
/// valid header value, that string is used for `user-agent`; otherwise a
/// stable default `"Mozilla/5.0 (compatible; Generic/1.0)"` is used.
///
/// Removed request headers: `x-forwarded-for`, `via`, `forwarded`, `dnt`, `sec-gpc`.
///
/// # Examples
///
/// ```no_run
/// use axum::http::HeaderMap;
/// use crate::obfuscation::{apply_request_headers, Profile, ObfuscationConfig};
///
/// let mut headers = HeaderMap::new();
/// headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
/// headers.insert("user-agent", "original".parse().unwrap());
///
/// let config = ObfuscationConfig { fox_ua_override: String::new(), ..Default::default() };
/// apply_request_headers(&mut headers, &Profile::FoxNews, &config);
///
/// // The proxy/privacy headers are removed and user-agent is set to a Fox-compatible value.
/// assert!(!headers.contains_key("x-forwarded-for"));
/// assert!(headers.contains_key("user-agent"));
/// ```
pub fn apply_request_headers(
    headers: &mut axum::http::HeaderMap,
    profile: &Profile,
    config: &ObfuscationConfig,
) {
    if matches!(profile, Profile::None) {
        return;
    }

    headers.remove("x-forwarded-for");
    headers.remove("via");
    headers.remove("forwarded");
    headers.remove("dnt");
    headers.remove("sec-gpc");

    let ua = if config.fox_ua_override.is_empty() {
        axum::http::HeaderValue::from_static("Mozilla/5.0 (compatible; Generic/1.0)")
    } else {
        axum::http::HeaderValue::from_str(&config.fox_ua_override).unwrap_or_else(|_| {
            axum::http::HeaderValue::from_static("Mozilla/5.0 (compatible; Generic/1.0)")
        })
    };
    headers.insert("user-agent", ua);
}

/// Remove CDN- and proxy-related response headers for Fox-family obfuscation profiles.
///
/// If `profile` is `Profile::None`, this function leaves the headers unchanged.
///
/// The following response headers are removed when a Fox profile is active:
/// - `x-cache`
/// - `x-edge-ip`
/// - `x-served-by`
///
/// # Examples
///
/// ```
/// use axum::http::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("x-cache", "HIT".parse().unwrap());
/// headers.insert("x-edge-ip", "203.0.113.1".parse().unwrap());
/// headers.insert("x-served-by", "edge-1".parse().unwrap());
///
/// // assuming `apply_response_headers` and `Profile` are in scope
/// apply_response_headers(&mut headers, &Profile::FoxNews);
///
/// assert!(headers.get("x-cache").is_none());
/// assert!(headers.get("x-edge-ip").is_none());
/// assert!(headers.get("x-served-by").is_none());
/// ```
pub fn apply_response_headers(headers: &mut axum::http::HeaderMap, profile: &Profile) {
    if matches!(profile, Profile::None) {
        return;
    }

    headers.remove("x-cache");
    headers.remove("x-edge-ip");
    headers.remove("x-served-by");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn test_config() -> crate::config::Config {
        crate::config::Config::for_tests()
    }

    #[test]
    fn classify_obfuscation_fox_news() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxnews.com", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("www.foxnews.com", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("api.foxnews.com", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("sub.api.foxnews.com", &config.obfuscation),
            Profile::FoxNews
        );
    }

    #[test]
    fn classify_obfuscation_fox_sports() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxsports.com", &config.obfuscation),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("www.foxsports.com", &config.obfuscation),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("api.foxsports.com", &config.obfuscation),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("sub.api.foxsports.com", &config.obfuscation),
            Profile::FoxSports
        );
    }

    #[test]
    fn classify_obfuscation_none() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("google.com", &config.obfuscation),
            Profile::None
        );
        assert_eq!(
            classify_obfuscation("example.com", &config.obfuscation),
            Profile::None
        );
        assert_eq!(
            classify_obfuscation("notfox.com", &config.obfuscation),
            Profile::None
        );
    }

    #[test]
    fn classify_obfuscation_case_insensitive() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("FOXNEWS.COM", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("FoxSports.Com", &config.obfuscation),
            Profile::FoxSports
        );
    }

    #[test]
    fn classify_obfuscation_trailing_dot() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxnews.com.", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("www.foxnews.com.", &config.obfuscation),
            Profile::FoxNews
        );
    }

    #[test]
    fn apply_request_headers_fox_profile() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        headers.insert("via", HeaderValue::from_static("proxy.example.com"));
        headers.insert("forwarded", HeaderValue::from_static("for=192.168.1.1"));
        headers.insert("dnt", HeaderValue::from_static("1"));
        headers.insert("sec-gpc", HeaderValue::from_static("1"));
        headers.insert("user-agent", HeaderValue::from_static("Custom/1.0"));

        apply_request_headers(&mut headers, &Profile::FoxNews, &config.obfuscation);

        assert!(!headers.contains_key("x-forwarded-for"));
        assert!(!headers.contains_key("via"));
        assert!(!headers.contains_key("forwarded"));
        assert!(!headers.contains_key("dnt"));
        assert!(!headers.contains_key("sec-gpc"));
        assert!(headers.contains_key("user-agent"));
    }

    #[test]
    fn apply_request_headers_none_profile() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        headers.insert("user-agent", HeaderValue::from_static("Custom/1.0"));

        apply_request_headers(&mut headers, &Profile::None, &config.obfuscation);

        assert!(headers.contains_key("x-forwarded-for"));
        assert!(headers.contains_key("user-agent"));
    }

    #[test]
    fn apply_request_headers_ua_override() {
        let mut config = test_config();
        config.obfuscation.fox_ua_override = "TestUA/1.0".to_string();

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("Original/1.0"));

        apply_request_headers(&mut headers, &Profile::FoxNews, &config.obfuscation);

        assert_eq!(headers.get("user-agent").unwrap(), "TestUA/1.0");
    }

    #[test]
    fn apply_response_headers_fox_profile() {
        let mut headers = HeaderMap::new();
        headers.insert("x-cache", HeaderValue::from_static("HIT"));
        headers.insert("x-edge-ip", HeaderValue::from_static("1.2.3.4"));
        headers.insert("x-served-by", HeaderValue::from_static("cdn.example.com"));
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );

        apply_response_headers(&mut headers, &Profile::FoxNews);

        assert!(!headers.contains_key("x-cache"));
        assert!(!headers.contains_key("x-edge-ip"));
        assert!(!headers.contains_key("x-served-by"));
        assert!(headers.contains_key("content-security-policy"));
    }

    #[test]
    fn apply_response_headers_none_profile() {
        let mut headers = HeaderMap::new();
        headers.insert("x-cache", HeaderValue::from_static("HIT"));
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );

        apply_response_headers(&mut headers, &Profile::None);

        assert!(headers.contains_key("x-cache"));
        assert!(headers.contains_key("content-security-policy"));
    }
}
