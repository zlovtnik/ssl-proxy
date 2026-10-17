/// Classifies a destination host/port/ALPN tuple into a coarse, human-readable traffic category.
///
/// The function normalizes `host` by trimming a trailing dot and lowercasing, then applies ordered
/// label- and suffix-based heuristics to map common services into the v1 proxy taxonomy:
/// `ads_tracker`, `analytics`, `cdn`, `essential_api`, `auth`, or `unknown`.
///
/// # Examples
///
/// ```ignore
/// let cat = classify("SENTRY.IO.", 443, None);
/// assert_eq!(cat, "analytics");
/// ```
// This category describes a hostname heuristic, never a policy decision.
pub(crate) fn classify(host: &str, port: u16, alpn: Option<&str>) -> &'static str {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let h = h.as_str();
    macro_rules! matches_domain {
        ($suffix:literal) => {
            h == $suffix || h.ends_with(concat!(".", $suffix))
        };
    }
    let label_matches = |label: &str| h.split('.').any(|part| part == label);

    if matches_domain!("firebaselogging.googleapis.com")
        || matches_domain!("firebase-settings.crashlytics.com")
        || matches_domain!("app-measurement.com")
        || matches_domain!("crashlytics.com")
        || matches_domain!("sentry.io")
        || matches_domain!("analytics.google.com")
        || matches_domain!("telemetry.microsoft.com")
        || matches_domain!("metrics.apple.com")
        || matches_domain!("datadoghq.com")
        || matches_domain!("newrelic.com")
        || matches_domain!("segment.io")
        || matches_domain!("femetrics.grammarly.io")
        || matches_domain!("bugsnag.com")
        || matches_domain!("otel.cline.bot")
        || matches_domain!("events.data.microsoft.com")
    {
        return "analytics";
    }
    if matches_domain!("doubleclick.net")
        || matches_domain!("googlesyndication.com")
        || matches_domain!("adnxs.com")
        || matches_domain!("criteo.com")
        || matches_domain!("pubmatic.com")
        || matches_domain!("rubiconproject.com")
        || matches_domain!("scorecardresearch.com")
        || label_matches("ads")
    {
        return "ads_tracker";
    }
    if matches_domain!("push.apple.com")
        || matches_domain!("push.googleapis.com")
        || matches_domain!("fcm.googleapis.com")
        || matches_domain!("notify.windows.com")
    {
        return "essential_api";
    }
    if matches_domain!("accounts.google.com")
        || matches_domain!("oauth2.googleapis.com")
        || matches_domain!("auth0.com")
        || matches_domain!("okta.com")
        || matches_domain!("login.microsoftonline.com")
        || matches_domain!("appleid.apple.com")
    {
        return "auth";
    }
    if matches_domain!("akamai.net")
        || matches_domain!("cloudfront.net")
        || matches_domain!("fastly.net")
        || label_matches("cdn")
        || label_matches("static")
        || label_matches("assets")
    {
        return "cdn";
    }
    let _ = (port, alpn);
    "unknown"
}

/// Determines whether a hostname belongs to a domain that requires certificate-pinning bypass.
///
/// The input `hostname` is normalized by trimming a trailing `.` and lowercasing before matching
/// against a fixed list of pinned domain suffixes. A match occurs when the normalized hostname
/// is equal to a suffix or is a subdomain of a suffix (e.g., `sub.example.com` matches `example.com`).
///
/// # Examples
///
/// ```ignore
/// assert!(is_cert_pinned_host("APPLE.COM."));
/// assert!(is_cert_pinned_host("sub.youtube.com"));
/// assert!(!is_cert_pinned_host("example.com"));
/// ```
pub(crate) fn is_cert_pinned_host(hostname: &str) -> bool {
    let normalized = hostname.trim_end_matches('.').to_ascii_lowercase();
    let pinned_suffixes = [
        "facebook.com",
        "fbcdn.net",
        "instagram.com",
        "cdninstagram.com",
        "instagramstatic.com",
        "youtube.com",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com",
        "gvt1.com",
        "apple.com",
    ];
    pinned_suffixes
        .iter()
        .any(|suffix| normalized == *suffix || normalized.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::{classify, is_cert_pinned_host};

    #[test]
    fn classify_normalizes_case_and_trailing_dot() {
        assert_eq!(classify("SENTRY.IO.", 443, None), "analytics");
    }

    #[test]
    fn classify_requires_exact_suffix_matches() {
        assert_eq!(classify("sub.sentry.io", 1234, None), "analytics");
        assert_eq!(classify("sentry.io.com", 1234, None), "unknown");
    }

    #[test]
    fn broad_service_domain_does_not_imply_essential_purpose() {
        assert_eq!(classify("web.whatsapp.com", 443, None), "unknown");
        assert_eq!(classify("aet.spotify.com", 443, None), "unknown");
        assert_eq!(classify("foo.whatsapp.evil", 1234, None), "unknown");
    }

    #[test]
    fn classify_push_real_host_and_rejects_false_positive() {
        assert_eq!(classify("push.googleapis.com", 1234, None), "essential_api");
        assert_eq!(classify("foo.push.googleapis.evil", 1234, None), "unknown");
    }

    #[test]
    fn common_ports_do_not_imply_essential_purpose() {
        assert_eq!(classify("unrecognized.example", 443, None), "unknown");
        assert_eq!(classify("unrecognized.example", 80, None), "unknown");
        assert_eq!(classify("unrecognized.example", 5228, None), "unknown");
        assert_eq!(
            classify("inkwell.femetrics.grammarly.io", 443, None),
            "analytics"
        );
        assert_eq!(classify("static.ads.brave.com", 443, None), "ads_tracker");
    }

    #[test]
    fn pinned_host_normalization_handles_trailing_dot() {
        assert!(is_cert_pinned_host("APPLE.COM."));
    }
}
