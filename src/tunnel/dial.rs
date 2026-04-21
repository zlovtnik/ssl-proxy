//! Upstream authority parsing and resolver-backed dialing helpers.
//!
//! This module owns host/port parsing and the timeout-wrapped DNS + TCP dial
//! flow used by CONNECT and bypass paths. It does not emit audit events or
//! mutate application state beyond DNS lookups.

use std::{io, time::Instant};

use crate::state::SharedState;
use tracing::debug;

const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Describe a failure while resolving or connecting to an upstream target.
#[derive(Debug)]
pub(crate) enum UpstreamDialError {
    NegativeCached,
    ResolveTimeout,
    ResolveFailed(String),
    NoAddresses,
    ConnectTimeout,
    ConnectFailed(io::Error),
}

impl UpstreamDialError {
    /// Map the error variant to a low-cardinality string class for logging.
    ///
    /// # Returns
    ///
    /// A `&'static str` identifying the error class (one of
    /// `"resolve_timeout"`, `"resolve_failed"`, `"resolve_empty"`,
    /// `"connect_timeout"`, or `"connect_failed"`).
    pub(crate) fn class(&self) -> &'static str {
        match self {
            Self::NegativeCached => "resolve_negative_cached",
            Self::ResolveTimeout => "resolve_timeout",
            Self::ResolveFailed(_) => "resolve_failed",
            Self::NoAddresses => "resolve_empty",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectFailed(_) => "connect_failed",
        }
    }

    /// Human-readable detail string describing the error for logging.
    ///
    /// The returned string is concise and suitable for low-cardinality log fields.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::tunnel::dial::UpstreamDialError;
    /// assert_eq!(UpstreamDialError::ResolveTimeout.detail(), "resolver timeout");
    /// assert_eq!(UpstreamDialError::ResolveFailed("no such host".into()).detail(), "resolver error: no such host");
    /// ```
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::NegativeCached => "resolver skipped (negative cache hit)".to_string(),
            Self::ResolveTimeout => "resolver timeout".to_string(),
            Self::ResolveFailed(err) => format!("resolver error: {err}"),
            Self::NoAddresses => "resolver returned no addresses".to_string(),
            Self::ConnectTimeout => "upstream connect timeout".to_string(),
            Self::ConnectFailed(err) => format!("upstream connect error: {err}"),
        }
    }
}

/// Parse an authority string into a hostname and port, defaulting to port 443 when the port is missing or the authority is malformed.
///
/// This accepts typical forms:
/// - A hostname or IPv4 address with optional `:port` (e.g. `example.com:8443`, `1.2.3.4:80`).
/// - A bracketed IPv6 literal with optional `:port` (e.g. `[::1]:8443`, `[::1]`).
///
/// Malformed or ambiguous inputs fall back to returning the original authority string as the hostname and port `443`. Examples of fallbacks include unclosed brackets, extra characters after a `]`, or unbracketed IPv6-like strings containing multiple `:` characters.
///
/// # Returns
///
/// A tuple `(hostname, port)` where `hostname` is the parsed host portion (or the original authority on fallback) and `port` is the parsed port number or `443`.
///
/// # Examples
///
/// ```ignore
/// let (h, p) = parse_host_port("example.com");
/// assert_eq!(h, "example.com");
/// assert_eq!(p, 443);
///
/// let (h, p) = parse_host_port("example.com:8443");
/// assert_eq!(h, "example.com");
/// assert_eq!(p, 8443);
///
/// let (h, p) = parse_host_port("[::1]:8443");
/// assert_eq!(h, "::1");
/// assert_eq!(p, 8443);
///
/// // malformed bracketed authority falls back
/// let (h, p) = parse_host_port("[::1extra");
/// assert_eq!(h, "[::1extra");
/// assert_eq!(p, 443);
/// ```
pub(crate) fn parse_host_port(authority: &str) -> (String, u16) {
    if authority.starts_with('[') {
        let Some(bracket_end) = authority.find(']') else {
            return (authority.to_string(), 443);
        };
        let remainder = &authority[bracket_end + 1..];
        if !remainder.is_empty() && !remainder.starts_with(':') {
            return (authority.to_string(), 443);
        }

        let hostname = authority[1..bracket_end].to_string();
        if hostname.is_empty() {
            return (authority.to_string(), 443);
        }
        let port = remainder
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(443);
        return (hostname, port);
    }
    if authority.contains(']') {
        return (authority.to_string(), 443);
    }
    if authority.chars().filter(|&c| c == ':').count() > 1 {
        return (authority.to_string(), 443);
    }
    authority
        .rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|port| (h.to_string(), port)))
        .unwrap_or_else(|| (authority.to_string(), 443))
}

/// Resolves the upstream hostname from `authority` and establishes a TCP connection to the selected address.
///
/// On success, returns the connected `tokio::net::TcpStream`, a `Vec<String>` of all resolved IP addresses (text form), and the selected peer IP as a `String` (or `"-"` if the peer address cannot be determined).
///
/// # Examples
///
/// ```ignore
/// # use tunnel::dial::dial_upstream_with_resolver;
/// # use tunnel::state::SharedState;
/// # async fn example(state: &SharedState) {
/// let authority = "example.com:443";
/// let result = dial_upstream_with_resolver(state, authority).await;
/// match result {
///     Ok((stream, resolved, selected)) => {
///         println!("Connected to {} via {}", selected, stream.peer_addr().ok().map(|a| a.ip().to_string()).unwrap_or_default());
///         println!("Resolved addresses: {:?}", resolved);
///     }
///     Err(e) => eprintln!("Dial error: {:?}", e),
/// }
/// # }
/// ```
pub(crate) async fn dial_upstream_with_resolver(
    state: &SharedState,
    authority: &str,
) -> Result<(tokio::net::TcpStream, Vec<String>, String), UpstreamDialError> {
    let (hostname, port) = parse_host_port(authority);
    const POSITIVE_TTL_SECS: u64 = 300;
    const NEGATIVE_TTL_SECS: u64 = 60;

    if state
        .dns_negative_cache
        .get(&hostname)
        .map(|entry| entry.elapsed().as_secs() < NEGATIVE_TTL_SECS)
        .unwrap_or(false)
    {
        return Err(UpstreamDialError::NegativeCached);
    }

    let cached_ips = state
        .dns_cache
        .get(&hostname)
        .filter(|meta| meta.fresh(POSITIVE_TTL_SECS))
        .map(|meta| {
            meta.resolved_ips
                .iter()
                .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let ips: Vec<std::net::IpAddr> = if !cached_ips.is_empty() {
        cached_ips
    } else {
        let addrs = tokio::time::timeout(
            tokio::time::Duration::from_millis(state.config.runtime.dns_resolve_timeout_ms),
            state.resolver.lookup_ip(hostname.as_str()),
        )
        .await
        .map_err(|_| UpstreamDialError::ResolveTimeout)?
        .map_err(|e| {
            let detail = e.to_string();
            if detail.to_ascii_uppercase().contains("NXDOMAIN") {
                state
                    .dns_negative_cache
                    .insert(hostname.clone(), Instant::now());
            }
            UpstreamDialError::ResolveFailed(detail)
        })?;
        let ips: Vec<std::net::IpAddr> = addrs.iter().collect();
        if !ips.is_empty() {
            state.record_resolved(
                &hostname,
                ips.iter().map(ToString::to_string).collect(),
                None,
            );
        }
        ips
    };

    let resolved_ips: Vec<String> = ips.iter().map(ToString::to_string).collect();
    if ips.is_empty() {
        return Err(UpstreamDialError::NoAddresses);
    }

    let connect = async {
        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "No connect candidates");
        for ip in &ips {
            match tokio::net::TcpStream::connect((*ip, port)).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    debug!(%ip, port, %e, "upstream connect attempt failed");
                    last_err = e;
                }
            }
        }
        Err(last_err)
    };

    let upstream = tokio::time::timeout(
        tokio::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
        connect,
    )
    .await
    .map_err(|_| UpstreamDialError::ConnectTimeout)?
    .map_err(UpstreamDialError::ConnectFailed)?;

    let selected_ip = upstream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "-".to_string());

    Ok((upstream, resolved_ips, selected_ip))
}

#[cfg(test)]
mod tests {
    use super::parse_host_port;

    #[test]
    fn parses_ipv4_and_hostname_authorities() {
        assert_eq!(
            parse_host_port("example.com"),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("example.com:8443"),
            ("example.com".to_string(), 8443)
        );
        assert_eq!(parse_host_port("1.2.3.4:80"), ("1.2.3.4".to_string(), 80));
    }

    #[test]
    fn parses_ipv6_authorities() {
        assert_eq!(parse_host_port("[::1]"), ("::1".to_string(), 443));
        assert_eq!(parse_host_port("[::1]:8443"), ("::1".to_string(), 8443));
        assert_eq!(
            parse_host_port("2001:db8::1"),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn falls_back_for_malformed_bracketed_authorities() {
        assert_eq!(
            parse_host_port("foo[::1]:8443"),
            ("foo[::1]:8443".to_string(), 443)
        );
        assert_eq!(parse_host_port("[::1"), ("[::1".to_string(), 443));
        assert_eq!(
            parse_host_port("[::1]extra"),
            ("[::1]extra".to_string(), 443)
        );
    }
}
