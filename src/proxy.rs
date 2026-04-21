//! HTTP/1.1 explicit proxy handling for non-CONNECT requests.
//!
//! This module rewrites absolute-form URIs, strips identifying headers, applies
//! obfuscation profiles, and forwards requests through the shared HTTP client.
//! It does not handle CONNECT or transparent TCP tunnels.

use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use serde::Serialize;
use std::{sync::atomic::Ordering, time::Instant};
use tracing::{error, info};

use crate::{
    blocklist,
    events::{self, EmitPayload},
    obfuscation,
    state::SharedState,
};

/// Shared HTTP client type used for proxied non-CONNECT requests.
pub type ProxyClient = Client<HttpConnector, Body>;

/// Return a URI string with the query component replaced by `[REDACTED]`.
fn scrub_uri(uri: &axum::http::Uri) -> String {
    if uri.query().is_some() {
        format!("{}?[REDACTED]", uri.path())
    } else {
        uri.path().to_string()
    }
}

/// Extracts the request path and the list of query parameter names (keys) without their values.
///
/// Returns a tuple where the first element is the URI path and the second element is a Vec of
/// query parameter names in their original order. Empty keys are omitted; if the URI has no
/// query component the vector will be empty.
///
/// # Examples
///
/// ```
/// use axum::http::Uri;
///
/// let uri: Uri = "/search?q=rust&page=2&empty=&flag".parse().unwrap();
/// let (path, keys) = decompose_uri(&uri);
/// assert_eq!(path, "/search");
/// assert_eq!(keys, vec!["q".to_string(), "page".to_string(), "flag".to_string()]);
/// ```
fn decompose_uri(uri: &axum::http::Uri) -> (String, Vec<String>) {
    let path = uri.path().to_string();
    let keys = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|pair| {
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (pair, None),
            };
            if key.is_empty() || matches!(value, Some("")) {
                None
            } else {
                Some(key.to_string())
            }
        })
        .collect();
    (path, keys)
}
/// Handle a single non-CONNECT HTTP/1.1 proxy request.
///
/// Performs host blocklist checking, rewrites absolute-form URIs to origin-form,
/// strips identifying and hop-by-hop headers, applies an optional obfuscation
/// profile, forwards the request to the upstream via the shared client, and
/// sanitizes the upstream response before returning it.
///
/// Returns:
/// - `Ok(Response<Body>)` with the proxied and cleaned upstream response on success.
/// - `Err(StatusCode::BAD_REQUEST)` when the request is malformed (e.g., missing host or invalid URI).
/// - `Err(StatusCode::FORBIDDEN)` when the destination host is blocklisted.
/// - `Err(StatusCode::BAD_GATEWAY)` when the upstream request fails.
///
/// # Examples
///
/// ```no_run
/// use axum::extract::State;
/// use hyper::{Body, Request};
///
/// // Example sketch: call from an async runtime with a proper SharedState and Request.
/// // let state: SharedState = ...;
/// // let req: Request<Body> = Request::builder().uri("http://example/").body(Body::empty()).unwrap();
/// // let res = handler(State(state), req).await;
/// ```
pub async fn handler(
    State(state): State<SharedState>,
    mut req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let start = Instant::now();
    let peer_ip = req
        .extensions()
        .get::<std::net::IpAddr>()
        .map(std::string::ToString::to_string);
    let device_token = crate::identity::extract_device_token(req.headers());
    let user_agent = crate::identity::extract_user_agent(req.headers());
    let identity = crate::identity::resolve_identity(
        &state,
        peer_ip.clone(),
        device_token,
        user_agent.clone(),
    );

    // Check blocklist using the host from the URI or Host header.
    let hostname = req
        .uri()
        .host()
        .or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    let hostname = if hostname.starts_with('[') {
        hostname
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        hostname.split(':').next().unwrap_or("")
    }
    .to_string();
    if hostname.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if blocklist::is_blocked(&hostname, &state).await {
        #[derive(Serialize)]
        struct HttpBlockedExtra {
            method: String,
            uri: String,
            duration_ms: u128,
            req_content_length_bytes: Option<u64>,
            req_headers_present: Vec<String>,
            req_has_auth: bool,
            req_has_cookie: bool,
            req_path: String,
            req_query_keys: Vec<String>,
        }

        state.record_blocked();
        let scrubbed = scrub_uri(req.uri());
        // Epic 1.1 — Content-Length header value (no body buffering)
        let req_content_length: Option<u64> = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        state.record_host_block(&hostname, req_content_length.unwrap_or(0), "http");
        // Epic 1.2a — interesting header inventory
        let interesting = [
            "content-type",
            "user-agent",
            "x-client-data",
            "x-amz-target",
        ];
        let req_headers_present: Vec<String> = interesting
            .iter()
            .filter(|&&h| req.headers().contains_key(h))
            .map(|&h| h.to_string())
            .collect();
        // Epic 1.2b — auth/cookie presence flags (names only, zero value leakage)
        let req_has_auth = req.headers().contains_key("authorization");
        let req_has_cookie = req.headers().contains_key("cookie");
        // Epic 1.4 — URI decomposition
        let (req_path, req_query_keys) = decompose_uri(req.uri());
        let duration_ms = start.elapsed().as_millis();
        info!(
            target: "audit",
            event = "http_blocked",
            host = %hostname,
            method = %req.method(),
            uri = %scrubbed,
            duration_ms,
            "blocked snitch (http)"
        );
        events::emit_serializable(
            &state,
            "http_blocked",
            &hostname,
            identity.peer_ip.clone(),
            identity.wg_pubkey.clone(),
            identity.device_id.clone(),
            identity.identity_source.clone(),
            identity.peer_hostname.clone(),
            identity.client_ua.clone(),
            0,
            0,
            None,
            true,
            None,
            HttpBlockedExtra {
                method: req.method().as_str().to_string(),
                uri: scrubbed,
                duration_ms,
                req_content_length_bytes: req_content_length,
                req_headers_present,
                req_has_auth,
                req_has_cookie,
                req_path,
                req_query_keys,
            },
        );
        state.record_peer_block(
            identity.wg_pubkey.as_deref(),
            req_content_length.unwrap_or(0),
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Host allowed - reset block streak and count
    state.record_host_allow(&hostname);
    state.record_allowed();

    // Classify obfuscation profile after blocklist check
    let profile = obfuscation::classify_obfuscation(&hostname, &state.config.obfuscation);

    // Rewrite absolute URI to origin form and forward to the correct host.
    if req.uri().scheme().is_some() {
        let scheme = req.uri().scheme_str().unwrap_or_default();
        if scheme.eq_ignore_ascii_case("https") {
            // HTTPS proxying must use CONNECT; reject absolute-form https:// requests.
            return Err(StatusCode::BAD_REQUEST);
        }

        let host = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let new_uri = format!("http://{}{}", host, path_and_query);
        *req.uri_mut() = new_uri.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    }

    // Capture display values before req is consumed by the upstream call.
    let method = req.method().clone();
    let scrubbed_uri = scrub_uri(req.uri());

    req.headers_mut().remove("connection");
    req.headers_mut().remove("keep-alive");
    req.headers_mut().remove("te");
    req.headers_mut().remove("trailers");
    req.headers_mut().remove("transfer-encoding");
    // DO NOT REMOVE upgrade header - required for WebSocket handshake

    // Full global header scrubbing - remove ALL identifying headers
    {
        let headers = req.headers_mut();

        // Explicitly remove known leak headers
        for header in [
            "forwarded",
            "x-real-ip",
            "x-client-ip",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-for",
            "x-forwarded-server",
            "x-original-url",
            "x-original-uri",
            "x-request-id",
            "x-amzn-trace-id",
            "x-cloud-trace-context",
            "via",
        ] {
            headers.remove(header);
        }

        // Remove identifying x-* headers, but keep app/API critical ones.
        let x_headers: Vec<_> = headers
            .keys()
            .filter(|k| {
                let name = k.as_str();
                name.starts_with("x-")
                    && !matches!(
                        name,
                        "x-amz-target"
                            | "x-client-data"
                            | "x-ig-app-id"
                            | "x-ig-www-claim"
                            | "x-instagram-ajax"
                            | "x-csrftoken"
                            | "x-requested-with"
                            | "x-youtube-client-name"
                            | "x-youtube-client-version"
                            | "x-goog-api-key"
                            | "x-goog-visitor-id"
                    )
            })
            .cloned()
            .collect();

        for name in x_headers {
            headers.remove(name);
        }
    }

    // Apply request header obfuscation for Fox profiles
    if !matches!(profile, obfuscation::Profile::None) {
        obfuscation::apply_request_headers(req.headers_mut(), &profile, &state.config.obfuscation);
        state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
    }

    match state.client.request(req).await {
        Ok(mut res) => {
            let status = res.status().as_u16();
            info!(
                target: "audit",
                event = "http_proxied",
                host = %hostname,
                method = %method,
                uri = %scrubbed_uri,
                status = status,
                duration_ms = start.elapsed().as_millis(),
                "proxy response received"
            );
            // Apply response header obfuscation for Fox profiles
            if !matches!(profile, obfuscation::Profile::None) {
                obfuscation::apply_response_headers(res.headers_mut(), &profile);
            }

            // Emit obfuscated event if profile is not None
            if !matches!(profile, obfuscation::Profile::None) {
                info!(
                    target: "audit",
                    event = "http_obfuscated",
                    host = %hostname,
                    profile = profile.as_str(),
                    method = %method,
                    uri = %scrubbed_uri,
                    status = status,
                    duration_ms = start.elapsed().as_millis(),
                    "http traffic obfuscated"
                );
            }

            events::emit(
                &state,
                "http_proxied",
                &hostname,
                EmitPayload {
                    peer_ip: identity.peer_ip.clone(),
                    wg_pubkey: identity.wg_pubkey.clone(),
                    device_id: identity.device_id.clone(),
                    identity_source: identity.identity_source.clone(),
                    peer_hostname: identity.peer_hostname.clone(),
                    client_ua: identity.client_ua.clone(),
                    bytes_up: 0,
                    bytes_down: 0,
                    status_code: Some(status),
                    blocked: false,
                    obfuscation_profile: if matches!(profile, obfuscation::Profile::None) {
                        None
                    } else {
                        Some(profile.as_str().to_string())
                    },
                    extra: serde_json::json!({
                        "method": method.as_str(),
                        "uri":    scrubbed_uri,
                        "status": status,
                        "duration_ms": start.elapsed().as_millis(),
                        "obfuscation_profile": profile.as_str(),
                    }),
                },
            );
            let mut res = res.map(Body::new);

            // Collect any header names listed in the Connection header value.
            let conn_headers: Vec<String> = res
                .headers()
                .get_all("connection")
                .iter()
                .flat_map(|v| v.to_str().unwrap_or("").split(','))
                .map(|s| s.trim().to_lowercase())
                .collect();
            for name in &conn_headers {
                res.headers_mut().remove(name.as_str());
            }
            for h in &[
                "connection",
                "keep-alive",
                "proxy-connection",
                "te",
                "trailer",
                "trailers",
                "transfer-encoding",
            ] {
                res.headers_mut().remove(*h);
            }
            Ok(res)
        }
        Err(e) => {
            error!(
                target: "audit",
                event = "http_error",
                host = %hostname,
                method = %method,
                uri = %scrubbed_uri,
                duration_ms = start.elapsed().as_millis(),
                error = %e,
                "upstream request failed"
            );
            events::emit(
                &state,
                "http_error",
                &hostname,
                EmitPayload {
                    peer_ip: identity.peer_ip,
                    wg_pubkey: identity.wg_pubkey,
                    device_id: identity.device_id,
                    identity_source: identity.identity_source,
                    peer_hostname: identity.peer_hostname,
                    client_ua: identity.client_ua,
                    bytes_up: 0,
                    bytes_down: 0,
                    status_code: None,
                    blocked: false,
                    obfuscation_profile: None,
                    extra: serde_json::json!({
                        "method": method.as_str(),
                        "uri":    scrubbed_uri,
                        "error_kind": if e.is_connect() { "connect" }
                                      else if e.to_string().contains("timed out") { "timeout" }
                                      else { "other" },
                        "duration_ms": start.elapsed().as_millis(),
                    }),
                },
            );
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}
