//! QUIC/HTTP3 explicit proxy listener.
//!
//! This module accepts HTTP/3 CONNECT requests over QUIC and proxies the
//! resulting tunnel to the upstream destination. It does not handle admin
//! traffic or non-CONNECT HTTP methods beyond returning `405`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::blocklist;
use crate::check_proxy_auth;
use crate::config::Config;
use crate::events::{self, EmitPayload};
use crate::obfuscation;
use crate::state::SharedState;
use crate::tunnel::{dial_upstream_with_resolver, parse_host_port};

/// Create a TLS server configuration for QUIC using the certificate and private key
/// files specified in `config.tls.cert_path` and `config.tls.key_path`.
///
/// This function reads and parses PEM-formatted certificate chain and the first
/// private key, constructs a `rustls::ServerConfig` with no client authentication,
/// and enables HTTP/3 ALPN protocols (`h3` and `h3-29`).
///
/// # Panics
///
/// Panics if either path is not set on the provided `Config`, if the files cannot
/// be read, or if the PEM contents are malformed or do not contain a private key.
///
/// # Returns
///
/// An `Arc<rustls::ServerConfig>` configured for use with QUIC and HTTP/3.
///
/// # Examples
///
/// ```no_run
/// // Construct or obtain a `Config` with `tls.cert_path` and `tls.key_path` set,
/// // then pass a reference to this function to build the TLS config for QUIC.
/// // let cfg: Config = ...;
/// // let tls = build_rustls_config(&cfg);
/// ```
async fn build_rustls_config(config: &Config) -> Arc<rustls::ServerConfig> {
    let cert_path = config
        .tls
        .cert_path
        .as_ref()
        .expect("tls_cert_path must be set for QUIC");
    let key_path = config
        .tls
        .key_path
        .as_ref()
        .expect("tls_key_path must be set for QUIC");

    let cert_pem = tokio::fs::read(cert_path)
        .await
        .expect("failed to read TLS cert for QUIC");
    let key_pem = tokio::fs::read(key_path)
        .await
        .expect("failed to read TLS key for QUIC");
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .expect("invalid cert PEM for QUIC");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("failed to parse key PEM for QUIC")
        .expect("no private key found for QUIC");

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("invalid TLS config for QUIC");

    // Enable HTTP/3 ALPN with draft fallback for browser compatibility
    tls_config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];

    Arc::new(tls_config)
}

/// Start a QUIC + HTTP/3 listener on UDP 0.0.0.0:443 and spawn a task for each incoming connection.
///
/// The listener runs until `shutdown` is cancelled. For each accepted QUIC connection a background
/// task is spawned to process HTTP/3 requests for the lifetime of that connection. If `proxy_creds`
/// is provided, those credentials are used to authenticate incoming proxy requests.
///
/// # Examples
///
/// ```
/// // Typical usage pattern:
/// // let state: SharedState = ...;
/// // let config: Config = ...;
/// let shutdown = tokio_util::sync::CancellationToken::new();
/// // Spawn the listener (usually run in a dedicated runtime task)
/// // tokio::spawn(run_quic_listener(state, config, shutdown.clone(), None));
/// // Trigger shutdown when desired:
/// shutdown.cancel();
/// ```
const MAX_CONCURRENT_CONNECTIONS: usize = 10_000;

pub async fn run_quic_listener(
    state: SharedState,
    config: Config,
    shutdown: CancellationToken,
    proxy_creds: Option<Arc<(String, String)>>,
) {
    let rustls_config = build_rustls_config(&config).await;

    let quinn_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config);
    let quinn_config = match quinn_config {
        Ok(c) => c,
        Err(e) => {
            error!(%e, "failed to build QUIC server config");
            return;
        }
    };
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_config));

    let addr: SocketAddr = "0.0.0.0:443"
        .parse()
        .expect("static QUIC listen address must parse");
    let endpoint = match quinn::Endpoint::server(server_config, addr) {
        Ok(ep) => ep,
        Err(e) => {
            error!(%addr, %e, "failed to bind QUIC endpoint");
            return;
        }
    };
    info!(%addr, "QUIC/H3 listener active");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("QUIC listener shutting down");
                endpoint.close(0u32.into(), b"shutdown");

                // Wait for all in-flight connections to complete gracefully
                info!("Waiting for {} active QUIC connections to complete", tasks.len());
                loop {
                    match timeout(Duration::from_secs(30), tasks.join_next()).await {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => {
                            warn!("timed out draining QUIC connection tasks during shutdown");
                            break;
                        }
                    }
                }
                tasks.abort_all();
                info!("All QUIC connections drained");

                break;
            }
            incoming = endpoint.accept() => {
                let incoming = match incoming {
                    Some(i) => i,
                    None => {
                        info!("QUIC endpoint closed");
                        break;
                    }
                };

                // Acquire connection permit before spawning (applies backpressure at capacity)
                let permit = semaphore.clone().acquire_owned().await.expect("semaphore closed");

                let state = state.clone();
                let config = config.clone();
                let creds = proxy_creds.clone();

                tasks.spawn(async move {
                    // Hold permit for entire connection lifetime
                    let _permit_guard = permit;
                    handle_quic_connection(incoming, state, config, creds).await;
                });
            }
        }
    }
}

/// Handle a single QUIC connection: accept it, then process HTTP/3 requests.
async fn handle_quic_connection(
    incoming: quinn::Incoming,
    state: SharedState,
    config: Config,
    proxy_creds: Option<Arc<(String, String)>>,
) {
    let connection = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            debug!(%e, "QUIC connection failed");
            return;
        }
    };
    let peer = connection.remote_address();
    debug!(%peer, "QUIC connection established");

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match h3::server::Connection::new(h3_quinn::Connection::new(connection)).await {
            Ok(c) => c,
            Err(e) => {
                debug!(%peer, %e, "H3 connection setup failed");
                return;
            }
        };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let state = state.clone();
                let config = config.clone();
                let creds = proxy_creds.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            handle_h3_request(req, stream, state, config, peer, creds).await;
                        }
                        Err(e) => {
                            debug!(%peer, %e, "H3 request resolve failed");
                        }
                    }
                });
            }
            Ok(None) => {
                debug!(%peer, "H3 connection closed");
                break;
            }
            Err(e) => {
                debug!(%peer, %e, "H3 accept error");
                break;
            }
        }
    }
}

/// Handle an individual HTTP/3 proxy request over a bidirectional H3 stream.
///
/// This function processes an incoming HTTP/3 request and implements CONNECT-style
/// proxy behavior:
/// - If proxy credentials are configured, verifies Basic auth and returns a 407
///   challenge when authentication fails.
/// - Returns 405 for any non-CONNECT methods.
/// - For CONNECT requests, extracts the target from the `:authority` pseudo-header,
///   checks the blocklist, and either closes the request with an immediate OK (when
///   blocked) or opens a TCP connection to the resolved target and tunnels bytes
///   bidirectionally between the H3 stream and the upstream TCP connection.
/// - Emits `tunnel_open`, `tunnel_close`, and `block` events (with a small base64
///   payload preview), and updates allow/block accounting on the shared state.
///
/// Observable side effects include sending appropriate H3 responses (400/405/407/200),
/// stopping the H3 send stream on upstream connection failures, opening a TCP
/// connection to the target for successful CONNECTs, and emitting audit/events.
///
/// # Examples
///
/// Build a CONNECT request to use with an H3 handler:
///
/// ```
/// use axum::http::Request;
///
/// let req = Request::builder()
///     .method("CONNECT")
///     .uri("https://example.com:443")
///     .body(())
///     .unwrap();
///
/// // Pass `req` to an H3 handler along with a stream, state, config, peer, and optional creds.
/// // The full call requires runtime resources and types from the surrounding crate and
/// // therefore is not shown here.
/// ```
async fn handle_h3_request(
    req: axum::http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: SharedState,
    config: Config,
    peer: SocketAddr,
    proxy_creds: Option<Arc<(String, String)>>,
) {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let device_token = crate::identity::extract_device_token(req.headers());
    let user_agent = crate::identity::extract_user_agent(req.headers());
    let identity = crate::identity::resolve_identity(
        &state,
        Some(peer.ip().to_string()),
        device_token,
        user_agent,
    );

    // Proxy authentication check — all H3 requests are proxy requests
    // (QUIC/H3 is only used for CONNECT tunnels, not internal management).
    if let Some(ref creds) = proxy_creds {
        if !check_proxy_auth(&req, &creds.0, &creds.1) {
            let resp = axum::http::Response::builder()
                .status(axum::http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("Proxy-Authenticate", "Basic realm=\"proxy\"")
                .body(())
                .expect("proxy auth challenge response must build");
            stream.send_response(resp).await.ok();
            stream.finish().await.ok();
            return;
        }
    }

    if method != axum::http::Method::CONNECT {
        // Non-CONNECT: return 405 Method Not Allowed
        let resp = axum::http::Response::builder()
            .status(axum::http::StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .expect("405 response must build");
        if let Err(e) = stream.send_response(resp).await {
            debug!(%peer, %e, "failed to send H3 405 response");
        }
        stream.finish().await.ok();
        return;
    }

    // Extract host from :authority pseudo-header
    let host = match uri.authority().map(|a| a.to_string()) {
        Some(h) => h,
        None => {
            error!(%peer, uri = %uri, "H3 CONNECT missing :authority");
            let resp = axum::http::Response::builder()
                .status(axum::http::StatusCode::BAD_REQUEST)
                .body(())
                .expect("400 response must build");
            stream.send_response(resp).await.ok();
            stream.finish().await.ok();
            return;
        }
    };

    // Parse host with proper IPv6 support
    let (hostname, _port) = parse_host_port(&host);

    // Blocklist check — same logic as tunnel::handle (lines 801-935)
    if blocklist::is_blocked(&hostname, &state).await {
        #[derive(Serialize)]
        struct QuicBlockExtra {
            kind: &'static str,
        }

        state.record_blocked();
        let approx_bytes = (50 + hostname.len()) as u64;
        state.record_host_block(&hostname, approx_bytes, "quic");
        state.record_peer_block(identity.wg_pubkey.as_deref(), approx_bytes);
        info!(
            target: "audit",
            event = "tunnel_blocked",
            kind = "quic-h3",
            host = %host,
            "blocked snitch (QUIC/H3)"
        );
        events::emit_serializable(
            &state,
            "block",
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
            QuicBlockExtra { kind: "quic-h3" },
        );

        // Return 200 OK then immediately close (fast drop)
        let resp = axum::http::Response::builder()
            .status(axum::http::StatusCode::OK)
            .body(())
            .expect("blocked QUIC response must build");
        stream.send_response(resp).await.ok();
        stream.finish().await.ok();
        return;
    }

    // Classify obfuscation profile after blocklist check
    let profile = obfuscation::classify_obfuscation(&hostname, &config.obfuscation);

    // Record allow for streak reset
    state.record_host_allow(&hostname);

    // Send 200 OK to acknowledge the CONNECT
    let resp = axum::http::Response::builder()
        .status(axum::http::StatusCode::OK)
        .body(())
        .expect("QUIC CONNECT response must build");
    if let Err(e) = stream.send_response(resp).await {
        debug!(%peer, %e, "failed to send H3 200 response");
        return;
    }

    // Connect to the upstream target
    let mut upstream = match dial_upstream_with_resolver(&state, &host).await {
        Ok((stream, _resolved_ips, _selected_ip)) => stream,
        Err(e) => {
            error!(
                %host,
                error_kind = e.class(),
                error = %e.detail(),
                "QUIC: failed to connect to tunnel target"
            );
            stream.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
            stream.finish().await.ok();
            return;
        }
    };

    let start = Instant::now();
    info!(
        target: "audit",
        event = "tunnel_open",
        kind = "quic-h3",
        host = %host,
        "QUIC tunnel established"
    );
    if !matches!(profile, crate::obfuscation::Profile::None) {
        state
            .obfuscated_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        info!(
            target: "audit",
            event = "tunnel_obfuscated",
            kind = "quic-h3",
            host = %host,
            profile = profile.as_str(),
            "QUIC tunnel obfuscated"
        );
    }
    state.record_tunnel_open_for_peer(identity.wg_pubkey.as_deref());
    events::emit(
        &state,
        "tunnel_open",
        &host,
        EmitPayload {
            peer_ip: identity.peer_ip.clone(),
            wg_pubkey: identity.wg_pubkey.clone(),
            device_id: identity.device_id.clone(),
            identity_source: identity.identity_source.clone(),
            peer_hostname: identity.peer_hostname.clone(),
            client_ua: identity.client_ua.clone(),
            bytes_up: 0,
            bytes_down: 0,
            status_code: None,
            blocked: false,
            obfuscation_profile: if matches!(profile, crate::obfuscation::Profile::None) {
                None
            } else {
                Some(profile.as_str().to_string())
            },
            extra: serde_json::json!({
                "kind": "quic-h3",
            }),
        },
    );

    /// Maximum bytes to capture per direction for payload preview
    const PAYLOAD_PREVIEW_LIMIT: usize = 4096;

    // Bidirectional copy between H3 stream and upstream TCP.
    // Split the H3 bidi stream into send/recv halves and the upstream TCP stream.
    let (mut h3_send, mut h3_recv) = stream.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    // Only allocate payload capture buffers if explicitly enabled in configuration
    let capture_payloads = state.config.proxy.capture_plaintext_payloads;
    let mut up_buf = if capture_payloads {
        Vec::with_capacity(PAYLOAD_PREVIEW_LIMIT)
    } else {
        Vec::new()
    };
    let mut down_buf = if capture_payloads {
        Vec::with_capacity(PAYLOAD_PREVIEW_LIMIT)
    } else {
        Vec::new()
    };

    // H3 → upstream: read H3 data chunks and write to TCP
    let h3_to_upstream = async {
        let mut total: u64 = 0;
        loop {
            match h3_recv.recv_data().await {
                Ok(Some(mut buf)) => {
                    while bytes::Buf::has_remaining(&buf) {
                        let chunk: &[u8] = bytes::Buf::chunk(&buf);
                        let len = chunk.len();
                        if let Err(e) = upstream_write.write_all(chunk).await {
                            debug!(%host, %e, "QUIC: upstream write failed");
                            return total;
                        }
                        total += len as u64;

                        // Capture first N bytes only if payload capture is enabled
                        if capture_payloads && up_buf.len() < PAYLOAD_PREVIEW_LIMIT {
                            let take = (PAYLOAD_PREVIEW_LIMIT - up_buf.len()).min(len);
                            up_buf.extend_from_slice(&chunk[..take]);
                        }

                        bytes::Buf::advance(&mut buf, len);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    debug!(%host, %e, "QUIC: H3 recv failed");
                    break;
                }
            }
        }
        total
    };

    // upstream → H3: read TCP and send as H3 data
    let upstream_to_h3 = async {
        let mut total: u64 = 0;
        let mut buf = vec![0u8; 16384];
        loop {
            match upstream_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&buf[..n]);
                    if let Err(e) = h3_send.send_data(data).await {
                        debug!(%host, %e, "QUIC: H3 send failed");
                        break;
                    }
                    total += n as u64;

                    // Capture first N bytes only if payload capture is enabled
                    if capture_payloads && down_buf.len() < PAYLOAD_PREVIEW_LIMIT {
                        let take = (PAYLOAD_PREVIEW_LIMIT - down_buf.len()).min(n);
                        down_buf.extend_from_slice(&buf[..take]);
                    }
                }
                Err(e) => {
                    debug!(%host, %e, "QUIC: upstream read failed");
                    break;
                }
            }
        }
        h3_send.finish().await.ok();
        total
    };

    let (up, down) = tokio::join!(h3_to_upstream, upstream_to_h3);
    state.record_tunnel_close_for_peer(identity.wg_pubkey.as_deref(), up, down);

    // Only build payload preview when capture is explicitly enabled
    let payload_preview = if capture_payloads {
        let mut up_redacted = up_buf.clone();
        let mut down_redacted = down_buf.clone();

        redact_sensitive_data(&mut up_redacted);
        redact_sensitive_data(&mut down_redacted);

        Some(serde_json::json!({
            "up": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &up_redacted),
            "down": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &down_redacted),
            "truncated_up": up > PAYLOAD_PREVIEW_LIMIT as u64,
            "truncated_down": down > PAYLOAD_PREVIEW_LIMIT as u64,
            "byte_count_up": up_buf.len(),
            "byte_count_down": down_buf.len(),
            "redacted": true,
        }))
    } else {
        // When capture is disabled: only include metadata, no raw bytes
        Some(serde_json::json!({
            "capture_disabled": true,
            "truncated_up": up > PAYLOAD_PREVIEW_LIMIT as u64,
            "truncated_down": down > PAYLOAD_PREVIEW_LIMIT as u64,
        }))
    };

    info!(
        target: "audit",
        event = "tunnel_close",
        kind = "quic-h3",
        host = %host,
        bytes_up = up,
        bytes_down = down,
        duration_ms = start.elapsed().as_millis(),
        "QUIC tunnel closed"
    );

    // Emit event with payload preview for downstream sync consumers
    events::emit(
        &state,
        "tunnel_close",
        &host,
        EmitPayload {
            peer_ip: identity.peer_ip,
            wg_pubkey: identity.wg_pubkey,
            device_id: identity.device_id,
            identity_source: identity.identity_source,
            peer_hostname: identity.peer_hostname,
            client_ua: identity.client_ua,
            bytes_up: up,
            bytes_down: down,
            status_code: None,
            blocked: false,
            obfuscation_profile: if matches!(profile, crate::obfuscation::Profile::None) {
                None
            } else {
                Some(profile.as_str().to_string())
            },
            extra: serde_json::json!({
                "kind":        "quic-h3",
                "bytes_up":    up,
                "bytes_down":  down,
                "duration_ms": start.elapsed().as_millis(),
                "payload_preview": payload_preview,
            }),
        },
    );
}

/// Redact known sensitive patterns from captured payload.
fn redact_sensitive_data(buf: &mut Vec<u8>) {
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
                // Cookie and Set-Cookie headers mask entire line to preserve all values
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
        mask_range(buf, pos + "bearer ".len(), b"\r\n;& \t");
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
                    mask_range(buf, value_start + 1, b"\"");
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
    fn redacts_cookie_multi_pairs() {
        let mut payload = b"Cookie: a=1; b=2; c=three\r\nOther-Header: value\r\n".to_vec();
        redact_sensitive_data(&mut payload);
        let redacted = String::from_utf8(payload).unwrap();

        // Verify all cookie values are redacted
        assert!(!redacted.contains("a=1"));
        assert!(!redacted.contains("b=2"));
        assert!(!redacted.contains("c=three"));

        // Verify cookie key remains
        assert!(redacted.contains("Cookie:"));

        // Verify other header is untouched
        assert!(redacted.contains("Other-Header: value"));

        // All values are completely masked - no structure information remains
        assert!(!redacted.contains('='));
        assert!(!redacted.contains("1"));
        assert!(!redacted.contains("2"));
        assert!(!redacted.contains("three"));
    }
}
