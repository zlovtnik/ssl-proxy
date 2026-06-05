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
    let (hostname, port) = parse_host_port(&host);

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
    let upstream = match dial_upstream_with_resolver(&state, &host).await {
        Ok((stream, resolved_ips, selected_ip)) => (stream, resolved_ips, selected_ip),
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
    let (mut upstream, resolved_ips, selected_ip) = upstream;

    let start = Instant::now();
    // Split streams before open so the first H3 data frame can be inspected and replayed.
    let (mut h3_send, mut h3_recv) = stream.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let mut first_up_chunk = Vec::new();
    match timeout(Duration::from_millis(500), h3_recv.recv_data()).await {
        Ok(Ok(Some(mut buf))) => {
            while bytes::Buf::has_remaining(&buf) {
                let chunk: &[u8] = bytes::Buf::chunk(&buf);
                let len = chunk.len();
                first_up_chunk.extend_from_slice(chunk);
                bytes::Buf::advance(&mut buf, len);
            }
        }
        Ok(Ok(None)) => {}
        Ok(Err(e)) => debug!(%host, %e, "QUIC: first H3 recv failed"),
        Err(_) => {}
    }
    let tls = parse_tls_info(&first_up_chunk);
    let category = classify(&hostname, port, tls.alpn.as_deref());
    let context = TunnelAuditContext::new("quic-h3", category, None, profile)
        .with_resolution(resolved_ips.clone(), selected_ip.clone())
        .with_tls(tls.clone());

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
    context.emit_open(&state, &host, &identity);

    /// Maximum bytes to capture per direction for payload preview
    const PAYLOAD_PREVIEW_LIMIT: usize = 4096;

    // Only allocate payload capture buffers for non-TLS tunnel bytes when explicitly enabled.
    let capture_payloads = state.config.proxy.capture_plaintext_payloads
        && tls.sni.is_none()
        && tls.alpn.is_none()
        && tls.tls_ver.is_none()
        && tls.ja3_lite.is_none();
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
        if !first_up_chunk.is_empty() {
            if let Err(e) = upstream_write.write_all(&first_up_chunk).await {
                debug!(%host, %e, "QUIC: upstream first write failed");
                return total;
            }
            total += first_up_chunk.len() as u64;
            if capture_payloads && up_buf.len() < PAYLOAD_PREVIEW_LIMIT {
                let take = (PAYLOAD_PREVIEW_LIMIT - up_buf.len()).min(first_up_chunk.len());
                up_buf.extend_from_slice(&first_up_chunk[..take]);
            }
        }
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

    let payload_preview = capture_payloads
        .then(|| payload_preview_json(&up_buf, &down_buf, up, down, PAYLOAD_PREVIEW_LIMIT));

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

    context.emit_close(
        &state,
        &host,
        &identity,
        up,
        down,
        start.elapsed(),
        payload_preview,
    );
}
