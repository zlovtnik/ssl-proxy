// Plaintext HTTP must be authorized per request, including keep-alive and pipelining.
struct HttpTunnelObservation {
    state: SharedState,
    destination: SocketAddr,
    started: Instant,
    flow: Option<(
        String,
        crate::identity::ResolvedIdentity,
        &'static str,
        TunnelAuditContext,
    )>,
    bytes_up: u64,
    bytes_down: u64,
    up_preview: Vec<u8>,
    down_preview: Vec<u8>,
}

impl HttpTunnelObservation {
    fn open(&mut self, host: &str, identity: &crate::identity::ResolvedIdentity) {
        if self.flow.is_some() {
            return;
        }
        let category = classify(host, 80, None);
        let profile = obfuscation::classify_obfuscation(host, &self.state.config.obfuscation);
        if !matches!(profile, obfuscation::Profile::None) {
            self.state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
        }
        let context = TunnelAuditContext::new(
            "transparent",
            category,
            Some(POLICY_REASON_ALLOWED_PLAINTEXT),
            profile,
        )
        .with_resolution(
            vec![self.destination.ip().to_string()],
            self.destination.ip().to_string(),
        );
        context.emit_open(&self.state, host, identity);
        self.state
            .record_tunnel_open_for_peer(identity.wg_pubkey.as_deref());
        observe_forensic_chunk(
            &self.state,
            host,
            category,
            identity,
            PacketDirection::Upstream,
            self.bytes_up as usize,
            &TlsInfo::default(),
        );
        self.flow = Some((host.to_string(), identity.clone(), category, context));
    }

    fn observe(&mut self, data: &[u8], direction: PacketDirection) {
        let (counter, preview) = match direction {
            PacketDirection::Upstream => (&mut self.bytes_up, &mut self.up_preview),
            PacketDirection::Downstream => (&mut self.bytes_down, &mut self.down_preview),
        };
        *counter += data.len() as u64;
        if self.state.config.proxy.capture_plaintext_payloads {
            let remaining = 4096usize.saturating_sub(preview.len());
            preview.extend_from_slice(&data[..data.len().min(remaining)]);
        }
        if !data.is_empty() {
            if let Some((host, identity, category, _)) = &self.flow {
                observe_forensic_chunk(
                    &self.state,
                    host,
                    category,
                    identity,
                    direction,
                    data.len(),
                    &TlsInfo::default(),
                );
            }
        }
    }
}

// Observe the client socket, including upgraded WebSockets, without changing HTTP framing.
struct TransparentHttpIo {
    stream: tokio::net::TcpStream,
    observation: Arc<std::sync::Mutex<HttpTunnelObservation>>,
}

impl tokio::io::AsyncRead for TransparentHttpIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = std::pin::Pin::new(&mut this.stream).poll_read(cx, buffer);
        if let std::task::Poll::Ready(Ok(())) = &result {
            this.observation
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .observe(&buffer.filled()[before..], PacketDirection::Upstream);
        }
        result
    }
}

impl tokio::io::AsyncWrite for TransparentHttpIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.stream).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(count)) = &result {
            this.observation
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .observe(&data[..*count], PacketDirection::Downstream);
        }
        result
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl Drop for TransparentHttpIo {
    fn drop(&mut self) {
        let observed = self
            .observation
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some((host, identity, _, context)) = &observed.flow {
            observed.state.record_tunnel_close_for_peer(
                identity.wg_pubkey.as_deref(),
                observed.bytes_up,
                observed.bytes_down,
            );
            let preview = observed
                .state
                .config
                .proxy
                .capture_plaintext_payloads
                .then(|| {
                    payload_preview_json(
                        &observed.up_preview,
                        &observed.down_preview,
                        observed.bytes_up,
                        observed.bytes_down,
                        4096,
                    )
                });
            context.emit_close(
                &observed.state,
                host,
                identity,
                observed.bytes_up,
                observed.bytes_down,
                observed.started.elapsed(),
                preview,
            );
            if !observed.up_preview.is_empty() {
                crate::payload_audit::audit_http_preview(
                    &observed.up_preview,
                    host,
                    identity,
                    &observed.state,
                );
            }
        }
    }
}

async fn serve_transparent_http(
    stream: tokio::net::TcpStream,
    state: SharedState,
    orig_dst: SocketAddr,
    peer_ip: Option<String>,
) {
    use hyper_util::rt::{TokioIo, TokioTimer};
    let observation = Arc::new(std::sync::Mutex::new(HttpTunnelObservation {
        state: state.clone(),
        destination: orig_dst,
        started: Instant::now(),
        flow: None,
        bytes_up: 0,
        bytes_down: 0,
        up_preview: Vec::new(),
        down_preview: Vec::new(),
    }));
    let io = TransparentHttpIo {
        stream,
        observation: observation.clone(),
    };
    let service = hyper::service::service_fn(move |req| {
        transparent_http_request(
            req,
            state.clone(),
            orig_dst,
            peer_ip.clone(),
            observation.clone(),
        )
    });
    let result = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(10))
        .max_buf_size(32 * 1024)
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades()
        .await;
    if let Err(error) = result {
        debug!(%error, "transparent HTTP connection closed");
    }
}

fn transparent_http_hostname<B>(req: &hyper::Request<B>) -> Option<String> {
    use hyper::http::uri::Authority;
    let mut hosts = req.headers().get_all(hyper::header::HOST).iter();
    let host = hosts.next()?.to_str().ok()?;
    if hosts.next().is_some() || host.contains('@') {
        return None;
    }
    let authority: Authority = host.parse().ok()?;
    let hostname = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let hostname = hostname.trim_end_matches('.').to_string();
    if hostname.is_empty() {
        return None;
    }
    if let Some(target) = req.uri().authority() {
        if req.uri().scheme_str() != Some("http")
            || target.as_str().contains('@')
            || target
                .host()
                .trim_matches(['[', ']'])
                .trim_end_matches('.')
                .to_ascii_lowercase()
                != hostname
            || target.port_u16().unwrap_or(80) != authority.port_u16().unwrap_or(80)
        {
            return None;
        }
    } else if req.uri().scheme().is_some() || req.method() == hyper::Method::CONNECT {
        return None;
    }
    Some(hostname)
}

async fn transparent_http_request(
    mut req: hyper::Request<hyper::body::Incoming>,
    state: SharedState,
    orig_dst: SocketAddr,
    peer_ip: Option<String>,
    observation: Arc<std::sync::Mutex<HttpTunnelObservation>>,
) -> Result<hyper::Response<axum::body::Body>, std::convert::Infallible> {
    use axum::body::Body;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    let response = |status| {
        Response::builder()
            .status(status)
            .body(Body::empty())
            .unwrap()
    };
    let Some(hostname) = transparent_http_hostname(&req) else {
        return Ok(response(StatusCode::BAD_REQUEST));
    };
    // An h2c/raw upgrade would restore an opaque stream with unchecked authorities.
    let websocket = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if req.headers().get_all(hyper::header::UPGRADE).iter().count() > 1
        || (req.headers().contains_key(hyper::header::UPGRADE) && !websocket)
    {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let tls = TlsInfo::default();
    let identity = crate::identity::resolve_identity(
        &state,
        peer_ip,
        crate::identity::extract_device_token(req.headers()),
        crate::identity::extract_user_agent(req.headers()),
    );
    let decision =
        evaluate_transparent_policy(&state, orig_dst, &tls, Some(hostname.clone())).await;
    match decision {
        TransparentPolicyDecision::Block(decision)
        | TransparentPolicyDecision::Tarpit(decision) => {
            state.record_peer_block(identity.wg_pubkey.as_deref(), decision.blocked_bytes);
            events::emit(
                &state,
                "http_blocked",
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
                    status_code: Some(403),
                    blocked: true,
                    obfuscation_profile: None,
                    extra: serde_json::json!({"category": decision.flow.category, "reason": decision.flow.reason}),
                },
            );
            return Ok(response(StatusCode::FORBIDDEN));
        }
        _ => {}
    }
    state.record_host_allow(&hostname);
    state.record_host_reason(&hostname, POLICY_REASON_ALLOWED_PLAINTEXT);
    let target = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    *req.uri_mut() = target
        .parse()
        .unwrap_or_else(|_| hyper::Uri::from_static("/"));
    req.headers_mut().remove(hyper::header::PROXY_AUTHORIZATION);
    let upgrade = hyper::upgrade::on(&mut req);
    let upstream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(orig_dst),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return Ok(response(StatusCode::BAD_GATEWAY)),
    };
    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await {
            Ok(parts) => parts,
            Err(_) => return Ok(response(StatusCode::BAD_GATEWAY)),
        };
    observation
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .open(&hostname, &identity);
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    match sender
        .send_request(crate::proxy::prepare_origin_request(req.map(Body::new)))
        .await
    {
        Ok(mut result) => {
            if result.status() == StatusCode::SWITCHING_PROTOCOLS {
                if !websocket
                    || !result
                        .headers()
                        .get(hyper::header::UPGRADE)
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
                {
                    return Ok(response(StatusCode::BAD_GATEWAY));
                }
                let upstream_upgrade = hyper::upgrade::on(&mut result);
                tokio::spawn(async move {
                    if let Ok((client, upstream)) = tokio::try_join!(upgrade, upstream_upgrade) {
                        let _ = tokio::io::copy_bidirectional(
                            &mut TokioIo::new(client),
                            &mut TokioIo::new(upstream),
                        )
                        .await;
                    }
                });
            }
            events::emit(
                &state,
                "request",
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
                    status_code: Some(result.status().as_u16()),
                    blocked: false,
                    obfuscation_profile: None,
                    extra: serde_json::json!({"reason": POLICY_REASON_ALLOWED_PLAINTEXT}),
                },
            );
            Ok(result.map(Body::new))
        }
        Err(_) => Ok(response(StatusCode::BAD_GATEWAY)),
    }
}
