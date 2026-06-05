/// Proxy a client TCP stream to its original destination and record tunnel lifecycle events.
///
/// This function establishes a connection to `orig_dst`, proxies bytes bidirectionally between
/// `client` and the upstream connection, and captures up/down byte counts plus a truncated
/// payload preview when plaintext capture is enabled and the flow does not look like TLS. It
/// emits lifecycle events and host/telemetry updates in `state`, applies TCP keepalive to the
/// client, enforces a connection timeout when dialing the upstream, and records final tunnel
/// statistics whether the proxying completes normally or the peer closes the connection
/// prematurely. It also emits payload preview metadata when capture is enabled.
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use tokio::net::TcpStream;
/// // `state`, `tls`, and `profile` would be created by the application context.
/// # async fn _example(state: crate::SharedState, tls: crate::TlsInfo, profile: crate::obfuscation::Profile) {
/// let client: TcpStream = TcpStream::connect("127.0.0.1:0").await.unwrap();
/// let orig_dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
/// let host = "example.com:443".to_string();
/// let category: &'static str = "web";
/// let peer_ip = client.peer_addr().ok().map(|a| a.ip().to_string());
/// crate::tunnel::transparent::run_transparent(client, orig_dst, host, state, category, "allowed_sni", tls, peer_ip, profile).await;
/// # }

/// ```
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_transparent(
    client: tokio::net::TcpStream,
    orig_dst: SocketAddr,
    host: String,
    state: SharedState,
    category: &'static str,
    reason: &'static str,
    tls: TlsInfo,
    identity: crate::identity::ResolvedIdentity,
    profile: crate::obfuscation::Profile,
) {
    set_keepalive(&client);

    match tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(orig_dst),
    )
    .await
    {
        Ok(Ok(upstream)) => {
            let start = Instant::now();
            let context = TunnelAuditContext::new("transparent", category, Some(reason), profile)
                .with_resolution(vec![orig_dst.ip().to_string()], orig_dst.ip().to_string())
                .with_tls(tls.clone());
            info!(
                target: "audit",
                event = "tunnel_open",
                kind = "transparent",
                host = %host,
                category,
                reason,
                "transparent tunnel established"
            );
            if !matches!(profile, crate::obfuscation::Profile::None) {
                state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
                info!(
                    target: "audit",
                    event = "tunnel_obfuscated",
                    kind = "transparent",
                    host = %host,
                    profile = profile.as_str(),
                    category,
                    "transparent tunnel obfuscated"
                );
            }

            context.emit_open(&state, &host, &identity);
            state.record_tunnel_open_for_peer(identity.wg_pubkey.as_deref());

            const PAYLOAD_PREVIEW_LIMIT: usize = 4096;
            let capture_payloads =
                state.config.proxy.capture_plaintext_payloads && !tls_detected(&tls);

            let (mut client_read, mut client_write) = tokio::io::split(client);
            let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

            let mut up_buf = Vec::with_capacity(if capture_payloads {
                PAYLOAD_PREVIEW_LIMIT
            } else {
                0
            });
            let mut down_buf = Vec::with_capacity(if capture_payloads {
                PAYLOAD_PREVIEW_LIMIT
            } else {
                0
            });
            let preview_summary = |buf: &[u8]| {
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, buf)
            };

            let bytes_up_counter = Arc::new(AtomicU64::new(0));
            let bytes_down_counter = Arc::new(AtomicU64::new(0));
            let up_counter = Arc::clone(&bytes_up_counter);
            let down_counter = Arc::clone(&bytes_down_counter);

            let up_task = async {
                let mut buf = [0u8; 8192];
                let mut total = 0u64;
                loop {
                    let n = client_read.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    if let Err(e) = upstream_write.write_all(&buf[..n]).await {
                        let preview_b64 = if capture_payloads {
                            preview_summary(&up_buf)
                        } else {
                            String::new()
                        };
                        debug!(
                            %host,
                            %e,
                            bytes_transferred = total,
                            preview_len = up_buf.len(),
                            preview_b64 = %preview_b64,
                            "transparent upstream write failed"
                        );
                        return Err(e);
                    }
                    total += n as u64;
                    up_counter.fetch_add(n as u64, Ordering::Relaxed);
                    observe_forensic_chunk(
                        &state,
                        &host,
                        category,
                        &identity,
                        PacketDirection::Upstream,
                        n,
                        &tls,
                    );

                    if capture_payloads && up_buf.len() < PAYLOAD_PREVIEW_LIMIT {
                        let take = (PAYLOAD_PREVIEW_LIMIT - up_buf.len()).min(n);
                        up_buf.extend_from_slice(&buf[..take]);
                    }
                }
                Ok::<u64, std::io::Error>(total)
            };

            let down_task = async {
                let mut buf = [0u8; 8192];
                let mut total = 0u64;
                loop {
                    let n = upstream_read.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        let preview_b64 = if capture_payloads {
                            preview_summary(&down_buf)
                        } else {
                            String::new()
                        };
                        debug!(
                            %host,
                            %e,
                            bytes_transferred = total,
                            preview_len = down_buf.len(),
                            preview_b64 = %preview_b64,
                            "transparent downstream write failed"
                        );
                        return Err(e);
                    }
                    total += n as u64;
                    down_counter.fetch_add(n as u64, Ordering::Relaxed);
                    observe_forensic_chunk(
                        &state,
                        &host,
                        category,
                        &identity,
                        PacketDirection::Downstream,
                        n,
                        &tls,
                    );

                    if capture_payloads && down_buf.len() < PAYLOAD_PREVIEW_LIMIT {
                        let take = (PAYLOAD_PREVIEW_LIMIT - down_buf.len()).min(n);
                        down_buf.extend_from_slice(&buf[..take]);
                    }
                }
                Ok::<u64, std::io::Error>(total)
            };

            match tokio::try_join!(up_task, down_task) {
                Ok((_up, _down)) => {
                    let bytes_up = bytes_up_counter.load(Ordering::Relaxed);
                    let bytes_down = bytes_down_counter.load(Ordering::Relaxed);
                    state.record_tunnel_close_for_peer(
                        identity.wg_pubkey.as_deref(),
                        bytes_up,
                        bytes_down,
                    );
                    info!(
                        target: "audit",
                        event = "tunnel_close",
                        kind = "transparent",
                        host = %host,
                        bytes_up = bytes_up,
                        bytes_down = bytes_down,
                        duration_ms = start.elapsed().as_millis(),
                        category,
                        reason,
                        "transparent tunnel closed"
                    );

                    let payload_preview = capture_payloads.then(|| {
                        payload_preview_json(
                            &up_buf,
                            &down_buf,
                            bytes_up,
                            bytes_down,
                            PAYLOAD_PREVIEW_LIMIT,
                        )
                    });

                    context.emit_close(
                        &state,
                        &host,
                        &identity,
                        bytes_up,
                        bytes_down,
                        start.elapsed(),
                        payload_preview,
                    );
                }
                Err(e) => {
                    let bytes_up = bytes_up_counter.load(Ordering::Relaxed);
                    let bytes_down = bytes_down_counter.load(Ordering::Relaxed);
                    state.record_tunnel_close_for_peer(
                        identity.wg_pubkey.as_deref(),
                        bytes_up,
                        bytes_down,
                    );
                    context.emit_close(
                        &state,
                        &host,
                        &identity,
                        bytes_up,
                        bytes_down,
                        start.elapsed(),
                        None,
                    );
                    debug!(%host, %e, "transparent tunnel closed by peer");
                }
            }
        }
        Ok(Err(e)) => error!(%host, %e, "transparent tunnel connect failed"),
        Err(_) => error!(%host, "transparent tunnel connect timed out"),
    }
}

/// Enable TCP keepalive on the given stream with a 10 second idle time and 5 second probe interval.
///
/// This sets the socket's keepalive `time` to 10s and `interval` to 5s. Any error produced while
/// applying these settings is ignored.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> std::io::Result<()> {
/// let stream = tokio::net::TcpStream::connect("127.0.0.1:80").await?;
/// // `set_keepalive` is a private helper used internally to configure TCP keepalive.
/// let _ = stream;
/// # Ok(()) }
/// ```
fn set_keepalive(stream: &tokio::net::TcpStream) {
    use std::time::Duration;

    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}
