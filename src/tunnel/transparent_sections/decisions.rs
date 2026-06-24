fn maybe_resolve_blocked_host(state: &SharedState, hostname: Option<&String>) {
    let Some(hostname) = hostname else {
        return;
    };
    if !state.config.proxy.enable_dns_lookups {
        return;
    }

    let state2 = state.clone();
    let hostname2 = hostname.clone();
    tokio::spawn(async move {
        const TTL_SECS: u64 = 300;
        if state2
            .dns_cache
            .get(&hostname2)
            .map(|e| e.resolved_at.elapsed().as_secs() < TTL_SECS)
            .unwrap_or(false)
        {
            return;
        }
        if let Ok(Ok(addrs)) = tokio::time::timeout(
            tokio::time::Duration::from_millis(500),
            state2.resolver.lookup_ip(hostname2.as_str()),
        )
        .await
        {
            let resolved_ips: Vec<String> = addrs.iter().map(|ip| ip.to_string()).collect();
            if !resolved_ips.is_empty() {
                state2.record_resolved(&hostname2, resolved_ips, None);
            }
        }
    });
}

async fn peek_plaintext_identity_hints(
    stream: &mut tokio::net::TcpStream,
) -> PlaintextIdentityHints {
    let mut buf = vec![0u8; 4096];
    let read = match tokio::time::timeout(
        tokio::time::Duration::from_millis(150),
        stream.peek(&mut buf),
    )
    .await
    {
        Ok(Ok(read)) => read,
        _ => return PlaintextIdentityHints::default(),
    };
    if read == 0 {
        return PlaintextIdentityHints::default();
    }
    let preview = String::from_utf8_lossy(&buf[..read]);
    PlaintextIdentityHints {
        client_ua: extract_http_header_value(&preview, "user-agent")
            .map(|value| crate::identity::truncate(&value, 512)),
        device_token: extract_http_header_value(&preview, crate::identity::DEVICE_TOKEN_HEADER),
        preview: buf[..read].to_vec(),
    }
}

fn extract_http_header_value(preview: &str, header_name: &str) -> Option<String> {
    preview
        .lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case(header_name) {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
}

fn plaintext_host_header(preview: &[u8]) -> Option<String> {
    let preview = std::str::from_utf8(preview).ok()?;
    let host = extract_http_header_value(preview, "host")?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    if host.starts_with('[') || host.rsplit_once(':').is_some() {
        Some(host.to_string())
    } else {
        Some(format!("{host}:80"))
    }
}

async fn block_transparent_flow(
    stream: &mut tokio::net::TcpStream,
    state: &SharedState,
    tls: &TlsInfo,
    orig_dst: SocketAddr,
    identity: crate::identity::ResolvedIdentity,
    decision: TransparentBlockDecision,
    tarpit: bool,
) {
    state.record_peer_block(
        identity.wg_pubkey.as_deref(),
        (50 + decision.flow.audit_host.len()) as u64,
    );

    info!(
        target: "audit",
        event = "tunnel_blocked",
        kind = "transparent",
        host = %decision.flow.audit_host,
        orig_dst = %orig_dst,
        category = decision.flow.category,
        attempt_count = decision.attempts,
        verdict = decision.verdict,
        reason = decision.flow.reason,
        "blocked snitch (transparent)"
    );
    events::emit_serializable(
        state,
        "block",
        &decision.flow.audit_host,
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
        TransparentBlockExtra {
            category: decision.flow.category,
            fingerprint: TransparentFingerprint {
                tls_ver: tls.tls_ver.clone(),
                alpn: tls.alpn.clone(),
                cipher_suites_count: tls.cipher_suites_count,
                ja3_lite: tls.ja3_lite.clone(),
            },
            metrics: TransparentMetrics {
                attempt_count: decision.attempts,
                total_blocked_bytes_approx: decision.blocked_bytes,
                frequency_hz: decision.frequency_hz,
                risk_score: decision.risk_score,
                iat_ms: decision.iat_ms,
                consecutive_blocks: decision.consecutive_blocks,
            },
            verdict: decision.verdict,
            reason: decision.flow.reason,
        },
    );

    if tarpit {
        if let Ok(_permit) = state.tarpit_sem.clone().try_acquire_owned() {
            let tarpit_start = Instant::now();
            let mut sink = tokio::io::sink();
            let _ = tokio::time::timeout(
                tokio::time::Duration::from_millis(MAX_TARPIT_MS),
                tokio::io::copy(stream, &mut sink),
            )
            .await;
            let held_ms = tarpit_start.elapsed().as_millis() as u64;
            state.record_tarpit_held(&decision.flow.audit_host, held_ms);
            info!(
                target: "audit",
                event = "tunnel_tarpitted",
                kind = "transparent",
                host = %decision.flow.audit_host,
                orig_dst = %orig_dst,
                category = decision.flow.category,
                attempt_count = decision.attempts,
                verdict = decision.verdict,
                tarpit_held_ms = held_ms,
                reason = decision.flow.reason,
                "tarpitted snitch (transparent)"
            );
        } else {
            debug!(
                target: "audit",
                event = "tarpit_skipped",
                kind = "transparent",
                host = %decision.flow.audit_host,
                orig_dst = %orig_dst,
                category = decision.flow.category,
                attempt_count = decision.attempts,
                verdict = decision.verdict,
                reason = decision.flow.reason,
                "tarpit skipped due to concurrency limit (transparent)"
            );
        }
    }
}

async fn bypass_transparent_flow(
    mut stream: tokio::net::TcpStream,
    state: SharedState,
    orig_dst: SocketAddr,
    identity: crate::identity::ResolvedIdentity,
    flow: TransparentFlowContext,
    tls: TlsInfo,
) {
    let start = Instant::now();

    if let Some(ref name) = flow.hostname {
        state.record_host_allow(name);
        state.record_host_reason(name, flow.reason);
    }

    info!(
        target: "audit",
        event = "tunnel_bypass",
        kind = "transparent",
        host = %flow.audit_host,
        orig_dst = %orig_dst,
        category = flow.category,
        reason = flow.reason,
        "certificate pinned domain detected, bypassing interception"
    );

    match tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(orig_dst),
    )
    .await
    {
        Ok(Ok(mut upstream)) => {
            super::socket_tuning::configure_tunnel_tcp(&upstream);
            let context = TunnelAuditContext::bypass("transparent", flow.category, flow.reason)
                .with_resolution(vec![orig_dst.ip().to_string()], orig_dst.ip().to_string())
                .with_tls(tls);
            state.record_tunnel_open_for_peer(identity.wg_pubkey.as_deref());
            context.emit_open(&state, &flow.authority, &identity);

            let (bytes_up, bytes_down) =
                super::socket_tuning::copy_bidirectional(&mut stream, &mut upstream)
                    .await
                    .unwrap_or((0, 0));
            state.record_tunnel_close_for_peer(identity.wg_pubkey.as_deref(), bytes_up, bytes_down);
            context.emit_close(
                &state,
                &flow.authority,
                &identity,
                bytes_up,
                bytes_down,
                start.elapsed(),
                None,
            );
        }
        Ok(Err(e)) => {
            error!(host = %flow.audit_host, %e, reason = flow.reason, "transparent bypass connect failed")
        }
        Err(_) => {
            error!(host = %flow.audit_host, reason = flow.reason, "transparent bypass connect timed out")
        }
    }
}

/// Retrieve the original destination address set by the kernel (SO_ORIGINAL_DST).
///
/// This queries the socket option used by transparent proxying and returns the original
/// peer destination as a `SocketAddr`. The function will attempt to obtain an IPv6
/// destination first and fall back to IPv4 if necessary.
///
/// # Examples
///
/// ```no_run
/// use tokio::net::TcpStream;
/// use std::net::SocketAddr;
///
/// async fn handle(stream: TcpStream) -> std::io::Result<()> {
///     let orig: SocketAddr = crate::tunnel::transparent::original_dst(&stream)?;
///     println!("original destination: {}", orig);
///     Ok(())
/// }
/// ```
pub(crate) fn original_dst(stream: &tokio::net::TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const IPV4_ORIG_DST_OPT: libc::c_int = libc::SO_ORIGINAL_DST;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const IPV4_ORIG_DST_OPT: libc::c_int = 80;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const IPV6_ORIG_DST_OPT: libc::c_int = libc::IP6T_SO_ORIGINAL_DST;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const IPV6_ORIG_DST_OPT: libc::c_int = 80;

    let fd = stream.as_raw_fd();
    let v6: Result<SocketAddr, _> = unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_ORIG_DST_OPT,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret == 0 {
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::from((ip, port)))
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    if let Ok(addr) = v6 {
        return Ok(addr);
    }

    let addr: libc::sockaddr_in = unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            IPV4_ORIG_DST_OPT,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        addr
    };
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::from((ip, port)))
}

fn tls_detected(tls: &TlsInfo) -> bool {
    tls.sni.is_some() || tls.alpn.is_some() || tls.tls_ver.is_some() || tls.ja3_lite.is_some()
}
