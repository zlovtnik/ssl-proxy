//! Transparent proxy tunnel flow.
//!
//! This module handles raw TCP connections redirected by iptables, extracting
//! the original destination, optional TLS metadata, and then either blocking,
//! bypassing, or proxying the connection. It does not own CONNECT handling.

use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info};

use crate::{
    blocklist,
    events::{self, EmitPayload},
    forensic::{PacketDirection, PeerIdentity},
    obfuscation,
    state::SharedState,
};

use super::classify::{classify, is_cert_pinned_host};
use super::tarpit::MAX_TARPIT_MS;
use super::tls::{peek_tls_info, TlsInfo};

const POLICY_REASON_MATCHED_BLOCKLIST: &str = "matched_blocklist";
const POLICY_REASON_NO_SNI_HTTPS: &str = "no_sni_https";
const POLICY_REASON_CERTIFICATE_PINNING_BYPASS: &str = "certificate_pinning_bypass";
const POLICY_REASON_ALLOWED_SNI: &str = "allowed_sni";
const POLICY_REASON_ALLOWED_PLAINTEXT: &str = "allowed_plaintext";

fn observe_forensic_chunk(
    state: &SharedState,
    host: &str,
    category: &'static str,
    identity: &crate::identity::ResolvedIdentity,
    direction: PacketDirection,
    bytes: usize,
    tls: &TlsInfo,
) {
    let finding = state.forensic.observe_chunk(
        &PeerIdentity {
            peer_ip: identity.peer_ip.clone(),
            wg_pubkey: identity.wg_pubkey.clone(),
        },
        host,
        category,
        direction,
        bytes,
        tls.ja3_lite.as_deref(),
    );
    let Some(finding) = finding else {
        return;
    };

    state.forensic.queue_hardware_command(&finding);
    events::emit(
        state,
        "forensic_flow_flagged",
        host,
        EmitPayload {
            peer_ip: identity.peer_ip.clone(),
            wg_pubkey: identity.wg_pubkey.clone(),
            device_id: identity.device_id.clone(),
            identity_source: identity.identity_source.clone(),
            peer_hostname: identity.peer_hostname.clone(),
            client_ua: identity.client_ua.clone(),
            bytes_up: finding.bytes_up,
            bytes_down: finding.bytes_down,
            status_code: None,
            blocked: false,
            obfuscation_profile: None,
            extra: serde_json::json!({
                "category": finding.category,
                "direction": finding.direction.as_str(),
                "reason": finding.reason,
                "peer_hash": finding.peer_hash,
                "packet_count": finding.packet_count,
                "bytes_up": finding.bytes_up,
                "bytes_down": finding.bytes_down,
                "iat_ema_ms": finding.iat_ema_ms,
                "jitter_ema_ms": finding.jitter_ema_ms,
                "low_jitter_streak": finding.low_jitter_streak,
                "regularity_score": (finding.regularity_score * 1000.0).round() / 1000.0,
                "ja3_lite": finding.ja3_lite,
            }),
        },
    );
}

#[derive(Serialize)]
struct TransparentFingerprint {
    tls_ver: Option<String>,
    alpn: Option<String>,
    cipher_suites_count: Option<u8>,
    ja3_lite: Option<String>,
}

#[derive(Serialize)]
struct TransparentMetrics {
    attempt_count: u64,
    total_blocked_bytes_approx: u64,
    frequency_hz: f64,
    risk_score: f64,
    iat_ms: Option<u64>,
    consecutive_blocks: u32,
}

#[derive(Serialize)]
struct TransparentBlockExtra {
    category: &'static str,
    fingerprint: TransparentFingerprint,
    metrics: TransparentMetrics,
    verdict: &'static str,
    reason: &'static str,
}

#[derive(Clone)]
struct TransparentFlowContext {
    authority: String,
    audit_host: String,
    hostname: Option<String>,
    category: &'static str,
    reason: &'static str,
}

struct TransparentBlockDecision {
    flow: TransparentFlowContext,
    verdict: &'static str,
    attempts: u64,
    blocked_bytes: u64,
    frequency_hz: f64,
    iat_ms: Option<u64>,
    consecutive_blocks: u32,
    risk_score: f64,
}

enum TransparentPolicyDecision {
    Block(TransparentBlockDecision),
    Tarpit(TransparentBlockDecision),
    Bypass(TransparentFlowContext),
    Proxy(TransparentFlowContext),
}

#[derive(Clone, Default)]
struct PlaintextIdentityHints {
    client_ua: Option<String>,
    device_token: Option<String>,
}

/// Orchestrates handling of a single redirected TCP connection from iptables.
///
/// This function processes one transparent-proxy TCP stream by retrieving the original
/// destination address set by the kernel, optionally extracting TLS metadata (when the
/// destination port is 443), classifying the connection, and routing the connection into
/// block, bypass, or proxy flows. It updates shared state, emits lifecycle and audit events,
/// and either terminates, tarpits, bypasses, or proxies the connection as determined by
/// classification and policy.
///
/// # Examples
///
/// ```no_run
/// use tokio::net::TcpListener;
/// # async fn example(state: crate::state::SharedState) -> std::io::Result<()> {
/// let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
/// let (stream, _) = listener.accept().await?;
/// // handle_transparent consumes the stream and the shared state
/// tokio::spawn(async move {
///     crate::tunnel::transparent::handle_transparent(stream, state).await;
/// });
/// # Ok(())
/// # }
/// ```
pub async fn handle_transparent(mut stream: tokio::net::TcpStream, state: SharedState) {
    let orig_dst = match original_dst(&stream) {
        Ok(a) => a,
        Err(e) => {
            error!(%e, "SO_ORIGINAL_DST failed");
            return;
        }
    };

    let tls = if orig_dst.port() == 443 {
        peek_tls_info(&mut stream).await
    } else {
        TlsInfo::default()
    };

    handle_transparent_inner(stream, state, orig_dst, tls).await;
}

async fn handle_transparent_inner(
    mut stream: tokio::net::TcpStream,
    state: SharedState,
    orig_dst: SocketAddr,
    tls: TlsInfo,
) {
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip().to_string());
    if let Some(ref ip) = peer_ip {
        if state.config.proxy.enable_dns_lookups {
            let ptr_hostname = crate::wg_stats::reverse_ptr_lookup(&state, ip).await;
            state.record_peer_hostname(ip, ptr_hostname);
        }
    }
    let hints = if orig_dst.port() == 80 {
        peek_plaintext_identity_hints(&mut stream).await
    } else {
        PlaintextIdentityHints::default()
    };
    let identity = crate::identity::resolve_identity(
        &state,
        peer_ip.clone(),
        hints.device_token.clone(),
        hints.client_ua.clone(),
    );
    match evaluate_transparent_policy(&state, orig_dst, &tls).await {
        TransparentPolicyDecision::Block(decision) => {
            block_transparent_flow(
                &mut stream,
                &state,
                &tls,
                orig_dst,
                identity.clone(),
                decision,
                false,
            )
            .await;
        }
        TransparentPolicyDecision::Tarpit(decision) => {
            block_transparent_flow(
                &mut stream,
                &state,
                &tls,
                orig_dst,
                identity.clone(),
                decision,
                true,
            )
            .await;
        }
        TransparentPolicyDecision::Bypass(flow) => {
            bypass_transparent_flow(stream, state, orig_dst, identity, flow).await;
        }
        TransparentPolicyDecision::Proxy(flow) => {
            if let Some(ref name) = flow.hostname {
                state.record_host_allow(name);
                state.record_host_reason(name, flow.reason);
            }

            let profile = if let Some(ref name) = flow.hostname {
                obfuscation::classify_obfuscation(name, &state.config.obfuscation)
            } else {
                obfuscation::Profile::None
            };

            run_transparent(
                stream,
                orig_dst,
                flow.authority,
                state,
                flow.category,
                flow.reason,
                tls,
                identity,
                profile,
            )
            .await;
        }
    }
}

async fn evaluate_transparent_policy(
    state: &SharedState,
    orig_dst: SocketAddr,
    tls: &TlsInfo,
) -> TransparentPolicyDecision {
    let hostname = tls.sni.clone();
    let authority = match &hostname {
        Some(name) => format!("{name}:{}", orig_dst.port()),
        None => format!("{}:{}", orig_dst.ip(), orig_dst.port()),
    };
    let audit_host = hostname.clone().unwrap_or_else(|| authority.clone());
    let category = classify(
        hostname.as_deref().unwrap_or(""),
        orig_dst.port(),
        tls.alpn.as_deref(),
    );

    if let Some(ref name) = hostname {
        if blocklist::is_blocked(name, state).await {
            let blocked_name = name.clone();
            return build_transparent_block_decision(
                state,
                TransparentFlowContext {
                    authority,
                    audit_host,
                    hostname: Some(blocked_name.clone()),
                    category,
                    reason: POLICY_REASON_MATCHED_BLOCKLIST,
                },
                blocked_name,
                tls,
            )
            .await;
        }
    }

    if orig_dst.port() == 443 && state.config.proxy.fail_closed_no_sni && hostname.is_none() {
        return build_transparent_block_decision(
            state,
            TransparentFlowContext {
                authority: authority.clone(),
                audit_host,
                hostname,
                category,
                reason: POLICY_REASON_NO_SNI_HTTPS,
            },
            authority,
            tls,
        )
        .await;
    }

    if let Some(ref name) = hostname {
        if is_cert_pinned_host(name) {
            return TransparentPolicyDecision::Bypass(TransparentFlowContext {
                authority,
                audit_host,
                hostname,
                category,
                reason: POLICY_REASON_CERTIFICATE_PINNING_BYPASS,
            });
        }
    }

    TransparentPolicyDecision::Proxy(TransparentFlowContext {
        authority,
        audit_host,
        hostname,
        category,
        reason: if tls.sni.is_some() {
            POLICY_REASON_ALLOWED_SNI
        } else {
            POLICY_REASON_ALLOWED_PLAINTEXT
        },
    })
}

async fn build_transparent_block_decision(
    state: &SharedState,
    flow: TransparentFlowContext,
    stats_host: String,
    tls: &TlsInfo,
) -> TransparentPolicyDecision {
    let approx_bytes = (50 + stats_host.len()) as u64;
    state.record_blocked();
    let verdict_change = state.record_host_block(&stats_host, approx_bytes, flow.category);
    state.record_tls_fingerprint(
        &stats_host,
        tls.tls_ver.clone(),
        tls.alpn.clone(),
        tls.cipher_suites_count,
        tls.ja3_lite.clone(),
    );
    state.record_host_reason(&stats_host, flow.reason);
    maybe_resolve_blocked_host(state, flow.hostname.as_ref());

    let (attempts, blocked_bytes, frequency_hz, verdict, iat_ms, consecutive_blocks, risk_score) =
        state
            .host_stats
            .get(&stats_host)
            .map(|s| {
                (
                    s.blocked_attempts,
                    s.blocked_bytes_approx,
                    (s.frequency_hz() * 100.0).round() / 100.0,
                    s.verdict(),
                    s.iat_ms,
                    s.consecutive_blocks,
                    (s.risk_score() * 100.0).round() / 100.0,
                )
            })
            .unwrap_or((1, approx_bytes, 0.0, "BLOCKED", None, 1, 0.0));

    if let Some((prev, next)) = verdict_change {
        let vc = serde_json::json!({
            "type": "verdict_change",
            "host": flow.audit_host,
            "prev_verdict": prev,
            "next_verdict": next,
            "attempt_count": attempts,
            "frequency_hz": frequency_hz,
            "time": chrono::Utc::now().to_rfc3339(),
        });
        let _ = state.events_tx.send(vc.to_string());
    }

    let decision = TransparentBlockDecision {
        flow,
        verdict,
        attempts,
        blocked_bytes,
        frequency_hz,
        iat_ms,
        consecutive_blocks,
        risk_score,
    };

    if verdict == "TARPIT" {
        TransparentPolicyDecision::Tarpit(decision)
    } else {
        TransparentPolicyDecision::Block(decision)
    }
}

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
            set_keepalive(&upstream);
            state.record_tunnel_open_for_peer(identity.wg_pubkey.as_deref());
            events::emit(
                &state,
                "tunnel_open",
                &flow.authority,
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
                    obfuscation_profile: None,
                    extra: serde_json::json!({
                        "kind": "transparent",
                        "category": flow.category,
                        "reason": flow.reason,
                    }),
                },
            );

            let (bytes_up, bytes_down) = tokio::io::copy_bidirectional(&mut stream, &mut upstream)
                .await
                .unwrap_or((0, 0));
            state.record_tunnel_close_for_peer(identity.wg_pubkey.as_deref(), bytes_up, bytes_down);
            events::emit(
                &state,
                "tunnel_close",
                &flow.authority,
                EmitPayload {
                    peer_ip: identity.peer_ip.clone(),
                    wg_pubkey: identity.wg_pubkey.clone(),
                    device_id: identity.device_id.clone(),
                    identity_source: identity.identity_source.clone(),
                    peer_hostname: identity.peer_hostname.clone(),
                    client_ua: identity.client_ua.clone(),
                    bytes_up,
                    bytes_down,
                    status_code: None,
                    blocked: false,
                    obfuscation_profile: None,
                    extra: serde_json::json!({
                        "kind": "transparent",
                        "category": flow.category,
                        "duration_ms": start.elapsed().as_millis(),
                        "reason": flow.reason,
                    }),
                },
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

fn tls_metadata_present(tls: &TlsInfo) -> bool {
    tls.tls_ver.is_some()
        || tls.sni.is_some()
        || tls.alpn.is_some()
        || tls.cipher_suites_count.is_some()
        || tls.ja3_lite.is_some()
}

/// Proxy a client TCP stream to its original destination and record tunnel lifecycle events.
///
/// This function establishes a connection to `orig_dst`, proxies bytes bidirectionally between
/// `client` and the upstream connection, and captures up/down byte counts plus a truncated
/// payload preview when TLS metadata is present or plaintext capture is explicitly enabled. It
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
                        "kind":             "transparent",
                        "category":         category,
                        "reason":           reason,
                        "alpn":             tls.alpn,
                        "tls_ver":          tls.tls_ver,
                        "obfuscation_profile": profile.as_str(),
                    }),
                },
            );
            state.record_tunnel_open_for_peer(identity.wg_pubkey.as_deref());

            const PAYLOAD_PREVIEW_LIMIT: usize = 4096;
            let capture_payloads =
                state.config.proxy.capture_plaintext_payloads || tls_metadata_present(&tls);

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
                        serde_json::json!({
                            "up": base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &up_buf,
                            ),
                            "down": base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &down_buf,
                            ),
                            "truncated_up": bytes_up > PAYLOAD_PREVIEW_LIMIT as u64,
                            "truncated_down": bytes_down > PAYLOAD_PREVIEW_LIMIT as u64,
                        })
                    });

                    let extra = if let Some(payload_preview) = payload_preview {
                        serde_json::json!({
                            "kind":        "transparent",
                            "category":    category,
                            "bytes_up":    bytes_up,
                            "bytes_down":  bytes_down,
                            "duration_ms": start.elapsed().as_millis(),
                            "reason":      reason,
                            "payload_preview": payload_preview,
                        })
                    } else {
                        serde_json::json!({
                            "kind":        "transparent",
                            "category":    category,
                            "bytes_up":    bytes_up,
                            "bytes_down":  bytes_down,
                            "duration_ms": start.elapsed().as_millis(),
                            "reason":      reason,
                        })
                    };

                    events::emit(
                        &state,
                        "tunnel_close",
                        &host,
                        EmitPayload {
                            peer_ip: identity.peer_ip.clone(),
                            wg_pubkey: identity.wg_pubkey.clone(),
                            device_id: identity.device_id.clone(),
                            identity_source: identity.identity_source.clone(),
                            peer_hostname: identity.peer_hostname.clone(),
                            client_ua: identity.client_ua.clone(),
                            bytes_up,
                            bytes_down,
                            status_code: None,
                            blocked: false,
                            obfuscation_profile: if matches!(
                                profile,
                                crate::obfuscation::Profile::None
                            ) {
                                None
                            } else {
                                Some(profile.as_str().to_string())
                            },
                            extra,
                        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use hickory_resolver::TokioAsyncResolver;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::broadcast;

    async fn test_state() -> SharedState {
        let (stats_tx, _) = broadcast::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new());
        let config = crate::config::Config::for_tests();

        AppState::new(client, resolver, stats_tx, events_tx, config)
    }

    #[tokio::test]
    async fn blocked_non_tarpit_transparent_sessions_do_not_fall_through() {
        let state = test_state().await;
        let mut events_rx = state.events_tx.subscribe();
        let blocked_host = "blocked.example";
        let mut blocked = HashSet::new();
        blocked.insert(blocked_host.to_string());
        state.blocklist.store(Arc::new(blocked));

        let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let orig_dst = upstream_listener.local_addr().unwrap();

        let client_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_task =
            tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
        let (stream, _) = client_listener.accept().await.unwrap();
        let _client = client_task.await.unwrap();

        let tls = TlsInfo {
            sni: Some(blocked_host.to_string()),
            alpn: None,
            tls_ver: None,
            cipher_suites_count: None,
            ja3_lite: None,
        };

        handle_transparent_inner(stream, state, orig_dst, tls).await;

        let connected =
            tokio::time::timeout(Duration::from_millis(300), upstream_listener.accept()).await;
        assert!(
            connected.is_err(),
            "blocked transparent session unexpectedly connected to upstream"
        );

        let event: serde_json::Value = serde_json::from_str(&events_rx.recv().await.unwrap())
            .expect("transparent block event should serialize");
        assert_eq!(event["reason"], POLICY_REASON_MATCHED_BLOCKLIST);
    }

    #[tokio::test]
    async fn no_sni_https_is_blocked_before_upstream_connect() {
        let state = test_state().await;
        let mut events_rx = state.events_tx.subscribe();

        let client_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_task =
            tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
        let (stream, _) = client_listener.accept().await.unwrap();
        let _client = client_task.await.unwrap();

        handle_transparent_inner(
            stream,
            state,
            SocketAddr::from(([127, 0, 0, 1], 443)),
            TlsInfo::default(),
        )
        .await;

        let event: serde_json::Value = serde_json::from_str(&events_rx.recv().await.unwrap())
            .expect("transparent no-sni event should serialize");
        assert_eq!(event["reason"], POLICY_REASON_NO_SNI_HTTPS);
        assert_eq!(event["host"], "127.0.0.1:443");
    }

    #[tokio::test]
    async fn pinned_transparent_hosts_bypass_and_connect() {
        let state = test_state().await;
        let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let orig_dst = upstream_listener.local_addr().unwrap();

        let client_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_task =
            tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
        let (stream, _) = client_listener.accept().await.unwrap();

        let state_clone = state.clone();
        let handler = tokio::spawn(async move {
            handle_transparent_inner(
                stream,
                state_clone,
                orig_dst,
                TlsInfo {
                    sni: Some("i.instagram.com".to_string()),
                    alpn: Some("h2".to_string()),
                    tls_ver: Some("TLS1.3".to_string()),
                    cipher_suites_count: Some(4),
                    ja3_lite: Some("771,4865-4866,0-16,29-23,0".to_string()),
                },
            )
            .await;
        });

        let mut client = client_task.await.unwrap();
        let (mut upstream, _) =
            tokio::time::timeout(Duration::from_secs(1), upstream_listener.accept())
                .await
                .expect("bypass should connect upstream")
                .unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(1), upstream.read_exact(&mut buf))
            .await
            .expect("upstream should receive client bytes")
            .unwrap();
        assert_eq!(&buf, b"ping");

        drop(client);
        drop(upstream);
        handler.await.unwrap();
    }
}
