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
    payload_redaction::payload_preview_json,
    state::SharedState,
};

use super::audit_event::TunnelAuditContext;
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
    preview: Vec<u8>,
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
    if orig_dst.port() == 80 && !hints.preview.is_empty() {
        let audit_host = plaintext_host_header(&hints.preview).unwrap_or_else(|| {
            tls.sni
                .clone()
                .unwrap_or_else(|| format!("{}:{}", orig_dst.ip(), orig_dst.port()))
        });
        crate::payload_audit::audit_http_preview(&hints.preview, &audit_host, &identity, &state);
    }
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
            bypass_transparent_flow(stream, state, orig_dst, identity, flow, tls).await;
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
    state.record_classification(category);

    if let Some(ref name) = hostname {
        if blocklist::is_blocked(name, state) {
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
            "time": crate::time::now_rfc3339(),
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
