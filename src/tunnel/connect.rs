//! Explicit HTTP CONNECT tunnel flow.
//!
//! This module owns CONNECT handshake processing, block decisions, bypass
//! handling for certificate-pinned destinations, and the steady-state tunnel
//! copy loop. It does not handle transparent-proxy sockets.

// Packet ownership stays out of scope for the cutover core. See
// docs/adr/0002-packet-ownership-deferred.md for the deferred embedded-TUN path.
use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

use crate::{
    blocklist,
    events::{self, EmitPayload},
    obfuscation,
    state::SharedState,
};

use super::classify::{classify, is_cert_pinned_host};
use super::dial::{dial_upstream_with_resolver, parse_host_port};
use super::tarpit::run_tarpit;

/// Handle an explicit HTTP CONNECT request.
pub async fn handle(
    mut req: Request<Body>,
    state: SharedState,
    peer_ip: Option<String>,
) -> Result<Response<Body>, hyper::Error> {
    let host = match req.uri().authority().map(|a| a.to_string()) {
        Some(h) => h,
        None => {
            error!(uri = %req.uri(), "CONNECT request missing host");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())
                .expect("CONNECT bad request response must build"));
        }
    };

    let connect_ua: Option<String> = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect());
    let device_token = crate::identity::extract_device_token(req.headers());
    let identity = crate::identity::resolve_identity(
        &state,
        peer_ip.clone(),
        device_token,
        connect_ua.clone(),
    );

    let (hostname_owned, port) = parse_host_port(&host);
    let category = classify(&hostname_owned, port, None);

    let upgrade_fut = hyper::upgrade::on(&mut req);
    let hostname = hostname_owned.as_str();

    if blocklist::is_blocked(hostname, &state).await {
        let blocked_session_id = uuid::Uuid::new_v4().to_string();
        state.record_blocked();
        let approx_bytes = (50 + hostname.len()) as u64;
        state.record_peer_block(identity.wg_pubkey.as_deref(), approx_bytes);
        let verdict_change = state.record_host_block(hostname, approx_bytes, category);
        let (attempts, blocked_bytes, freq_hz, verdict, streak, risk) = state
            .host_stats
            .get(hostname)
            .map(|s| {
                (
                    s.blocked_attempts,
                    s.blocked_bytes_approx,
                    s.frequency_hz(),
                    s.verdict(),
                    s.consecutive_blocks,
                    (s.risk_score() * 100.0).round() / 100.0,
                )
            })
            .unwrap_or((1, approx_bytes, 0.0, "BLOCKED", 1, 0.0));
        if let Some((prev, next)) = verdict_change {
            let vc = serde_json::json!({
                "type": "verdict_change", "host": hostname,
                "prev_verdict": prev, "next_verdict": next,
                "attempt_count": attempts, "frequency_hz": (freq_hz * 100.0).round() / 100.0,
                "time": chrono::Utc::now().to_rfc3339(),
            });
            let _ = state.events_tx.send(vc.to_string());
        }
        {
            let state2 = state.clone();
            let hostname2 = hostname.to_string();
            if state2.config.proxy.enable_dns_lookups {
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
                        let resolved_ips: Vec<String> =
                            addrs.iter().map(|ip| ip.to_string()).collect();
                        if !resolved_ips.is_empty() {
                            state2.record_resolved(&hostname2, resolved_ips, None);
                        }
                    }
                });
            }
        }
        info!(
            target: "audit",
            event = "tunnel_blocked",
            kind = "connect",
            host = %host,
            category,
            attempt_count = attempts,
            verdict,
            "blocked snitch"
        );
        events::emit_serializable(
            &state,
            "session.blocked",
            hostname,
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
            serde_json::json!({
                "blocked_session_id": blocked_session_id,
                "category": category,
                "verdict": verdict,
                "attempt_count": attempts,
                "blocked_bytes": blocked_bytes,
                "risk_score": risk,
                "consecutive_blocks": streak
            }),
        );

        if verdict == "TARPIT" {
            if let Ok(permit) = state.tarpit_sem.clone().try_acquire_owned() {
                let host_owned = hostname.to_string();
                let state_clone = state.clone();
                tokio::spawn(async move {
                    run_tarpit(upgrade_fut, host_owned, state_clone.clone()).await;
                    drop(permit);
                });
            } else {
                tokio::spawn(async move {
                    if let Ok(upgraded) = upgrade_fut.await {
                        drop(TokioIo::new(upgraded));
                    }
                });
            }

            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/plain; charset=utf-8")
                .body(Body::from("Access denied"))
                .expect("CONNECT tarpit denial response must build"));
        }

        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade_fut.await {
                let mut stream = TokioIo::new(upgraded);
                let _ = tokio::time::timeout(
                    tokio::time::Duration::from_millis(200),
                    tokio::io::copy(&mut stream, &mut tokio::io::sink()),
                )
                .await;
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(Body::from("Access denied"))
            .expect("CONNECT denial response must build"));
    }

    let is_pinned_app = is_cert_pinned_host(hostname);

    if is_pinned_app {
        let start = Instant::now();
        info!(
            target: "audit",
            event = "tunnel_bypass",
            kind = "connect",
            host = %host,
            category,
            reason = "certificate_pinning",
            "certificate-pinned domain bypass enabled"
        );

        let identity = identity.clone();
        tokio::spawn(async move {
            let upgraded = match upgrade_fut.await {
                Ok(u) => u,
                Err(_) => return,
            };

            let mut client_io = TokioIo::new(upgraded);

            match dial_upstream_with_resolver(&state, &host).await {
                Ok((mut upstream, resolved_ips, selected_ip)) => {
                    set_keepalive(&upstream);
                    state.record_tunnel_open_for_peer(identity.wg_pubkey.as_deref());
                    info!(
                        target: "audit",
                        event = "tunnel_open",
                        kind = "bypass",
                        host = %host,
                        category,
                        resolved_ips = ?resolved_ips,
                        selected_ip = %selected_ip,
                        obfuscation_profile = "none",
                        reason = "certificate_pinning",
                        "bypass tunnel established"
                    );
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
                            obfuscation_profile: Some("none".to_string()),
                            extra: serde_json::json!({
                                "kind":                "bypass",
                                "category":            category,
                                "resolved_ips":        resolved_ips,
                                "selected_ip":         selected_ip,
                                "obfuscation_profile": "none",
                                "bypass_reason":       "certificate_pinning",
                            }),
                        },
                    );

                    let (bytes_up, bytes_down) =
                        tokio::io::copy_bidirectional(&mut client_io, &mut upstream)
                            .await
                            .unwrap_or((0, 0));
                    state.record_tunnel_close_for_peer(
                        identity.wg_pubkey.as_deref(),
                        bytes_up,
                        bytes_down,
                    );

                    info!(
                        target: "audit",
                        event = "tunnel_close",
                        kind = "bypass",
                        host = %host,
                        bytes_up,
                        bytes_down,
                        duration_ms = start.elapsed().as_millis(),
                        category,
                        obfuscation_profile = "none",
                        reason = "certificate_pinning",
                        "bypass tunnel closed"
                    );
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
                            obfuscation_profile: Some("none".to_string()),
                            extra: serde_json::json!({
                                "kind":                "bypass",
                                "category":            category,
                                "bytes_up":            bytes_up,
                                "bytes_down":          bytes_down,
                                "duration_ms":         start.elapsed().as_millis(),
                                "selected_ip":         selected_ip,
                                "obfuscation_profile": "none",
                                "bypass_reason":       "certificate_pinning",
                            }),
                        },
                    );
                }
                Err(e) => {
                    error!(
                        %host,
                        failure_class = e.class(),
                        error = %e.detail(),
                        "bypass tunnel connect failed"
                    );
                    let _ = client_io.shutdown().await;
                }
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .expect("CONNECT bypass response must build"));
    }

    let profile = obfuscation::classify_obfuscation(hostname, &state.config.obfuscation);
    state.record_host_allow(hostname);

    tokio::spawn(async move {
        let identity = identity.clone();
        match upgrade_fut.await {
            Ok(upgraded) => {
                run_tunnel(upgraded, host, state, category, identity, profile).await;
            }
            Err(e) => {
                let error_kind = if e.is_canceled() {
                    "client_disconnected"
                } else {
                    "unknown"
                };

                error!(
                    %host,
                    peer_ip = %peer_ip.as_deref().unwrap_or("-"),
                    user_agent = %connect_ua.as_deref().unwrap_or("-"),
                    %category,
                    error_kind,
                    %e,
                    "CONNECT upgrade failed"
                );
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("CONNECT success response must build"))
}

/// Handle a fully upgraded CONNECT tunnel: establish an upstream connection, forward bidirectional traffic, and record/emit tunnel lifecycle events.
///
/// This function dials the configured upstream for `host`, emits `tunnel_open`/`tunnel_close` events, updates tunnel accounting in `state`, optionally records Oracle DB session data when enabled, and performs bidirectional byte forwarding between the client (represented by the completed HTTP upgrade) and the upstream connection. On dial failure or copy errors it logs the error and attempts to shut down the client side; successful completion records transferred byte counts and duration.
///
/// # Examples
///
/// ```no_run
/// # use tokio::runtime::Runtime;
/// # async fn example() {
/// // After completing an HTTP upgrade, pass the upgraded stream and metadata to run_tunnel.
/// // `upgraded`, `state` and other values are placeholders for the real values your caller will have.
/// // tokio::spawn(async move {
/// //     run_tunnel(upgraded, host.to_string(), state, "category", peer_ip, profile).await;
/// // });
/// # }
/// ```
pub(crate) async fn run_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    state: SharedState,
    category: &'static str,
    identity: crate::identity::ResolvedIdentity,
    profile: crate::obfuscation::Profile,
) {
    let mut client = TokioIo::new(upgraded);
    match dial_upstream_with_resolver(&state, &host).await {
        Ok((mut upstream, resolved_ips, selected_ip)) => {
            set_keepalive(&upstream);
            let start = Instant::now();
            info!(
                target: "audit",
                event = "tunnel_open",
                kind = "connect",
                host = %host,
                category,
                resolved_ips = ?resolved_ips,
                selected_ip = %selected_ip,
                "tunnel established"
            );

            if !matches!(profile, crate::obfuscation::Profile::None) {
                state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
                info!(
                    target: "audit",
                    event = "tunnel_obfuscated",
                    kind = "connect",
                    host = %host,
                    profile = profile.as_str(),
                    category,
                    "connect tunnel obfuscated"
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
                        "kind":             "connect",
                        "category":         category,
                        "resolved_ips":     resolved_ips,
                        "selected_ip":      selected_ip,
                        "obfuscation_profile": profile.as_str(),
                    }),
                },
            );
            state.record_tunnel_open_for_peer(identity.wg_pubkey.as_deref());
            match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                Ok((up, down)) => {
                    state.record_tunnel_close_for_peer(identity.wg_pubkey.as_deref(), up, down);
                    info!(
                        target: "audit",
                        event = "tunnel_close",
                        kind = "connect",
                        host = %host,
                        bytes_up = up,
                        bytes_down = down,
                        duration_ms = start.elapsed().as_millis(),
                        category,
                        "tunnel closed"
                    );
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
                            bytes_up: up,
                            bytes_down: down,
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
                            extra: serde_json::json!({
                                "kind":        "connect",
                                "category":    category,
                                "bytes_up":    up,
                                "bytes_down":  down,
                                "duration_ms": start.elapsed().as_millis(),
                            }),
                        },
                    );
                }
                Err(e) => {
                    state.record_tunnel_close_for_peer(identity.wg_pubkey.as_deref(), 0, 0);
                    debug!(%host, %e, "tunnel closed by peer");
                }
            }
        }
        Err(e) => {
            error!(
                %host,
                failure_class = e.class(),
                error = %e.detail(),
                "failed to connect to tunnel target"
            );
            let _ = client.shutdown().await;
        }
    }
}

/// Configure TCP keepalive on the given `TcpStream` with a 10-second idle time and a 5-second probe interval.
fn set_keepalive(stream: &tokio::net::TcpStream) {
    use std::time::Duration;

    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}
