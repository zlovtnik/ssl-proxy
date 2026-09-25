async fn get_or_create_session(
    client_addr: SocketAddr,
    public_socket: Arc<UdpSocket>,
    internal_addr: SocketAddr,
    settings: RelaySettings,
    sessions: Arc<DashMap<SocketAddr, Arc<RelaySession>>>,
    shutdown: CancellationToken,
    clock: Arc<RelayClock>,
    metrics: Arc<RelayMetrics>,
) -> io::Result<Arc<RelaySession>> {
    if let Some(existing) = sessions.get(&client_addr) {
        let session = existing.value().clone();
        return Ok(session);
    }

    // Bound the session table so unauthenticated traffic cannot exhaust
    // memory, sockets, and tasks. The keyed header tag must already have
    // validated before callers reach this point.
    while sessions.len() >= settings.max_sessions {
        if !evict_oldest_idle_session(&sessions, &clock, &metrics) {
            return Err(io::Error::other(
                "WireGuard relay session limit reached; no session could be evicted",
            ));
        }
    }

    let upstream_socket = Arc::new(bind_tuned_udp_socket(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        settings.udp_socket_buffer_bytes,
        "wg-relay-internal",
    )?);
    upstream_socket.connect(internal_addr).await?;

    let (session, is_new) = {
        let entry = sessions.entry(client_addr);
        match entry {
            dashmap::mapref::entry::Entry::Occupied(existing) => (existing.get().clone(), false),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let session = Arc::new(RelaySession::new(
                    upstream_socket,
                    clock.now_millis(),
                    settings.idle_timeout,
                ));
                vacant.insert(session.clone());
                metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
                (session, true)
            }
        }
    };

    if is_new {
        let sessions_for_task = sessions.clone();
        tokio::spawn(run_session_receiver(
            client_addr,
            session.clone(),
            public_socket,
            settings,
            sessions_for_task,
            shutdown,
            clock.clone(),
            metrics,
        ));
    }

    session.touch(clock.now_millis());
    Ok(session)
}

/// Evict the most idle session to make room under the session cap.
///
/// Returns false when the table contains no evictable entry (every entry is
/// currently referenced elsewhere), leaving the caller to shed load.
fn evict_oldest_idle_session(
    sessions: &DashMap<SocketAddr, Arc<RelaySession>>,
    clock: &Arc<RelayClock>,
    metrics: &Arc<RelayMetrics>,
) -> bool {
    let now = clock.now_millis();
    let mut oldest: Option<(SocketAddr, Arc<RelaySession>, u64)> = None;
    for entry in sessions.iter() {
        let idle_for = entry.value().idle_for(now).as_millis() as u64;
        match &oldest {
            Some((_, _, current)) if idle_for <= *current => {}
            _ => {
                oldest = Some((*entry.key(), entry.value().clone(), idle_for));
            }
        }
    }
    let Some((client_addr, session, _)) = oldest else {
        return false;
    };
    if remove_session_if_current(sessions, client_addr, &session) {
        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        metrics
            .sessions_evicted_table_limit
            .fetch_add(1, Ordering::Relaxed);
    }
    session.close();
    true
}

async fn run_session_receiver(
    client_addr: SocketAddr,
    session: Arc<RelaySession>,
    public_socket: Arc<UdpSocket>,
    settings: RelaySettings,
    sessions: Arc<DashMap<SocketAddr, Arc<RelaySession>>>,
    shutdown: CancellationToken,
    clock: Arc<RelayClock>,
    metrics: Arc<RelayMetrics>,
) {
    let mut buf = vec![0u8; settings.max_datagram_bytes];
    let packet_start = packet_encode_headroom(&settings.obfuscation);
    // Drain mode: after the global shutdown token fires, keep forwarding
    // in-flight server replies for a bounded window so clients do not lose
    // the final datagrams of an exchange across restarts. The drain ends
    // when the window elapses or the session sweep closes the session.
    let drain_window = relay_drain_window();
    let mut drain_deadline: Option<tokio::time::Instant> = None;
    loop {
        tokio::select! {
            biased;
            _ = session.shutdown.cancelled() => break,
            _ = async {
                match drain_deadline {
                    Some(_) => std::future::pending::<()>().await,
                    None => shutdown.cancelled().await,
                }
            } => {
                if drain_deadline.is_none() {
                    if drain_window.is_zero() {
                        break;
                    }
                    drain_deadline = Some(tokio::time::Instant::now() + drain_window);
                }
            }
            result = async {
                match drain_deadline {
                    Some(deadline) => tokio::time::timeout_at(deadline, session.upstream_socket.recv(&mut buf[packet_start..])).await,
                    None => Ok(session.upstream_socket.recv(&mut buf[packet_start..]).await),
                }
            } => {
                let len = match result {
                    Ok(Ok(len)) => len,
                    Ok(Err(err)) => {
                        warn!(%client_addr, %err, "WireGuard relay session receive failed");
                        continue;
                    }
                    Err(_elapsed) => {
                        // Drain deadline elapsed.
                        break;
                    }
                };

                let now = clock.now_millis();
                session.touch(now);
                let encoded_range = match encode_packet_in_place_with_headroom(
                    &mut buf,
                    packet_start,
                    len,
                    &settings.obfuscation,
                    &session.server_to_client_encode,
                    PacketDirection::ServerToClient,
                ) {
                    Ok(encoded_range) => encoded_range,
                    Err(err) => {
                        metrics.encode_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(%client_addr, %err, "failed to encode WireGuard relay reply");
                        break;
                    }
                };
                if let Err(err) = public_socket.send_to(&buf[encoded_range], client_addr).await {
                    warn!(%client_addr, %err, "failed to send obfuscated WireGuard packet to client");
                    break;
                } else {
                    metrics
                        .packets_server_to_client
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    if remove_session_if_current(&sessions, client_addr, &session) {
        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        if shutdown.is_cancelled() || session.shutdown.is_cancelled() {
            metrics
                .sessions_closed_shutdown
                .fetch_add(1, Ordering::Relaxed);
        } else {
            metrics
                .sessions_evicted_send_failure
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    session.close();
}

async fn run_cleanup_loop(
    sessions: Arc<DashMap<SocketAddr, Arc<RelaySession>>>,
    shutdown: CancellationToken,
    idle_timeout: Duration,
    clock: Arc<RelayClock>,
    metrics: Arc<RelayMetrics>,
) {
    let mut interval = tokio::time::interval(cleanup_interval(idle_timeout));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = interval.tick() => {
                let now = clock.now_millis();
                let stale_sessions: Vec<_> = sessions
                    .iter()
                    .filter_map(|entry| {
                        let client_addr = *entry.key();
                        let session = entry.value().clone();
                        session
                            .idle_expired(now, idle_timeout)
                            .then_some((client_addr, session))
                    })
                    .collect();

                for (client_addr, session) in stale_sessions {
                    if remove_session_if_current(&sessions, client_addr, &session) {
                        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                        metrics
                            .sessions_evicted_idle
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    session.close();
                }
            }
        }
    }
}

fn remove_session_if_current(
    sessions: &DashMap<SocketAddr, Arc<RelaySession>>,
    client_addr: SocketAddr,
    session: &Arc<RelaySession>,
) -> bool {
    sessions
        .remove_if(&client_addr, |_, current| Arc::ptr_eq(current, session))
        .is_some()
}
