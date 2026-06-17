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
        session.touch(clock.now_millis());
        return Ok(session);
    }

    let upstream_socket = Arc::new(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?);
    upstream_socket.connect(internal_addr).await?;

    let (session, is_new) = {
        let entry = sessions.entry(client_addr);
        match entry {
            dashmap::mapref::entry::Entry::Occupied(existing) => (existing.get().clone(), false),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let session = Arc::new(RelaySession::new(upstream_socket, clock.now_millis()));
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
    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = session.shutdown.cancelled() => break,
            recv = session.upstream_socket.recv(&mut buf) => {
                let len = match recv {
                    Ok(len) => len,
                    Err(err) => {
                        warn!(%client_addr, %err, "WireGuard relay session receive failed");
                        break;
                    }
                };

                let now = clock.now_millis();
                session.touch(now);
                let encoded_len = match encode_packet_in_place(
                    &mut buf,
                    len,
                    &settings.obfuscation,
                    &session.server_to_client_encode,
                    PacketDirection::ServerToClient,
                    now,
                ) {
                    Ok(encoded_len) => encoded_len,
                    Err(err) => {
                        metrics.encode_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(%client_addr, %err, "failed to encode WireGuard relay reply");
                        break;
                    }
                };
                if let Err(err) = public_socket.send_to(&buf[..encoded_len], client_addr).await {
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
                        (session.idle_for(now) >= idle_timeout).then_some((client_addr, session))
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
