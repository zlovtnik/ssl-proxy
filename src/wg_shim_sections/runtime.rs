use rand_core::{OsRng, RngCore};
use tokio::time::MissedTickBehavior;

async fn get_or_create_session(
    client_addr: SocketAddr,
    config: Arc<WgObfsShimConfig>,
    context: ShimSessionContext,
) -> io::Result<Arc<ShimSession>> {
    if let Some(existing) = context.sessions.get(&client_addr) {
        return Ok(existing.clone());
    }

    enforce_session_limit(
        &context.sessions,
        config.max_sessions,
        &context.metrics,
        Some(client_addr),
    )?;
    let receiver_context = context.clone();
    match context.sessions.entry(client_addr) {
        dashmap::mapref::entry::Entry::Occupied(existing) => Ok(existing.get().clone()),
        dashmap::mapref::entry::Entry::Vacant(vacant) => {
            if context.shutdown.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "WireGuard shim shutdown is in progress",
                ));
            }

            let now = context.clock.now_millis();
            let session_id = context.next_session_id.fetch_add(1, Ordering::Relaxed);
            let (upstream_tx, upstream_rx) = mpsc::channel(config.send_queue_capacity());
            let span = info_span!(
                "wg_shim_session",
                client_addr = %client_addr,
                session_id,
            );
            let session = Arc::new(ShimSession::new(
                session_id,
                config.clone(),
                upstream_tx,
                0,
                now,
                span.clone(),
            ));
            let session = vacant.insert(session).clone();
            context
                .metrics
                .active_sessions
                .fetch_add(1, Ordering::Relaxed);
            context
                .metrics
                .record_send_queue_capacity_add(session.send_queue_capacity());
            session.span.in_scope(|| {
                info!("WireGuard shim session created");
            });
            let handle = tokio::spawn(run_session_receiver(
                client_addr,
                session.clone(),
                upstream_rx,
                receiver_context,
            ));
            session.set_receiver_task(handle);
            Ok(session)
        }
    }
}

async fn run_session_receiver(
    client_addr: SocketAddr,
    session: Arc<ShimSession>,
    mut upstream_rx: mpsc::Receiver<QueuedUpstreamPacket>,
    context: ShimSessionContext,
) {
    let mut connection = match connect_next_upstream(&session.config, &context.next_server_index)
        .await
    {
        Ok(connection) => {
            session.set_upstream_port(connection.local_port);
            connection
        }
        Err(err) => {
            warn!(%client_addr, session_id = session.id, %err, "failed to create initial WireGuard shim upstream socket");
            close_session_if_current(
                &context.sessions,
                client_addr,
                &session,
                &context.metrics,
                SessionCloseReason::SendFailure,
            );
            return;
        }
    };

    let mut chaff_interval = session.config.chaff_interval().map(|period| {
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval
    });
    if session.config.chaff_pps > 0 && chaff_interval.is_none() {
        warn!(
            %client_addr,
            session_id = session.id,
            "WG_OBFS_SHIM_CHAFF_PPS is set but chaff requires framed obfuscation; ignoring chaff for this session"
        );
    }

    loop {
        let Some(mut lease) = lease_buffer_or_wait(&context, Some(&session.shutdown)).await else {
            break;
        };

        tokio::select! {
            _ = context.shutdown.cancelled() => break,
            _ = session.shutdown.cancelled() => break,
            queued = upstream_rx.recv() => {
                let Some(packet) = queued else {
                    break;
                };
                session.record_send_queue_dequeued(
                    &context.metrics,
                    packet.queued_at_millis,
                    context.clock.now_millis(),
                );
                if !await_send_jitter(&context, &session).await {
                    break;
                }
                match send_with_failover(
                    &mut connection,
                    packet,
                    &session,
                    client_addr,
                    &session.config,
                    &context.next_server_index,
                    &context.shutdown,
                    &context.clock,
                )
                .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        let failure_millis = context.clock.now_millis();
                        warn!(
                            %client_addr,
                            session_id = session.id,
                            upstream_port = session.upstream_port.load(Ordering::Relaxed),
                            last_server_reply_age_ms = ?session.last_server_reply_age_millis(failure_millis),
                            last_server_rtt_ms = ?session.last_server_rtt_millis(),
                            %err,
                            "failed to send obfuscated WireGuard packet to all configured upstream servers"
                        );
                        close_session_if_current(
                            &context.sessions,
                            client_addr,
                            &session,
                            &context.metrics,
                            SessionCloseReason::SendFailure,
                        );
                        break;
                    }
                }
            }
            _ = optional_interval_tick(chaff_interval.as_mut()) => {
                let now = context.clock.now_millis();
                if session
                    .config
                    .chaff_interval()
                    .is_some_and(|interval| session.idle_for(now) < interval)
                {
                    continue;
                }

                let packet_start = packet_encode_headroom(&session.config.obfuscation);
                let encoded_range = match encode_packet_in_place_with_headroom(
                    &mut lease,
                    packet_start,
                    0,
                    &session.config.obfuscation,
                    &session.client_to_server_encode,
                    PacketDirection::ClientToServer,
                    now,
                ) {
                    Ok(encoded_range) => encoded_range,
                    Err(err) => {
                        context.metrics.encode_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(%client_addr, session_id = session.id, %err, "failed to encode WireGuard shim chaff packet");
                        continue;
                    }
                };

                if !await_send_jitter(&context, &session).await {
                    break;
                }

                let packet = QueuedUpstreamPacket {
                    lease,
                    start: encoded_range.start,
                    len: encoded_range.len(),
                    queued_at_millis: now,
                    is_chaff: true,
                };
                match send_with_failover(
                    &mut connection,
                    packet,
                    &session,
                    client_addr,
                    &session.config,
                    &context.next_server_index,
                    &context.shutdown,
                    &context.clock,
                )
                .await
                {
                    Ok(()) => {
                        context.metrics.chaff_packets_sent.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(err) => {
                        warn!(
                            %client_addr,
                            session_id = session.id,
                            upstream_port = session.upstream_port.load(Ordering::Relaxed),
                            %err,
                            "failed to send WireGuard shim chaff packet to all configured upstream servers"
                        );
                        close_session_if_current(
                            &context.sessions,
                            client_addr,
                            &session,
                            &context.metrics,
                            SessionCloseReason::SendFailure,
                        );
                        break;
                    }
                }
            }
            recv = connection.socket.recv(&mut lease) => {
                let len = match recv {
                    Ok(len) => len,
                    Err(err) => {
                        warn!(
                            %client_addr,
                            session_id = session.id,
                            upstream_addr = %connection.server_addr,
                            %err,
                            "WireGuard shim session receive failed"
                        );
                        break;
                    }
                };

                let now = context.clock.now_millis();
                session.touch(now);
                // Server replies carry the relay encoder's salt in-band, so
                // the shim decodes without holding the relay's encode state.
                let decoded_range = {
                    let mut replay = session
                        .server_to_client_replay
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    match decode_packet_in_place_view(
                        &mut lease,
                        len,
                        &session.config.obfuscation,
                        Some(&mut replay),
                        PacketDirection::ServerToClient,
                    ) {
                        Ok(decoded_range) => decoded_range,
                        Err(PacketDecodeError::MagicByteMismatch) => {
                            context.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                            warn!(%client_addr, session_id = session.id, packet_len = len, "dropping server reply with missing or invalid obfuscation marker");
                            continue;
                        }
                        Err(PacketDecodeError::EmptyPayload) => {
                            context.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                            warn!(%client_addr, session_id = session.id, packet_len = len, "dropping server reply with empty obfuscation payload");
                            continue;
                        }
                        Err(PacketDecodeError::ReplayDetected) => {
                            context.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                            context.metrics.replay_detected.fetch_add(1, Ordering::Relaxed);
                            warn!(%client_addr, session_id = session.id, packet_len = len, "dropping replayed server reply");
                            continue;
                        }
                        Err(err) => {
                            context.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                %client_addr,
                                session_id = session.id,
                                packet_len = len,
                                reason = err.as_str(),
                                %err,
                                "dropping server reply after structured decode failure"
                            );
                            continue;
                        }
                    }
                };
                session.record_server_reply(now);

                if let Err(err) = context.listen_socket.send_to(&lease[decoded_range], client_addr).await {
                    warn!(%client_addr, session_id = session.id, %err, "failed to deliver plaintext WireGuard packet back to local client");
                    close_session_if_current(
                        &context.sessions,
                        client_addr,
                        &session,
                        &context.metrics,
                        SessionCloseReason::SendFailure,
                    );
                    break;
                }
                context.metrics.packets_server_to_client.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    drain_pending_upstream_packets(
        &session,
        &context.metrics,
        &mut upstream_rx,
        context.clock.now_millis(),
    );

    let close_reason = if context.shutdown.is_cancelled() {
        SessionCloseReason::Shutdown
    } else {
        SessionCloseReason::SendFailure
    };
    close_session_if_current(
        &context.sessions,
        client_addr,
        &session,
        &context.metrics,
        close_reason,
    );
    session.close();
}

fn drain_pending_upstream_packets(
    session: &ShimSession,
    metrics: &ShimMetrics,
    upstream_rx: &mut mpsc::Receiver<QueuedUpstreamPacket>,
    now_millis: u64,
) {
    while let Ok(packet) = upstream_rx.try_recv() {
        session.record_send_queue_dequeued(metrics, packet.queued_at_millis, now_millis);
        drop(packet);
    }
}

async fn connect_next_upstream(
    config: &WgObfsShimConfig,
    next_server_index: &AtomicUsize,
) -> io::Result<UpstreamConnection> {
    let server_count = config.server_addrs.len();
    if server_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard shim requires at least one server address",
        ));
    }

    let start = next_server_index.fetch_add(1, Ordering::Relaxed);
    for offset in 0..server_count {
        let index = (start + offset) % server_count;
        match connect_upstream(config, config.server_addrs[index], index).await {
            Ok(connection) => return Ok(connection),
            Err(err) => {
                warn!(
                    server_addr = %config.server_addrs[index],
                    %err,
                    "failed to connect WireGuard shim upstream socket"
                );
            }
        }
    }

    Err(io::Error::other(
        "failed to connect any configured WireGuard shim upstream server",
    ))
}

async fn send_with_failover(
    connection: &mut UpstreamConnection,
    packet: QueuedUpstreamPacket,
    session: &ShimSession,
    client_addr: SocketAddr,
    config: &WgObfsShimConfig,
    next_server_index: &AtomicUsize,
    shutdown: &CancellationToken,
    clock: &ShimClock,
) -> io::Result<()> {
    let mut last_error = None;
    let max_attempts = config.server_addrs.len().max(1);
    for attempt in 0..max_attempts {
        match connection.socket.send(packet.bytes()).await {
            Ok(_) => {
                if !packet.is_chaff {
                    session.record_upstream_send(packet.queued_at_millis);
                }
                return Ok(());
            }
            Err(err) => {
                last_error = Some(err);
                warn!(
                    %client_addr,
                    session_id = session.id,
                    attempt = attempt + 1,
                    will_retry = attempt + 1 < max_attempts,
                    upstream_addr = %connection.server_addr,
                    upstream_port = connection.local_port,
                    "WireGuard shim upstream send failed"
                );
                if attempt + 1 == max_attempts {
                    break;
                }
                if !await_retry_backoff(shutdown, &session.shutdown, attempt).await {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "WireGuard shim session shutdown interrupted upstream retry backoff",
                    ));
                }
                *connection = connect_next_upstream(config, next_server_index).await?;
                session.set_upstream_port(connection.local_port);
                if !packet.is_chaff {
                    session.record_upstream_send(clock.now_millis());
                }
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| io::Error::other("failed to send WireGuard shim upstream packet")))
}

async fn await_retry_backoff(
    shutdown: &CancellationToken,
    session_shutdown: &CancellationToken,
    attempt: usize,
) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => false,
        _ = session_shutdown.cancelled() => false,
        _ = tokio::time::sleep(retry_backoff_delay(attempt)) => true,
    }
}

async fn await_send_jitter(context: &ShimSessionContext, session: &ShimSession) -> bool {
    let delay = random_jitter_delay(session.config.send_jitter_max);
    if delay.is_zero() {
        return true;
    }

    tokio::select! {
        _ = context.shutdown.cancelled() => false,
        _ = session.shutdown.cancelled() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

fn random_jitter_delay(max: Duration) -> Duration {
    let max_nanos = max.as_nanos().min(u128::from(u64::MAX)) as u64;
    if max_nanos == 0 {
        return Duration::ZERO;
    }
    let nanos = if max_nanos == u64::MAX {
        OsRng.next_u64()
    } else {
        OsRng.next_u64() % (max_nanos + 1)
    };
    Duration::from_nanos(nanos)
}

fn retry_backoff_delay(attempt: usize) -> Duration {
    const BASE: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(30);

    let multiplier = 1u32 << attempt.min(8);
    let capped = BASE.saturating_mul(multiplier).min(MAX);
    let jitter_percent = 75u128 + u128::from(OsRng.next_u32() % 51);
    let nanos = capped
        .as_nanos()
        .saturating_mul(jitter_percent)
        .saturating_div(100)
        .min(u128::from(u64::MAX)) as u64;
    Duration::from_nanos(nanos)
}

async fn connect_upstream(
    config: &WgObfsShimConfig,
    server_addr: SocketAddr,
    _server_index: usize,
) -> io::Result<UpstreamConnection> {
    let bind_addr = upstream_bind_addr(server_addr);
    let socket = crate::udp_tuning::bind_tuned_udp_socket(
        bind_addr,
        config.udp_socket_buffer_bytes,
        "wg-shim-upstream",
    )?;
    socket.connect(server_addr).await?;
    let local_port = socket.local_addr()?.port();
    Ok(UpstreamConnection {
        socket,
        server_addr,
        local_port,
    })
}

fn upstream_bind_addr(server_addr: SocketAddr) -> SocketAddr {
    if server_addr.is_ipv6() {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    }
}

async fn run_cleanup_loop(context: ShimSessionContext) {
    let mut interval = tokio::time::interval(context.config_store.load().cleanup_interval());
    loop {
        tokio::select! {
            _ = context.shutdown.cancelled() => return,
            _ = interval.tick() => {
                let config = context.config_store.load_full();
                let now = context.clock.now_millis();
                let stale_sessions: Vec<_> = context.sessions
                    .iter()
                    .filter_map(|entry| {
                        let client_addr = *entry.key();
                        let session = entry.value().clone();
                        (session.idle_for(now) >= config.idle_timeout).then_some((client_addr, session))
                    })
                    .collect();

                for (client_addr, session) in stale_sessions {
                    close_session_if_current(
                        &context.sessions,
                        client_addr,
                        &session,
                        &context.metrics,
                        SessionCloseReason::Idle,
                    );
                }
            }
        }
    }
}

async fn lease_buffer_or_wait(
    context: &ShimSessionContext,
    session_shutdown: Option<&CancellationToken>,
) -> Option<UdpBufferLease> {
    if let Some(lease) = context.buffer_pool.lease() {
        return Some(lease);
    }

    let mut wait_started = Instant::now();
    loop {
        context
            .metrics
            .buffer_pool_exhausted
            .fetch_add(1, Ordering::Relaxed);
        tokio::select! {
            _ = context.shutdown.cancelled() => return None,
            _ = optional_cancelled(session_shutdown) => return None,
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        record_buffer_pool_wait_since(&context.metrics, wait_started);
        if let Some(lease) = context.buffer_pool.lease() {
            return Some(lease);
        }
        wait_started = Instant::now();
    }
}

async fn optional_cancelled(token: Option<&CancellationToken>) {
    if let Some(token) = token {
        token.cancelled().await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn optional_interval_tick(interval: Option<&mut tokio::time::Interval>) {
    if let Some(interval) = interval {
        interval.tick().await;
    } else {
        std::future::pending::<()>().await;
    }
}

fn record_buffer_pool_wait_since(metrics: &ShimMetrics, wait_started: Instant) {
    let waited_millis = wait_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    metrics
        .buffer_pool_wait_millis_total
        .fetch_add(waited_millis, Ordering::Relaxed);
}

fn enforce_session_limit(
    sessions: &DashMap<SocketAddr, Arc<ShimSession>>,
    max_sessions: Option<usize>,
    metrics: &ShimMetrics,
    exclude: Option<SocketAddr>,
) -> io::Result<()> {
    let Some(max_sessions) = max_sessions else {
        return Ok(());
    };
    if max_sessions == 0 {
        return Err(io::Error::other("WireGuard shim max_sessions is zero"));
    }

    while sessions.len() >= max_sessions {
        if !evict_oldest_session(sessions, metrics, exclude) {
            return Err(io::Error::other(
                "WireGuard shim session limit reached and no session could be evicted",
            ));
        }
    }
    Ok(())
}
