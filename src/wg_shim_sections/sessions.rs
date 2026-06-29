impl ShimSession {
    fn new(
        id: u64,
        config: Arc<WgObfsShimConfig>,
        upstream_tx: mpsc::Sender<QueuedUpstreamPacket>,
        upstream_port: u16,
        now_millis: u64,
        span: Span,
    ) -> Self {
        let rate_limit = config.rate_limit;
        let send_queue_capacity = config.send_queue_capacity();
        Self {
            id,
            config,
            upstream_tx,
            upstream_port: AtomicU16::new(upstream_port),
            last_activity_millis: AtomicU64::new(now_millis),
            shutdown: CancellationToken::new(),
            receiver_task: Mutex::new(None),
            client_to_server_encode: PacketEncodeState::new(now_millis),
            server_to_client_replay: Mutex::new(ReplayWindow::default()),
            rate_limiter: rate_limit.map(|config| Mutex::new(TokenBucket::new(config, now_millis))),
            first_send_logged: AtomicBool::new(false),
            send_queue_depth: AtomicUsize::new(0),
            send_queue_capacity,
            send_queue_full_notice: Mutex::new(RateLimitedLogNotice::new(
                SEND_QUEUE_FULL_LOG_INTERVAL,
            )),
            last_upstream_send_millis: AtomicU64::new(0),
            last_server_reply_millis: AtomicU64::new(0),
            last_server_rtt_millis: AtomicU64::new(0),
            last_server_rtt_known: AtomicBool::new(false),
            span,
        }
    }

    fn touch(&self, now_millis: u64) {
        self.last_activity_millis
            .store(now_millis, Ordering::Relaxed);
    }

    fn idle_for(&self, now_millis: u64) -> Duration {
        Duration::from_millis(
            now_millis.saturating_sub(self.last_activity_millis.load(Ordering::Relaxed)),
        )
    }

    fn last_activity_millis(&self) -> u64 {
        self.last_activity_millis.load(Ordering::Relaxed)
    }

    fn close(&self) {
        self.shutdown.cancel();
    }

    fn set_receiver_task(&self, handle: JoinHandle<()>) {
        *self
            .receiver_task
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(handle);
    }

    fn take_receiver_task(&self) -> Option<JoinHandle<()>> {
        self.receiver_task
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }

    fn allow_upstream_send(&self, now_millis: u64) -> bool {
        self.rate_limiter
            .as_ref()
            .map(|bucket| {
                bucket
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .try_take(now_millis)
            })
            .unwrap_or(true)
    }

    fn record_first_send(&self) {
        if !self.first_send_logged.swap(true, Ordering::AcqRel) {
            self.span.in_scope(|| {
                info!(
                    session_id = self.id,
                    upstream_port = self.upstream_port.load(Ordering::Relaxed),
                    "WireGuard shim session first upstream send"
                );
            });
        }
    }

    fn send_queue_capacity(&self) -> usize {
        self.send_queue_capacity
    }

    fn send_queue_depth(&self) -> usize {
        self.send_queue_depth.load(Ordering::Relaxed)
    }

    fn reserve_send_queue_slot(&self, metrics: &ShimMetrics) -> SendQueueReservation {
        let total_depth = metrics.reserve_send_queue_slot();
        let session_depth = self.send_queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        SendQueueReservation {
            session_depth,
            total_depth,
        }
    }

    fn release_send_queue_slots(&self, metrics: &ShimMetrics, count: usize) {
        if count == 0 {
            return;
        }
        let released = self
            .send_queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(count))
            })
            .map(|previous| previous.min(count))
            .unwrap_or(0);
        metrics.release_send_queue_slots(released as u64);
    }

    fn release_send_queue_slot(&self, metrics: &ShimMetrics) {
        self.release_send_queue_slots(metrics, 1);
    }

    fn clear_send_queue(&self, metrics: &ShimMetrics) -> usize {
        let depth = self.send_queue_depth.swap(0, Ordering::Relaxed);
        metrics.release_send_queue_slots(depth as u64);
        depth
    }

    fn record_send_queue_accepted(
        &self,
        metrics: &ShimMetrics,
        reservation: SendQueueReservation,
    ) {
        metrics.record_send_queue_accepted(
            reservation.session_depth,
            self.send_queue_capacity,
            reservation.total_depth,
        );
    }

    fn record_send_queue_dequeued(
        &self,
        metrics: &ShimMetrics,
        queued_at_millis: u64,
        now_millis: u64,
    ) {
        self.release_send_queue_slot(metrics);
        metrics.record_send_queue_dequeued(queued_at_millis, now_millis);
    }

    fn record_send_queue_full_drop(&self, metrics: &ShimMetrics) {
        metrics.record_send_queue_full_drop(self.send_queue_capacity);
    }

    fn queue_full_log_suppressed(&self, now: Instant) -> Option<u64> {
        self.send_queue_full_notice
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .record(now)
    }

    fn set_upstream_port(&self, upstream_port: u16) {
        self.upstream_port.store(upstream_port, Ordering::Relaxed);
    }

    fn record_upstream_send(&self, now_millis: u64) {
        self.last_upstream_send_millis
            .store(now_millis, Ordering::Release);
    }

    fn record_server_reply(&self, now_millis: u64) {
        let last_send = self.last_upstream_send_millis.load(Ordering::Acquire);
        if last_send > 0 {
            self.last_server_rtt_millis
                .store(now_millis.saturating_sub(last_send), Ordering::Relaxed);
            self.last_server_rtt_known.store(true, Ordering::Release);
        }
        self.last_server_reply_millis
            .store(now_millis, Ordering::Relaxed);
    }

    fn last_server_reply_age_millis(&self, now_millis: u64) -> Option<u64> {
        let last_reply = self.last_server_reply_millis.load(Ordering::Relaxed);
        (last_reply > 0).then(|| now_millis.saturating_sub(last_reply))
    }

    fn last_server_rtt_millis(&self) -> Option<u64> {
        self.last_server_rtt_known
            .load(Ordering::Acquire)
            .then(|| self.last_server_rtt_millis.load(Ordering::Relaxed))
    }
}

#[derive(Clone, Copy)]
struct SendQueueReservation {
    session_depth: usize,
    total_depth: u64,
}

struct QueuedUpstreamPacket {
    lease: UdpBufferLease,
    len: usize,
    queued_at_millis: u64,
    is_chaff: bool,
}

impl QueuedUpstreamPacket {
    fn bytes(&self) -> &[u8] {
        &self.lease[..self.len]
    }
}

struct UpstreamConnection {
    socket: UdpSocket,
    server_addr: SocketAddr,
    local_port: u16,
}

#[derive(Clone)]
struct ShimSessionContext {
    listen_socket: Arc<UdpSocket>,
    config_store: Arc<ArcSwap<WgObfsShimConfig>>,
    sessions: Arc<DashMap<SocketAddr, Arc<ShimSession>>>,
    shutdown: CancellationToken,
    clock: Arc<ShimClock>,
    metrics: Arc<ShimMetrics>,
    next_session_id: Arc<AtomicU64>,
    buffer_pool: Arc<UdpBufferPool>,
    next_server_index: Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
enum SessionCloseReason {
    Idle,
    SendFailure,
    TableLimit,
    Shutdown,
}

impl SessionCloseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::SendFailure => "send_failure",
            Self::TableLimit => "table_limit",
            Self::Shutdown => "shutdown",
        }
    }
}

pub async fn spawn(
    config: WgObfsShimConfig,
    shutdown: CancellationToken,
) -> io::Result<JoinHandle<()>> {
    spawn_runtime(config, shutdown)
        .await
        .map(|runtime| runtime.handle)
}

#[allow(dead_code)]
pub(crate) async fn spawn_with_addrs(
    listen_addr: SocketAddr,
    server_addr: SocketAddr,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    spawn_with_config(
        WgObfsShimConfig::new(listen_addr, server_addr, obfuscation, idle_timeout),
        shutdown,
    )
    .await
}

pub(crate) async fn spawn_with_config(
    config: WgObfsShimConfig,
    shutdown: CancellationToken,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let runtime = spawn_runtime(config, shutdown).await?;
    Ok((runtime.local_addr, runtime.handle))
}

pub async fn spawn_runtime(
    config: WgObfsShimConfig,
    shutdown: CancellationToken,
) -> io::Result<WgObfsShimRuntime> {
    if config.server_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WireGuard shim requires at least one server address",
        ));
    }

    let listen_socket = Arc::new(crate::udp_tuning::bind_tuned_udp_socket(
        config.listen_addr,
        config.udp_socket_buffer_bytes,
        "wg-shim-listen",
    )?);
    let local_addr = listen_socket.local_addr()?;
    let sessions = Arc::new(DashMap::new());
    let clock = Arc::new(ShimClock::new());
    let metrics = Arc::new(ShimMetrics::default());
    let next_session_id = Arc::new(AtomicU64::new(1));
    let buffer_pool = Arc::new(UdpBufferPool::new(
        config.buffer_pool_capacity(),
        config.max_datagram_bytes(),
    ));
    let next_server_index = Arc::new(AtomicUsize::new(0));
    let config = Arc::new(ArcSwap::from_pointee(config));
    let context = ShimSessionContext {
        listen_socket,
        config_store: config.clone(),
        sessions,
        shutdown,
        clock,
        metrics: metrics.clone(),
        next_session_id,
        buffer_pool,
        next_server_index,
    };

    let runtime_sessions = context.sessions.clone();
    let task = tokio::spawn(run_shim(context));

    Ok(WgObfsShimRuntime {
        local_addr,
        handle: task,
        config,
        metrics,
        sessions: runtime_sessions,
    })
}

async fn run_shim(context: ShimSessionContext) {
    let startup_config = context.config_store.load_full();
    info!(
        listen_addr = %context.listen_socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0))),
        server_addrs = ?startup_config.server_addrs,
        magic_byte = ?startup_config.obfuscation.magic_byte,
        encryption_mode = ?startup_config.obfuscation.encryption_mode,
        idle_timeout_secs = startup_config.idle_timeout.as_secs(),
        cleanup_interval_secs = startup_config.cleanup_interval().as_secs_f64(),
        max_datagram_bytes = startup_config.max_datagram_bytes(),
        udp_socket_buffer_bytes = startup_config.udp_socket_buffer_bytes,
        max_sessions = ?startup_config.max_sessions,
        "WireGuard obfuscation shim started"
    );

    let cleanup_task = tokio::spawn(run_cleanup_loop(context.clone()));

    #[cfg(feature = "metrics")]
    let metrics_task = startup_config.metrics_addr.map(|metrics_addr| {
        tokio::spawn(run_metrics_server(
            metrics_addr,
            context.metrics.clone(),
            context.shutdown.clone(),
        ))
    });
    #[cfg(not(feature = "metrics"))]
    if let Some(metrics_addr) = startup_config.metrics_addr {
        warn!(
            %metrics_addr,
            "WG obfuscation shim metrics address configured but binary was built without the metrics feature"
        );
    }

    loop {
        let Some(mut lease) = lease_buffer_or_wait(&context, None).await else {
            break;
        };

        tokio::select! {
            _ = context.shutdown.cancelled() => break,
            recv = context.listen_socket.recv_from(&mut lease) => {
                let (len, client_addr) = match recv {
                    Ok(result) => result,
                    Err(err) => {
                        if context.shutdown.is_cancelled() {
                            break;
                        }
                        warn!(%err, "WireGuard obfuscation shim receive failed");
                        continue;
                    }
                };

                let config = context.config_store.load_full();
                let session = match get_or_create_session(
                    client_addr,
                    config.clone(),
                    context.clone(),
                )
                .await
                {
                    Ok(session) => session,
                    Err(err) => {
                        warn!(%client_addr, %err, "failed to create WireGuard shim session");
                        continue;
                    }
                };

                let now = context.clock.now_millis();
                session.touch(now);
                if !session.allow_upstream_send(now) {
                    context.metrics.rate_limited_drops.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        %client_addr,
                        session_id = session.id,
                        "dropping WireGuard packet because per-session upstream rate limit was exceeded"
                    );
                    continue;
                }

                session.record_first_send();
                let encoded_len = match encode_packet_in_place(
                    &mut lease,
                    len,
                    &session.config.obfuscation,
                    &session.client_to_server_encode,
                    PacketDirection::ClientToServer,
                    now,
                ) {
                    Ok(encoded_len) => encoded_len,
                    Err(err) => {
                        context.metrics.encode_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(%client_addr, session_id = session.id, %err, "failed to encode WireGuard packet for upstream send");
                        continue;
                    }
                };

                let send_started_millis = context.clock.now_millis();
                let packet = QueuedUpstreamPacket {
                    lease,
                    len: encoded_len,
                    queued_at_millis: send_started_millis,
                    is_chaff: false,
                };
                let queue_reservation = session.reserve_send_queue_slot(&context.metrics);
                match session.upstream_tx.try_send(packet) {
                    Ok(()) => {
                        session.record_send_queue_accepted(
                            &context.metrics,
                            queue_reservation,
                        );
                        session.record_upstream_send(send_started_millis);
                        context.metrics.packets_client_to_server.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Full(_packet)) => {
                        session.release_send_queue_slot(&context.metrics);
                        session.record_send_queue_full_drop(&context.metrics);
                        if let Some(suppressed_since_last) =
                            session.queue_full_log_suppressed(Instant::now())
                        {
                            let failure_millis = context.clock.now_millis();
                            warn!(
                                %client_addr,
                                session_id = session.id,
                                queue_depth = session.send_queue_depth(),
                                queue_capacity = session.send_queue_capacity(),
                                total_queue_depth = context.metrics.send_queue_depth(),
                                total_queue_capacity = context.metrics.send_queue_capacity(),
                                upstream_port = session.upstream_port.load(Ordering::Relaxed),
                                last_server_reply_age_ms = ?session.last_server_reply_age_millis(failure_millis),
                                last_server_rtt_ms = ?session.last_server_rtt_millis(),
                                suppressed_since_last,
                                "dropping WireGuard packet because per-session upstream send queue is full"
                            );
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_packet)) => {
                        session.release_send_queue_slot(&context.metrics);
                        let failure_millis = context.clock.now_millis();
                        warn!(
                            %client_addr,
                            session_id = session.id,
                            upstream_port = session.upstream_port.load(Ordering::Relaxed),
                            last_server_reply_age_ms = ?session.last_server_reply_age_millis(failure_millis),
                            last_server_rtt_ms = ?session.last_server_rtt_millis(),
                            "failed to queue obfuscated WireGuard packet because session upstream task is closed"
                        );
                        close_session_if_current(
                            &context.sessions,
                            client_addr,
                            &session,
                            &context.metrics,
                            SessionCloseReason::SendFailure,
                        );
                    }
                }
            }
        }
    }

    let _ = cleanup_task.await;
    #[cfg(feature = "metrics")]
    if let Some(metrics_task) = metrics_task {
        let _ = metrics_task.await;
    }

    let sessions_to_close: Vec<_> = context
        .sessions
        .iter()
        .map(|entry| (*entry.key(), entry.value().clone()))
        .collect();
    let mut receiver_tasks = Vec::new();
    for (client_addr, session) in sessions_to_close {
        if close_session_if_current(
            &context.sessions,
            client_addr,
            &session,
            &context.metrics,
            SessionCloseReason::Shutdown,
        ) {
            if let Some(handle) = session.take_receiver_task() {
                receiver_tasks.push(handle);
            }
        }
    }
    drain_receiver_tasks(receiver_tasks, context.config_store.load().drain_timeout).await;

    info!("WireGuard obfuscation shim shutting down");
}
