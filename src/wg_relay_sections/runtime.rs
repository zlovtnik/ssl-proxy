use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use rand_core::{OsRng, RngCore};
use tokio::{net::UdpSocket, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    config::WireGuardConfig,
    wg_packet_obfuscation::{
        cleanup_interval, decode_packet_in_place, encode_packet_in_place, validate_framed_header,
        PacketDecodeError, PacketDirection, PacketEncodeState, ReplayWindow, WgPacketObfuscation,
        XorRekeyPolicy, MAX_UDP_PACKET_SIZE,
    },
};

const DROP_LOG_INTERVAL: Duration = Duration::from_secs(30);
const PROBE_BLOCK_WINDOW: Duration = Duration::from_secs(60);
const PROBE_BLOCK_DURATION: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct RelayMetricsSnapshot {
    pub active_sessions: u64,
    pub packets_client_to_server: u64,
    pub packets_server_to_client: u64,
    pub decode_errors: u64,
    pub encode_errors: u64,
    pub replay_detected: u64,
    pub probe_blocked_packets: u64,
    pub sessions_evicted_idle: u64,
    pub sessions_evicted_send_failure: u64,
    pub sessions_closed_shutdown: u64,
}

#[derive(Default)]
pub struct RelayMetrics {
    active_sessions: AtomicU64,
    packets_client_to_server: AtomicU64,
    packets_server_to_client: AtomicU64,
    decode_errors: AtomicU64,
    encode_errors: AtomicU64,
    replay_detected: AtomicU64,
    probe_blocked_packets: AtomicU64,
    sessions_evicted_idle: AtomicU64,
    sessions_evicted_send_failure: AtomicU64,
    sessions_closed_shutdown: AtomicU64,
}

impl RelayMetrics {
    pub fn snapshot(&self) -> RelayMetricsSnapshot {
        RelayMetricsSnapshot {
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            packets_client_to_server: self.packets_client_to_server.load(Ordering::Relaxed),
            packets_server_to_client: self.packets_server_to_client.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            encode_errors: self.encode_errors.load(Ordering::Relaxed),
            replay_detected: self.replay_detected.load(Ordering::Relaxed),
            probe_blocked_packets: self.probe_blocked_packets.load(Ordering::Relaxed),
            sessions_evicted_idle: self.sessions_evicted_idle.load(Ordering::Relaxed),
            sessions_evicted_send_failure: self
                .sessions_evicted_send_failure
                .load(Ordering::Relaxed),
            sessions_closed_shutdown: self.sessions_closed_shutdown.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
struct RelaySettings {
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    probe_block: Option<ProbeBlockConfig>,
}

impl RelaySettings {
    fn from_config(config: &WireGuardConfig) -> Self {
        let obfuscation = WgPacketObfuscation::new(
            config.obfuscation_key.clone(),
            config.obfuscation_magic_byte,
        )
        .with_encryption_mode(config.obfuscation_encryption_mode)
        .with_padding(config.obfuscation_padding.clone())
        .with_magic_position(config.obfuscation_magic_position)
        .with_xor_rekey(XorRekeyPolicy::new(
            config.obfuscation_xor_rekey_packets,
            config.obfuscation_xor_rekey_secs,
        ))
        .with_replay_protection(config.obfuscation_replay_protection);
        Self {
            obfuscation,
            idle_timeout: Duration::from_secs(config.obfuscation_session_idle_secs),
            probe_block: read_probe_block_config(),
        }
    }
}

#[derive(Clone, Copy)]
struct ProbeBlockConfig {
    threshold: u64,
    window: Duration,
    block_duration: Duration,
}

#[derive(Clone, Debug)]
struct ProbeState {
    window_started: Instant,
    errors: u64,
    blocked_until: Option<Instant>,
}

struct ProbeDetector {
    config: Option<ProbeBlockConfig>,
    states: DashMap<IpAddr, ProbeState>,
}

impl ProbeDetector {
    fn new(config: Option<ProbeBlockConfig>) -> Self {
        Self {
            config,
            states: DashMap::new(),
        }
    }

    fn is_blocked(&self, ip: IpAddr, now: Instant) -> bool {
        let Some(mut entry) = self.states.get_mut(&ip) else {
            return false;
        };
        if entry
            .blocked_until
            .is_some_and(|blocked_until| blocked_until > now)
        {
            return true;
        }
        if entry.blocked_until.is_some() {
            entry.blocked_until = None;
            entry.errors = 0;
            entry.window_started = now;
        }
        false
    }

    fn record_decode_error(&self, ip: IpAddr, now: Instant) -> bool {
        let Some(config) = self.config else {
            return false;
        };

        let mut entry = self.states.entry(ip).or_insert(ProbeState {
            window_started: now,
            errors: 0,
            blocked_until: None,
        });
        let state = entry.value_mut();
        if state
            .blocked_until
            .is_some_and(|blocked_until| blocked_until > now)
        {
            return false;
        }
        if now.duration_since(state.window_started) >= config.window {
            state.window_started = now;
            state.errors = 0;
            state.blocked_until = None;
        }

        state.errors = state.errors.saturating_add(1);
        if state.errors >= config.threshold {
            state.blocked_until = Some(now + config.block_duration);
            state.errors = 0;
            state.window_started = now;
            return true;
        }
        false
    }
}

fn read_probe_block_config() -> Option<ProbeBlockConfig> {
    let threshold = read_env_u64("WG_RELAY_PROBE_BLOCK_THRESHOLD").filter(|value| *value > 0)?;
    let window = read_env_u64("WG_RELAY_PROBE_BLOCK_WINDOW_SECS")
        .map(Duration::from_secs)
        .unwrap_or(PROBE_BLOCK_WINDOW);
    let block_duration = read_env_u64("WG_RELAY_PROBE_BLOCK_SECS")
        .map(Duration::from_secs)
        .unwrap_or(PROBE_BLOCK_DURATION);
    Some(ProbeBlockConfig {
        threshold,
        window,
        block_duration,
    })
}

fn read_env_u64(var: &str) -> Option<u64> {
    std::env::var(var)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

struct RelaySession {
    upstream_socket: Arc<UdpSocket>,
    last_activity_millis: AtomicU64,
    client_to_server_replay: Mutex<ReplayWindow>,
    // Server-to-client frames use this encoder state to choose the direction's
    // session salt. The salt is embedded in every frame, so the client shim can
    // derive reply keys from the frame alone without sharing this state object.
    server_to_client_encode: PacketEncodeState,
    idle_jitter: Duration,
    shutdown: CancellationToken,
}

impl RelaySession {
    fn new(upstream_socket: Arc<UdpSocket>, now_millis: u64, idle_timeout: Duration) -> Self {
        Self {
            upstream_socket,
            last_activity_millis: AtomicU64::new(now_millis),
            client_to_server_replay: Mutex::new(ReplayWindow::default()),
            server_to_client_encode: PacketEncodeState::new(now_millis),
            idle_jitter: random_idle_jitter(idle_timeout),
            shutdown: CancellationToken::new(),
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

    fn idle_expired(&self, now_millis: u64, idle_timeout: Duration) -> bool {
        self.idle_for(now_millis) >= idle_timeout.saturating_add(self.idle_jitter)
    }

    fn close(&self) {
        self.shutdown.cancel();
    }
}

fn random_idle_jitter(idle_timeout: Duration) -> Duration {
    let max_millis = (idle_timeout.as_millis() / 10)
        .saturating_mul(3)
        .min(u128::from(u64::MAX)) as u64;
    if max_millis == 0 {
        return Duration::ZERO;
    }
    let millis = if max_millis == u64::MAX {
        OsRng.next_u64()
    } else {
        OsRng.next_u64() % (max_millis + 1)
    };
    Duration::from_millis(millis)
}

#[derive(Clone)]
struct RelayClock {
    started: Instant,
}

impl RelayClock {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    fn now_millis(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropReason {
    MagicByteMismatch,
    EmptyPayload,
}

impl DropReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::MagicByteMismatch => "magic_byte_mismatch",
            Self::EmptyPayload => "empty_payload",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::MagicByteMismatch => {
                "dropping inbound WireGuard UDP packet: obfuscation marker missing or invalid; raw direct clients are unsupported on this public port"
            }
            Self::EmptyPayload => {
                "dropping inbound WireGuard UDP packet: obfuscation payload was empty"
            }
        }
    }
}

#[derive(Debug)]
struct RateLimitedDropNotice {
    interval: Duration,
    last_log: Option<Instant>,
    suppressed: u64,
}

impl RateLimitedDropNotice {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_log: None,
            suppressed: 0,
        }
    }

    fn record(&mut self, now: Instant) -> Option<u64> {
        match self.last_log {
            Some(last_log) if now.duration_since(last_log) < self.interval => {
                self.suppressed += 1;
                None
            }
            _ => {
                let suppressed = self.suppressed;
                self.suppressed = 0;
                self.last_log = Some(now);
                Some(suppressed)
            }
        }
    }
}

pub async fn spawn(
    config: &WireGuardConfig,
    shutdown: CancellationToken,
) -> io::Result<JoinHandle<()>> {
    spawn_with_metrics(config, shutdown, Arc::new(RelayMetrics::default())).await
}

pub async fn spawn_with_metrics(
    config: &WireGuardConfig,
    shutdown: CancellationToken,
    metrics: Arc<RelayMetrics>,
) -> io::Result<JoinHandle<()>> {
    let public_addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let internal_addr = SocketAddr::from(([127, 0, 0, 1], config.internal_port));

    spawn_with_addrs_and_metrics(
        public_addr,
        internal_addr,
        RelaySettings::from_config(config).obfuscation,
        Duration::from_secs(config.obfuscation_session_idle_secs),
        shutdown,
        metrics,
    )
    .await
    .map(|(_, handle)| handle)
}

#[allow(dead_code)]
pub(crate) async fn spawn_with_addrs(
    public_bind_addr: SocketAddr,
    internal_addr: SocketAddr,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    spawn_with_addrs_and_metrics(
        public_bind_addr,
        internal_addr,
        obfuscation,
        idle_timeout,
        shutdown,
        Arc::new(RelayMetrics::default()),
    )
    .await
}

pub(crate) async fn spawn_with_addrs_and_metrics(
    public_bind_addr: SocketAddr,
    internal_addr: SocketAddr,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    shutdown: CancellationToken,
    metrics: Arc<RelayMetrics>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let public_socket = Arc::new(UdpSocket::bind(public_bind_addr).await?);
    let local_addr = public_socket.local_addr()?;
    let sessions = Arc::new(DashMap::new());
    let clock = Arc::new(RelayClock::new());
    let settings = RelaySettings {
        obfuscation,
        idle_timeout,
        probe_block: read_probe_block_config(),
    };

    let task = tokio::spawn(run_relay(
        public_socket,
        internal_addr,
        settings,
        sessions,
        shutdown,
        clock,
        metrics,
    ));

    Ok((local_addr, task))
}

async fn run_relay(
    public_socket: Arc<UdpSocket>,
    internal_addr: SocketAddr,
    settings: RelaySettings,
    sessions: Arc<DashMap<SocketAddr, Arc<RelaySession>>>,
    shutdown: CancellationToken,
    clock: Arc<RelayClock>,
    metrics: Arc<RelayMetrics>,
) {
    info!(
        public_addr = %public_socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
        internal_addr = %internal_addr,
        magic_byte = ?settings.obfuscation.magic_byte,
        idle_timeout_secs = settings.idle_timeout.as_secs(),
        "WireGuard obfuscation relay started"
    );

    let cleanup_task = tokio::spawn(run_cleanup_loop(
        sessions.clone(),
        shutdown.clone(),
        settings.idle_timeout,
        clock.clone(),
        metrics.clone(),
    ));
    let mut magic_drop_notice = RateLimitedDropNotice::new(DROP_LOG_INTERVAL);
    let mut empty_drop_notice = RateLimitedDropNotice::new(DROP_LOG_INTERVAL);
    let mut other_drop_notice = RateLimitedDropNotice::new(DROP_LOG_INTERVAL);
    let probe_detector = ProbeDetector::new(settings.probe_block);

    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            recv = public_socket.recv_from(&mut buf) => {
                let (len, client_addr) = match recv {
                    Ok(result) => result,
                    Err(err) => {
                        if shutdown.is_cancelled() {
                            break;
                        }
                        warn!(%err, "WireGuard obfuscation relay receive failed");
                        continue;
                    }
                };

                let packet_received_at = Instant::now();
                if probe_detector.is_blocked(client_addr.ip(), packet_received_at) {
                    metrics
                        .probe_blocked_packets
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                let (session, decoded_len) = if settings.obfuscation.uses_framed_encoding() {
                    if let Err(err) = validate_framed_header(
                        &buf,
                        len,
                        &settings.obfuscation,
                    ) {
                        handle_decode_error(
                            &mut magic_drop_notice,
                            &mut empty_drop_notice,
                            &mut other_drop_notice,
                            &metrics,
                            &probe_detector,
                            err,
                            client_addr,
                            len,
                            packet_received_at,
                        );
                        continue;
                    }

                    let session = match get_or_create_session(
                            client_addr,
                            public_socket.clone(),
                            internal_addr,
                            settings.clone(),
                            sessions.clone(),
                            shutdown.clone(),
                            clock.clone(),
                            metrics.clone(),
                        )
                        .await
                    {
                        Ok(session) => session,
                        Err(err) => {
                            warn!(%client_addr, %err, "failed to create WireGuard relay session");
                            continue;
                        }
                    };

                    let decoded_len = {
                        let mut replay = session
                            .client_to_server_replay
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        match decode_packet_in_place(
                            &mut buf,
                            len,
                            &settings.obfuscation,
                            Some(&mut replay),
                            PacketDirection::ClientToServer,
                        ) {
                            Ok(decoded_len) => decoded_len,
                            Err(err) => {
                                handle_decode_error(
                                    &mut magic_drop_notice,
                                    &mut empty_drop_notice,
                                    &mut other_drop_notice,
                                    &metrics,
                                    &probe_detector,
                                    err,
                                    client_addr,
                                    len,
                                    packet_received_at,
                                );
                                continue;
                            }
                        }
                    };
                    (session, decoded_len)
                } else {
                    let decoded_len = match decode_packet_in_place(
                        &mut buf,
                        len,
                        &settings.obfuscation,
                        None,
                        PacketDirection::ClientToServer,
                    ) {
                        Ok(decoded_len) => decoded_len,
                        Err(err) => {
                            handle_decode_error(
                                &mut magic_drop_notice,
                                &mut empty_drop_notice,
                                &mut other_drop_notice,
                                &metrics,
                                &probe_detector,
                                err,
                                client_addr,
                                len,
                                packet_received_at,
                            );
                            continue;
                        }
                    };
                    let session = match get_or_create_session(
                        client_addr,
                        public_socket.clone(),
                        internal_addr,
                        settings.clone(),
                        sessions.clone(),
                        shutdown.clone(),
                        clock.clone(),
                        metrics.clone(),
                    )
                    .await
                    {
                        Ok(session) => session,
                        Err(err) => {
                            warn!(%client_addr, %err, "failed to create WireGuard relay session");
                            continue;
                        }
                    };
                    (session, decoded_len)
                };

                session.touch(clock.now_millis());
                if let Err(err) = session.upstream_socket.send(&buf[..decoded_len]).await {
                    warn!(%client_addr, %err, "failed to forward WireGuard packet to kernel listener");
                    if remove_session_if_current(&sessions, client_addr, &session) {
                        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                        metrics
                            .sessions_evicted_send_failure
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    session.close();
                } else {
                    metrics
                        .packets_client_to_server
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    cleanup_task.abort();
    let _ = cleanup_task.await;

    let sessions_to_close: Vec<_> = sessions
        .iter()
        .map(|entry| (*entry.key(), entry.value().clone()))
        .collect();
    for (client_addr, session) in sessions_to_close {
        if remove_session_if_current(&sessions, client_addr, &session) {
            metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
            metrics
                .sessions_closed_shutdown
                .fetch_add(1, Ordering::Relaxed);
        }
        session.close();
    }

    info!("WireGuard obfuscation relay shutting down");
}

fn log_decode_drop(
    notice: &mut RateLimitedDropNotice,
    reason: DropReason,
    client_addr: SocketAddr,
    packet_len: usize,
) {
    if let Some(suppressed_since_last) = notice.record(Instant::now()) {
        warn!(
            %client_addr,
            packet_len,
            reason = reason.as_str(),
            suppressed_since_last,
            "{}",
            reason.message()
        );
    }
}

fn handle_decode_error(
    magic_drop_notice: &mut RateLimitedDropNotice,
    empty_drop_notice: &mut RateLimitedDropNotice,
    other_drop_notice: &mut RateLimitedDropNotice,
    metrics: &RelayMetrics,
    probe_detector: &ProbeDetector,
    err: PacketDecodeError,
    client_addr: SocketAddr,
    packet_len: usize,
    now: Instant,
) {
    if matches!(err, PacketDecodeError::ChaffFrame) {
        return;
    }

    metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
    if matches!(err, PacketDecodeError::ReplayDetected) {
        metrics.replay_detected.fetch_add(1, Ordering::Relaxed);
    }

    if probe_detector.record_decode_error(client_addr.ip(), now) {
        warn!(
            event = "probe_detected",
            %client_addr,
            packet_len,
            reason = err.as_str(),
            "temporary WireGuard relay probe block installed for source IP"
        );
    }

    match err {
        PacketDecodeError::MagicByteMismatch => log_decode_drop(
            magic_drop_notice,
            DropReason::MagicByteMismatch,
            client_addr,
            packet_len,
        ),
        PacketDecodeError::EmptyPayload => log_decode_drop(
            empty_drop_notice,
            DropReason::EmptyPayload,
            client_addr,
            packet_len,
        ),
        PacketDecodeError::ChaffFrame => {}
        err => {
            if let Some(suppressed_since_last) = other_drop_notice.record(Instant::now()) {
                warn!(
                    %client_addr,
                    packet_len,
                    reason = err.as_str(),
                    %err,
                    suppressed_since_last,
                    "dropping inbound WireGuard UDP packet after structured decode failure"
                );
            }
        }
    }
}
