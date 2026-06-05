use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use tokio::{net::UdpSocket, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    config::WireGuardConfig,
    wg_packet_obfuscation::{
        cleanup_interval, decode_packet_in_place, encode_packet_in_place, PacketDecodeError,
        PacketDirection, PacketEncodeState, ReplayWindow, WgPacketObfuscation, XorRekeyPolicy,
        MAX_UDP_PACKET_SIZE,
    },
};

const DROP_LOG_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct RelaySettings {
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
}

impl RelaySettings {
    fn from_config(config: &WireGuardConfig) -> Self {
        let obfuscation = WgPacketObfuscation::new(
            config.obfuscation_key.clone(),
            config.obfuscation_magic_byte,
        )
        .with_encryption_mode(config.obfuscation_encryption_mode)
        .with_padding(config.obfuscation_padding)
        .with_magic_position(config.obfuscation_magic_position)
        .with_xor_rekey(XorRekeyPolicy::new(
            config.obfuscation_xor_rekey_packets,
            config.obfuscation_xor_rekey_secs,
        ))
        .with_replay_protection(config.obfuscation_replay_protection);
        Self {
            obfuscation,
            idle_timeout: Duration::from_secs(config.obfuscation_session_idle_secs),
        }
    }
}

struct RelaySession {
    upstream_socket: Arc<UdpSocket>,
    last_activity_millis: AtomicU64,
    client_to_server_replay: Mutex<ReplayWindow>,
    // Server-to-client frames use this encoder state to choose the direction's
    // session salt. The salt is embedded in every frame, so the client shim can
    // derive reply keys from the frame alone without sharing this state object.
    server_to_client_encode: PacketEncodeState,
    shutdown: CancellationToken,
}

impl RelaySession {
    fn new(upstream_socket: Arc<UdpSocket>, now_millis: u64) -> Self {
        Self {
            upstream_socket,
            last_activity_millis: AtomicU64::new(now_millis),
            client_to_server_replay: Mutex::new(ReplayWindow::default()),
            server_to_client_encode: PacketEncodeState::new(now_millis),
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

    fn close(&self) {
        self.shutdown.cancel();
    }
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
    let public_addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let internal_addr = SocketAddr::from(([127, 0, 0, 1], config.internal_port));

    spawn_with_addrs(
        public_addr,
        internal_addr,
        RelaySettings::from_config(config).obfuscation,
        Duration::from_secs(config.obfuscation_session_idle_secs),
        shutdown,
    )
    .await
    .map(|(_, handle)| handle)
}

pub(crate) async fn spawn_with_addrs(
    public_bind_addr: SocketAddr,
    internal_addr: SocketAddr,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let public_socket = Arc::new(UdpSocket::bind(public_bind_addr).await?);
    let local_addr = public_socket.local_addr()?;
    let sessions = Arc::new(DashMap::new());
    let clock = Arc::new(RelayClock::new());
    let settings = RelaySettings {
        obfuscation,
        idle_timeout,
    };

    let task = tokio::spawn(run_relay(
        public_socket,
        internal_addr,
        settings,
        sessions,
        shutdown,
        clock,
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
    ));
    let mut magic_drop_notice = RateLimitedDropNotice::new(DROP_LOG_INTERVAL);
    let mut empty_drop_notice = RateLimitedDropNotice::new(DROP_LOG_INTERVAL);

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

                let (session, decoded_len) = if settings.obfuscation.uses_framed_encoding() {
                    let mut validation_buf = buf[..len].to_vec();
                    if let Err(err) = decode_packet_in_place(
                        &mut validation_buf,
                        len,
                        &settings.obfuscation,
                        None,
                        PacketDirection::ClientToServer,
                    ) {
                        log_decode_error(
                            &mut magic_drop_notice,
                            &mut empty_drop_notice,
                            err,
                            client_addr,
                            len,
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
                                log_decode_error(
                                    &mut magic_drop_notice,
                                    &mut empty_drop_notice,
                                    err,
                                    client_addr,
                                    len,
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
                            log_decode_error(
                                &mut magic_drop_notice,
                                &mut empty_drop_notice,
                                err,
                                client_addr,
                                len,
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
                    remove_session_if_current(&sessions, client_addr, &session);
                    session.close();
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
        remove_session_if_current(&sessions, client_addr, &session);
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

fn log_decode_error(
    magic_drop_notice: &mut RateLimitedDropNotice,
    empty_drop_notice: &mut RateLimitedDropNotice,
    err: PacketDecodeError,
    client_addr: SocketAddr,
    packet_len: usize,
) {
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
        err => warn!(
            %client_addr,
            packet_len,
            reason = err.as_str(),
            %err,
            "dropping inbound WireGuard UDP packet after structured decode failure"
        ),
    }
}
