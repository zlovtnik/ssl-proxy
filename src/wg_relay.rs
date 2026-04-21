//! Obfuscated WireGuard UDP relay.
//!
//! This relay fronts the public WireGuard UDP port, removes the configured
//! XOR-plus-magic-byte wrapping from inbound packets, forwards plaintext
//! packets to the local kernel WireGuard listener, and applies the inverse
//! transform to replies before sending them back to the client.

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use tokio::{net::UdpSocket, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    config::WireGuardConfig,
    wg_packet_obfuscation::{
        decode_packet, encode_packet, PacketDecodeError, WgPacketObfuscation, MAX_UDP_PACKET_SIZE,
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
        Self {
            obfuscation: WgPacketObfuscation::new(
                config.obfuscation_key.clone(),
                config.obfuscation_magic_byte,
            ),
            idle_timeout: Duration::from_secs(config.obfuscation_session_idle_secs),
        }
    }
}

struct RelaySession {
    upstream_socket: Arc<UdpSocket>,
    last_activity: Mutex<Instant>,
    shutdown: CancellationToken,
}

impl RelaySession {
    fn new(upstream_socket: Arc<UdpSocket>) -> Self {
        Self {
            upstream_socket,
            last_activity: Mutex::new(Instant::now()),
            shutdown: CancellationToken::new(),
        }
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
    }

    fn close(&self) {
        self.shutdown.cancel();
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
    ));

    Ok((local_addr, task))
}

async fn run_relay(
    public_socket: Arc<UdpSocket>,
    internal_addr: SocketAddr,
    settings: RelaySettings,
    sessions: Arc<DashMap<SocketAddr, Arc<RelaySession>>>,
    shutdown: CancellationToken,
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

                let packet = match decode_packet(&buf[..len], &settings.obfuscation) {
                    Ok(packet) => packet,
                    Err(PacketDecodeError::MagicByteMismatch) => {
                        log_decode_drop(
                            &mut magic_drop_notice,
                            DropReason::MagicByteMismatch,
                            client_addr,
                            len,
                        );
                        continue;
                    }
                    Err(PacketDecodeError::EmptyPayload) => {
                        log_decode_drop(
                            &mut empty_drop_notice,
                            DropReason::EmptyPayload,
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
                )
                .await
                {
                    Ok(session) => session,
                    Err(err) => {
                        warn!(%client_addr, %err, "failed to create WireGuard relay session");
                        continue;
                    }
                };

                session.touch();
                if let Err(err) = session.upstream_socket.send(&packet).await {
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

async fn get_or_create_session(
    client_addr: SocketAddr,
    public_socket: Arc<UdpSocket>,
    internal_addr: SocketAddr,
    settings: RelaySettings,
    sessions: Arc<DashMap<SocketAddr, Arc<RelaySession>>>,
    shutdown: CancellationToken,
) -> io::Result<Arc<RelaySession>> {
    if let Some(existing) = sessions.get(&client_addr) {
        let session = existing.value().clone();
        session.touch();
        return Ok(session);
    }

    let upstream_socket = Arc::new(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?);
    upstream_socket.connect(internal_addr).await?;

    let session = Arc::new(RelaySession::new(upstream_socket.clone()));
    sessions.insert(client_addr, session.clone());

    tokio::spawn(run_session_receiver(
        client_addr,
        session.clone(),
        public_socket,
        settings,
        sessions,
        shutdown,
    ));

    Ok(session)
}

async fn run_session_receiver(
    client_addr: SocketAddr,
    session: Arc<RelaySession>,
    public_socket: Arc<UdpSocket>,
    settings: RelaySettings,
    sessions: Arc<DashMap<SocketAddr, Arc<RelaySession>>>,
    shutdown: CancellationToken,
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

                session.touch();
                let packet = encode_packet(&buf[..len], &settings.obfuscation);
                if let Err(err) = public_socket.send_to(&packet, client_addr).await {
                    warn!(%client_addr, %err, "failed to send obfuscated WireGuard packet to client");
                    break;
                }
            }
        }
    }

    remove_session_if_current(&sessions, client_addr, &session);
    session.close();
}

async fn run_cleanup_loop(
    sessions: Arc<DashMap<SocketAddr, Arc<RelaySession>>>,
    shutdown: CancellationToken,
    idle_timeout: Duration,
) {
    let mut interval = tokio::time::interval(cleanup_interval(idle_timeout));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = interval.tick() => {
                let stale_sessions: Vec<_> = sessions
                    .iter()
                    .filter_map(|entry| {
                        let client_addr = *entry.key();
                        let session = entry.value().clone();
                        (session.idle_for() >= idle_timeout).then_some((client_addr, session))
                    })
                    .collect();

                for (client_addr, session) in stale_sessions {
                    remove_session_if_current(&sessions, client_addr, &session);
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
) {
    let Some(existing) = sessions.get(&client_addr) else {
        return;
    };
    if Arc::ptr_eq(existing.value(), session) {
        drop(existing);
        sessions.remove(&client_addr);
    }
}

fn cleanup_interval(idle_timeout: Duration) -> Duration {
    let half = idle_timeout / 2;
    if half.is_zero() {
        Duration::from_millis(1)
    } else {
        half.min(Duration::from_secs(5))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use tokio::time::{sleep, timeout};

    use super::*;

    fn test_settings(magic_byte: Option<u8>, idle_timeout: Duration) -> WgPacketObfuscation {
        let _ = idle_timeout;
        WgPacketObfuscation::new(b"test-obfuscation-key".to_vec(), magic_byte)
    }

    #[test]
    fn drop_notice_is_rate_limited() {
        let mut notice = RateLimitedDropNotice::new(Duration::from_secs(30));
        let now = Instant::now();

        assert_eq!(notice.record(now), Some(0));
        assert_eq!(notice.record(now + Duration::from_secs(1)), None);
        assert_eq!(notice.record(now + Duration::from_secs(31)), Some(1));
    }

    #[tokio::test]
    async fn relay_forwards_plaintext_to_internal_listener_and_replies() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_settings(Some(0xAA), Duration::from_secs(1));
        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_addr, relay_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"handshake-init");
            internal_socket
                .send_to(b"handshake-reply", relay_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let encoded = encode_packet(b"handshake-init", &obfuscation);
        client.send_to(&encoded, public_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let decoded = decode_packet(&buf[..len], &obfuscation).unwrap();
        assert_eq!(decoded, b"handshake-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn relay_uses_distinct_upstream_ports_per_client() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_settings(Some(0xAA), Duration::from_secs(1));
        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_addr, relay_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..2 {
                let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
                peers.push(relay_peer);
                internal_socket
                    .send_to(&buf[..len], relay_peer)
                    .await
                    .unwrap();
            }
            peers
        });

        let client_one = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let client_two = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();

        client_one
            .send_to(&encode_packet(b"peer-one", &obfuscation), public_addr)
            .await
            .unwrap();
        client_two
            .send_to(&encode_packet(b"peer-two", &obfuscation), public_addr)
            .await
            .unwrap();

        let mut buf_one = [0u8; 2048];
        let mut buf_two = [0u8; 2048];
        let (len_one, _) = timeout(Duration::from_secs(1), client_one.recv_from(&mut buf_one))
            .await
            .unwrap()
            .unwrap();
        let (len_two, _) = timeout(Duration::from_secs(1), client_two.recv_from(&mut buf_two))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_packet(&buf_one[..len_one], &obfuscation).unwrap(),
            b"peer-one"
        );
        assert_eq!(
            decode_packet(&buf_two[..len_two], &obfuscation).unwrap(),
            b"peer-two"
        );

        let peers = upstream.await.unwrap();
        let unique_peers: HashSet<_> = peers.into_iter().map(|peer| peer.port()).collect();
        assert_eq!(unique_peers.len(), 2);

        shutdown.cancel();
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn relay_drops_raw_direct_packets_without_magic_byte() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_settings(Some(0xAA), Duration::from_secs(1));
        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_addr, relay_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation,
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"missing-magic-byte", public_addr)
            .await
            .unwrap();

        let mut internal_buf = [0u8; 2048];
        let mut client_buf = [0u8; 2048];
        assert!(timeout(
            Duration::from_millis(250),
            internal_socket.recv_from(&mut internal_buf)
        )
        .await
        .is_err());
        assert!(timeout(
            Duration::from_millis(250),
            client.recv_from(&mut client_buf)
        )
        .await
        .is_err());

        shutdown.cancel();
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn relay_evicts_idle_sessions_and_recreates_upstream_socket() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_settings(Some(0xAA), Duration::from_millis(100));
        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_addr, relay_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation.clone(),
            Duration::from_millis(100),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut peers = Vec::new();
            for _ in 0..2 {
                let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
                peers.push(relay_peer);
                internal_socket
                    .send_to(&buf[..len], relay_peer)
                    .await
                    .unwrap();
            }
            peers
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(&encode_packet(b"first-packet", &obfuscation), public_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        sleep(Duration::from_millis(250)).await;

        client
            .send_to(&encode_packet(b"second-packet", &obfuscation), public_addr)
            .await
            .unwrap();
        timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let peers = upstream.await.unwrap();
        assert_eq!(peers.len(), 2);
        assert_ne!(peers[0].port(), peers[1].port());

        shutdown.cancel();
        relay_task.await.unwrap();
    }
}
