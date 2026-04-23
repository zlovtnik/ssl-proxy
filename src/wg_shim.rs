//! Linux WireGuard obfuscation shim.
//!
//! The shim listens locally for plaintext WireGuard UDP packets from a client
//! and forwards them to the real server endpoint using the same XOR-plus-
//! optional-magic-byte wrapper as the server relay.

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

use crate::wg_packet_obfuscation::{
    decode_packet, encode_packet, PacketDecodeError, WgPacketObfuscation, MAX_UDP_PACKET_SIZE,
};

pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:51821";
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgObfsShimConfig {
    pub listen_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub obfuscation: WgPacketObfuscation,
    pub idle_timeout: Duration,
}

impl WgObfsShimConfig {
    pub fn new(
        listen_addr: SocketAddr,
        server_addr: SocketAddr,
        obfuscation: WgPacketObfuscation,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            listen_addr,
            server_addr,
            obfuscation,
            idle_timeout,
        }
    }
}

struct ShimSession {
    upstream_socket: Arc<UdpSocket>,
    last_activity: Mutex<Instant>,
    shutdown: CancellationToken,
}

impl ShimSession {
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

pub async fn spawn(
    config: WgObfsShimConfig,
    shutdown: CancellationToken,
) -> io::Result<JoinHandle<()>> {
    spawn_with_addrs(
        config.listen_addr,
        config.server_addr,
        config.obfuscation,
        config.idle_timeout,
        shutdown,
    )
    .await
    .map(|(_, handle)| handle)
}

pub(crate) async fn spawn_with_addrs(
    listen_addr: SocketAddr,
    server_addr: SocketAddr,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listen_socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    let local_addr = listen_socket.local_addr()?;
    let sessions = Arc::new(DashMap::new());

    let task = tokio::spawn(run_shim(
        listen_socket,
        server_addr,
        obfuscation,
        idle_timeout,
        sessions,
        shutdown,
    ));

    Ok((local_addr, task))
}

async fn run_shim(
    listen_socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    sessions: Arc<DashMap<SocketAddr, Arc<ShimSession>>>,
    shutdown: CancellationToken,
) {
    info!(
        listen_addr = %listen_socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0))),
        server_addr = %server_addr,
        magic_byte = ?obfuscation.magic_byte,
        idle_timeout_secs = idle_timeout.as_secs(),
        "WireGuard obfuscation shim started"
    );

    let cleanup_task = tokio::spawn(run_cleanup_loop(
        sessions.clone(),
        shutdown.clone(),
        idle_timeout,
    ));

    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            recv = listen_socket.recv_from(&mut buf) => {
                let (len, client_addr) = match recv {
                    Ok(result) => result,
                    Err(err) => {
                        if shutdown.is_cancelled() {
                            break;
                        }
                        warn!(%err, "WireGuard obfuscation shim receive failed");
                        continue;
                    }
                };

                let session = match get_or_create_session(
                    client_addr,
                    listen_socket.clone(),
                    server_addr,
                    obfuscation.clone(),
                    idle_timeout,
                    sessions.clone(),
                    shutdown.clone(),
                )
                .await
                {
                    Ok(session) => session,
                    Err(err) => {
                        warn!(%client_addr, %err, "failed to create WireGuard shim session");
                        continue;
                    }
                };

                session.touch();
                let packet = encode_packet(&buf[..len], &obfuscation);
                if let Err(err) = session.upstream_socket.send(&packet).await {
                    warn!(%client_addr, %err, "failed to send obfuscated WireGuard packet to server");
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

    info!("WireGuard obfuscation shim shutting down");
}

async fn get_or_create_session(
    client_addr: SocketAddr,
    listen_socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    sessions: Arc<DashMap<SocketAddr, Arc<ShimSession>>>,
    shutdown: CancellationToken,
) -> io::Result<Arc<ShimSession>> {
    if let Some(existing) = sessions.get(&client_addr) {
        return Ok(existing.clone());
    }

    let upstream_socket = Arc::new(UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?);
    upstream_socket.connect(server_addr).await?;
    let candidate = Arc::new(ShimSession::new(upstream_socket));

    let session = match sessions.entry(client_addr) {
        dashmap::mapref::entry::Entry::Occupied(existing) => existing.get().clone(),
        dashmap::mapref::entry::Entry::Vacant(vacant) => {
            let session = vacant.insert(candidate).clone();
            let sessions_for_task = sessions.clone();
            tokio::spawn(run_session_receiver(
                client_addr,
                session.clone(),
                listen_socket,
                obfuscation,
                idle_timeout,
                sessions_for_task,
                shutdown,
            ));
            session
        }
    };
    Ok(session)
}

async fn run_session_receiver(
    client_addr: SocketAddr,
    session: Arc<ShimSession>,
    listen_socket: Arc<UdpSocket>,
    obfuscation: WgPacketObfuscation,
    idle_timeout: Duration,
    sessions: Arc<DashMap<SocketAddr, Arc<ShimSession>>>,
    shutdown: CancellationToken,
) {
    let _ = idle_timeout;
    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = session.shutdown.cancelled() => break,
            recv = session.upstream_socket.recv(&mut buf) => {
                let len = match recv {
                    Ok(len) => len,
                    Err(err) => {
                        warn!(%client_addr, %err, "WireGuard shim session receive failed");
                        break;
                    }
                };

                session.touch();
                let packet = match decode_packet(&buf[..len], &obfuscation) {
                    Ok(packet) => packet,
                    Err(PacketDecodeError::MagicByteMismatch) => {
                        warn!(%client_addr, packet_len = len, "dropping server reply with missing or invalid obfuscation marker");
                        continue;
                    }
                    Err(PacketDecodeError::EmptyPayload) => {
                        warn!(%client_addr, packet_len = len, "dropping server reply with empty obfuscation payload");
                        continue;
                    }
                };

                if let Err(err) = listen_socket.send_to(&packet, client_addr).await {
                    warn!(%client_addr, %err, "failed to deliver plaintext WireGuard packet back to local client");
                    break;
                }
            }
        }
    }

    remove_session_if_current(&sessions, client_addr, &session);
    session.close();
}

async fn run_cleanup_loop(
    sessions: Arc<DashMap<SocketAddr, Arc<ShimSession>>>,
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
    sessions: &DashMap<SocketAddr, Arc<ShimSession>>,
    client_addr: SocketAddr,
    session: &Arc<ShimSession>,
) {
    let _ = sessions.remove_if(&client_addr, |_, current| Arc::ptr_eq(current, session));
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
    use crate::{wg_packet_obfuscation::decode_packet as decode_obfuscated_packet, wg_relay};

    fn test_obfuscation(magic_byte: Option<u8>) -> WgPacketObfuscation {
        WgPacketObfuscation::new(b"test-obfuscation-key".to_vec(), magic_byte)
    }

    #[tokio::test]
    async fn shim_obfuscates_plaintext_and_decodes_replies() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
            let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
            assert_eq!(decoded, b"handshake-init");
            let response = encode_packet(b"handshake-reply", &obfuscation);
            server_socket.send_to(&response, shim_peer).await.unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"handshake-init", listen_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"handshake-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_uses_distinct_upstream_ports_per_local_client() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
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
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
                let response = encode_packet(&decoded, &obfuscation);
                server_socket.send_to(&response, shim_peer).await.unwrap();
            }
            peers
        });

        let client_one = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let client_two = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();

        client_one.send_to(b"peer-one", listen_addr).await.unwrap();
        client_two.send_to(b"peer-two", listen_addr).await.unwrap();

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
        assert_eq!(&buf_one[..len_one], b"peer-one");
        assert_eq!(&buf_two[..len_two], b"peer-two");

        let peers = upstream.await.unwrap();
        let unique_peers: HashSet<_> = peers.into_iter().map(|peer| peer.port()).collect();
        assert_eq!(unique_peers.len(), 2);

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_evicts_idle_sessions_and_recreates_upstream_socket() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));
        let server_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            server_addr,
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
                let (len, shim_peer) = server_socket.recv_from(&mut buf).await.unwrap();
                peers.push(shim_peer);
                let decoded = decode_obfuscated_packet(&buf[..len], &obfuscation).unwrap();
                let response = encode_packet(&decoded, &obfuscation);
                server_socket.send_to(&response, shim_peer).await.unwrap();
            }
            peers
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client.send_to(b"first-packet", listen_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        sleep(Duration::from_millis(250)).await;

        client.send_to(b"second-packet", listen_addr).await.unwrap();
        timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let peers = upstream.await.unwrap();
        assert_eq!(peers.len(), 2);
        assert_ne!(peers[0].port(), peers[1].port());

        shutdown.cancel();
        shim_task.await.unwrap();
    }

    #[tokio::test]
    async fn shim_and_server_relay_round_trip_end_to_end() {
        let shutdown = CancellationToken::new();
        let obfuscation = test_obfuscation(Some(0xAA));

        let internal_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let internal_addr = internal_socket.local_addr().unwrap();
        let (public_server_addr, relay_task) = wg_relay::spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            internal_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let (shim_listen_addr, shim_task) = spawn_with_addrs(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            public_server_addr,
            obfuscation.clone(),
            Duration::from_secs(1),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, relay_peer) = internal_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"end-to-end-handshake");
            internal_socket
                .send_to(b"end-to-end-reply", relay_peer)
                .await
                .unwrap();
        });

        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        client
            .send_to(b"end-to-end-handshake", shim_listen_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"end-to-end-reply");

        upstream.await.unwrap();
        shutdown.cancel();
        shim_task.await.unwrap();
        relay_task.await.unwrap();
    }
}
