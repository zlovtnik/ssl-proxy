use std::{io, net::SocketAddr};

use tokio::net::UdpSocket;
use tracing::warn;

pub const DEFAULT_UDP_SOCKET_BUFFER_BYTES: usize = 16 * 1024 * 1024;

pub fn bind_tuned_udp_socket(
    bind_addr: SocketAddr,
    buffer_bytes: usize,
    label: &'static str,
) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind_addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    tune_udp_socket_buffers(&socket, label, buffer_bytes);
    let sock_addr = socket2::SockAddr::from(bind_addr);
    socket.bind(&sock_addr)?;

    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket)
}

pub fn tune_udp_socket_buffers(socket: &socket2::Socket, label: &'static str, size: usize) {
    if let Err(err) = socket.set_recv_buffer_size(size) {
        warn!(
            socket = label,
            requested_bytes = size,
            %err,
            "failed to set UDP receive buffer"
        );
    }
    if let Err(err) = socket.set_send_buffer_size(size) {
        warn!(
            socket = label,
            requested_bytes = size,
            %err,
            "failed to set UDP send buffer"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tune_udp_socket_buffers_applies_to_socket() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();

        let initial_recv = socket.recv_buffer_size().unwrap();
        let initial_send = socket.send_buffer_size().unwrap();
        let requested_size = initial_recv.max(initial_send).saturating_add(256 * 1024);

        tune_udp_socket_buffers(&socket, "test", requested_size);

        assert!(socket.recv_buffer_size().unwrap() >= initial_recv);
        assert!(socket.send_buffer_size().unwrap() >= initial_send);
    }
}
