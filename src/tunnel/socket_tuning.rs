use std::io;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub(super) const TUNNEL_COPY_BUFFER_SIZE: usize = 128 * 1024;

pub(super) fn configure_tunnel_tcp(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    set_keepalive(stream);
}

pub(super) async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional_with_sizes(a, b, TUNNEL_COPY_BUFFER_SIZE, TUNNEL_COPY_BUFFER_SIZE)
        .await
}

fn set_keepalive(stream: &TcpStream) {
    let ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(10))
        .with_interval(std::time::Duration::from_secs(5));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}
