use std::io;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

pub(super) const TUNNEL_COPY_BUFFER_SIZE: usize = 128 * 1024;

pub(super) fn configure_tunnel_tcp(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    set_keepalive(stream);
}

/// Counts successful writes, including writes preceding an error. Reading a
/// byte or buffering a prefix is not evidence it reached the other socket.
pub(super) struct CountingIo<T> {
    pub inner: T,
    pub written: u64,
}

impl<T> CountingIo<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, written: 0 }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            self.written = self.written.saturating_add(n as u64);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) async fn write_prefix<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> (u64, io::Result<()>) {
    let mut counted = CountingIo::new(writer);
    let result = counted.write_all(bytes).await;
    (counted.written, result)
}

pub(super) async fn measured_copy<A, B>(a: &mut A, b: &mut B) -> (u64, u64, bool)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a = CountingIo::new(a);
    let mut b = CountingIo::new(b);
    let complete = copy_bidirectional(&mut a, &mut b).await.is_ok();
    (b.written, a.written, complete)
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

#[cfg(test)]
#[path = "socket_tuning_tests.rs"]
mod tests;
