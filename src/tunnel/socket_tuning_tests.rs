use super::*;

struct PartialWriter {
    remaining: usize,
    bytes: Vec<u8>,
}
impl AsyncWrite for PartialWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.remaining == 0 {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let n = bytes.len().min(self.remaining);
        self.bytes.extend_from_slice(&bytes[..n]);
        self.remaining -= n;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn prefix_partial_write_counts_only_accepted_bytes() {
    let mut writer = PartialWriter {
        remaining: 3,
        bytes: vec![],
    };
    let (written, outcome) = write_prefix(&mut writer, b"clienthello").await;
    assert_eq!(written, 3);
    assert!(outcome.is_err());
    assert_eq!(&writer.bytes, b"cli");
}

#[tokio::test]
async fn measured_copy_preserves_partial_totals_on_error() {
    struct Duplex {
        input: std::io::Cursor<Vec<u8>>,
        output: PartialWriter,
    }
    impl AsyncRead for Duplex {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.input).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for Duplex {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.output).poll_write(cx, b)
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let mut a = Duplex {
        input: std::io::Cursor::new(b"upload".to_vec()),
        output: PartialWriter {
            remaining: 100,
            bytes: vec![],
        },
    };
    let mut b = Duplex {
        input: std::io::Cursor::new(vec![]),
        output: PartialWriter {
            remaining: 2,
            bytes: vec![],
        },
    };
    let (up, down, complete) = measured_copy(&mut a, &mut b).await;
    assert_eq!((up, down, complete), (2, 0, false));
}

#[tokio::test]
async fn empty_transfer_is_measured_zero() {
    let (mut a, a_peer) = tokio::io::duplex(64);
    let (mut b, b_peer) = tokio::io::duplex(64);
    drop(a_peer);
    drop(b_peer);
    assert_eq!(measured_copy(&mut a, &mut b).await, (0, 0, true));
}
