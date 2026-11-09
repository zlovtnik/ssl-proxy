//! Direct TCP dialing or an explicitly configured HTTP CONNECT egress hop.

use std::{io, net::SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const MAX_CONNECT_HEADERS: usize = 8192;

/// Connect without falling back to direct egress when a proxy is configured.
/// Callers retain their existing timeout around the complete dial and handshake.
pub(super) async fn connect(target: SocketAddr, proxy: Option<&str>) -> io::Result<TcpStream> {
    let Some(proxy) = proxy else {
        return TcpStream::connect(target).await;
    };
    let url = reqwest::Url::parse(proxy).map_err(|_| invalid_proxy())?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid_proxy());
    }
    let host = url.host_str().ok_or_else(invalid_proxy)?;
    let port = url.port_or_known_default().ok_or_else(invalid_proxy)?;
    let mut stream = TcpStream::connect((host.trim_matches(['[', ']']), port)).await?;
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;

    let headers = read_headers(&mut stream).await?;
    let headers = std::str::from_utf8(&headers)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid CONNECT response"))?;
    let mut status = headers
        .lines()
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid CONNECT status line",
        ));
    }
    match status.next() {
        Some("200") => Ok(stream),
        Some(code) if code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit()) => {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "egress proxy rejected CONNECT",
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid CONNECT status code",
        )),
    }
}

fn invalid_proxy() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "UPSTREAM_PROXY must be an http://host:port URL without credentials, path or query",
    )
}

async fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut headers = Vec::with_capacity(256);
    while headers.len() < MAX_CONNECT_HEADERS {
        // Read exactly the headers so bytes already sent by the destination
        // remain available to the tunnel, including server-first protocols.
        headers.push(stream.read_u8().await?);
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(headers);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "CONNECT response headers exceed limit",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_connection_preserves_existing_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let client = connect(target, None).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(client.local_addr().unwrap(), peer);
        assert_eq!(client.peer_addr().unwrap(), target);
    }

    #[tokio::test]
    async fn connect_preserves_target_authority_and_immediate_tunnel_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_headers(&mut stream).await.unwrap();
            assert_eq!(
                request,
                b"CONNECT [2001:db8::5]:443 HTTP/1.1\r\nHost: [2001:db8::5]:443\r\n\r\n"
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\nhello")
                .await
                .unwrap();
            let mut received = [0; 4];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"ping");
        });
        let mut client = connect("[2001:db8::5]:443".parse().unwrap(), Some(&proxy))
            .await
            .unwrap();
        let mut received = [0; 5];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello");
        client.write_all(b"ping").await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_and_malformed_responses_fail_without_direct_fallback() {
        for (response, expected) in [
            (
                b"HTTP/1.1 403 Forbidden\r\n\r\n".as_slice(),
                io::ErrorKind::ConnectionRefused,
            ),
            (
                b"HTTP/2 200 OK\r\n\r\n".as_slice(),
                io::ErrorKind::InvalidData,
            ),
            (
                b"HTTP/1.1 2000 Invalid\r\n\r\n".as_slice(),
                io::ErrorKind::InvalidData,
            ),
            (b"invalid\r\n\r\n".as_slice(), io::ErrorKind::InvalidData),
        ] {
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
            let task = tokio::spawn(async move {
                let (mut stream, _) = proxy.accept().await.unwrap();
                read_headers(&mut stream).await.unwrap();
                stream.write_all(response).await.unwrap();
            });
            let error = connect(target.local_addr().unwrap(), Some(&proxy_url))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), expected);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), target.accept())
                    .await
                    .is_err()
            );
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn oversized_response_is_rejected() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            read_headers(&mut stream).await.unwrap();
            stream
                .write_all(&vec![b'x'; MAX_CONNECT_HEADERS])
                .await
                .unwrap();
        });
        let error = connect("192.0.2.1:443".parse().unwrap(), Some(&proxy_url))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_proxy_configuration_fails_closed() {
        for proxy in [
            "https://127.0.0.1:80",
            "http://user:secret@127.0.0.1:80",
            "http://127.0.0.1/path",
            "not a URL",
        ] {
            let error = connect("192.0.2.1:443".parse().unwrap(), Some(proxy))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(!error.to_string().contains("secret"));
        }
    }
}
