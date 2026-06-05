use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::blocklist;
use crate::check_proxy_auth;
use crate::config::Config;
use crate::events;
use crate::obfuscation;
use crate::payload_redaction::payload_preview_json;
use crate::state::SharedState;
use crate::tunnel::{
    audit_event::TunnelAuditContext, classify, dial_upstream_with_resolver, parse_host_port,
    tls::parse_tls_info,
};

/// Create a TLS server configuration for QUIC using the certificate and private key
/// files specified in `config.tls.cert_path` and `config.tls.key_path`.
///
/// This function reads and parses PEM-formatted certificate chain and the first
/// private key, constructs a `rustls::ServerConfig` with no client authentication,
/// and enables HTTP/3 ALPN protocols (`h3` and `h3-29`).
///
/// # Panics
///
/// Panics if either path is not set on the provided `Config`, if the files cannot
/// be read, or if the PEM contents are malformed or do not contain a private key.
///
/// # Returns
///
/// An `Arc<rustls::ServerConfig>` configured for use with QUIC and HTTP/3.
///
/// # Examples
///
/// ```no_run
/// // Construct or obtain a `Config` with `tls.cert_path` and `tls.key_path` set,
/// // then pass a reference to this function to build the TLS config for QUIC.
/// // let cfg: Config = ...;
/// // let tls = build_rustls_config(&cfg);
/// ```
async fn build_rustls_config(config: &Config) -> Arc<rustls::ServerConfig> {
    let cert_path = config
        .tls
        .cert_path
        .as_ref()
        .expect("tls_cert_path must be set for QUIC");
    let key_path = config
        .tls
        .key_path
        .as_ref()
        .expect("tls_key_path must be set for QUIC");

    let cert_pem = tokio::fs::read(cert_path)
        .await
        .expect("failed to read TLS cert for QUIC");
    let key_pem = tokio::fs::read(key_path)
        .await
        .expect("failed to read TLS key for QUIC");
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .expect("invalid cert PEM for QUIC");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("failed to parse key PEM for QUIC")
        .expect("no private key found for QUIC");

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("invalid TLS config for QUIC");

    // Enable HTTP/3 ALPN with draft fallback for browser compatibility
    tls_config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];

    Arc::new(tls_config)
}

/// Start a QUIC + HTTP/3 listener on UDP 0.0.0.0:443 and spawn a task for each incoming connection.
///
/// The listener runs until `shutdown` is cancelled. For each accepted QUIC connection a background
/// task is spawned to process HTTP/3 requests for the lifetime of that connection. If `proxy_creds`
/// is provided, those credentials are used to authenticate incoming proxy requests.
///
/// # Examples
///
/// ```
/// // Typical usage pattern:
/// // let state: SharedState = ...;
/// // let config: Config = ...;
/// let shutdown = tokio_util::sync::CancellationToken::new();
/// // Spawn the listener (usually run in a dedicated runtime task)
/// // tokio::spawn(run_quic_listener(state, config, shutdown.clone(), None));
/// // Trigger shutdown when desired:
/// shutdown.cancel();
/// ```
const MAX_CONCURRENT_CONNECTIONS: usize = 10_000;

pub async fn run_quic_listener(
    state: SharedState,
    config: Config,
    shutdown: CancellationToken,
    proxy_creds: Option<Arc<(String, String)>>,
) {
    let rustls_config = build_rustls_config(&config).await;

    let quinn_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config);
    let quinn_config = match quinn_config {
        Ok(c) => c,
        Err(e) => {
            error!(%e, "failed to build QUIC server config");
            return;
        }
    };
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_config));

    let addr: SocketAddr = "0.0.0.0:443"
        .parse()
        .expect("static QUIC listen address must parse");
    let endpoint = match quinn::Endpoint::server(server_config, addr) {
        Ok(ep) => ep,
        Err(e) => {
            error!(%addr, %e, "failed to bind QUIC endpoint");
            return;
        }
    };
    info!(%addr, "QUIC/H3 listener active");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("QUIC listener shutting down");
                endpoint.close(0u32.into(), b"shutdown");

                // Wait for all in-flight connections to complete gracefully
                info!("Waiting for {} active QUIC connections to complete", tasks.len());
                loop {
                    match timeout(Duration::from_secs(30), tasks.join_next()).await {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => {
                            warn!("timed out draining QUIC connection tasks during shutdown");
                            break;
                        }
                    }
                }
                tasks.abort_all();
                info!("All QUIC connections drained");

                break;
            }
            incoming = endpoint.accept() => {
                let incoming = match incoming {
                    Some(i) => i,
                    None => {
                        info!("QUIC endpoint closed");
                        break;
                    }
                };

                // Acquire connection permit before spawning (applies backpressure at capacity)
                let permit = semaphore.clone().acquire_owned().await.expect("semaphore closed");

                let state = state.clone();
                let config = config.clone();
                let creds = proxy_creds.clone();

                tasks.spawn(async move {
                    // Hold permit for entire connection lifetime
                    let _permit_guard = permit;
                    handle_quic_connection(incoming, state, config, creds).await;
                });
            }
        }
    }
}

/// Handle a single QUIC connection: accept it, then process HTTP/3 requests.
async fn handle_quic_connection(
    incoming: quinn::Incoming,
    state: SharedState,
    config: Config,
    proxy_creds: Option<Arc<(String, String)>>,
) {
    let connection = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            debug!(%e, "QUIC connection failed");
            return;
        }
    };
    let peer = connection.remote_address();
    debug!(%peer, "QUIC connection established");

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match h3::server::Connection::new(h3_quinn::Connection::new(connection)).await {
            Ok(c) => c,
            Err(e) => {
                debug!(%peer, %e, "H3 connection setup failed");
                return;
            }
        };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let state = state.clone();
                let config = config.clone();
                let creds = proxy_creds.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            handle_h3_request(req, stream, state, config, peer, creds).await;
                        }
                        Err(e) => {
                            debug!(%peer, %e, "H3 request resolve failed");
                        }
                    }
                });
            }
            Ok(None) => {
                debug!(%peer, "H3 connection closed");
                break;
            }
            Err(e) => {
                debug!(%peer, %e, "H3 accept error");
                break;
            }
        }
    }
}
