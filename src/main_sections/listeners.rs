async fn spawn_transparent_listener(
    config: &config::Config,
    state: state::SharedState,
    shutdown: CancellationToken,
    connection_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
) -> tokio::task::JoinHandle<()> {
    // Transparent proxy listener — receives connections redirected by iptables REDIRECT
    let tproxy_addr = SocketAddr::from(([0, 0, 0, 0], config.proxy.transparent_port));
    let tproxy_listener = tokio::net::TcpListener::bind(tproxy_addr)
        .await
        .unwrap_or_else(|e| {
            error!(%tproxy_addr, %e, "failed to bind transparent proxy listener");
            std::process::exit(1)
        });
    info!(%tproxy_addr, "transparent proxy listener active");

    let tproxy_state = state.clone();
    let tproxy_shutdown = shutdown.clone();
    let tproxy_connection_semaphore = connection_semaphore.clone();
    tokio::spawn(async move {
        let mut tproxy_tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                _ = tproxy_shutdown.cancelled() => break,
                result = tproxy_listener.accept() => {
                    match result {
                        Ok((stream, _peer)) => {
                            let permit = match tproxy_connection_semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!("max connections reached, dropping transparent connection");
                                    continue;
                                }
                            };
                            let s = tproxy_state.clone();
                            tproxy_tasks.spawn(async move {
                                let _permit = permit; // hold until task completes
                                tunnel::handle_transparent(stream, s).await;
                            });
                        }
                        Err(e) => error!(%e, "tproxy accept failed"),
                    }
                }
            }
        }
        while tproxy_tasks.join_next().await.is_some() {}
    })
}

fn build_explicit_proxy_router(
    state: state::SharedState,
    cors: CorsLayer,
) -> Router {
    Router::new()
        .fallback(any(proxy::handler))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

fn build_proxy_credentials(
    config: &config::Config,
) -> Option<std::sync::Arc<(String, String)>> {
    let proxy_creds = config.proxy.credentials.as_ref().map(|creds| {
        info!(username = %creds.username, "explicit proxy authentication enabled");
        std::sync::Arc::new((creds.username.clone(), creds.password.clone()))
    });
    if proxy_creds.is_none() {
        warn!("PROXY_USERNAME / PROXY_PASSWORD not set — explicit proxy has NO authentication");
    }
    proxy_creds
}

fn build_tls_acceptor(config: &config::Config) -> Option<TlsAcceptor> {
    if let (Some(cert_path), Some(key_path)) = (&config.tls.cert_path, &config.tls.key_path) {
        let cert_pem = std::fs::read(cert_path).expect("failed to read TLS cert");
        let key_pem = std::fs::read(key_path).expect("failed to read TLS key");
        let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<_, _>>()
            .expect("invalid cert PEM");
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .expect("failed to parse key PEM")
            .expect("no private key found");
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("invalid TLS config");
        info!("TLS enabled on explicit proxy listener");
        Some(TlsAcceptor::from(std::sync::Arc::new(tls_config)))
    } else {
        warn!("TLS_CERT_PATH / TLS_KEY_PATH not set — explicit proxy listener is PLAINTEXT");
        None
    }
}

fn spawn_quic_listener_if_enabled(
    config: &config::Config,
    state: state::SharedState,
    shutdown: CancellationToken,
    proxy_creds: Option<std::sync::Arc<(String, String)>>,
    tls_acceptor: &Option<TlsAcceptor>,
    tasks: &mut JoinSet<()>,
) {
    #[cfg(feature = "quic")]
    if tls_acceptor.is_some() {
        let quic_state = state.clone();
        let quic_config = config.clone();
        let quic_shutdown = shutdown.clone();
        let quic_creds = proxy_creds.clone();
        tasks.spawn(async move {
            quic::run_quic_listener(quic_state, quic_config, quic_shutdown, quic_creds).await;
        });
    }
    #[cfg(not(feature = "quic"))]
    if tls_acceptor.is_some() {
        warn!("TLS enabled for explicit proxy but QUIC support is disabled at compile time");
    }
}

async fn run_explicit_proxy_listener(
    config: &config::Config,
    state: state::SharedState,
    shutdown: &CancellationToken,
    connection_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    tasks: &mut JoinSet<()>,
    cors: CorsLayer,
) {
    warn!(
        "EXPLICIT_PROXY_ENABLED=true — legacy explicit proxy listeners are active; plaintext HTTP CONNECT leaks target hostnames on the client-to-proxy leg"
    );

    let router = build_explicit_proxy_router(state.clone(), cors);
    let proxy_creds = build_proxy_credentials(config);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.proxy.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            error!(%addr, %e, "failed to bind explicit proxy listener");
            std::process::exit(1)
        });
    info!(%addr, "explicit proxy listener active");

    let tls_acceptor = build_tls_acceptor(config);
    spawn_quic_listener_if_enabled(
        config,
        state.clone(),
        shutdown.clone(),
        proxy_creds.clone(),
        &tls_acceptor,
        tasks,
    );

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("shutdown signal received, stopping explicit proxy accept loop");
                shutdown.cancel();
                break;
            }
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    error!(%e, "ctrl_c signal handler failed");
                }
                info!("shutdown signal received, stopping explicit proxy accept loop");
                shutdown.cancel();
                break;
            }
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok(c) => c,
                    Err(e) => {
                        error!(%e, "accept failed");
                        continue;
                    }
                };

                let permit = match connection_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("max connections reached, dropping connection");
                        continue;
                    }
                };

                let state = state.clone();
                let router = router.clone();
                let token = shutdown.clone();
                let tls_acceptor = tls_acceptor.clone();
                let proxy_creds = proxy_creds.clone();

                tasks.spawn(async move {
                    let _permit = permit; // hold until task completes
                    serve_explicit_proxy_connection(
                        stream,
                        peer,
                        state,
                        router,
                        token,
                        tls_acceptor,
                        proxy_creds,
                    )
                    .await;
                });
            }
        }
    }
}

async fn serve_explicit_proxy_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    state: state::SharedState,
    router: Router,
    token: CancellationToken,
    tls_acceptor: Option<TlsAcceptor>,
    proxy_creds: Option<std::sync::Arc<(String, String)>>,
) {
    macro_rules! serve_io {
        ($io:expr) => {{
            let io = $io;
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let state = state.clone();
                let router = router.clone();
                let creds = proxy_creds.clone();
                async move {
                    let req: Request<Body> = req.map(Body::new);

                    let is_proxy_request =
                        req.method() == Method::CONNECT || req.uri().scheme().is_some();

                    if is_proxy_request {
                        if let Some(ref c) = creds {
                            if !check_proxy_auth(&req, &c.0, &c.1) {
                                return Ok(Response::builder()
                                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                                    .header("Proxy-Authenticate", "Basic realm=\"Proxy Access\"")
                                    .body(Body::empty())
                                    .unwrap());
                            }
                        }
                    }

                    if req.method() == Method::CONNECT {
                        tunnel::handle(req, state, Some(peer.ip().to_string())).await
                    } else {
                        let mut req = req;
                        req.extensions_mut().insert(peer.ip());
                        let mut router = router.clone();
                        router.call(req).await.map_err(|e| match e {})
                    }
                }
            });

            let builder = ServerBuilder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(io, svc);
            tokio::select! {
                result = conn => {
                    if let Err(e) = result {
                        debug!(%peer, %e, "connection error");
                    }
                }
                _ = token.cancelled() => {
                    debug!(%peer, "connection dropped due to shutdown");
                }
            }
        }};
    }

    if let Some(ref acceptor) = tls_acceptor {
        match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                serve_io!(TokioIo::new(tls_stream));
            }
            Err(e) => {
                debug!(%peer, %e, "TLS handshake failed");
            }
        }
    } else {
        serve_io!(TokioIo::new(stream));
    }
}

async fn wait_for_background_shutdown(config: &config::Config, shutdown: &CancellationToken) {
    info!(
        proxy_port = config.proxy.port,
        "explicit proxy listener disabled; WireGuard is the supported client ingress"
    );
    if config.tls.cert_path.is_some() || config.tls.key_path.is_some() {
        warn!(
            "TLS_CERT_PATH / TLS_KEY_PATH set while EXPLICIT_PROXY_ENABLED=false — skipping HTTPS and QUIC explicit-proxy listeners"
        );
    }
    tokio::select! {
        _ = shutdown.cancelled() => {
            info!("shutdown signal received, stopping background listeners");
        }
        result = tokio::signal::ctrl_c() => {
            if let Err(e) = result {
                error!(%e, "ctrl_c signal handler failed");
            }
            info!("shutdown signal received, stopping background listeners");
            shutdown.cancel();
        }
    }
    shutdown.cancel();
}

async fn drain_shutdown(
    mut tasks: JoinSet<()>,
    tproxy_handle: tokio::task::JoinHandle<()>,
    otel_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
) {
    info!("draining in-flight connections (5s timeout)");
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), tproxy_handle).await;
    observability::shutdown_tracer_provider(otel_provider);
    info!("shutdown complete");
}

/// Application entrypoint that initializes runtime components and runs the proxy service.
#[tokio::main]
async fn main() {
    if let Some(exit_code) = run_boringtun_subcommand() {
        std::process::exit(exit_code);
    }

    install_rustls_provider();
    let config = config::Config::from_env_or_panic();
    if let Err(e) = security::verify_startup_integrity() {
        eprintln!("startup integrity verification failed; refusing to start: {e}");
        std::process::exit(1);
    }

    let otel_provider = init_tracing(&config);
    let shutdown = CancellationToken::new();
    let state = build_state(&config);
    spawn_background_tasks(&config, state.clone(), shutdown.clone());

    // Semaphore to limit concurrent connections
    let connection_semaphore =
        std::sync::Arc::new(tokio::sync::Semaphore::new(config.proxy.max_connections));
    let cors = build_admin_cors(&config);

    spawn_admin_listener(&config, state.clone(), shutdown.clone(), cors.clone()).await;
    log_runtime_ports(&config);
    let _wg_relay = spawn_wireguard_relay(&config, state.clone(), shutdown.clone()).await;
    let tproxy_handle = spawn_transparent_listener(
        &config,
        state.clone(),
        shutdown.clone(),
        connection_semaphore.clone(),
    )
    .await;

    let mut tasks: JoinSet<()> = JoinSet::new();
    if config.proxy.explicit_enabled {
        run_explicit_proxy_listener(
            &config,
            state,
            &shutdown,
            connection_semaphore,
            &mut tasks,
            cors,
        )
        .await;
    } else {
        wait_for_background_shutdown(&config, &shutdown).await;
    }

    drain_shutdown(tasks, tproxy_handle, otel_provider).await;
}
