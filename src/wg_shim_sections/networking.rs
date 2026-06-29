fn evict_oldest_session(
    sessions: &DashMap<SocketAddr, Arc<ShimSession>>,
    metrics: &ShimMetrics,
    exclude: Option<SocketAddr>,
) -> bool {
    let oldest = sessions
        .iter()
        .filter(|entry| Some(*entry.key()) != exclude)
        .min_by_key(|entry| entry.value().last_activity_millis())
        .map(|entry| (*entry.key(), entry.value().clone()));

    let Some((client_addr, session)) = oldest else {
        return false;
    };

    close_session_if_current(
        sessions,
        client_addr,
        &session,
        metrics,
        SessionCloseReason::TableLimit,
    )
}

fn close_session_if_current(
    sessions: &DashMap<SocketAddr, Arc<ShimSession>>,
    client_addr: SocketAddr,
    session: &Arc<ShimSession>,
    metrics: &ShimMetrics,
    reason: SessionCloseReason,
) -> bool {
    let removed = sessions
        .remove_if(&client_addr, |_, current| Arc::ptr_eq(current, session))
        .is_some();
    if removed {
        session.close();
        let abandoned_queue_depth = session.clear_send_queue(metrics);
        metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        metrics.record_send_queue_capacity_sub(session.send_queue_capacity());
        match reason {
            SessionCloseReason::Idle => {
                metrics
                    .sessions_evicted_idle
                    .fetch_add(1, Ordering::Relaxed);
            }
            SessionCloseReason::SendFailure => {
                metrics
                    .sessions_evicted_send_failure
                    .fetch_add(1, Ordering::Relaxed);
            }
            SessionCloseReason::TableLimit => {
                metrics
                    .sessions_evicted_table_limit
                    .fetch_add(1, Ordering::Relaxed);
            }
            SessionCloseReason::Shutdown => {
                metrics
                    .sessions_closed_shutdown
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        session.span.in_scope(|| {
            info!(
                reason = reason.as_str(),
                session_id = session.id,
                upstream_port = session.upstream_port.load(Ordering::Relaxed),
                abandoned_queue_depth,
                "WireGuard shim session closed"
            );
        });
    }
    removed
}

async fn drain_receiver_tasks(mut handles: Vec<JoinHandle<()>>, drain_timeout: Duration) {
    let deadline = Instant::now() + drain_timeout;
    for mut handle in handles.drain(..) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            handle.abort();
            let _ = handle.await;
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(remaining) => {
                handle.abort();
                let _ = handle.await;
            }
            _ = &mut handle => {}
        }
    }
}

#[cfg(feature = "metrics")]
async fn run_metrics_server(
    metrics_addr: SocketAddr,
    metrics: Arc<ShimMetrics>,
    shutdown: CancellationToken,
) {
    use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};

    async fn metrics_handler(State(metrics): State<Arc<ShimMetrics>>) -> impl IntoResponse {
        (
            [(
                header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            metrics.render_openmetrics(),
        )
    }

    let listener = match tokio::net::TcpListener::bind(metrics_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            warn!(%metrics_addr, %err, "failed to bind WireGuard shim metrics listener");
            return;
        }
    };
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
    {
        warn!(%metrics_addr, %err, "WireGuard shim metrics server failed");
    }
}
