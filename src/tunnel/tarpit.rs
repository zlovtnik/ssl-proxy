//! Tarpit support for blocked CONNECT flows.
//!
//! The tarpit path keeps selected blocked connections open to suppress rapid
//! client retries. It does not decide whether a request should be tarpitted;
//! it only enforces the configured hold window.

use std::sync::Arc;
use std::time::Instant;

use hyper_util::rt::TokioIo;
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::state::SharedState;

/// Maximum time a single tarpit connection is held open.
pub(crate) const MAX_TARPIT_MS: u64 = 10_000;

/// Creates the process-wide tarpit semaphore.
///
/// The returned `Arc<Semaphore>` is initialized with `max_tarpit` permits and is intended
/// to limit the number of concurrent tarpit connections held by the process.
///
/// # Examples
///
/// ```
/// let sem = tarpit_semaphore(5);
/// assert_eq!(sem.available_permits(), 5);
/// ```
pub fn tarpit_semaphore(max_tarpit: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(max_tarpit))
}

/// Hold a blocked CONNECT stream open until the tarpit timeout elapses.
pub(crate) async fn run_tarpit(
    upgrade_fut: hyper::upgrade::OnUpgrade,
    host: String,
    state: SharedState,
) -> Option<u64> {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(MAX_TARPIT_MS);
    let upgraded = match tokio::time::timeout_at(deadline, upgrade_fut).await {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => {
            debug!(%host, %e, "tarpit upgrade failed");
            return None;
        }
        Err(_) => {
            debug!(%host, "tarpit upgrade timed out");
            return None;
        }
    };
    let start = Instant::now();
    let mut stream = TokioIo::new(upgraded);
    let _ = tokio::time::timeout_at(
        deadline,
        tokio::io::copy(&mut stream, &mut tokio::io::sink()),
    )
    .await;
    let held_ms = start.elapsed().as_millis() as u64;
    state.record_tarpit_held(&host, held_ms);
    info!(
        target: "audit",
        event = "tarpit_released",
        host = %host,
        held_ms,
        "tarpit connection released"
    );
    Some(held_ms)
}
