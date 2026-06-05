
use super::*;
use std::env;

struct EnvGuard(Vec<(&'static str, Option<String>)>);

impl EnvGuard {
    fn preserve(keys: &[&'static str]) -> Self {
        let values = keys.iter().map(|&key| (key, env::var(key).ok())).collect();
        Self(values)
    }

    fn remove(&self, key: &'static str) {
        env::remove_var(key);
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.0.iter() {
            if let Some(value) = value {
                env::set_var(key, value);
            } else {
                env::remove_var(key);
            }
        }
    }
}

#[test]
fn config_default_values_are_expected() {
    let keys = [
        "VECTOR_EMBEDDINGS_ENABLED",
        "VECTOR_EMBEDDING_PROVIDER",
        "VECTOR_EMBEDDING_URL",
        "VECTOR_EMBEDDING_MODEL",
        "VECTOR_EMBEDDING_DIMENSIONS",
        "VECTOR_EMBEDDING_BATCH_SIZE",
        "VECTOR_EMBEDDING_REQUEST_BATCH_SIZE",
        "VECTOR_EMBEDDING_REQUEST_BATCH_MAX",
        "VECTOR_EMBEDDING_LEASE_SECONDS",
        "VECTOR_EMBEDDING_WORKER_NAME",
        "DATABASE_URL",
        "SYNC_DATABASE_URL",
        "POLL_INTERVAL_SECONDS",
        "VECTOR_EMBEDDING_MAX_DRAIN_BATCHES",
        "VECTOR_EMBEDDING_DB_CALL_TIMEOUT_SECONDS",
        "VECTOR_EMBEDDING_MAX_CONCURRENT_PREPARES",
        "VECTOR_EMBEDDING_MAX_CONCURRENT_COMPLETES",
        "VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS",
        "VECTOR_EMBEDDING_MAX_INPUT_TOKENS",
        "DATABASE_POOL_MAX_CONNECTIONS",
        "DATABASE_POOL_MIN_CONNECTIONS",
        "ALERT_POOL_MAX_CONNECTIONS",
    ];

    let guard = EnvGuard::preserve(&keys);
    for key in keys.iter() {
        guard.remove(key);
    }

    env::set_var("DATABASE_URL", "postgres://sync:sync@localhost:5432/sync");

    let cfg = Config::from_env().expect("default config should load");

    assert_eq!(cfg.batch_size, 64);
    assert_eq!(cfg.request_batch_max, 128);
    assert_eq!(cfg.request_batch_size, 64);
    assert_eq!(cfg.max_concurrent_completes, 16);
    assert_eq!(cfg.max_concurrent_embed_requests, 4);
    assert_eq!(cfg.poll_interval_secs, 5);
    assert_eq!(cfg.max_drain_batches, 0);
    assert_eq!(cfg.db_call_timeout_seconds, 30);
    assert_eq!(cfg.effective_pool_max_connections(), 28);
    assert_eq!(cfg.database_pool_min_connections, 1);
    assert_eq!(cfg.effective_pool_min_connections(), 1);

    drop(guard);
}
