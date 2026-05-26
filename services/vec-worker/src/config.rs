//! Runtime configuration loaded from environment variables.
//!
//! Call `Config::from_env()` once at startup. All fields are validated before
//! `Ok` is returned; invalid configurations produce a `WorkerError` instead of panicking.

use crate::WorkerError;

/// The embedding provider backend.
#[derive(Clone, Debug, PartialEq)]
pub enum EmbeddingProvider {
    /// Ollama provider (`POST /api/embed`).
    Ollama,
    /// llama.cpp provider (`POST /v1/embeddings`, OpenAI-compatible).
    LlamaCpp,
}

impl EmbeddingProvider {
    /// Parse a provider name from its string representation.
    ///
    /// Accepts `"ollama"` or `"llamacpp"` (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ollama" => Some(Self::Ollama),
            "llamacpp" => Some(Self::LlamaCpp),
            _ => None,
        }
    }

    /// Return the string representation of this provider.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::LlamaCpp => "llamacpp",
        }
    }
}

/// Runtime configuration for the vector embeddings worker.
#[derive(Clone)]
pub struct Config {
    /// Whether vector embeddings are enabled.
    pub embeddings_enabled: bool,
    /// Embedding provider backend ("ollama" or "llamacpp").
    pub provider: EmbeddingProvider,
    /// Embedding provider URL (default: "http://127.0.0.1:11434").
    pub embed_url: String,
    /// Model name (required when embeddings_enabled=true).
    pub model: String,
    /// Expected embedding vector dimension (required when embeddings_enabled=true).
    pub dimensions: usize,
    /// Batch size for job leasing (default: 25).
    pub batch_size: usize,
    /// Request batch size for embedding requests (default: min(batch_size, 32)).
    pub request_batch_size: usize,
    /// Lease duration in seconds (default: 1800).
    pub lease_seconds: u64,
    /// Worker identifier for heartbeat (default: hostname).
    pub worker_name: String,
    /// PostgreSQL database URL for job leasing and upserting embeddings.
    pub database_url: String,
    /// Poll interval in seconds for job leasing loop (default: 5).
    pub poll_interval_secs: u64,
    /// Maximum number of concurrent `prepare_job` calls (text fetching is IO bound).
    /// Default: 8. Set to 1 for fully sequential behaviour.
    pub max_concurrent_prepares: usize,
    /// Maximum number of concurrent per-job completion transactions.
    /// Used only when bulk completion is unavailable. Default: 8.
    pub max_concurrent_completes: usize,
    /// Maximum number of in-flight embedding HTTP requests across chunks. Default: 1.
    pub max_concurrent_embed_requests: usize,
    /// Upper bound for `request_batch_size` when not explicitly set. Default: 64.
    pub request_batch_max: usize,
    /// Override for `PgPool` max connections; when unset, derived from concurrency knobs.
    pub database_pool_max_connections: Option<u32>,
    /// Run a single pass and exit (set by CLI `--once` flag).
    pub once: bool,
}

impl Config {
    /// Effective Postgres pool size: env override or `max(prepares, completes, embed) + 2`, floor 10.
    pub fn effective_pool_max_connections(&self) -> u32 {
        if let Some(n) = self.database_pool_max_connections {
            return n.max(1);
        }
        let derived = self
            .max_concurrent_prepares
            .max(self.max_concurrent_completes)
            .max(self.max_concurrent_embed_requests)
            .saturating_add(2);
        (derived.max(10)) as u32
    }

    /// Load and validate configuration from environment variables.
    ///
    /// Reads all vector embedding configuration from the environment:
    /// - `VECTOR_EMBEDDINGS_ENABLED` (bool, default false)
    /// - `VECTOR_EMBEDDING_PROVIDER` (string, must be "ollama" if set)
    /// - `VECTOR_EMBEDDING_URL` (string, default "http://127.0.0.1:11434")
    /// - `VECTOR_EMBEDDING_MODEL` (string, required if enabled)
    /// - `VECTOR_EMBEDDING_DIMENSIONS` (usize, required if enabled)
    /// - `VECTOR_EMBEDDING_BATCH_SIZE` (usize, default 64)
    /// - `VECTOR_EMBEDDING_REQUEST_BATCH_SIZE` (usize, default min(batch_size, VECTOR_EMBEDDING_REQUEST_BATCH_MAX))
    /// - `VECTOR_EMBEDDING_REQUEST_BATCH_MAX` (usize, default 128)
    /// - `VECTOR_EMBEDDING_LEASE_SECONDS` (u64, default 1800)
    /// - `VECTOR_EMBEDDING_WORKER_NAME` (string, default hostname)
    /// - `DATABASE_URL` or `SYNC_DATABASE_URL` (at least one required)
    /// - `POLL_INTERVAL_SECONDS` (u64, default 5)
    ///
    /// # Returns
    ///
    /// `Ok(Config)` with all fields populated on success, or `Err(WorkerError::Config(_))` on validation failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use vec_worker::Config;
    /// let cfg = Config::from_env()?;
    /// println!("Worker {} connecting to {}", cfg.worker_name, cfg.database_url);
    /// # Ok::<(), vec_worker::WorkerError>(())
    /// ```
    /// Returns a copy of this config with credential-bearing URLs redacted for logging.
    pub fn sanitized(&self) -> SanitizedConfig<'_> {
        SanitizedConfig { inner: self }
    }

    pub fn from_env() -> Result<Self, WorkerError> {
        let embeddings_enabled = read_bool("VECTOR_EMBEDDINGS_ENABLED", false)?;

        // Parse and validate provider if embeddings are enabled.
        let provider = if embeddings_enabled {
            let raw = std::env::var("VECTOR_EMBEDDING_PROVIDER")
                .unwrap_or_else(|_| "ollama".to_string());
            EmbeddingProvider::from_str(&raw).ok_or_else(|| {
                WorkerError::config(format!(
                    "VECTOR_EMBEDDING_PROVIDER must be 'ollama' or 'llamacpp', got '{}'",
                    raw
                ))
            })?
        } else {
            EmbeddingProvider::Ollama
        };

        // Default URL differs by provider:
        //   ollama  -> http://127.0.0.1:11434
        //   llamacpp -> http://127.0.0.1:8080
        let default_url = match provider {
            EmbeddingProvider::Ollama => "http://127.0.0.1:11434",
            EmbeddingProvider::LlamaCpp => "http://127.0.0.1:8080",
        };
        let embed_url = std::env::var("VECTOR_EMBEDDING_URL")
            .unwrap_or_else(|_| default_url.to_string());

        let model = std::env::var("VECTOR_EMBEDDING_MODEL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if embeddings_enabled {
                    "".to_string()
                } else {
                    "nomic-embed-text".to_string()
                }
            });

        if embeddings_enabled && model.is_empty() {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_MODEL is required when VECTOR_EMBEDDINGS_ENABLED=true",
            ));
        }

        let dimensions = match std::env::var("VECTOR_EMBEDDING_DIMENSIONS") {
            Ok(val) => val.parse::<usize>().map_err(|_| {
                WorkerError::config(format!(
                    "VECTOR_EMBEDDING_DIMENSIONS must be a valid usize, got '{}'",
                    val
                ))
            })?,
            Err(_) if embeddings_enabled => {
                return Err(WorkerError::config(
                    "VECTOR_EMBEDDING_DIMENSIONS is required when VECTOR_EMBEDDINGS_ENABLED=true",
                ))
            }
            Err(_) => 768,
        };
        if dimensions == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_DIMENSIONS must be >= 1",
            ));
        }

        let batch_size = read_usize("VECTOR_EMBEDDING_BATCH_SIZE", 64)?;
        if batch_size == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_BATCH_SIZE must be >= 1",
            ));
        }
        let request_batch_max = read_usize("VECTOR_EMBEDDING_REQUEST_BATCH_MAX", 128)?;
        if request_batch_max == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_REQUEST_BATCH_MAX must be >= 1",
            ));
        }
        let mut request_batch_size = read_usize(
            "VECTOR_EMBEDDING_REQUEST_BATCH_SIZE",
            batch_size.min(request_batch_max),
        )?;
        if request_batch_size == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_REQUEST_BATCH_SIZE must be >= 1",
            ));
        }
        request_batch_size = request_batch_size
            .min(batch_size.min(request_batch_max))
            .max(1);
        let lease_seconds = read_u64("VECTOR_EMBEDDING_LEASE_SECONDS", 1800)?;

        let worker_name = std::env::var("VECTOR_EMBEDDING_WORKER_NAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                hostname::get()
                    .ok()
                    .and_then(|hn| hn.into_string().ok())
                    .unwrap_or_else(|| "unknown-worker".to_string())
            });

        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::env::var("SYNC_DATABASE_URL")
                    .ok()
                    .filter(|s| !s.is_empty())
            })
            .ok_or_else(|| {
                WorkerError::config(
                    "DATABASE_URL or SYNC_DATABASE_URL is required",
                )
            })?;

        let poll_interval_secs = read_u64("POLL_INTERVAL_SECONDS", 5)?;
        let max_concurrent_prepares =
            read_usize("VECTOR_EMBEDDING_MAX_CONCURRENT_PREPARES", 8)?;
        if max_concurrent_prepares == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_MAX_CONCURRENT_PREPARES must be >= 1",
            ));
        }
        let max_concurrent_completes =
            read_usize("VECTOR_EMBEDDING_MAX_CONCURRENT_COMPLETES", 16)?;
        if max_concurrent_completes == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_MAX_CONCURRENT_COMPLETES must be >= 1",
            ));
        }
        let max_concurrent_embed_requests =
            read_usize("VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS", 4)?;
        if max_concurrent_embed_requests == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS must be >= 1",
            ));
        }
        let database_pool_max_connections = match std::env::var("DATABASE_POOL_MAX_CONNECTIONS") {
            Ok(v) => {
                let n: u32 = v.parse().map_err(|_| {
                    WorkerError::config(format!(
                        "DATABASE_POOL_MAX_CONNECTIONS must be a valid u32, got '{v}'"
                    ))
                })?;
                if n == 0 {
                    return Err(WorkerError::config(
                        "DATABASE_POOL_MAX_CONNECTIONS must be >= 1",
                    ));
                }
                Some(n)
            }
            Err(_) => None,
        };

        Ok(Self {
            embeddings_enabled,
            provider,
            embed_url,
            model,
            dimensions,
            batch_size,
            request_batch_size,
            lease_seconds,
            worker_name,
            database_url,
            poll_interval_secs,
            max_concurrent_prepares,
            max_concurrent_completes,
            max_concurrent_embed_requests,
            request_batch_max,
            database_pool_max_connections,
            once: false,
        })
    }
}

/// Config view with credential-bearing URLs redacted for safe logging.
pub struct SanitizedConfig<'a> {
    inner: &'a Config,
}

impl std::fmt::Debug for SanitizedConfig<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("embeddings_enabled", &self.inner.embeddings_enabled)
            .field("provider", &self.inner.provider)
            .field("embed_url", &redact_url(&self.inner.embed_url))
            .field("model", &self.inner.model)
            .field("dimensions", &self.inner.dimensions)
            .field("batch_size", &self.inner.batch_size)
            .field("request_batch_size", &self.inner.request_batch_size)
            .field("lease_seconds", &self.inner.lease_seconds)
            .field("worker_name", &self.inner.worker_name)
            .field("database_url", &redact_url(&self.inner.database_url))
            .field("poll_interval_secs", &self.inner.poll_interval_secs)
            .field("max_concurrent_prepares", &self.inner.max_concurrent_prepares)
            .field("max_concurrent_completes", &self.inner.max_concurrent_completes)
            .field(
                "max_concurrent_embed_requests",
                &self.inner.max_concurrent_embed_requests,
            )
            .field("request_batch_max", &self.inner.request_batch_max)
            .field(
                "database_pool_max_connections",
                &self.inner.effective_pool_max_connections(),
            )
            .field("once", &self.inner.once)
            .finish()
    }
}

fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    if let Some(at_pos) = rest.find('@') {
        format!("{}****{}", &url[..scheme_end + 3], &rest[at_pos..])
    } else {
        url.to_string()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("embeddings_enabled", &self.embeddings_enabled)
            .field("provider", &self.provider)
            .field("embed_url", &self.embed_url)
            .field("model", &self.model)
            .field("dimensions", &self.dimensions)
            .field("batch_size", &self.batch_size)
            .field("request_batch_size", &self.request_batch_size)
            .field("lease_seconds", &self.lease_seconds)
            .field("worker_name", &self.worker_name)
            .field("database_url", &"[redacted]")
            .field("poll_interval_secs", &self.poll_interval_secs)
            .field("max_concurrent_prepares", &self.max_concurrent_prepares)
            .field("max_concurrent_completes", &self.max_concurrent_completes)
            .field(
                "max_concurrent_embed_requests",
                &self.max_concurrent_embed_requests,
            )
            .field("request_batch_max", &self.request_batch_max)
            .field(
                "database_pool_max_connections",
                &self.effective_pool_max_connections(),
            )
            .field("once", &self.once)
            .finish()
    }
}

/// Read a boolean environment variable with a fallback default.
fn read_bool(var: &str, default: bool) -> Result<bool, WorkerError> {
    match std::env::var(var) {
        Ok(v) => match v.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(WorkerError::config(format!(
                "{var} must be a boolean, got '{v}'"
            ))),
        },
        Err(_) => Ok(default),
    }
}

/// Read a u64 environment variable with a fallback default.
fn read_u64(var: &str, default: u64) -> Result<u64, WorkerError> {
    match std::env::var(var) {
        Ok(v) => v.parse::<u64>().map_err(|_| {
            WorkerError::config(format!("{var} must be a valid u64, got '{v}'"))
        }),
        Err(_) => Ok(default),
    }
}

/// Read a usize environment variable with a fallback default.
fn read_usize(var: &str, default: usize) -> Result<usize, WorkerError> {
    match std::env::var(var) {
        Ok(v) => v.parse::<usize>().map_err(|_| {
            WorkerError::config(format!("{var} must be a valid usize, got '{v}'"))
        }),
        Err(_) => Ok(default),
    }
}

// A simple hostname fallback for systems that may not have the hostname crate
mod hostname {
    use libc;

    pub fn get() -> std::io::Result<std::ffi::OsString> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let mut buf = [0u8; 256];
            let result = unsafe {
                libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len())
            };
            if result == 0 {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                Ok(std::ffi::OsStr::from_bytes(&buf[..len]).to_os_string())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        #[cfg(not(unix))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "hostname not available on this platform",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    struct EnvGuard(Vec<(&'static str, Option<String>)>);

    impl EnvGuard {
        fn preserve(keys: &[&'static str]) -> Self {
            let values = keys
                .iter()
                .map(|&key| (key, env::var(key).ok()))
                .collect();
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
            "VECTOR_EMBEDDING_MAX_CONCURRENT_PREPARES",
            "VECTOR_EMBEDDING_MAX_CONCURRENT_COMPLETES",
            "VECTOR_EMBEDDING_MAX_CONCURRENT_EMBED_REQUESTS",
            "DATABASE_POOL_MAX_CONNECTIONS",
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
        assert_eq!(cfg.effective_pool_max_connections(), 18);

        drop(guard);
    }
}
