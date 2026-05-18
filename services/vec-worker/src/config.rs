//! Runtime configuration loaded from environment variables.
//!
//! Call `Config::from_env()` once at startup. All fields are validated before
//! `Ok` is returned; invalid configurations produce a `WorkerError` instead of panicking.

use crate::WorkerError;

/// Runtime configuration for the vector embeddings worker.
#[derive(Clone, Debug)]
pub struct Config {
    /// Whether vector embeddings are enabled.
    pub embeddings_enabled: bool,
    /// Ollama provider URL (default: "http://127.0.0.1:11434").
    pub ollama_url: String,
    /// Ollama model name (required when embeddings_enabled=true).
    pub model: String,
    /// Expected embedding vector dimension (required when embeddings_enabled=true).
    pub dimensions: usize,
    /// Batch size for job leasing (default: 25).
    pub batch_size: usize,
    /// Request batch size for Ollama (default: min(batch_size, 32)).
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
    /// Default: 4. Set to 1 for fully sequential behaviour.
    pub max_concurrent_prepares: usize,
    /// Run a single pass and exit (set by CLI `--once` flag).
    pub once: bool,
}

impl Config {
    /// Load and validate configuration from environment variables.
    ///
    /// Reads all vector embedding configuration from the environment:
    /// - `VECTOR_EMBEDDINGS_ENABLED` (bool, default false)
    /// - `VECTOR_EMBEDDING_PROVIDER` (string, must be "ollama" if set)
    /// - `VECTOR_EMBEDDING_URL` (string, default "http://127.0.0.1:11434")
    /// - `VECTOR_EMBEDDING_MODEL` (string, required if enabled)
    /// - `VECTOR_EMBEDDING_DIMENSIONS` (usize, required if enabled)
    /// - `VECTOR_EMBEDDING_BATCH_SIZE` (usize, default 25)
    /// - `VECTOR_EMBEDDING_REQUEST_BATCH_SIZE` (usize, default min(batch_size, 32))
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
    pub fn from_env() -> Result<Self, WorkerError> {
        let embeddings_enabled = read_bool("VECTOR_EMBEDDINGS_ENABLED", false);

        // Validate provider if embeddings are enabled
        if embeddings_enabled {
            let provider = std::env::var("VECTOR_EMBEDDING_PROVIDER")
                .unwrap_or_else(|_| "ollama".to_string());
            if provider != "ollama" {
                return Err(WorkerError::config(format!(
                    "VECTOR_EMBEDDING_PROVIDER must be 'ollama', got '{}'",
                    provider
                )));
            }
        }

        let ollama_url = std::env::var("VECTOR_EMBEDDING_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());

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

        let batch_size = read_usize("VECTOR_EMBEDDING_BATCH_SIZE", 25);
        let request_batch_size = read_usize(
            "VECTOR_EMBEDDING_REQUEST_BATCH_SIZE",
            batch_size.min(32),
        );
        let lease_seconds = read_u64("VECTOR_EMBEDDING_LEASE_SECONDS", 1800);

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

        let poll_interval_secs = read_u64("POLL_INTERVAL_SECONDS", 5);
        let max_concurrent_prepares = read_usize("VECTOR_EMBEDDING_MAX_CONCURRENT_PREPARES", 4);

        Ok(Self {
            embeddings_enabled,
            ollama_url,
            model,
            dimensions,
            batch_size,
            request_batch_size,
            lease_seconds,
            worker_name,
            database_url,
            poll_interval_secs,
            max_concurrent_prepares,
            once: false,
        })
    }
}

/// Read a boolean environment variable with a fallback default.
fn read_bool(var: &str, default: bool) -> bool {
    std::env::var(var)
        .map(|v| match v.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => default,
        })
        .unwrap_or(default)
}

/// Read a u64 environment variable with a fallback default.
fn read_u64(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Read a usize environment variable with a fallback default.
fn read_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

// A simple hostname fallback for systems that may not have the hostname crate
mod hostname {
    pub fn get() -> std::io::Result<std::ffi::OsString> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let mut buf = [0u8; 256];
            let result = unsafe {
                libc::gethostname(buf.as_mut_ptr() as *mut i8, buf.len())
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
