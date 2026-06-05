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
    /// Batch size for job leasing (default: 64).
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
    /// Maximum lease/process batches to drain before yielding to the outer loop.
    /// `0` means drain until no jobs are leased.
    pub max_drain_batches: usize,
    /// Timeout for short database lifecycle calls such as lease and worker state.
    pub db_call_timeout_seconds: u64,
    /// Maximum number of concurrent `prepare_job` calls (text fetching is IO bound).
    /// Default: 8. Set to 1 for fully sequential behaviour.
    pub max_concurrent_prepares: usize,
    /// Maximum number of concurrent per-job completion transactions.
    /// Used only when bulk completion is unavailable. Default: 8.
    pub max_concurrent_completes: usize,
    /// Primary embedding throughput knob: maximum in-flight embedding HTTP
    /// requests across chunks. Permits are intentionally held for the full
    /// provider round trip. Default: 4.
    pub max_concurrent_embed_requests: usize,
    /// Upper bound for `request_batch_size` when not explicitly set. Default: 64.
    pub request_batch_max: usize,
    /// Override for `PgPool` max connections; when unset, derived from concurrency knobs.
    pub database_pool_max_connections: Option<u32>,
    /// Minimum pre-warmed connections for the main worker pool (default: 1).
    pub database_pool_min_connections: u32,
    /// Connection pool size for the alert sweep pool (default: 4).
    pub alert_pool_max_connections: u32,
    /// Run a single pass and exit (set by CLI `--once` flag).
    pub once: bool,
    /// Maximum allowed tokens per input text sent to the embedding provider.
    /// Texts longer than `max_input_tokens * 4` characters are truncated at a line
    /// boundary.  Default: 512  (matches llama.cpp default `physical_batch`).
    /// Increase if your provider can handle longer individual inputs.
    pub max_input_tokens: usize,
}

impl Config {
    /// Effective Postgres pool size: env override or sum of concurrent activities + headroom, floor 10.
    ///
    /// Concurrent activities that each hold a connection simultaneously:
    ///   - complete fallback transactions:       max_concurrent_completes
    ///   - prepare batch queries (per-kind):     max_concurrent_prepares
    ///   - system: lease, state, reaper, count:  4
    /// Alert sweep is on a separate pool, not counted here.
    pub fn effective_pool_max_connections(&self) -> u32 {
        if let Some(n) = self.database_pool_max_connections {
            return n.max(1);
        }
        let derived = self
            .max_concurrent_completes
            .saturating_add(self.max_concurrent_prepares)
            .saturating_add(4); // lease + mark_worker_state + release_expired_leases + headroom
        (derived.max(10)) as u32
    }

    /// Effective Postgres pool prewarm size, clamped to the configured maximum.
    pub fn effective_pool_min_connections(&self) -> u32 {
        self.database_pool_min_connections
            .min(self.effective_pool_max_connections())
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
    /// - `VECTOR_EMBEDDING_MAX_DRAIN_BATCHES` (usize, default 0 = drain until empty)
    /// - `VECTOR_EMBEDDING_DB_CALL_TIMEOUT_SECONDS` (u64, default 30)
    /// - `DATABASE_POOL_MAX_CONNECTIONS` (u32, default derived from worker concurrency)
    /// - `DATABASE_POOL_MIN_CONNECTIONS` (u32, default 1)
    /// - `ALERT_POOL_MAX_CONNECTIONS` (u32, default 4)
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
            let raw =
                std::env::var("VECTOR_EMBEDDING_PROVIDER").unwrap_or_else(|_| "ollama".to_string());
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
        let embed_url =
            std::env::var("VECTOR_EMBEDDING_URL").unwrap_or_else(|_| default_url.to_string());

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

        let dimensions =
            match std::env::var("VECTOR_EMBEDDING_DIMENSIONS") {
                Ok(val) => val.parse::<usize>().map_err(|_| {
                    WorkerError::config(format!(
                        "VECTOR_EMBEDDING_DIMENSIONS must be a valid usize, got '{}'",
                        val
                    ))
                })?,
                Err(_) if embeddings_enabled => return Err(WorkerError::config(
                    "VECTOR_EMBEDDING_DIMENSIONS is required when VECTOR_EMBEDDINGS_ENABLED=true",
                )),
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
            .ok_or_else(|| WorkerError::config("DATABASE_URL or SYNC_DATABASE_URL is required"))?;

        let poll_interval_secs = read_u64("POLL_INTERVAL_SECONDS", 5)?;
        let max_drain_batches = read_usize("VECTOR_EMBEDDING_MAX_DRAIN_BATCHES", 0)?;
        let db_call_timeout_seconds = read_u64("VECTOR_EMBEDDING_DB_CALL_TIMEOUT_SECONDS", 30)?;
        if db_call_timeout_seconds == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_DB_CALL_TIMEOUT_SECONDS must be >= 1",
            ));
        }
        let max_concurrent_prepares = read_usize("VECTOR_EMBEDDING_MAX_CONCURRENT_PREPARES", 8)?;
        if max_concurrent_prepares == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_MAX_CONCURRENT_PREPARES must be >= 1",
            ));
        }
        let max_concurrent_completes = read_usize("VECTOR_EMBEDDING_MAX_CONCURRENT_COMPLETES", 16)?;
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
        let database_pool_min_connections = read_u32("DATABASE_POOL_MIN_CONNECTIONS", 1)?;

        let alert_pool_max_connections = match std::env::var("ALERT_POOL_MAX_CONNECTIONS") {
            Ok(v) => {
                let n: u32 = v.parse().map_err(|_| {
                    WorkerError::config(format!(
                        "ALERT_POOL_MAX_CONNECTIONS must be a valid u32, got '{v}'"
                    ))
                })?;
                if n == 0 {
                    return Err(WorkerError::config(format!(
                        "ALERT_POOL_MAX_CONNECTIONS must be >= 1, got '{n}'"
                    )));
                }
                n
            }
            Err(_) => 4,
        };

        let max_input_tokens = read_usize("VECTOR_EMBEDDING_MAX_INPUT_TOKENS", 512)?;
        if max_input_tokens == 0 {
            return Err(WorkerError::config(
                "VECTOR_EMBEDDING_MAX_INPUT_TOKENS must be >= 1",
            ));
        }

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
            max_drain_batches,
            db_call_timeout_seconds,
            max_concurrent_prepares,
            max_concurrent_completes,
            max_concurrent_embed_requests,
            request_batch_max,
            database_pool_max_connections,
            database_pool_min_connections,
            alert_pool_max_connections,
            once: false,
            max_input_tokens,
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
            .field("max_drain_batches", &self.inner.max_drain_batches)
            .field(
                "db_call_timeout_seconds",
                &self.inner.db_call_timeout_seconds,
            )
            .field(
                "max_concurrent_prepares",
                &self.inner.max_concurrent_prepares,
            )
            .field(
                "max_concurrent_completes",
                &self.inner.max_concurrent_completes,
            )
            .field(
                "max_concurrent_embed_requests",
                &self.inner.max_concurrent_embed_requests,
            )
            .field("request_batch_max", &self.inner.request_batch_max)
            .field(
                "database_pool_max_connections",
                &self.inner.database_pool_max_connections,
            )
            .field(
                "database_pool_min_connections",
                &self.inner.database_pool_min_connections,
            )
            .field(
                "effective_pool_min_connections",
                &self.inner.effective_pool_min_connections(),
            )
            .field(
                "alert_pool_max_connections",
                &self.inner.alert_pool_max_connections,
            )
            .field(
                "effective_pool_max_connections",
                &self.inner.effective_pool_max_connections(),
            )
            .field("once", &self.inner.once)
            .field("max_input_tokens", &self.inner.max_input_tokens)
            .finish()
    }
}
