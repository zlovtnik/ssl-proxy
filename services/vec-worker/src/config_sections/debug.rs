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
            .field("max_drain_batches", &self.max_drain_batches)
            .field("db_call_timeout_seconds", &self.db_call_timeout_seconds)
            .field("max_concurrent_prepares", &self.max_concurrent_prepares)
            .field("max_concurrent_completes", &self.max_concurrent_completes)
            .field(
                "max_concurrent_embed_requests",
                &self.max_concurrent_embed_requests,
            )
            .field("request_batch_max", &self.request_batch_max)
            .field(
                "database_pool_max_connections",
                &self.database_pool_max_connections,
            )
            .field(
                "database_pool_min_connections",
                &self.database_pool_min_connections,
            )
            .field(
                "effective_pool_min_connections",
                &self.effective_pool_min_connections(),
            )
            .field(
                "alert_pool_max_connections",
                &self.alert_pool_max_connections,
            )
            .field(
                "effective_pool_max_connections",
                &self.effective_pool_max_connections(),
            )
            .field("once", &self.once)
            .field("max_input_tokens", &self.max_input_tokens)
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
        Ok(v) => v
            .parse::<u64>()
            .map_err(|_| WorkerError::config(format!("{var} must be a valid u64, got '{v}'"))),
        Err(_) => Ok(default),
    }
}

/// Read a u32 environment variable with a fallback default.
fn read_u32(var: &str, default: u32) -> Result<u32, WorkerError> {
    match std::env::var(var) {
        Ok(v) => v
            .parse::<u32>()
            .map_err(|_| WorkerError::config(format!("{var} must be a valid u32, got '{v}'"))),
        Err(_) => Ok(default),
    }
}

/// Read a usize environment variable with a fallback default.
fn read_usize(var: &str, default: usize) -> Result<usize, WorkerError> {
    match std::env::var(var) {
        Ok(v) => v
            .parse::<usize>()
            .map_err(|_| WorkerError::config(format!("{var} must be a valid usize, got '{v}'"))),
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
            let result =
                unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
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
