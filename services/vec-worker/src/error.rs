//! Typed errors for the vector embeddings worker.
//!
//! `WorkerError` is the top-level error enum covering database, HTTP, configuration,
//! and validation failures. Each variant maps to a specific subsystem for precise
//! error handling and diagnostics.

use thiserror::Error;

/// Errors produced by the vector embeddings worker.
///
/// Each variant corresponds to a subsystem that may fail during operation:
/// - `Database`: PostgreSQL connection or query failure
/// - `Http`: Ollama HTTP request failure
/// - `DimensionMismatch`: Embedding vector dimension validation failure
/// - `Config`: Configuration loading or validation failure
/// - `TextBuild`: Text content building failure
#[derive(Debug, Error)]
pub enum WorkerError {
    /// Database connection or query error.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// HTTP request or response parsing error (Ollama client).
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// Embedding vector dimension mismatch (expected vs. received).
    #[error("dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },

    /// Configuration loading or validation error.
    #[error("config error: {0}")]
    Config(String),

    /// Text content or metadata building error.
    #[error("text build error: {0}")]
    TextBuild(String),

    /// Generic I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl WorkerError {
    /// Constructs a `Config` error from a message.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Constructs a `TextBuild` error from a message.
    pub fn text_build(msg: impl Into<String>) -> Self {
        Self::TextBuild(msg.into())
    }
}
