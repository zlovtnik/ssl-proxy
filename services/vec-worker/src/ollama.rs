//! Ollama HTTP client — pure async functions for embedding requests.
//!
//! # Design
//!
//! `OllamaClient` is a lightweight struct that holds the base URL, model name,
//! and a shared `reqwest::Client`. Functions that perform I/O take `&OllamaClient`
//! as a parameter and return `Result<_, WorkerError>`.
//!
//! # Pure helpers
//!
//! * [`validate_dimensions`] is a pure function that checks an embedding vector
//!   has the expected length, no IO required.

use crate::WorkerError;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Configuration and HTTP client for Ollama embedding requests.
///
/// Construct once at startup and share via `&OllamaClient`.
#[derive(Clone, Debug)]
pub struct OllamaClient {
    /// Base URL of the Ollama server, e.g. `"http://127.0.0.1:11434"`.
    pub base_url: String,
    /// Model name to use for embedding, e.g. `"nomic-embed-text"`.
    pub model: String,
    /// Shared HTTP client (constructed once, reused across requests).
    #[doc(hidden)]
    pub client: reqwest::Client,
}

impl OllamaClient {
    /// Create a new `OllamaClient`.
    ///
    /// The `reqwest::Client` is constructed with sensible defaults for a
    /// long-lived worker (timeouts, keep-alive, etc.).
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("reqwest::Client::builder should always succeed with default settings"),
        }
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// JSON body sent to `POST /api/embed`.
#[derive(Serialize)]
struct EmbedRequest {
    model: String,
    input: Vec<String>,
}

/// JSON body returned by `POST /api/embed`.
#[derive(Deserialize, Debug)]
struct EmbedResponse {
    /// One embedding vector per input text, in the same order.
    embeddings: Vec<Vec<f32>>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Send a batch of texts to Ollama and return their embedding vectors.
///
/// # Arguments
///
/// * `client` — The `OllamaClient` holding base URL, model, and HTTP client.
/// * `texts`  — One or more text strings to embed.
///
/// # Returns
///
/// A `Vec<Vec<f32>>` whose length matches `texts.len()`.  Each inner vector
/// has the embedding-model's native dimensionality (e.g. 768 for `nomic-embed-text`).
///
/// # Errors
///
/// * `WorkerError::Http` if the HTTP request or response parsing fails.
/// * `WorkerError::DimensionMismatch` if the response contains a different
///   number of embeddings than the number of input texts.
///
/// # Logging
///
/// * `DEBUG` — request start with model and input count
/// * `INFO`  — completion with elapsed milliseconds
/// * `DEBUG` — response embedding count
pub async fn embed_many(
    client: &OllamaClient,
    texts: &[String],
) -> Result<Vec<Vec<f32>>, WorkerError> {
    let url = format!("{}/api/embed", client.base_url);
    let input_count = texts.len();

    debug!(
        url = %url,
        model = %client.model,
        input_count = input_count,
        "embed_many request",
    );

    let body = EmbedRequest {
        model: client.model.clone(),
        input: texts.to_vec(),
    };

    let start = Instant::now();

    let response = client
        .client
        .post(&url)
        .json(&body)
        .send()
        .await?; // WorkerError::Http via `From` impl

    let elapsed_ms = start.elapsed().as_millis() as u64;
    info!(elapsed_ms, "embed_many completed");

    let embed_resp: EmbedResponse = response.json().await?; // WorkerError::Http

    let count = embed_resp.embeddings.len();
    debug!(embedding_count = count, "embed_many response");

    if count != input_count {
        return Err(WorkerError::DimensionMismatch {
            expected: input_count,
            actual: count,
        });
    }

    Ok(embed_resp.embeddings)
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Validate that an embedding vector has the expected number of dimensions.
///
/// This is a pure function with no IO.  Use it after receiving an embedding
/// from Ollama to assert the vector length matches the configured model
/// dimensions before storing the embedding.
///
/// # Errors
///
/// Returns `WorkerError::DimensionMismatch` when `vector.len() != expected`.
///
/// # Example
///
/// ```ignore
/// let embedding = vec![0.1, 0.2, 0.3];
/// validate_dimensions(&embedding, 768)?;
/// ```
pub fn validate_dimensions(vector: &[f32], expected: usize) -> Result<(), WorkerError> {
    let actual = vector.len();
    if actual != expected {
        return Err(WorkerError::DimensionMismatch { expected, actual });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_dimensions_ok() {
        let v = vec![0.1; 768];
        assert!(validate_dimensions(&v, 768).is_ok());
    }

    #[test]
    fn validate_dimensions_mismatch() {
        let v = vec![0.1; 512];
        let err = validate_dimensions(&v, 768).unwrap_err();
        match err {
            WorkerError::DimensionMismatch { expected, actual } => {
                assert_eq!(expected, 768);
                assert_eq!(actual, 512);
            }
            _ => panic!("expected DimensionMismatch"),
        }
    }

    #[test]
    fn validate_dimensions_empty() {
        let v: Vec<f32> = vec![];
        let err = validate_dimensions(&v, 768).unwrap_err();
        match err {
            WorkerError::DimensionMismatch { expected, actual } => {
                assert_eq!(expected, 768);
                assert_eq!(actual, 0);
            }
            _ => panic!("expected DimensionMismatch"),
        }
    }

    #[test]
    fn ollama_client_new_sets_fields() {
        let client = OllamaClient::new("http://localhost:11434", "nomic-embed-text");
        assert_eq!(client.base_url, "http://localhost:11434");
        assert_eq!(client.model, "nomic-embed-text");
    }
}