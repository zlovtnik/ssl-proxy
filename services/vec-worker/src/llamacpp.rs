//! llama.cpp HTTP client — pure async functions for embedding requests.
//!
//! Communicates with a llama.cpp server via its OpenAI-compatible
//! `POST /v1/embeddings` endpoint.
//!
//! # Design
//!
//! `LlamaCppClient` is a lightweight struct that holds the base URL, model name,
//! and a shared `reqwest::Client`. Functions that perform I/O take `&LlamaCppClient`
//! as a parameter and return `Result<_, WorkerError>`.

use crate::WorkerError;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Configuration and HTTP client for llama.cpp embedding requests.
///
/// Construct once at startup and share via `&LlamaCppClient`.
#[derive(Clone, Debug)]
pub struct LlamaCppClient {
    /// Base URL of the llama.cpp server, e.g. `"http://127.0.0.1:8080"`.
    pub base_url: String,
    /// Model name to use for embedding, e.g. `"nomic-embed-text-v1.5"`.
    pub model: String,
    /// Shared HTTP client (constructed once, reused across requests).
    #[doc(hidden)]
    pub client: reqwest::Client,
}

impl LlamaCppClient {
    /// Create a new `LlamaCppClient`.
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

/// JSON body sent to `POST /v1/embeddings` (OpenAI-compatible API).
#[derive(Serialize)]
struct EmbedRequest {
    model: String,
    input: Vec<String>,
}

/// A single embedding datum in the OpenAI-compatible response.
#[derive(Deserialize, Debug)]
struct EmbeddingDatum {
    /// Positional index matching the input order.
    index: usize,
    /// The embedding vector.
    embedding: Vec<f32>,
}

/// JSON body returned by `POST /v1/embeddings`.
#[derive(Deserialize, Debug)]
struct EmbedResponse {
    /// One embedding datum per input text, in the same order.
    data: Vec<EmbeddingDatum>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Send a batch of texts to llama.cpp and return their embedding vectors.
///
/// # Arguments
///
/// * `client` — The `LlamaCppClient` holding base URL, model, and HTTP client.
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
/// * `WorkerError::ResponseCountMismatch` if the response contains a different
///   number of embeddings than the number of input texts.
///
/// # Logging
///
/// * `DEBUG` — request start with model and input count
/// * `INFO`  — completion with elapsed milliseconds
/// * `DEBUG` — response embedding count
pub async fn embed_many(
    client: &LlamaCppClient,
    texts: &[String],
) -> Result<Vec<Vec<f32>>, WorkerError> {
    let mut last_err = None;
    for attempt in 0..2 {
        if attempt > 0 {
            warn!("llamacpp embed_many retry after error, waiting 2 seconds");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        match try_embed_many(client, texts).await {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap())
}

/// Internal embed_many implementation without retry logic.
async fn try_embed_many(
    client: &LlamaCppClient,
    texts: &[String],
) -> Result<Vec<Vec<f32>>, WorkerError> {
    let url = format!("{}/v1/embeddings", client.base_url.trim_end_matches('/'));
    let input_count = texts.len();

    debug!(
        url = %url,
        model = %client.model,
        input_count = input_count,
        "llamacpp embed_many request",
    );

    let body = EmbedRequest {
        model: client.model.clone(),
        input: texts.to_vec(),
    };

    let start = Instant::now();

    let response = client.client.post(&url).json(&body).send().await?; // WorkerError::Http via `From` impl

    let elapsed_ms = start.elapsed().as_millis() as u64;
    info!(elapsed_ms, "llamacpp embed_many completed");

    let status = response.status();
    if !status.is_success() {
        error!(
            http_status = status.as_u16(),
            url = %url,
            model = %client.model,
            "embedding provider returned error status"
        );
        return Err(WorkerError::Http(response.error_for_status().unwrap_err()));
    }
    let embed_resp: EmbedResponse = response.json().await?; // WorkerError::Http

    let count = embed_resp.data.len();
    debug!(embedding_count = count, "llamacpp embed_many response");

    if count != input_count {
        return Err(WorkerError::ResponseCountMismatch {
            expected: input_count,
            actual: count,
        });
    }

    let mut seen = vec![false; input_count];
    for datum in &embed_resp.data {
        if datum.index >= input_count {
            return Err(WorkerError::EmbeddingIndex(format!(
                "embedding index {} is out of range for {} inputs",
                datum.index, input_count
            )));
        }
        if seen[datum.index] {
            return Err(WorkerError::EmbeddingIndex(format!(
                "duplicate embedding index {}",
                datum.index
            )));
        }
        seen[datum.index] = true;
    }
    if seen.iter().any(|present| !*present) {
        return Err(WorkerError::EmbeddingIndex(format!(
            "embedding response missing one or more indices in 0..{}",
            input_count
        )));
    }

    // Sort by index to ensure we return embeddings in input order
    // (llama.cpp may return them out of order).
    let mut sorted = embed_resp.data;
    sorted.sort_by_key(|d| d.index);

    let embeddings: Vec<Vec<f32>> = sorted.into_iter().map(|d| d.embedding).collect();

    Ok(embeddings)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llamacpp_client_new_sets_fields() {
        let client = LlamaCppClient::new("http://localhost:8080", "nomic-embed-text");
        assert_eq!(client.base_url, "http://localhost:8080");
        assert_eq!(client.model, "nomic-embed-text");
    }

    #[test]
    fn llamacpp_client_strips_trailing_slash() {
        let client = LlamaCppClient::new("http://localhost:8080/", "test-model");
        let url = format!("{}/v1/embeddings", client.base_url.trim_end_matches('/'));
        assert_eq!(url, "http://localhost:8080/v1/embeddings");
    }

    #[test]
    fn embed_response_deserialization() {
        let json = r#"{
            "data": [
                {"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]},
                {"object": "embedding", "index": 1, "embedding": [0.4, 0.5, 0.6]}
            ],
            "model": "nomic-embed-text",
            "usage": {"prompt_tokens": 10, "total_tokens": 10}
        }"#;

        let resp: EmbedResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0].index, 0);
        assert_eq!(resp.data[0].embedding, vec![0.1, 0.2, 0.3]);
        assert_eq!(resp.data[1].index, 1);
        assert_eq!(resp.data[1].embedding, vec![0.4, 0.5, 0.6]);
    }

    #[test]
    fn embed_response_sorts_by_index() {
        let json = r#"{
            "data": [
                {"object": "embedding", "index": 3, "embedding": [0.7, 0.8]},
                {"object": "embedding", "index": 0, "embedding": [0.1, 0.2]},
                {"object": "embedding", "index": 2, "embedding": [0.5, 0.6]},
                {"object": "embedding", "index": 1, "embedding": [0.3, 0.4]}
            ],
            "model": "test",
            "usage": {"prompt_tokens": 10, "total_tokens": 10}
        }"#;

        let resp: EmbedResponse = serde_json::from_str(json).unwrap();
        let mut sorted = resp.data;
        sorted.sort_by_key(|d| d.index);
        let embeddings: Vec<Vec<f32>> = sorted.into_iter().map(|d| d.embedding).collect();

        assert_eq!(embeddings[0], vec![0.1, 0.2]);
        assert_eq!(embeddings[1], vec![0.3, 0.4]);
        assert_eq!(embeddings[2], vec![0.5, 0.6]);
        assert_eq!(embeddings[3], vec![0.7, 0.8]);
    }
}
