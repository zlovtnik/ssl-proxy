//! Embedding client abstraction — dispatches between Ollama and llama.cpp providers.
//!
//! # Design
//!
//! `EmbeddingClient` is an enum over the two provider clients. Callers
//! construct the appropriate variant once at startup and then call
//! [`embed_many`] without caring which backend is in use.
//!
//! Dimension validation is delegated to [`crate::ollama::validate_dimensions`]
//! (which is provider-agnostic despite living in the `ollama` module).

use crate::llamacpp::LlamaCppClient;
use crate::ollama::{self, OllamaClient};
use crate::WorkerError;

/// Unified embedding client that dispatches to the configured provider.
///
/// Construct once (e.g. in `main`) and pass `&EmbeddingClient` through the
/// worker pipeline.  No trait objects, no async-trait — just a simple enum.
#[derive(Clone, Debug)]
pub enum EmbeddingClient {
    /// Ollama provider (`POST /api/embed`).
    Ollama(OllamaClient),
    /// llama.cpp provider (`POST /v1/embeddings`, OpenAI-compatible).
    LlamaCpp(LlamaCppClient),
}

impl EmbeddingClient {
    /// Embed a batch of texts using the configured provider.
    ///
    /// # Arguments
    ///
    /// * `texts` — One or more text strings to embed.
    ///
    /// # Returns
    ///
    /// A `Vec<Vec<f32>>` whose length matches `texts.len()`.  Each inner vector
    /// has the embedding-model's native dimensionality.
    ///
    /// # Errors
    ///
    /// Delegates to the underlying provider — see [`ollama::embed_many`] and
    /// [`crate::llamacpp::embed_many`].
    pub async fn embed_many(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, WorkerError> {
        match self {
            Self::Ollama(client) => ollama::embed_many(client, texts).await,
            Self::LlamaCpp(client) => crate::llamacpp::embed_many(client, texts).await,
        }
    }

    /// Validate that an embedding vector has the expected number of dimensions.
    ///
    /// This is provider-agnostic — delegates to [`ollama::validate_dimensions`].
    ///
    /// # Errors
    ///
    /// Returns `WorkerError::DimensionMismatch` when `vector.len() != expected`.
    pub fn validate_dimensions(&self, vector: &[f32], expected: usize) -> Result<(), WorkerError> {
        ollama::validate_dimensions(vector, expected)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding_client_validate_dimensions_ok() {
        let client = EmbeddingClient::Ollama(OllamaClient::new("http://localhost:11434", "test"));
        let v = vec![0.1; 768];
        assert!(client.validate_dimensions(&v, 768).is_ok());
    }

    #[test]
    fn embedding_client_validate_dimensions_mismatch() {
        let client =
            EmbeddingClient::LlamaCpp(LlamaCppClient::new("http://localhost:8080", "test"));
        let v = vec![0.1; 512];
        let err = client.validate_dimensions(&v, 768).unwrap_err();
        match err {
            WorkerError::DimensionMismatch { expected, actual } => {
                assert_eq!(expected, 768);
                assert_eq!(actual, 512);
            }
            _ => panic!("expected DimensionMismatch"),
        }
    }
}
