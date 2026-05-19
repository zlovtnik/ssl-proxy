//! Rust Vector Embedding Service — Standalone worker for Ollama and llama.cpp embeddings.
//!
//! This library provides configuration, error handling, and core orchestration
//! for the vector embeddings worker. The binary entry point (`main.rs`) wires
//! these components together with CLI flags and tracing initialization.

pub mod config;
pub mod db;
pub mod embedder;
pub mod error;
pub mod llamacpp;
pub mod ollama;
pub mod text_builder;
pub mod worker;

pub use config::Config;
pub use embedder::EmbeddingClient;
pub use error::WorkerError;
pub use llamacpp::LlamaCppClient;
pub use ollama::OllamaClient;
