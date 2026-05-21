//! Rust Vector Embedding Service — Main entry point.
//!
//! Parses CLI arguments, loads configuration from environment, initializes structured logging,
//! and orchestrates the worker loop with graceful shutdown handling.

use clap::Parser;
use tracing_subscriber::fmt;
use vec_worker::config::EmbeddingProvider;
use vec_worker::{Config, EmbeddingClient, LlamaCppClient, OllamaClient};
use vec_worker::db;

/// Command-line arguments for the vector embeddings worker.
#[derive(Parser, Debug)]
#[command(name = "vec-worker")]
#[command(about = "Rust Vector Embedding Service", long_about = None)]
struct Args {
    /// Run a single embedding job pass and exit (implies --dry-run behavior for testing).
    #[arg(long)]
    once: bool,

    /// Load config and log it, then exit without starting the worker loop.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize tracing subscriber with JSON formatting.
    // Respects `RUST_LOG` env var, defaults to `vec_worker=info,sqlx=warn` when unset.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("vec_worker=info,sqlx=warn"));

    let log_format = std::env::var("LOG_FORMAT").unwrap_or_default();
    let use_pretty = matches!(
        log_format.to_ascii_lowercase().as_str(),
        "text" | "pretty" | "human"
    );

    let subscriber = fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter);

    if use_pretty {
        subscriber.pretty().init();
    } else {
        subscriber.json().init();
    }

    tracing::debug!(?args, "cli arguments parsed");

    // Load configuration from environment.
    let mut config = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!("configuration error: {}", e);
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Apply CLI overrides.
    config.once = args.once;

    tracing::info!(
        worker_name = config.worker_name,
        model = config.model,
        dimensions = config.dimensions,
        enabled = config.embeddings_enabled,
        once = config.once,
        "worker starting"
    );

    // If --dry-run is set, log config and exit.
    if args.dry_run {
        let sanitized = config.sanitized();
        tracing::debug!(?sanitized, "dry-run mode: exiting");
        println!("Dry-run complete. Config:\n{sanitized:#?}");
        return;
    }

    // Connect to PostgreSQL.
    let pool = match db::connect(&config.database_url, config.effective_pool_max_connections()).await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("database connection failed: {}", e);
            eprintln!("Database connection failed: {}", e);
            std::process::exit(1);
        }
    };

    // Create the embedding client based on provider.
    let embedder = match config.provider {
        EmbeddingProvider::Ollama => {
            EmbeddingClient::Ollama(OllamaClient::new(&config.embed_url, &config.model))
        }
        EmbeddingProvider::LlamaCpp => {
            EmbeddingClient::LlamaCpp(LlamaCppClient::new(&config.embed_url, &config.model))
        }
    };

    // Run the worker loop.
    if let Err(e) = vec_worker::worker::run_forever(config, pool, embedder).await {
        tracing::error!("worker error: {}", e);
        eprintln!("Worker error: {}", e);
        std::process::exit(1);
    }
}
