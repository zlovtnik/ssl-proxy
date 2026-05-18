//! Rust Vector Embedding Service — Main entry point.
//!
//! Parses CLI arguments, loads configuration from environment, initializes structured logging,
//! and orchestrates the worker loop with graceful shutdown handling.

use clap::Parser;
use tracing_subscriber::fmt;
use vec_worker::{Config, OllamaClient};
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

    fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .json()
        .init();

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
        tracing::debug!(?config, "dry-run mode: exiting");
        println!("Dry-run complete. Config:");
        println!("  embeddings_enabled: {}", config.embeddings_enabled);
        println!("  ollama_url: {}", config.ollama_url);
        println!("  model: {}", config.model);
        println!("  dimensions: {}", config.dimensions);
        println!("  batch_size: {}", config.batch_size);
        println!("  request_batch_size: {}", config.request_batch_size);
        println!("  lease_seconds: {}", config.lease_seconds);
        println!("  worker_name: {}", config.worker_name);
        println!("  database_url: {}", config.database_url);
        println!("  poll_interval_secs: {}", config.poll_interval_secs);
        println!("  once: {}", config.once);
        return;
    }

    // Connect to PostgreSQL.
    let pool = match db::connect(&config.database_url).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("database connection failed: {}", e);
            eprintln!("Database connection failed: {}", e);
            std::process::exit(1);
        }
    };

    // Create the Ollama client.
    let ollama = OllamaClient::new(&config.ollama_url, &config.model);

    // Run the worker loop.
    if let Err(e) = vec_worker::worker::run_forever(config, pool, ollama).await {
        tracing::error!("worker error: {}", e);
        eprintln!("Worker error: {}", e);
        std::process::exit(1);
    }
}
