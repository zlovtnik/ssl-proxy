use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "db-migrator",
    about = "Apply split Postgres SQL objects in deterministic order",
    version
)]
pub struct Cli {
    #[arg(long, global = true, help = "Postgres DSN (env: DATABASE_URL)")]
    pub database_url: Option<String>,

    #[arg(
        long,
        global = true,
        help = "Root of sql/ folder (env: SQL_DIR) [default: ./sql]"
    )]
    pub sql_dir: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        default_value_t = false,
        help = "Print SQL without executing"
    )]
    pub dry_run: bool,

    #[arg(
        long,
        global = true,
        default_value_t = false,
        help = "Echo each statement before running"
    )]
    pub verbose: bool,

    #[arg(
        long,
        global = true,
        default_value_t = false,
        help = "Continue processing after SQL errors"
    )]
    pub continue_on_error: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Apply all pending objects
    Apply,
    /// Check files parse as valid SQL and run idempotency heuristics (no DB required)
    Validate,
    /// Print discovered files in apply order
    List,
}
