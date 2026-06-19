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

    #[arg(
        long,
        global = true,
        default_value_t = 0,
        help = "Retry connection N times before failing (0 = no retry)"
    )]
    pub connect_retries: u32,

    #[arg(
        long,
        global = true,
        default_value_t = 2,
        help = "Base backoff seconds between connection retries"
    )]
    pub connect_retry_backoff: u64,

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
    /// Print tracked schema object status without applying SQL
    Status,
    /// Execute an explicit rollback script for a tracked object
    Rollback {
        #[arg(help = "object_name to roll back")]
        object: String,
    },
    /// Check schema readiness from schema_control.schema_ready
    Ready {
        #[arg(
            long,
            default_value_t = false,
            help = "Exit 0 only if all objects applied and none failed"
        )]
        strict: bool,
    },
}
