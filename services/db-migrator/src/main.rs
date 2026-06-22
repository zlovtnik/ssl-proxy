mod audit;
mod cli;
mod discovery;
mod error;
mod executor;
mod graph;
mod schema_control;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;

use crate::audit::validate_sql_files;
use crate::cli::{Cli, Commands};
use crate::discovery::{discover_sql_files, DiscoveryResult};
use crate::error::ExecutionError;
use crate::executor::{
    apply_sql_files, connect_client, print_dry_run, print_status_table, rollback_object,
};
use crate::schema_control::{check_ready, fetch_ready_status, fetch_status};

const EXIT_SUCCESS: u8 = 0;
const EXIT_PARTIAL_FAILURE: u8 = 1;
const EXIT_CONNECTION_FAILURE: u8 = 2;
const EXIT_NON_RETRYABLE_FAILURE: u8 = 3;

#[tokio::main]
async fn main() -> ExitCode {
    dotenv::dotenv().ok();

    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{} {}", "error:".red().bold(), error);
            ExitCode::from(EXIT_PARTIAL_FAILURE)
        }
    }
}

async fn run() -> Result<u8> {
    let cli = Cli::parse();
    let command = cli.command.clone().unwrap_or(Commands::Apply);
    let sql_dir = resolve_sql_dir(cli.sql_dir.clone());

    match command {
        Commands::List => {
            let discovery = discover_and_warn(&sql_dir)?;
            for file in &discovery.files {
                println!("{}", file.relative_path());
            }
            Ok(EXIT_SUCCESS)
        }
        Commands::Validate => {
            let discovery = discover_and_warn(&sql_dir)?;
            let report = validate_sql_files(&discovery.files);
            let has_errors = report.has_errors();
            for warning in &report.warnings {
                eprintln!("{} {}", "warning:".yellow(), warning);
            }
            for error in &report.errors {
                eprintln!("{} {}", "error:".red().bold(), error);
            }
            if has_errors {
                Ok(EXIT_PARTIAL_FAILURE)
            } else {
                Ok(EXIT_SUCCESS)
            }
        }
        Commands::Apply => {
            let discovery = discover_and_warn(&sql_dir)?;
            if cli.dry_run {
                print_dry_run(&discovery.files)?;
                return Ok(EXIT_SUCCESS);
            }

            let database_url = resolve_database_url(cli.database_url)
                .context("DATABASE_URL is required unless --dry-run is used")?;

            match apply_sql_files(
                &database_url,
                &discovery.files,
                cli.verbose,
                cli.continue_on_error,
                cli.connect_retries,
                cli.connect_retry_backoff,
            )
            .await
            {
                Ok(report) => {
                    if report.failed_files == 0 {
                        Ok(EXIT_SUCCESS)
                    } else {
                        Ok(EXIT_PARTIAL_FAILURE)
                    }
                }
                Err(error) if error.is_connection_failure() => {
                    eprintln!("{} {}", "error:".red().bold(), error);
                    Ok(EXIT_CONNECTION_FAILURE)
                }
                Err(error) if error.is_non_retryable_apply() => {
                    eprintln!("{} {}", "error:".red().bold(), error);
                    Ok(EXIT_NON_RETRYABLE_FAILURE)
                }
                Err(error) => {
                    eprintln!("{} {}", "error:".red().bold(), error);
                    Ok(EXIT_PARTIAL_FAILURE)
                }
            }
        }
        Commands::Status => {
            let database_url = resolve_database_url(cli.database_url)
                .context("DATABASE_URL is required for status")?;
            let result: std::result::Result<(), ExecutionError> = async {
                let client = connect_client(&database_url).await?;
                let statuses = fetch_status(&client).await?;
                let ready = fetch_ready_status(&client).await?;
                print_status_table(&statuses, &ready);
                Ok(())
            }
            .await;
            Ok(execution_result_to_exit_code(result))
        }
        Commands::Rollback { object } => {
            let database_url = resolve_database_url(cli.database_url)
                .context("DATABASE_URL is required for rollback")?;
            let result = rollback_object(&database_url, &sql_dir, &object).await;
            Ok(execution_result_to_exit_code(result))
        }
        Commands::Ready { strict } => {
            let database_url = resolve_database_url(cli.database_url)
                .context("DATABASE_URL is required for ready check")?;
            let result: std::result::Result<bool, ExecutionError> = async {
                let client = connect_client(&database_url).await?;
                check_ready(&client).await
            }
            .await;

            match result {
                Ok(true) => {
                    println!("schema ready");
                    Ok(EXIT_SUCCESS)
                }
                Ok(false) => {
                    eprintln!("schema not ready");
                    Ok(ready_false_exit_code(strict))
                }
                Err(error) => Ok(execution_result_to_exit_code(Err(error))),
            }
        }
    }
}

fn ready_false_exit_code(strict: bool) -> u8 {
    if strict {
        EXIT_PARTIAL_FAILURE
    } else {
        EXIT_SUCCESS
    }
}

fn discover_and_warn(sql_dir: &PathBuf) -> Result<DiscoveryResult> {
    let discovery = discover_sql_files(sql_dir)
        .with_context(|| format!("failed to discover SQL files in {}", sql_dir.display()))?;
    for warning in &discovery.warnings {
        eprintln!("{} {}", "warning:".yellow(), warning);
    }
    Ok(discovery)
}

fn execution_result_to_exit_code(result: std::result::Result<(), ExecutionError>) -> u8 {
    match result {
        Ok(()) => EXIT_SUCCESS,
        Err(error) if error.is_connection_failure() => {
            eprintln!("{} {}", "error:".red().bold(), error);
            EXIT_CONNECTION_FAILURE
        }
        Err(error) if error.is_non_retryable_apply() => {
            eprintln!("{} {}", "error:".red().bold(), error);
            EXIT_NON_RETRYABLE_FAILURE
        }
        Err(error) => {
            eprintln!("{} {}", "error:".red().bold(), error);
            EXIT_PARTIAL_FAILURE
        }
    }
}

fn resolve_database_url(cli_database_url: Option<String>) -> Option<String> {
    cli_database_url.or_else(|| std::env::var("DATABASE_URL").ok())
}

fn resolve_sql_dir(cli_sql_dir: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_sql_dir {
        return path;
    }
    if let Ok(path) = std::env::var("SQL_DIR") {
        return PathBuf::from(path);
    }
    PathBuf::from("./sql")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;

    #[test]
    fn cli_defaults_to_apply_when_command_is_absent() {
        let parsed = Cli::parse_from(["db-migrator"]);
        assert!(parsed.command.is_none());
    }

    #[test]
    fn resolve_sql_dir_prefers_cli_flag() {
        let dir = resolve_sql_dir(Some(PathBuf::from("/tmp/custom")));
        assert_eq!(dir, PathBuf::from("/tmp/custom"));
    }

    #[test]
    fn ready_false_is_success_unless_strict() {
        assert_eq!(ready_false_exit_code(false), EXIT_SUCCESS);
        assert_eq!(ready_false_exit_code(true), EXIT_PARTIAL_FAILURE);
    }
}
