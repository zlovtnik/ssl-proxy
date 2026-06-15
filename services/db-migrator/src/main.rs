mod audit;
mod cli;
mod discovery;
mod error;
mod executor;
mod schema_control;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;

use crate::audit::validate_sql_files;
use crate::cli::{Cli, Commands};
use crate::discovery::discover_sql_files;
use crate::executor::{apply_sql_files, print_dry_run};

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

    let discovery = discover_sql_files(&sql_dir)
        .with_context(|| format!("failed to discover SQL files in {}", sql_dir.display()))?;
    for warning in &discovery.warnings {
        eprintln!("{} {}", "warning:".yellow(), warning);
    }

    match command {
        Commands::List => {
            for file in &discovery.files {
                println!("{}", file.relative_path());
            }
            Ok(EXIT_SUCCESS)
        }
        Commands::Validate => {
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
}
