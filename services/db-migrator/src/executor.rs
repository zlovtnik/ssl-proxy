use std::fs;

use anyhow::Result;
use colored::Colorize;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use tokio_postgres::{Client, NoTls};

use crate::discovery::SqlFile;
use crate::error::{format_pg_error, ExecutionError};

#[derive(Debug, Default, Clone, Copy)]
pub struct ApplyReport {
    pub applied_files: usize,
    pub failed_files: usize,
}

pub fn print_dry_run(files: &[SqlFile]) -> Result<()> {
    for file in files {
        let sql = fs::read_to_string(&file.path)?;
        let preview = compact_preview(&sql, 120);
        println!("{} {}", file.relative_path().cyan(), preview);
    }
    Ok(())
}

pub async fn apply_sql_files(
    database_url: &str,
    files: &[SqlFile],
    verbose: bool,
    continue_on_error: bool,
) -> Result<ApplyReport, ExecutionError> {
    let mut client = connect_client(database_url).await?;
    let mut report = ApplyReport::default();

    let mut offset = 0;
    while offset < files.len() {
        let folder = files[offset].folder.clone();
        let mut next = offset + 1;
        while next < files.len() && files[next].folder == folder {
            next += 1;
        }
        let folder_files = &files[offset..next];
        apply_folder(
            &mut client,
            folder_files,
            verbose,
            continue_on_error,
            &mut report,
        )
        .await?;
        offset = next;
    }

    Ok(report)
}

async fn connect_client(database_url: &str) -> Result<Client, ExecutionError> {
    let use_tls = sslmode_requires_tls(database_url);

    if use_tls {
        let connector = TlsConnector::builder().build().map_err(|error| {
            ExecutionError::connection(format!("failed to build TLS connector: {error}"))
        })?;
        let tls = MakeTlsConnector::new(connector);
        let (client, connection) =
            tokio_postgres::connect(database_url, tls)
                .await
                .map_err(|error| {
                    ExecutionError::connection(format!("database connection failed: {error}"))
                })?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("{} {}", "error:".red().bold(), error);
            }
        });
        Ok(client)
    } else {
        let (client, connection) =
            tokio_postgres::connect(database_url, NoTls)
                .await
                .map_err(|error| {
                    ExecutionError::connection(format!("database connection failed: {error}"))
                })?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("{} {}", "error:".red().bold(), error);
            }
        });
        Ok(client)
    }
}

async fn apply_folder(
    client: &mut Client,
    files: &[SqlFile],
    verbose: bool,
    continue_on_error: bool,
    report: &mut ApplyReport,
) -> Result<(), ExecutionError> {
    if files.is_empty() {
        return Ok(());
    }

    let folder_name = files[0].folder.clone();
    let transaction = client.transaction().await.map_err(|error| {
        ExecutionError::apply(format!(
            "failed to start {folder_name} transaction: {error}"
        ))
    })?;

    for file in files {
        let relative_path = file.relative_path();
        let sql = match fs::read_to_string(&file.path) {
            Ok(sql) => sql,
            Err(error) => {
                report.failed_files += 1;
                eprintln!(
                    "{} {}: failed to read SQL file ({error})",
                    "error:".red().bold(),
                    relative_path
                );
                if !continue_on_error {
                    transaction.rollback().await.map_err(|rollback_error| {
                        ExecutionError::apply(format!(
                            "rollback failed after read error in {relative_path}: {rollback_error}"
                        ))
                    })?;
                    return Err(ExecutionError::apply(format!(
                        "aborted in folder '{}' after read error: {}",
                        folder_name, relative_path
                    )));
                }
                continue;
            }
        };

        if verbose {
            println!(
                "{} {}\n{}\n",
                "executing".blue().bold(),
                relative_path.blue(),
                sql
            );
        }

        if continue_on_error {
            transaction
                .batch_execute("SAVEPOINT db_migrator_file")
                .await
                .map_err(|error| {
                    ExecutionError::apply(format!(
                        "failed to create savepoint for {relative_path}: {error}"
                    ))
                })?;

            match transaction.batch_execute(&sql).await {
                Ok(_) => {
                    transaction
                        .batch_execute("RELEASE SAVEPOINT db_migrator_file")
                        .await
                        .map_err(|error| {
                            ExecutionError::apply(format!(
                                "failed to release savepoint for {relative_path}: {error}"
                            ))
                        })?;
                    report.applied_files += 1;
                    println!("{} {}", "✓".green().bold(), relative_path.green());
                }
                Err(error) => {
                    report.failed_files += 1;
                    eprintln!(
                        "{} {}",
                        "error:".red().bold(),
                        format_pg_error(&relative_path, &error)
                    );
                    transaction
                        .batch_execute("ROLLBACK TO SAVEPOINT db_migrator_file")
                        .await
                        .map_err(|rollback_error| {
                            ExecutionError::apply(format!(
                                "failed to rollback savepoint for {relative_path}: {rollback_error}"
                            ))
                        })?;
                    transaction
                        .batch_execute("RELEASE SAVEPOINT db_migrator_file")
                        .await
                        .map_err(|release_error| {
                            ExecutionError::apply(format!(
                                "failed to release savepoint after rollback for {relative_path}: {release_error}"
                            ))
                        })?;
                }
            }
        } else {
            match transaction.batch_execute(&sql).await {
                Ok(_) => {
                    report.applied_files += 1;
                    println!("{} {}", "✓".green().bold(), relative_path.green());
                }
                Err(error) => {
                    report.failed_files += 1;
                    let formatted = format_pg_error(&relative_path, &error);
                    eprintln!("{} {}", "error:".red().bold(), formatted);
                    transaction
                        .rollback()
                        .await
                        .map_err(|rollback_error| {
                            ExecutionError::apply(format!(
                                "rollback failed for folder '{}' after {relative_path}: {rollback_error}",
                                folder_name
                            ))
                        })?;
                    return Err(ExecutionError::apply(format!(
                        "aborted in folder '{}' after failure in {relative_path}",
                        folder_name
                    )));
                }
            }
        }
    }

    transaction.commit().await.map_err(|error| {
        ExecutionError::apply(format!("failed to commit folder '{folder_name}': {error}"))
    })?;
    Ok(())
}

fn compact_preview(sql: &str, width: usize) -> String {
    let collapsed = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= width {
        return collapsed;
    }
    let mut output = String::with_capacity(width + 3);
    for character in collapsed.chars().take(width) {
        output.push(character);
    }
    output.push_str("...");
    output
}

fn sslmode_requires_tls(database_url: &str) -> bool {
    let lowered = database_url.to_lowercase();
    let sslmode = if let Some(query_index) = lowered.find("sslmode=") {
        let mode_part = &lowered[query_index + "sslmode=".len()..];
        mode_part
            .split(['&', ' ', '\n', '\t'])
            .next()
            .unwrap_or("prefer")
    } else {
        "prefer"
    };
    matches!(sslmode, "require" | "verify-ca" | "verify-full")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_truncates_long_sql() {
        let preview = compact_preview("select 1 from some_table where column = 42", 12);
        assert_eq!(preview, "select 1 fro...");
    }

    #[test]
    fn sslmode_parsing_defaults_to_prefer() {
        assert!(!sslmode_requires_tls(
            "postgres://sync:sync@localhost:5432/sync"
        ));
        assert!(sslmode_requires_tls(
            "postgres://sync:sync@localhost:5432/sync?sslmode=require"
        ));
    }
}
