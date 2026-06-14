use std::fs;
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

use anyhow::Result;
use colored::Colorize;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use tokio_postgres::{Client, NoTls};

use crate::discovery::SqlFile;
use crate::error::{format_pg_error, ExecutionError, ExecutionErrorKind};
use crate::schema_control::{
    acquire_apply_lock, bootstrap, build_manifest, prepare_manifest, record_applied, record_failed,
    record_skipped, release_apply_lock, PreparedSchemaObject,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct ApplyReport {
    pub applied_files: usize,
    pub skipped_files: usize,
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
    let manifest = build_manifest(files)?;

    bootstrap(&client).await?;
    acquire_apply_lock(&client).await?;
    let result = apply_with_lock(&mut client, manifest, verbose, continue_on_error).await;
    let unlock_result = release_apply_lock(&client).await;

    match (result, unlock_result) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), Ok(())) => Err(error),
        (Ok(report), Err(error)) => {
            warn_unlock_error("after successful apply", &error);
            Ok(report)
        }
        (Err(error), Err(unlock_error)) => {
            warn_unlock_error("after failed apply", &unlock_error);
            Err(error)
        }
    }
}

fn warn_unlock_error(context: &str, error: &ExecutionError) {
    let detail = unlock_warning_detail(error);
    eprintln!(
        "{} schema apply {detail} {context}: {error}",
        "warning:".yellow()
    );
}

fn unlock_warning_detail(error: &ExecutionError) -> &'static str {
    match error.kind {
        ExecutionErrorKind::LockNotHeld => "lock was not held",
        _ => "unlock failed",
    }
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

async fn apply_with_lock(
    client: &mut Client,
    manifest: Vec<crate::schema_control::SchemaObject>,
    verbose: bool,
    continue_on_error: bool,
) -> Result<ApplyReport, ExecutionError> {
    let prepared = prepare_manifest(client, manifest).await?;
    let total = prepared.len();
    let mut report = ApplyReport::default();

    for (index, object) in prepared.iter().enumerate() {
        let position = index + 1;

        if !object.needs_apply {
            record_skipped(client, object).await?;
            report.skipped_files += 1;
            print_progress_line(
                skipped_message(position, total, &object.object.source_file),
                true,
            );
            continue;
        }

        if verbose {
            println!(
                "{} {}\n{}\n",
                "executing".blue().bold(),
                object.object.source_file.blue(),
                object.object.raw_sql
            );
        }

        print_progress_line(
            running_message(position, total, &object.object.source_file),
            false,
        );
        let started = Instant::now();

        match apply_one_file(client, object, started).await {
            Ok(duration) => {
                report.applied_files += 1;
                print_progress_line(
                    completed_message(position, total, &object.object.source_file, duration),
                    true,
                );
            }
            Err(error) => {
                report.failed_files += 1;
                print_progress_line(
                    failed_message(
                        position,
                        total,
                        &object.object.source_file,
                        started.elapsed(),
                    ),
                    true,
                );
                eprintln!("{} {}", "error:".red().bold(), error);
                if !continue_on_error {
                    return Err(ExecutionError::apply(format!(
                        "aborted after failure in {}",
                        object.object.source_file
                    )));
                }
            }
        }
    }

    Ok(report)
}

async fn apply_one_file(
    client: &mut Client,
    object: &PreparedSchemaObject,
    started: Instant,
) -> Result<Duration, ExecutionError> {
    if !object.object.transactional {
        return apply_one_file_without_transaction(client, object, started).await;
    }

    let transaction = client.transaction().await.map_err(|error| {
        ExecutionError::apply(format!(
            "failed to start transaction for {}: {error}",
            object.object.source_file
        ))
    })?;

    match transaction.batch_execute(&object.object.raw_sql).await {
        Ok(()) => {
            let duration = started.elapsed();
            record_applied(&transaction, object, duration).await?;
            transaction.commit().await.map_err(|error| {
                ExecutionError::apply(format!(
                    "failed to commit {}: {error}",
                    object.object.source_file
                ))
            })?;
            Ok(duration)
        }
        Err(error) => {
            let formatted = format_pg_error(&object.object.source_file, &error);
            transaction.rollback().await.map_err(|rollback_error| {
                ExecutionError::apply(format!(
                    "rollback failed after {}: {rollback_error}",
                    object.object.source_file
                ))
            })?;
            record_failed(client, object, &formatted, started.elapsed()).await?;
            Err(ExecutionError::apply(formatted))
        }
    }
}

async fn apply_one_file_without_transaction(
    client: &Client,
    object: &PreparedSchemaObject,
    started: Instant,
) -> Result<Duration, ExecutionError> {
    match client.batch_execute(&object.object.raw_sql).await {
        Ok(()) => {
            let duration = started.elapsed();
            record_applied(client, object, duration).await?;
            Ok(duration)
        }
        Err(error) => {
            let formatted = format_pg_error(&object.object.source_file, &error);
            record_failed(client, object, &formatted, started.elapsed()).await?;
            Err(ExecutionError::apply(formatted))
        }
    }
}

fn print_progress_line(message: impl std::fmt::Display, finalize: bool) {
    let is_terminal = io::stdout().is_terminal();
    let mut stdout = io::stdout().lock();

    if is_terminal {
        if finalize {
            let _ = writeln!(stdout, "\r{}\x1b[K", message);
        } else {
            let _ = write!(stdout, "\r{}\x1b[K", message);
        }
    } else {
        let _ = writeln!(stdout, "{message}");
    }

    let _ = stdout.flush();
}

fn running_message(index: usize, total: usize, source_file: &str) -> String {
    format!("[{index}/{total}] Running {source_file} ...")
}

fn completed_message(index: usize, total: usize, source_file: &str, duration: Duration) -> String {
    format!(
        "[{index}/{total}] ✓ {source_file} ({})",
        format_duration(duration)
    )
}

fn skipped_message(index: usize, total: usize, source_file: &str) -> String {
    format!("[{index}/{total}] ↷ {source_file} (unchanged)")
}

fn failed_message(index: usize, total: usize, source_file: &str, duration: Duration) -> String {
    format!(
        "[{index}/{total}] ✗ {source_file} ({})",
        format_duration(duration)
    )
}

fn format_duration(duration: Duration) -> String {
    format!("{:.1}s", duration.as_secs_f64())
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

    #[test]
    fn unlock_warning_detail_uses_lock_not_held_kind() {
        let error = ExecutionError::lock_not_held("schema apply lock was not held");

        assert_eq!(unlock_warning_detail(&error), "lock was not held");
    }

    #[test]
    fn unlock_warning_detail_does_not_infer_from_apply_message() {
        let error = ExecutionError::apply("schema apply lock was not held");

        assert_eq!(unlock_warning_detail(&error), "unlock failed");
    }

    #[test]
    fn format_duration_uses_one_decimal_second() {
        assert_eq!(format_duration(Duration::from_millis(47_234)), "47.2s");
    }

    #[test]
    fn completed_message_includes_counter_and_duration() {
        assert_eq!(
            completed_message(
                3,
                12,
                "sql/tables/vec_embedding_jobs.sql",
                Duration::from_millis(47_234),
            ),
            "[3/12] ✓ sql/tables/vec_embedding_jobs.sql (47.2s)"
        );
    }

    #[test]
    fn skipped_message_marks_unchanged_files() {
        assert_eq!(
            skipped_message(3, 12, "sql/tables/vec_embedding_jobs.sql"),
            "[3/12] ↷ sql/tables/vec_embedding_jobs.sql (unchanged)"
        );
    }
}
