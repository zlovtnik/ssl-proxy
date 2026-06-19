use std::collections::BTreeMap;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use colored::Colorize;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_postgres::{Client, NoTls};

use crate::discovery::SqlFile;
use crate::error::{format_pg_error, ExecutionError, ExecutionErrorKind};
use crate::graph::topological_sort;
use crate::schema_control::{
    acquire_apply_lock, bootstrap, build_manifest, fetch_rollback_target, prepare_manifest,
    record_applied, record_failed, record_rolled_back, record_skipped, release_apply_lock,
    ObjectStatus, PreparedSchemaObject, SchemaReadyStatus,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct ApplyReport {
    pub applied_files: usize,
    pub skipped_files: usize,
    pub failed_files: usize,
}

const PROGRESS_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
const PROGRESS_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const LIVE_PROGRESS_WIDTH: usize = 360;

pub fn print_dry_run(files: &[SqlFile]) -> Result<()> {
    for file in files {
        let sql = fs::read_to_string(&file.path)?;
        let preview = compact_preview(&sql, 120);
        println!("{} {}", file.relative_path().cyan(), preview);
    }
    Ok(())
}

pub fn print_status_table(statuses: &[ObjectStatus], ready: &SchemaReadyStatus) {
    if statuses.is_empty() {
        println!("No schema objects tracked.");
        print_ready_summary(ready);
        return;
    }

    println!(
        "{:<18} {:<44} {:<10} {:<19} {:<12} SOURCE",
        "KIND", "OBJECT", "STATUS", "APPLIED_AT", "SHA256"
    );
    for status in statuses {
        let status_text = format!("{:<10}", status.apply_status);
        println!(
            "{:<18} {:<44} {} {:<19} {:<12} {}",
            truncate_chars(&status.kind, 18),
            truncate_chars(&status.object_name, 44),
            color_status(&status.apply_status, &status_text),
            status.applied_at.as_deref().unwrap_or("-"),
            short_sha(&status.content_sha256),
            status.source_file
        );
        if let Some(last_error) = status.last_error.as_deref() {
            println!("  error: {}", truncate_chars(last_error, 140).red());
        }
    }

    print_ready_summary(ready);
}

pub async fn apply_sql_files(
    database_url: &str,
    files: &[SqlFile],
    verbose: bool,
    continue_on_error: bool,
    connect_retries: u32,
    connect_retry_backoff: u64,
) -> Result<ApplyReport, ExecutionError> {
    let mut client =
        connect_with_retry(database_url, connect_retries, connect_retry_backoff).await?;
    let manifest = topological_sort(build_manifest(files)?)?;

    bootstrap(&client).await?;
    acquire_apply_lock(&client).await?;
    let result = apply_with_lock(
        &mut client,
        database_url,
        manifest,
        verbose,
        continue_on_error,
    )
    .await;
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

pub async fn rollback_object(
    database_url: &str,
    sql_dir: &Path,
    object_name: &str,
) -> Result<(), ExecutionError> {
    let mut client = connect_client(database_url).await?;

    bootstrap(&client).await?;
    acquire_apply_lock(&client).await?;
    let result = rollback_with_lock(&mut client, sql_dir, object_name).await;
    let unlock_result = release_apply_lock(&client).await;

    match (result, unlock_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => {
            warn_unlock_error("after successful rollback", &error);
            Ok(())
        }
        (Err(error), Err(unlock_error)) => {
            warn_unlock_error("after failed rollback", &unlock_error);
            Err(error)
        }
    }
}

async fn rollback_with_lock(
    client: &mut Client,
    sql_dir: &Path,
    object_name: &str,
) -> Result<(), ExecutionError> {
    let target = fetch_rollback_target(client, object_name).await?;
    let rollback_path = resolve_rollback_path(sql_dir, &target.rollback_file).ok_or_else(|| {
        ExecutionError::apply(format!(
            "{} declares rollback file '{}' but it was not found",
            target.object_name, target.rollback_file
        ))
    })?;
    let rollback_sql = fs::read_to_string(&rollback_path).map_err(|error| {
        ExecutionError::apply(format!(
            "{}: failed to read rollback SQL ({error})",
            rollback_path.display()
        ))
    })?;
    if rollback_sql.trim().is_empty() {
        return Err(ExecutionError::apply(format!(
            "{}: rollback SQL file is empty",
            rollback_path.display()
        )));
    }

    let started = Instant::now();
    let transaction = client.transaction().await.map_err(|error| {
        ExecutionError::apply(format!(
            "failed to start rollback transaction for {}:{}: {error}",
            target.kind, target.object_name
        ))
    })?;

    match transaction.batch_execute(&rollback_sql).await {
        Ok(()) => {
            record_rolled_back(&transaction, &target, started.elapsed()).await?;
            transaction.commit().await.map_err(|error| {
                ExecutionError::apply(format!(
                    "failed to commit rollback for {}:{}: {error}",
                    target.kind, target.object_name
                ))
            })?;
            println!(
                "{} {}:{} via {} ({})",
                "rolled back".green().bold(),
                target.kind,
                target.object_name,
                rollback_path.display(),
                format_duration(started.elapsed())
            );
            Ok(())
        }
        Err(error) => {
            let formatted = format_pg_error(&rollback_path.display().to_string(), &error);
            transaction.rollback().await.map_err(|rollback_error| {
                ExecutionError::apply(format!(
                    "rollback transaction cleanup failed after {}:{}: {rollback_error}",
                    target.kind, target.object_name
                ))
            })?;
            Err(ExecutionError::apply(formatted))
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

pub async fn connect_client(database_url: &str) -> Result<Client, ExecutionError> {
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

async fn connect_with_retry(
    database_url: &str,
    retries: u32,
    backoff_secs: u64,
) -> Result<Client, ExecutionError> {
    let mut retries_used = 0;
    loop {
        match connect_client(database_url).await {
            Ok(client) => return Ok(client),
            Err(error) if error.is_connection_failure() && retries_used < retries => {
                let delay = retry_backoff_duration(backoff_secs, retries_used);
                eprintln!(
                    "{} connection attempt {}/{} failed, retrying in {}: {error}",
                    "warning:".yellow(),
                    retries_used + 1,
                    retries + 1,
                    format_duration(delay)
                );
                time::sleep(delay).await;
                retries_used += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

fn retry_backoff_duration(backoff_secs: u64, retries_used: u32) -> Duration {
    let multiplier = 1u64.checked_shl(retries_used).unwrap_or(u64::MAX);
    Duration::from_secs(backoff_secs.saturating_mul(multiplier))
}

async fn read_backend_pid(client: &Client) -> Result<i32, ExecutionError> {
    let row = client
        .query_one("select pg_backend_pid()", &[])
        .await
        .map_err(|error| ExecutionError::apply(format!("failed to read backend pid: {error}")))?;
    Ok(row.get(0))
}

async fn apply_with_lock(
    client: &mut Client,
    database_url: &str,
    manifest: Vec<crate::schema_control::SchemaObject>,
    verbose: bool,
    continue_on_error: bool,
) -> Result<ApplyReport, ExecutionError> {
    let prepared = prepare_manifest(client, manifest).await?;
    let backend_pid = read_backend_pid(client).await?;
    let total = prepared.len();
    let mut report = ApplyReport::default();
    let mut non_retryable_error: Option<ExecutionError> = None;

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

        match apply_one_file(
            client,
            object,
            position,
            total,
            database_url,
            backend_pid,
            started,
        )
        .await
        {
            Ok(duration) => {
                report.applied_files += 1;
                print_progress_line(
                    completed_message(position, total, &object.object.source_file, duration),
                    true,
                );
            }
            Err(error) => {
                let is_non_retryable = error.is_non_retryable_apply();
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
                if is_non_retryable {
                    if !continue_on_error {
                        return Err(error);
                    }
                    if non_retryable_error.is_none() {
                        non_retryable_error = Some(error);
                    }
                    continue;
                }
                if !continue_on_error {
                    return Err(ExecutionError::apply(format!(
                        "aborted after failure in {}",
                        object.object.source_file
                    )));
                }
            }
        }
    }

    if let Some(error) = non_retryable_error {
        return Err(error);
    }

    Ok(report)
}

async fn apply_one_file(
    client: &mut Client,
    object: &PreparedSchemaObject,
    index: usize,
    total: usize,
    database_url: &str,
    backend_pid: i32,
    started: Instant,
) -> Result<Duration, ExecutionError> {
    if !object.object.transactional {
        return apply_one_file_without_transaction(
            client,
            object,
            index,
            total,
            database_url,
            backend_pid,
            started,
        )
        .await;
    }

    let transaction = client.transaction().await.map_err(|error| {
        ExecutionError::apply(format!(
            "failed to start transaction for {}: {error}",
            object.object.source_file
        ))
    })?;

    let progress_monitor =
        ActiveProgressMonitor::start(database_url, backend_pid, object, index, total, started);

    match transaction.batch_execute(&object.object.raw_sql).await {
        Ok(()) => {
            progress_monitor.finish().await;
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
            progress_monitor.finish().await;
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
    index: usize,
    total: usize,
    database_url: &str,
    backend_pid: i32,
    started: Instant,
) -> Result<Duration, ExecutionError> {
    let progress_monitor =
        ActiveProgressMonitor::start(database_url, backend_pid, object, index, total, started);

    match client.batch_execute(&object.object.raw_sql).await {
        Ok(()) => {
            progress_monitor.finish().await;
            let duration = started.elapsed();
            if let Err(error) = record_applied(client, object, duration).await {
                return Err(ExecutionError::non_retryable_apply(format!(
                    "{}: applied SQL but failed to record migration state (non-retriable): {error}",
                    object.object.source_file
                )));
            }
            Ok(duration)
        }
        Err(error) => {
            progress_monitor.finish().await;
            let formatted = format_pg_error(&object.object.source_file, &error);
            record_failed(client, object, &formatted, started.elapsed()).await?;
            Err(ExecutionError::apply(formatted))
        }
    }
}

#[derive(Debug, Clone)]
struct ProgressContext {
    index: usize,
    total: usize,
    kind: String,
    object_name: String,
    source_file: String,
    rewrite_probe_expected: bool,
}

impl ProgressContext {
    fn new(index: usize, total: usize, object: &PreparedSchemaObject) -> Self {
        Self {
            index,
            total,
            kind: object.object.kind.clone(),
            object_name: object.object.object_name.clone(),
            source_file: object.object.source_file.clone(),
            rewrite_probe_expected: sql_may_rewrite_table(&object.object.raw_sql),
        }
    }
}

struct ActiveProgressMonitor {
    stop_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl ActiveProgressMonitor {
    fn start(
        database_url: &str,
        backend_pid: i32,
        object: &PreparedSchemaObject,
        index: usize,
        total: usize,
        started: Instant,
    ) -> Self {
        let context = ProgressContext::new(index, total, object);
        let database_url = database_url.to_string();
        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            monitor_object_progress(database_url, backend_pid, context, started, stop_rx).await;
        });

        Self { stop_tx, handle }
    }

    async fn finish(self) {
        let _ = self.stop_tx.send(true);
        let mut handle = self.handle;
        tokio::select! {
            result = &mut handle => {
                if let Err(error) = result {
                    eprintln!(
                        "{} migration progress monitor task failed: {error}",
                        "warning:".yellow()
                    );
                }
            }
            _ = time::sleep(PROGRESS_SHUTDOWN_TIMEOUT) => {
                handle.abort();
                eprintln!(
                    "{} migration progress monitor did not stop within {}; aborting monitor only",
                    "warning:".yellow(),
                    format_duration(PROGRESS_SHUTDOWN_TIMEOUT)
                );
            }
        }
    }
}

async fn monitor_object_progress(
    database_url: String,
    backend_pid: i32,
    context: ProgressContext,
    started: Instant,
    mut stop_rx: watch::Receiver<bool>,
) {
    tokio::select! {
        changed = stop_rx.changed() => {
            if changed.is_err() || *stop_rx.borrow() {
                return;
            }
        }
        _ = time::sleep(PROGRESS_SAMPLE_INTERVAL) => {}
    }
    if *stop_rx.borrow() {
        return;
    }

    let client = match connect_client(&database_url).await {
        Ok(client) => client,
        Err(error) => {
            eprintln!(
                "{} progress details unavailable for {}: {error}",
                "warning:".yellow(),
                context.source_file
            );
            return;
        }
    };
    let mut sampler = ProgressSampler::default();

    loop {
        if *stop_rx.borrow() {
            break;
        }

        let sample = sampler.sample(&client, backend_pid).await;
        print_progress_line(live_progress_message(&context, started, &sample), false);

        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
            }
            _ = time::sleep(PROGRESS_SAMPLE_INTERVAL) => {}
        }
    }
}

#[derive(Debug, Default)]
struct ProgressSampler {
    rewrite_tracker: RewriteFileTracker,
    reported_exact_progress_error: bool,
    reported_activity_error: bool,
    reported_lock_error: bool,
    reported_filesystem_error: bool,
}

impl ProgressSampler {
    async fn sample(&mut self, client: &Client, backend_pid: i32) -> ProgressSample {
        let mut warnings = Vec::new();
        let exact = self
            .sample_exact_progress(client, backend_pid, &mut warnings)
            .await;
        let activity = self
            .sample_activity(client, backend_pid, &mut warnings)
            .await;
        let locks = self
            .sample_relation_locks(client, backend_pid, &mut warnings)
            .await;
        let rewrite = if exact.is_none() {
            self.sample_rewrite_file_progress(client, &locks, &mut warnings)
                .await
        } else {
            None
        };

        ProgressSample {
            exact,
            activity,
            locks,
            rewrite,
            warnings,
        }
    }

    async fn sample_exact_progress(
        &mut self,
        client: &Client,
        backend_pid: i32,
        warnings: &mut Vec<String>,
    ) -> Option<ExactProgress> {
        match read_exact_progress(client, backend_pid).await {
            Ok(progress) => progress,
            Err(error) => {
                if !self.reported_exact_progress_error {
                    warnings.push(format!(
                        "native progress views unavailable: {}",
                        compact_error(&error)
                    ));
                    self.reported_exact_progress_error = true;
                }
                None
            }
        }
    }

    async fn sample_activity(
        &mut self,
        client: &Client,
        backend_pid: i32,
        warnings: &mut Vec<String>,
    ) -> Option<ActivitySample> {
        match read_activity(client, backend_pid).await {
            Ok(activity) => activity,
            Err(error) => {
                if !self.reported_activity_error {
                    warnings.push(format!(
                        "pg_stat_activity unavailable: {}",
                        compact_error(&error)
                    ));
                    self.reported_activity_error = true;
                }
                None
            }
        }
    }

    async fn sample_relation_locks(
        &mut self,
        client: &Client,
        backend_pid: i32,
        warnings: &mut Vec<String>,
    ) -> Vec<RelationLockSample> {
        match read_relation_locks(client, backend_pid).await {
            Ok(locks) => locks,
            Err(error) => {
                if !self.reported_lock_error {
                    warnings.push(format!("pg_locks unavailable: {}", compact_error(&error)));
                    self.reported_lock_error = true;
                }
                Vec::new()
            }
        }
    }

    async fn sample_rewrite_file_progress(
        &mut self,
        client: &Client,
        locks: &[RelationLockSample],
        warnings: &mut Vec<String>,
    ) -> Option<RewriteFileEstimate> {
        match self.rewrite_tracker.sample(client, locks).await {
            Ok(estimate) => estimate,
            Err(error) => {
                if !self.reported_filesystem_error {
                    warnings.push(error);
                    self.reported_filesystem_error = true;
                }
                None
            }
        }
    }
}

#[derive(Debug, Default)]
struct ProgressSample {
    exact: Option<ExactProgress>,
    activity: Option<ActivitySample>,
    locks: Vec<RelationLockSample>,
    rewrite: Option<RewriteFileEstimate>,
    warnings: Vec<String>,
}

impl ProgressSample {
    fn has_access_exclusive_lock(&self) -> bool {
        self.locks
            .iter()
            .any(|lock| lock.granted && lock.mode == "AccessExclusiveLock")
    }

    fn primary_lock(&self) -> Option<&RelationLockSample> {
        self.locks
            .iter()
            .find(|lock| lock.granted && lock.mode == "AccessExclusiveLock")
            .or_else(|| self.locks.iter().find(|lock| lock.granted))
            .or_else(|| self.locks.first())
    }
}

#[derive(Debug, Clone)]
struct ExactProgress {
    command: String,
    phase: String,
    relation_name: Option<String>,
    index_name: Option<String>,
    percent: Option<f64>,
    blocks_done: Option<i64>,
    blocks_total: Option<i64>,
    tuples_done: Option<i64>,
    tuples_total: Option<i64>,
    lockers_done: Option<i64>,
    lockers_total: Option<i64>,
    bytes_done: Option<i64>,
    bytes_total: Option<i64>,
}

#[derive(Debug, Clone)]
struct ActivitySample {
    state: String,
    wait_event_type: Option<String>,
    wait_event: Option<String>,
    query_age_seconds: Option<f64>,
}

#[derive(Debug, Clone)]
struct RelationLockSample {
    relation: String,
    relkind: Option<String>,
    mode: String,
    granted: bool,
    relation_bytes: Option<i64>,
    total_bytes: Option<i64>,
    path: Option<String>,
    relfilenode: Option<String>,
}

#[derive(Debug, Clone)]
struct RewriteFileEstimate {
    directory: String,
    relfilenode: String,
    bytes_written: i64,
    source_relation_bytes: i64,
    percent: f64,
}

#[derive(Debug, Default)]
struct RewriteFileTracker {
    previous_sizes: BTreeMap<String, i64>,
    last_estimate: Option<RewriteFileEstimate>,
}

impl RewriteFileTracker {
    async fn sample(
        &mut self,
        client: &Client,
        locks: &[RelationLockSample],
    ) -> Result<Option<RewriteFileEstimate>, String> {
        let Some(relation) = rewrite_relation_candidate(locks) else {
            return Ok(self.last_estimate.clone());
        };
        let Some(path) = relation.path.as_deref() else {
            return Ok(self.last_estimate.clone());
        };
        let Some(directory) = relation_storage_dir(path) else {
            return Ok(self.last_estimate.clone());
        };
        let Some(source_relation_bytes) = relation.relation_bytes.filter(|bytes| *bytes > 0) else {
            return Ok(self.last_estimate.clone());
        };

        let groups = read_relation_file_groups(client, directory)
            .await
            .map_err(|error| format!("server file probe unavailable: {}", compact_error(&error)))?;
        let excluded_relfilenode = relation.relfilenode.as_deref();
        let mut best_growth: Option<(FileGroupSample, i64)> = None;

        for group in &groups {
            if Some(group.relfilenode.as_str()) == excluded_relfilenode {
                continue;
            }
            let key = format!("{directory}/{}", group.relfilenode);
            if let Some(previous_bytes) = self.previous_sizes.get(&key) {
                let growth = group.bytes - *previous_bytes;
                if growth > 0
                    && best_growth
                        .as_ref()
                        .is_none_or(|(_best, best_growth)| growth > *best_growth)
                {
                    best_growth = Some((group.clone(), growth));
                }
            }
        }

        self.previous_sizes.clear();
        for group in groups {
            self.previous_sizes
                .insert(format!("{directory}/{}", group.relfilenode), group.bytes);
        }

        if let Some((group, _growth)) = best_growth {
            let percent = (group.bytes as f64 / source_relation_bytes as f64 * 100.0).min(100.0);
            self.last_estimate = Some(RewriteFileEstimate {
                directory: directory.to_string(),
                relfilenode: group.relfilenode,
                bytes_written: group.bytes,
                source_relation_bytes,
                percent,
            });
        }

        Ok(self.last_estimate.clone())
    }
}

#[derive(Debug, Clone)]
struct FileGroupSample {
    relfilenode: String,
    bytes: i64,
}

async fn read_exact_progress(
    client: &Client,
    backend_pid: i32,
) -> Result<Option<ExactProgress>, tokio_postgres::Error> {
    if let Some(progress) = read_create_index_progress(client, backend_pid).await? {
        return Ok(Some(progress));
    }
    if let Some(progress) = read_cluster_progress(client, backend_pid).await? {
        return Ok(Some(progress));
    }
    if let Some(progress) = read_copy_progress(client, backend_pid).await? {
        return Ok(Some(progress));
    }
    Ok(None)
}

async fn read_create_index_progress(
    client: &Client,
    backend_pid: i32,
) -> Result<Option<ExactProgress>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            r#"
select
  p.command::text as command,
  p.phase::text as phase,
  case when p.relid = 0::oid then null else p.relid::regclass::text end as relation_name,
  case when p.index_relid = 0::oid then null else p.index_relid::regclass::text end as index_name,
  p.blocks_done::bigint as blocks_done,
  p.blocks_total::bigint as blocks_total,
  p.tuples_done::bigint as tuples_done,
  p.tuples_total::bigint as tuples_total,
  p.lockers_done::bigint as lockers_done,
  p.lockers_total::bigint as lockers_total
from pg_stat_progress_create_index p
where p.pid = $1
"#,
            &[&backend_pid],
        )
        .await?;

    Ok(row.map(|row| {
        let blocks_done = row.get::<_, i64>("blocks_done");
        let blocks_total = row.get::<_, i64>("blocks_total");
        let tuples_done = row.get::<_, i64>("tuples_done");
        let tuples_total = row.get::<_, i64>("tuples_total");
        let lockers_done = row.get::<_, i64>("lockers_done");
        let lockers_total = row.get::<_, i64>("lockers_total");
        ExactProgress {
            command: row.get("command"),
            phase: row.get("phase"),
            relation_name: row.get("relation_name"),
            index_name: row.get("index_name"),
            percent: percent_from_counts(blocks_done, blocks_total)
                .or_else(|| percent_from_counts(tuples_done, tuples_total))
                .or_else(|| percent_from_counts(lockers_done, lockers_total)),
            blocks_done: Some(blocks_done),
            blocks_total: Some(blocks_total),
            tuples_done: Some(tuples_done),
            tuples_total: Some(tuples_total),
            lockers_done: Some(lockers_done),
            lockers_total: Some(lockers_total),
            bytes_done: None,
            bytes_total: None,
        }
    }))
}

async fn read_cluster_progress(
    client: &Client,
    backend_pid: i32,
) -> Result<Option<ExactProgress>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            r#"
select
  p.command::text as command,
  p.phase::text as phase,
  case when p.relid = 0::oid then null else p.relid::regclass::text end as relation_name,
  case when p.cluster_index_relid = 0::oid then null else p.cluster_index_relid::regclass::text end as index_name,
  p.heap_blks_scanned::bigint as blocks_done,
  p.heap_blks_total::bigint as blocks_total,
  p.heap_tuples_written::bigint as tuples_done,
  p.heap_tuples_scanned::bigint as tuples_total
from pg_stat_progress_cluster p
where p.pid = $1
"#,
            &[&backend_pid],
        )
        .await?;

    Ok(row.map(|row| {
        let blocks_done = row.get::<_, i64>("blocks_done");
        let blocks_total = row.get::<_, i64>("blocks_total");
        let tuples_done = row.get::<_, i64>("tuples_done");
        let tuples_total = row.get::<_, i64>("tuples_total");
        ExactProgress {
            command: row.get("command"),
            phase: row.get("phase"),
            relation_name: row.get("relation_name"),
            index_name: row.get("index_name"),
            percent: percent_from_counts(blocks_done, blocks_total)
                .or_else(|| percent_from_counts(tuples_done, tuples_total)),
            blocks_done: Some(blocks_done),
            blocks_total: Some(blocks_total),
            tuples_done: Some(tuples_done),
            tuples_total: Some(tuples_total),
            lockers_done: None,
            lockers_total: None,
            bytes_done: None,
            bytes_total: None,
        }
    }))
}

async fn read_copy_progress(
    client: &Client,
    backend_pid: i32,
) -> Result<Option<ExactProgress>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            r#"
select
  p.command::text as command,
  p.type::text || ': ' || p.command::text as phase,
  case when p.relid = 0::oid then null else p.relid::regclass::text end as relation_name,
  p.bytes_processed::bigint as bytes_done,
  p.bytes_total::bigint as bytes_total,
  p.tuples_processed::bigint as tuples_done
from pg_stat_progress_copy p
where p.pid = $1
"#,
            &[&backend_pid],
        )
        .await?;

    Ok(row.map(|row| {
        let bytes_done = row.get::<_, i64>("bytes_done");
        let bytes_total = row.get::<_, i64>("bytes_total");
        ExactProgress {
            command: row.get("command"),
            phase: row.get("phase"),
            relation_name: row.get("relation_name"),
            index_name: None,
            percent: percent_from_counts(bytes_done, bytes_total),
            blocks_done: None,
            blocks_total: None,
            tuples_done: Some(row.get("tuples_done")),
            tuples_total: None,
            lockers_done: None,
            lockers_total: None,
            bytes_done: Some(bytes_done),
            bytes_total: Some(bytes_total),
        }
    }))
}

async fn read_activity(
    client: &Client,
    backend_pid: i32,
) -> Result<Option<ActivitySample>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            r#"
select
  coalesce(state, 'unknown')::text as state,
  wait_event_type::text as wait_event_type,
  wait_event::text as wait_event,
  extract(epoch from (clock_timestamp() - query_start))::double precision as query_age_seconds
from pg_stat_activity
where pid = $1
"#,
            &[&backend_pid],
        )
        .await?;

    Ok(row.map(|row| ActivitySample {
        state: row.get("state"),
        wait_event_type: row.get("wait_event_type"),
        wait_event: row.get("wait_event"),
        query_age_seconds: row.get("query_age_seconds"),
    }))
}

async fn read_relation_locks(
    client: &Client,
    backend_pid: i32,
) -> Result<Vec<RelationLockSample>, tokio_postgres::Error> {
    let rows = client
        .query(
            r#"
select
  coalesce(n.nspname || '.' || c.relname, l.relation::text) as relation_name,
  c.relkind::text as relkind,
  l.mode::text as mode,
  l.granted as granted,
  case when c.oid is null then null else pg_relation_size(c.oid) end as relation_bytes,
  case when c.oid is null then null else pg_total_relation_size(c.oid) end as total_bytes,
  case when c.oid is null then null else pg_relation_filepath(c.oid) end as relation_path,
  c.relfilenode::text as relfilenode
from pg_locks l
left join pg_class c on c.oid = l.relation
left join pg_namespace n on n.oid = c.relnamespace
where l.pid = $1
  and l.relation is not null
order by (l.mode = 'AccessExclusiveLock') desc, l.granted desc, relation_name, l.mode
limit 8
"#,
            &[&backend_pid],
        )
        .await?;

    Ok(rows
        .into_iter()
        .map(|row| RelationLockSample {
            relation: row.get("relation_name"),
            relkind: row.get("relkind"),
            mode: row.get("mode"),
            granted: row.get("granted"),
            relation_bytes: row.get("relation_bytes"),
            total_bytes: row.get("total_bytes"),
            path: row.get("relation_path"),
            relfilenode: row.get("relfilenode"),
        })
        .collect())
}

async fn read_relation_file_groups(
    client: &Client,
    directory: &str,
) -> Result<Vec<FileGroupSample>, tokio_postgres::Error> {
    let rows = client
        .query(
            r#"
select
  split_part(name, '.', 1) as relfilenode,
  coalesce(sum((pg_stat_file($1 || '/' || name, true)).size), 0)::bigint as bytes
from pg_ls_dir($1) as name
where name ~ '^[0-9]+(\.[0-9]+)?$'
group by 1
"#,
            &[&directory],
        )
        .await?;

    Ok(rows
        .into_iter()
        .map(|row| FileGroupSample {
            relfilenode: row.get("relfilenode"),
            bytes: row.get("bytes"),
        })
        .collect())
}

fn live_progress_message(
    context: &ProgressContext,
    started: Instant,
    sample: &ProgressSample,
) -> String {
    let mut parts = vec![
        format!("[{}/{}]", context.index, context.total),
        "Running".blue().bold().to_string(),
        format!(
            "{}:{}",
            context.kind.cyan(),
            context.object_name.cyan().bold()
        ),
        context.source_file.clone(),
        format!("elapsed={}", format_duration(started.elapsed()).yellow()),
    ];

    if let Some(exact) = &sample.exact {
        parts.push(exact_progress_detail(exact));
    } else {
        parts.push(format!("progress={}", "n/a".yellow()));
        if context.rewrite_probe_expected || sample.has_access_exclusive_lock() {
            parts.push(
                "alter_progress=no native pg_stat_progress_alter"
                    .yellow()
                    .to_string(),
            );
        }
    }

    if let Some(activity) = &sample.activity {
        parts.push(activity_detail(activity));
    }
    if let Some(lock) = sample.primary_lock() {
        parts.push(lock_detail(lock));
    }
    if let Some(rewrite) = &sample.rewrite {
        parts.push(rewrite_estimate_detail(rewrite));
    }
    if let Some(warning) = sample.warnings.first() {
        parts.push(format!("note={}", warning.yellow()));
    }

    truncate_chars(&parts.join(" | "), LIVE_PROGRESS_WIDTH)
}

fn exact_progress_detail(progress: &ExactProgress) -> String {
    let mut detail = vec![format!("native={}", progress.command.green().bold())];
    if let Some(percent) = progress.percent {
        detail.push(format!(
            "progress={}",
            format!("{percent:.1}%").green().bold()
        ));
    } else {
        detail.push(format!("progress={}", "n/a".yellow()));
    }
    detail.push(format!("phase={}", progress.phase));
    if let Some(relation) = &progress.relation_name {
        detail.push(format!("table={relation}"));
    }
    if let Some(index) = &progress.index_name {
        detail.push(format!("index={index}"));
    }
    if let (Some(done), Some(total)) = (progress.blocks_done, progress.blocks_total) {
        detail.push(format!("blocks={done}/{total}"));
    }
    if let (Some(done), Some(total)) = (progress.tuples_done, progress.tuples_total) {
        detail.push(format!("tuples={done}/{total}"));
    } else if let Some(done) = progress.tuples_done {
        detail.push(format!("tuples={done}"));
    }
    if let (Some(done), Some(total)) = (progress.lockers_done, progress.lockers_total) {
        detail.push(format!("lockers={done}/{total}"));
    }
    if let (Some(done), Some(total)) = (progress.bytes_done, progress.bytes_total) {
        detail.push(format!(
            "bytes={}/{}",
            format_bytes(done),
            format_bytes(total)
        ));
    }
    detail.join(" ")
}

fn activity_detail(activity: &ActivitySample) -> String {
    let mut detail = vec![format!("state={}", activity.state)];
    if let Some(age_seconds) = activity.query_age_seconds {
        detail.push(format!("query_age={}", format_seconds(age_seconds)));
    }
    match (&activity.wait_event_type, &activity.wait_event) {
        (Some(wait_type), Some(wait_event)) => {
            detail.push(format!("wait={wait_type}/{wait_event}"));
        }
        (Some(wait_type), None) => detail.push(format!("wait={wait_type}")),
        _ => {}
    }
    detail.join(" ")
}

fn lock_detail(lock: &RelationLockSample) -> String {
    let granted = if lock.granted { "granted" } else { "waiting" };
    let mut detail = vec![
        format!("lock={}({granted})", lock.mode),
        format!("relation={}", lock.relation),
    ];
    if let Some(relkind) = &lock.relkind {
        detail.push(format!("relkind={relkind}"));
    }
    if let Some(bytes) = lock.relation_bytes {
        detail.push(format!("heap={}", format_bytes(bytes)));
    }
    if let Some(bytes) = lock.total_bytes {
        detail.push(format!("total={}", format_bytes(bytes)));
    }
    if let Some(path) = &lock.path {
        detail.push(format!("path={path}"));
    }
    if let Some(relfilenode) = &lock.relfilenode {
        detail.push(format!("relfilenode={relfilenode}"));
    }
    detail.join(" ")
}

fn rewrite_estimate_detail(estimate: &RewriteFileEstimate) -> String {
    format!(
        "rewrite_estimate={} growing={}/{} written={} source_heap={}",
        format!("{:.1}%", estimate.percent).yellow().bold(),
        estimate.directory,
        estimate.relfilenode,
        format_bytes(estimate.bytes_written),
        format_bytes(estimate.source_relation_bytes)
    )
}

fn rewrite_relation_candidate(locks: &[RelationLockSample]) -> Option<&RelationLockSample> {
    locks
        .iter()
        .find(|lock| {
            lock.granted
                && lock.mode == "AccessExclusiveLock"
                && matches!(lock.relkind.as_deref(), Some("r" | "m" | "t"))
        })
        .or_else(|| {
            locks.iter().find(|lock| {
                lock.granted
                    && matches!(lock.relkind.as_deref(), Some("r" | "m" | "t"))
                    && lock.relation_bytes.unwrap_or_default() > 0
            })
        })
}

fn relation_storage_dir(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(directory, _file)| directory)
}

fn percent_from_counts(done: i64, total: i64) -> Option<f64> {
    if total <= 0 {
        return None;
    }
    Some((done.max(0) as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
}

fn sql_may_rewrite_table(sql: &str) -> bool {
    let lowered = sql.to_ascii_lowercase();
    if !lowered.contains("alter table") {
        return false;
    }

    lowered.contains("generated always") && lowered.contains("stored")
        || lowered.contains("set data type")
        || lowered.contains(" alter column ") && lowered.contains(" type ")
        || lowered.contains("add column")
            && lowered.contains("not null")
            && lowered.contains("default")
}

fn compact_error(error: &tokio_postgres::Error) -> String {
    if let Some(db_error) = error.as_db_error() {
        return format!("[{}] {}", db_error.code().code(), db_error.message());
    }
    error.to_string()
}

fn format_seconds(seconds: f64) -> String {
    if seconds.is_finite() && seconds >= 0.0 {
        format!("{seconds:.1}s")
    } else {
        "n/a".to_string()
    }
}

fn format_bytes(bytes: i64) -> String {
    let mut value = bytes.max(0) as f64;
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut unit_index = 0usize;
    while value >= 1024.0 && unit_index + 1 < units.len() {
        value /= 1024.0;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{} {}", value as i64, units[unit_index])
    } else {
        format!("{value:.1} {}", units[unit_index])
    }
}

fn truncate_chars(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut output = String::with_capacity(width + 3);
    for character in value.chars().take(width) {
        output.push(character);
    }
    output.push_str("...");
    output
}

fn color_status(status: &str, padded: &str) -> colored::ColoredString {
    match status {
        "applied" => padded.green(),
        "failed" => padded.red().bold(),
        "pending" => padded.yellow(),
        "skipped" => padded.dimmed(),
        _ => padded.normal(),
    }
}

fn short_sha(sha256: &str) -> String {
    truncate_chars(sha256, 12)
}

fn print_ready_summary(ready: &SchemaReadyStatus) {
    let ready_label = if ready.ready {
        "true".green().bold()
    } else {
        "false".red().bold()
    };
    println!(
        "schema_ready: ready={} total={} applied={} pending={} failed={} last_applied_at={} last_updated_at={}",
        ready_label,
        ready.total_count,
        ready.applied_count,
        ready.pending_count,
        ready.failed_count,
        ready.last_applied_at.as_deref().unwrap_or("-"),
        ready.last_updated_at.as_deref().unwrap_or("-")
    );
    if !ready.failed_objects.is_empty() {
        println!("failed_objects: {}", ready.failed_objects.join(", ").red());
    }
}

fn resolve_rollback_path(sql_dir: &Path, rollback_file: &str) -> Option<PathBuf> {
    rollback_path_candidates(sql_dir, rollback_file)
        .into_iter()
        .find(|path| path.exists())
}

fn rollback_path_candidates(sql_dir: &Path, rollback_file: &str) -> Vec<PathBuf> {
    let reference = Path::new(rollback_file);
    if reference.is_absolute() {
        return vec![reference.to_path_buf()];
    }

    let mut candidates = vec![reference.to_path_buf(), sql_dir.join(reference)];
    if let Ok(stripped) = reference.strip_prefix("sql") {
        candidates.push(sql_dir.join(stripped));
    }
    if let Some(repo_dir) = sql_dir.parent() {
        candidates.push(repo_dir.join(reference));
    }
    dedupe_paths(candidates)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }
    deduped
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

    #[test]
    fn percent_from_counts_ignores_missing_totals_and_clamps() {
        assert_eq!(percent_from_counts(25, 100), Some(25.0));
        assert_eq!(percent_from_counts(1, 0), None);
        assert_eq!(percent_from_counts(120, 100), Some(100.0));
        assert_eq!(percent_from_counts(-5, 100), Some(0.0));
    }

    #[test]
    fn rewrite_detection_flags_stored_generated_alter() {
        assert!(sql_may_rewrite_table(
            "alter table wireless_frames add column if not exists bssid_oui text generated always as (lower(bssid)) stored;"
        ));
        assert!(!sql_may_rewrite_table(
            "alter table wireless_frames add column if not exists frame_subtype text;"
        ));
    }

    #[test]
    fn relation_storage_dir_uses_postgres_relative_path() {
        assert_eq!(relation_storage_dir("base/16384/24576"), Some("base/16384"));
        assert_eq!(relation_storage_dir("24576"), None);
    }

    #[test]
    fn rewrite_candidate_prefers_access_exclusive_heap_lock() {
        let locks = vec![
            RelationLockSample {
                relation: "schema_control.schema_objects".to_string(),
                relkind: Some("r".to_string()),
                mode: "RowExclusiveLock".to_string(),
                granted: true,
                relation_bytes: Some(8_192),
                total_bytes: Some(16_384),
                path: Some("base/1/10".to_string()),
                relfilenode: Some("10".to_string()),
            },
            RelationLockSample {
                relation: "public.wireless_frames".to_string(),
                relkind: Some("r".to_string()),
                mode: "AccessExclusiveLock".to_string(),
                granted: true,
                relation_bytes: Some(1024 * 1024),
                total_bytes: Some(2 * 1024 * 1024),
                path: Some("base/1/20".to_string()),
                relfilenode: Some("20".to_string()),
            },
        ];

        let candidate = rewrite_relation_candidate(&locks).expect("rewrite candidate");
        assert_eq!(candidate.relation, "public.wireless_frames");
    }

    #[test]
    fn live_message_reports_alter_progress_absence_and_lock_details() {
        let context = ProgressContext {
            index: 3,
            total: 12,
            kind: "table".to_string(),
            object_name: "wireless_frames".to_string(),
            source_file: "tables/003_wireless_frames.sql".to_string(),
            rewrite_probe_expected: true,
        };
        let sample = ProgressSample {
            activity: Some(ActivitySample {
                state: "active".to_string(),
                wait_event_type: Some("IO".to_string()),
                wait_event: Some("DataFileRead".to_string()),
                query_age_seconds: Some(3.4),
            }),
            locks: vec![RelationLockSample {
                relation: "public.wireless_frames".to_string(),
                relkind: Some("r".to_string()),
                mode: "AccessExclusiveLock".to_string(),
                granted: true,
                relation_bytes: Some(1024 * 1024),
                total_bytes: Some(2 * 1024 * 1024),
                path: Some("base/1/20".to_string()),
                relfilenode: Some("20".to_string()),
            }],
            ..ProgressSample::default()
        };

        let message = live_progress_message(&context, Instant::now(), &sample);

        assert!(message.contains("[3/12]"));
        assert!(message.contains("pg_stat_progress_alter"));
        assert!(message.contains("AccessExclusiveLock"));
        assert!(message.contains("public.wireless_frames"));
        assert!(message.contains("base/1/20"));
    }

    #[test]
    fn exact_progress_detail_includes_percent_and_counts() {
        let detail = exact_progress_detail(&ExactProgress {
            command: "CREATE INDEX".to_string(),
            phase: "building index".to_string(),
            relation_name: Some("public.wireless_frames".to_string()),
            index_name: Some("wireless_frames_bssid_oui_idx".to_string()),
            percent: Some(42.5),
            blocks_done: Some(425),
            blocks_total: Some(1000),
            tuples_done: None,
            tuples_total: None,
            lockers_done: Some(0),
            lockers_total: Some(0),
            bytes_done: None,
            bytes_total: None,
        });

        assert!(detail.contains("42.5%"));
        assert!(detail.contains("blocks=425/1000"));
        assert!(detail.contains("wireless_frames_bssid_oui_idx"));
    }

    #[test]
    fn format_bytes_uses_binary_units() {
        assert_eq!(format_bytes(42), "42 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0 MiB");
    }
}
