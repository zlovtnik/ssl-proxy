use std::fs;
use std::process;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};

use crate::discovery::SqlFile;
use crate::error::ExecutionError;

const APPLY_LOCK_NAMESPACE: &str = "ssl-proxy:db-migrator:schema-apply";
const APPLY_LOCK_KEY: i64 = advisory_lock_key(APPLY_LOCK_NAMESPACE);

const fn advisory_lock_key(namespace: &str) -> i64 {
    let bytes = namespace.as_bytes();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut index = 0;

    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }

    (hash & 0x7fff_ffff_ffff_ffff) as i64
}

#[derive(Debug, Clone)]
pub struct SchemaObject {
    pub kind: String,
    pub object_name: String,
    pub source_file: String,
    pub depends_on: Vec<String>,
    pub raw_sql: String,
    pub canonical_sql: String,
    pub sha256: String,
}

#[derive(Debug)]
pub struct PreparedSchemaObject {
    pub object: SchemaObject,
    pub old_sha256: Option<String>,
    pub needs_apply: bool,
}

pub fn build_manifest(files: &[SqlFile]) -> Result<Vec<SchemaObject>, ExecutionError> {
    files
        .iter()
        .map(schema_object_from_file)
        .collect::<Result<Vec<_>, _>>()
}

pub async fn bootstrap(client: &Client) -> Result<(), ExecutionError> {
    client
        .batch_execute(
            r#"
create schema if not exists schema_control;

create table if not exists schema_control.schema_objects (
  id              bigserial primary key,
  kind            text        not null,
  object_name     text        not null,
  source_file     text        not null,
  depends_on      text[]      not null default '{}',
  canonical_sql   text        not null,
  content_sha256  text        not null,
  applied_at      timestamptz,
  apply_status    text        not null default 'pending',
  last_error      text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  constraint schema_objects_unique unique (kind, object_name),
  constraint schema_objects_status_chk check (
    apply_status in ('pending', 'applied', 'failed', 'skipped')
  )
);

create table if not exists schema_control.schema_apply_log (
  log_id        bigserial primary key,
  kind          text        not null,
  object_name   text        not null,
  source_file   text        not null,
  action        text        not null,
  old_sha256    text,
  new_sha256    text,
  duration_ms   integer,
  error_text    text,
  applied_by    text,
  applied_at    timestamptz not null default now()
);

create index if not exists schema_apply_log_object_idx
  on schema_control.schema_apply_log(kind, object_name, applied_at desc);

create or replace view schema_control.schema_ready as
select
  now() as measured_at,
  count(*)::bigint as total_count,
  count(*) filter (where apply_status = 'pending')::bigint as pending_count,
  count(*) filter (where apply_status = 'failed')::bigint as failed_count,
  count(*) filter (where apply_status in ('applied', 'skipped'))::bigint as applied_count,
  (
    count(*) > 0
    and coalesce(bool_and(apply_status in ('applied', 'skipped')), false)
  ) as all_applied,
  (
    count(*) > 0
    and coalesce(bool_and(apply_status in ('applied', 'skipped')), false)
    and count(*) filter (where apply_status = 'failed') = 0
  ) as ready,
  coalesce(
    array_agg(kind || ':' || object_name order by kind, object_name)
      filter (where apply_status = 'failed'),
    array[]::text[]
  ) as failed_objects,
  max(updated_at) as last_updated_at,
  max(applied_at) as last_applied_at
from schema_control.schema_objects;
"#,
        )
        .await
        .map_err(|error| ExecutionError::apply(format!("schema_control bootstrap failed: {error}")))
}

pub async fn acquire_apply_lock(client: &Client) -> Result<(), ExecutionError> {
    let row = client
        .query_one("select pg_try_advisory_lock($1)", &[&APPLY_LOCK_KEY])
        .await
        .map_err(|error| {
            ExecutionError::apply(format!("failed to acquire schema apply lock: {error}"))
        })?;
    let acquired: bool = row.get(0);
    if acquired {
        Ok(())
    } else {
        Err(ExecutionError::apply(format!(
            "schema apply lock {APPLY_LOCK_KEY} ({APPLY_LOCK_NAMESPACE}) is already held"
        )))
    }
}

pub async fn release_apply_lock(client: &Client) -> Result<(), ExecutionError> {
    let row = client
        .query_one("select pg_advisory_unlock($1)", &[&APPLY_LOCK_KEY])
        .await
        .map_err(|error| {
            ExecutionError::apply(format!("failed to release schema apply lock: {error}"))
        })?;
    let released: bool = row.get(0);
    if released {
        Ok(())
    } else {
        Err(ExecutionError::apply(format!(
            "schema apply lock {APPLY_LOCK_KEY} ({APPLY_LOCK_NAMESPACE}) was not held"
        )))
    }
}

pub async fn prepare_manifest(
    client: &Client,
    objects: Vec<SchemaObject>,
) -> Result<Vec<PreparedSchemaObject>, ExecutionError> {
    let mut prepared = Vec::with_capacity(objects.len());

    for object in objects {
        let existing = client
            .query_opt(
                r#"
select content_sha256, apply_status
from schema_control.schema_objects
where kind = $1 and object_name = $2
"#,
                &[&object.kind, &object.object_name],
            )
            .await
            .map_err(|error| {
                ExecutionError::apply(format!(
                    "failed to read schema control state for {}:{}: {error}",
                    object.kind, object.object_name
                ))
            })?;

        let old_sha256 = existing
            .as_ref()
            .map(|row| row.get::<_, String>("content_sha256"));
        let old_status = existing
            .as_ref()
            .map(|row| row.get::<_, String>("apply_status"));
        let needs_apply = !matches!(
            (old_sha256.as_deref(), old_status.as_deref()),
            (Some(old_sha), Some("applied" | "skipped")) if old_sha == object.sha256
        );
        let apply_status = if needs_apply { "pending" } else { "skipped" };

        client
            .execute(
                r#"
insert into schema_control.schema_objects (
  kind, object_name, source_file, depends_on, canonical_sql, content_sha256,
  applied_at, apply_status, last_error, updated_at
) values (
  $1, $2, $3, $4, $5, $6,
  case when $7::text = 'pending' then null else now() end,
  $7, null, now()
)
on conflict (kind, object_name) do update set
  source_file = excluded.source_file,
  depends_on = excluded.depends_on,
  canonical_sql = excluded.canonical_sql,
  content_sha256 = excluded.content_sha256,
  applied_at = case
    when excluded.apply_status = 'pending' then null
    else coalesce(schema_control.schema_objects.applied_at, now())
  end,
  apply_status = excluded.apply_status,
  last_error = null,
  updated_at = now()
"#,
                &[
                    &object.kind,
                    &object.object_name,
                    &object.source_file,
                    &object.depends_on,
                    &object.canonical_sql,
                    &object.sha256,
                    &apply_status,
                ],
            )
            .await
            .map_err(|error| {
                ExecutionError::apply(format!(
                    "failed to prepare schema control state for {}:{}: {error}",
                    object.kind, object.object_name
                ))
            })?;

        prepared.push(PreparedSchemaObject {
            object,
            old_sha256,
            needs_apply,
        });
    }

    Ok(prepared)
}

pub async fn record_skipped(
    client: &Client,
    prepared: &PreparedSchemaObject,
) -> Result<(), ExecutionError> {
    insert_apply_log(
        client,
        &prepared.object,
        "skipped",
        prepared.old_sha256.as_deref(),
        None,
        None,
    )
    .await
}

pub async fn record_applied(
    transaction: &Transaction<'_>,
    prepared: &PreparedSchemaObject,
    duration: Duration,
) -> Result<(), ExecutionError> {
    let duration_ms = duration_ms(duration);
    transaction
        .execute(
            r#"
update schema_control.schema_objects
   set apply_status = 'applied',
       applied_at = now(),
       last_error = null,
       updated_at = now()
 where kind = $1 and object_name = $2
"#,
            &[&prepared.object.kind, &prepared.object.object_name],
        )
        .await
        .map_err(|error| {
            ExecutionError::apply(format!(
                "failed to mark {}:{} applied: {error}",
                prepared.object.kind, prepared.object.object_name
            ))
        })?;

    insert_apply_log(
        transaction,
        &prepared.object,
        "applied",
        prepared.old_sha256.as_deref(),
        Some(duration_ms),
        None,
    )
    .await
}

pub async fn record_failed(
    client: &Client,
    prepared: &PreparedSchemaObject,
    error_text: &str,
    duration: Duration,
) -> Result<(), ExecutionError> {
    let duration_ms = duration_ms(duration);
    client
        .execute(
            r#"
update schema_control.schema_objects
   set apply_status = 'failed',
       last_error = $3,
       updated_at = now()
 where kind = $1 and object_name = $2
"#,
            &[
                &prepared.object.kind,
                &prepared.object.object_name,
                &error_text,
            ],
        )
        .await
        .map_err(|error| {
            ExecutionError::apply(format!(
                "failed to mark {}:{} failed: {error}",
                prepared.object.kind, prepared.object.object_name
            ))
        })?;

    insert_apply_log(
        client,
        &prepared.object,
        "failed",
        prepared.old_sha256.as_deref(),
        Some(duration_ms),
        Some(error_text),
    )
    .await
}

async fn insert_apply_log<C>(
    client: &C,
    object: &SchemaObject,
    action: &str,
    old_sha256: Option<&str>,
    duration_ms: Option<i32>,
    error_text: Option<&str>,
) -> Result<(), ExecutionError>
where
    C: tokio_postgres::GenericClient + Sync,
{
    let applied_by = applied_by();
    client
        .execute(
            r#"
insert into schema_control.schema_apply_log (
  kind, object_name, source_file, action, old_sha256, new_sha256,
  duration_ms, error_text, applied_by
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
"#,
            &[
                &object.kind,
                &object.object_name,
                &object.source_file,
                &action,
                &old_sha256,
                &object.sha256,
                &duration_ms,
                &error_text,
                &applied_by,
            ],
        )
        .await
        .map_err(|error| {
            ExecutionError::apply(format!(
                "failed to write schema apply log for {}:{}: {error}",
                object.kind, object.object_name
            ))
        })?;
    Ok(())
}

fn schema_object_from_file(file: &SqlFile) -> Result<SchemaObject, ExecutionError> {
    let raw_sql = fs::read_to_string(&file.path).map_err(|error| {
        ExecutionError::apply(format!(
            "{}: failed to read SQL file ({error})",
            file.relative_path()
        ))
    })?;
    let object_name = parse_header_value(&raw_sql, "object").ok_or_else(|| {
        ExecutionError::apply(format!(
            "{}: missing required '-- object:' header",
            file.relative_path()
        ))
    })?;
    let depends_on = parse_header_value(&raw_sql, "depends_on")
        .map(|value| parse_depends_on(&value))
        .unwrap_or_default();
    let canonical_sql = canonicalize_sql(&raw_sql);
    let sha256 = sha256_hex(&canonical_sql);

    Ok(SchemaObject {
        kind: kind_for_folder(&file.folder, &file.name).to_string(),
        object_name,
        source_file: file.relative_path(),
        depends_on,
        raw_sql,
        canonical_sql,
        sha256,
    })
}

fn parse_header_value(sql: &str, key: &str) -> Option<String> {
    let prefix = format!("-- {key}:");
    sql.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_depends_on(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty() && *item != "-")
        .map(ToOwned::to_owned)
        .collect()
}

fn kind_for_folder(folder: &str, name: &str) -> &'static str {
    match folder {
        "extensions" => "extension",
        "schemas" => "schema",
        "types" => "type",
        "tables" => "table",
        "indexes" => "index",
        "functions" => "function",
        "views" => "view",
        "materialized_views" => "materialized_view",
        "cron" if name.starts_with("000_") => "pre_apply_hook",
        "cron" => "cron_job",
        _ => "sql_file",
    }
}

fn canonicalize_sql(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut output = String::with_capacity(sql.len());
    let mut index = 0usize;
    let mut pending_space = false;

    while index < bytes.len() {
        let current = bytes[index];
        let next = bytes.get(index + 1).copied();

        if current == b'-' && next == Some(b'-') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            pending_space = true;
            continue;
        }

        if current == b'/' && next == Some(b'*') {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            pending_space = true;
            continue;
        }

        if current == b'\'' {
            push_pending_space(&mut output, &mut pending_space);
            index = copy_single_quoted(sql, index, &mut output);
            continue;
        }

        if current == b'"' {
            push_pending_space(&mut output, &mut pending_space);
            index = copy_double_quoted(sql, index, &mut output);
            continue;
        }

        if current == b'$' {
            if let Some(tag) = parse_dollar_tag(bytes, index) {
                if let Some(end) = find_subslice(bytes, index + tag.len(), &tag) {
                    push_pending_space(&mut output, &mut pending_space);
                    output.push_str("$$");
                    let body = &sql[index + tag.len()..end];
                    output.push_str(&canonicalize_sql(body));
                    output.push_str("$$");
                    index = end + tag.len();
                    continue;
                }
            }
        }

        let character = sql[index..].chars().next().expect("valid char boundary");
        if character.is_whitespace() {
            pending_space = true;
        } else {
            push_pending_space(&mut output, &mut pending_space);
            output.push(character);
        }
        index += character.len_utf8();
    }

    output.trim().to_string()
}

fn push_pending_space(output: &mut String, pending_space: &mut bool) {
    if *pending_space && !output.is_empty() && !output.ends_with(' ') {
        output.push(' ');
    }
    *pending_space = false;
}

fn copy_single_quoted(sql: &str, start: usize, output: &mut String) -> usize {
    let bytes = sql.as_bytes();
    let escape_backslash = start > 0 && matches!(bytes[start - 1], b'e' | b'E');
    output.push('\'');
    let mut index = start + 1;
    while index < bytes.len() {
        let character = sql[index..].chars().next().expect("valid char boundary");
        output.push(character);
        index += character.len_utf8();
        if escape_backslash && character == '\\' && index < bytes.len() {
            let escaped = sql[index..].chars().next().expect("valid char boundary");
            output.push(escaped);
            index += escaped.len_utf8();
            continue;
        }
        if character == '\'' {
            if bytes.get(index) == Some(&b'\'') {
                output.push('\'');
                index += 1;
                continue;
            }
            break;
        }
    }
    index
}

fn copy_double_quoted(sql: &str, start: usize, output: &mut String) -> usize {
    let bytes = sql.as_bytes();
    output.push('"');
    let mut index = start + 1;
    while index < bytes.len() {
        let character = sql[index..].chars().next().expect("valid char boundary");
        output.push(character);
        index += character.len_utf8();
        if character == '"' {
            break;
        }
    }
    index
}

fn parse_dollar_tag(bytes: &[u8], start: usize) -> Option<Vec<u8>> {
    if bytes.get(start).copied() != Some(b'$') {
        return None;
    }
    let mut index = start + 1;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if ch == '$' {
            return Some(bytes[start..=index].to_vec());
        }
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            return None;
        }
        index += 1;
    }
    None
}

fn find_subslice(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| start + position)
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{digest:x}")
}

fn duration_ms(duration: Duration) -> i32 {
    duration.as_millis().min(i32::MAX as u128) as i32
}

fn applied_by() -> String {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string());
    format!("{host}:{}", process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_ignores_comments_and_outer_whitespace() {
        let left = r#"
-- object: sample
-- folder: functions
-- depends_on: -
create or replace function sample()
returns void
language plpgsql
as $fn$
begin
  -- implementation note
  perform 1;
end;
$fn$;
"#;
        let right = r#"
create or replace function sample() returns void language plpgsql as $$
begin

  perform 1;
end;
$$;
"#;

        assert_eq!(canonicalize_sql(left), canonicalize_sql(right));
        assert_eq!(
            sha256_hex(&canonicalize_sql(left)),
            sha256_hex(&canonicalize_sql(right))
        );
    }

    #[test]
    fn canonical_hash_preserves_string_literal_whitespace() {
        let left = canonicalize_sql("select 'a  b';");
        let right = canonicalize_sql("select 'a b';");

        assert_ne!(left, right);
    }

    #[test]
    fn canonical_hash_preserves_escaped_string_quotes() {
        let canonical = canonicalize_sql(r"select E'a\'b'; -- comment");

        assert_eq!(canonical, r"select E'a\'b';");
    }

    #[test]
    fn parses_depends_on_header() {
        assert_eq!(
            parse_depends_on(" vec_embedding_jobs, sync_events , - "),
            vec!["vec_embedding_jobs", "sync_events"]
        );
    }

    #[test]
    fn maps_cron_zero_file_to_pre_apply_hook() {
        assert_eq!(
            kind_for_folder("cron", "000_unschedule_cron_jobs.sql"),
            "pre_apply_hook"
        );
        assert_eq!(
            kind_for_folder("cron", "001_vec_install_cron_jobs.sql"),
            "cron_job"
        );
    }
}
