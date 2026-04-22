create table if not exists sync_cursor (
  stream_name text primary key,
  cursor_value text not null,
  updated_at timestamptz not null default now()
);

create or replace function sync_stable_uuid(value text)
returns uuid
language sql
immutable
as $$
  select (
    substr(md5(value), 1, 8) || '-' ||
    substr(md5(value), 9, 4) || '-' ||
    substr(md5(value), 13, 4) || '-' ||
    substr(md5(value), 17, 4) || '-' ||
    substr(md5(value), 21, 12)
  )::uuid
$$;

create table if not exists sync_scan_ingest (
  dedupe_key text primary key,
  stream_name text not null,
  observed_at timestamptz not null,
  payload_ref text not null,
  payload jsonb,
  payload_sha256 text,
  status text not null default 'pending',
  attempt_count integer not null default 0,
  last_error text,
  producer text not null default 'unknown',
  event_kind text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists sync_job (
  job_id uuid primary key,
  stream_name text not null,
  status text not null,
  attempt_count integer not null default 0,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz
);

create table if not exists sync_batch (
  batch_id uuid primary key,
  job_id uuid not null,
  batch_no integer not null,
  payload_ref text not null,
  status text not null,
  row_count integer,
  checksum text,
  attempt_count integer not null default 0,
  last_error text,
  dedupe_key text not null,
  cursor_start text not null,
  cursor_end text not null
);

create table if not exists sync_error (
  id bigserial primary key,
  job_id uuid,
  batch_id uuid,
  error_class text not null,
  error_text text not null,
  created_at timestamptz not null default now()
);

create unique index if not exists sync_batch_dedupe_idx on sync_batch (dedupe_key);
create index if not exists sync_scan_ingest_status_idx on sync_scan_ingest (status, observed_at);
create index if not exists sync_scan_ingest_stream_idx on sync_scan_ingest (stream_name, observed_at);

create table if not exists audit_backlog (
  dedupe_key text primary key,
  stream_name text not null,
  payload text not null,
  status text not null default 'pending',
  attempt_count integer not null default 0,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists audit_backlog_status_idx on audit_backlog (status, updated_at);
