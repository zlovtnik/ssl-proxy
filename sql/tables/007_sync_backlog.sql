-- object: sync_backlog
-- folder: tables
-- depends_on: sync_events
create table if not exists sync_backlog (
  dedupe_key text primary key,
  stream_name text not null,
  payload jsonb not null,
  status text not null default 'pending',
  attempt_count integer not null default 0,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint chk_sync_backlog_status check (status in ('pending','synced','sync_failed','failed'))
);
