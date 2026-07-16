-- PostgreSQL schema aggregate
-- Generated from the canonical ordered sources listed in sql/postgres.sql.
-- Edit the split files, then regenerate this file.

-- object: extensions
-- folder: extensions
-- depends_on: -
-- =============================================================================
-- ssl-proxy canonical Postgres schema
-- Fresh baseline. Do not append migration-style ALTER blocks here.
-- =============================================================================

create extension if not exists pg_trgm;

create extension if not exists vector;

create extension if not exists pgcrypto;

do $$
begin
  begin
    execute 'create extension if not exists pg_stat_statements';
  exception when others then
    raise notice 'pg_stat_statements extension unavailable; query statistics will not be exported: %', sqlerrm;
  end;
end $$;

do $$
begin
  begin
    execute 'create extension if not exists pg_cron';
  exception when others then
    raise notice 'pg_cron extension unavailable; cron jobs will not be installed: %', sqlerrm;
  end;
end $$;

-- object: coordinator
-- folder: schemas
-- depends_on: extensions
create schema if not exists coordinator;

-- object: sync_cursors
-- folder: tables
-- depends_on: coordinator schema
create table if not exists sync_cursors (
  stream_name text primary key,
  cursor_value text not null,
  updated_at timestamptz not null default now()
);

-- object: sync_events
-- folder: tables
-- depends_on: sync_cursors
create table if not exists sync_events (
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
  updated_at timestamptz not null default now(),
  constraint chk_sync_events_status check (status in ('pending','processing','batched','failed'))
);

alter table sync_events set (
  autovacuum_vacuum_scale_factor = 0.005,
  autovacuum_vacuum_threshold = 1000,
  autovacuum_analyze_scale_factor = 0.005,
  autovacuum_analyze_threshold = 1000
);

-- object: wireless_frames
-- folder: tables
-- depends_on: -
create table if not exists wireless_frames (
  dedupe_key text primary key,
  sensor_id text,
  location_id text,
  schema_version integer not null default 1,
  frame_type text,
  frame_subtype text,
  source_mac text,
  transmitter_mac text,
  receiver_mac text,
  bssid text,
  destination_bssid text,
  bssid_oui text generated always as (
    nullif(lower(substr(regexp_replace(coalesce(nullif(bssid, ''), nullif(destination_bssid, ''), ''), '[:\-]', '', 'g'), 1, 6)), '')
  ) stored,
  ssid text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table wireless_frames
  drop constraint if exists wireless_frames_dedupe_key_fkey;

-- object: sync_jobs
-- folder: tables
-- depends_on: sync_cursors
create table if not exists sync_jobs (
  job_id uuid primary key,
  stream_name text not null references sync_cursors(stream_name) deferrable initially deferred,
  status text not null,
  attempt_count integer not null default 0,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz,
  constraint chk_sync_jobs_status check (status in ('pending','running','completed','failed'))
);

-- object: sync_batches
-- folder: tables
-- depends_on: sync_jobs
create table if not exists sync_batches (
  batch_id uuid primary key,
  job_id uuid not null references sync_jobs(job_id),
  batch_no integer not null,
  payload_ref text not null,
  status text not null,
  row_count integer,
  checksum text,
  attempt_count integer not null default 0,
  last_error text,
  dedupe_key text not null unique,
  cursor_start text not null,
  cursor_end text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint chk_sync_batches_status check (status in ('pending','processing','dispatched','completed','failed'))
);

-- object: sync_errors
-- folder: tables
-- depends_on: sync_jobs, sync_batches
create table if not exists sync_errors (
  id bigserial primary key,
  job_id uuid references sync_jobs(job_id),
  batch_id uuid references sync_batches(batch_id),
  error_class text not null,
  error_text text not null,
  created_at timestamptz not null default now()
);

-- object: sync_backlog
-- folder: tables
-- depends_on: sync_events
create table if not exists sync_backlog (
  dedupe_key text primary key,
  stream_name text not null,
  payload jsonb not null,
  failure_stage text not null default 'pre_publish',
  status text not null default 'pending',
  attempt_count integer not null default 0,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint chk_sync_backlog_failure_stage check (failure_stage in ('pre_publish','post_publish')),
  constraint chk_sync_backlog_status check (status in ('pending','synced','sync_failed','failed'))
);

alter table if exists sync_backlog
  add column if not exists failure_stage text not null default 'pre_publish';

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'chk_sync_backlog_failure_stage'
      and conrelid = 'sync_backlog'::regclass
      and contype = 'c'
  ) then
    alter table sync_backlog
      add constraint chk_sync_backlog_failure_stage
      check (failure_stage in ('pre_publish','post_publish'));
  end if;
end;
$$;

-- object: wireless_authorized_networks
-- folder: tables
-- depends_on: -
create table if not exists wireless_authorized_networks (
  id bigserial primary key,
  ssid text,
  bssid text,
  location_id text,
  label text,
  enabled boolean not null default true,
  notes text,
  psk_ciphertext text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint wireless_authorized_networks_identity_chk check (
    nullif(trim(coalesce(ssid, '')), '') is not null
    or nullif(trim(coalesce(bssid, '')), '') is not null
  )
);

-- object: wireless_clients
-- folder: tables
-- depends_on: wireless_authorized_networks
create table if not exists wireless_clients (
  ssid text not null,
  client_mac text not null,
  known_bssid text,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  probe_count integer not null default 1,
  location_id text,
  primary key (ssid, client_mac)
);

-- object: wireless_shadow_alerts
-- folder: tables
-- depends_on: devices
create table if not exists wireless_shadow_alerts (
  source_mac text primary key,
  first_occurred_at timestamptz not null,
  last_occurred_at timestamptz not null,
  occurrence_count bigint not null default 1,
  destination_bssid text,
  ssid text,
  sensor_id text,
  location_id text,
  signal_dbm integer,
  reason text not null,
  evidence jsonb not null default '{}'::jsonb,
  resolved_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint wireless_shadow_alerts_source_mac_format_chk check (source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
);

-- object: devices
-- folder: tables
-- depends_on: -
create table if not exists devices (
  mac_id text primary key,
  wg_pubkey text,
  claim_token_hash text,
  display_name text,
  username text,
  hostname text,
  os_hint text,
  mac_hint text not null,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  notes text,
  constraint devices_mac_id_format_chk check (
    mac_id ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
    and lower(mac_hint) = mac_id
  )
);

-- object: device_identity_clusters
-- folder: tables
-- depends_on: devices
-- Track 2: MAC-rotated devices tracked as a single identity cluster.
-- Multiple devices (different mac_ids) that belong to the same physical
-- device are grouped into one cluster. The mac_ids array stores all
-- associated MACs, and size is a denormalized count for fast querying.
create table if not exists device_identity_clusters (
  cluster_id    bigserial primary key,
  cluster_name  text,                        -- optional human-readable label
  mac_ids       text[] not null default '{}', -- array of associated mac_ids
  size          integer not null default 1,   -- number of MACs in the cluster
  embedding_centroid vector(768),
  centroid_updated_at timestamptz,
  centroid_sample_count integer not null default 0,
  first_seen    timestamptz not null default now(),
  last_seen     timestamptz not null default now(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

alter table device_identity_clusters
  add column if not exists embedding_centroid vector(768),
  add column if not exists centroid_updated_at timestamptz,
  add column if not exists centroid_sample_count integer not null default 0;

-- object: vec_embeddings
-- folder: tables
-- depends_on: pgvector extension
create table if not exists vec_embeddings (
  embedding_id bigserial primary key,
  embedding_model text not null,
  embedding_kind text not null,
  embedding_dimensions integer not null,
  content_sha256 text not null,
  content_text text not null,
  embedding vector not null,
  metadata jsonb not null default '{}'::jsonb,
  embedded_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_embeddings_kind_chk check (embedding_kind in ('event', 'device', 'behaviour_window', 'baseline_profile', 'frame_sequence', 'infrastructure_subgraph', 'timing_profile')),
  constraint vec_embeddings_dimensions_chk check (embedding_dimensions > 0),
  constraint chk_embedding_dims_matches_embedding_dimensions check (vector_dims(embedding) = embedding_dimensions)
);

alter table vec_embeddings set (
  autovacuum_vacuum_scale_factor = 0.01,
  autovacuum_vacuum_threshold = 500,
  autovacuum_analyze_scale_factor = 0.005,
  autovacuum_analyze_threshold = 500
);

alter table vec_embeddings
  drop constraint if exists vec_embeddings_kind_chk;

alter table vec_embeddings
  add constraint vec_embeddings_kind_chk check (embedding_kind in ('event', 'device', 'behaviour_window', 'baseline_profile', 'frame_sequence', 'infrastructure_subgraph', 'timing_profile'));

-- object: vec_behaviour_snapshots
-- folder: tables
-- depends_on: sync_events
create table if not exists vec_behaviour_snapshots (
  snapshot_id bigserial primary key,
  snapshot_key text not null unique,
  source_mac text not null,
  location_id text,
  sensor_id text,
  window_start timestamptz not null,
  window_end timestamptz not null,
  event_count bigint not null default 0,
  text_summary text not null,
  embedding_text text,     -- identity-stripped behavioural text for dense embedding
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_behaviour_snapshots_window_chk check (window_end > window_start)
);

-- object: vec_baseline_profiles
-- folder: tables
-- depends_on: vec_behaviour_snapshots
create table if not exists vec_baseline_profiles (
  baseline_id bigserial primary key,
  bssid text not null,
  metric text not null,
  p5 numeric not null,
  p50 numeric not null,
  p95 numeric not null,
  sample_count bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_baseline_profiles_unique unique (bssid, metric)
);

-- object: vec_frame_sequences
-- folder: tables
-- depends_on: wireless_frames
create table if not exists vec_frame_sequences (
  session_key text primary key,
  source_mac text,
  location_id text,
  sensor_id text,
  window_start timestamptz not null,
  window_end timestamptz not null,
  sequence_tokens text not null,
  semantic_tokens text,
  frame_count bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table vec_frame_sequences
  add column if not exists semantic_tokens text;

-- object: vec_transition_model
-- folder: tables
-- depends_on: vec_frame_sequences
-- Track 5.1: Bigram transition model for sequence scoring
create table if not exists vec_transition_model (
  id bigserial primary key,
  prev_token text not null,
  next_token text not null,
  embedding_kind text not null default 'frame_sequence',
  count bigint not null default 0,
  last_updated timestamptz not null default now(),
  constraint vec_transition_model_unique unique (prev_token, next_token, embedding_kind)
);

-- object: vec_infrastructure_graph
-- folder: tables
-- depends_on: wireless_frames
create table if not exists vec_infrastructure_graph (
  edge_id bigserial primary key,
  node_a text not null,
  node_a_type text not null check (node_a_type in ('bssid', 'client_mac', 'ssid', 'vendor')),
  node_b text not null,
  node_b_type text not null check (node_b_type in ('bssid', 'client_mac', 'ssid', 'vendor')),
  edge_type text not null check (edge_type in ('association', 'probe_target', 'roaming', 'rf_proximity', 'same_channel', 'vendor_link')),
  weight numeric not null default 1,
  last_seen timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_infrastructure_graph_unique unique (node_a, node_a_type, node_b, node_b_type, edge_type)
);

-- object: vec_similarity_pairs
-- folder: tables
-- depends_on: vec_embeddings
create table if not exists vec_similarity_pairs (
  pair_id bigserial primary key,
  left_embedding_id bigint not null references vec_embeddings(embedding_id) on delete cascade,
  right_embedding_id bigint not null references vec_embeddings(embedding_id) on delete cascade,
  cosine_distance double precision not null,
  cosine_similarity double precision not null,
  rank integer not null default 1,
  computed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_similarity_pairs_order_chk check (left_embedding_id < right_embedding_id),
  constraint vec_similarity_pairs_distance_chk check (cosine_distance >= 0),
  constraint vec_similarity_pairs_similarity_chk check (cosine_similarity <= 1)
);

-- object: vec_embedding_jobs
-- folder: tables
-- depends_on: vec_embeddings
create table if not exists vec_embedding_jobs (
  job_id bigserial primary key,
  source_table text not null,
  source_key text not null,
  embedding_model text not null,
  embedding_kind text not null,
  status text not null default 'pending',
  priority integer not null default 100,
  content_sha256 text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_embedding_jobs_kind_chk check (embedding_kind in ('event', 'device', 'behaviour_window', 'baseline_profile', 'frame_sequence', 'infrastructure_subgraph', 'timing_profile')),
  constraint vec_embedding_jobs_status_chk check (status in ('pending', 'leased', 'completed', 'failed')),
  constraint vec_embedding_jobs_source_unique unique (source_table, source_key, embedding_model, embedding_kind)
);

alter table vec_embedding_jobs set (
  autovacuum_vacuum_scale_factor = 0.005,
  autovacuum_vacuum_threshold = 500,
  autovacuum_analyze_scale_factor = 0.005,
  autovacuum_analyze_threshold = 500
);

alter table vec_embedding_jobs
  drop constraint if exists vec_embedding_jobs_kind_chk;

alter table vec_embedding_jobs
  add constraint vec_embedding_jobs_kind_chk check (embedding_kind in ('event', 'device', 'behaviour_window', 'baseline_profile', 'frame_sequence', 'infrastructure_subgraph', 'timing_profile'));

-- object: vec_worker_state
-- folder: tables
-- depends_on: vec_embedding_jobs
create table if not exists vec_worker_state (
  worker_name text primary key,
  status text not null default 'idle',
  last_cursor text,
  last_run_started_at timestamptz,
  last_run_finished_at timestamptz,
  rows_processed bigint not null default 0,
  last_error text,
  updated_at timestamptz not null default now()
);

alter table vec_worker_state set (
  autovacuum_vacuum_scale_factor = 0,
  autovacuum_vacuum_threshold = 10,
  autovacuum_analyze_scale_factor = 0,
  autovacuum_analyze_threshold = 10
);

-- object: vec_alerts
-- folder: tables
-- depends_on: vec_similarity_pairs
-- V020: Create vec_alerts table for actionable alert feed
--
-- Stores alerts generated from embedding analysis:
-- - near_duplicate_cluster: when a device exceeds the near-duplicate threshold
-- - behaviour_anomaly: when a behaviour window deviates from baseline
-- - new_device: first-seen device with embedding profile
-- - device_fingerprint_change: WPS identity or fingerprint shift

CREATE TABLE IF NOT EXISTS vec_alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_type TEXT NOT NULL,
    source_mac TEXT,
    sensor_id TEXT,
    location_id TEXT,
    score DOUBLE PRECISION,
    explanation_text TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE vec_alerts ADD COLUMN IF NOT EXISTS explanation_text TEXT;

COMMENT ON TABLE vec_alerts IS
  'Actionable alerts generated from embedding analysis (near-duplicate, behaviour anomaly, etc.).';

-- object: vec_job_locks
-- folder: tables
-- depends_on: none
create table if not exists vec_job_locks (
  job_name text primary key,
  locked_at timestamptz not null default now(),
  locked_by text
);

-- object: vec_timing_profiles
-- folder: tables
-- depends_on: sync_events
create table if not exists vec_timing_profiles (
  profile_id bigserial primary key,
  profile_key text not null unique,
  source_mac text not null,
  sensor_id text,
  location_id text,
  window_start timestamptz not null,
  window_end timestamptz not null,
  embedding_text text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_timing_profiles_window_chk check (window_end > window_start)
);

-- object: vec_rf_sensor_locations
-- folder: tables
-- depends_on: -
create table if not exists vec_rf_sensor_locations (
  sensor_id text not null,
  location_id text not null default '',
  latitude double precision not null,
  longitude double precision not null,
  site_label text,
  enabled boolean not null default true,
  updated_at timestamptz not null default now(),
  constraint vec_rf_sensor_locations_pk primary key (sensor_id, location_id),
  constraint vec_rf_sensor_locations_latitude_chk check (latitude between -90 and 90),
  constraint vec_rf_sensor_locations_longitude_chk check (longitude between -180 and 180)
);

-- object: vec_dns_policy
-- folder: tables
-- depends_on: devices
create table if not exists vec_dns_policy (
  wg_pubkey text primary key,
  policy text not null,
  allow_mdns boolean not null default false,
  updated_at timestamptz not null default now(),
  constraint vec_dns_policy_policy_chk check (policy in ('secure_required', 'monitor', 'disabled'))
);

-- object: vec_dns_resolver_ledger
-- folder: tables
-- depends_on: vec_dns_policy
create table if not exists vec_dns_resolver_ledger (
  ledger_id bigserial primary key,
  wg_pubkey text not null,
  observed_at timestamptz not null,
  protocol text not null,
  query_name text,
  query_name_hash text,
  status text not null default 'observed',
  constraint vec_dns_resolver_ledger_protocol_chk check (protocol in ('doh', 'dot', 'wireguard_dns', 'dnscrypt', 'unknown')),
  constraint vec_dns_resolver_ledger_query_chk check (query_name is not null or query_name_hash is not null)
);

-- object: search_queries
-- folder: tables
-- depends_on: pgvector extension
-- Search analytics store hashes by default; raw query_text/result_keys are
-- nullable and reserved for explicit diagnostic opt-in paths.
create table if not exists search_queries (
  query_id          bigserial primary key,
  query_text        text,
  hashed_query_text text not null,
  query_kind        text not null,
  query_vec         vector,
  top_k             integer not null default 10,
  result_keys       text[],
  result_key_hashes text[] not null default '{}',
  session_hash      text,
  latency_ms        integer,
  created_at        timestamptz not null default now(),
  expires_at        timestamptz not null default (now() + interval '30 days'),
  constraint search_queries_top_k_chk check (top_k > 0),
  constraint search_queries_latency_chk check (latency_ms is null or latency_ms >= 0)
);

create index if not exists search_queries_created_idx
  on search_queries (created_at desc);

create index if not exists search_queries_expires_idx
  on search_queries (expires_at);

create index if not exists search_queries_hash_idx
  on search_queries (hashed_query_text);

-- object: search_feedback
-- folder: tables
-- depends_on: search_queries
create table if not exists search_feedback (
  feedback_id bigserial primary key,
  query_id    bigint not null references search_queries(query_id) on delete cascade,
  source_key  text not null,
  relevant    boolean not null,
  created_at  timestamptz not null default now()
);

-- Repeated feedback events are allowed; consumers can aggregate by query/source.
create index if not exists search_feedback_query_idx
  on search_feedback (query_id, source_key);

-- object: sync_event_payload_archives
-- folder: tables
-- depends_on: sync_events
create table if not exists sync_event_payload_archives (
  dedupe_key text primary key,
  stream_name text not null,
  observed_at timestamptz not null,
  payload_sha256 text,
  archive_uri text not null,
  payload_bytes bigint not null default 0,
  archived_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- object: sync_event_tombstones
-- folder: tables
-- depends_on: sync_events
create table if not exists sync_event_tombstones (
  dedupe_key text primary key,
  stream_name text not null,
  payload_sha256 text,
  observed_at timestamptz not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- object: device_graph_workmap_hardening_columns
-- folder: tables
-- depends_on: sync_backlog, wireless_clients, vec_dns_resolver_ledger, vec_alerts, vec_behaviour_snapshots, vec_timing_profiles, vec_frame_sequences, vec_baseline_profiles, search_queries

alter table sync_backlog
  add column if not exists max_attempts integer not null default 5;

alter table wireless_clients
  alter column probe_count type bigint;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'chk_sync_backlog_attempts'
      and conrelid = 'sync_backlog'::regclass
      and contype = 'c'
  ) then
    alter table sync_backlog
      add constraint chk_sync_backlog_attempts
      check (attempt_count >= 0 and max_attempts > 0);
  end if;
end;
$$;

alter table vec_dns_resolver_ledger
  add column if not exists expires_at timestamptz;

update vec_dns_resolver_ledger
   set expires_at = observed_at + interval '90 days'
 where expires_at is null;

alter table vec_dns_resolver_ledger
  alter column expires_at set default (now() + interval '90 days');

alter table vec_dns_resolver_ledger
  alter column expires_at set not null;

alter table vec_alerts
  add column if not exists resolved_at timestamptz,
  add column if not exists suppressed_until timestamptz,
  add column if not exists acknowledged_by text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vec_alerts_type_chk'
      and conrelid = 'vec_alerts'::regclass
      and contype = 'c'
  ) then
    alter table vec_alerts
      add constraint vec_alerts_type_chk
      check (
        alert_type in (
          'behaviour_anomaly',
          'deauth_flood',
          'deauth_precursor',
          'device_fingerprint_change',
          'dns_privacy_leak',
          'embedding_drift',
          'high_risk_ap',
          'near_duplicate_cluster',
          'new_device',
          'rf_impossible_travel',
          'rogue_cluster',
          'rogue_rf_path',
          'signal_anomaly',
          'zero_trust_overlay_risk'
        )
      )
      not valid;
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vec_behaviour_snapshots_embedding_text_chk'
      and conrelid = 'vec_behaviour_snapshots'::regclass
      and contype = 'c'
  ) then
    alter table vec_behaviour_snapshots
      add constraint vec_behaviour_snapshots_embedding_text_chk
      check (nullif(embedding_text, '') is not null)
      not valid;
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vec_timing_profiles_embedding_text_chk'
      and conrelid = 'vec_timing_profiles'::regclass
      and contype = 'c'
  ) then
    alter table vec_timing_profiles
      add constraint vec_timing_profiles_embedding_text_chk
      check (nullif(embedding_text, '') is not null)
      not valid;
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vec_frame_sequences_sequence_tokens_len_chk'
      and conrelid = 'vec_frame_sequences'::regclass
      and contype = 'c'
  ) then
    alter table vec_frame_sequences
      add constraint vec_frame_sequences_sequence_tokens_len_chk
      check (length(sequence_tokens) < 65536)
      not valid;
  end if;
end;
$$;

alter table vec_baseline_profiles
  add column if not exists baseline_window_days integer not null default 7;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vec_baseline_profiles_window_days_chk'
      and conrelid = 'vec_baseline_profiles'::regclass
      and contype = 'c'
  ) then
    alter table vec_baseline_profiles
      add constraint vec_baseline_profiles_window_days_chk
      check (baseline_window_days > 0);
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'search_queries_query_vec_dims_chk'
      and conrelid = 'search_queries'::regclass
      and contype = 'c'
  ) then
    alter table search_queries
      add constraint search_queries_query_vec_dims_chk
      check (query_vec is null or vector_dims(query_vec) = 768)
      not valid;
  end if;
end;
$$;

-- object: vec_timing_profile_stats
-- folder: tables
-- depends_on: vec_timing_profiles
create table if not exists vec_timing_profile_stats (
  profile_id bigint primary key references vec_timing_profiles(profile_id) on delete cascade,
  tsft_p50_us numeric,
  tsft_p95_us numeric,
  tsft_jitter numeric,
  wall_p50_ms numeric,
  wall_jitter_ms numeric,
  beacon_interval_median_ms numeric,
  beacon_jitter_ms numeric
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_timing_profiles'
      and column_name = 'tsft_p50_us'
  ) then
    execute $backfill$
      insert into vec_timing_profile_stats (
        profile_id, tsft_p50_us, tsft_p95_us, tsft_jitter,
        wall_p50_ms, wall_jitter_ms, beacon_interval_median_ms, beacon_jitter_ms
      )
      select
        profile_id, tsft_p50_us, tsft_p95_us, tsft_jitter,
        wall_p50_ms, wall_jitter_ms, beacon_interval_median_ms, beacon_jitter_ms
      from vec_timing_profiles
      on conflict (profile_id) do update set
        tsft_p50_us = excluded.tsft_p50_us,
        tsft_p95_us = excluded.tsft_p95_us,
        tsft_jitter = excluded.tsft_jitter,
        wall_p50_ms = excluded.wall_p50_ms,
        wall_jitter_ms = excluded.wall_jitter_ms,
        beacon_interval_median_ms = excluded.beacon_interval_median_ms,
        beacon_jitter_ms = excluded.beacon_jitter_ms
    $backfill$;
  end if;
end;
$$;

create or replace function vec_timing_profiles_legacy_to_stats()
returns trigger
language plpgsql
as $$
declare
  legacy jsonb := to_jsonb(new);
begin
  if pg_trigger_depth() > 1 or not (legacy ? 'tsft_p50_us') then
    return new;
  end if;

  insert into vec_timing_profile_stats (
    profile_id, tsft_p50_us, tsft_p95_us, tsft_jitter,
    wall_p50_ms, wall_jitter_ms, beacon_interval_median_ms, beacon_jitter_ms
  )
  values (
    new.profile_id,
    (legacy->>'tsft_p50_us')::numeric,
    (legacy->>'tsft_p95_us')::numeric,
    (legacy->>'tsft_jitter')::numeric,
    (legacy->>'wall_p50_ms')::numeric,
    (legacy->>'wall_jitter_ms')::numeric,
    (legacy->>'beacon_interval_median_ms')::numeric,
    (legacy->>'beacon_jitter_ms')::numeric
  )
  on conflict (profile_id) do update set
    tsft_p50_us = excluded.tsft_p50_us,
    tsft_p95_us = excluded.tsft_p95_us,
    tsft_jitter = excluded.tsft_jitter,
    wall_p50_ms = excluded.wall_p50_ms,
    wall_jitter_ms = excluded.wall_jitter_ms,
    beacon_interval_median_ms = excluded.beacon_interval_median_ms,
    beacon_jitter_ms = excluded.beacon_jitter_ms;
  return new;
end;
$$;

create or replace function vec_timing_profile_stats_to_legacy()
returns trigger
language plpgsql
as $$
begin
  if pg_trigger_depth() > 1 or not exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_timing_profiles'
      and column_name = 'tsft_p50_us'
  ) then
    return new;
  end if;

  execute $sync$
    update vec_timing_profiles set
      tsft_p50_us = $1, tsft_p95_us = $2, tsft_jitter = $3,
      wall_p50_ms = $4, wall_jitter_ms = $5,
      beacon_interval_median_ms = $6, beacon_jitter_ms = $7
    where profile_id = $8
  $sync$ using
    new.tsft_p50_us, new.tsft_p95_us, new.tsft_jitter,
    new.wall_p50_ms, new.wall_jitter_ms,
    new.beacon_interval_median_ms, new.beacon_jitter_ms, new.profile_id;
  return new;
end;
$$;

drop trigger if exists vec_timing_profiles_legacy_to_stats on vec_timing_profiles;
create trigger vec_timing_profiles_legacy_to_stats
after insert or update on vec_timing_profiles
for each row execute function vec_timing_profiles_legacy_to_stats();

drop trigger if exists vec_timing_profile_stats_to_legacy on vec_timing_profile_stats;
create trigger vec_timing_profile_stats_to_legacy
after insert or update on vec_timing_profile_stats
for each row execute function vec_timing_profile_stats_to_legacy();

-- object: vec_behaviour_snapshot_stats
-- folder: tables
-- depends_on: vec_behaviour_snapshots
create table if not exists vec_behaviour_snapshot_stats (
  snapshot_id bigint primary key references vec_behaviour_snapshots(snapshot_id) on delete cascade,
  protocol_mix jsonb not null default '{}'::jsonb,
  frame_type_distribution jsonb not null default '{}'::jsonb,
  signal_min_dbm integer,
  signal_max_dbm integer,
  signal_avg_dbm numeric(8,2),
  retry_count bigint not null default 0,
  protected_count bigint not null default 0,
  unprotected_count bigint not null default 0,
  unique_bssid_count bigint not null default 0,
  mac_rotation_indicators jsonb not null default '{}'::jsonb
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_behaviour_snapshots'
      and column_name = 'protocol_mix'
  ) then
    execute $backfill$
      insert into vec_behaviour_snapshot_stats (
        snapshot_id, protocol_mix, frame_type_distribution,
        signal_min_dbm, signal_max_dbm, signal_avg_dbm,
        retry_count, protected_count, unprotected_count,
        unique_bssid_count, mac_rotation_indicators
      )
      select
        snapshot_id, protocol_mix, frame_type_distribution,
        signal_min_dbm, signal_max_dbm, signal_avg_dbm,
        retry_count, protected_count, unprotected_count,
        unique_bssid_count, mac_rotation_indicators
      from vec_behaviour_snapshots
      on conflict (snapshot_id) do update set
        protocol_mix = excluded.protocol_mix,
        frame_type_distribution = excluded.frame_type_distribution,
        signal_min_dbm = excluded.signal_min_dbm,
        signal_max_dbm = excluded.signal_max_dbm,
        signal_avg_dbm = excluded.signal_avg_dbm,
        retry_count = excluded.retry_count,
        protected_count = excluded.protected_count,
        unprotected_count = excluded.unprotected_count,
        unique_bssid_count = excluded.unique_bssid_count,
        mac_rotation_indicators = excluded.mac_rotation_indicators
    $backfill$;
  end if;
end;
$$;

create or replace function vec_behaviour_snapshots_legacy_to_stats()
returns trigger
language plpgsql
as $$
declare
  legacy jsonb := to_jsonb(new);
begin
  if pg_trigger_depth() > 1 or not (legacy ? 'protocol_mix') then
    return new;
  end if;

  insert into vec_behaviour_snapshot_stats (
    snapshot_id, protocol_mix, frame_type_distribution,
    signal_min_dbm, signal_max_dbm, signal_avg_dbm,
    retry_count, protected_count, unprotected_count,
    unique_bssid_count, mac_rotation_indicators
  )
  values (
    new.snapshot_id,
    coalesce(legacy->'protocol_mix', '{}'::jsonb),
    coalesce(legacy->'frame_type_distribution', '{}'::jsonb),
    (legacy->>'signal_min_dbm')::integer,
    (legacy->>'signal_max_dbm')::integer,
    (legacy->>'signal_avg_dbm')::numeric,
    coalesce((legacy->>'retry_count')::bigint, 0),
    coalesce((legacy->>'protected_count')::bigint, 0),
    coalesce((legacy->>'unprotected_count')::bigint, 0),
    coalesce((legacy->>'unique_bssid_count')::bigint, 0),
    coalesce(legacy->'mac_rotation_indicators', '{}'::jsonb)
  )
  on conflict (snapshot_id) do update set
    protocol_mix = excluded.protocol_mix,
    frame_type_distribution = excluded.frame_type_distribution,
    signal_min_dbm = excluded.signal_min_dbm,
    signal_max_dbm = excluded.signal_max_dbm,
    signal_avg_dbm = excluded.signal_avg_dbm,
    retry_count = excluded.retry_count,
    protected_count = excluded.protected_count,
    unprotected_count = excluded.unprotected_count,
    unique_bssid_count = excluded.unique_bssid_count,
    mac_rotation_indicators = excluded.mac_rotation_indicators;
  return new;
end;
$$;

create or replace function vec_behaviour_snapshot_stats_to_legacy()
returns trigger
language plpgsql
as $$
begin
  if pg_trigger_depth() > 1 or not exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_behaviour_snapshots'
      and column_name = 'protocol_mix'
  ) then
    return new;
  end if;

  execute $sync$
    update vec_behaviour_snapshots set
      protocol_mix = $1, frame_type_distribution = $2,
      signal_min_dbm = $3, signal_max_dbm = $4, signal_avg_dbm = $5,
      retry_count = $6, protected_count = $7, unprotected_count = $8,
      unique_bssid_count = $9, mac_rotation_indicators = $10
    where snapshot_id = $11
  $sync$ using
    new.protocol_mix, new.frame_type_distribution,
    new.signal_min_dbm, new.signal_max_dbm, new.signal_avg_dbm,
    new.retry_count, new.protected_count, new.unprotected_count,
    new.unique_bssid_count, new.mac_rotation_indicators, new.snapshot_id;
  return new;
end;
$$;

drop trigger if exists vec_behaviour_snapshots_legacy_to_stats on vec_behaviour_snapshots;
create trigger vec_behaviour_snapshots_legacy_to_stats
after insert or update on vec_behaviour_snapshots
for each row execute function vec_behaviour_snapshots_legacy_to_stats();

drop trigger if exists vec_behaviour_snapshot_stats_to_legacy on vec_behaviour_snapshot_stats;
create trigger vec_behaviour_snapshot_stats_to_legacy
after insert or update on vec_behaviour_snapshot_stats
for each row execute function vec_behaviour_snapshot_stats_to_legacy();

-- object: vec_embedding_sources
-- folder: tables
-- depends_on: vec_embeddings
create table if not exists vec_embedding_sources (
  embedding_id bigint primary key references vec_embeddings(embedding_id) on delete cascade,
  source_table text not null,
  source_key text not null,
  source_observed_at timestamptz,
  source_stream_name text,
  source_sensor_id text,
  source_location_id text,
  source_mac text,
  embedding_model text not null,
  embedding_kind text not null,
  constraint vec_embedding_sources_unique
    unique (source_table, source_key, embedding_model, embedding_kind)
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_embeddings'
      and column_name = 'source_table'
  ) then
    execute $backfill$
      insert into vec_embedding_sources (
        embedding_id, source_table, source_key, source_observed_at,
        source_stream_name, source_sensor_id, source_location_id, source_mac,
        embedding_model, embedding_kind
      )
      select
        embedding_id, source_table, source_key, source_observed_at,
        source_stream_name, source_sensor_id, source_location_id, source_mac,
        embedding_model, embedding_kind
      from vec_embeddings
      on conflict (embedding_id) do update set
        source_table = excluded.source_table,
        source_key = excluded.source_key,
        source_observed_at = excluded.source_observed_at,
        source_stream_name = excluded.source_stream_name,
        source_sensor_id = excluded.source_sensor_id,
        source_location_id = excluded.source_location_id,
        source_mac = excluded.source_mac,
        embedding_model = excluded.embedding_model,
        embedding_kind = excluded.embedding_kind
    $backfill$;
  end if;
end;
$$;

create or replace function vec_embeddings_legacy_to_source()
returns trigger
language plpgsql
as $$
declare
  legacy jsonb := to_jsonb(new);
begin
  if pg_trigger_depth() > 1 or not (legacy ? 'source_table') then
    return new;
  end if;

  insert into vec_embedding_sources (
    embedding_id, source_table, source_key, source_observed_at,
    source_stream_name, source_sensor_id, source_location_id, source_mac,
    embedding_model, embedding_kind
  )
  values (
    new.embedding_id,
    legacy->>'source_table',
    legacy->>'source_key',
    (legacy->>'source_observed_at')::timestamptz,
    legacy->>'source_stream_name',
    legacy->>'source_sensor_id',
    legacy->>'source_location_id',
    legacy->>'source_mac',
    new.embedding_model,
    new.embedding_kind
  )
  on conflict (embedding_id) do update set
    source_table = excluded.source_table,
    source_key = excluded.source_key,
    source_observed_at = excluded.source_observed_at,
    source_stream_name = excluded.source_stream_name,
    source_sensor_id = excluded.source_sensor_id,
    source_location_id = excluded.source_location_id,
    source_mac = excluded.source_mac,
    embedding_model = excluded.embedding_model,
    embedding_kind = excluded.embedding_kind;
  return new;
end;
$$;

create or replace function vec_embedding_sources_to_legacy()
returns trigger
language plpgsql
as $$
begin
  if pg_trigger_depth() > 1 or not exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_embeddings'
      and column_name = 'source_table'
  ) then
    return new;
  end if;

  execute $sync$
    update vec_embeddings set
      source_table = $1, source_key = $2, source_observed_at = $3,
      source_stream_name = $4, source_sensor_id = $5,
      source_location_id = $6, source_mac = $7
    where embedding_id = $8
  $sync$ using
    new.source_table, new.source_key, new.source_observed_at,
    new.source_stream_name, new.source_sensor_id,
    new.source_location_id, new.source_mac, new.embedding_id;
  return new;
end;
$$;

drop trigger if exists vec_embeddings_legacy_to_source on vec_embeddings;
create trigger vec_embeddings_legacy_to_source
after insert or update on vec_embeddings
for each row execute function vec_embeddings_legacy_to_source();

drop trigger if exists vec_embedding_sources_to_legacy on vec_embedding_sources;
create trigger vec_embedding_sources_to_legacy
after insert or update on vec_embedding_sources
for each row execute function vec_embedding_sources_to_legacy();

-- object: vec_embedding_job_leases
-- folder: tables
-- depends_on: vec_embedding_jobs
create table if not exists vec_embedding_job_leases (
  job_id bigint primary key references vec_embedding_jobs(job_id) on delete cascade,
  lease_token text,
  leased_at timestamptz,
  locked_by text,
  due_at timestamptz not null default now(),
  attempts integer not null default 0,
  max_attempts integer not null default 5,
  last_error text,
  completed_at timestamptz,
  constraint vec_embedding_job_leases_attempts_chk
    check (attempts >= 0 and max_attempts > 0)
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_embedding_jobs'
      and column_name = 'lease_token'
  ) then
    execute $backfill$
      insert into vec_embedding_job_leases (
        job_id, lease_token, leased_at, locked_by, due_at,
        attempts, max_attempts, last_error, completed_at
      )
      select
        job_id, lease_token, leased_at, locked_by, due_at,
        attempts, max_attempts, last_error, completed_at
      from vec_embedding_jobs
      on conflict (job_id) do update set
        lease_token = excluded.lease_token,
        leased_at = excluded.leased_at,
        locked_by = excluded.locked_by,
        due_at = excluded.due_at,
        attempts = excluded.attempts,
        max_attempts = excluded.max_attempts,
        last_error = excluded.last_error,
        completed_at = excluded.completed_at
    $backfill$;
  else
    insert into vec_embedding_job_leases (job_id)
    select job_id from vec_embedding_jobs
    on conflict (job_id) do nothing;
  end if;
end;
$$;

create or replace function vec_embedding_jobs_ensure_lease()
returns trigger
language plpgsql
as $$
declare
  legacy jsonb := to_jsonb(new);
  previous jsonb := case when tg_op = 'UPDATE' then to_jsonb(old) else '{}'::jsonb end;
begin
  if pg_trigger_depth() > 1 then
    return new;
  end if;

  if tg_op = 'UPDATE'
     and not (
       legacy->'lease_token' is distinct from previous->'lease_token'
       or legacy->'leased_at' is distinct from previous->'leased_at'
       or legacy->'locked_by' is distinct from previous->'locked_by'
       or legacy->'due_at' is distinct from previous->'due_at'
       or legacy->'attempts' is distinct from previous->'attempts'
       or legacy->'max_attempts' is distinct from previous->'max_attempts'
       or legacy->'last_error' is distinct from previous->'last_error'
       or legacy->'completed_at' is distinct from previous->'completed_at'
     ) then
    return new;
  end if;

  insert into vec_embedding_job_leases (
    job_id, lease_token, leased_at, locked_by, due_at,
    attempts, max_attempts, last_error, completed_at
  )
  values (
    new.job_id,
    legacy->>'lease_token',
    (legacy->>'leased_at')::timestamptz,
    legacy->>'locked_by',
    coalesce((legacy->>'due_at')::timestamptz, now()),
    coalesce((legacy->>'attempts')::integer, 0),
    coalesce((legacy->>'max_attempts')::integer, 5),
    legacy->>'last_error',
    (legacy->>'completed_at')::timestamptz
  )
  on conflict (job_id) do update set
    lease_token = case when legacy ? 'lease_token' then excluded.lease_token else vec_embedding_job_leases.lease_token end,
    leased_at = case when legacy ? 'leased_at' then excluded.leased_at else vec_embedding_job_leases.leased_at end,
    locked_by = case when legacy ? 'locked_by' then excluded.locked_by else vec_embedding_job_leases.locked_by end,
    due_at = case when legacy ? 'due_at' then excluded.due_at else vec_embedding_job_leases.due_at end,
    attempts = case when legacy ? 'attempts' then excluded.attempts else vec_embedding_job_leases.attempts end,
    max_attempts = case when legacy ? 'max_attempts' then excluded.max_attempts else vec_embedding_job_leases.max_attempts end,
    last_error = case when legacy ? 'last_error' then excluded.last_error else vec_embedding_job_leases.last_error end,
    completed_at = case when legacy ? 'completed_at' then excluded.completed_at else vec_embedding_job_leases.completed_at end;
  return new;
end;
$$;

create or replace function vec_embedding_job_leases_to_legacy()
returns trigger
language plpgsql
as $$
begin
  if pg_trigger_depth() > 1 or not exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_embedding_jobs'
      and column_name = 'lease_token'
  ) then
    return new;
  end if;

  execute $sync$
    update vec_embedding_jobs set
      lease_token = $1, leased_at = $2, locked_by = $3, due_at = $4,
      attempts = $5, max_attempts = $6, last_error = $7, completed_at = $8
    where job_id = $9
  $sync$ using
    new.lease_token, new.leased_at, new.locked_by, new.due_at,
    new.attempts, new.max_attempts, new.last_error, new.completed_at, new.job_id;
  return new;
end;
$$;

drop trigger if exists vec_embedding_jobs_ensure_lease on vec_embedding_jobs;
create trigger vec_embedding_jobs_ensure_lease
after insert or update on vec_embedding_jobs
for each row execute function vec_embedding_jobs_ensure_lease();

drop trigger if exists vec_embedding_job_leases_to_legacy on vec_embedding_job_leases;
create trigger vec_embedding_job_leases_to_legacy
after insert or update on vec_embedding_job_leases
for each row execute function vec_embedding_job_leases_to_legacy();

-- object: vec_similarity_pair_meta
-- folder: tables
-- depends_on: vec_similarity_pairs
create table if not exists vec_similarity_pair_meta (
  pair_id bigint primary key references vec_similarity_pairs(pair_id) on delete cascade,
  pair_kind text not null,
  embedding_model text not null,
  embedding_kind text not null,
  left_source_table text not null,
  left_source_key text not null,
  right_source_table text not null,
  right_source_key text not null,
  evidence jsonb not null default '{}'::jsonb,
  left_embedding_id bigint not null,
  right_embedding_id bigint not null,
  constraint vec_similarity_pair_meta_kind_chk
    check (pair_kind in ('event_event', 'device_device', 'cross_sensor', 'sequence_sequence', 'timing_timing')),
  constraint vec_similarity_pair_meta_unique
    unique (pair_kind, embedding_model, embedding_kind, left_embedding_id, right_embedding_id)
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_similarity_pairs'
      and column_name = 'pair_kind'
  ) then
    execute $backfill$
      insert into vec_similarity_pair_meta (
        pair_id, pair_kind, embedding_model, embedding_kind,
        left_source_table, left_source_key, right_source_table, right_source_key,
        evidence, left_embedding_id, right_embedding_id
      )
      select
        pair_id, pair_kind, embedding_model, embedding_kind,
        left_source_table, left_source_key, right_source_table, right_source_key,
        evidence, left_embedding_id, right_embedding_id
      from vec_similarity_pairs
      on conflict (pair_id) do update set
        pair_kind = excluded.pair_kind,
        embedding_model = excluded.embedding_model,
        embedding_kind = excluded.embedding_kind,
        left_source_table = excluded.left_source_table,
        left_source_key = excluded.left_source_key,
        right_source_table = excluded.right_source_table,
        right_source_key = excluded.right_source_key,
        evidence = excluded.evidence,
        left_embedding_id = excluded.left_embedding_id,
        right_embedding_id = excluded.right_embedding_id
    $backfill$;
  end if;
end;
$$;

create or replace function vec_similarity_pairs_legacy_to_meta()
returns trigger
language plpgsql
as $$
declare
  legacy jsonb := to_jsonb(new);
begin
  if pg_trigger_depth() > 1 or not (legacy ? 'pair_kind') then
    return new;
  end if;

  insert into vec_similarity_pair_meta (
    pair_id, pair_kind, embedding_model, embedding_kind,
    left_source_table, left_source_key, right_source_table, right_source_key,
    evidence, left_embedding_id, right_embedding_id
  )
  values (
    new.pair_id,
    legacy->>'pair_kind',
    legacy->>'embedding_model',
    legacy->>'embedding_kind',
    legacy->>'left_source_table',
    legacy->>'left_source_key',
    legacy->>'right_source_table',
    legacy->>'right_source_key',
    coalesce(legacy->'evidence', '{}'::jsonb),
    new.left_embedding_id,
    new.right_embedding_id
  )
  on conflict (pair_id) do update set
    pair_kind = excluded.pair_kind,
    embedding_model = excluded.embedding_model,
    embedding_kind = excluded.embedding_kind,
    left_source_table = excluded.left_source_table,
    left_source_key = excluded.left_source_key,
    right_source_table = excluded.right_source_table,
    right_source_key = excluded.right_source_key,
    evidence = excluded.evidence,
    left_embedding_id = excluded.left_embedding_id,
    right_embedding_id = excluded.right_embedding_id;
  return new;
end;
$$;

create or replace function vec_similarity_pair_meta_to_legacy()
returns trigger
language plpgsql
as $$
begin
  if pg_trigger_depth() > 1 or not exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'vec_similarity_pairs'
      and column_name = 'pair_kind'
  ) then
    return new;
  end if;

  execute $sync$
    update vec_similarity_pairs set
      pair_kind = $1, embedding_model = $2, embedding_kind = $3,
      left_source_table = $4, left_source_key = $5,
      left_source_mac = (select source_mac from vec_embedding_sources where embedding_id = $9),
      left_sensor_id = (select source_sensor_id from vec_embedding_sources where embedding_id = $9),
      left_location_id = (select source_location_id from vec_embedding_sources where embedding_id = $9),
      left_observed_at = (select source_observed_at from vec_embedding_sources where embedding_id = $9),
      right_source_table = $6, right_source_key = $7,
      right_source_mac = (select source_mac from vec_embedding_sources where embedding_id = $10),
      right_sensor_id = (select source_sensor_id from vec_embedding_sources where embedding_id = $10),
      right_location_id = (select source_location_id from vec_embedding_sources where embedding_id = $10),
      right_observed_at = (select source_observed_at from vec_embedding_sources where embedding_id = $10),
      evidence = $8
    where pair_id = $11
  $sync$ using
    new.pair_kind, new.embedding_model, new.embedding_kind,
    new.left_source_table, new.left_source_key,
    new.right_source_table, new.right_source_key, new.evidence,
    new.left_embedding_id, new.right_embedding_id, new.pair_id;
  return new;
end;
$$;

drop trigger if exists vec_similarity_pairs_legacy_to_meta on vec_similarity_pairs;
create trigger vec_similarity_pairs_legacy_to_meta
after insert or update on vec_similarity_pairs
for each row execute function vec_similarity_pairs_legacy_to_meta();

drop trigger if exists vec_similarity_pair_meta_to_legacy on vec_similarity_pair_meta;
create trigger vec_similarity_pair_meta_to_legacy
after insert or update on vec_similarity_pair_meta
for each row execute function vec_similarity_pair_meta_to_legacy();

-- object: wireless_frame_radio
-- folder: tables
-- depends_on: wireless_frames
create table if not exists wireless_frame_radio (
  dedupe_key text primary key references wireless_frames(dedupe_key) on delete cascade,
  signal_dbm integer,
  noise_dbm integer,
  frequency_mhz integer,
  channel_flags integer,
  data_rate_kbps integer,
  antenna_id integer,
  tsft bigint,
  fragment_number integer,
  channel_number integer,
  tsft_delta_us bigint,
  wall_clock_delta_ms bigint
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'wireless_frames'
      and column_name = 'signal_dbm'
  ) then
    execute $backfill$
      insert into wireless_frame_radio (
        dedupe_key, signal_dbm, noise_dbm, frequency_mhz, channel_flags,
        data_rate_kbps, antenna_id, tsft, fragment_number, channel_number,
        tsft_delta_us, wall_clock_delta_ms
      )
      select
        dedupe_key, signal_dbm, noise_dbm, frequency_mhz, channel_flags,
        data_rate_kbps, antenna_id, tsft, fragment_number, channel_number,
        tsft_delta_us, wall_clock_delta_ms
      from wireless_frames
      on conflict (dedupe_key) do update set
        signal_dbm = excluded.signal_dbm,
        noise_dbm = excluded.noise_dbm,
        frequency_mhz = excluded.frequency_mhz,
        channel_flags = excluded.channel_flags,
        data_rate_kbps = excluded.data_rate_kbps,
        antenna_id = excluded.antenna_id,
        tsft = excluded.tsft,
        fragment_number = excluded.fragment_number,
        channel_number = excluded.channel_number,
        tsft_delta_us = excluded.tsft_delta_us,
        wall_clock_delta_ms = excluded.wall_clock_delta_ms
    $backfill$;
  end if;
end;
$$;

-- object: wireless_frame_qos
-- folder: tables
-- depends_on: wireless_frames
create table if not exists wireless_frame_qos (
  dedupe_key text primary key references wireless_frames(dedupe_key) on delete cascade,
  qos_tid integer,
  qos_eosp boolean,
  qos_ack_policy integer,
  qos_ack_policy_label text,
  qos_amsdu boolean,
  more_data boolean not null default false,
  retry boolean not null default false,
  power_save boolean not null default false,
  protected boolean not null default false,
  frame_control_flags integer not null default 0
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'wireless_frames'
      and column_name = 'qos_tid'
  ) then
    execute $backfill$
      insert into wireless_frame_qos (
        dedupe_key, qos_tid, qos_eosp, qos_ack_policy, qos_ack_policy_label,
        qos_amsdu, more_data, retry, power_save, protected, frame_control_flags
      )
      select
        dedupe_key, qos_tid, qos_eosp, qos_ack_policy, qos_ack_policy_label,
        qos_amsdu, more_data, retry, power_save, protected, frame_control_flags
      from wireless_frames
      on conflict (dedupe_key) do update set
        qos_tid = excluded.qos_tid,
        qos_eosp = excluded.qos_eosp,
        qos_ack_policy = excluded.qos_ack_policy,
        qos_ack_policy_label = excluded.qos_ack_policy_label,
        qos_amsdu = excluded.qos_amsdu,
        more_data = excluded.more_data,
        retry = excluded.retry,
        power_save = excluded.power_save,
        protected = excluded.protected,
        frame_control_flags = excluded.frame_control_flags
    $backfill$;
  end if;
end;
$$;

-- object: wireless_frame_network
-- folder: tables
-- depends_on: wireless_frames
create table if not exists wireless_frame_network (
  dedupe_key text primary key references wireless_frames(dedupe_key) on delete cascade,
  llc_oui text,
  ethertype integer,
  ethertype_name text,
  src_ip text,
  dst_ip text,
  ip_ttl integer,
  ip_protocol integer,
  ip_protocol_name text,
  src_port integer,
  dst_port integer,
  transport_protocol text,
  transport_length integer,
  transport_checksum integer,
  app_protocol text
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'wireless_frames'
      and column_name = 'llc_oui'
  ) then
    execute $backfill$
      insert into wireless_frame_network (
        dedupe_key, llc_oui, ethertype, ethertype_name, src_ip, dst_ip,
        ip_ttl, ip_protocol, ip_protocol_name, src_port, dst_port,
        transport_protocol, transport_length, transport_checksum, app_protocol
      )
      select
        dedupe_key, llc_oui, ethertype, ethertype_name, src_ip, dst_ip,
        ip_ttl, ip_protocol, ip_protocol_name, src_port, dst_port,
        transport_protocol, transport_length, transport_checksum, app_protocol
      from wireless_frames
      on conflict (dedupe_key) do update set
        llc_oui = excluded.llc_oui,
        ethertype = excluded.ethertype,
        ethertype_name = excluded.ethertype_name,
        src_ip = excluded.src_ip,
        dst_ip = excluded.dst_ip,
        ip_ttl = excluded.ip_ttl,
        ip_protocol = excluded.ip_protocol,
        ip_protocol_name = excluded.ip_protocol_name,
        src_port = excluded.src_port,
        dst_port = excluded.dst_port,
        transport_protocol = excluded.transport_protocol,
        transport_length = excluded.transport_length,
        transport_checksum = excluded.transport_checksum,
        app_protocol = excluded.app_protocol
    $backfill$;
  end if;
end;
$$;

-- object: wireless_frame_app_signals
-- folder: tables
-- depends_on: wireless_frames
create table if not exists wireless_frame_app_signals (
  dedupe_key text primary key references wireless_frames(dedupe_key) on delete cascade,
  ssdp_message_type text,
  ssdp_st text,
  ssdp_mx text,
  ssdp_usn text,
  dhcp_requested_ip text,
  dhcp_hostname text,
  dhcp_vendor_class text,
  dns_query_name text,
  mdns_name text
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'wireless_frames'
      and column_name = 'ssdp_message_type'
  ) then
    execute $backfill$
      insert into wireless_frame_app_signals (
        dedupe_key, ssdp_message_type, ssdp_st, ssdp_mx, ssdp_usn,
        dhcp_requested_ip, dhcp_hostname, dhcp_vendor_class, dns_query_name, mdns_name
      )
      select
        dedupe_key, ssdp_message_type, ssdp_st, ssdp_mx, ssdp_usn,
        dhcp_requested_ip, dhcp_hostname, dhcp_vendor_class, dns_query_name, mdns_name
      from wireless_frames
      on conflict (dedupe_key) do update set
        ssdp_message_type = excluded.ssdp_message_type,
        ssdp_st = excluded.ssdp_st,
        ssdp_mx = excluded.ssdp_mx,
        ssdp_usn = excluded.ssdp_usn,
        dhcp_requested_ip = excluded.dhcp_requested_ip,
        dhcp_hostname = excluded.dhcp_hostname,
        dhcp_vendor_class = excluded.dhcp_vendor_class,
        dns_query_name = excluded.dns_query_name,
        mdns_name = excluded.mdns_name
    $backfill$;
  end if;
end;
$$;

-- object: wireless_frame_identity
-- folder: tables
-- depends_on: wireless_frames, wireless_frame_network
create table if not exists wireless_frame_identity (
  dedupe_key text primary key references wireless_frames(dedupe_key) on delete cascade,
  username text,
  event_type text,
  session_key text,
  retransmit_key text,
  frame_fingerprint text,
  payload_visibility text,
  identity_source text,
  device_fingerprint text,
  wps_device_name text,
  wps_manufacturer text,
  wps_model_name text,
  handshake_captured boolean not null default false,
  search_tsv tsvector
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'wireless_frames'
      and column_name = 'username'
  ) then
    execute $backfill$
      insert into wireless_frame_identity (
        dedupe_key, username, event_type, session_key, retransmit_key,
        frame_fingerprint, payload_visibility, identity_source, device_fingerprint,
        wps_device_name, wps_manufacturer, wps_model_name, handshake_captured
      )
      select
        dedupe_key, username, event_type, session_key, retransmit_key,
        frame_fingerprint, payload_visibility, identity_source, device_fingerprint,
        wps_device_name, wps_manufacturer, wps_model_name, handshake_captured
      from wireless_frames
      on conflict (dedupe_key) do update set
        username = excluded.username,
        event_type = excluded.event_type,
        session_key = excluded.session_key,
        retransmit_key = excluded.retransmit_key,
        frame_fingerprint = excluded.frame_fingerprint,
        payload_visibility = excluded.payload_visibility,
        identity_source = excluded.identity_source,
        device_fingerprint = excluded.device_fingerprint,
        wps_device_name = excluded.wps_device_name,
        wps_manufacturer = excluded.wps_manufacturer,
        wps_model_name = excluded.wps_model_name,
        handshake_captured = excluded.handshake_captured
    $backfill$;
  end if;
end;
$$;

create or replace function wireless_frame_identity_search_tsv()
returns trigger
language plpgsql
as $$
declare
  core wireless_frames%rowtype;
  network wireless_frame_network%rowtype;
begin
  select * into core from wireless_frames where dedupe_key = new.dedupe_key;
  select * into network from wireless_frame_network where dedupe_key = new.dedupe_key;

  new.search_tsv := to_tsvector(
    'simple'::regconfig,
    lower(concat_ws(
      ' ', core.sensor_id, core.source_mac, core.bssid, core.destination_bssid, core.ssid,
      new.wps_device_name, new.wps_manufacturer, new.wps_model_name, new.device_fingerprint,
      network.app_protocol, network.src_ip, network.dst_ip, new.username
    ))
  );
  return new;
end;
$$;

drop trigger if exists wireless_frame_identity_search_tsv on wireless_frame_identity;
create trigger wireless_frame_identity_search_tsv
before insert or update on wireless_frame_identity
for each row execute function wireless_frame_identity_search_tsv();

-- object: wireless_frame_security
-- folder: tables
-- depends_on: wireless_frames
create table if not exists wireless_frame_security (
  dedupe_key text primary key references wireless_frames(dedupe_key) on delete cascade,
  large_frame boolean not null default false,
  mixed_encryption boolean,
  dedupe_or_replay_suspect boolean not null default false,
  raw_len integer not null default 0,
  security_flags integer not null default 0,
  risk_score double precision,
  tags jsonb not null default '[]'::jsonb,
  signal_status text,
  adjacent_mac_hint text
);

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'wireless_frames'
      and column_name = 'large_frame'
  ) then
    execute $backfill$
      insert into wireless_frame_security (
        dedupe_key, large_frame, mixed_encryption, dedupe_or_replay_suspect,
        raw_len, security_flags, risk_score, tags, signal_status, adjacent_mac_hint
      )
      select
        dedupe_key, large_frame, mixed_encryption, dedupe_or_replay_suspect,
        raw_len, security_flags, risk_score, tags, signal_status, adjacent_mac_hint
      from wireless_frames
      on conflict (dedupe_key) do update set
        large_frame = excluded.large_frame,
        mixed_encryption = excluded.mixed_encryption,
        dedupe_or_replay_suspect = excluded.dedupe_or_replay_suspect,
        raw_len = excluded.raw_len,
        security_flags = excluded.security_flags,
        risk_score = excluded.risk_score,
        tags = excluded.tags,
        signal_status = excluded.signal_status,
        adjacent_mac_hint = excluded.adjacent_mac_hint
    $backfill$;
  end if;
end;
$$;

create or replace function wireless_frames_legacy_to_split()
returns trigger
language plpgsql
as $$
declare
  legacy jsonb := to_jsonb(new);
begin
  if pg_trigger_depth() > 1 or not (legacy ? 'signal_dbm') then
    return new;
  end if;

  insert into wireless_frame_radio (
    dedupe_key, signal_dbm, noise_dbm, frequency_mhz, channel_flags,
    data_rate_kbps, antenna_id, tsft, fragment_number, channel_number,
    tsft_delta_us, wall_clock_delta_ms
  ) values (
    new.dedupe_key,
    (legacy->>'signal_dbm')::integer,
    (legacy->>'noise_dbm')::integer,
    (legacy->>'frequency_mhz')::integer,
    (legacy->>'channel_flags')::integer,
    (legacy->>'data_rate_kbps')::integer,
    (legacy->>'antenna_id')::integer,
    (legacy->>'tsft')::bigint,
    (legacy->>'fragment_number')::integer,
    (legacy->>'channel_number')::integer,
    (legacy->>'tsft_delta_us')::bigint,
    (legacy->>'wall_clock_delta_ms')::bigint
  ) on conflict (dedupe_key) do update set
    signal_dbm = excluded.signal_dbm,
    noise_dbm = excluded.noise_dbm,
    frequency_mhz = excluded.frequency_mhz,
    channel_flags = excluded.channel_flags,
    data_rate_kbps = excluded.data_rate_kbps,
    antenna_id = excluded.antenna_id,
    tsft = excluded.tsft,
    fragment_number = excluded.fragment_number,
    channel_number = excluded.channel_number,
    tsft_delta_us = excluded.tsft_delta_us,
    wall_clock_delta_ms = excluded.wall_clock_delta_ms;

  insert into wireless_frame_qos (
    dedupe_key, qos_tid, qos_eosp, qos_ack_policy, qos_ack_policy_label,
    qos_amsdu, more_data, retry, power_save, protected, frame_control_flags
  ) values (
    new.dedupe_key,
    (legacy->>'qos_tid')::integer,
    (legacy->>'qos_eosp')::boolean,
    (legacy->>'qos_ack_policy')::integer,
    legacy->>'qos_ack_policy_label',
    (legacy->>'qos_amsdu')::boolean,
    coalesce((legacy->>'more_data')::boolean, false),
    coalesce((legacy->>'retry')::boolean, false),
    coalesce((legacy->>'power_save')::boolean, false),
    coalesce((legacy->>'protected')::boolean, false),
    coalesce((legacy->>'frame_control_flags')::integer, 0)
  ) on conflict (dedupe_key) do update set
    qos_tid = excluded.qos_tid,
    qos_eosp = excluded.qos_eosp,
    qos_ack_policy = excluded.qos_ack_policy,
    qos_ack_policy_label = excluded.qos_ack_policy_label,
    qos_amsdu = excluded.qos_amsdu,
    more_data = excluded.more_data,
    retry = excluded.retry,
    power_save = excluded.power_save,
    protected = excluded.protected,
    frame_control_flags = excluded.frame_control_flags;

  insert into wireless_frame_network (
    dedupe_key, llc_oui, ethertype, ethertype_name, src_ip, dst_ip,
    ip_ttl, ip_protocol, ip_protocol_name, src_port, dst_port,
    transport_protocol, transport_length, transport_checksum, app_protocol
  ) values (
    new.dedupe_key,
    legacy->>'llc_oui',
    (legacy->>'ethertype')::integer,
    legacy->>'ethertype_name',
    legacy->>'src_ip',
    legacy->>'dst_ip',
    (legacy->>'ip_ttl')::integer,
    (legacy->>'ip_protocol')::integer,
    legacy->>'ip_protocol_name',
    (legacy->>'src_port')::integer,
    (legacy->>'dst_port')::integer,
    legacy->>'transport_protocol',
    (legacy->>'transport_length')::integer,
    (legacy->>'transport_checksum')::integer,
    legacy->>'app_protocol'
  ) on conflict (dedupe_key) do update set
    llc_oui = excluded.llc_oui,
    ethertype = excluded.ethertype,
    ethertype_name = excluded.ethertype_name,
    src_ip = excluded.src_ip,
    dst_ip = excluded.dst_ip,
    ip_ttl = excluded.ip_ttl,
    ip_protocol = excluded.ip_protocol,
    ip_protocol_name = excluded.ip_protocol_name,
    src_port = excluded.src_port,
    dst_port = excluded.dst_port,
    transport_protocol = excluded.transport_protocol,
    transport_length = excluded.transport_length,
    transport_checksum = excluded.transport_checksum,
    app_protocol = excluded.app_protocol;

  insert into wireless_frame_app_signals (
    dedupe_key, ssdp_message_type, ssdp_st, ssdp_mx, ssdp_usn,
    dhcp_requested_ip, dhcp_hostname, dhcp_vendor_class, dns_query_name, mdns_name
  ) values (
    new.dedupe_key,
    legacy->>'ssdp_message_type',
    legacy->>'ssdp_st',
    legacy->>'ssdp_mx',
    legacy->>'ssdp_usn',
    legacy->>'dhcp_requested_ip',
    legacy->>'dhcp_hostname',
    legacy->>'dhcp_vendor_class',
    legacy->>'dns_query_name',
    legacy->>'mdns_name'
  ) on conflict (dedupe_key) do update set
    ssdp_message_type = excluded.ssdp_message_type,
    ssdp_st = excluded.ssdp_st,
    ssdp_mx = excluded.ssdp_mx,
    ssdp_usn = excluded.ssdp_usn,
    dhcp_requested_ip = excluded.dhcp_requested_ip,
    dhcp_hostname = excluded.dhcp_hostname,
    dhcp_vendor_class = excluded.dhcp_vendor_class,
    dns_query_name = excluded.dns_query_name,
    mdns_name = excluded.mdns_name;

  insert into wireless_frame_identity (
    dedupe_key, username, event_type, session_key, retransmit_key,
    frame_fingerprint, payload_visibility, identity_source, device_fingerprint,
    wps_device_name, wps_manufacturer, wps_model_name, handshake_captured
  ) values (
    new.dedupe_key,
    legacy->>'username',
    legacy->>'event_type',
    legacy->>'session_key',
    legacy->>'retransmit_key',
    legacy->>'frame_fingerprint',
    legacy->>'payload_visibility',
    legacy->>'identity_source',
    legacy->>'device_fingerprint',
    legacy->>'wps_device_name',
    legacy->>'wps_manufacturer',
    legacy->>'wps_model_name',
    coalesce((legacy->>'handshake_captured')::boolean, false)
  ) on conflict (dedupe_key) do update set
    username = excluded.username,
    event_type = excluded.event_type,
    session_key = excluded.session_key,
    retransmit_key = excluded.retransmit_key,
    frame_fingerprint = excluded.frame_fingerprint,
    payload_visibility = excluded.payload_visibility,
    identity_source = excluded.identity_source,
    device_fingerprint = excluded.device_fingerprint,
    wps_device_name = excluded.wps_device_name,
    wps_manufacturer = excluded.wps_manufacturer,
    wps_model_name = excluded.wps_model_name,
    handshake_captured = excluded.handshake_captured;

  insert into wireless_frame_security (
    dedupe_key, large_frame, mixed_encryption, dedupe_or_replay_suspect,
    raw_len, security_flags, risk_score, tags, signal_status, adjacent_mac_hint
  ) values (
    new.dedupe_key,
    coalesce((legacy->>'large_frame')::boolean, false),
    (legacy->>'mixed_encryption')::boolean,
    coalesce((legacy->>'dedupe_or_replay_suspect')::boolean, false),
    coalesce((legacy->>'raw_len')::integer, 0),
    coalesce((legacy->>'security_flags')::integer, 0),
    (legacy->>'risk_score')::double precision,
    coalesce(legacy->'tags', '[]'::jsonb),
    legacy->>'signal_status',
    legacy->>'adjacent_mac_hint'
  ) on conflict (dedupe_key) do update set
    large_frame = excluded.large_frame,
    mixed_encryption = excluded.mixed_encryption,
    dedupe_or_replay_suspect = excluded.dedupe_or_replay_suspect,
    raw_len = excluded.raw_len,
    security_flags = excluded.security_flags,
    risk_score = excluded.risk_score,
    tags = excluded.tags,
    signal_status = excluded.signal_status,
    adjacent_mac_hint = excluded.adjacent_mac_hint;

  return new;
end;
$$;

create or replace function wireless_frame_split_to_legacy()
returns trigger
language plpgsql
as $$
begin
  if pg_trigger_depth() > 1 or not exists (
    select 1 from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'wireless_frames'
      and column_name = 'signal_dbm'
  ) then
    return new;
  end if;

  if tg_table_name = 'wireless_frame_radio' then
    execute $sync$
      update wireless_frames set
        signal_dbm = $1, noise_dbm = $2, frequency_mhz = $3,
        channel_flags = $4, data_rate_kbps = $5, antenna_id = $6,
        tsft = $7, fragment_number = $8, channel_number = $9,
        tsft_delta_us = $10, wall_clock_delta_ms = $11
      where dedupe_key = $12
    $sync$ using
      new.signal_dbm, new.noise_dbm, new.frequency_mhz,
      new.channel_flags, new.data_rate_kbps, new.antenna_id,
      new.tsft, new.fragment_number, new.channel_number,
      new.tsft_delta_us, new.wall_clock_delta_ms, new.dedupe_key;
  elsif tg_table_name = 'wireless_frame_qos' then
    execute $sync$
      update wireless_frames set
        qos_tid = $1, qos_eosp = $2, qos_ack_policy = $3,
        qos_ack_policy_label = $4, qos_amsdu = $5,
        more_data = $6, retry = $7, power_save = $8,
        protected = $9, frame_control_flags = $10
      where dedupe_key = $11
    $sync$ using
      new.qos_tid, new.qos_eosp, new.qos_ack_policy,
      new.qos_ack_policy_label, new.qos_amsdu,
      new.more_data, new.retry, new.power_save,
      new.protected, new.frame_control_flags, new.dedupe_key;
  elsif tg_table_name = 'wireless_frame_network' then
    execute $sync$
      update wireless_frames set
        llc_oui = $1, ethertype = $2, ethertype_name = $3,
        src_ip = $4, dst_ip = $5, ip_ttl = $6, ip_protocol = $7,
        ip_protocol_name = $8, src_port = $9, dst_port = $10,
        transport_protocol = $11, transport_length = $12,
        transport_checksum = $13, app_protocol = $14
      where dedupe_key = $15
    $sync$ using
      new.llc_oui, new.ethertype, new.ethertype_name,
      new.src_ip, new.dst_ip, new.ip_ttl, new.ip_protocol,
      new.ip_protocol_name, new.src_port, new.dst_port,
      new.transport_protocol, new.transport_length,
      new.transport_checksum, new.app_protocol, new.dedupe_key;
  elsif tg_table_name = 'wireless_frame_app_signals' then
    execute $sync$
      update wireless_frames set
        ssdp_message_type = $1, ssdp_st = $2, ssdp_mx = $3, ssdp_usn = $4,
        dhcp_requested_ip = $5, dhcp_hostname = $6, dhcp_vendor_class = $7,
        dns_query_name = $8, mdns_name = $9
      where dedupe_key = $10
    $sync$ using
      new.ssdp_message_type, new.ssdp_st, new.ssdp_mx, new.ssdp_usn,
      new.dhcp_requested_ip, new.dhcp_hostname, new.dhcp_vendor_class,
      new.dns_query_name, new.mdns_name, new.dedupe_key;
  elsif tg_table_name = 'wireless_frame_identity' then
    execute $sync$
      update wireless_frames set
        username = $1, event_type = $2, session_key = $3, retransmit_key = $4,
        frame_fingerprint = $5, payload_visibility = $6, identity_source = $7,
        device_fingerprint = $8, wps_device_name = $9,
        wps_manufacturer = $10, wps_model_name = $11, handshake_captured = $12
      where dedupe_key = $13
    $sync$ using
      new.username, new.event_type, new.session_key, new.retransmit_key,
      new.frame_fingerprint, new.payload_visibility, new.identity_source,
      new.device_fingerprint, new.wps_device_name,
      new.wps_manufacturer, new.wps_model_name, new.handshake_captured, new.dedupe_key;
  elsif tg_table_name = 'wireless_frame_security' then
    execute $sync$
      update wireless_frames set
        large_frame = $1, mixed_encryption = $2, dedupe_or_replay_suspect = $3,
        raw_len = $4, security_flags = $5, risk_score = $6, tags = $7,
        signal_status = $8, adjacent_mac_hint = $9
      where dedupe_key = $10
    $sync$ using
      new.large_frame, new.mixed_encryption, new.dedupe_or_replay_suspect,
      new.raw_len, new.security_flags, new.risk_score, new.tags,
      new.signal_status, new.adjacent_mac_hint, new.dedupe_key;
  end if;

  return new;
end;
$$;

drop trigger if exists wireless_frames_legacy_to_split on wireless_frames;
create trigger wireless_frames_legacy_to_split
after insert or update on wireless_frames
for each row execute function wireless_frames_legacy_to_split();

drop trigger if exists wireless_frame_radio_to_legacy on wireless_frame_radio;
create trigger wireless_frame_radio_to_legacy after insert or update on wireless_frame_radio
for each row execute function wireless_frame_split_to_legacy();

drop trigger if exists wireless_frame_qos_to_legacy on wireless_frame_qos;
create trigger wireless_frame_qos_to_legacy after insert or update on wireless_frame_qos
for each row execute function wireless_frame_split_to_legacy();

drop trigger if exists wireless_frame_network_to_legacy on wireless_frame_network;
create trigger wireless_frame_network_to_legacy after insert or update on wireless_frame_network
for each row execute function wireless_frame_split_to_legacy();

drop trigger if exists wireless_frame_app_signals_to_legacy on wireless_frame_app_signals;
create trigger wireless_frame_app_signals_to_legacy after insert or update on wireless_frame_app_signals
for each row execute function wireless_frame_split_to_legacy();

drop trigger if exists wireless_frame_identity_to_legacy on wireless_frame_identity;
create trigger wireless_frame_identity_to_legacy after insert or update on wireless_frame_identity
for each row execute function wireless_frame_split_to_legacy();

drop trigger if exists wireless_frame_security_to_legacy on wireless_frame_security;
create trigger wireless_frame_security_to_legacy after insert or update on wireless_frame_security
for each row execute function wireless_frame_split_to_legacy();

-- object: sync plane indexes
-- folder: indexes
-- depends_on: sync_* tables
create index if not exists sync_events_status_idx on sync_events (status, observed_at);

create index if not exists sync_events_stream_idx on sync_events (stream_name, observed_at);

create index if not exists sync_events_ready_idx on sync_events (status, stream_name, observed_at) where status in ('pending', 'failed');

create index if not exists sync_events_wireless_observed_idx
  on sync_events (observed_at desc)
  where stream_name = 'wireless.audit'
    and status = 'batched';

create index if not exists sync_events_processing_idx on sync_events (updated_at) where status = 'processing';

create index if not exists sync_jobs_stream_name_idx on sync_jobs (stream_name);

create index if not exists sync_jobs_status_created_at_idx on sync_jobs (status, created_at);

create index if not exists sync_batches_job_batch_no_idx on sync_batches (job_id, batch_no);

create index if not exists sync_batches_status_idx on sync_batches (status);

create index if not exists sync_batches_pending_idx on sync_batches (status, batch_id) where status = 'pending';

create index if not exists sync_batches_dispatch_lease_idx on sync_batches (status, updated_at) where status in ('dispatched', 'failed');

create index if not exists sync_errors_job_id_idx on sync_errors (job_id);

create index if not exists sync_errors_batch_id_idx on sync_errors (batch_id);

create index if not exists sync_backlog_status_idx on sync_backlog (status, updated_at);

create index if not exists wireless_authorized_networks_enabled_idx on wireless_authorized_networks (enabled, location_id);

create unique index if not exists wireless_authorized_networks_match_idx on wireless_authorized_networks (coalesce(lower(ssid), ''), coalesce(lower(bssid), ''), coalesce(location_id, ''));

create index if not exists wireless_clients_client_mac_idx on wireless_clients (client_mac);

create index if not exists wireless_clients_last_seen_idx on wireless_clients (last_seen desc);

create index if not exists wireless_clients_known_bssid_idx on wireless_clients (known_bssid) where known_bssid is not null;

create index if not exists wireless_shadow_alerts_open_idx on wireless_shadow_alerts (last_occurred_at desc) where resolved_at is null;

create index if not exists devices_wg_pubkey_idx on devices (wg_pubkey);

create index if not exists devices_username_idx on devices (username, last_seen desc);

-- object: wireless_frames indexes
-- folder: indexes
-- depends_on: wireless_frames
create index if not exists wireless_frames_ssid_idx on wireless_frames (ssid);

create index if not exists wireless_frames_source_mac_idx on wireless_frames (lower(source_mac));

create index if not exists wireless_frames_bssid_idx on wireless_frames (lower(bssid));

create index if not exists wireless_frames_bssid_updated_idx
  on wireless_frames (lower(bssid), updated_at desc)
  where bssid is not null;

create index if not exists wireless_frames_destination_bssid_idx on wireless_frames (lower(destination_bssid));

create index if not exists wireless_frames_destination_bssid_updated_idx
  on wireless_frames (lower(destination_bssid), updated_at desc)
  where destination_bssid is not null;

create index if not exists wireless_frames_bssid_oui_idx
  on wireless_frames (bssid_oui)
  where bssid_oui is not null;

create index if not exists wireless_frames_schema_version_idx on wireless_frames (schema_version);

create index if not exists wireless_frames_signal_idx on wireless_frame_radio (signal_dbm) where signal_dbm is not null;

create index if not exists wireless_frames_src_ip_idx on wireless_frame_network (src_ip) where src_ip is not null;

create index if not exists wireless_frames_dst_ip_idx on wireless_frame_network (dst_ip) where dst_ip is not null;

create index if not exists wireless_frames_app_protocol_idx on wireless_frame_network (app_protocol) where app_protocol is not null;

create index if not exists wireless_frames_session_key_idx on wireless_frame_identity (session_key) where session_key is not null;

create index if not exists wireless_frames_fingerprint_idx on wireless_frame_identity (frame_fingerprint) where frame_fingerprint is not null;

create index if not exists wireless_frames_search_tsv_idx on wireless_frame_identity using gin (search_tsv);

create index if not exists wireless_frames_common_search_idx on wireless_frames using gin ((
  lower(coalesce(sensor_id, '')) || ' ' || lower(coalesce(source_mac, '')) || ' ' || lower(coalesce(ssid, ''))
) gin_trgm_ops);

create index if not exists wireless_frames_device_fingerprint_idx on wireless_frame_identity (device_fingerprint) where device_fingerprint is not null;

create index if not exists wireless_frames_security_flags_idx on wireless_frame_security (security_flags) where security_flags <> 0;

create index if not exists wireless_frames_handshake_captured_idx on wireless_frame_identity (dedupe_key) where handshake_captured;

create index if not exists wireless_frames_tags_idx on wireless_frame_security using gin (tags);

create index if not exists wireless_frames_risk_score_idx
  on wireless_frame_security (risk_score desc)
  where risk_score is not null;

create index if not exists wireless_frames_event_type_idx
  on wireless_frame_identity (event_type)
  where event_type is not null;

-- object: vec_embeddings indexes
-- folder: indexes
-- depends_on: vec_embeddings
create index if not exists vec_embeddings_source_idx
  on vec_embedding_sources (source_table, source_key);

create index if not exists vec_embeddings_kind_model_idx
  on vec_embeddings (embedding_kind, embedding_model, embedded_at desc);

create index if not exists vec_embeddings_source_mac_idx
  on vec_embedding_sources (lower(source_mac), source_observed_at desc)
  where source_mac is not null;

create index if not exists vec_embeddings_event_hnsw_768_idx
  on vec_embeddings using hnsw ((embedding::vector(768)) vector_cosine_ops)
  where embedding_kind = 'event'
    and embedding_model = 'nomic-embed-text-v2-moe'
    and embedding_dimensions = 768;

create index if not exists vec_embeddings_device_hnsw_768_idx
  on vec_embeddings using hnsw ((embedding::vector(768)) vector_cosine_ops)
  where embedding_kind = 'device'
    and embedding_model = 'nomic-embed-text-v2-moe'
    and embedding_dimensions = 768;

create index if not exists vec_embeddings_behaviour_hnsw_768_idx
  on vec_embeddings using hnsw ((embedding::vector(768)) vector_cosine_ops)
  where embedding_kind = 'behaviour_window'
    and embedding_model = 'nomic-embed-text-v2-moe'
    and embedding_dimensions = 768;

create index if not exists vec_embeddings_frame_sequence_hnsw_768_idx
  on vec_embeddings using hnsw ((embedding::vector(768)) vector_cosine_ops)
  where embedding_kind = 'frame_sequence'
    and embedding_model = 'nomic-embed-text-v2-moe'
    and embedding_dimensions = 768;

create index if not exists vec_embeddings_timing_hnsw_768_idx
  on vec_embeddings using hnsw ((embedding::vector(768)) vector_cosine_ops)
  where embedding_kind = 'timing_profile'
    and embedding_model = 'nomic-embed-text-v2-moe'
    and embedding_dimensions = 768;

-- object: vec_behaviour_snapshots indexes
-- folder: indexes
-- depends_on: vec_behaviour_snapshots
create index if not exists vec_behaviour_snapshots_mac_time_idx
  on vec_behaviour_snapshots (source_mac, window_start desc);

create index if not exists vec_behaviour_snapshots_location_time_idx
  on vec_behaviour_snapshots (location_id, window_start desc);

-- object: vec_frame_sequences indexes
-- folder: indexes
-- depends_on: vec_frame_sequences
create index if not exists vec_frame_sequences_sensor_idx
  on vec_frame_sequences (sensor_id, window_start desc);

create index if not exists vec_frame_sequences_location_idx
  on vec_frame_sequences (location_id, window_start desc);

-- object: vec_transition_model indexes
-- folder: indexes
-- depends_on: vec_transition_model
create index if not exists vec_transition_model_prev_idx
  on vec_transition_model (prev_token, embedding_kind);

-- object: vec_infrastructure_graph indexes
-- folder: indexes
-- depends_on: vec_infrastructure_graph
create index if not exists vec_infrastructure_graph_node_a_idx
  on vec_infrastructure_graph (node_a_type, node_a, edge_type, last_seen desc);

create index if not exists vec_infrastructure_graph_node_b_idx
  on vec_infrastructure_graph (node_b_type, node_b, edge_type, last_seen desc);

-- object: vec_similarity_pairs indexes
-- folder: indexes
-- depends_on: vec_similarity_pairs
create index if not exists vec_similarity_pairs_kind_idx
  on vec_similarity_pair_meta (pair_kind, embedding_model, embedding_kind, pair_id);

create index if not exists vec_similarity_pairs_score_idx
  on vec_similarity_pairs (cosine_similarity desc, pair_id);

create index if not exists vec_similarity_pairs_left_source_idx
  on vec_similarity_pair_meta (left_source_table, left_source_key);

create index if not exists vec_similarity_pairs_right_source_idx
  on vec_similarity_pair_meta (right_source_table, right_source_key);

create index if not exists vec_similarity_pairs_left_embedding_idx
  on vec_similarity_pairs (left_embedding_id);

create index if not exists vec_similarity_pairs_right_embedding_idx
  on vec_similarity_pairs (right_embedding_id);

create index if not exists vec_similarity_pairs_computed_idx
  on vec_similarity_pairs (computed_at desc, pair_id);

-- object: vec_embedding_jobs indexes
-- folder: indexes
-- depends_on: vec_embedding_jobs
create index if not exists vec_embedding_jobs_pending_idx
  on vec_embedding_jobs (status, priority, job_id)
  where status in ('pending', 'failed');

create index if not exists vec_embedding_jobs_pending_kind_idx
  on vec_embedding_jobs (embedding_kind, status, priority, job_id)
  where status in ('pending', 'failed');

create index if not exists vec_embedding_jobs_lease_idx
  on vec_embedding_job_leases (leased_at, due_at, job_id)
  where leased_at is not null;

create index if not exists vec_embedding_jobs_lease_kind_idx
  on vec_embedding_job_leases (due_at, attempts, max_attempts, job_id);

create index if not exists vec_embedding_jobs_completion_idx
  on vec_embedding_job_leases (job_id, lease_token);

-- object: vec_alerts indexes
-- folder: indexes
-- depends_on: vec_alerts
CREATE INDEX IF NOT EXISTS idx_vec_alerts_type_created
    ON vec_alerts (alert_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_mac
    ON vec_alerts (source_mac);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_created
    ON vec_alerts (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_metadata_bssid
    ON vec_alerts ((metadata->>'bssid'))
    WHERE metadata->>'bssid' IS NOT NULL;

-- V022: Add composite index for vec_alerts near-duplicate dedupe predicate
--
-- check_near_duplicates filters by alert_type, source_mac, and recent
-- created_at. A single composite index serves that predicate more efficiently
-- than the three separate indexes added in V020.
--
-- The existing indexes (idx_vec_alerts_type_created, idx_vec_alerts_mac,
-- idx_vec_alerts_created) are left in place since they may serve other
-- query patterns.

CREATE INDEX IF NOT EXISTS idx_vec_alerts_type_mac_created
    ON vec_alerts (alert_type, source_mac, created_at DESC);

-- object: device_identity_clusters indexes
-- folder: indexes
-- depends_on: device_identity_clusters
-- GIN index for fast membership lookups via ANY(mac_ids)
create index if not exists idx_device_identity_clusters_mac_ids
  on device_identity_clusters using gin (mac_ids);

-- object: vec_timing_profiles indexes
-- folder: indexes
-- depends_on: vec_timing_profiles
create index if not exists vec_timing_profiles_source_mac_idx
  on vec_timing_profiles (source_mac, window_start desc);

create index if not exists vec_timing_profiles_sensor_window_idx
  on vec_timing_profiles (sensor_id, location_id, window_start desc);

-- object: sync_events_wireless_batched_updated_idx (replacement)
-- folder: indexes
-- depends_on: sync_events
-- Extracted from 001_sync_events_indexes.sql to avoid modifying the historical
-- migration. Created by 044_vec_complete_embedding_batch_replace.sql.
create index if not exists sync_events_wireless_batched_updated_idx
  on sync_events (updated_at, dedupe_key)
  where stream_name = 'wireless.audit'
    and status = 'batched';
-- object: vector detector support indexes
-- folder: indexes
-- depends_on: vec_rf_sensor_locations, vec_dns_policy, vec_dns_resolver_ledger, vec_alerts
create index if not exists vec_rf_sensor_locations_enabled_idx
  on vec_rf_sensor_locations (sensor_id, location_id)
  where enabled;

create index if not exists vec_dns_policy_secure_required_idx
  on vec_dns_policy (wg_pubkey)
  where policy = 'secure_required';

create index if not exists vec_dns_resolver_ledger_pubkey_time_idx
  on vec_dns_resolver_ledger (wg_pubkey, observed_at desc);

create index if not exists vec_dns_resolver_ledger_query_hash_idx
  on vec_dns_resolver_ledger (wg_pubkey, query_name_hash, observed_at desc)
  where query_name_hash is not null;

create index if not exists vec_alerts_metadata_wg_pubkey_idx
  on vec_alerts ((metadata->>'wg_pubkey'))
  where metadata ? 'wg_pubkey';

create index if not exists vec_alerts_metadata_cluster_id_idx
  on vec_alerts ((metadata->>'cluster_id'))
  where metadata ? 'cluster_id';

create index if not exists vec_alerts_metadata_session_key_idx
  on vec_alerts ((metadata->>'session_key'))
  where metadata ? 'session_key';

-- object: sync event retention indexes
-- folder: indexes
-- depends_on: sync_event_payload_archives, sync_event_tombstones
create index if not exists sync_event_payload_archives_observed_idx
  on sync_event_payload_archives (stream_name, observed_at desc);

create index if not exists sync_event_payload_archives_archived_idx
  on sync_event_payload_archives (archived_at desc);

create index if not exists sync_event_tombstones_expires_idx
  on sync_event_tombstones (expires_at);

create index if not exists sync_event_tombstones_stream_observed_idx
  on sync_event_tombstones (stream_name, observed_at desc);

-- object: device_graph_workmap_indexes
-- folder: indexes
-- depends_on: sync_events, sync_backlog, wireless_frames, vec_dns_resolver_ledger, vec_infrastructure_graph, search_feedback

create index if not exists sync_events_stream_status_idx
  on sync_events (stream_name, status)
  where status in ('pending', 'processing');

create index if not exists sync_backlog_retry_ready_idx
  on sync_backlog (status, updated_at)
  where status = 'pending'
    and attempt_count < max_attempts;

create index if not exists wireless_frames_source_mac_time_idx
  on wireless_frames (lower(source_mac), created_at desc)
  where source_mac is not null;

create index if not exists vec_dns_resolver_ledger_expires_idx
  on vec_dns_resolver_ledger (expires_at);

create index if not exists vec_infrastructure_graph_last_seen_idx
  on vec_infrastructure_graph (last_seen);

create index if not exists vec_infrastructure_graph_node_a_lookup_idx
  on vec_infrastructure_graph (node_a, node_a_type, last_seen desc);

create index if not exists vec_infrastructure_graph_node_b_lookup_idx
  on vec_infrastructure_graph (node_b, node_b_type, last_seen desc);

create index if not exists search_feedback_created_idx
  on search_feedback (created_at desc);

-- object: graph SSID indexes
-- folder: indexes
-- depends_on: wireless_frames, wireless_clients, wireless_shadow_alerts, wireless_authorized_networks
create index if not exists wireless_frames_graph_ssid_trgm_idx
  on wireless_frames using gin (lower(coalesce(ssid, '')) gin_trgm_ops)
  where nullif(ssid, '') is not null;

create index if not exists wireless_clients_graph_ssid_trgm_idx
  on wireless_clients using gin (lower(coalesce(ssid, '')) gin_trgm_ops)
  where nullif(ssid, '') is not null;

create index if not exists wireless_shadow_alerts_graph_ssid_trgm_idx
  on wireless_shadow_alerts using gin (lower(coalesce(ssid, '')) gin_trgm_ops)
  where nullif(ssid, '') is not null;

create index if not exists wireless_authorized_networks_graph_ssid_trgm_idx
  on wireless_authorized_networks using gin (lower(coalesce(ssid, '')) gin_trgm_ops)
  where nullif(ssid, '') is not null;

-- object: sync_stable_uuid
-- folder: functions
-- depends_on: -
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

-- object: coordinator.safe helpers
-- folder: functions
-- depends_on: coordinator schema
create or replace function coordinator.safe_int(p_value text)
returns integer
language plpgsql
immutable
as $$
begin
  if p_value is null or p_value !~ '^-?[0-9]+$' then
    return null;
  end if;

  begin
    return p_value::integer;
  exception
    when others then
      return null;
  end;
end;
$$;

create or replace function coordinator.safe_bigint(p_value text)
returns bigint
language sql
immutable
as $$
  select case when p_value ~ '^-?[0-9]+$' then p_value::bigint end
$$;

create or replace function coordinator.safe_double(p_value text)
returns double precision
language sql
immutable
as $$
  select case
    when p_value ~ '^-?([0-9]+(\.[0-9]+)?|\.[0-9]+)([eE][+-]?[0-9]+)?$'
    then p_value::double precision
  end
$$;

create or replace function coordinator.safe_bool(p_value text)
returns boolean
language sql
immutable
as $$
  select case
    when lower(p_value) in ('true', 't', '1', 'yes', 'y') then true
    when lower(p_value) in ('false', 'f', '0', 'no', 'n') then false
  end
$$;

create or replace function coordinator.safe_timestamptz(p_value text)
returns timestamptz
language plpgsql
stable
as $$
begin
  if p_value is null or btrim(p_value) = '' then
    return null;
  end if;

  begin
    return p_value::timestamptz;
  exception
    when others then
      return null;
  end;
end;
$$;

create or replace function coordinator.safe_jsonb_array(p_value jsonb)
returns jsonb
language sql
immutable
as $$
  select case when jsonb_typeof(p_value) = 'array' then p_value else '[]'::jsonb end
$$;

create or replace function coordinator.has_threat_tag(p_tags jsonb)
returns boolean
language sql
immutable
as $$
  select exists (
    select 1
    from jsonb_array_elements_text(coordinator.safe_jsonb_array(p_tags)) as tag(value)
    where tag.value like 'threat:%'
  )
$$;

-- object: coordinator.upsert_wireless_frame_from_payload
-- folder: functions
-- depends_on: wireless_frames, wireless_frame_radio, wireless_frame_qos, wireless_frame_network, wireless_frame_app_signals, wireless_frame_identity, wireless_frame_security, sync_events
create or replace function coordinator.upsert_wireless_frame_from_payload(
  p_dedupe_key text,
  p_stream_name text,
  p_payload jsonb
)
returns void
language plpgsql
as $$
begin
  if p_stream_name <> 'wireless.audit' or p_payload is null then
    return;
  end if;

  insert into wireless_frames (
    dedupe_key, sensor_id, location_id, schema_version, frame_type, frame_subtype,
    source_mac, transmitter_mac, receiver_mac, bssid, destination_bssid, ssid,
    created_at, updated_at
  )
  values (
    p_dedupe_key,
    nullif(p_payload->>'sensor_id', ''),
    nullif(p_payload->>'location_id', ''),
    coalesce(coordinator.safe_int(p_payload->>'schema_version'), 1),
    nullif(p_payload->>'frame_type', ''),
    nullif(p_payload->>'frame_subtype', ''),
    lower(nullif(p_payload->>'source_mac', '')),
    lower(nullif(p_payload->>'transmitter_mac', '')),
    lower(nullif(p_payload->>'receiver_mac', '')),
    lower(nullif(p_payload->>'bssid', '')),
    lower(nullif(coalesce(p_payload->>'destination_bssid', p_payload->>'destination_mac'), '')),
    nullif(p_payload->>'ssid', ''),
    now(),
    now()
  )
  on conflict (dedupe_key) do update set
    sensor_id = excluded.sensor_id,
    location_id = excluded.location_id,
    schema_version = excluded.schema_version,
    frame_type = excluded.frame_type,
    frame_subtype = excluded.frame_subtype,
    source_mac = excluded.source_mac,
    transmitter_mac = excluded.transmitter_mac,
    receiver_mac = excluded.receiver_mac,
    bssid = excluded.bssid,
    destination_bssid = excluded.destination_bssid,
    ssid = excluded.ssid,
    updated_at = now();

  insert into wireless_frame_radio (
    dedupe_key, signal_dbm, noise_dbm, frequency_mhz, channel_flags,
    data_rate_kbps, antenna_id, tsft, fragment_number, channel_number,
    tsft_delta_us, wall_clock_delta_ms
  )
  values (
    p_dedupe_key,
    coordinator.safe_int(p_payload->>'signal_dbm'),
    coordinator.safe_int(p_payload->>'noise_dbm'),
    coordinator.safe_int(p_payload->>'frequency_mhz'),
    coordinator.safe_int(p_payload->>'channel_flags'),
    coordinator.safe_int(p_payload->>'data_rate_kbps'),
    coordinator.safe_int(p_payload->>'antenna_id'),
    coordinator.safe_bigint(p_payload->>'tsft'),
    coordinator.safe_int(p_payload->>'fragment_number'),
    coordinator.safe_int(coalesce(p_payload->>'channel_number', p_payload->>'channel')),
    coordinator.safe_bigint(p_payload->>'tsft_delta_us'),
    coordinator.safe_bigint(p_payload->>'wall_clock_delta_ms')
  )
  on conflict (dedupe_key) do update set
    signal_dbm = excluded.signal_dbm,
    noise_dbm = excluded.noise_dbm,
    frequency_mhz = excluded.frequency_mhz,
    channel_flags = excluded.channel_flags,
    data_rate_kbps = excluded.data_rate_kbps,
    antenna_id = excluded.antenna_id,
    tsft = excluded.tsft,
    fragment_number = excluded.fragment_number,
    channel_number = excluded.channel_number,
    tsft_delta_us = excluded.tsft_delta_us,
    wall_clock_delta_ms = excluded.wall_clock_delta_ms;

  insert into wireless_frame_qos (
    dedupe_key, qos_tid, qos_eosp, qos_ack_policy, qos_ack_policy_label,
    qos_amsdu, more_data, retry, power_save, protected, frame_control_flags
  )
  values (
    p_dedupe_key,
    coordinator.safe_int(p_payload->>'qos_tid'),
    coordinator.safe_bool(p_payload->>'qos_eosp'),
    coordinator.safe_int(p_payload->>'qos_ack_policy'),
    nullif(p_payload->>'qos_ack_policy_label', ''),
    coordinator.safe_bool(p_payload->>'qos_amsdu'),
    coalesce(coordinator.safe_bool(p_payload->>'more_data'), false),
    coalesce(coordinator.safe_bool(p_payload->>'retry'), false),
    coalesce(coordinator.safe_bool(p_payload->>'power_save'), false),
    coalesce(coordinator.safe_bool(p_payload->>'protected'), false),
    coalesce(coordinator.safe_int(p_payload->>'frame_control_flags'), 0)
  )
  on conflict (dedupe_key) do update set
    qos_tid = excluded.qos_tid,
    qos_eosp = excluded.qos_eosp,
    qos_ack_policy = excluded.qos_ack_policy,
    qos_ack_policy_label = excluded.qos_ack_policy_label,
    qos_amsdu = excluded.qos_amsdu,
    more_data = excluded.more_data,
    retry = excluded.retry,
    power_save = excluded.power_save,
    protected = excluded.protected,
    frame_control_flags = excluded.frame_control_flags;

  insert into wireless_frame_network (
    dedupe_key, llc_oui, ethertype, ethertype_name, src_ip, dst_ip,
    ip_ttl, ip_protocol, ip_protocol_name, src_port, dst_port,
    transport_protocol, transport_length, transport_checksum, app_protocol
  )
  values (
    p_dedupe_key,
    nullif(p_payload->>'llc_oui', ''),
    coordinator.safe_int(p_payload->>'ethertype'),
    nullif(p_payload->>'ethertype_name', ''),
    nullif(p_payload->>'src_ip', ''),
    nullif(p_payload->>'dst_ip', ''),
    coordinator.safe_int(p_payload->>'ip_ttl'),
    coordinator.safe_int(p_payload->>'ip_protocol'),
    nullif(p_payload->>'ip_protocol_name', ''),
    coordinator.safe_int(p_payload->>'src_port'),
    coordinator.safe_int(p_payload->>'dst_port'),
    nullif(p_payload->>'transport_protocol', ''),
    coordinator.safe_int(p_payload->>'transport_length'),
    coordinator.safe_int(p_payload->>'transport_checksum'),
    nullif(p_payload->>'app_protocol', '')
  )
  on conflict (dedupe_key) do update set
    llc_oui = excluded.llc_oui,
    ethertype = excluded.ethertype,
    ethertype_name = excluded.ethertype_name,
    src_ip = excluded.src_ip,
    dst_ip = excluded.dst_ip,
    ip_ttl = excluded.ip_ttl,
    ip_protocol = excluded.ip_protocol,
    ip_protocol_name = excluded.ip_protocol_name,
    src_port = excluded.src_port,
    dst_port = excluded.dst_port,
    transport_protocol = excluded.transport_protocol,
    transport_length = excluded.transport_length,
    transport_checksum = excluded.transport_checksum,
    app_protocol = excluded.app_protocol;

  insert into wireless_frame_app_signals (
    dedupe_key, ssdp_message_type, ssdp_st, ssdp_mx, ssdp_usn,
    dhcp_requested_ip, dhcp_hostname, dhcp_vendor_class, dns_query_name, mdns_name
  )
  values (
    p_dedupe_key,
    nullif(p_payload->>'ssdp_message_type', ''),
    nullif(p_payload->>'ssdp_st', ''),
    nullif(p_payload->>'ssdp_mx', ''),
    nullif(p_payload->>'ssdp_usn', ''),
    nullif(p_payload->>'dhcp_requested_ip', ''),
    nullif(p_payload->>'dhcp_hostname', ''),
    nullif(p_payload->>'dhcp_vendor_class', ''),
    nullif(p_payload->>'dns_query_name', ''),
    nullif(p_payload->>'mdns_name', '')
  )
  on conflict (dedupe_key) do update set
    ssdp_message_type = excluded.ssdp_message_type,
    ssdp_st = excluded.ssdp_st,
    ssdp_mx = excluded.ssdp_mx,
    ssdp_usn = excluded.ssdp_usn,
    dhcp_requested_ip = excluded.dhcp_requested_ip,
    dhcp_hostname = excluded.dhcp_hostname,
    dhcp_vendor_class = excluded.dhcp_vendor_class,
    dns_query_name = excluded.dns_query_name,
    mdns_name = excluded.mdns_name;

  insert into wireless_frame_identity (
    dedupe_key, username, event_type, session_key, retransmit_key,
    frame_fingerprint, payload_visibility, identity_source, device_fingerprint,
    wps_device_name, wps_manufacturer, wps_model_name, handshake_captured
  )
  values (
    p_dedupe_key,
    nullif(p_payload->>'username', ''),
    nullif(coalesce(p_payload->>'event_type', p_payload->>'type'), ''),
    nullif(p_payload->>'session_key', ''),
    nullif(p_payload->>'retransmit_key', ''),
    nullif(p_payload->>'frame_fingerprint', ''),
    nullif(p_payload->>'payload_visibility', ''),
    nullif(p_payload->>'identity_source', ''),
    nullif(p_payload->>'device_fingerprint', ''),
    nullif(p_payload->>'wps_device_name', ''),
    nullif(p_payload->>'wps_manufacturer', ''),
    nullif(p_payload->>'wps_model_name', ''),
    coalesce(coordinator.safe_bool(p_payload->>'handshake_captured'), false)
  )
  on conflict (dedupe_key) do update set
    username = excluded.username,
    event_type = excluded.event_type,
    session_key = excluded.session_key,
    retransmit_key = excluded.retransmit_key,
    frame_fingerprint = excluded.frame_fingerprint,
    payload_visibility = excluded.payload_visibility,
    identity_source = excluded.identity_source,
    device_fingerprint = excluded.device_fingerprint,
    wps_device_name = excluded.wps_device_name,
    wps_manufacturer = excluded.wps_manufacturer,
    wps_model_name = excluded.wps_model_name,
    handshake_captured = excluded.handshake_captured;

  insert into wireless_frame_security (
    dedupe_key, large_frame, mixed_encryption, dedupe_or_replay_suspect,
    raw_len, security_flags, risk_score, tags, signal_status, adjacent_mac_hint
  )
  values (
    p_dedupe_key,
    coalesce(coordinator.safe_bool(p_payload->>'large_frame'), false),
    coordinator.safe_bool(p_payload->>'mixed_encryption'),
    coalesce(coordinator.safe_bool(p_payload->>'dedupe_or_replay_suspect'), false),
    coalesce(coordinator.safe_int(p_payload->>'raw_len'), 0),
    coalesce(coordinator.safe_int(p_payload->>'security_flags'), 0),
    coordinator.safe_double(p_payload->>'risk_score'),
    case when jsonb_typeof(p_payload->'tags') = 'array' then p_payload->'tags' else '[]'::jsonb end,
    nullif(p_payload->>'signal_status', ''),
    lower(nullif(p_payload->>'adjacent_mac_hint', ''))
  )
  on conflict (dedupe_key) do update set
    large_frame = excluded.large_frame,
    mixed_encryption = excluded.mixed_encryption,
    dedupe_or_replay_suspect = wireless_frame_security.dedupe_or_replay_suspect or excluded.dedupe_or_replay_suspect,
    raw_len = excluded.raw_len,
    security_flags = excluded.security_flags,
    risk_score = excluded.risk_score,
    tags = excluded.tags,
    signal_status = excluded.signal_status,
    adjacent_mac_hint = excluded.adjacent_mac_hint;
end;
$$;

-- object: vec job lock helpers
-- folder: functions
-- depends_on: vec_job_locks
create or replace function vec_try_begin_job(p_job_name text)
returns boolean
language plpgsql
as $$
begin
  if not pg_try_advisory_lock(hashtextextended(p_job_name, 0)) then
    raise notice '% already running, skipping', p_job_name;
    return false;
  end if;

  insert into vec_job_locks (job_name, locked_at, locked_by)
  values (p_job_name, now(), pg_backend_pid()::text)
  on conflict (job_name) do update
    set locked_at = excluded.locked_at,
        locked_by = excluded.locked_by;

  return true;
end;
$$;

create or replace function vec_finish_job(p_job_name text)
returns void
language plpgsql
as $$
begin
  delete from vec_job_locks where job_name = p_job_name;
  perform pg_advisory_unlock(hashtextextended(p_job_name, 0));
end;
$$;

create or replace function vec_try_begin_maintenance_job(p_job_name text)
returns boolean
language plpgsql
as $$
declare
  v_lock_name text := 'vec_maintenance';
begin
  if not pg_try_advisory_lock(hashtextextended(v_lock_name, 0)) then
    raise notice 'vector maintenance already running, skipping %', p_job_name;
    return false;
  end if;

  insert into vec_job_locks (job_name, locked_at, locked_by)
  values ('maintenance:' || p_job_name, now(), pg_backend_pid()::text)
  on conflict (job_name) do update
    set locked_at = excluded.locked_at,
        locked_by = excluded.locked_by;

  return true;
end;
$$;

create or replace function vec_finish_maintenance_job(p_job_name text)
returns void
language plpgsql
as $$
declare
  v_lock_name text := 'vec_maintenance';
begin
  delete from vec_job_locks where job_name = 'maintenance:' || p_job_name;
  perform pg_advisory_unlock(hashtextextended(v_lock_name, 0));
end;
$$;

create or replace function vec_run_maintenance_sql(p_job_name text, p_statement text)
returns void
language plpgsql
as $$
begin
  if not vec_try_begin_maintenance_job(p_job_name) then
    return;
  end if;

  execute p_statement;

  perform vec_finish_maintenance_job(p_job_name);
exception when others then
  perform vec_finish_maintenance_job(p_job_name);
  raise;
end;
$$;

-- object: vec_update_transition_model
-- folder: functions
-- depends_on: vec_transition_model
-- Update transition counts from ordered frame_subtype sequences in sync_events
-- over a rolling 24-hour window. Uses Laplace-smoothed bigrams.
create or replace function vec_update_transition_model()
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  if not vec_try_begin_job('vec_update_transition_model') then
    return 0;
  end if;

  with windowed as (
    select
      coalesce(
        nullif(frame_subtype, ''),
        nullif(payload->>'frame_subtype', '')
      ) as frame_subtype,
      coalesce(session_key, payload->>'session_key') as session_key,
      observed_at
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and status = 'batched'
      and observed_at >= now() - interval '24 hours'
      and coalesce(session_key, payload->>'session_key') is not null
      and coalesce(
        nullif(frame_subtype, ''),
        nullif(payload->>'frame_subtype', '')
      ) is not null
  ),
  ordered as (
    select
      session_key,
      frame_subtype,
      lag(frame_subtype) over (partition by session_key order by observed_at) as prev_subtype
    from windowed
  ),
  bigrams as (
    select upper(regexp_replace(prev_subtype, '-', '_', 'g'))::text as prev_token,
           upper(regexp_replace(frame_subtype, '-', '_', 'g'))::text as next_token
    from ordered
    where prev_subtype is not null
  )
  insert into vec_transition_model (prev_token, next_token, embedding_kind, count, last_updated)
  select prev_token, next_token, 'frame_sequence', count(*)::bigint, now()
  from bigrams
  group by prev_token, next_token
  on conflict (prev_token, next_token, embedding_kind) do update set
    count = vec_transition_model.count + excluded.count,
    last_updated = now();

  get diagnostics v_count = row_count;
  perform vec_finish_job('vec_update_transition_model');
  return v_count;
exception when others then
  perform vec_finish_job('vec_update_transition_model');
  raise;
end;
$$;

-- object: vec_score_sequence
-- folder: functions
-- depends_on: vec_transition_model
-- Score a sequence of tokens using the Laplace-smoothed bigram log-probability.
-- Tokens are passed as a text array. Returns the sum of log2( P(next|prev) )
-- where P(next|prev) = (count(prev, next) + 1) / (total_from(prev) + vocab_size).
-- Sequences shorter than 2 tokens return 0 (no score).
create or replace function vec_score_sequence(p_tokens text[])
returns double precision
language plpgsql
as $$
declare
  v_log_prob double precision := 0.0;
  v_total bigint;
  v_vocab_size bigint;
  v_prev text;
  v_next text;
  v_count bigint;
  v_prob double precision;
begin
  if array_length(p_tokens, 1) < 2 then
    return 0.0;
  end if;

  -- Compute vocabulary size (distinct tokens seen in either position)
  select count(distinct token)::bigint into v_vocab_size
  from (
    select prev_token as token from vec_transition_model where embedding_kind = 'frame_sequence'
    union
    select next_token as token from vec_transition_model where embedding_kind = 'frame_sequence'
  ) vocab;

  -- Fallback: if no model exists, use uniform probability over a default vocab of 16
  if v_vocab_size is null or v_vocab_size = 0 then
    v_vocab_size := 16;
  end if;

  for i in 2 .. array_upper(p_tokens, 1) loop
    v_prev := p_tokens[i - 1];
    v_next := p_tokens[i];

    -- Count of this specific bigram
    select count into v_count
    from vec_transition_model
    where prev_token = v_prev
      and next_token = v_next
      and embedding_kind = 'frame_sequence';

    if not found then
      v_count := 0;
    end if;

    -- Total count of all bigrams starting with v_prev
    select coalesce(sum(count), 0)::bigint into v_total
    from vec_transition_model
    where prev_token = v_prev
      and embedding_kind = 'frame_sequence';

    if v_total is null or v_total = 0 then
      -- Unknown prefix: use Laplace-smooth uniform across vocab
      v_prob := 1.0 / v_vocab_size;
    else
      v_prob := (v_count + 1.0) / (v_total + v_vocab_size);
    end if;

    v_log_prob := v_log_prob + (ln(v_prob) / ln(2.0));
  end loop;

  return v_log_prob;
end;
$$;

-- object: vec_build_infrastructure_graph
-- folder: functions
-- depends_on: vec_infrastructure_graph, wireless_frames
create or replace function vec_build_infrastructure_graph(
  p_from timestamptz default now() - interval '1 hour',
  p_to timestamptz default now()
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
  v_row_count integer := 0;
begin
  if not vec_try_begin_job('vec_build_infrastructure_graph') then
    return 0;
  end if;

  with base as (
    select
      lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      lower(nullif(coalesce(ssid, payload->>'ssid'), '')) as ssid,
      lower(regexp_replace(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '[:\-]', '', 'g')) as normalized_bssid,
      observed_at,
      channel_number,
      stream_name,
      sensor_id,
      location_id
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and status = 'batched'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
  ),
  association_edges as (
    select
      bssid as node_a,
      'bssid'::text as node_a_type,
      source_mac as node_b,
      'client_mac'::text as node_b_type,
      'association'::text as edge_type,
      count(*)::numeric as weight,
      max(observed_at) as last_seen
    from base
    where source_mac is not null
    group by bssid, source_mac
  ),
  probe_edges as (
    select
      source_mac as node_a,
      'client_mac'::text as node_a_type,
      ssid as node_b,
      'ssid'::text as node_b_type,
      'probe_target'::text as edge_type,
      count(*)::numeric as weight,
      max(observed_at) as last_seen
    from base
    where ssid is not null
      and source_mac is not null
    group by source_mac, ssid
  ),
  roaming_edges as (
    select
      source_mac as node_a,
      'client_mac'::text as node_a_type,
      bssid as node_b,
      'bssid'::text as node_b_type,
      'roaming'::text as edge_type,
      count(*)::numeric as weight,
      max(observed_at) as last_seen
    from (
      select distinct source_mac, bssid, observed_at
      from base
      where source_mac is not null
        and bssid is not null
    ) sub
    group by source_mac, bssid
  ),
  vendor_edges as (
    select
      bssid as node_a,
      'bssid'::text as node_a_type,
      substr(normalized_bssid, 1, 6) as node_b,
      'vendor'::text as node_b_type,
      'vendor_link'::text as edge_type,
      count(*)::numeric as weight,
      max(observed_at) as last_seen
    from base
    where normalized_bssid is not null
    group by bssid, substr(normalized_bssid, 1, 6)
  ),
  same_channel_edges as (
    select
      b1.bssid as node_a,
      'bssid'::text as node_a_type,
      b2.bssid as node_b,
      'bssid'::text as node_b_type,
      'same_channel'::text as edge_type,
      count(*)::numeric as weight,
      max(greatest(b1.observed_at, b2.observed_at)) as last_seen
    from base b1
    join base b2
      on b1.sensor_id is not distinct from b2.sensor_id
     and b1.channel_number is not distinct from b2.channel_number
     and b1.bssid < b2.bssid
     and abs(extract(epoch from b1.observed_at - b2.observed_at)) <= 10
    group by b1.bssid, b2.bssid
  ),
  rf_proximity_edges as (
    select
      b1.bssid as node_a,
      'bssid'::text as node_a_type,
      b2.bssid as node_b,
      'bssid'::text as node_b_type,
      'rf_proximity'::text as edge_type,
      count(*)::numeric as weight,
      max(greatest(b1.observed_at, b2.observed_at)) as last_seen
    from base b1
    join base b2
      on b1.sensor_id is not distinct from b2.sensor_id
     and b1.bssid < b2.bssid
     and abs(extract(epoch from b1.observed_at - b2.observed_at)) <= 10
    group by b1.bssid, b2.bssid
  ),
  all_edges as (
    select * from association_edges
    union all
    select * from probe_edges
    union all
    select * from roaming_edges
    union all
    select * from vendor_edges
    union all
    select * from same_channel_edges
    union all
    select * from rf_proximity_edges
  )
  insert into vec_infrastructure_graph (
    node_a, node_a_type, node_b, node_b_type, edge_type, weight, last_seen, updated_at
  )
  select
    node_a, node_a_type, node_b, node_b_type, edge_type, sum(weight), max(last_seen), now()
  from all_edges
  group by node_a, node_a_type, node_b, node_b_type, edge_type
  on conflict (node_a, node_a_type, node_b, node_b_type, edge_type) do update set
    weight = vec_infrastructure_graph.weight + excluded.weight,
    last_seen = greatest(vec_infrastructure_graph.last_seen, excluded.last_seen),
    updated_at = now();

  get diagnostics v_count = row_count;
  perform vec_finish_job('vec_build_infrastructure_graph');
  return v_count;
exception when others then
  perform vec_finish_job('vec_build_infrastructure_graph');
  raise;
end;
$$;

-- object: vec_detect_rogue_clusters
-- folder: functions
-- depends_on: vec_alerts
drop function if exists vec_detect_rogue_clusters(timestamp with time zone, timestamp with time zone);

create or replace function vec_detect_rogue_clusters(
  p_from timestamp with time zone DEFAULT (now() - '01:00:00'::interval),
  p_to   timestamp with time zone DEFAULT now()
)
RETURNS integer
LANGUAGE plpgsql
AS $$
declare
  v_count     integer := 0;
  v_row_count integer := 0;
begin
  if not vec_try_begin_job('vec_detect_rogue_clusters') then
    return 0;
  end if;

  -- Track 1: Degree spike
  with current_assoc as (
    select
      lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      observed_at
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and status = 'batched'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
      and nullif(coalesce(source_mac, payload->>'source_mac'), '') is not null
  ),
  current_counts as (
    select bssid, count(distinct source_mac) as client_count
    from current_assoc
    group by bssid
  ),
  previous_assoc as (
    select
      lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and status = 'batched'
      and observed_at >= p_from - interval '1 hour'
      and observed_at < p_from
      and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
      and nullif(coalesce(source_mac, payload->>'source_mac'), '') is not null
  ),
  previous_counts as (
    select bssid, count(distinct source_mac) as client_count
    from previous_assoc
    group by bssid
  ),
  suspicious_bssids as (
    select
      c.bssid,
      c.client_count as current_clients,
      coalesce(p.client_count, 0) as previous_clients
    from current_counts c
    left join previous_counts p using (bssid)
    where c.client_count >= 20
      and c.client_count >= greatest(coalesce(p.client_count, 0) * 2, 10)
  )
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'rogue_cluster'::text,
    s.bssid,
    greatest(s.current_clients::double precision, 1.0),
    jsonb_build_object(
      'bssid',            s.bssid,
      'reason',           'degree_spike',
      'current_clients',  s.current_clients,
      'previous_clients', s.previous_clients
    )
  from suspicious_bssids s
  where not exists (
    select 1 from vec_alerts a
    where a.alert_type  = 'rogue_cluster'
      and a.source_mac is not distinct from s.bssid
      and a.created_at  > now() - interval '1 hour'
  );

  get diagnostics v_count = row_count;

  -- Track 2: Vendor conflict
  with vendor_conflicts as (
    select
      lower(nullif(wf.ssid, '')) as ssid,
      array_agg(distinct lower(coalesce(nullif(wf.bssid, ''), nullif(wf.destination_bssid, '')))) as bssids,
      array_agg(distinct wf.bssid_oui) as vendor_ouis,
      count(distinct wf.bssid_oui) as vendor_count
    from wireless_frames_expanded wf
    join sync_events se on se.dedupe_key = wf.dedupe_key
    where se.stream_name = 'wireless.audit'
      and se.status = 'batched'
      and se.observed_at >= p_from
      and se.observed_at < p_to
      and nullif(wf.ssid, '') is not null
      and coalesce(nullif(wf.bssid, ''), nullif(wf.destination_bssid, '')) is not null
      and wf.bssid_oui is not null
    group by lower(nullif(wf.ssid, ''))
    having count(distinct wf.bssid_oui) >= 2
  )
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'rogue_cluster'::text,
    null,
    greatest(vc.vendor_count::double precision, 1.0),
    jsonb_build_object(
      'reason',      'vendor_conflict',
      'ssid',        vc.ssid,
      'bssids',      vc.bssids,
      'vendor_ouis', vc.vendor_ouis
    )
  from vendor_conflicts vc
  where not exists (
    select 1 from vec_alerts a
    where a.alert_type          = 'rogue_cluster'
      and a.source_mac          is null
      and a.created_at          > now() - interval '1 hour'
      and a.metadata->>'reason' = 'vendor_conflict'
      and a.metadata->>'ssid'   = vc.ssid
  );

  get diagnostics v_row_count = row_count;
  v_count := v_count + v_row_count;

  -- Track 3: Fast roaming
  with fast_roamers as (
    select
      source_mac,
      min(observed_at)       as first_seen,
      max(observed_at)       as last_seen,
      count(distinct bssid)  as distinct_bssids
    from (
      select
        lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
        lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
        observed_at
      from sync_events_expanded
      where stream_name = 'wireless.audit'
        and status = 'batched'
        and observed_at >= p_from
        and observed_at < p_to
        and nullif(coalesce(source_mac, payload->>'source_mac'), '') is not null
        and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
    ) t
    group by source_mac
    having count(distinct bssid) >= 3
       and max(observed_at) - min(observed_at) <= interval '60 seconds'
  )
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'rogue_cluster'::text,
    f.source_mac,
    greatest(f.distinct_bssids::double precision, 1.0),
    jsonb_build_object(
      'reason',         'fast_roaming',
      'distinct_bssids', f.distinct_bssids,
      'first_seen',      f.first_seen,
      'last_seen',       f.last_seen
    )
  from fast_roamers f
  where not exists (
    select 1 from vec_alerts a
    where a.alert_type          = 'rogue_cluster'
      and a.source_mac is not distinct from f.source_mac
      and a.created_at          > now() - interval '1 hour'
      and a.metadata->>'reason' = 'fast_roaming'
  );

  get diagnostics v_row_count = row_count;
  v_count := v_count + v_row_count;

  perform vec_finish_job('vec_detect_rogue_clusters');
  return v_count;
exception when others then
  perform vec_finish_job('vec_detect_rogue_clusters');
  raise;
end;
$$;

-- object: vec_build_frame_sequences
-- folder: functions
-- depends_on: vec_frame_sequences, wireless_frames
create or replace function vec_build_frame_sequences(
  p_from timestamptz default now() - interval '2 hours',
  p_to timestamptz default now()
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  if not vec_try_begin_job('vec_build_frame_sequences') then
    return 0;
  end if;

  with base as (
    select
      -- Prefer real session_key from payload; fall back to synthetic key
      -- derived from (source_mac, bssid, minute) so events with no session
      -- identifier still get grouped into meaningful frame sequences.
      coalesce(
        nullif(coalesce(session_key, payload->>'session_key'), ''),
        md5(
          coalesce(lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')), '')
          || '|'
          || coalesce(lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')), '')
          || '|'
          || to_char(date_trunc('minute', observed_at), 'YYYY-MM-DD HH24:MI:SS')
        )
      ) as session_key,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      nullif(coalesce(location_id, payload->>'location_id'), '') as location_id,
      nullif(coalesce(sensor_id, payload->>'sensor_id'), '') as sensor_id,
      observed_at,
      coalesce(
        nullif(frame_subtype, ''),
        nullif(payload->>'frame_subtype', '')
      ) as frame_subtype_value,
      case
        when upper(regexp_replace(coalesce(nullif(frame_subtype, ''), nullif(payload->>'frame_subtype', '')), '-', '_', 'g')) in
             ('PROBE_REQ', 'PROBE_REQUEST', 'PROBE_RESP', 'PROBE_RESPONSE') then 'DISCOVERY'
        when upper(regexp_replace(coalesce(nullif(frame_subtype, ''), nullif(payload->>'frame_subtype', '')), '-', '_', 'g')) in
             ('AUTH', 'AUTHENTICATION', 'ASSOC_REQ', 'ASSOCIATION_REQUEST', 'ASSOC_RESP', 'ASSOCIATION_RESPONSE',
              'REASSOC_REQ', 'REASSOCIATION_REQUEST', 'REASSOC_RESP', 'REASSOCIATION_RESPONSE') then 'ASSOCIATION'
        when upper(regexp_replace(coalesce(nullif(frame_subtype, ''), nullif(payload->>'frame_subtype', '')), '-', '_', 'g')) in
             ('DEAUTH', 'DEAUTHENTICATION', 'DISASSOC', 'DISASSOCIATION') then 'TERMINATION'
        when upper(regexp_replace(coalesce(nullif(frame_subtype, ''), nullif(payload->>'frame_subtype', '')), '-', '_', 'g')) in
             ('EAPOL', 'EAPOL_KEY') then 'HANDSHAKE'
        when upper(regexp_replace(coalesce(nullif(frame_subtype, ''), nullif(payload->>'frame_subtype', '')), '-', '_', 'g')) in
             ('DATA', 'DATA_QOS', 'QOS_DATA', 'NULL_DATA') then 'DATA'
        when upper(regexp_replace(coalesce(nullif(frame_subtype, ''), nullif(payload->>'frame_subtype', '')), '-', '_', 'g')) = 'BEACON' then 'BEACON'
        when upper(regexp_replace(coalesce(nullif(frame_subtype, ''), nullif(payload->>'frame_subtype', '')), '-', '_', 'g')) = 'ACTION' then 'ACTION'
        else 'OTHER'
      end as semantic_token
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and status = 'batched'
      and observed_at >= p_from
      and observed_at < p_to
      and coalesce(
        nullif(frame_subtype, ''),
        nullif(payload->>'frame_subtype', '')
      ) is not null
  ),
  prepared as (
    select
      session_key,
      min(source_mac) as source_mac,
      min(location_id) as location_id,
      min(sensor_id) as sensor_id,
      min(observed_at) as window_start,
      max(observed_at) as window_end,
      left(
        string_agg(
          upper(regexp_replace(frame_subtype_value, '-', '_', 'g')),
          ' ' order by observed_at
        ),
        65535
      ) as sequence_tokens,
      left(
        string_agg(semantic_token, ' ' order by observed_at),
        65535
      ) as semantic_tokens,
      count(*)::bigint as frame_count
    from base
    where session_key is not null
    group by session_key
  )
  insert into vec_frame_sequences (
    session_key,
    source_mac,
    location_id,
    sensor_id,
    window_start,
    window_end,
    sequence_tokens,
    semantic_tokens,
    frame_count,
    created_at,
    updated_at
  )
  select
    session_key,
    source_mac,
    location_id,
    sensor_id,
    window_start,
    window_end,
    sequence_tokens,
    semantic_tokens,
    frame_count,
    now(),
    now()
  from prepared
  on conflict (session_key) do update set
    source_mac = excluded.source_mac,
    location_id = excluded.location_id,
    sensor_id = excluded.sensor_id,
    window_start = excluded.window_start,
    window_end = excluded.window_end,
    sequence_tokens = excluded.sequence_tokens,
    semantic_tokens = excluded.semantic_tokens,
    frame_count = excluded.frame_count,
    updated_at = now();

  get diagnostics v_count = row_count;
  perform vec_finish_job('vec_build_frame_sequences');
  return v_count;
exception when others then
  perform vec_finish_job('vec_build_frame_sequences');
  raise;
end;
$$;

-- object: vec_build_baseline_profiles
-- folder: functions
-- depends_on: vec_baseline_profiles, vec_behaviour_snapshots
drop function if exists vec_build_baseline_profiles(timestamptz, timestamptz);

create or replace function vec_build_baseline_profiles(
  p_from timestamptz default now() - interval '7 days',
  p_to timestamptz default now(),
  p_window interval default interval '15 minutes'
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  if not vec_try_begin_job('vec_build_baseline_profiles') then
    return 0;
  end if;

  with base as (
    select
      lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
      observed_at,
      coalesce(signal_dbm,
        case when payload->>'signal_dbm' ~ '^-?[0-9]+$' then (payload->>'signal_dbm')::integer end
      ) as signal_dbm,
      coalesce(retry, false) as retry,
      coalesce(channel_number::text, payload->>'channel_number', payload->>'channel') as channel_number,
      coalesce(frame_subtype, payload->>'frame_subtype') as frame_subtype,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and status = 'batched'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
  ),
  beacon_intervals as (
    select
      bssid,
      extract(epoch from observed_at - lag(observed_at) over (partition by bssid order by observed_at)) * 1000.0 as interval_ms
    from base
    where frame_subtype = 'beacon'
  ),
  beacon_metrics as (
    select
      bssid,
      'beacon_interval_ms'::text as metric,
      percentile_cont(0.05) within group (order by interval_ms) as p5,
      percentile_cont(0.5) within group (order by interval_ms) as p50,
      percentile_cont(0.95) within group (order by interval_ms) as p95,
      count(*) as sample_count
    from beacon_intervals
    where interval_ms is not null and interval_ms > 0
    group by bssid
  ),
  retry_window as (
    select
      bssid,
      date_bin(p_window, observed_at, timestamptz '2000-01-01 00:00:00+00') as window_start,
      avg((retry::int)::numeric) as retry_rate
    from base
    group by bssid, window_start
  ),
  retry_metrics as (
    select
      bssid,
      'retry_rate'::text as metric,
      percentile_cont(0.05) within group (order by retry_rate) as p5,
      percentile_cont(0.5) within group (order by retry_rate) as p50,
      percentile_cont(0.95) within group (order by retry_rate) as p95,
      count(*) as sample_count
    from retry_window
    group by bssid
  ),
  signal_window as (
    select
      bssid,
      date_bin(p_window, observed_at, timestamptz '2000-01-01 00:00:00+00') as window_start,
      percentile_cont(0.25) within group (order by signal_dbm) as q25,
      percentile_cont(0.75) within group (order by signal_dbm) as q75
    from base
    where signal_dbm is not null
    group by bssid, window_start
  ),
  signal_metrics as (
    select
      bssid,
      'signal_iqr_dbm'::text as metric,
      percentile_cont(0.05) within group (order by q75 - q25) as p5,
      percentile_cont(0.5) within group (order by q75 - q25) as p50,
      percentile_cont(0.95) within group (order by q75 - q25) as p95,
      count(*) as sample_count
    from signal_window
    where q25 is not null and q75 is not null
    group by bssid
  ),
  channel_window as (
    select
      bssid,
      date_bin(p_window, observed_at, timestamptz '2000-01-01 00:00:00+00') as window_start,
      channel_number,
      count(*)::bigint as channel_count
    from base
    where channel_number is not null
    group by bssid, window_start, channel_number
  ),
  channel_dwell as (
    select
      bssid,
      window_start,
      max(channel_share) as top_channel_share
    from (
      select
        bssid,
        window_start,
        channel_count::numeric / sum(channel_count) over (partition by bssid, window_start) as channel_share
      from channel_window
    ) sub
    group by bssid, window_start
  ),
  channel_metrics as (
    select
      bssid,
      'channel_dwell_ratio'::text as metric,
      percentile_cont(0.05) within group (order by top_channel_share) as p5,
      percentile_cont(0.5) within group (order by top_channel_share) as p50,
      percentile_cont(0.95) within group (order by top_channel_share) as p95,
      count(*) as sample_count
    from channel_dwell
    group by bssid
  ),
  assoc_deltas as (
    select
      bssid,
      extract(epoch from observed_at - lag(observed_at) over (partition by bssid, source_mac order by observed_at)) as delta_secs
    from base
    where frame_subtype in ('association_request', 'reassociation_request')
      and source_mac is not null
  ),
  assoc_metrics as (
    select
      bssid,
      'association_timing_secs'::text as metric,
      percentile_cont(0.05) within group (order by delta_secs) as p5,
      percentile_cont(0.5) within group (order by delta_secs) as p50,
      percentile_cont(0.95) within group (order by delta_secs) as p95,
      count(*) as sample_count
    from assoc_deltas
    where delta_secs is not null and delta_secs >= 0
    group by bssid
  ),
  metrics as (
    select * from beacon_metrics
    union all
    select * from retry_metrics
    union all
    select * from signal_metrics
    union all
    select * from channel_metrics
    union all
    select * from assoc_metrics
  )
  insert into vec_baseline_profiles (
    bssid, metric, p5, p50, p95, sample_count, created_at, updated_at
  )
  select
    bssid, metric, p5, p50, p95, sample_count, now(), now()
  from metrics
  on conflict (bssid, metric) do update set
    p5 = excluded.p5,
    p50 = excluded.p50,
    p95 = excluded.p95,
    sample_count = excluded.sample_count,
    updated_at = now();

  get diagnostics v_count = row_count;
  perform vec_finish_job('vec_build_baseline_profiles');
  return v_count;
exception when others then
  perform vec_finish_job('vec_build_baseline_profiles');
  raise;
end;
$$;

-- object: vec_build_behaviour_snapshots
-- folder: functions
-- depends_on: vec_behaviour_snapshots
create or replace function vec_build_behaviour_snapshots(
  p_from timestamptz default now() - interval '2 hours',
  p_to timestamptz default now(),
  p_window interval default interval '15 minutes'
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  if not vec_try_begin_job('vec_build_behaviour_snapshots') then
    return 0;
  end if;

  with base as (
    select
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      nullif(coalesce(location_id, payload->>'location_id'), '') as location_id,
      nullif(coalesce(sensor_id, payload->>'sensor_id'), '') as sensor_id,
      date_bin(p_window, observed_at, timestamptz '2000-01-01 00:00:00+00') as window_start,
      coalesce(app_protocol, payload->>'app_protocol', payload->>'ip_protocol_name', payload->>'transport_protocol', 'unknown') as app_protocol,
      coalesce(frame_type, payload->>'frame_type', payload->>'frame_subtype', 'unknown') as frame_type,
      coalesce(
        signal_dbm,
        case when payload->>'signal_dbm' ~ '^-?[0-9]+$' then (payload->>'signal_dbm')::integer end
      ) as signal_dbm,
      coalesce(channel_number::text, payload->>'channel_number', payload->>'channel') as channel_number,
      coalesce(retry, false) as retry,
      coalesce(protected, false) as protected,
      coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid') as bssid,
      coalesce(wps_device_name, payload->>'wps_device_name') as wps_device_name,
      coalesce(wps_manufacturer, payload->>'wps_manufacturer') as wps_manufacturer,
      coalesce(wps_model_name, payload->>'wps_model_name') as wps_model_name,
      coalesce(device_fingerprint, payload->>'device_fingerprint') as device_fingerprint
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and status = 'batched'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(source_mac, payload->>'source_mac'), '') is not null
  ),
  rollup as (
    select
      source_mac,
      location_id,
      min(sensor_id) filter (where sensor_id is not null) as sensor_id,
      window_start,
      window_start + p_window as window_end,
      count(*)::bigint as event_count,
      min(signal_dbm) as signal_min_dbm,
      max(signal_dbm) as signal_max_dbm,
      round(avg(signal_dbm)::numeric, 2) as signal_avg_dbm,
      count(*) filter (where retry)::bigint as retry_count,
      count(*) filter (where protected)::bigint as protected_count,
      count(*) filter (where not protected)::bigint as unprotected_count,
      count(distinct lower(bssid)) filter (where bssid is not null)::bigint as unique_bssid_count,
      bool_or(wps_device_name is not null or wps_manufacturer is not null or wps_model_name is not null) as has_wps_identity,
      count(distinct device_fingerprint) filter (where device_fingerprint is not null)::bigint as device_fingerprint_count
    from base
    group by source_mac, location_id, window_start
  ),
  protocol_counts as (
    select source_mac, location_id, window_start, app_protocol, count(*)::bigint as item_count
    from base
    group by source_mac, location_id, window_start, app_protocol
  ),
  protocol_json as (
    select source_mac, location_id, window_start, jsonb_object_agg(app_protocol, item_count order by app_protocol) as protocol_mix
    from protocol_counts
    group by source_mac, location_id, window_start
  ),
  frame_counts as (
    select source_mac, location_id, window_start, frame_type, count(*)::bigint as item_count
    from base
    group by source_mac, location_id, window_start, frame_type
  ),
  frame_json as (
    select source_mac, location_id, window_start, jsonb_object_agg(frame_type, item_count order by frame_type) as frame_type_distribution
    from frame_counts
    group by source_mac, location_id, window_start
  ),
  channel_counts as (
    select source_mac, location_id, window_start, channel_number, count(*)::bigint as item_count
    from base
    where channel_number is not null
    group by source_mac, location_id, window_start, channel_number
  ),
  channel_mix as (
    select
      source_mac,
      location_id,
      window_start,
      string_agg(channel_number || ':' || item_count::text, ' ' order by item_count desc, channel_number) as channel_mix
    from channel_counts
    group by source_mac, location_id, window_start
  ),
  cross_mac as (
    select
      location_id,
      window_start,
      bool_and(
        (get_byte(decode(split_part(source_mac, ':', 1), 'hex'), 0) & 2) = 2
      ) as is_locally_administered,
      count(distinct source_mac) filter (
        where (get_byte(decode(split_part(source_mac, ':', 1), 'hex'), 0) & 2) = 2
      )::bigint as la_mac_count,
      max(signal_dbm) - min(signal_dbm) as signal_range_dbm
    from base
    where signal_dbm is not null
      and source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
    group by location_id, window_start
  ),
  prepared as (
    select
      md5(r.source_mac || '|' || coalesce(r.location_id, '') || '|' || r.window_start::text || '|' || r.window_end::text) as snapshot_key,
      r.source_mac,
      r.location_id,
      r.sensor_id,
      r.window_start,
      r.window_end,
      r.event_count,
      coalesce(p.protocol_mix, '{}'::jsonb) as protocol_mix,
      coalesce(f.frame_type_distribution, '{}'::jsonb) as frame_type_distribution,
      r.signal_min_dbm,
      r.signal_max_dbm,
      r.signal_avg_dbm,
      r.retry_count,
      r.protected_count,
      r.unprotected_count,
      r.unique_bssid_count,
      jsonb_build_object(
        'has_wps_identity', coalesce(r.has_wps_identity, false),
        'device_fingerprint_count', r.device_fingerprint_count,
        'unique_bssid_count', r.unique_bssid_count,
        'protected_ratio', case when r.event_count = 0 then 0 else round((r.protected_count::numeric / r.event_count::numeric), 4) end,
        'retry_ratio', case when r.event_count = 0 then 0 else round((r.retry_count::numeric / r.event_count::numeric), 4) end,
        'is_locally_administered', coalesce(cm.is_locally_administered, false),
        'la_mac_count_in_window', coalesce(cm.la_mac_count, 0),
        'signal_range_dbm', coalesce(cm.signal_range_dbm, 0),
        'rotation_confidence', case
          when coalesce(cm.la_mac_count, 0) >= 3
           and coalesce(cm.signal_range_dbm, 999) < 20
          then least(1.0, round(coalesce(cm.la_mac_count, 0)::numeric / 5.0, 2))
          else 0
        end
      ) as mac_rotation_indicators,
      concat_ws(
        E'\n',
        'kind: behaviour_window',
        'source_mac: ' || r.source_mac,
        'location_id: ' || coalesce(r.location_id, 'unknown'),
        'sensor_id: ' || coalesce(r.sensor_id, 'unknown'),
        'window_start: ' || r.window_start::text,
        'window_end: ' || r.window_end::text,
        'event_count: ' || r.event_count::text,
        'protocol_mix: ' || coalesce(p.protocol_mix, '{}'::jsonb)::text,
        'frame_type_distribution: ' || coalesce(f.frame_type_distribution, '{}'::jsonb)::text,
        'signal_min_dbm: ' || coalesce(r.signal_min_dbm::text, 'unknown'),
        'signal_max_dbm: ' || coalesce(r.signal_max_dbm::text, 'unknown'),
        'signal_avg_dbm: ' || coalesce(r.signal_avg_dbm::text, 'unknown'),
        'retry_count: ' || r.retry_count::text,
        'protected_count: ' || r.protected_count::text,
        'unprotected_count: ' || r.unprotected_count::text,
        'unique_bssid_count: ' || r.unique_bssid_count::text,
        'rf_channel_mix: ' || coalesce(ch.channel_mix, 'unknown'),
        'rf_bssid_count: ' || r.unique_bssid_count::text,
        'la_mac_count_in_window: ' || coalesce(cm.la_mac_count, 0)::text,
        'is_locally_administered: ' || coalesce(cm.is_locally_administered, false)::text,
        'signal_range_dbm: ' || coalesce(cm.signal_range_dbm::text, 'unknown'),
        'rotation_confidence: ' || coalesce(
          case
            when coalesce(cm.la_mac_count, 0) >= 3
             and coalesce(cm.signal_range_dbm, 999) < 20
            then least(1.0, round(coalesce(cm.la_mac_count, 0)::numeric / 5.0, 2))
            else 0
          end,
          0
        )::text
      ) as text_summary,
      -- Identity-stripped text for dense embedding: behavioural signal only
      concat_ws(
        E'\n',
        'kind: behaviour_window',
        'window_start: ' || r.window_start::text,
        'window_end: ' || r.window_end::text,
        'event_count: ' || r.event_count::text,
        'protocol_mix: ' || coalesce(p.protocol_mix, '{}'::jsonb)::text,
        'frame_type_distribution: ' || coalesce(f.frame_type_distribution, '{}'::jsonb)::text,
        'signal_min_dbm: ' || coalesce(r.signal_min_dbm::text, 'unknown'),
        'signal_max_dbm: ' || coalesce(r.signal_max_dbm::text, 'unknown'),
        'signal_avg_dbm: ' || coalesce(r.signal_avg_dbm::text, 'unknown'),
        'retry_count: ' || r.retry_count::text,
        'protected_count: ' || r.protected_count::text,
        'unprotected_count: ' || r.unprotected_count::text,
        'unique_bssid_count: ' || r.unique_bssid_count::text,
        'rf_channel_mix: ' || coalesce(ch.channel_mix, 'unknown'),
        'rf_bssid_count: ' || r.unique_bssid_count::text,
        'la_mac_count_in_window: ' || coalesce(cm.la_mac_count, 0)::text,
        'is_locally_administered: ' || coalesce(cm.is_locally_administered, false)::text,
        'signal_range_dbm: ' || coalesce(cm.signal_range_dbm::text, 'unknown'),
        'rotation_confidence: ' || coalesce(
          case
            when coalesce(cm.la_mac_count, 0) >= 3
             and coalesce(cm.signal_range_dbm, 999) < 20
            then least(1.0, round(coalesce(cm.la_mac_count, 0)::numeric / 5.0, 2))
            else 0
          end,
          0
        )::text
      ) as embedding_text
    from rollup r
    left join protocol_json p
      on p.source_mac = r.source_mac
     and p.location_id is not distinct from r.location_id
     and p.window_start = r.window_start
    left join frame_json f
      on f.source_mac = r.source_mac
     and f.location_id is not distinct from r.location_id
     and f.window_start = r.window_start
    left join channel_mix ch
      on ch.source_mac = r.source_mac
     and ch.location_id is not distinct from r.location_id
     and ch.window_start = r.window_start
    left join cross_mac cm
      on cm.location_id is not distinct from r.location_id
     and cm.window_start = r.window_start
  ),
  upserted as (
    insert into vec_behaviour_snapshots (
      snapshot_key, source_mac, location_id, sensor_id, window_start, window_end,
      event_count, text_summary, embedding_text, created_at, updated_at
    )
    select
      snapshot_key, source_mac, location_id, sensor_id, window_start, window_end,
      event_count, text_summary, embedding_text, now(), now()
    from prepared
    on conflict (snapshot_key) do update set
      sensor_id = excluded.sensor_id,
      event_count = excluded.event_count,
      text_summary = excluded.text_summary,
      embedding_text = excluded.embedding_text,
      updated_at = now()
    returning snapshot_id, snapshot_key
  )
  insert into vec_behaviour_snapshot_stats (
    snapshot_id, protocol_mix, frame_type_distribution, signal_min_dbm, signal_max_dbm,
    signal_avg_dbm, retry_count, protected_count, unprotected_count, unique_bssid_count,
    mac_rotation_indicators
  )
  select
    upserted.snapshot_id, prepared.protocol_mix, prepared.frame_type_distribution,
    prepared.signal_min_dbm, prepared.signal_max_dbm, prepared.signal_avg_dbm,
    prepared.retry_count, prepared.protected_count, prepared.unprotected_count,
    prepared.unique_bssid_count, prepared.mac_rotation_indicators
  from upserted
  join prepared using (snapshot_key)
  on conflict (snapshot_id) do update set
    protocol_mix = excluded.protocol_mix,
    frame_type_distribution = excluded.frame_type_distribution,
    signal_min_dbm = excluded.signal_min_dbm,
    signal_max_dbm = excluded.signal_max_dbm,
    signal_avg_dbm = excluded.signal_avg_dbm,
    retry_count = excluded.retry_count,
    protected_count = excluded.protected_count,
    unprotected_count = excluded.unprotected_count,
    unique_bssid_count = excluded.unique_bssid_count,
    mac_rotation_indicators = excluded.mac_rotation_indicators;

  get diagnostics v_count = row_count;
  perform vec_finish_job('vec_build_behaviour_snapshots');
  return v_count;
exception when others then
  perform vec_finish_job('vec_build_behaviour_snapshots');
  raise;
end;
$$;

-- object: vec_enqueue_embedding_jobs
-- folder: functions
-- depends_on: vec_embedding_jobs
drop function if exists vec_enqueue_embedding_jobs(text);

create or replace function vec_enqueue_embedding_jobs(
  p_model text default 'nomic-embed-text-v2-moe',
  p_event_embedding_scope text default 'high_signal'
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
  v_event_count integer := 0;
  v_event_cursor timestamptz;
  v_event_cursor_next timestamptz;
begin
  if not vec_try_begin_job('vec_enqueue_embedding_jobs') then
    return 0;
  end if;

  select coalesce(
    (select cursor_value::timestamptz
       from sync_cursors
      where stream_name = 'vec_embeddings.sync_events.wireless.audit'),
    timestamptz '1970-01-01 00:00:00+00'
  )
  into v_event_cursor;

  with cursor_event_keys as (
    select
      e.dedupe_key,
      greatest(e.updated_at, coalesce(frame.updated_at, e.updated_at)) as event_updated_at,
      greatest(e.updated_at, coalesce(frame.updated_at, e.updated_at)) as cursor_updated_at
    from sync_events e
    left join wireless_frames_expanded frame on frame.dedupe_key = e.dedupe_key
    where e.stream_name = 'wireless.audit'
      and e.status = 'batched'
      and greatest(e.updated_at, coalesce(frame.updated_at, e.updated_at)) > v_event_cursor
    order by cursor_updated_at, e.dedupe_key
  ),
  alert_event_keys as (
    select
      e.dedupe_key,
      greatest(e.updated_at, coalesce(frame.updated_at, e.updated_at), alert.created_at) as event_updated_at,
      alert.created_at as cursor_updated_at
    from vec_alerts alert
    join sync_events e
      on e.stream_name = 'wireless.audit'
     and e.status = 'batched'
     and alert.created_at > v_event_cursor
     and (
       alert.metadata->>'dedupe_key' = e.dedupe_key
       or alert.metadata->>'source_key' = e.dedupe_key
     )
    left join wireless_frames_expanded frame on frame.dedupe_key = e.dedupe_key
    order by cursor_updated_at, e.dedupe_key
  ),
  event_keys as (
    select * from cursor_event_keys
    union
    select * from alert_event_keys
  ),
  event_jobs as (
    select
      'sync_events'::text as source_table,
      source.dedupe_key::text as source_key,
      p_model as embedding_model,
      'event'::text as embedding_kind,
      10 as priority
    from event_keys keys
    join sync_events_expanded source
      on source.dedupe_key = keys.dedupe_key
    left join vec_embeddings_expanded existing
      on existing.source_table = 'sync_events'
     and existing.source_key = source.dedupe_key
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'event'
    left join vec_embedding_jobs_expanded existing_job
      on existing_job.source_table = 'sync_events'
     and existing_job.source_key = source.dedupe_key
     and existing_job.embedding_model = p_model
     and existing_job.embedding_kind = 'event'
    where source.stream_name = 'wireless.audit'
      and source.status = 'batched'
      and (
        coalesce(nullif(p_event_embedding_scope, ''), 'high_signal') = 'all'
        or coalesce(source.handshake_captured, false)
        or coalesce(coordinator.safe_double(source.payload->>'risk_score'), 0::double precision) >= 0.5
        or coordinator.has_threat_tag(coordinator.safe_jsonb_array(source.payload->'tags'))
        or exists (
          select 1
          from vec_alerts alert
          where alert.created_at >= source.observed_at - interval '1 hour'
            and alert.created_at <= source.observed_at + interval '24 hours'
            and (
              alert.metadata->>'dedupe_key' = source.dedupe_key
              or alert.metadata->>'source_key' = source.dedupe_key
              or (
                source.source_mac is not null
                and lower(alert.source_mac) = lower(source.source_mac)
              )
              or (
                source.bssid is not null
                and lower(alert.metadata->>'bssid') = lower(source.bssid)
              )
              or (
                source.destination_bssid is not null
                and lower(alert.metadata->>'destination_bssid') = lower(source.destination_bssid)
              )
            )
        )
      )
      and (
        existing.embedding_id is null
        or (
          existing_job.job_id is null
          and keys.event_updated_at > existing.embedded_at
        )
        or (
          existing_job.status = 'completed'
          and keys.event_updated_at > coalesce(existing_job.completed_at, existing.embedded_at)
        )
      )
  ),
  device_jobs as (
    select
      'devices'::text as source_table,
      mac_id::text as source_key,
      p_model as embedding_model,
      'device'::text as embedding_kind,
      30 as priority
    from devices source
    left join vec_embeddings_expanded existing
      on existing.source_table = 'devices'
     and existing.source_key = source.mac_id
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'device'
    left join vec_embedding_jobs_expanded existing_job
      on existing_job.source_table = 'devices'
     and existing_job.source_key = source.mac_id
     and existing_job.embedding_model = p_model
     and existing_job.embedding_kind = 'device'
    where existing.embedding_id is null
       or (
         existing_job.job_id is null
         and source.last_seen > existing.embedded_at
       )
       or (
         existing_job.status = 'completed'
         and source.last_seen > coalesce(existing_job.completed_at, existing.embedded_at)
       )
  ),
  behaviour_jobs as (
    select
      'vec_behaviour_snapshots'::text as source_table,
      snapshot_id::text as source_key,
      p_model as embedding_model,
      'behaviour_window'::text as embedding_kind,
      20 as priority
    from vec_behaviour_snapshots_expanded source
    left join vec_embeddings_expanded existing
      on existing.source_table = 'vec_behaviour_snapshots'
     and existing.source_key = source.snapshot_id::text
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'behaviour_window'
    left join vec_embedding_jobs_expanded existing_job
      on existing_job.source_table = 'vec_behaviour_snapshots'
     and existing_job.source_key = source.snapshot_id::text
     and existing_job.embedding_model = p_model
     and existing_job.embedding_kind = 'behaviour_window'
    where existing.embedding_id is null
       or (
         existing_job.job_id is null
         and source.updated_at > existing.embedded_at
       )
       or (
         existing_job.status = 'completed'
         and source.updated_at > coalesce(existing_job.completed_at, existing.embedded_at)
       )
  ),
  frame_sequence_jobs as (
    select
      'vec_frame_sequences'::text as source_table,
      fs.session_key::text as source_key,
      p_model as embedding_model,
      'frame_sequence'::text as embedding_kind,
      18 as priority
    from vec_frame_sequences fs
    left join vec_embeddings_expanded existing
      on existing.source_table = 'vec_frame_sequences'
     and existing.source_key = fs.session_key
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'frame_sequence'
    left join vec_embedding_jobs_expanded existing_job
      on existing_job.source_table = 'vec_frame_sequences'
     and existing_job.source_key = fs.session_key
     and existing_job.embedding_model = p_model
     and existing_job.embedding_kind = 'frame_sequence'
    where existing.embedding_id is null
       or (
         existing_job.job_id is null
         and fs.updated_at > existing.embedded_at
       )
       or (
         existing_job.status = 'completed'
         and fs.updated_at > coalesce(existing_job.completed_at, existing.embedded_at)
       )
  ),
  timing_profile_jobs as (
    select
      'vec_timing_profiles'::text as source_table,
      tp.profile_id::text as source_key,
      p_model as embedding_model,
      'timing_profile'::text as embedding_kind,
      17 as priority
    from vec_timing_profiles_expanded tp
    left join vec_embeddings_expanded existing
      on existing.source_table = 'vec_timing_profiles'
     and existing.source_key = tp.profile_id::text
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'timing_profile'
    left join vec_embedding_jobs_expanded existing_job
      on existing_job.source_table = 'vec_timing_profiles'
     and existing_job.source_key = tp.profile_id::text
     and existing_job.embedding_model = p_model
     and existing_job.embedding_kind = 'timing_profile'
    where existing.embedding_id is null
       or (
         existing_job.job_id is null
         and tp.updated_at > existing.embedded_at
       )
       or (
         existing_job.status = 'completed'
         and tp.updated_at > coalesce(existing_job.completed_at, existing.embedded_at)
       )
  ),
  graph_keys as (
    select source_key, max(updated_at) as source_updated_at
    from (
      select node_a as source_key, updated_at
      from vec_infrastructure_graph
      where node_a_type = 'bssid'
      union all
      select node_b as source_key, updated_at
      from vec_infrastructure_graph
      where node_b_type = 'bssid'
    ) keys
    group by source_key
  ),
  graph_jobs as (
    select
      'vec_infrastructure_graph'::text as source_table,
      keys.source_key,
      p_model as embedding_model,
      'infrastructure_subgraph'::text as embedding_kind,
      15 as priority
    from graph_keys keys
    left join vec_embeddings_expanded existing
      on existing.source_table = 'vec_infrastructure_graph'
     and existing.source_key = keys.source_key
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'infrastructure_subgraph'
    left join vec_embedding_jobs_expanded existing_job
      on existing_job.source_table = 'vec_infrastructure_graph'
     and existing_job.source_key = keys.source_key
     and existing_job.embedding_model = p_model
     and existing_job.embedding_kind = 'infrastructure_subgraph'
    where existing.embedding_id is null
       or (
         existing_job.job_id is null
         and keys.source_updated_at > existing.embedded_at
       )
       or (
         existing_job.status = 'completed'
         and keys.source_updated_at > coalesce(existing_job.completed_at, existing.embedded_at)
       )
  ),
  baseline_jobs as (
    select
      'vec_baseline_profiles'::text as source_table,
      bp.bssid as source_key,
      p_model as embedding_model,
      'baseline_profile'::text as embedding_kind,
      25 as priority
    from vec_baseline_profiles bp
    left join lateral (
      select count(*) as new_frame_count
      from (
        select source.dedupe_key
        from wireless_frames_expanded source
        join sync_events event on event.dedupe_key = source.dedupe_key
        where source.bssid is not null
          and lower(source.bssid) = bp.bssid
          and source.updated_at > bp.updated_at
          and event.status = 'batched'
        union
        select source.dedupe_key
        from wireless_frames_expanded source
        join sync_events event on event.dedupe_key = source.dedupe_key
        where source.destination_bssid is not null
          and lower(source.destination_bssid) = bp.bssid
          and source.updated_at > bp.updated_at
          and event.status = 'batched'
      ) source
    ) frames on true
    left join vec_embeddings_expanded existing
      on existing.source_table = 'vec_baseline_profiles'
     and existing.source_key = bp.bssid
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'baseline_profile'
    left join vec_embedding_jobs_expanded existing_job
      on existing_job.source_table = 'vec_baseline_profiles'
     and existing_job.source_key = bp.bssid
     and existing_job.embedding_model = p_model
     and existing_job.embedding_kind = 'baseline_profile'
    where frames.new_frame_count >= 50
      and (
        existing.embedding_id is null
        or (
          existing_job.job_id is null
          and bp.updated_at > existing.embedded_at
        )
        or (
          existing_job.status = 'completed'
          and bp.updated_at > coalesce(existing_job.completed_at, existing.embedded_at)
        )
      )
  ),
  inserted as (
    insert into vec_embedding_jobs (
      source_table, source_key, embedding_model, embedding_kind,
      priority, status, created_at, updated_at
    )
    select
      source_table,
      source_key,
      embedding_model,
      embedding_kind,
      min(priority) as priority,
      'pending',
      now(),
      now()
    from (
      select * from event_jobs
      union all
      select * from device_jobs
      union all
      select * from behaviour_jobs
      union all
      select * from frame_sequence_jobs
      union all
      select * from timing_profile_jobs
      union all
      select * from baseline_jobs
      union all
      select * from graph_jobs
    ) jobs
    group by source_table, source_key, embedding_model, embedding_kind
    on conflict (source_table, source_key, embedding_model, embedding_kind) do update set
      status = 'pending',
      priority = least(vec_embedding_jobs.priority, excluded.priority),
      content_sha256 = null,
      updated_at = now()
    where vec_embedding_jobs.status = 'completed'
    returning job_id, source_table, source_key, embedding_kind
  ),
  leases_reset as (
    update vec_embedding_job_leases lease
       set due_at = least(lease.due_at, now()),
           completed_at = null,
           attempts = 0,
           lease_token = null,
           leased_at = null,
           locked_by = null,
           last_error = null
      from inserted
     where lease.job_id = inserted.job_id
    returning lease.job_id
  )
  select
    (select count(*) from inserted),
    (select count(*) from event_keys),
    (select max(cursor_updated_at) from event_keys)
    into v_count, v_event_count, v_event_cursor_next
  ;

  if v_event_count > 0 and v_event_cursor_next is not null then
    insert into sync_cursors (stream_name, cursor_value, updated_at)
    values (
      'vec_embeddings.sync_events.wireless.audit',
      v_event_cursor_next::text,
      now()
    )
    on conflict (stream_name) do update set
      cursor_value = greatest(sync_cursors.cursor_value::timestamptz, excluded.cursor_value::timestamptz)::text,
      updated_at = now();
  end if;

  perform vec_finish_job('vec_enqueue_embedding_jobs');
  return v_count;
exception when others then
  perform vec_finish_job('vec_enqueue_embedding_jobs');
  raise;
end;
$$;

-- object: vec_lease_embedding_jobs
-- folder: functions
-- depends_on: vec_embedding_jobs, vec_embedding_job_leases, vec_worker_state
drop function if exists vec_lease_embedding_jobs(integer, text, interval);

create or replace function vec_lease_embedding_jobs(
  p_limit integer default 25,
  p_worker_name text default 'vector-worker',
  p_lease interval default interval '5 minutes'
)
returns table (
  job_id bigint,
  source_table text,
  source_key text,
  embedding_model text,
  embedding_kind text,
  status text,
  priority integer,
  attempts integer,
  max_attempts integer,
  lease_token text,
  leased_at timestamptz,
  locked_by text,
  due_at timestamptz,
  content_sha256 text,
  last_error text,
  completed_at timestamptz,
  created_at timestamptz,
  updated_at timestamptz
)
language plpgsql
as $$
#variable_conflict use_column
begin
  return query
  with kind_order(embedding_kind, kind_rank) as (
    values
      ('event', 1),
      ('device', 2),
      ('behaviour_window', 3),
      ('baseline_profile', 4),
      ('frame_sequence', 5),
      ('infrastructure_subgraph', 6),
      ('timing_profile', 7)
  ),
  candidates as materialized (
    select
      candidate.job_id,
      candidate.embedding_kind,
      candidate.priority,
      candidate.due_at,
      candidate.leased_at,
      candidate.reclaim_rank,
      kind.kind_rank
    from kind_order kind
    cross join lateral (
      select
        job.job_id,
        job.embedding_kind,
        job.priority,
        lease.due_at,
        lease.leased_at,
        case when job.status in ('pending', 'failed') then 0 else 1 end as reclaim_rank
      from vec_embedding_jobs job
      join vec_embedding_job_leases lease using (job_id)
      where job.embedding_kind = kind.embedding_kind
        and lease.attempts < lease.max_attempts
        and lease.due_at <= now()
        and (
          job.status in ('pending', 'failed')
          or (
            job.status = 'leased'
            and lease.leased_at < now() - p_lease
          )
        )
      order by
        reclaim_rank,
        case when job.status = 'leased' then lease.leased_at end asc,
        job.priority asc,
        lease.due_at asc,
        job.job_id asc
      for update of job, lease skip locked
      limit greatest(p_limit, 1)
    ) candidate
  ),
  ranked as (
    select
      job_id,
      priority,
      due_at,
      leased_at,
      reclaim_rank,
      kind_rank,
      row_number() over (
        partition by embedding_kind
        order by reclaim_rank, priority, due_at, job_id
      ) as kind_round
    from candidates
  ),
  selected as (
    select job_id
    from ranked
    order by reclaim_rank, kind_round, kind_rank, priority, due_at, job_id
    limit greatest(p_limit, 1)
  ),
  leases_updated as (
    update vec_embedding_job_leases lease
       set attempts = lease.attempts + 1,
           lease_token = md5(random()::text || clock_timestamp()::text || lease.job_id::text),
           leased_at = now(),
           locked_by = p_worker_name,
           last_error = null
      from selected
     where lease.job_id = selected.job_id
    returning lease.*
  ),
  jobs_updated as (
    update vec_embedding_jobs job
       set status = 'leased',
           updated_at = now()
      from leases_updated lease
     where job.job_id = lease.job_id
    returning job.*
  )
  select
    job.job_id,
    job.source_table,
    job.source_key,
    job.embedding_model,
    job.embedding_kind,
    job.status,
    job.priority,
    lease.attempts,
    lease.max_attempts,
    lease.lease_token,
    lease.leased_at,
    lease.locked_by,
    lease.due_at,
    job.content_sha256,
    lease.last_error,
    lease.completed_at,
    job.created_at,
    job.updated_at
  from jobs_updated job
  join leases_updated lease using (job_id)
  order by job.priority, lease.due_at, job.job_id;
end;
$$;

-- object: vec_upsert_embedding
-- folder: functions
-- depends_on: vec_embeddings, vec_embedding_sources
create or replace function vec_upsert_embedding(
  p_source_table text,
  p_source_key text,
  p_source_observed_at timestamptz,
  p_source_stream_name text,
  p_source_sensor_id text,
  p_source_location_id text,
  p_source_mac text,
  p_embedding_model text,
  p_embedding_kind text,
  p_embedding_dimensions integer,
  p_content_sha256 text,
  p_content_text text,
  p_embedding vector,
  p_metadata jsonb
)
returns bigint
language plpgsql
as $$
declare
  v_embedding_id bigint;
begin
  perform pg_advisory_xact_lock(hashtextextended(
    concat_ws(E'\x1f', p_source_table, p_source_key, p_embedding_model, p_embedding_kind),
    0
  ));

  select embedding_id
    into v_embedding_id
  from vec_embedding_sources
  where source_table = p_source_table
    and source_key = p_source_key
    and embedding_model = p_embedding_model
    and embedding_kind = p_embedding_kind
  for update;

  if v_embedding_id is null then
    if exists (
      select 1
      from information_schema.columns
      where table_schema = current_schema()
        and table_name = 'vec_embeddings'
        and column_name = 'source_table'
    ) then
      execute $legacy_insert$
        insert into vec_embeddings (
          source_table, source_key, source_observed_at, source_stream_name,
          source_sensor_id, source_location_id, source_mac,
          embedding_model, embedding_kind, embedding_dimensions,
          content_sha256, content_text, embedding, metadata,
          embedded_at, created_at, updated_at
        )
        values (
          $1, $2, $3, $4, $5, $6, $7,
          $8, $9, $10, $11, $12, $13, $14,
          now(), now(), now()
        )
        returning embedding_id
      $legacy_insert$
      into v_embedding_id
      using
        p_source_table, p_source_key, p_source_observed_at, p_source_stream_name,
        p_source_sensor_id, p_source_location_id, p_source_mac,
        p_embedding_model, p_embedding_kind, p_embedding_dimensions,
        p_content_sha256, p_content_text, p_embedding,
        coalesce(p_metadata, '{}'::jsonb);
    else
      insert into vec_embeddings (
        embedding_model, embedding_kind, embedding_dimensions,
        content_sha256, content_text, embedding, metadata,
        embedded_at, created_at, updated_at
      )
      values (
        p_embedding_model, p_embedding_kind, p_embedding_dimensions,
        p_content_sha256, p_content_text, p_embedding, coalesce(p_metadata, '{}'::jsonb),
        now(), now(), now()
      )
      returning embedding_id into v_embedding_id;
    end if;

    insert into vec_embedding_sources (
      embedding_id, source_table, source_key, source_observed_at,
      source_stream_name, source_sensor_id, source_location_id, source_mac,
      embedding_model, embedding_kind
    )
    values (
      v_embedding_id, p_source_table, p_source_key, p_source_observed_at,
      p_source_stream_name, p_source_sensor_id, p_source_location_id, p_source_mac,
      p_embedding_model, p_embedding_kind
    )
    on conflict (embedding_id) do update set
      source_table = excluded.source_table,
      source_key = excluded.source_key,
      source_observed_at = excluded.source_observed_at,
      source_stream_name = excluded.source_stream_name,
      source_sensor_id = excluded.source_sensor_id,
      source_location_id = excluded.source_location_id,
      source_mac = excluded.source_mac,
      embedding_model = excluded.embedding_model,
      embedding_kind = excluded.embedding_kind;
  else
    update vec_embeddings
       set embedding_dimensions = p_embedding_dimensions,
           content_sha256 = p_content_sha256,
           content_text = p_content_text,
           embedding = p_embedding,
           metadata = coalesce(p_metadata, '{}'::jsonb),
           embedded_at = now(),
           updated_at = now()
     where embedding_id = v_embedding_id;

    update vec_embedding_sources
       set source_observed_at = p_source_observed_at,
           source_stream_name = p_source_stream_name,
           source_sensor_id = p_source_sensor_id,
           source_location_id = p_source_location_id,
           source_mac = p_source_mac
     where embedding_id = v_embedding_id;
  end if;

  return v_embedding_id;
end;
$$;

-- object: vec_complete_embedding_batch
-- folder: functions
-- depends_on: vec_embedding_jobs, vec_embedding_job_leases, vec_upsert_embedding
create or replace function vec_complete_embedding_batch(p_payload jsonb)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  if p_payload is null or jsonb_typeof(p_payload) <> 'array' or jsonb_array_length(p_payload) = 0 then
    return 0;
  end if;

  with payload_rows as materialized (
    select *
    from jsonb_to_recordset(p_payload) as r(
      job_id bigint,
      lease_token text,
      source_table text,
      source_key text,
      source_observed_at timestamptz,
      source_stream_name text,
      source_sensor_id text,
      source_location_id text,
      source_mac text,
      embedding_model text,
      embedding_kind text,
      embedding_dimensions integer,
      content_sha256 text,
      content_text text,
      embedding text,
      metadata jsonb
    )
  ),
  locked as materialized (
    select payload.*
    from payload_rows payload
    join vec_embedding_jobs job on job.job_id = payload.job_id
    join vec_embedding_job_leases lease on lease.job_id = job.job_id
    where lease.lease_token is not distinct from payload.lease_token
    order by job.job_id
    for update of job, lease skip locked
  ),
  upserted as materialized (
    select
      locked.job_id,
      locked.lease_token,
      locked.content_sha256,
      vec_upsert_embedding(
        locked.source_table,
        locked.source_key,
        locked.source_observed_at,
        locked.source_stream_name,
        locked.source_sensor_id,
        locked.source_location_id,
        locked.source_mac,
        locked.embedding_model,
        locked.embedding_kind,
        locked.embedding_dimensions,
        locked.content_sha256,
        locked.content_text,
        locked.embedding::vector,
        coalesce(locked.metadata, '{}'::jsonb)
      ) as embedding_id
    from locked
  ),
  jobs_completed as (
    update vec_embedding_jobs job
       set status = 'completed',
           content_sha256 = upserted.content_sha256,
           updated_at = now()
      from upserted
     where job.job_id = upserted.job_id
    returning job.job_id
  ),
  leases_completed as (
    update vec_embedding_job_leases lease
       set completed_at = now(),
           lease_token = null,
           leased_at = null,
           locked_by = null,
           last_error = null
      from jobs_completed
     where lease.job_id = jobs_completed.job_id
    returning lease.job_id
  )
  select count(*) into v_count from leases_completed;

  return v_count;
end;
$$;

-- object: vec_upsert_similarity_pair
-- folder: functions
-- depends_on: vec_similarity_pairs, vec_similarity_pair_meta
create or replace function vec_upsert_similarity_pair(
  p_pair_kind text,
  p_embedding_model text,
  p_embedding_kind text,
  p_left_embedding_id bigint,
  p_right_embedding_id bigint,
  p_left_source_table text,
  p_left_source_key text,
  p_right_source_table text,
  p_right_source_key text,
  p_cosine_distance double precision,
  p_cosine_similarity double precision,
  p_rank integer,
  p_evidence jsonb
)
returns bigint
language plpgsql
as $$
declare
  v_pair_id bigint;
  v_left_source_mac text;
  v_left_sensor_id text;
  v_left_location_id text;
  v_left_observed_at timestamptz;
  v_right_source_mac text;
  v_right_sensor_id text;
  v_right_location_id text;
  v_right_observed_at timestamptz;
begin
  perform pg_advisory_xact_lock(hashtextextended(
    concat_ws(
      E'\x1f', p_pair_kind, p_embedding_model, p_embedding_kind,
      p_left_embedding_id::text, p_right_embedding_id::text
    ),
    0
  ));

  select pair_id
    into v_pair_id
  from vec_similarity_pair_meta
  where pair_kind = p_pair_kind
    and embedding_model = p_embedding_model
    and embedding_kind = p_embedding_kind
    and left_embedding_id = p_left_embedding_id
    and right_embedding_id = p_right_embedding_id
  for update;

  if v_pair_id is null then
    if exists (
      select 1
      from information_schema.columns
      where table_schema = current_schema()
        and table_name = 'vec_similarity_pairs'
        and column_name = 'pair_kind'
    ) then
      select source_mac, source_sensor_id, source_location_id, source_observed_at
        into v_left_source_mac, v_left_sensor_id, v_left_location_id, v_left_observed_at
      from vec_embedding_sources
      where embedding_id = p_left_embedding_id;

      select source_mac, source_sensor_id, source_location_id, source_observed_at
        into v_right_source_mac, v_right_sensor_id, v_right_location_id, v_right_observed_at
      from vec_embedding_sources
      where embedding_id = p_right_embedding_id;

      execute $legacy_insert$
        insert into vec_similarity_pairs (
          pair_kind, embedding_model, embedding_kind,
          left_embedding_id, right_embedding_id,
          left_source_table, left_source_key, left_source_mac,
          left_sensor_id, left_location_id, left_observed_at,
          right_source_table, right_source_key, right_source_mac,
          right_sensor_id, right_location_id, right_observed_at,
          cosine_distance, cosine_similarity, rank, evidence,
          computed_at, created_at, updated_at
        )
        values (
          $1, $2, $3, $4, $5,
          $6, $7, $8, $9, $10, $11,
          $12, $13, $14, $15, $16, $17,
          $18, $19, $20, $21,
          now(), now(), now()
        )
        returning pair_id
      $legacy_insert$
      into v_pair_id
      using
        p_pair_kind, p_embedding_model, p_embedding_kind,
        p_left_embedding_id, p_right_embedding_id,
        p_left_source_table, p_left_source_key, v_left_source_mac,
        v_left_sensor_id, v_left_location_id, v_left_observed_at,
        p_right_source_table, p_right_source_key, v_right_source_mac,
        v_right_sensor_id, v_right_location_id, v_right_observed_at,
        p_cosine_distance, p_cosine_similarity, p_rank,
        coalesce(p_evidence, '{}'::jsonb);
    else
      insert into vec_similarity_pairs (
        left_embedding_id, right_embedding_id, cosine_distance,
        cosine_similarity, rank, computed_at, created_at, updated_at
      )
      values (
        p_left_embedding_id, p_right_embedding_id, p_cosine_distance,
        p_cosine_similarity, p_rank, now(), now(), now()
      )
      returning pair_id into v_pair_id;
    end if;

    insert into vec_similarity_pair_meta (
      pair_id, pair_kind, embedding_model, embedding_kind,
      left_source_table, left_source_key, right_source_table, right_source_key,
      evidence, left_embedding_id, right_embedding_id
    )
    values (
      v_pair_id, p_pair_kind, p_embedding_model, p_embedding_kind,
      p_left_source_table, p_left_source_key, p_right_source_table, p_right_source_key,
      coalesce(p_evidence, '{}'::jsonb), p_left_embedding_id, p_right_embedding_id
    )
    on conflict (pair_id) do update set
      pair_kind = excluded.pair_kind,
      embedding_model = excluded.embedding_model,
      embedding_kind = excluded.embedding_kind,
      left_source_table = excluded.left_source_table,
      left_source_key = excluded.left_source_key,
      right_source_table = excluded.right_source_table,
      right_source_key = excluded.right_source_key,
      evidence = excluded.evidence,
      left_embedding_id = excluded.left_embedding_id,
      right_embedding_id = excluded.right_embedding_id;
  else
    update vec_similarity_pairs
       set cosine_distance = p_cosine_distance,
           cosine_similarity = p_cosine_similarity,
           rank = p_rank,
           computed_at = now(),
           updated_at = now()
     where pair_id = v_pair_id;

    update vec_similarity_pair_meta
       set left_source_table = p_left_source_table,
           left_source_key = p_left_source_key,
           right_source_table = p_right_source_table,
           right_source_key = p_right_source_key,
           evidence = coalesce(p_evidence, '{}'::jsonb)
     where pair_id = v_pair_id;
  end if;

  return v_pair_id;
end;
$$;

-- object: vec_materialize_similarity_pairs
-- folder: functions
-- depends_on: vec_similarity_pairs, sync_cursors, vec_job_locks
drop function if exists vec_materialize_similarity_pairs(text, integer, double precision, double precision);
drop function if exists vec_materialize_similarity_pairs(text, integer, double precision, double precision, double precision);
drop function if exists vec_materialize_similarity_pairs(text, integer, double precision, double precision, double precision, double precision);

create or replace function vec_materialize_similarity_pairs(
  p_model text default 'nomic-embed-text-v2-moe',
  p_top_k integer default 10,
  p_event_dup_distance_threshold double precision default 0.05,
  p_behaviour_similarity_threshold double precision default 0.88,
  p_sequence_similarity_threshold double precision default 0.10,
  p_timing_similarity_threshold double precision default 0.05
)
returns integer
language plpgsql
as $$
declare
  v_total integer := 0;
  v_count integer := 0;
  v_started_at timestamptz := now();
begin
  if not vec_try_begin_job('vec_materialize_similarity_pairs') then
    return 0;
  end if;

  insert into sync_cursors (stream_name, cursor_value, updated_at)
  values ('vec_similarity_pairs.last_run', '1970-01-01T00:00:00+00:00', now())
  on conflict (stream_name) do nothing;

  with last_run as materialized (
    select cursor_value::timestamptz as ts
    from sync_cursors
    where stream_name = 'vec_similarity_pairs.last_run'
  ),
  candidates as (
    select
      least(e1.embedding_id, neighbor.embedding_id) as left_embedding_id,
      greatest(e1.embedding_id, neighbor.embedding_id) as right_embedding_id,
      min(neighbor.cosine_distance) as cosine_distance
    from vec_embeddings_expanded e1
    cross join last_run
    join lateral (
      select
        e2.embedding_id,
        (e2.embedding::vector(768) <=> e1.embedding::vector(768)) as cosine_distance
      from vec_embeddings_expanded e2
      where e2.embedding_kind = 'event'
        and e2.embedding_model = p_model
        and e2.embedding_dimensions = 768
        and e2.embedding_id <> e1.embedding_id
      order by e2.embedding::vector(768) <=> e1.embedding::vector(768)
      limit greatest(p_top_k, 1)
    ) neighbor on true
    where e1.embedding_kind = 'event'
      and e1.embedding_model = p_model
      and e1.embedding_dimensions = 768
      and e1.embedded_at > last_run.ts
      and e1.embedded_at <= v_started_at
      and neighbor.cosine_distance <= p_event_dup_distance_threshold
    group by least(e1.embedding_id, neighbor.embedding_id), greatest(e1.embedding_id, neighbor.embedding_id)
  )
  select count(*) into v_count
  from (
    select vec_upsert_similarity_pair(
      'event_event', p_model, 'event',
      candidates.left_embedding_id, candidates.right_embedding_id,
      left_e.source_table, left_e.source_key,
      right_e.source_table, right_e.source_key,
      candidates.cosine_distance, 1 - candidates.cosine_distance, 1,
      jsonb_build_object('threshold', p_event_dup_distance_threshold, 'detector', 'near_duplicate_event')
    ) as pair_id
    from candidates
    join vec_embeddings_expanded left_e on left_e.embedding_id = candidates.left_embedding_id
    join vec_embeddings_expanded right_e on right_e.embedding_id = candidates.right_embedding_id
  ) upserted;
  v_total := v_total + v_count;

  with last_run as materialized (
    select cursor_value::timestamptz as ts
    from sync_cursors
    where stream_name = 'vec_similarity_pairs.last_run'
  ),
  candidates as (
    select
      least(e1.embedding_id, neighbor.embedding_id) as left_embedding_id,
      greatest(e1.embedding_id, neighbor.embedding_id) as right_embedding_id,
      min(neighbor.cosine_distance) as cosine_distance
    from vec_embeddings_expanded e1
    cross join last_run
    join lateral (
      select
        e2.embedding_id,
        (e2.embedding::vector(768) <=> e1.embedding::vector(768)) as cosine_distance
      from vec_embeddings_expanded e2
      where e2.embedding_kind = 'event'
        and e2.embedding_model = p_model
        and e2.embedding_dimensions = 768
        and e2.embedding_id <> e1.embedding_id
        and (
          e2.source_sensor_id is distinct from e1.source_sensor_id
          or e2.source_stream_name is distinct from e1.source_stream_name
        )
      order by e2.embedding::vector(768) <=> e1.embedding::vector(768)
      limit greatest(p_top_k, 1)
    ) neighbor on true
    where e1.embedding_kind = 'event'
      and e1.embedding_model = p_model
      and e1.embedding_dimensions = 768
      and e1.embedded_at > last_run.ts
      and e1.embedded_at <= v_started_at
      and neighbor.cosine_distance <= greatest(p_event_dup_distance_threshold * 3, p_event_dup_distance_threshold)
    group by least(e1.embedding_id, neighbor.embedding_id), greatest(e1.embedding_id, neighbor.embedding_id)
  )
  select count(*) into v_count
  from (
    select vec_upsert_similarity_pair(
      'cross_sensor', p_model, 'event',
      candidates.left_embedding_id, candidates.right_embedding_id,
      left_e.source_table, left_e.source_key,
      right_e.source_table, right_e.source_key,
      candidates.cosine_distance, 1 - candidates.cosine_distance, 1,
      jsonb_build_object('detector', 'cross_sensor_event_cluster')
    ) as pair_id
    from candidates
    join vec_embeddings_expanded left_e on left_e.embedding_id = candidates.left_embedding_id
    join vec_embeddings_expanded right_e on right_e.embedding_id = candidates.right_embedding_id
  ) upserted;
  v_total := v_total + v_count;

  with last_run as materialized (
    select cursor_value::timestamptz as ts
    from sync_cursors
    where stream_name = 'vec_similarity_pairs.last_run'
  ),
  candidates as (
    select
      least(e1.embedding_id, neighbor.embedding_id) as left_embedding_id,
      greatest(e1.embedding_id, neighbor.embedding_id) as right_embedding_id,
      min(neighbor.cosine_distance) as cosine_distance
    from vec_embeddings_expanded e1
    cross join last_run
    join vec_behaviour_snapshots_expanded s1 on s1.snapshot_id::text = e1.source_key
    join lateral (
      select
        e2.embedding_id,
        (e2.embedding::vector(768) <=> e1.embedding::vector(768)) as cosine_distance
      from vec_embeddings_expanded e2
      join vec_behaviour_snapshots_expanded s2 on s2.snapshot_id::text = e2.source_key
      where e2.embedding_kind = 'behaviour_window'
        and e2.embedding_model = p_model
        and e2.embedding_dimensions = 768
        and e2.embedding_id <> e1.embedding_id
        and s2.source_mac <> s1.source_mac
        and s2.location_id is not distinct from s1.location_id
      order by e2.embedding::vector(768) <=> e1.embedding::vector(768)
      limit greatest(p_top_k, 1)
    ) neighbor on true
    where e1.embedding_kind = 'behaviour_window'
      and e1.embedding_model = p_model
      and e1.embedding_dimensions = 768
      and e1.embedded_at > last_run.ts
      and e1.embedded_at <= v_started_at
      and neighbor.cosine_distance <= (1 - p_behaviour_similarity_threshold)
    group by least(e1.embedding_id, neighbor.embedding_id), greatest(e1.embedding_id, neighbor.embedding_id)
  )
  select count(*) into v_count
  from (
    select vec_upsert_similarity_pair(
      'device_device', p_model, 'behaviour_window',
      candidates.left_embedding_id, candidates.right_embedding_id,
      left_e.source_table, left_e.source_key,
      right_e.source_table, right_e.source_key,
      candidates.cosine_distance, 1 - candidates.cosine_distance, 1,
      jsonb_build_object('threshold', p_behaviour_similarity_threshold, 'detector', 'mac_rotation_suspected')
    ) as pair_id
    from candidates
    join vec_embeddings_expanded left_e on left_e.embedding_id = candidates.left_embedding_id
    join vec_embeddings_expanded right_e on right_e.embedding_id = candidates.right_embedding_id
  ) upserted;
  v_total := v_total + v_count;

  with last_run as materialized (
    select cursor_value::timestamptz as ts
    from sync_cursors
    where stream_name = 'vec_similarity_pairs.last_run'
  ),
  candidates as (
    select
      least(e1.embedding_id, neighbor.embedding_id) as left_embedding_id,
      greatest(e1.embedding_id, neighbor.embedding_id) as right_embedding_id,
      min(neighbor.cosine_distance) as cosine_distance
    from vec_embeddings_expanded e1
    cross join last_run
    join lateral (
      select
        e2.embedding_id,
        (e2.embedding::vector(768) <=> e1.embedding::vector(768)) as cosine_distance
      from vec_embeddings_expanded e2
      where e2.embedding_kind = 'frame_sequence'
        and e2.embedding_model = p_model
        and e2.embedding_dimensions = 768
        and e2.embedding_id <> e1.embedding_id
      order by e2.embedding::vector(768) <=> e1.embedding::vector(768)
      limit greatest(p_top_k, 1)
    ) neighbor on true
    where e1.embedding_kind = 'frame_sequence'
      and e1.embedding_model = p_model
      and e1.embedding_dimensions = 768
      and e1.embedded_at > last_run.ts
      and e1.embedded_at <= v_started_at
      and neighbor.cosine_distance <= p_sequence_similarity_threshold
    group by least(e1.embedding_id, neighbor.embedding_id), greatest(e1.embedding_id, neighbor.embedding_id)
  )
  select count(*) into v_count
  from (
    select vec_upsert_similarity_pair(
      'sequence_sequence', p_model, 'frame_sequence',
      candidates.left_embedding_id, candidates.right_embedding_id,
      left_e.source_table, left_e.source_key,
      right_e.source_table, right_e.source_key,
      candidates.cosine_distance, 1 - candidates.cosine_distance, 1,
      jsonb_build_object('detector', 'similar_frame_sequence', 'threshold', p_sequence_similarity_threshold)
    ) as pair_id
    from candidates
    join vec_embeddings_expanded left_e on left_e.embedding_id = candidates.left_embedding_id
    join vec_embeddings_expanded right_e on right_e.embedding_id = candidates.right_embedding_id
  ) upserted;
  v_total := v_total + v_count;

  with last_run as materialized (
    select cursor_value::timestamptz as ts
    from sync_cursors
    where stream_name = 'vec_similarity_pairs.last_run'
  ),
  candidates as (
    select
      least(e1.embedding_id, neighbor.embedding_id) as left_embedding_id,
      greatest(e1.embedding_id, neighbor.embedding_id) as right_embedding_id,
      min(neighbor.cosine_distance) as cosine_distance
    from vec_embeddings_expanded e1
    cross join last_run
    join lateral (
      select
        e2.embedding_id,
        (e2.embedding::vector(768) <=> e1.embedding::vector(768)) as cosine_distance
      from vec_embeddings_expanded e2
      where e2.embedding_kind = 'timing_profile'
        and e2.embedding_model = p_model
        and e2.embedding_dimensions = 768
        and e2.embedding_id <> e1.embedding_id
        and e2.source_mac is not null
        and e1.source_mac is not null
        and e2.source_mac <> e1.source_mac
        and e2.source_sensor_id is not distinct from e1.source_sensor_id
        and e2.source_location_id is not distinct from e1.source_location_id
      order by e2.embedding::vector(768) <=> e1.embedding::vector(768)
      limit greatest(p_top_k, 1)
    ) neighbor on true
    where e1.embedding_kind = 'timing_profile'
      and e1.embedding_model = p_model
      and e1.embedding_dimensions = 768
      and e1.embedded_at > last_run.ts
      and e1.embedded_at <= v_started_at
      and neighbor.cosine_distance <= p_timing_similarity_threshold
    group by least(e1.embedding_id, neighbor.embedding_id), greatest(e1.embedding_id, neighbor.embedding_id)
  )
  select count(*) into v_count
  from (
    select vec_upsert_similarity_pair(
      'timing_timing', p_model, 'timing_profile',
      candidates.left_embedding_id, candidates.right_embedding_id,
      left_e.source_table, left_e.source_key,
      right_e.source_table, right_e.source_key,
      candidates.cosine_distance, 1 - candidates.cosine_distance, 1,
      jsonb_build_object('detector', 'timing_fingerprint_match', 'threshold', p_timing_similarity_threshold)
    ) as pair_id
    from candidates
    join vec_embeddings_expanded left_e on left_e.embedding_id = candidates.left_embedding_id
    join vec_embeddings_expanded right_e on right_e.embedding_id = candidates.right_embedding_id
  ) upserted;
  v_total := v_total + v_count;

  insert into sync_cursors (stream_name, cursor_value, updated_at)
  values ('vec_similarity_pairs.last_run', v_started_at::text, now())
  on conflict (stream_name) do update
    set cursor_value = excluded.cursor_value,
        updated_at = now();

  perform vec_finish_job('vec_materialize_similarity_pairs');
  return v_total;
exception when others then
  perform vec_finish_job('vec_materialize_similarity_pairs');
  raise;
end;
$$;

-- object: vec_reembed_changed_jobs
-- folder: functions
-- depends_on: vec_embeddings_expanded, vec_embedding_jobs, vec_embedding_job_leases
create or replace function vec_reembed_changed_jobs(
  p_limit integer default 1000
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  with candidates as materialized (
    select
      embedding.source_table,
      embedding.source_key,
      embedding.embedding_model,
      embedding.embedding_kind
    from vec_embeddings_expanded embedding
    where embedding.content_sha256 is distinct from encode(
      digest(embedding.content_text, 'sha256'), 'hex'
    )
      and not exists (
        select 1
        from vec_embedding_jobs job
        where job.source_table = embedding.source_table
          and job.source_key = embedding.source_key
          and job.embedding_model = embedding.embedding_model
          and job.embedding_kind = embedding.embedding_kind
          and job.status in ('pending', 'leased')
      )
    order by embedding.embedded_at asc
    limit greatest(p_limit, 1)
  ),
  jobs_queued as (
    insert into vec_embedding_jobs (
      source_table, source_key, embedding_model, embedding_kind,
      status, priority, content_sha256, created_at, updated_at
    )
    select
      source_table, source_key, embedding_model, embedding_kind,
      'pending', 0, null, now(), now()
    from candidates
    on conflict (source_table, source_key, embedding_model, embedding_kind)
    do update set
      status = 'pending',
      priority = 0,
      content_sha256 = null,
      updated_at = now()
    returning job_id
  ),
  leases_reset as (
    update vec_embedding_job_leases lease
       set max_attempts = 3,
           attempts = 0,
           due_at = now(),
           lease_token = null,
           leased_at = null,
           locked_by = null,
           last_error = null,
           completed_at = null
      from jobs_queued
     where lease.job_id = jobs_queued.job_id
    returning lease.job_id
  )
  select count(*) into v_count from leases_reset;

  return v_count;
end;
$$;

comment on function vec_reembed_changed_jobs is
  'Re-queues embedding jobs for existing rows where content_sha256 no longer matches the SHA-256 of content_text. Typically invoked after text builder changes to force re-embedding of affected rows.';

-- object: vec_release_expired_leases
-- folder: functions
-- depends_on: vec_embedding_jobs, vec_embedding_job_leases
create or replace function vec_release_expired_leases(
  p_lease_interval interval default interval '30 minutes'
)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  with selected as materialized (
    select
      job.job_id,
      lease.attempts >= lease.max_attempts as exhausted
    from vec_embedding_jobs job
    join vec_embedding_job_leases lease using (job_id)
    where job.status = 'leased'
      and lease.leased_at < now() - p_lease_interval
    order by job.job_id
    for update of job, lease skip locked
  ),
  leases_released as (
    update vec_embedding_job_leases lease
       set lease_token = null,
           leased_at = null,
           locked_by = null,
           due_at = case when selected.exhausted then lease.due_at else now() end,
           last_error = case
             when selected.exhausted then 'lease expired after max attempts'
             else 'lease expired'
           end
      from selected
     where lease.job_id = selected.job_id
    returning lease.job_id
  ),
  jobs_released as (
    update vec_embedding_jobs job
       set status = case when selected.exhausted then 'failed' else 'pending' end,
           updated_at = now()
      from selected
      join leases_released using (job_id)
     where job.job_id = selected.job_id
    returning job.job_id
  )
  select count(*) into v_count from jobs_released;

  return v_count;
end;
$$;

-- object: vec_reap_stale_workers
-- folder: functions
-- depends_on: vec_worker_state
-- Mark worker rows stale if heartbeat (updated_at) is older than threshold.
-- These are ghost workers from dead containers with no active lease.
create or replace function vec_reap_stale_workers(
  p_stale_after interval default interval '5 minutes'
)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  update vec_worker_state
     set status = 'stale',
         updated_at = now()
   where status = 'running'
     and updated_at < now() - p_stale_after;

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

-- object: vec_assign_device_cluster
-- folder: functions
-- depends_on: device_identity_clusters
-- Function to assign or find a cluster for a given MAC.
-- Returns the cluster_id the MAC belongs to (creating one if needed).
-- Uses rotation indicators from vec_behaviour_snapshots_expanded to identify
-- related MACs that belong to the same physical device.
create or replace function vec_assign_device_cluster(
  p_mac_id text
) returns bigint
language plpgsql
as $$
declare
  v_cluster_id bigint;
  v_related_macs text[];
begin
  -- 1. If the MAC already belongs to a cluster, return it.
  select cluster_id into v_cluster_id
  from device_identity_clusters
  where p_mac_id = any(mac_ids);

  if found then
    -- Bump last_seen
    update device_identity_clusters
    set last_seen = now(),
        updated_at = now()
    where cluster_id = v_cluster_id;
    return v_cluster_id;
  end if;

  -- 2. Look for related MACs via rotation indicators in behaviour snapshots.
  --    Find other source_macs that share rotation indicators with this MAC
  --    within the last 24 hours.
  with related as (
    select distinct lb.source_mac as related_mac
    from vec_behaviour_snapshots_expanded lb
    where lb.source_mac = p_mac_id
      and lb.window_start > now() - interval '24 hours'
      and lb.mac_rotation_indicators is not null
      and lb.mac_rotation_indicators != '{}'::jsonb
    intersect
    select distinct rb.source_mac
    from vec_behaviour_snapshots_expanded rb
    where rb.source_mac != p_mac_id
      and rb.window_start > now() - interval '24 hours'
      and rb.mac_rotation_indicators is not null
      and rb.mac_rotation_indicators != '{}'::jsonb
  )
  select array_agg(related_mac) into v_related_macs from related;

  -- 3. Check if any of the related MACs already belong to a cluster.
  if v_related_macs is not null and array_length(v_related_macs, 1) > 0 then
    select cluster_id into v_cluster_id
    from device_identity_clusters
    where mac_ids && v_related_macs
    limit 1;
  end if;

  -- 4. If no existing cluster found, create one.
  if v_cluster_id is null then
    insert into device_identity_clusters (
      mac_ids, size, first_seen, last_seen, created_at, updated_at
    )
    values (
      array_append(coalesce(v_related_macs, '{}'::text[]), p_mac_id),
      coalesce(array_length(v_related_macs, 1), 0) + 1,
      now(), now(), now(), now()
    )
    returning cluster_id into v_cluster_id;
  else
    -- 5. Merge this MAC into the existing cluster.
    update device_identity_clusters
    set mac_ids = array(
          select distinct unnest(mac_ids || array[p_mac_id])
          order by 1
        ),
        size = (
          select count(distinct m)
          from unnest(mac_ids || array[p_mac_id]) as m
        ),
        last_seen = now(),
        updated_at = now()
    where cluster_id = v_cluster_id
      and not (p_mac_id = any(mac_ids));
  end if;

  return v_cluster_id;
end;
$$;

-- object: check_high_risk_aps
-- folder: functions
-- depends_on: mv_ap_risk_score
-- Check for high-risk APs and insert alerts when composite_risk exceeds threshold
create or replace function check_high_risk_aps(p_threshold double precision default 0.75)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  insert into vec_alerts (alert_type, source_mac, score, explanation_text, metadata)
  select
    'high_risk_ap'::text,
    scored.bssid,
    scored.composite_risk,
    concat(
      'High-risk AP ', scored.bssid, ': composite_risk=',
      round(scored.composite_risk::numeric, 2), ' exceeded threshold ',
      round(p_threshold::numeric, 2), '. ',
      'Dominant signal: ', scored.dominant_signal, '. ',
      'Contributing factors: deauth_score=',
      round(scored.deauth_score::numeric, 2),
      ', signal_anomaly_score=',
      round(scored.signal_anomaly_score::numeric, 2),
      ', typosquat_score=',
      round(scored.typosquat_score::numeric, 2),
      ', vendor_mismatch_score=',
      round(scored.vendor_mismatch_score::numeric, 2),
      ', embedding_outlier_score=',
      round(scored.embedding_outlier_score::numeric, 2),
      ', baseline_deviation_score=',
      round(scored.baseline_deviation_score::numeric, 2), '.'
    ),
    jsonb_build_object(
      'composite_risk', scored.composite_risk,
      'deauth_score', scored.deauth_score,
      'signal_anomaly_score', scored.signal_anomaly_score,
      'typosquat_score', scored.typosquat_score,
      'vendor_mismatch_score', scored.vendor_mismatch_score,
      'embedding_outlier_score', scored.embedding_outlier_score,
      'baseline_deviation_score', scored.baseline_deviation_score,
      'dominant_signal', scored.dominant_signal
    )
  from (
    select
      r.*,
      case
        when r.deauth_score >= greatest(r.signal_anomaly_score, r.typosquat_score, r.vendor_mismatch_score, r.embedding_outlier_score, r.baseline_deviation_score)
          and r.deauth_score > 0 then 'deauth_storm'
        when r.baseline_deviation_score >= greatest(r.deauth_score, r.signal_anomaly_score, r.typosquat_score, r.vendor_mismatch_score, r.embedding_outlier_score)
          and r.baseline_deviation_score > 0 then 'baseline_deviation'
        when r.typosquat_score > 0 then 'typosquatting'
        when r.embedding_outlier_score > 0 then 'embedding_outlier'
        when r.signal_anomaly_score > 0 then 'signal_anomaly'
        when r.vendor_mismatch_score > 0 then 'vendor_mismatch'
        else 'composite_risk'
      end as dominant_signal
    from mv_ap_risk_score r
  ) scored
  where scored.composite_risk > p_threshold
    and not exists (
      select 1 from vec_alerts a
      where a.alert_type = 'high_risk_ap'
        and a.source_mac is not distinct from scored.bssid
        and a.created_at > now() - interval '1 hour'
    );

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

-- object: coordinator.ensure_cursor
-- folder: functions
-- depends_on: sync_cursors
create or replace function coordinator.ensure_cursor(
  p_stream_name text,
  p_default_cursor text default '0'
)
returns text
language plpgsql
as $$
declare
  v_cursor text;
begin
  insert into sync_cursors (stream_name, cursor_value, updated_at)
  values (p_stream_name, p_default_cursor, now())
  on conflict (stream_name) do nothing;

  select cursor_value
    into v_cursor
    from sync_cursors
   where stream_name = p_stream_name;

  return v_cursor;
end;
$$;

-- object: coordinator.record_scan_request
-- folder: functions
-- depends_on: sync_events, wireless_frames
create or replace function coordinator.record_scan_request(
  p_request jsonb,
  p_payload jsonb,
  p_payload_sha256 text,
  p_stream_names text[]
)
returns jsonb
language plpgsql
as $$
declare
  v_stream_name text := p_request->>'stream_name';
  v_dedupe_key text := p_request->>'dedupe_key';
  v_payload_ref text := p_request->>'payload_ref';
  v_observed_at timestamptz := (p_request->>'observed_at')::timestamptz;
  v_recorded boolean := false;
begin
  if v_stream_name is null or not exists (
    select 1
      from unnest(p_stream_names) as configured(stream_name)
     where btrim(configured.stream_name) = v_stream_name
  ) then
    return jsonb_build_object(
      'recorded', false,
      'reason', 'unsupported_stream',
      'stream_name', v_stream_name
    );
  end if;

  if nullif(v_dedupe_key, '') is null then
    raise exception 'scan request missing dedupe_key';
  end if;
  if nullif(v_payload_ref, '') is null then
    raise exception 'scan request missing payload_ref';
  end if;

  if exists (
    select 1
      from sync_event_tombstones tombstone
     where tombstone.dedupe_key = v_dedupe_key
       and tombstone.stream_name = v_stream_name
       and tombstone.expires_at > now()
  ) then
    return jsonb_build_object(
      'recorded', false,
      'reason', 'tombstone_dedupe',
      'dedupe_key', v_dedupe_key,
      'stream_name', v_stream_name
    );
  end if;

  insert into sync_events (
    dedupe_key,
    stream_name,
    observed_at,
    payload_ref,
    payload,
    payload_sha256,
    status,
    attempt_count,
    last_error,
    producer,
    event_kind,
    created_at,
    updated_at
  )
  values (
    v_dedupe_key,
    v_stream_name,
    v_observed_at,
    v_payload_ref,
    p_payload,
    p_payload_sha256,
    'pending',
    0,
    null,
    'ssl-proxy',
    nullif(p_payload->>'type', ''),
    now(),
    now()
  )
  on conflict (dedupe_key)
  do update set
    observed_at = excluded.observed_at,
    payload_ref = excluded.payload_ref,
    payload = coalesce(excluded.payload, sync_events.payload),
    payload_sha256 = excluded.payload_sha256,
    producer = excluded.producer,
    event_kind = coalesce(excluded.event_kind, sync_events.event_kind),
    status = case
      when sync_events.status in ('pending', 'failed') then 'pending'
      else sync_events.status
    end,
    last_error = case
      when sync_events.status in ('pending', 'failed') then null
      else sync_events.last_error
    end,
    updated_at = now()
  returning true into v_recorded;

  perform coordinator.upsert_wireless_frame_from_payload(v_dedupe_key, v_stream_name, p_payload);

  return jsonb_build_object(
    'recorded', coalesce(v_recorded, false),
    'dedupe_key', v_dedupe_key,
    'stream_name', v_stream_name
  );
end;
$$;

-- object: coordinator.record_scan_request_batch
-- folder: functions
-- depends_on: sync_events, wireless_frames
create or replace function coordinator.record_scan_request_batch(
  p_requests jsonb[],
  p_payloads jsonb[],
  p_payload_sha256s text[],
  p_stream_names text[]
)
returns integer
language plpgsql
as $$
declare
  v_recorded_count integer := 0;
begin
  if cardinality(p_requests) <> cardinality(p_payloads)
     or cardinality(p_requests) <> cardinality(p_payload_sha256s) then
    raise exception 'record_scan_request_batch array length mismatch';
  end if;

  if exists (
    with incoming as (
      select raw.request->>'stream_name' as stream_name,
             raw.request->>'dedupe_key' as dedupe_key
        from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
    ),
    configured_streams as (
      select btrim(configured.stream_name) as stream_name
        from unnest(p_stream_names) as configured(stream_name)
       where btrim(configured.stream_name) <> ''
    )
    select 1
      from incoming
      join configured_streams on configured_streams.stream_name = incoming.stream_name
     where nullif(dedupe_key, '') is null
  ) then
    raise exception 'scan request missing dedupe_key';
  end if;

  if exists (
    with incoming as (
      select raw.request->>'stream_name' as stream_name,
             raw.request->>'payload_ref' as payload_ref
        from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
    ),
    configured_streams as (
      select btrim(configured.stream_name) as stream_name
        from unnest(p_stream_names) as configured(stream_name)
       where btrim(configured.stream_name) <> ''
    )
    select 1
      from incoming
      join configured_streams on configured_streams.stream_name = incoming.stream_name
     where nullif(payload_ref, '') is null
  ) then
    raise exception 'scan request missing payload_ref';
  end if;

  with incoming as (
    select raw.request,
           raw.payload,
           raw.payload_sha256,
           raw.request->>'stream_name' as stream_name,
           raw.request->>'dedupe_key' as dedupe_key,
           raw.request->>'payload_ref' as payload_ref,
           raw.request->>'observed_at' as observed_at_text
      from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
  ),
  configured_streams as (
    select btrim(configured.stream_name) as stream_name
      from unnest(p_stream_names) as configured(stream_name)
     where btrim(configured.stream_name) <> ''
  ),
  typed as (
    select incoming.*,
           coordinator.safe_timestamptz(incoming.observed_at_text) as observed_at
      from incoming
  ),
  valid as (
    select typed.*
      from typed
      join configured_streams on configured_streams.stream_name = typed.stream_name
      left join sync_event_tombstones tombstone
        on tombstone.dedupe_key = typed.dedupe_key
       and tombstone.stream_name = typed.stream_name
       and tombstone.expires_at > now()
     where tombstone.dedupe_key is null
       and typed.observed_at is not null
  ),
  upserted as (
    insert into sync_events (
      dedupe_key,
      stream_name,
      observed_at,
      payload_ref,
      payload,
      payload_sha256,
      status,
      attempt_count,
      last_error,
      producer,
      event_kind,
      created_at,
      updated_at
    )
    select dedupe_key,
           stream_name,
           observed_at,
           payload_ref,
           payload,
           payload_sha256,
           'pending',
           0,
           null,
           'ssl-proxy',
           nullif(payload->>'type', ''),
           now(),
           now()
      from valid
    on conflict (dedupe_key)
    do update set
      observed_at = excluded.observed_at,
      payload_ref = excluded.payload_ref,
      payload = coalesce(excluded.payload, sync_events.payload),
      payload_sha256 = excluded.payload_sha256,
      producer = excluded.producer,
      event_kind = coalesce(excluded.event_kind, sync_events.event_kind),
      status = case
        when sync_events.status in ('pending', 'failed') then 'pending'
        else sync_events.status
      end,
      last_error = case
        when sync_events.status in ('pending', 'failed') then null
        else sync_events.last_error
      end,
      updated_at = now()
    returning 1
  )
  select count(*) into v_recorded_count from upserted;

  perform coordinator.upsert_wireless_frame_from_payload(
    raw.request->>'dedupe_key',
    raw.request->>'stream_name',
    raw.payload
  )
  from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
  join unnest(p_stream_names) as configured(stream_name)
    on btrim(configured.stream_name) = raw.request->>'stream_name'
  where raw.request->>'stream_name' = 'wireless.audit'
    and coordinator.safe_timestamptz(raw.request->>'observed_at') is not null;

  return coalesce(v_recorded_count, 0);
end;
$$;

-- object: coordinator.process_ingest_ledger
-- folder: functions
-- depends_on: sync_events, sync_jobs, sync_batches
drop function if exists coordinator.process_ingest_ledger(text[], integer, integer);

create or replace function coordinator.process_ingest_ledger(
  p_stream_names text[],
  p_oracle_stream_names text[],
  p_max_attempts integer,
  p_backoff_secs integer,
  p_batch_size integer default 200
)
returns integer
language plpgsql
as $$
declare
  v_marked_count integer := 0;
  v_recovered_count integer := 0;
  v_batched_count integer := 0;
  v_limit integer := greatest(coalesce(p_batch_size, 200), 1);
  v_processed_dedupe_keys text[] := array[]::text[];
begin
  update sync_events ingest
     set status = 'batched',
         updated_at = now()
   where status = 'processing'
     and exists (
       select 1
         from sync_batches batch
        where batch.dedupe_key = ingest.dedupe_key
     );
  get diagnostics v_marked_count = row_count;

  update sync_events ingest
     set status = 'failed',
         updated_at = now(),
         last_error = coalesce(ingest.last_error, 'coordinator processing lease expired')
   where status = 'processing'
     and updated_at < now() - interval '5 minutes'
     and not exists (
       select 1
         from sync_batches batch
        where batch.dedupe_key = ingest.dedupe_key
     );
  get diagnostics v_recovered_count = row_count;

  with next_ingest as (
    update sync_events
       set status = 'processing',
           attempt_count = attempt_count + 1,
           updated_at = now(),
           last_error = null
     where dedupe_key in (
       select dedupe_key
         from sync_events
        where status in ('pending', 'failed')
          and stream_name in (
                select btrim(configured.stream_name)
                  from unnest(p_stream_names) as configured(stream_name)
              )
          and attempt_count < p_max_attempts
          and (
                status = 'pending'
                or observed_at <= now() - make_interval(secs => (greatest(attempt_count, 1) * p_backoff_secs))
              )
        order by observed_at asc
        limit v_limit
        for update skip locked
     )
    returning dedupe_key
  )
  select coalesce(array_agg(dedupe_key), array[]::text[])
    into v_processed_dedupe_keys
    from next_ingest;

  insert into sync_cursors (stream_name, cursor_value, updated_at)
  select distinct stream_name, '0', now()
    from sync_events
   where dedupe_key = any(v_processed_dedupe_keys)
  on conflict (stream_name) do nothing;

  insert into sync_jobs (job_id, stream_name, status, attempt_count, created_at, started_at)
  select sync_stable_uuid(dedupe_key || ':job'),
         stream_name,
         'pending',
         0,
         now(),
         now()
    from sync_events
   where dedupe_key = any(v_processed_dedupe_keys)
     and stream_name in (
           select btrim(configured.stream_name)
             from unnest(p_oracle_stream_names) as configured(stream_name)
     )
  on conflict (job_id) do nothing;

  insert into sync_batches (
    batch_id,
    job_id,
    batch_no,
    payload_ref,
    status,
    row_count,
    checksum,
    attempt_count,
    last_error,
    dedupe_key,
    cursor_start,
    cursor_end
  )
  select sync_stable_uuid(ingest.dedupe_key || ':batch'),
         sync_stable_uuid(ingest.dedupe_key || ':job'),
         0,
         ingest.payload_ref,
         'pending',
         1,
         ingest.payload_sha256,
         0,
         null,
         ingest.dedupe_key,
         cursor.cursor_value,
         extract(epoch from ingest.observed_at)::bigint::text
    from sync_events ingest
    join sync_cursors cursor on cursor.stream_name = ingest.stream_name
   where ingest.dedupe_key = any(v_processed_dedupe_keys)
     and ingest.stream_name in (
           select btrim(configured.stream_name)
             from unnest(p_oracle_stream_names) as configured(stream_name)
     )
  on conflict (dedupe_key) do nothing;

  update sync_events ingest
     set status = 'batched',
         updated_at = now()
   where ingest.dedupe_key = any(v_processed_dedupe_keys)
     and (
           ingest.stream_name not in (
             select btrim(configured.stream_name)
               from unnest(p_oracle_stream_names) as configured(stream_name)
           )
           or exists (
             select 1
               from sync_batches batch
              where batch.dedupe_key = ingest.dedupe_key
           )
     );
  get diagnostics v_batched_count = row_count;

  insert into sync_cursors (stream_name, cursor_value, updated_at)
  select distinct on (stream_name)
         stream_name,
         extract(epoch from observed_at)::bigint::text,
         now()
    from sync_events
   where dedupe_key = any(v_processed_dedupe_keys)
   order by stream_name, observed_at desc
  on conflict (stream_name)
  do update set cursor_value = excluded.cursor_value, updated_at = now()
  where sync_cursors.cursor_value::bigint < excluded.cursor_value::bigint;

  return v_marked_count + v_recovered_count + v_batched_count;
end;
$$;

-- object: coordinator.recover_stale_dispatched_batches
-- folder: functions
-- depends_on: sync_batches, sync_jobs
drop function if exists coordinator.get_next_batch();

create or replace function coordinator.recover_stale_dispatched_batches(
  p_oracle_stream_names text[],
  p_dispatch_lease_seconds integer,
  p_max_attempts integer
)
returns integer
language plpgsql
as $$
declare
  v_recovered_count integer := 0;
  v_lease_seconds integer := greatest(coalesce(p_dispatch_lease_seconds, 300), 1);
  v_max_attempts integer := greatest(coalesce(p_max_attempts, 5), 1);
begin
  with stale_dispatched as (
    select batch.batch_id
      from sync_batches batch
      join sync_jobs job on job.job_id = batch.job_id
     where batch.status = 'dispatched'
       and batch.updated_at < now() - make_interval(secs => v_lease_seconds)
       and job.stream_name in (
             select btrim(configured.stream_name)
               from unnest(p_oracle_stream_names) as configured(stream_name)
              where btrim(configured.stream_name) <> ''
           )
     order by batch.updated_at asc
     for update skip locked
  ),
  failed_dispatch as (
    select batch.batch_id
      from sync_batches batch
      join sync_jobs job on job.job_id = batch.job_id
     where batch.status = 'failed'
       and (
             batch.last_error like 'sync.oracle.load publish failed:%'
             or batch.last_error like 'sync.oracle.load dispatch lease expired%'
           )
       and job.stream_name in (
             select btrim(configured.stream_name)
               from unnest(p_oracle_stream_names) as configured(stream_name)
              where btrim(configured.stream_name) <> ''
           )
     order by batch.updated_at asc
     for update skip locked
  ),
  stale_recovered as (
    update sync_batches batch
       set status = case
                     when batch.attempt_count >= v_max_attempts then 'failed'
                     else 'pending'
                   end,
           last_error = case
                         when batch.attempt_count >= v_max_attempts
                         then 'sync.oracle.load dispatch lease expired'
                         else 'sync.oracle.load dispatch lease expired; retrying'
                       end,
           updated_at = now()
      from stale_dispatched
     where batch.batch_id = stale_dispatched.batch_id
    returning batch.job_id,
              batch.batch_id,
              batch.status,
              batch.last_error
  ),
  failed_dispatch_recovered as (
    update sync_batches batch
       set status = 'pending',
           last_error = 'sync.oracle.load dispatch failure recovered; retrying',
           updated_at = now()
      from failed_dispatch
     where batch.batch_id = failed_dispatch.batch_id
       and batch.attempt_count < v_max_attempts
    returning batch.job_id,
              batch.batch_id,
              batch.status,
              batch.last_error
  ),
  recovered as (
    select * from stale_recovered
    union all
    select * from failed_dispatch_recovered
  ),
  error_insert as (
    insert into sync_errors (job_id, batch_id, error_class, error_text)
    select job_id,
           batch_id,
           'dispatch_lease_expired',
           coalesce(last_error, 'sync.oracle.load dispatch lease expired')
      from recovered
     where status = 'failed'
    returning id
  ),
  job_update as (
    update sync_jobs job
       set status = case
                     when exists (
                       select 1
                         from recovered
                        where recovered.job_id = job.job_id
                          and recovered.status = 'failed'
                     ) then 'failed'
                     else 'pending'
                   end,
           finished_at = case
                           when exists (
                             select 1
                               from recovered
                              where recovered.job_id = job.job_id
                                and recovered.status = 'failed'
                           ) then now()
                           else null
                         end
     where job.job_id in (select job_id from recovered)
    returning job.job_id
  )
  select count(*) into v_recovered_count from recovered;

  return coalesce(v_recovered_count, 0);
end;
$$;

-- object: coordinator.release_batch_dispatch
-- folder: functions
-- depends_on: sync_batches, sync_jobs
create or replace function coordinator.release_batch_dispatch(
  p_load jsonb,
  p_error_text text
)
returns jsonb
language plpgsql
as $$
declare
  v_batch_id uuid := (p_load->>'batch_id')::uuid;
  v_summary jsonb;
begin
  if v_batch_id is null then
    raise exception 'release_batch_dispatch requires batch_id';
  end if;

  with batch_update as (
    update sync_batches batch
       set attempt_count = greatest(batch.attempt_count - 1, 0),
           status = 'pending',
           last_error = nullif(p_error_text, ''),
           updated_at = now()
     where batch.batch_id = v_batch_id
       and batch.status = 'dispatched'
    returning batch.job_id,
              batch.batch_id,
              batch.status,
              batch.attempt_count,
              batch.last_error
  ),
  job_update as (
    update sync_jobs job
       set status = 'pending',
           finished_at = null
     where job.job_id in (select job_id from batch_update)
    returning job.job_id, job.status
  )
  select jsonb_build_object(
           'updated', exists(select 1 from batch_update),
           'batch_id', (select batch_id::text from batch_update limit 1),
           'new_status', (select status from batch_update limit 1),
           'attempt_count', (select attempt_count from batch_update limit 1),
           'job_id', (select job_id::text from batch_update limit 1),
           'job_status', (select status from job_update limit 1)
         )
    into v_summary;

  return coalesce(v_summary, jsonb_build_object('updated', false));
end;
$$;

-- object: coordinator.mark_batch_dispatch_failed
-- folder: functions
-- depends_on: sync_batches, sync_jobs
create or replace function coordinator.mark_batch_dispatch_failed(
  p_load jsonb,
  p_error_text text,
  p_max_attempts integer
)
returns jsonb
language plpgsql
as $$
declare
  v_batch_id uuid := (p_load->>'batch_id')::uuid;
  v_max_attempts integer := greatest(coalesce(p_max_attempts, 5), 1);
  v_summary jsonb;
begin
  if v_batch_id is null then
    raise exception 'mark_batch_dispatch_failed requires batch_id';
  end if;

  with batch_update as (
    update sync_batches batch
       set attempt_count = batch.attempt_count + 1,
           status = case
                     when batch.attempt_count + 1 >= v_max_attempts then 'failed'
                     else 'pending'
                   end,
           last_error = nullif(p_error_text, ''),
           updated_at = now()
     where batch.batch_id = v_batch_id
       and batch.status = 'dispatched'
    returning batch.job_id,
              batch.batch_id,
              batch.status,
              batch.attempt_count,
              batch.last_error
  ),
  error_insert as (
    insert into sync_errors (job_id, batch_id, error_class, error_text)
    select job_id,
           batch_id,
           'dispatch_publish_failed',
           coalesce(last_error, 'sync.oracle.load publish failed')
      from batch_update
     where status = 'failed'
    returning id
  ),
  job_update as (
    update sync_jobs job
       set status = case
                     when exists (
                       select 1
                         from batch_update
                        where batch_update.job_id = job.job_id
                          and batch_update.status = 'failed'
                     ) then 'failed'
                     else 'pending'
                   end,
           finished_at = case
                           when exists (
                             select 1
                               from batch_update
                              where batch_update.job_id = job.job_id
                                and batch_update.status = 'failed'
                           ) then now()
                           else null
                         end
     where job.job_id in (select job_id from batch_update)
    returning job.job_id, job.status
  )
  select jsonb_build_object(
           'updated', exists(select 1 from batch_update),
           'batch_id', (select batch_id::text from batch_update limit 1),
           'new_status', (select status from batch_update limit 1),
           'attempt_count', (select attempt_count from batch_update limit 1),
           'job_id', (select job_id::text from batch_update limit 1),
           'job_status', (select status from job_update limit 1),
           'error_logged', exists(select 1 from error_insert)
         )
    into v_summary;

  return coalesce(v_summary, jsonb_build_object('updated', false));
end;
$$;

-- object: coordinator.get_next_batch
-- folder: functions
-- depends_on: sync_batches, sync_jobs
create or replace function coordinator.get_next_batch(
  p_oracle_stream_names text[]
)
returns jsonb
language plpgsql
as $$
declare
  v_payload jsonb;
begin
  with picked as (
    select batch.batch_id,
           batch.payload_ref,
           event.payload as stored_payload
      from sync_batches batch
      join sync_jobs job on job.job_id = batch.job_id
      left join sync_events event on event.dedupe_key = batch.dedupe_key
     where batch.status = 'pending'
       and job.stream_name in (
             select btrim(configured.stream_name)
               from unnest(p_oracle_stream_names) as configured(stream_name)
              where btrim(configured.stream_name) <> ''
           )
     order by batch.batch_id
     limit 1
     for update of batch skip locked
  ),
  corrupt as (
    update sync_batches batch
       set status = 'failed',
           last_error = 'sync.oracle.load payload_ref missing and stored payload unavailable',
           updated_at = now()
      from picked
     where batch.batch_id = picked.batch_id
       and nullif(btrim(picked.payload_ref), '') is null
       and picked.stored_payload is null
    returning batch.job_id,
              batch.batch_id,
              batch.last_error
  ),
  error_insert as (
    insert into sync_errors (job_id, batch_id, error_class, error_text)
    select job_id,
           batch_id,
           'dispatch_payload_ref_missing',
           last_error
      from corrupt
    returning id
  ),
  corrupt_job_mark as (
    update sync_jobs job
       set status = 'failed',
           finished_at = now()
      from corrupt
     where job.job_id = corrupt.job_id
    returning job.job_id
  ),
  updated as (
    update sync_batches batch
       set status = 'dispatched',
           attempt_count = batch.attempt_count + 1,
           last_error = null,
           updated_at = now(),
           payload_ref = coalesce(
             nullif(btrim(batch.payload_ref), ''),
             'inline://json/' ||
             rtrim(
               translate(
                 replace(encode(convert_to(picked.stored_payload::text, 'UTF8'), 'base64'), E'\n', ''),
                 '+/',
                 '-_'
               ),
               '='
             )
           )
      from picked
     where batch.batch_id = picked.batch_id
       and not exists (select 1 from corrupt)
       and (
             nullif(btrim(picked.payload_ref), '') is not null
             or picked.stored_payload is not null
           )
    returning batch.batch_id,
              batch.job_id,
              batch.batch_no,
              batch.payload_ref,
              batch.cursor_start,
              batch.cursor_end,
              batch.attempt_count
  ),
  job_mark as (
    update sync_jobs job
       set status = 'running',
           started_at = coalesce(job.started_at, now())
      from updated
     where job.job_id = updated.job_id
    returning job.job_id, job.stream_name
  )
  select jsonb_build_object(
           'job_id', updated.job_id::text,
           'batch_id', updated.batch_id::text,
           'batch_no', updated.batch_no,
           'stream_name', job_mark.stream_name,
           'payload_ref', updated.payload_ref,
           'cursor_start', updated.cursor_start,
           'cursor_end', updated.cursor_end,
           'attempt', updated.attempt_count
         )
    into v_payload
    from updated
    join job_mark on job_mark.job_id = updated.job_id;

  return v_payload;
end;
$$;

-- object: coordinator.generate_shadow_alerts
-- folder: functions
-- depends_on: sync_events, wireless_frames, wireless_shadow_alerts
create or replace function coordinator.generate_shadow_alerts()
returns setof jsonb
language sql
as $$
  with wireless as (
    select
      event.observed_at,
      lower(frame.source_mac) as source_mac,
      lower(coalesce(nullif(trim(frame.destination_bssid), ''), nullif(trim(frame.bssid), ''))) as destination_bssid,
      frame.ssid,
      radio.signal_dbm,
      coalesce(frame.sensor_id, event.payload->>'sensor_id') as sensor_id,
      coalesce(frame.location_id, event.payload->>'location_id') as location_id
    from sync_events event
    join wireless_frames frame on frame.dedupe_key = event.dedupe_key
    join wireless_frame_radio radio on radio.dedupe_key = frame.dedupe_key
    where event.stream_name = 'wireless.audit'
      and event.observed_at >= now() - interval '60 seconds'
      and frame.source_mac is not null
      and lower(frame.source_mac) ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
      and radio.signal_dbm >= -50
  ),
  candidates as (
    select distinct on (source_mac)
      observed_at,
      source_mac,
      destination_bssid,
      ssid,
      sensor_id,
      location_id,
      signal_dbm,
      'strong_wireless_without_proxy_presence'::text as reason,
      jsonb_build_object(
        'window_seconds', 60,
        'signal_threshold_dbm', -50,
        'presence_window_seconds', 300
      ) as evidence
    from wireless w
    where not exists (
      select 1
        from wireless_authorized_networks awn
       where awn.enabled
         and (awn.location_id is null or awn.location_id = w.location_id)
         and (awn.ssid is null or (w.ssid is not null and lower(awn.ssid) = lower(w.ssid)))
         and (awn.bssid is null or (w.destination_bssid is not null and lower(awn.bssid) = w.destination_bssid))
         and (awn.ssid is not null or awn.bssid is not null)
    )
      and not exists (
        select 1
          from devices d
         where d.mac_id = w.source_mac
           and d.last_seen >= now() - interval '5 minutes'
      )
      and not exists (
        select 1
          from sync_events proxy
          join devices d on d.mac_id = lower(coalesce(proxy.payload->>'mac_id', proxy.payload->>'device_id'))
         where proxy.stream_name = 'proxy.events'
           and proxy.observed_at >= now() - interval '5 minutes'
           and d.mac_id = w.source_mac
      )
    order by source_mac, observed_at desc
  ),
  inserted as (
    insert into wireless_shadow_alerts as target (
      source_mac,
      first_occurred_at,
      last_occurred_at,
      occurrence_count,
      destination_bssid,
      ssid,
      sensor_id,
      location_id,
      signal_dbm,
      reason,
      evidence,
      created_at,
      updated_at
    )
    select
      source_mac,
      observed_at,
      observed_at,
      1,
      destination_bssid,
      ssid,
      sensor_id,
      location_id,
      signal_dbm,
      reason,
      evidence,
      now(),
      now()
    from candidates
    on conflict (source_mac) do update
      set last_occurred_at = greatest(target.last_occurred_at, excluded.last_occurred_at),
          occurrence_count = target.occurrence_count + 1,
          destination_bssid = case when excluded.last_occurred_at >= target.last_occurred_at then excluded.destination_bssid else target.destination_bssid end,
          ssid = case when excluded.last_occurred_at >= target.last_occurred_at then excluded.ssid else target.ssid end,
          sensor_id = case when excluded.last_occurred_at >= target.last_occurred_at then excluded.sensor_id else target.sensor_id end,
          location_id = case when excluded.last_occurred_at >= target.last_occurred_at then excluded.location_id else target.location_id end,
          signal_dbm = case when excluded.last_occurred_at >= target.last_occurred_at then excluded.signal_dbm else target.signal_dbm end,
          reason = excluded.reason,
          evidence = excluded.evidence,
          resolved_at = null,
          updated_at = now()
    returning *
  )
  select jsonb_build_object(
           'event_type', 'shadow_device',
           'first_occurred_at', first_occurred_at,
           'last_occurred_at', last_occurred_at,
           'source_mac', source_mac,
           'occurrence_count', occurrence_count,
           'destination_bssid', destination_bssid,
           'ssid', ssid,
           'sensor_id', sensor_id,
           'location_id', location_id,
           'signal_dbm', signal_dbm,
           'reason', reason,
           'evidence', evidence
         )
    from inserted;
$$;

-- object: coordinator.process_batch_result
-- folder: functions
-- depends_on: sync_batches, sync_jobs
create or replace function coordinator.process_batch_result(result_json jsonb)
returns jsonb
language plpgsql
as $$
declare
  v_summary jsonb;
begin
  with result as (
    select result_json as payload
  ),
  batch_update as (
    update sync_batches batch
       set status = case result.payload->>'status'
                     when 'success' then 'completed'
                     when 'completed' then 'completed'
                     else 'failed'
                   end,
           row_count = coalesce((result.payload->>'row_count')::integer, row_count),
           checksum = nullif(result.payload->>'checksum', ''),
           last_error = nullif(result.payload->>'error_text', ''),
           updated_at = now()
      from result
     where batch.batch_id = (result.payload->>'batch_id')::uuid
    returning batch.job_id, batch.batch_id, batch.status, batch.last_error
  ),
  error_insert as (
    insert into sync_errors (job_id, batch_id, error_class, error_text)
    select job_id,
           batch_id,
           coalesce(nullif((select payload->>'error_class' from result), ''), 'unknown'),
           coalesce(last_error, 'oracle load failed')
      from batch_update
     where status = 'failed'
    returning id
  ),
  job_done as (
    update sync_jobs job
       set status = case
                     when exists (
                       select 1
                         from sync_batches b
                        where b.job_id = job.job_id
                          and b.status = 'failed'
                     ) then 'failed'
                     else 'completed'
                   end,
           finished_at = now()
     where job.job_id in (select job_id from batch_update)
       and not exists (
         select 1
           from sync_batches b
          where b.job_id = job.job_id
            and b.status not in ('completed', 'failed')
       )
    returning job_id, status
  )
  select jsonb_build_object(
           'updated', exists(select 1 from batch_update),
           'batch_id', (select batch_id::text from batch_update limit 1),
           'batch_status', (select status from batch_update limit 1),
           'job_id', (select job_id::text from batch_update limit 1),
           'job_status', (select status from job_done limit 1),
           'error_logged', exists(select 1 from error_insert)
         )
    into v_summary;

  return coalesce(v_summary, jsonb_build_object('updated', false));
end;
$$;

-- object: coordinator.process_batch_results
-- folder: functions
-- depends_on: sync_batches, sync_jobs
create or replace function coordinator.process_batch_results(result_jsons jsonb[])
returns integer
language plpgsql
as $$
declare
  v_updated_count integer := 0;
begin
  with raw_result as (
    select payload,
           ordinality
      from unnest(result_jsons) with ordinality as raw(payload, ordinality)
     where nullif(payload->>'batch_id', '') is not null
  ),
  result as (
    select distinct on ((payload->>'batch_id')::uuid)
           (payload->>'batch_id')::uuid as batch_id,
           payload
      from raw_result
     order by (payload->>'batch_id')::uuid, ordinality desc
  ),
  batch_update as (
    update sync_batches batch
       set status = case result.payload->>'status'
                     when 'success' then 'completed'
                     when 'completed' then 'completed'
                     else 'failed'
                   end,
           row_count = coalesce((result.payload->>'row_count')::integer, row_count),
           checksum = nullif(result.payload->>'checksum', ''),
           last_error = nullif(result.payload->>'error_text', ''),
           updated_at = now()
      from result
     where batch.batch_id = result.batch_id
    returning batch.job_id, batch.batch_id, batch.status, batch.last_error
  ),
  error_insert as (
    insert into sync_errors (job_id, batch_id, error_class, error_text)
    select job_id,
           batch_id,
           coalesce(nullif((select payload->>'error_class' from result where result.batch_id = batch_update.batch_id), ''), 'unknown'),
           coalesce(last_error, 'oracle load failed')
      from batch_update
     where status = 'failed'
    returning id
  ),
  affected_jobs as (
    select distinct job_id from batch_update
  ),
  job_done as (
    update sync_jobs job
       set status = case
                     when exists (
                       select 1
                         from sync_batches b
                        where b.job_id = job.job_id
                          and b.status = 'failed'
                     ) then 'failed'
                     else 'completed'
                   end,
           finished_at = now()
     where job.job_id in (select job_id from affected_jobs)
       and not exists (
         select 1
           from sync_batches b
          where b.job_id = job.job_id
            and b.status not in ('completed', 'failed')
       )
    returning job_id, status
  )
  select count(*) into v_updated_count from batch_update;

  return coalesce(v_updated_count, 0);
end;
$$;

-- object: coordinator.save_backlog_entry
-- folder: functions
-- depends_on: sync_backlog
create or replace function coordinator.save_backlog_entry(p_payload jsonb)
returns void
language plpgsql
as $$
begin
  if nullif(p_payload->>'dedupe_key', '') is null then
    raise exception 'coordinator.save_backlog_entry requires dedupe_key';
  end if;

  insert into sync_backlog (
    dedupe_key,
    stream_name,
    payload,
    failure_stage,
    status,
    attempt_count,
    last_error,
    created_at,
    updated_at
  )
  values (
    p_payload->>'dedupe_key',
    p_payload->>'stream_name',
    p_payload->'payload',
    coalesce(nullif(p_payload->>'failure_stage', ''), 'pre_publish'),
    'pending',
    0,
    nullif(p_payload->>'error', ''),
    now(),
    now()
  )
  on conflict (dedupe_key) do update
    set stream_name = excluded.stream_name,
        payload = excluded.payload,
        failure_stage = excluded.failure_stage,
        status = 'pending',
        last_error = excluded.last_error,
        updated_at = now();
end;
$$;

-- object: coordinator.list_pending_backlog
-- folder: functions
-- depends_on: sync_backlog
create or replace function coordinator.list_pending_backlog()
returns jsonb
language sql
as $$
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'dedupe_key', dedupe_key,
      'stream_name', stream_name,
      'payload', payload,
      'failure_stage', failure_stage,
      'attempt_count', attempt_count,
      'created_at', created_at
    )
  ), '[]'::jsonb)
  from (
    select dedupe_key, stream_name, payload, failure_stage, attempt_count, created_at
    from sync_backlog
    where status = 'pending'
    order by created_at asc
    limit 100
  ) pending;
$$;

-- object: coordinator.mark_backlog_synced
-- folder: functions
-- depends_on: sync_backlog
create or replace function coordinator.mark_backlog_synced(p_dedupe_key text)
returns void
language sql
as $$
  update sync_backlog
  set status = 'synced', updated_at = now()
  where dedupe_key = p_dedupe_key;
$$;

-- object: coordinator.prune_backlog
-- folder: functions
-- depends_on: sync_backlog
create or replace function coordinator.prune_backlog()
returns integer
language plpgsql
as $$
declare
  v_deleted integer;
begin
  delete from sync_backlog
  where status = 'synced'
    and updated_at < now() - interval '7 days';
  get diagnostics v_deleted = row_count;
  return v_deleted;
end;
$$;

-- object: coordinator.lookup_device_by_mac
-- folder: functions
-- depends_on: devices
create or replace function coordinator.lookup_device_by_mac(p_mac text)
returns jsonb
language sql
as $$
  select jsonb_build_object(
    'device_id', mac_id,
    'username', username,
    'display_name', display_name,
    'hostname', hostname
  )
  from devices
  where lower(mac_id) = lower(p_mac)
  limit 1;
$$;

-- object: coordinator.list_authorized_networks
-- folder: functions
-- depends_on: wireless_authorized_networks
create or replace function coordinator.list_authorized_networks()
returns jsonb
language sql
as $$
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'ssid', ssid,
      'bssid', lower(bssid),
      'location_id', location_id,
      'label', label,
      'enabled', enabled
    )
  ), '[]'::jsonb)
  from wireless_authorized_networks
  where enabled;
$$;

-- object: coordinator.flush_probe_batch
-- folder: functions
-- depends_on: wireless_clients, wireless_authorized_networks
create or replace function coordinator.flush_probe_batch(p_probes jsonb)
returns integer
language plpgsql
as $$
declare
  v_inserted integer := 0;
  v_probes jsonb;
  v_probe jsonb;
begin
  v_probes := case
    when jsonb_typeof(p_probes) = 'array' then p_probes
    when jsonb_typeof(p_probes) = 'object'
      and jsonb_typeof(p_probes->'probes') = 'array' then p_probes->'probes'
    else null
  end;

  if v_probes is null then
    raise exception 'coordinator.flush_probe_batch requires a probe array or envelope with probes array';
  end if;

  for v_probe in select jsonb_array_elements(v_probes)
  loop
    insert into wireless_clients (ssid, client_mac, known_bssid, first_seen, last_seen, probe_count)
    values (
      v_probe->>'ssid',
      v_probe->>'client_mac',
      (select bssid from wireless_authorized_networks
       where lower(ssid) = lower(v_probe->>'ssid') and enabled limit 1),
      (v_probe->>'first_seen')::timestamptz,
      (v_probe->>'last_seen')::timestamptz,
      (v_probe->>'probe_count')::integer
    )
    on conflict (ssid, client_mac) do update
      set first_seen = least(wireless_clients.first_seen, excluded.first_seen),
          last_seen = greatest(wireless_clients.last_seen, excluded.last_seen),
          probe_count = wireless_clients.probe_count + excluded.probe_count,
          known_bssid = coalesce(excluded.known_bssid, wireless_clients.known_bssid);
    v_inserted := v_inserted + 1;
  end loop;
  return v_inserted;
end;
$$;

-- object: coordinator.pending_ledger_count
-- folder: functions
-- depends_on: sync_events
-- Backpressure: count events waiting in the ingest pipeline (pending + processing).
-- Called every iteration to decide whether to pull more from Redpanda.
create or replace function coordinator.pending_ledger_count()
returns bigint
language sql stable
as $$
  select count(*)::bigint from sync_events where status in ('pending', 'processing');
$$;

-- object: vec_build_timing_profiles
-- folder: functions
-- depends_on: vec_timing_profiles
create or replace function vec_build_timing_profiles(
  p_from timestamptz default now() - interval '2 hours',
  p_to timestamptz default now(),
  p_window interval default interval '15 minutes'
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  if not vec_try_begin_job('vec_build_timing_profiles') then
    return 0;
  end if;

  with base as (
    select
      lower(nullif(coalesce(sse.source_mac, sse.payload->>'source_mac'), '')) as source_mac,
      nullif(coalesce(sse.sensor_id, sse.payload->>'sensor_id'), '') as sensor_id,
      nullif(coalesce(sse.location_id, sse.payload->>'location_id'), '') as location_id,
      date_bin(p_window, sse.observed_at, timestamptz '2000-01-01 00:00:00+00') as window_start,
      coalesce(sse.tsft_delta_us, timeline.tsft_delta_us) as tsft_delta_us,
      coalesce(sse.wall_clock_delta_ms, timeline.wall_clock_delta_ms) as wall_clock_delta_ms,
      coalesce(sse.frame_subtype, sse.payload->>'frame_subtype') as frame_subtype
    from sync_events_expanded sse
    left join v_wireless_session_timeline timeline
      on timeline.dedupe_key = sse.dedupe_key
    where sse.stream_name = 'wireless.audit'
      and sse.status = 'batched'
      and sse.observed_at >= p_from
      and sse.observed_at < p_to
      and nullif(coalesce(sse.source_mac, sse.payload->>'source_mac'), '') is not null
      and coalesce(sse.tsft_delta_us, timeline.tsft_delta_us) is not null
      and coalesce(sse.tsft_delta_us, timeline.tsft_delta_us) >= 0
  ),
  stats as (
    select
      source_mac,
      sensor_id,
      location_id,
      window_start,
      window_start + p_window as window_end,
      percentile_cont(0.50) within group (order by tsft_delta_us) as tsft_p50_us,
      percentile_cont(0.95) within group (order by tsft_delta_us) as tsft_p95_us,
      percentile_cont(0.75) within group (order by tsft_delta_us)
        - percentile_cont(0.25) within group (order by tsft_delta_us) as tsft_jitter,
      percentile_cont(0.50) within group (order by wall_clock_delta_ms) as wall_p50_ms,
      percentile_cont(0.75) within group (order by wall_clock_delta_ms)
        - percentile_cont(0.25) within group (order by wall_clock_delta_ms) as wall_jitter_ms
    from base
    group by source_mac, sensor_id, location_id, window_start
    having count(*) >= 5
  ),
  beacon_stats as (
    select
      source_mac,
      sensor_id,
      location_id,
      window_start,
      percentile_cont(0.50) within group (order by tsft_delta_us / 1000.0) as beacon_interval_median_ms,
      percentile_cont(0.75) within group (order by tsft_delta_us / 1000.0)
        - percentile_cont(0.25) within group (order by tsft_delta_us / 1000.0) as beacon_jitter_ms
    from base
    where frame_subtype ilike '%beacon%'
    group by source_mac, sensor_id, location_id, window_start
  ),
  prepared as (
    select
      md5(
        s.source_mac || '|' ||
        coalesce(s.sensor_id, '') || '|' ||
        coalesce(s.location_id, '') || '|' ||
        s.window_start::text || '|' ||
        s.window_end::text
      ) as profile_key,
      s.source_mac,
      s.sensor_id,
      s.location_id,
      s.window_start,
      s.window_end,
      s.tsft_p50_us,
      s.tsft_p95_us,
      s.tsft_jitter,
      s.wall_p50_ms,
      s.wall_jitter_ms,
      b.beacon_interval_median_ms,
      b.beacon_jitter_ms,
      concat_ws(
        E'\n',
        'kind: timing_profile',
        'tsft_p50_us: ' || round(coalesce(s.tsft_p50_us, 0)::numeric, 1),
        'tsft_p95_us: ' || round(coalesce(s.tsft_p95_us, 0)::numeric, 1),
        'tsft_jitter: ' || round(coalesce(s.tsft_jitter, 0)::numeric, 1),
        'wall_p50_ms: ' || round(coalesce(s.wall_p50_ms, 0)::numeric, 2),
        'wall_jitter_ms: ' || round(coalesce(s.wall_jitter_ms, 0)::numeric, 2),
        'beacon_interval_ms: ' || round(coalesce(b.beacon_interval_median_ms, 0)::numeric, 2),
        'beacon_jitter_ms: ' || round(coalesce(b.beacon_jitter_ms, 0)::numeric, 2)
      ) as embedding_text
    from stats s
    left join beacon_stats b
      on b.source_mac = s.source_mac
     and b.sensor_id is not distinct from s.sensor_id
     and b.location_id is not distinct from s.location_id
     and b.window_start = s.window_start
  ),
  upserted as (
    insert into vec_timing_profiles (
      profile_key, source_mac, sensor_id, location_id,
      window_start, window_end, embedding_text, created_at, updated_at
    )
    select
      profile_key, source_mac, sensor_id, location_id,
      window_start, window_end, embedding_text, now(), now()
    from prepared
    on conflict (profile_key) do update set
      source_mac = excluded.source_mac,
      sensor_id = excluded.sensor_id,
      location_id = excluded.location_id,
      window_start = excluded.window_start,
      window_end = excluded.window_end,
      embedding_text = excluded.embedding_text,
      updated_at = now()
    returning profile_id, profile_key
  )
  insert into vec_timing_profile_stats (
    profile_id, tsft_p50_us, tsft_p95_us, tsft_jitter,
    wall_p50_ms, wall_jitter_ms, beacon_interval_median_ms, beacon_jitter_ms
  )
  select
    upserted.profile_id, prepared.tsft_p50_us, prepared.tsft_p95_us,
    prepared.tsft_jitter, prepared.wall_p50_ms, prepared.wall_jitter_ms,
    prepared.beacon_interval_median_ms, prepared.beacon_jitter_ms
  from upserted
  join prepared using (profile_key)
  on conflict (profile_id) do update set
    tsft_p50_us = excluded.tsft_p50_us,
    tsft_p95_us = excluded.tsft_p95_us,
    tsft_jitter = excluded.tsft_jitter,
    wall_p50_ms = excluded.wall_p50_ms,
    wall_jitter_ms = excluded.wall_jitter_ms,
    beacon_interval_median_ms = excluded.beacon_interval_median_ms,
    beacon_jitter_ms = excluded.beacon_jitter_ms;

  get diagnostics v_count = row_count;
  perform vec_finish_job('vec_build_timing_profiles');
  return v_count;
exception when others then
  perform vec_finish_job('vec_build_timing_profiles');
  raise;
end;
$$;

-- object: vec_apply_similarity_flags
-- folder: functions
-- depends_on: vec_similarity_pairs, wireless_frames, wireless_shadow_alerts
create or replace function vec_apply_similarity_flags(
  p_model text default 'nomic-embed-text-v2-moe',
  p_event_dup_distance_threshold double precision default 0.05,
  p_behaviour_similarity_threshold double precision default 0.88
)
returns integer
language plpgsql
as $$
declare
  v_total integer := 0;
  v_count integer := 0;
begin
  if not vec_try_begin_job('vec_apply_similarity_flags') then
    return 0;
  end if;

  update wireless_frame_security target
     set dedupe_or_replay_suspect = true,
         updated_at = now()
   where target.dedupe_key in (
     select left_source_key
     from vec_similarity_pairs_expanded
     where pair_kind = 'event_event'
       and embedding_model = p_model
       and embedding_kind = 'event'
       and cosine_distance <= p_event_dup_distance_threshold
     union
     select right_source_key
     from vec_similarity_pairs_expanded
     where pair_kind = 'event_event'
       and embedding_model = p_model
       and embedding_kind = 'event'
       and cosine_distance <= p_event_dup_distance_threshold
   )
     and not coalesce(target.dedupe_or_replay_suspect, false);

  get diagnostics v_count = row_count;
  v_total := v_total + v_count;

  insert into wireless_shadow_alerts (
    source_mac, first_occurred_at, last_occurred_at, occurrence_count,
    destination_bssid, ssid, sensor_id, location_id, signal_dbm,
    reason, evidence, resolved_at, created_at, updated_at
  )
  select distinct on (right_snapshot.source_mac)
    right_snapshot.source_mac,
    least(left_snapshot.window_start, right_snapshot.window_start),
    greatest(left_snapshot.window_end, right_snapshot.window_end),
    1,
    null,
    null,
    right_snapshot.sensor_id,
    right_snapshot.location_id,
    right_snapshot.signal_avg_dbm::integer,
    'mac_rotation_suspected',
    jsonb_build_object(
      'matched_mac', left_snapshot.source_mac,
      'behaviour_similarity', round(pair.cosine_similarity::numeric, 4),
      'left_snapshot_id', left_snapshot.snapshot_id,
      'right_snapshot_id', right_snapshot.snapshot_id,
      'pair_id', pair.pair_id
    ),
    null,
    now(),
    now()
  from vec_similarity_pairs_expanded pair
  join vec_behaviour_snapshots_expanded left_snapshot on left_snapshot.snapshot_id::text = pair.left_source_key
  join vec_behaviour_snapshots_expanded right_snapshot on right_snapshot.snapshot_id::text = pair.right_source_key
  where pair.pair_kind = 'device_device'
    and pair.embedding_model = p_model
    and pair.embedding_kind = 'behaviour_window'
    and pair.cosine_similarity >= p_behaviour_similarity_threshold
    and left_snapshot.source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
    and right_snapshot.source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
    and left_snapshot.source_mac <> right_snapshot.source_mac
  order by right_snapshot.source_mac, pair.cosine_similarity desc
  on conflict (source_mac) do update set
    last_occurred_at = greatest(wireless_shadow_alerts.last_occurred_at, excluded.last_occurred_at),
    occurrence_count = coalesce(wireless_shadow_alerts.occurrence_count, 0) + case
      when excluded.last_occurred_at > wireless_shadow_alerts.last_occurred_at
      then excluded.occurrence_count
      else 0
    end,
    sensor_id = excluded.sensor_id,
    location_id = excluded.location_id,
    signal_dbm = excluded.signal_dbm,
    reason = excluded.reason,
    evidence = excluded.evidence,
    updated_at = now();

  get diagnostics v_count = row_count;
  v_total := v_total + v_count;

  perform vec_finish_job('vec_apply_similarity_flags');
  return v_total;
exception when others then
  perform vec_finish_job('vec_apply_similarity_flags');
  raise;
end;
$$;

-- object: vec_update_device_centroids
-- folder: functions
-- depends_on: device_identity_clusters, vec_embeddings
create or replace function vec_update_device_centroids(
  p_model text default 'nomic-embed-text-v2-moe',
  p_min_samples integer default 10,
  p_window interval default interval '7 days'
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  if not vec_try_begin_job('vec_update_device_centroids') then
    return 0;
  end if;

  with recent_embeddings as materialized (
    select
      lower(source_mac) as source_mac,
      embedding::vector(768) as emb,
      embedded_at
    from vec_embeddings_expanded
    where embedding_kind = 'event'
      and embedding_model = p_model
      and embedding_dimensions = 768
      and embedded_at >= now() - p_window
      and source_mac is not null
  ),
  cluster_centroids as (
    select
      dic.cluster_id,
      avg(recent.emb)::vector(768) as centroid,
      count(*)::integer as sample_count,
      min(recent.embedded_at) as first_seen_at,
      max(recent.embedded_at) as last_seen_at
    from device_identity_clusters dic
    join recent_embeddings recent
      on exists (
        select 1
        from unnest(dic.mac_ids) as cluster_mac(mac)
        where lower(cluster_mac.mac) = recent.source_mac
      )
    group by dic.cluster_id
    having count(*) >= p_min_samples
  ),
  updated as (
    update device_identity_clusters dic
       set embedding_centroid = cluster_centroids.centroid,
           centroid_updated_at = now(),
           centroid_sample_count = cluster_centroids.sample_count,
           first_seen = least(dic.first_seen, cluster_centroids.first_seen_at),
           last_seen = greatest(dic.last_seen, cluster_centroids.last_seen_at),
           updated_at = now()
      from cluster_centroids
     where dic.cluster_id = cluster_centroids.cluster_id
     returning 1
  ),
  unclustered_mac_centroids as (
    select
      recent.source_mac,
      avg(recent.emb)::vector(768) as centroid,
      count(*)::integer as sample_count,
      min(recent.embedded_at) as first_seen_at,
      max(recent.embedded_at) as last_seen_at
    from recent_embeddings recent
    where not exists (
      select 1
      from device_identity_clusters dic
      where exists (
        select 1
        from unnest(dic.mac_ids) as cluster_mac(mac)
        where lower(cluster_mac.mac) = recent.source_mac
      )
    )
    group by recent.source_mac
    having count(*) >= p_min_samples
  ),
  inserted as (
    insert into device_identity_clusters (
      mac_ids,
      size,
      embedding_centroid,
      centroid_updated_at,
      centroid_sample_count,
      first_seen,
      last_seen,
      created_at,
      updated_at
    )
    select
      array[source_mac],
      1,
      centroid,
      now(),
      sample_count,
      first_seen_at,
      last_seen_at,
      now(),
      now()
    from unclustered_mac_centroids
    returning 1
  )
  select count(*)::integer into v_count
  from (
    select 1 from updated
    union all
    select 1 from inserted
  ) changed;

  perform vec_finish_job('vec_update_device_centroids');
  return v_count;
exception when others then
  perform vec_finish_job('vec_update_device_centroids');
  raise;
end;
$$;

-- object: vec_fuse_device_identities
-- folder: functions
-- depends_on: device_identity_clusters, vec_similarity_pairs
create or replace function vec_fuse_device_identities(
  p_behaviour_distance_threshold double precision default 0.12,
  p_time_overlap_minutes integer default 30,
  p_timing_distance_threshold double precision default 0.05
)
returns integer
language plpgsql
as $$
declare
  v_pair record;
  v_cluster_ids bigint[];
  v_target_cluster_id bigint;
  v_merged_macs text[];
  v_count integer := 0;
  v_rows integer := 0;
begin
  if not vec_try_begin_job('vec_fuse_device_identities') then
    return 0;
  end if;

  for v_pair in
    with behaviour_pairs as (
      select
        lower(sp.left_source_mac) as mac_a,
        lower(sp.right_source_mac) as mac_b
      from vec_similarity_pairs_expanded sp
      join vec_behaviour_snapshots_expanded left_snapshot
        on left_snapshot.snapshot_id::text = sp.left_source_key
      join vec_behaviour_snapshots_expanded right_snapshot
        on right_snapshot.snapshot_id::text = sp.right_source_key
      where sp.pair_kind = 'device_device'
        and sp.embedding_kind = 'behaviour_window'
        and sp.cosine_distance <= p_behaviour_distance_threshold
        and sp.computed_at >= now() - interval '2 hours'
        and sp.left_source_mac is not null
        and sp.right_source_mac is not null
        and lower(sp.left_source_mac) <> lower(sp.right_source_mac)
        and left_snapshot.sensor_id is not distinct from right_snapshot.sensor_id
        and left_snapshot.location_id is not distinct from right_snapshot.location_id
        and abs(extract(epoch from (left_snapshot.window_start - right_snapshot.window_start))) <= p_time_overlap_minutes * 60
    ),
    timing_pairs as (
      select
        lower(sp.left_source_mac) as mac_a,
        lower(sp.right_source_mac) as mac_b
      from vec_similarity_pairs_expanded sp
      join vec_timing_profiles_expanded left_profile
        on left_profile.profile_id::text = sp.left_source_key
      join vec_timing_profiles_expanded right_profile
        on right_profile.profile_id::text = sp.right_source_key
      where sp.pair_kind = 'timing_timing'
        and sp.embedding_kind = 'timing_profile'
        and sp.cosine_distance <= p_timing_distance_threshold
        and sp.computed_at >= now() - interval '2 hours'
        and sp.left_source_mac is not null
        and sp.right_source_mac is not null
        and lower(sp.left_source_mac) <> lower(sp.right_source_mac)
        and left_profile.sensor_id is not distinct from right_profile.sensor_id
        and left_profile.location_id is not distinct from right_profile.location_id
    ),
    candidate_pairs as (
      select mac_a, mac_b from behaviour_pairs
      union
      select mac_a, mac_b from timing_pairs
    ),
    normalized_pairs as (
      select distinct
        least(mac_a, mac_b) as mac_a,
        greatest(mac_a, mac_b) as mac_b
      from candidate_pairs
      where mac_a ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
        and mac_b ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
        and (get_byte(decode(split_part(mac_a, ':', 1), 'hex'), 0) & 2) = 2
        and (get_byte(decode(split_part(mac_b, ':', 1), 'hex'), 0) & 2) = 2
    )
    select mac_a, mac_b
    from normalized_pairs
  loop
    select array_agg(cluster_id order by cluster_id)
      into v_cluster_ids
    from device_identity_clusters
    where exists (
      select 1
      from unnest(mac_ids) as cluster_mac(mac)
      where lower(cluster_mac.mac) in (v_pair.mac_a, v_pair.mac_b)
    );

    if v_cluster_ids is null or cardinality(v_cluster_ids) = 0 then
      insert into device_identity_clusters (
        mac_ids,
        size,
        first_seen,
        last_seen,
        created_at,
        updated_at
      )
      values (
        array[v_pair.mac_a, v_pair.mac_b],
        2,
        now(),
        now(),
        now(),
        now()
      );
      get diagnostics v_rows = row_count;
      v_count := v_count + v_rows;
    else
      v_target_cluster_id := v_cluster_ids[1];

      select array_agg(mac order by mac)
        into v_merged_macs
      from (
        select distinct lower(cluster_mac.mac) as mac
        from device_identity_clusters
        cross join lateral unnest(mac_ids) as cluster_mac(mac)
        where cluster_id = any(v_cluster_ids)
        union
        select v_pair.mac_a
        union
        select v_pair.mac_b
      ) merged;

      update device_identity_clusters target
         set mac_ids = v_merged_macs,
             size = cardinality(v_merged_macs),
             first_seen = (
               select min(first_seen)
               from device_identity_clusters
               where cluster_id = any(v_cluster_ids)
             ),
             last_seen = now(),
             updated_at = now()
       where target.cluster_id = v_target_cluster_id;

      get diagnostics v_rows = row_count;
      v_count := v_count + v_rows;

      if cardinality(v_cluster_ids) > 1 then
        delete from device_identity_clusters
        where cluster_id = any(v_cluster_ids[2:cardinality(v_cluster_ids)]);

        get diagnostics v_rows = row_count;
        v_count := v_count + v_rows;
      end if;
    end if;
  end loop;

  perform vec_finish_job('vec_fuse_device_identities');
  return v_count;
exception when others then
  perform vec_finish_job('vec_fuse_device_identities');
  raise;
end;
$$;

-- object: vec_reembed_on_alert
-- folder: functions
-- depends_on: vec_alerts, vec_embedding_jobs
create or replace function vec_reembed_on_alert()
returns trigger
language plpgsql
as $$
begin
  if new.alert_type = 'high_risk_ap' and new.source_mac is not null then
    with jobs_reset as (
      update vec_embedding_jobs
         set status = 'pending',
             content_sha256 = null,
             updated_at = now()
       where source_table = 'vec_baseline_profiles'
         and source_key = lower(new.source_mac)
         and status = 'completed'
      returning job_id
    )
    update vec_embedding_job_leases lease
       set due_at = now(),
           completed_at = null,
           lease_token = null,
           leased_at = null,
           locked_by = null,
           last_error = null
      from jobs_reset
     where lease.job_id = jobs_reset.job_id;
  end if;

  if new.alert_type = 'embedding_drift' and new.source_mac is not null then
    with jobs_reset as (
      update vec_embedding_jobs
         set status = 'pending',
             content_sha256 = null,
             updated_at = now()
       where source_table = 'sync_events'
         and status = 'completed'
         and source_key in (
           select dedupe_key
           from sync_events_expanded
           where lower(coalesce(source_mac, payload->>'source_mac')) = lower(new.source_mac)
             and observed_at >= now() - interval '2 hours'
         )
      returning job_id
    )
    update vec_embedding_job_leases lease
       set due_at = now(),
           completed_at = null,
           lease_token = null,
           leased_at = null,
           locked_by = null,
           last_error = null
      from jobs_reset
     where lease.job_id = jobs_reset.job_id;
  end if;

  return new;
end;
$$;

drop trigger if exists vec_alert_reembed on vec_alerts;

create trigger vec_alert_reembed
after insert on vec_alerts
for each row execute function vec_reembed_on_alert();

-- object: vec_complete_embedding_batch
-- folder: functions
-- depends_on: vec_embedding_jobs, vec_embedding_job_leases, vec_upsert_embedding
create or replace function vec_complete_embedding_batch(p_payload jsonb)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  perform 1;

  if p_payload is null or jsonb_typeof(p_payload) <> 'array' or jsonb_array_length(p_payload) = 0 then
    return 0;
  end if;

  with payload_rows as materialized (
    select *
    from jsonb_to_recordset(p_payload) as r(
      job_id bigint,
      lease_token text,
      source_table text,
      source_key text,
      source_observed_at timestamptz,
      source_stream_name text,
      source_sensor_id text,
      source_location_id text,
      source_mac text,
      embedding_model text,
      embedding_kind text,
      embedding_dimensions integer,
      content_sha256 text,
      content_text text,
      embedding text,
      metadata jsonb
    )
  ),
  locked as materialized (
    select payload.*
    from payload_rows payload
    join vec_embedding_jobs job on job.job_id = payload.job_id
    join vec_embedding_job_leases lease on lease.job_id = job.job_id
    where lease.lease_token is not distinct from payload.lease_token
    order by job.job_id
    for update of job, lease skip locked
  ),
  upserted as materialized (
    select
      locked.job_id,
      locked.lease_token,
      locked.content_sha256,
      vec_upsert_embedding(
        locked.source_table,
        locked.source_key,
        locked.source_observed_at,
        locked.source_stream_name,
        locked.source_sensor_id,
        locked.source_location_id,
        locked.source_mac,
        locked.embedding_model,
        locked.embedding_kind,
        locked.embedding_dimensions,
        locked.content_sha256,
        locked.content_text,
        locked.embedding::vector,
        coalesce(locked.metadata, '{}'::jsonb)
      ) as embedding_id
    from locked
  ),
  jobs_completed as (
    update vec_embedding_jobs job
       set status = 'completed',
           content_sha256 = upserted.content_sha256,
           updated_at = now()
      from upserted
     where job.job_id = upserted.job_id
    returning job.job_id
  ),
  leases_completed as (
    update vec_embedding_job_leases lease
       set completed_at = now(),
           lease_token = null,
           leased_at = null,
           locked_by = null,
           last_error = null
      from jobs_completed
     where lease.job_id = jobs_completed.job_id
    returning lease.job_id
  )
  select count(*) into v_count from leases_completed;

  return v_count;
end;
$$;

-- object: vec_complete_one_embedding
-- folder: functions
-- depends_on: vec_embedding_jobs, vec_embedding_job_leases, vec_upsert_embedding
create or replace function vec_complete_one_embedding(p_payload jsonb)
returns boolean
language plpgsql
as $$
begin
  if p_payload is null or jsonb_typeof(p_payload) <> 'object' then
    return false;
  end if;

  return exists (
    with payload as materialized (
      select *
      from jsonb_to_record(p_payload) as r(
        job_id bigint,
        lease_token text,
        source_table text,
        source_key text,
        source_observed_at timestamptz,
        source_stream_name text,
        source_sensor_id text,
        source_location_id text,
        source_mac text,
        embedding_model text,
        embedding_kind text,
        embedding_dimensions integer,
        content_sha256 text,
        content_text text,
        embedding text,
        metadata jsonb
      )
    ),
    locked as materialized (
      select payload.*
      from payload
      join vec_embedding_jobs job on job.job_id = payload.job_id
      join vec_embedding_job_leases lease on lease.job_id = job.job_id
      where lease.lease_token is not distinct from payload.lease_token
      for update of job, lease
    ),
    upserted as materialized (
      select
        locked.job_id,
        locked.content_sha256,
        vec_upsert_embedding(
          locked.source_table,
          locked.source_key,
          locked.source_observed_at,
          locked.source_stream_name,
          locked.source_sensor_id,
          locked.source_location_id,
          locked.source_mac,
          locked.embedding_model,
          locked.embedding_kind,
          locked.embedding_dimensions,
          locked.content_sha256,
          locked.content_text,
          locked.embedding::vector,
          coalesce(locked.metadata, '{}'::jsonb)
        ) as embedding_id
      from locked
    ),
    job_completed as (
      update vec_embedding_jobs job
         set status = 'completed',
             content_sha256 = upserted.content_sha256,
             updated_at = now()
        from upserted
       where job.job_id = upserted.job_id
      returning job.job_id
    ),
    lease_completed as (
      update vec_embedding_job_leases lease
         set completed_at = now(),
             lease_token = null,
             leased_at = null,
             locked_by = null,
             last_error = null
        from job_completed
       where lease.job_id = job_completed.job_id
      returning lease.job_id
    )
    select 1 from lease_completed
  );
end;
$$;

-- object: search_purge_expired_queries
-- folder: functions
-- depends_on: search_queries
-- Deletes expired search analytics rows; search_feedback rows cascade by query_id.
create or replace function search_purge_expired_queries(p_now timestamptz default now())
returns bigint
language plpgsql
as $$
declare
  v_deleted bigint;
begin
  delete from search_queries
   where expires_at < p_now;

  get diagnostics v_deleted = row_count;
  return v_deleted;
end;
$$;

-- object: coordinator event retention
-- folder: functions
-- depends_on: sync_events, wireless_frames, sync_event_payload_archives, sync_event_tombstones
create or replace function coordinator.list_wireless_payload_archive_candidates(
  p_hot_days integer default 7,
  p_limit integer default 100
)
returns table (
  dedupe_key text,
  stream_name text,
  observed_at timestamptz,
  payload_sha256 text,
  payload_bytes bigint,
  payload jsonb
)
language sql
volatile
as $$
  select
    event.dedupe_key,
    event.stream_name,
    event.observed_at,
    event.payload_sha256,
    pg_column_size(event.payload)::bigint as payload_bytes,
    event.payload
  from sync_events event
  left join sync_event_payload_archives archive
    on archive.dedupe_key = event.dedupe_key
  where event.stream_name = 'wireless.audit'
    and event.status = 'batched'
    and event.payload is not null
    and event.observed_at < now() - make_interval(days => greatest(coalesce(p_hot_days, 7), 1))
    and archive.dedupe_key is null
  order by event.observed_at asc, event.dedupe_key asc
  limit greatest(coalesce(p_limit, 100), 1)
  for update of event skip locked
$$;

create or replace function coordinator.record_payload_archive(
  p_dedupe_key text,
  p_payload_sha256 text,
  p_archive_uri text,
  p_payload_bytes bigint
)
returns boolean
language plpgsql
as $$
declare
  v_event record;
  v_updated integer := 0;
begin
  if nullif(p_dedupe_key, '') is null then
    raise exception 'payload archive missing dedupe_key';
  end if;
  if nullif(p_archive_uri, '') is null then
    raise exception 'payload archive missing archive_uri';
  end if;

  select dedupe_key, stream_name, observed_at, payload_sha256
    into v_event
    from sync_events
   where dedupe_key = p_dedupe_key
     and payload is not null
   for update;

  if not found then
    return false;
  end if;

  if p_payload_sha256 is not null
     and v_event.payload_sha256 is not null
     and v_event.payload_sha256 <> p_payload_sha256 then
    return false;
  end if;

  insert into sync_event_payload_archives (
    dedupe_key,
    stream_name,
    observed_at,
    payload_sha256,
    archive_uri,
    payload_bytes,
    archived_at,
    created_at,
    updated_at
  )
  values (
    v_event.dedupe_key,
    v_event.stream_name,
    v_event.observed_at,
    coalesce(p_payload_sha256, v_event.payload_sha256),
    p_archive_uri,
    greatest(coalesce(p_payload_bytes, 0), 0),
    now(),
    now(),
    now()
  )
  on conflict (dedupe_key) do update set
    payload_sha256 = excluded.payload_sha256,
    archive_uri = excluded.archive_uri,
    payload_bytes = excluded.payload_bytes,
    archived_at = now(),
    updated_at = now();

  update sync_events
     set payload = null,
         updated_at = now()
   where dedupe_key = p_dedupe_key
     and payload is not null
     and (
       p_payload_sha256 is null
       or payload_sha256 is null
       or payload_sha256 = p_payload_sha256
     );
  get diagnostics v_updated = row_count;

  return v_updated > 0;
end;
$$;

create or replace function coordinator.prune_sync_event_retention(
  p_event_retention_days integer default 30,
  p_tombstone_retention_days integer default 45,
  p_limit integer default 5000
)
returns jsonb
language plpgsql
as $$
declare
  v_tombstoned integer := 0;
  v_wireless_frames_deleted integer := 0;
  v_deleted integer := 0;
  v_expired_tombstones integer := 0;
begin
  with candidates as materialized (
    select
      event.dedupe_key,
      event.stream_name,
      event.payload_sha256,
      event.observed_at
    from sync_events event
    where event.observed_at < now() - make_interval(days => greatest(coalesce(p_event_retention_days, 30), 1))
      and event.status not in ('pending', 'processing')
      and (
        event.stream_name <> 'wireless.audit'
        or event.payload is null
        or exists (
          select 1
          from sync_event_payload_archives archive
          where archive.dedupe_key = event.dedupe_key
        )
      )
    order by event.observed_at asc, event.dedupe_key asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  tombstoned as (
    insert into sync_event_tombstones (
      dedupe_key,
      stream_name,
      payload_sha256,
      observed_at,
      expires_at,
      created_at,
      updated_at
    )
    select
      dedupe_key,
      stream_name,
      payload_sha256,
      observed_at,
      now() + make_interval(days => greatest(coalesce(p_tombstone_retention_days, 45), 1)),
      now(),
      now()
    from candidates
    on conflict (dedupe_key) do update set
      stream_name = excluded.stream_name,
      payload_sha256 = excluded.payload_sha256,
      observed_at = excluded.observed_at,
      expires_at = greatest(sync_event_tombstones.expires_at, excluded.expires_at),
      updated_at = now()
    returning 1
  )
  select count(*) into v_tombstoned from tombstoned;

  with candidates as materialized (
    select event.dedupe_key
    from sync_events event
    where event.observed_at < now() - make_interval(days => greatest(coalesce(p_event_retention_days, 30), 1))
      and event.status not in ('pending', 'processing')
      and exists (
        select 1
        from sync_event_tombstones tombstone
        where tombstone.dedupe_key = event.dedupe_key
      )
      and (
        event.stream_name <> 'wireless.audit'
        or event.payload is null
        or exists (
          select 1
          from sync_event_payload_archives archive
          where archive.dedupe_key = event.dedupe_key
        )
      )
    order by event.observed_at asc, event.dedupe_key asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  wireless_deleted as (
    delete from wireless_frames frame
    using candidates
    where frame.dedupe_key = candidates.dedupe_key
    returning 1
  )
  select count(*) into v_wireless_frames_deleted from wireless_deleted;

  with candidates as materialized (
    select event.dedupe_key
    from sync_events event
    where event.observed_at < now() - make_interval(days => greatest(coalesce(p_event_retention_days, 30), 1))
      and event.status not in ('pending', 'processing')
      and exists (
        select 1
        from sync_event_tombstones tombstone
        where tombstone.dedupe_key = event.dedupe_key
      )
      and (
        event.stream_name <> 'wireless.audit'
        or event.payload is null
        or exists (
          select 1
          from sync_event_payload_archives archive
          where archive.dedupe_key = event.dedupe_key
        )
      )
    order by event.observed_at asc, event.dedupe_key asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from sync_events event
    using candidates
    where event.dedupe_key = candidates.dedupe_key
    returning 1
  )
  select count(*) into v_deleted from deleted;

  delete from sync_event_tombstones
   where expires_at < now();
  get diagnostics v_expired_tombstones = row_count;

  return jsonb_build_object(
    'tombstoned', v_tombstoned,
    'wireless_frames_deleted', v_wireless_frames_deleted,
    'deleted', v_deleted,
    'expired_tombstones', v_expired_tombstones
  );
end;
$$;

-- object: vec_prune_retention
-- folder: functions
-- depends_on: vec_embeddings, vec_embedding_jobs, vec_similarity_pairs
create or replace function vec_prune_retention(
  p_event_embedding_days integer default 14,
  p_rollup_embedding_days integer default 30,
  p_similarity_pair_days integer default 14,
  p_completed_job_days integer default 7,
  p_failed_job_days integer default 30,
  p_limit integer default 5000
)
returns jsonb
language plpgsql
as $$
declare
  v_pairs_deleted integer := 0;
  v_event_embeddings_deleted integer := 0;
  v_rollup_embeddings_deleted integer := 0;
  v_completed_jobs_deleted integer := 0;
  v_failed_jobs_deleted integer := 0;
  v_behaviour_deleted integer := 0;
  v_sequences_deleted integer := 0;
  v_timing_deleted integer := 0;
begin
  with doomed as (
    select pair_id
    from vec_similarity_pairs_expanded
    where computed_at < now() - make_interval(days => greatest(coalesce(p_similarity_pair_days, 14), 1))
    order by computed_at asc, pair_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_similarity_pairs pair
    using doomed
    where pair.pair_id = doomed.pair_id
    returning 1
  )
  select count(*) into v_pairs_deleted from deleted;

  with doomed as (
    select embedding_id
    from vec_embeddings_expanded
    where embedding_kind = 'event'
      and coalesce(source_observed_at, embedded_at) < now() - make_interval(days => greatest(coalesce(p_event_embedding_days, 14), 1))
    order by coalesce(source_observed_at, embedded_at) asc, embedding_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_embeddings embedding
    using doomed
    where embedding.embedding_id = doomed.embedding_id
    returning 1
  )
  select count(*) into v_event_embeddings_deleted from deleted;

  with doomed as (
    select embedding_id
    from vec_embeddings_expanded
    where embedding_kind in ('behaviour_window', 'baseline_profile', 'frame_sequence', 'infrastructure_subgraph', 'timing_profile')
      and coalesce(source_observed_at, embedded_at) < now() - make_interval(days => greatest(coalesce(p_rollup_embedding_days, 30), 1))
    order by coalesce(source_observed_at, embedded_at) asc, embedding_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_embeddings embedding
    using doomed
    where embedding.embedding_id = doomed.embedding_id
    returning 1
  )
  select count(*) into v_rollup_embeddings_deleted from deleted;

  with doomed as (
    select job_id
    from vec_embedding_jobs_expanded
    where status = 'completed'
      and coalesce(completed_at, updated_at) < now() - make_interval(days => greatest(coalesce(p_completed_job_days, 7), 1))
    order by coalesce(completed_at, updated_at) asc, job_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_embedding_jobs job
    using doomed
    where job.job_id = doomed.job_id
    returning 1
  )
  select count(*) into v_completed_jobs_deleted from deleted;

  with doomed as (
    select job_id
    from vec_embedding_jobs_expanded
    where status = 'failed'
      and updated_at < now() - make_interval(days => greatest(coalesce(p_failed_job_days, 30), 1))
    order by updated_at asc, job_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_embedding_jobs job
    using doomed
    where job.job_id = doomed.job_id
    returning 1
  )
  select count(*) into v_failed_jobs_deleted from deleted;

  with doomed as (
    select snapshot_id
    from vec_behaviour_snapshots_expanded
    where window_end < now() - make_interval(days => greatest(coalesce(p_rollup_embedding_days, 30), 1))
    order by window_end asc, snapshot_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_behaviour_snapshots snapshot
    using doomed
    where snapshot.snapshot_id = doomed.snapshot_id
    returning 1
  )
  select count(*) into v_behaviour_deleted from deleted;

  with doomed as (
    select session_key
    from vec_frame_sequences
    where window_end < now() - make_interval(days => greatest(coalesce(p_rollup_embedding_days, 30), 1))
    order by window_end asc, session_key asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_frame_sequences sequence
    using doomed
    where sequence.session_key = doomed.session_key
    returning 1
  )
  select count(*) into v_sequences_deleted from deleted;

  with doomed as (
    select profile_id
    from vec_timing_profiles_expanded
    where window_end < now() - make_interval(days => greatest(coalesce(p_rollup_embedding_days, 30), 1))
    order by window_end asc, profile_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_timing_profiles profile
    using doomed
    where profile.profile_id = doomed.profile_id
    returning 1
  )
  select count(*) into v_timing_deleted from deleted;

  return jsonb_build_object(
    'similarity_pairs_deleted', v_pairs_deleted,
    'event_embeddings_deleted', v_event_embeddings_deleted,
    'rollup_embeddings_deleted', v_rollup_embeddings_deleted,
    'completed_jobs_deleted', v_completed_jobs_deleted,
    'failed_jobs_deleted', v_failed_jobs_deleted,
    'behaviour_snapshots_deleted', v_behaviour_deleted,
    'frame_sequences_deleted', v_sequences_deleted,
    'timing_profiles_deleted', v_timing_deleted
  );
end;
$$;

-- object: coordinator_backlog_retry_caps
-- folder: functions
-- depends_on: sync_backlog

create or replace function coordinator.fail_exhausted_backlog()
returns integer
language plpgsql
as $$
declare
  v_updated integer := 0;
begin
  update sync_backlog
     set status = 'failed',
         updated_at = now()
   where status = 'pending'
     and attempt_count >= max_attempts;

  get diagnostics v_updated = row_count;
  return v_updated;
end;
$$;

create or replace function coordinator.save_backlog_entry(p_payload jsonb)
returns void
language plpgsql
as $$
declare
  v_max_attempts integer := 5;
  v_attempt_count integer := 0;
begin
  if nullif(p_payload->>'dedupe_key', '') is null then
    raise exception 'coordinator.save_backlog_entry requires dedupe_key';
  end if;

  if coalesce(p_payload->>'max_attempts', '') ~ '^[0-9]+$' then
    v_max_attempts := greatest(coordinator.safe_int(p_payload->>'max_attempts'), 1);
  end if;

  if coalesce(p_payload->>'attempt_count', '') ~ '^[0-9]+$' then
    v_attempt_count := greatest(coordinator.safe_int(p_payload->>'attempt_count'), 0);
  end if;

  insert into sync_backlog (
    dedupe_key,
    stream_name,
    payload,
    failure_stage,
    status,
    attempt_count,
    max_attempts,
    last_error,
    created_at,
    updated_at
  )
  values (
    p_payload->>'dedupe_key',
    p_payload->>'stream_name',
    p_payload->'payload',
    coalesce(nullif(p_payload->>'failure_stage', ''), 'pre_publish'),
    case when v_attempt_count >= v_max_attempts then 'failed' else 'pending' end,
    v_attempt_count,
    v_max_attempts,
    nullif(p_payload->>'error', ''),
    now(),
    now()
  )
  on conflict (dedupe_key) do update
    set stream_name = excluded.stream_name,
        payload = excluded.payload,
        failure_stage = excluded.failure_stage,
        attempt_count = sync_backlog.attempt_count + 1,
        max_attempts = greatest(sync_backlog.max_attempts, excluded.max_attempts, 1),
        status = case
          when sync_backlog.attempt_count + 1 >= greatest(sync_backlog.max_attempts, excluded.max_attempts, 1)
          then 'failed'
          else 'pending'
        end,
        last_error = excluded.last_error,
        updated_at = now();
end;
$$;

create or replace function coordinator.list_pending_backlog()
returns jsonb
language plpgsql
as $$
declare
  v_result jsonb;
begin
  perform coordinator.fail_exhausted_backlog();

  select coalesce(jsonb_agg(
    jsonb_build_object(
      'dedupe_key', dedupe_key,
      'stream_name', stream_name,
      'payload', payload,
      'failure_stage', failure_stage,
      'attempt_count', attempt_count,
      'max_attempts', max_attempts,
      'created_at', created_at
    ) order by created_at asc
  ), '[]'::jsonb)
    into v_result
  from (
    select dedupe_key, stream_name, payload, failure_stage, attempt_count, max_attempts, created_at
    from sync_backlog
    where status = 'pending'
      and attempt_count < max_attempts
    order by created_at asc
    limit 100
  ) pending;

  return v_result;
end;
$$;

-- object: vec_job_lock_ttl_helpers
-- folder: functions
-- depends_on: vec_job_locks

create or replace function vec_prune_stale_job_locks(
  p_lock_ttl interval default interval '5 minutes'
)
returns integer
language plpgsql
as $$
declare
  v_deleted integer := 0;
begin
  delete from vec_job_locks
   where locked_at < now() - coalesce(p_lock_ttl, interval '5 minutes');

  get diagnostics v_deleted = row_count;
  return v_deleted;
end;
$$;

create or replace function vec_try_begin_job(p_job_name text)
returns boolean
language plpgsql
as $$
begin
  if not pg_try_advisory_lock(hashtextextended(p_job_name, 0)) then
    raise notice '% already running, skipping', p_job_name;
    return false;
  end if;

  delete from vec_job_locks
   where job_name = p_job_name
     and locked_at < now() - interval '5 minutes';

  insert into vec_job_locks (job_name, locked_at, locked_by)
  values (p_job_name, now(), pg_backend_pid()::text)
  on conflict (job_name) do update
    set locked_at = excluded.locked_at,
        locked_by = excluded.locked_by;

  return true;
end;
$$;

create or replace function vec_try_begin_maintenance_job(p_job_name text)
returns boolean
language plpgsql
as $$
declare
  v_lock_name text := 'vec_maintenance_' || p_job_name;
begin
  if not pg_try_advisory_lock(hashtextextended(v_lock_name, 0)) then
    raise notice 'vector maintenance already running, skipping %', p_job_name;
    return false;
  end if;

  delete from vec_job_locks
   where job_name like 'maintenance:%'
     and locked_at < now() - interval '5 minutes';

  insert into vec_job_locks (job_name, locked_at, locked_by)
  values ('maintenance:' || p_job_name, now(), pg_backend_pid()::text)
  on conflict (job_name) do update
    set locked_at = excluded.locked_at,
        locked_by = excluded.locked_by;

  return true;
end;
$$;

create or replace function vec_finish_maintenance_job(p_job_name text)
returns void
language plpgsql
as $$
declare
  v_lock_name text := 'vec_maintenance_' || p_job_name;
begin
  delete from vec_job_locks where job_name = 'maintenance:' || p_job_name;
  perform pg_advisory_unlock(hashtextextended(v_lock_name, 0));
end;
$$;

-- object: vec_device_graph_retention
-- folder: functions
-- depends_on: vec_dns_resolver_ledger, vec_infrastructure_graph

create or replace function vec_prune_device_graph_retention(
  p_dns_ledger_days integer default 90,
  p_infrastructure_edge_days integer default 90,
  p_limit integer default 5000
)
returns jsonb
language plpgsql
as $$
declare
  v_dns_deleted integer := 0;
  v_edges_deleted integer := 0;
begin
  with doomed as (
    select ledger_id
    from vec_dns_resolver_ledger
    where expires_at < now()
       or observed_at < now() - make_interval(days => greatest(coalesce(p_dns_ledger_days, 90), 1))
    order by observed_at asc, ledger_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_dns_resolver_ledger ledger
    using doomed
    where ledger.ledger_id = doomed.ledger_id
    returning 1
  )
  select count(*) into v_dns_deleted from deleted;

  with doomed as (
    select edge_id
    from vec_infrastructure_graph
    where last_seen < now() - make_interval(days => greatest(coalesce(p_infrastructure_edge_days, 90), 1))
    order by last_seen asc, edge_id asc
    limit greatest(coalesce(p_limit, 5000), 1)
  ),
  deleted as (
    delete from vec_infrastructure_graph graph
    using doomed
    where graph.edge_id = doomed.edge_id
    returning 1
  )
  select count(*) into v_edges_deleted from deleted;

  return jsonb_build_object(
    'dns_ledger_deleted', v_dns_deleted,
    'infrastructure_edges_deleted', v_edges_deleted
  );
end;
$$;

-- object: coordinator_flush_probe_batch_bigint
-- folder: functions
-- depends_on: wireless_clients, wireless_authorized_networks

create or replace function coordinator.flush_probe_batch(p_probes jsonb)
returns integer
language plpgsql
as $$
declare
  v_inserted integer := 0;
  v_probes jsonb;
  v_probe jsonb;
begin
  v_probes := case
    when jsonb_typeof(p_probes) = 'array' then p_probes
    when jsonb_typeof(p_probes) = 'object'
      and jsonb_typeof(p_probes->'probes') = 'array' then p_probes->'probes'
    else null
  end;

  if v_probes is null then
    raise exception 'coordinator.flush_probe_batch requires a probe array or envelope with probes array';
  end if;

  for v_probe in select jsonb_array_elements(v_probes)
  loop
    insert into wireless_clients (ssid, client_mac, known_bssid, first_seen, last_seen, probe_count)
    values (
      v_probe->>'ssid',
      v_probe->>'client_mac',
      (select bssid from wireless_authorized_networks
       where lower(ssid) = lower(v_probe->>'ssid') and enabled limit 1),
      (v_probe->>'first_seen')::timestamptz,
      (v_probe->>'last_seen')::timestamptz,
      (v_probe->>'probe_count')::bigint
    )
    on conflict (ssid, client_mac) do update
      set first_seen = least(wireless_clients.first_seen, excluded.first_seen),
          last_seen = greatest(wireless_clients.last_seen, excluded.last_seen),
          probe_count = wireless_clients.probe_count + excluded.probe_count,
          known_bssid = coalesce(excluded.known_bssid, wireless_clients.known_bssid);
    v_inserted := v_inserted + 1;
  end loop;
  return v_inserted;
end;
$$;

-- object: coordinator.record_scan_request_batch tombstone-safe wireless frame upsert
-- folder: functions
-- depends_on: sync_events, sync_event_tombstones, wireless_frames
create or replace function coordinator.record_scan_request_batch(
  p_requests jsonb[],
  p_payloads jsonb[],
  p_payload_sha256s text[],
  p_stream_names text[]
)
returns integer
language plpgsql
as $$
declare
  v_recorded_count integer := 0;
begin
  if cardinality(p_requests) <> cardinality(p_payloads)
     or cardinality(p_requests) <> cardinality(p_payload_sha256s) then
    raise exception 'record_scan_request_batch array length mismatch';
  end if;

  if exists (
    with incoming as (
      select raw.request->>'stream_name' as stream_name,
             raw.request->>'dedupe_key' as dedupe_key
        from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
    ),
    configured_streams as (
      select btrim(configured.stream_name) as stream_name
        from unnest(p_stream_names) as configured(stream_name)
       where btrim(configured.stream_name) <> ''
    )
    select 1
      from incoming
      join configured_streams on configured_streams.stream_name = incoming.stream_name
     where nullif(dedupe_key, '') is null
  ) then
    raise exception 'scan request missing dedupe_key';
  end if;

  if exists (
    with incoming as (
      select raw.request->>'stream_name' as stream_name,
             raw.request->>'payload_ref' as payload_ref
        from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
    ),
    configured_streams as (
      select btrim(configured.stream_name) as stream_name
        from unnest(p_stream_names) as configured(stream_name)
       where btrim(configured.stream_name) <> ''
    )
    select 1
      from incoming
      join configured_streams on configured_streams.stream_name = incoming.stream_name
     where nullif(payload_ref, '') is null
  ) then
    raise exception 'scan request missing payload_ref';
  end if;

  with incoming as (
    select raw.request,
           raw.payload,
           raw.payload_sha256,
           raw.request->>'stream_name' as stream_name,
           raw.request->>'dedupe_key' as dedupe_key,
           raw.request->>'payload_ref' as payload_ref,
           raw.request->>'observed_at' as observed_at_text
      from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
  ),
  configured_streams as (
    select btrim(configured.stream_name) as stream_name
      from unnest(p_stream_names) as configured(stream_name)
     where btrim(configured.stream_name) <> ''
  ),
  typed as (
    select incoming.*,
           coordinator.safe_timestamptz(incoming.observed_at_text) as observed_at
      from incoming
  ),
  valid as (
    select typed.*
      from typed
      join configured_streams on configured_streams.stream_name = typed.stream_name
      left join sync_event_tombstones tombstone
        on tombstone.dedupe_key = typed.dedupe_key
       and tombstone.stream_name = typed.stream_name
       and tombstone.expires_at > now()
     where tombstone.dedupe_key is null
       and typed.observed_at is not null
  ),
  upserted as (
    insert into sync_events (
      dedupe_key,
      stream_name,
      observed_at,
      payload_ref,
      payload,
      payload_sha256,
      status,
      attempt_count,
      last_error,
      producer,
      event_kind,
      created_at,
      updated_at
    )
    select dedupe_key,
           stream_name,
           observed_at,
           payload_ref,
           payload,
           payload_sha256,
           'pending',
           0,
           null,
           'ssl-proxy',
           nullif(payload->>'type', ''),
           now(),
           now()
      from valid
    on conflict (dedupe_key)
    do update set
      observed_at = excluded.observed_at,
      payload_ref = excluded.payload_ref,
      payload = coalesce(excluded.payload, sync_events.payload),
      payload_sha256 = excluded.payload_sha256,
      producer = excluded.producer,
      event_kind = coalesce(excluded.event_kind, sync_events.event_kind),
      status = case
        when sync_events.status in ('pending', 'failed') then 'pending'
        else sync_events.status
      end,
      last_error = case
        when sync_events.status in ('pending', 'failed') then null
        else sync_events.last_error
      end,
      updated_at = now()
    returning 1
  )
  select count(*) into v_recorded_count from upserted;

  perform coordinator.upsert_wireless_frame_from_payload(
    raw.dedupe_key,
    raw.stream_name,
    raw.payload
  )
  from (
    select raw.request,
           raw.payload,
           raw.request->>'stream_name' as stream_name,
           raw.request->>'dedupe_key' as dedupe_key
      from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
  ) raw
  join unnest(p_stream_names) as configured(stream_name)
    on btrim(configured.stream_name) = raw.stream_name
  left join sync_event_tombstones tombstone
    on tombstone.dedupe_key = raw.dedupe_key
   and tombstone.stream_name = raw.stream_name
   and tombstone.expires_at > now()
  where raw.stream_name = 'wireless.audit'
    and tombstone.dedupe_key is null
    and coordinator.safe_timestamptz(raw.request->>'observed_at') is not null;

  return coalesce(v_recorded_count, 0);
end;
$$;

-- object: coordinator.record_scan_request_batch duplicate-safe batch upsert
-- folder: functions
-- depends_on: sync_events, sync_event_tombstones, wireless_frames
create or replace function coordinator.record_scan_request_batch(
  p_requests jsonb[],
  p_payloads jsonb[],
  p_payload_sha256s text[],
  p_stream_names text[]
)
returns integer
language plpgsql
as $$
declare
  v_recorded_count integer := 0;
begin
  if cardinality(p_requests) <> cardinality(p_payloads)
     or cardinality(p_requests) <> cardinality(p_payload_sha256s) then
    raise exception 'record_scan_request_batch array length mismatch';
  end if;

  if exists (
    with incoming as (
      select raw.request->>'stream_name' as stream_name,
             raw.request->>'dedupe_key' as dedupe_key
        from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
    ),
    configured_streams as (
      select distinct btrim(configured.stream_name) as stream_name
        from unnest(p_stream_names) as configured(stream_name)
       where btrim(configured.stream_name) <> ''
    )
    select 1
      from incoming
      join configured_streams on configured_streams.stream_name = incoming.stream_name
     where nullif(dedupe_key, '') is null
  ) then
    raise exception 'scan request missing dedupe_key';
  end if;

  if exists (
    with incoming as (
      select raw.request->>'stream_name' as stream_name,
             raw.request->>'payload_ref' as payload_ref
        from unnest(p_requests, p_payloads, p_payload_sha256s) as raw(request, payload, payload_sha256)
    ),
    configured_streams as (
      select distinct btrim(configured.stream_name) as stream_name
        from unnest(p_stream_names) as configured(stream_name)
       where btrim(configured.stream_name) <> ''
    )
    select 1
      from incoming
      join configured_streams on configured_streams.stream_name = incoming.stream_name
     where nullif(payload_ref, '') is null
  ) then
    raise exception 'scan request missing payload_ref';
  end if;

  with incoming as (
    select raw.request,
           raw.payload,
           raw.payload_sha256,
           raw.input_ordinality,
           raw.request->>'stream_name' as stream_name,
           raw.request->>'dedupe_key' as dedupe_key,
           raw.request->>'payload_ref' as payload_ref,
           raw.request->>'observed_at' as observed_at_text
      from unnest(p_requests, p_payloads, p_payload_sha256s)
           with ordinality as raw(request, payload, payload_sha256, input_ordinality)
  ),
  configured_streams as (
    select distinct btrim(configured.stream_name) as stream_name
      from unnest(p_stream_names) as configured(stream_name)
     where btrim(configured.stream_name) <> ''
  ),
  typed as (
    select incoming.*,
           coordinator.safe_timestamptz(incoming.observed_at_text) as observed_at
      from incoming
  ),
  valid as (
    select typed.*
      from typed
      join configured_streams on configured_streams.stream_name = typed.stream_name
      left join sync_event_tombstones tombstone
        on tombstone.dedupe_key = typed.dedupe_key
       and tombstone.stream_name = typed.stream_name
       and tombstone.expires_at > now()
     where tombstone.dedupe_key is null
       and typed.observed_at is not null
  ),
  deduplicated as (
    select distinct on (valid.dedupe_key) valid.*
      from valid
     order by valid.dedupe_key, valid.input_ordinality desc
  ),
  upserted as (
    insert into sync_events (
      dedupe_key,
      stream_name,
      observed_at,
      payload_ref,
      payload,
      payload_sha256,
      status,
      attempt_count,
      last_error,
      producer,
      event_kind,
      created_at,
      updated_at
    )
    select dedupe_key,
           stream_name,
           observed_at,
           payload_ref,
           payload,
           payload_sha256,
           'pending',
           0,
           null,
           'ssl-proxy',
           nullif(payload->>'type', ''),
           now(),
           now()
      from deduplicated
    on conflict (dedupe_key)
    do update set
      observed_at = excluded.observed_at,
      payload_ref = excluded.payload_ref,
      payload = coalesce(excluded.payload, sync_events.payload),
      payload_sha256 = excluded.payload_sha256,
      producer = excluded.producer,
      event_kind = coalesce(excluded.event_kind, sync_events.event_kind),
      status = case
        when sync_events.status in ('pending', 'failed') then 'pending'
        else sync_events.status
      end,
      last_error = case
        when sync_events.status in ('pending', 'failed') then null
        else sync_events.last_error
      end,
      updated_at = now()
    returning 1
  )
  select count(*) into v_recorded_count from upserted;

  perform coordinator.upsert_wireless_frame_from_payload(
    deduplicated.dedupe_key,
    deduplicated.stream_name,
    deduplicated.payload
  )
  from (
    select distinct on (raw.dedupe_key)
           raw.dedupe_key,
           raw.stream_name,
           raw.payload
      from (
        select raw.request,
               raw.payload,
               raw.input_ordinality,
               raw.request->>'stream_name' as stream_name,
               raw.request->>'dedupe_key' as dedupe_key
          from unnest(p_requests, p_payloads, p_payload_sha256s)
               with ordinality as raw(request, payload, payload_sha256, input_ordinality)
      ) raw
      join (
        select distinct btrim(configured.stream_name) as stream_name
          from unnest(p_stream_names) as configured(stream_name)
         where btrim(configured.stream_name) <> ''
      ) configured_streams on configured_streams.stream_name = raw.stream_name
      left join sync_event_tombstones tombstone
        on tombstone.dedupe_key = raw.dedupe_key
       and tombstone.stream_name = raw.stream_name
       and tombstone.expires_at > now()
     where raw.dedupe_key is not null
       and tombstone.dedupe_key is null
       and coordinator.safe_timestamptz(raw.request->>'observed_at') is not null
     order by raw.dedupe_key, raw.input_ordinality desc
  ) deduplicated
  where deduplicated.stream_name = 'wireless.audit';

  return coalesce(v_recorded_count, 0);
end;
$$;

-- object: wireless_frames_expanded
-- folder: views
-- depends_on: wireless_frames, wireless_frame_radio, wireless_frame_qos, wireless_frame_network, wireless_frame_app_signals, wireless_frame_identity, wireless_frame_security
create or replace view wireless_frames_expanded as
select
  core.dedupe_key,
  core.sensor_id,
  core.location_id,
  identity.username,
  identity.event_type,
  core.schema_version,
  core.frame_type,
  core.frame_subtype,
  core.source_mac,
  core.transmitter_mac,
  core.receiver_mac,
  core.bssid,
  core.destination_bssid,
  core.bssid_oui,
  core.ssid,
  radio.signal_dbm,
  radio.noise_dbm,
  radio.frequency_mhz,
  radio.channel_flags,
  radio.data_rate_kbps,
  radio.antenna_id,
  radio.tsft,
  radio.fragment_number,
  radio.channel_number,
  security.signal_status,
  security.adjacent_mac_hint,
  qos.qos_tid,
  qos.qos_eosp,
  qos.qos_ack_policy,
  qos.qos_ack_policy_label,
  qos.qos_amsdu,
  network.llc_oui,
  network.ethertype,
  network.ethertype_name,
  network.src_ip,
  network.dst_ip,
  network.ip_ttl,
  network.ip_protocol,
  network.ip_protocol_name,
  network.src_port,
  network.dst_port,
  network.transport_protocol,
  network.transport_length,
  network.transport_checksum,
  network.app_protocol,
  app.ssdp_message_type,
  app.ssdp_st,
  app.ssdp_mx,
  app.ssdp_usn,
  app.dhcp_requested_ip,
  app.dhcp_hostname,
  app.dhcp_vendor_class,
  app.dns_query_name,
  app.mdns_name,
  identity.session_key,
  identity.retransmit_key,
  identity.frame_fingerprint,
  identity.payload_visibility,
  radio.tsft_delta_us,
  radio.wall_clock_delta_ms,
  security.large_frame,
  security.mixed_encryption,
  security.dedupe_or_replay_suspect,
  security.raw_len,
  qos.frame_control_flags,
  qos.more_data,
  qos.retry,
  qos.power_save,
  qos.protected,
  security.security_flags,
  security.risk_score,
  identity.identity_source,
  security.tags,
  identity.wps_device_name,
  identity.wps_manufacturer,
  identity.wps_model_name,
  identity.device_fingerprint,
  identity.handshake_captured,
  identity.search_tsv,
  core.created_at,
  core.updated_at
from wireless_frames core
left join wireless_frame_radio radio using (dedupe_key)
left join wireless_frame_qos qos using (dedupe_key)
left join wireless_frame_network network using (dedupe_key)
left join wireless_frame_app_signals app using (dedupe_key)
left join wireless_frame_identity identity using (dedupe_key)
left join wireless_frame_security security using (dedupe_key);

-- object: vec_embeddings_expanded
-- folder: views
-- depends_on: vec_embeddings, vec_embedding_sources
create or replace view vec_embeddings_expanded as
select
  embedding.embedding_id,
  source.source_table,
  source.source_key,
  source.source_observed_at,
  source.source_stream_name,
  source.source_sensor_id,
  source.source_location_id,
  source.source_mac,
  embedding.embedding_model,
  embedding.embedding_kind,
  embedding.embedding_dimensions,
  embedding.content_sha256,
  embedding.content_text,
  embedding.embedding,
  embedding.metadata,
  embedding.embedded_at,
  embedding.created_at,
  embedding.updated_at
from vec_embeddings embedding
join vec_embedding_sources source using (embedding_id);

-- object: vec_behaviour_snapshots_expanded
-- folder: views
-- depends_on: vec_behaviour_snapshots, vec_behaviour_snapshot_stats
create or replace view vec_behaviour_snapshots_expanded as
select
  snapshot.snapshot_id,
  snapshot.snapshot_key,
  snapshot.source_mac,
  snapshot.location_id,
  snapshot.sensor_id,
  snapshot.window_start,
  snapshot.window_end,
  snapshot.event_count,
  stats.protocol_mix,
  stats.frame_type_distribution,
  stats.signal_min_dbm,
  stats.signal_max_dbm,
  stats.signal_avg_dbm,
  stats.retry_count,
  stats.protected_count,
  stats.unprotected_count,
  stats.unique_bssid_count,
  stats.mac_rotation_indicators,
  snapshot.text_summary,
  snapshot.embedding_text,
  snapshot.created_at,
  snapshot.updated_at
from vec_behaviour_snapshots snapshot
join vec_behaviour_snapshot_stats stats using (snapshot_id);

-- object: vec_embedding_jobs_expanded
-- folder: views
-- depends_on: vec_embedding_jobs, vec_embedding_job_leases
create or replace view vec_embedding_jobs_expanded as
select
  job.job_id,
  job.source_table,
  job.source_key,
  job.embedding_model,
  job.embedding_kind,
  job.status,
  job.priority,
  lease.attempts,
  lease.max_attempts,
  lease.lease_token,
  lease.leased_at,
  lease.locked_by,
  lease.due_at,
  job.content_sha256,
  lease.last_error,
  lease.completed_at,
  job.created_at,
  job.updated_at
from vec_embedding_jobs job
join vec_embedding_job_leases lease using (job_id);

-- object: vec_similarity_pairs_expanded
-- folder: views
-- depends_on: vec_similarity_pairs, vec_similarity_pair_meta, vec_embedding_sources
create or replace view vec_similarity_pairs_expanded as
select
  pair.pair_id,
  meta.pair_kind,
  meta.embedding_model,
  meta.embedding_kind,
  pair.left_embedding_id,
  pair.right_embedding_id,
  meta.left_source_table,
  meta.left_source_key,
  left_source.source_mac as left_source_mac,
  left_source.source_sensor_id as left_sensor_id,
  left_source.source_location_id as left_location_id,
  left_source.source_observed_at as left_observed_at,
  meta.right_source_table,
  meta.right_source_key,
  right_source.source_mac as right_source_mac,
  right_source.source_sensor_id as right_sensor_id,
  right_source.source_location_id as right_location_id,
  right_source.source_observed_at as right_observed_at,
  pair.cosine_distance,
  pair.cosine_similarity,
  pair.rank,
  meta.evidence,
  pair.computed_at,
  pair.created_at,
  pair.updated_at
from vec_similarity_pairs pair
join vec_similarity_pair_meta meta using (pair_id)
join vec_embedding_sources left_source on left_source.embedding_id = pair.left_embedding_id
join vec_embedding_sources right_source on right_source.embedding_id = pair.right_embedding_id;

-- object: vec_timing_profiles_expanded
-- folder: views
-- depends_on: vec_timing_profiles, vec_timing_profile_stats
create or replace view vec_timing_profiles_expanded as
select
  profile.profile_id,
  profile.profile_key,
  profile.source_mac,
  profile.sensor_id,
  profile.location_id,
  profile.window_start,
  profile.window_end,
  stats.tsft_p50_us,
  stats.tsft_p95_us,
  stats.tsft_jitter,
  stats.wall_p50_ms,
  stats.wall_jitter_ms,
  stats.beacon_interval_median_ms,
  stats.beacon_jitter_ms,
  profile.embedding_text,
  profile.created_at,
  profile.updated_at
from vec_timing_profiles profile
join vec_timing_profile_stats stats using (profile_id);

-- object: sync_events_expanded
-- folder: views
-- depends_on: sync_events, wireless_frames, sync_event_payload_archives
-- CREATE OR REPLACE cannot insert columns mid-list; dependents are recreated below.
drop view if exists sync_events_expanded cascade;

create view sync_events_expanded as
select
  e.dedupe_key,
  e.stream_name,
  e.observed_at,
  e.payload_ref,
  e.payload,
  e.payload_sha256,
  archive.archive_uri as payload_archive_uri,
  archive.payload_bytes as archived_payload_bytes,
  archive.archived_at as payload_archived_at,
  (archive.dedupe_key is not null and e.payload is null) as payload_archived,
  e.status,
  e.attempt_count,
  e.last_error,
  e.producer,
  e.event_kind,
  f.sensor_id,
  f.location_id,
  f.username,
  f.event_type,
  f.schema_version,
  f.frame_type,
  f.frame_subtype,
  f.source_mac,
  f.transmitter_mac,
  f.receiver_mac,
  f.bssid,
  f.destination_bssid,
  f.ssid,
  f.signal_dbm,
  f.noise_dbm,
  f.frequency_mhz,
  f.channel_flags,
  f.data_rate_kbps,
  f.antenna_id,
  f.tsft,
  f.fragment_number,
  f.channel_number,
  f.signal_status,
  f.adjacent_mac_hint,
  f.qos_tid,
  f.qos_eosp,
  f.qos_ack_policy,
  f.qos_ack_policy_label,
  f.qos_amsdu,
  f.llc_oui,
  f.ethertype,
  f.ethertype_name,
  f.src_ip,
  f.dst_ip,
  f.ip_ttl,
  f.ip_protocol,
  f.ip_protocol_name,
  f.src_port,
  f.dst_port,
  f.transport_protocol,
  f.transport_length,
  f.transport_checksum,
  f.app_protocol,
  f.ssdp_message_type,
  f.ssdp_st,
  f.ssdp_mx,
  f.ssdp_usn,
  f.dhcp_requested_ip,
  f.dhcp_hostname,
  f.dhcp_vendor_class,
  f.dns_query_name,
  f.mdns_name,
  f.session_key,
  f.retransmit_key,
  f.frame_fingerprint,
  f.payload_visibility,
  f.tsft_delta_us,
  f.wall_clock_delta_ms,
  f.large_frame,
  f.mixed_encryption,
  f.dedupe_or_replay_suspect,
  f.raw_len,
  f.frame_control_flags,
  f.more_data,
  f.retry,
  f.power_save,
  f.protected,
  f.security_flags,
  f.risk_score,
  f.identity_source,
  f.tags,
  f.wps_device_name,
  f.wps_manufacturer,
  f.wps_model_name,
  f.device_fingerprint,
  f.handshake_captured,
  f.search_tsv as wireless_search_tsv,
  e.created_at,
  greatest(e.updated_at, coalesce(f.updated_at, e.updated_at)) as updated_at
from sync_events e
left join wireless_frames_expanded f on f.dedupe_key = e.dedupe_key
left join sync_event_payload_archives archive on archive.dedupe_key = e.dedupe_key;

-- object: v_wireless_audit_with_devices
-- folder: views
-- depends_on: sync_events_expanded, devices
drop view if exists v_wireless_audit_with_devices;

create view v_wireless_audit_with_devices as
select
  ssi.dedupe_key,
  ssi.observed_at,
  ssi.stream_name,
  ssi.status,
  ssi.producer,
  ssi.event_kind,
  ssi.event_type,
  ssi.payload_archived,
  ssi.payload_archive_uri,
  ssi.archived_payload_bytes,
  ssi.payload_archived_at,
  coalesce(ssi.schema_version, nullif(ssi.payload->>'schema_version', '')::integer, 1) as schema_version,
  coalesce(ssi.frame_type, ssi.payload->>'frame_type') as frame_type,
  coalesce(ssi.source_mac, ssi.payload->>'source_mac') as source_mac,
  coalesce(ssi.transmitter_mac, ssi.payload->>'transmitter_mac') as transmitter_mac,
  coalesce(ssi.receiver_mac, ssi.payload->>'receiver_mac') as receiver_mac,
  coalesce(ssi.bssid, ssi.payload->>'bssid') as bssid,
  coalesce(ssi.destination_bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') as destination_bssid,
  coalesce(ssi.ssid, ssi.payload->>'ssid') as ssid,
  coalesce(ssi.frame_subtype, ssi.payload->>'frame_subtype') as frame_subtype,
  coalesce(ssi.signal_dbm::text, ssi.payload->>'signal_dbm') as signal_dbm,
  coalesce(ssi.noise_dbm::text, ssi.payload->>'noise_dbm') as noise_dbm,
  coalesce(ssi.frequency_mhz::text, ssi.payload->>'frequency_mhz') as frequency_mhz,
  coalesce(ssi.channel_number::text, ssi.payload->>'channel_number') as channel_number,
  coalesce(ssi.channel_flags::text, ssi.payload->>'channel_flags') as channel_flags,
  coalesce(ssi.signal_status, ssi.payload->>'signal_status') as signal_status,
  coalesce(ssi.qos_tid::text, ssi.payload->>'qos_tid') as qos_tid,
  coalesce(ssi.ethertype::text, ssi.payload->>'ethertype') as ethertype,
  coalesce(ssi.src_ip, ssi.payload->>'src_ip') as src_ip,
  coalesce(ssi.dst_ip, ssi.payload->>'dst_ip') as dst_ip,
  coalesce(ssi.src_port::text, ssi.payload->>'src_port') as src_port,
  coalesce(ssi.dst_port::text, ssi.payload->>'dst_port') as dst_port,
  coalesce(ssi.app_protocol, ssi.payload->>'app_protocol') as app_protocol,
  coalesce(ssi.session_key, ssi.payload->>'session_key') as session_key,
  coalesce(ssi.retransmit_key, ssi.payload->>'retransmit_key') as retransmit_key,
  coalesce(ssi.frame_fingerprint, ssi.payload->>'frame_fingerprint') as frame_fingerprint,
  coalesce(ssi.payload_visibility, ssi.payload->>'payload_visibility') as payload_visibility,
  coalesce(ssi.large_frame::text, ssi.payload->>'large_frame') as large_frame,
  coalesce(ssi.mixed_encryption::text, ssi.payload->>'mixed_encryption') as mixed_encryption,
  coalesce(ssi.dedupe_or_replay_suspect::text, ssi.payload->>'dedupe_or_replay_suspect') as dedupe_or_replay_suspect,
  coalesce(ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') as dhcp_hostname,
  coalesce(ssi.dns_query_name, ssi.payload->>'dns_query_name') as dns_query_name,
  coalesce(ssi.mdns_name, ssi.payload->>'mdns_name') as mdns_name,
  coalesce(ssi.data_rate_kbps::text, ssi.payload->>'data_rate_kbps') as data_rate_kbps,
  coalesce(ssi.antenna_id::text, ssi.payload->>'antenna_id') as antenna_id,
  coalesce(ssi.tsft::text, ssi.payload->>'tsft') as tsft,
  coalesce(ssi.raw_len::text, ssi.payload->>'raw_len') as raw_len,
  coalesce(ssi.frame_control_flags::text, ssi.payload->>'frame_control_flags') as frame_control_flags,
  coalesce(ssi.more_data::text, ssi.payload->>'more_data') as more_data,
  coalesce(ssi.retry::text, ssi.payload->>'retry') as retry,
  coalesce(ssi.power_save::text, ssi.payload->>'power_save') as power_save,
  coalesce(ssi.protected::text, ssi.payload->>'protected') as protected,
  coalesce(ssi.location_id, ssi.payload->>'location_id') as location_id,
  coalesce(ssi.sensor_id, ssi.payload->>'sensor_id') as sensor_id,
  coalesce(ssi.risk_score::text, ssi.payload->>'risk_score') as risk_score,
  coalesce(ssi.identity_source, ssi.payload->>'identity_source') as identity_source,
  coalesce(ssi.username, ssi.payload->>'username') as username,
  case
    when ssi.tags is not null and ssi.tags <> '[]'::jsonb then ssi.tags
    else coordinator.safe_jsonb_array(ssi.payload->'tags')
  end as tags,
  ssi.security_flags,
  ssi.wps_device_name,
  ssi.wps_manufacturer,
  ssi.wps_model_name,
  ssi.device_fingerprint,
  ssi.handshake_captured,
  coalesce(d_src.mac_id, d_bssid.mac_id) as device_id,
  coalesce(d_src.display_name, d_bssid.display_name) as display_name,
  coalesce(d_src.username, d_bssid.username) as registered_username,
  coalesce(d_src.os_hint, d_bssid.os_hint) as os_hint,
  coalesce(d_src.hostname, d_bssid.hostname, ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') as hostname
from sync_events_expanded ssi
left join devices d_src
  on lower(d_src.mac_hint) = lower(coalesce(ssi.source_mac, ssi.payload->>'source_mac'))
left join devices d_bssid
  on lower(d_bssid.mac_hint) = lower(coalesce(ssi.bssid, ssi.payload->>'bssid'))
where ssi.stream_name = 'wireless.audit';

-- object: v_wireless_threats
-- folder: views
-- depends_on: v_wireless_audit_with_devices
drop view if exists v_wireless_threats;

create view v_wireless_threats as
with resolved as (
  select
    observed_at,
    coalesce(ssid, payload->>'ssid') as ssid,
    coalesce(bssid, payload->>'bssid') as bssid,
    coalesce(destination_bssid, payload->>'destination_bssid', payload->>'bssid') as destination_bssid,
    coalesce(source_mac, payload->>'source_mac') as source_mac,
    coalesce(sensor_id, payload->>'sensor_id') as sensor_id,
    coalesce(transmitter_mac, payload->>'transmitter_mac') as transmitter_mac,
    coalesce(receiver_mac, payload->>'receiver_mac') as receiver_mac,
    coalesce(frame_subtype, payload->>'frame_subtype') as frame_subtype,
    coalesce(signal_dbm::text, payload->>'signal_dbm') as signal_dbm,
    coalesce(noise_dbm::text, payload->>'noise_dbm') as noise_dbm,
    coalesce(frequency_mhz::text, payload->>'frequency_mhz') as frequency_mhz,
    coalesce(data_rate_kbps::text, payload->>'data_rate_kbps') as data_rate_kbps,
    coalesce(raw_len::text, payload->>'raw_len') as raw_len,
    coalesce(frame_control_flags::text, payload->>'frame_control_flags') as frame_control_flags,
    coalesce(more_data::text, payload->>'more_data') as more_data,
    coalesce(retry::text, payload->>'retry') as retry,
    coalesce(power_save::text, payload->>'power_save') as power_save,
    coalesce(protected::text, payload->>'protected') as protected,
    coalesce(location_id, payload->>'location_id') as location_id,
    coalesce(risk_score::text, payload->>'risk_score') as risk_score,
    coalesce(identity_source, payload->>'identity_source') as identity_source,
    coalesce(username, payload->>'username') as username,
    case
      when tags is not null and tags <> '[]'::jsonb then tags
      else coordinator.safe_jsonb_array(payload->'tags')
    end as resolved_tags,
    payload_archived,
    payload_archive_uri,
    payload_archived_at,
    security_flags,
    wps_device_name,
    wps_manufacturer,
    wps_model_name,
    device_fingerprint,
    handshake_captured
  from sync_events_expanded
  where stream_name = 'wireless.audit'
)
select
  observed_at,
  ssid,
  bssid,
  destination_bssid,
  source_mac,
  sensor_id,
  transmitter_mac,
  receiver_mac,
  frame_subtype,
  signal_dbm,
  noise_dbm,
  frequency_mhz,
  data_rate_kbps,
  raw_len,
  frame_control_flags,
  more_data,
  retry,
  power_save,
  protected,
  location_id,
  risk_score,
  identity_source,
  username,
  resolved_tags as tags,
  payload_archived,
  payload_archive_uri,
  payload_archived_at,
  security_flags,
  wps_device_name,
  wps_manufacturer,
  wps_model_name,
  device_fingerprint,
  handshake_captured
from resolved
where coordinator.has_threat_tag(resolved_tags)
  or handshake_captured
order by observed_at desc;

-- object: v_wireless_session_timeline
-- folder: views
-- depends_on: sync_events_expanded
create or replace view v_wireless_session_timeline as
with base as (
  select
    ssi.dedupe_key,
    ssi.observed_at,
    coalesce(ssi.session_key, ssi.payload->>'session_key') as session_key,
    coalesce(ssi.retransmit_key, ssi.payload->>'retransmit_key') as retransmit_key,
    coalesce(ssi.frame_fingerprint, ssi.payload->>'frame_fingerprint') as frame_fingerprint,
    coalesce(ssi.source_mac, ssi.payload->>'source_mac') as source_mac,
    coalesce(ssi.destination_bssid, ssi.bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') as destination_bssid,
    coalesce(ssi.ssid, ssi.payload->>'ssid') as ssid,
    coalesce(ssi.protected, false) as protected,
    coalesce(ssi.large_frame, false) as large_frame,
    coalesce(ssi.dedupe_or_replay_suspect, false) as dedupe_or_replay_suspect,
    coalesce(ssi.tsft, coordinator.safe_bigint(ssi.payload->>'tsft')) as tsft
  from sync_events_expanded ssi
  where ssi.stream_name = 'wireless.audit'
)
select
  dedupe_key,
  observed_at,
  session_key,
  retransmit_key,
  frame_fingerprint,
  source_mac,
  destination_bssid,
  ssid,
  protected,
  large_frame,
  dedupe_or_replay_suspect,
  tsft,
  case
    when lag(tsft) over session_window is not null and tsft is not null
      then tsft - lag(tsft) over session_window
  end as tsft_delta_us,
  case
    when lag(observed_at) over session_window is not null
      then round(extract(epoch from (observed_at - lag(observed_at) over session_window)) * 1000)
  end as wall_clock_delta_ms,
  (
    bool_or(protected) over session_partition
    and bool_or(not protected) over session_partition
  ) as mixed_encryption
from base
window
  session_partition as (partition by session_key),
  session_window as (partition by session_key order by observed_at);

-- object: v_wireless_device_inventory
-- folder: views
-- depends_on: sync_events_expanded
create or replace view v_wireless_device_inventory as
with recent_ingest as materialized (
  select *
  from sync_events_expanded
  where stream_name = 'wireless.audit'
    and coalesce(source_mac, payload->>'source_mac') is not null
  order by observed_at desc
  limit 20000
),
base as (
  select
    dedupe_key,
    observed_at,
    lower(coalesce(source_mac, payload->>'source_mac')) as source_mac,
    coalesce(bssid, payload->>'bssid') as bssid,
    coalesce(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid') as destination_bssid,
    coalesce(ssid, payload->>'ssid') as ssid,
    coalesce(signal_dbm, coordinator.safe_int(payload->>'signal_dbm')) as signal_dbm,
    coalesce(location_id, payload->>'location_id') as location_id,
    coalesce(sensor_id, payload->>'sensor_id') as sensor_id,
    coalesce(username, payload->>'username') as username,
    coalesce(src_ip, payload->>'src_ip') as src_ip,
    coalesce(dst_ip, payload->>'dst_ip') as dst_ip,
    coalesce(dhcp_hostname, mdns_name, payload->>'dhcp_hostname', payload->>'mdns_name') as hostname,
    coalesce(app_protocol, payload->>'app_protocol') as app_protocol,
    coalesce(dns_query_name, payload->>'dns_query_name') as dns_query_name,
    coalesce(protected, false) as protected,
    wps_device_name,
    wps_manufacturer,
    wps_model_name,
    device_fingerprint
  from recent_ingest
),
latest as (
  select *
  from (
    select base.*, row_number() over (partition by source_mac order by observed_at desc, dedupe_key desc) as row_number
    from base
  ) ranked
  where row_number = 1
),
rollup as (
  select
    source_mac,
    min(observed_at) as first_occurred_at,
    max(observed_at) as last_occurred_at,
    count(*)::bigint as occurrence_count,
    string_agg(distinct src_ip, ', ') filter (where src_ip is not null) as ip_addresses,
    string_agg(distinct hostname, ', ') filter (where hostname is not null) as hostnames,
    string_agg(distinct app_protocol, ', ') filter (where app_protocol is not null) as services,
    string_agg(distinct dns_query_name, ', ') filter (where dns_query_name is not null) as dns_names,
    sum(case when protected then 1 else 0 end)::bigint as protected_frame_count,
    sum(case when not protected then 1 else 0 end)::bigint as open_frame_count
  from base
  group by source_mac
)
select
  rollup.source_mac as inventory_key,
  rollup.source_mac,
  rollup.first_occurred_at,
  rollup.last_occurred_at,
  rollup.first_occurred_at as first_seen,
  rollup.last_occurred_at as last_seen,
  rollup.last_occurred_at as observed_at,
  rollup.occurrence_count,
  rollup.occurrence_count as frame_count,
  latest.location_id,
  latest.sensor_id,
  latest.bssid,
  latest.destination_bssid,
  latest.ssid,
  latest.signal_dbm::text as signal_dbm,
  latest.username,
  rollup.ip_addresses,
  rollup.hostnames,
  rollup.services,
  rollup.dns_names,
  rollup.protected_frame_count,
  rollup.open_frame_count,
  latest.wps_device_name,
  latest.wps_manufacturer,
  latest.wps_model_name,
  latest.device_fingerprint,
  devices.mac_id as device_id,
  devices.display_name,
  devices.username as registered_username,
  devices.os_hint,
  coalesce(devices.hostname, latest.hostname) as hostname
from rollup
join latest on latest.source_mac = rollup.source_mac
left join devices on devices.mac_id = rollup.source_mac;

-- object: v_wireless_anomalies
-- folder: views
-- depends_on: sync_events_expanded
create or replace view v_wireless_anomalies as
select
  timeline.dedupe_key,
  timeline.observed_at,
  timeline.session_key,
  timeline.source_mac,
  timeline.destination_bssid,
  timeline.ssid,
  timeline.tsft_delta_us,
  timeline.wall_clock_delta_ms,
  timeline.mixed_encryption,
  timeline.large_frame,
  timeline.dedupe_or_replay_suspect,
  array_remove(array[
    case when timeline.large_frame then 'large_frame' end,
    case when timeline.mixed_encryption then 'mixed_encryption' end,
    case when timeline.dedupe_or_replay_suspect then 'dedupe_or_replay_suspect' end
  ], null) as reasons
from v_wireless_session_timeline timeline
where timeline.large_frame
   or timeline.mixed_encryption
   or timeline.dedupe_or_replay_suspect;

-- object: v_sync_plane_health
-- folder: views
-- depends_on: sync_events, sync_jobs, sync_batches
create or replace view v_sync_plane_health as
with ingest_status as (
  select
    status,
    count(*)::bigint as row_count
  from sync_events_expanded
  group by status
),
wireless_ingest_status as (
  select
    status,
    count(*)::bigint as row_count
  from sync_events_expanded
  where stream_name = 'wireless.audit'
  group by status
),
ingest_time as (
  select
    count(*) filter (where stream_name = 'wireless.audit' and observed_at >= now() - interval '24 hours')::bigint as wireless_events_24h_count,
    max(observed_at) filter (where stream_name = 'wireless.audit') as wireless_last_observed_at
  from sync_events_expanded
),
batch_status as (
  select
    status,
    count(*)::bigint as row_count
  from sync_batches
  group by status
),
job_batch_rollup as (
  select
    job.job_id,
    job.status as stored_status,
    job.created_at,
    count(batch.batch_id)::bigint as batch_count,
    count(batch.batch_id) filter (where batch.status in ('pending', 'processing', 'dispatched'))::bigint as open_batch_count,
    count(batch.batch_id) filter (where batch.status = 'failed')::bigint as failed_batch_count,
    count(batch.batch_id) filter (where batch.status = 'completed')::bigint as completed_batch_count
  from sync_jobs job
  left join sync_batches batch on batch.job_id = job.job_id
  group by job.job_id, job.status, job.created_at
),
job_effective_status as (
  select
    case
      when open_batch_count > 0 then stored_status
      when failed_batch_count > 0 then 'failed'
      when completed_batch_count > 0 then 'completed'
      when stored_status in ('pending', 'running') and created_at < now() - interval '5 minutes' then 'orphaned'
      else stored_status
    end as effective_status,
    stored_status,
    count(*)::bigint as row_count
  from job_batch_rollup
  group by
    case
      when open_batch_count > 0 then stored_status
      when failed_batch_count > 0 then 'failed'
      when completed_batch_count > 0 then 'completed'
      when stored_status in ('pending', 'running') and created_at < now() - interval '5 minutes' then 'orphaned'
      else stored_status
    end,
    stored_status
),
backlog_status as (
  select
    status,
    count(*)::bigint as row_count
  from sync_backlog
  group by status
),
shadow_status as (
  select
    count(*) filter (where resolved_at is null)::bigint as open_alert_count,
    max(last_occurred_at) filter (where resolved_at is null) as last_open_alert_at
  from wireless_shadow_alerts
)
select
  now() as measured_at,
  coalesce((select wireless_events_24h_count from ingest_time), 0)::bigint as wireless_events_24h_count,
  (select wireless_last_observed_at from ingest_time) as wireless_last_observed_at,
  coalesce((select row_count from wireless_ingest_status where status = 'pending'), 0)::bigint as wireless_ingest_pending_count,
  coalesce((select row_count from wireless_ingest_status where status = 'processing'), 0)::bigint as wireless_ingest_processing_count,
  coalesce((select row_count from wireless_ingest_status where status = 'batched'), 0)::bigint as wireless_ingest_batched_count,
  coalesce((select row_count from wireless_ingest_status where status = 'failed'), 0)::bigint as wireless_ingest_failed_count,
  coalesce((select sum(row_count) from wireless_ingest_status), 0)::bigint as wireless_ingest_total_count,
  coalesce((select row_count from ingest_status where status = 'pending'), 0)::bigint as ingest_pending_count,
  coalesce((select row_count from ingest_status where status = 'processing'), 0)::bigint as ingest_processing_count,
  coalesce((select row_count from ingest_status where status = 'batched'), 0)::bigint as ingest_batched_count,
  coalesce((select row_count from ingest_status where status = 'failed'), 0)::bigint as ingest_failed_count,
  coalesce((select sum(row_count) from ingest_status), 0)::bigint as ingest_total_count,
  coalesce((select row_count from batch_status where status = 'pending'), 0)::bigint as batch_pending_count,
  coalesce((select row_count from batch_status where status = 'processing'), 0)::bigint as batch_processing_count,
  coalesce((select row_count from batch_status where status = 'dispatched'), 0)::bigint as batch_dispatched_count,
  coalesce((select row_count from batch_status where status = 'completed'), 0)::bigint as batch_completed_count,
  coalesce((select row_count from batch_status where status = 'failed'), 0)::bigint as batch_failed_count,
  coalesce((select sum(row_count) from batch_status), 0)::bigint as batch_total_count,
  coalesce((select sum(row_count) from job_effective_status where stored_status = 'pending'), 0)::bigint as job_stored_pending_count,
  coalesce((select sum(row_count) from job_effective_status where stored_status = 'running'), 0)::bigint as job_stored_running_count,
  coalesce((select sum(row_count) from job_effective_status where stored_status = 'completed'), 0)::bigint as job_stored_completed_count,
  coalesce((select sum(row_count) from job_effective_status where stored_status = 'failed'), 0)::bigint as job_stored_failed_count,
  coalesce((select sum(row_count) from job_effective_status), 0)::bigint as job_total_count,
  coalesce((select sum(row_count) from job_effective_status where effective_status = 'pending'), 0)::bigint as job_effective_pending_count,
  coalesce((select sum(row_count) from job_effective_status where effective_status = 'running'), 0)::bigint as job_effective_running_count,
  coalesce((select sum(row_count) from job_effective_status where effective_status = 'completed'), 0)::bigint as job_effective_completed_count,
  coalesce((select sum(row_count) from job_effective_status where effective_status = 'failed'), 0)::bigint as job_effective_failed_count,
  coalesce((select sum(row_count) from job_effective_status where effective_status = 'orphaned'), 0)::bigint as job_orphaned_count,
  coalesce((select row_count from backlog_status where status = 'pending'), 0)::bigint as backlog_pending_count,
  coalesce((select sum(row_count) from backlog_status where status in ('sync_failed', 'failed')), 0)::bigint as backlog_failed_count,
  coalesce((select open_alert_count from shadow_status), 0)::bigint as open_shadow_it_alert_count,
  (select last_open_alert_at from shadow_status) as last_shadow_it_alert_at,
  (select cursor_value from sync_cursors where stream_name = 'wireless.audit') as wireless_cursor_value,
  (select updated_at from sync_cursors where stream_name = 'wireless.audit') as wireless_cursor_updated_at;

-- object: v_wireless_shadow_alerts
-- folder: views
-- depends_on: wireless_shadow_alerts
create or replace view v_wireless_shadow_alerts as
select
  source_mac as alert_id,
  source_mac as dedupe_key,
  source_mac,
  first_occurred_at,
  last_occurred_at,
  last_occurred_at as observed_at,
  occurrence_count,
  destination_bssid,
  ssid,
  sensor_id,
  location_id,
  signal_dbm,
  reason,
  evidence,
  resolved_at,
  created_at,
  updated_at
from wireless_shadow_alerts
order by last_occurred_at desc;

-- object: v_bssid_anomaly_score
-- folder: views
-- depends_on: vec_behaviour_snapshots, vec_baseline_profiles
create or replace view v_bssid_anomaly_score as
with current_base as (
  select
    lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
    coalesce(signal_dbm,
      case when payload->>'signal_dbm' ~ '^-?[0-9]+$' then (payload->>'signal_dbm')::integer end
    ) as signal_dbm,
    coalesce(retry, false) as retry,
    coalesce(channel_number::text, payload->>'channel_number', payload->>'channel') as channel_number,
    coalesce(frame_subtype, payload->>'frame_subtype') as frame_subtype,
    lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
    observed_at,
    date_bin(interval '15 minutes', observed_at, timestamptz '2000-01-01 00:00:00+00') as window_start
  from sync_events_expanded
  where stream_name = 'wireless.audit'
    and observed_at >= now() - interval '1 hour'
    and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
),
current_metrics as (
  select bssid, 'beacon_interval_ms' as metric, percentile_cont(0.5) within group (order by interval_ms) as observed_metric
  from (
    select
      bssid,
      extract(epoch from observed_at - lag(observed_at) over (partition by bssid order by observed_at)) * 1000.0 as interval_ms
    from current_base
    where frame_subtype = 'beacon'
  ) beacon_intervals
  where interval_ms is not null and interval_ms > 0
  group by bssid
  union all
  select bssid, 'retry_rate' as metric, percentile_cont(0.5) within group (order by retry_rate) as observed_metric
  from (
    select bssid, window_start, avg((retry::int)::numeric) as retry_rate
    from current_base
    group by bssid, window_start
  ) retry_window
  group by bssid
  union all
  select bssid, 'signal_iqr_dbm' as metric, percentile_cont(0.5) within group (order by q75 - q25) as observed_metric
  from (
    select bssid, window_start,
      percentile_cont(0.25) within group (order by signal_dbm) as q25,
      percentile_cont(0.75) within group (order by signal_dbm) as q75
    from current_base
    where signal_dbm is not null
    group by bssid, window_start
  ) signal_window
  where q25 is not null and q75 is not null
  group by bssid
  union all
  select bssid, 'channel_dwell_ratio' as metric, percentile_cont(0.5) within group (order by top_channel_share) as observed_metric
  from (
    select
      bssid,
      window_start,
      max(channel_share) as top_channel_share
    from (
      select
        bssid,
        window_start,
        channel_count::numeric / sum(channel_count) over (partition by bssid, window_start) as channel_share
      from (
        select bssid, window_start, channel_number, count(*)::bigint as channel_count
        from current_base
        where channel_number is not null
        group by bssid, window_start, channel_number
      ) channel_window
    ) sub
    group by bssid, window_start
  ) channel_dwell
  group by bssid
  union all
  select bssid, 'association_timing_secs' as metric, percentile_cont(0.5) within group (order by delta_secs) as observed_metric
  from (
    select
      bssid,
      extract(epoch from observed_at - lag(observed_at) over (partition by bssid, source_mac order by observed_at)) as delta_secs
    from current_base
    where frame_subtype in ('association_request', 'reassociation_request')
      and source_mac is not null
  ) assoc_deltas
  where delta_secs is not null and delta_secs >= 0
  group by bssid
)
select
  cm.bssid,
  cm.metric,
  cm.observed_metric,
  bp.p5,
  bp.p50,
  bp.p95,
  case when bp.p95 > bp.p5 then (cm.observed_metric - bp.p50) / nullif(bp.p95 - bp.p5, 0) else null end as anomaly_score
from current_metrics cm
join vec_baseline_profiles bp
  on bp.bssid = cm.bssid
  and bp.metric = cm.metric;

-- object: v_wireless_session_timeline override
-- folder: views
-- depends_on: v_wireless_session_timeline
create or replace view v_wireless_session_timeline as
with base as (
  select
    ssi.dedupe_key,
    ssi.observed_at,
    coalesce(ssi.session_key, ssi.payload->>'session_key') as session_key,
    coalesce(ssi.retransmit_key, ssi.payload->>'retransmit_key') as retransmit_key,
    coalesce(ssi.frame_fingerprint, ssi.payload->>'frame_fingerprint') as frame_fingerprint,
    coalesce(ssi.source_mac, ssi.payload->>'source_mac') as source_mac,
    coalesce(ssi.destination_bssid, ssi.bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') as destination_bssid,
    coalesce(ssi.ssid, ssi.payload->>'ssid') as ssid,
    coalesce(ssi.protected, false) as protected,
    coalesce(ssi.large_frame, false) as large_frame,
    coalesce(ssi.dedupe_or_replay_suspect, false) as dedupe_or_replay_suspect,
    coalesce(ssi.tsft, coordinator.safe_bigint(ssi.payload->>'tsft')) as tsft
  from sync_events_expanded ssi
  where ssi.stream_name = 'wireless.audit'
)
select
  dedupe_key,
  observed_at,
  session_key,
  retransmit_key,
  frame_fingerprint,
  source_mac,
  destination_bssid,
  ssid,
  protected,
  large_frame,
  dedupe_or_replay_suspect,
  tsft,
  case
    when lag(tsft) over session_window is not null and tsft is not null
      then tsft - lag(tsft) over session_window
  end as tsft_delta_us,
  case
    when lag(observed_at) over session_window is not null
      then round(extract(epoch from (observed_at - lag(observed_at) over session_window)) * 1000)
  end as wall_clock_delta_ms,
  (
    bool_or(protected) over session_partition
    and bool_or(not protected) over session_partition
  ) as mixed_encryption
from base
window
  session_partition as (partition by session_key),
  session_window as (partition by session_key order by observed_at);

-- object: v_ap_risk_score
-- folder: views
-- depends_on: vec_alerts, vec_similarity_pairs
-- Track 6.1: Composite AP risk score combining deauth, signal, typosquat,
-- vendor mismatch, and embedding outlier signals into a single score.
create or replace view v_ap_risk_score as
with alert_bssid_scores as (
  select
    alert_bssid.bssid,
    alert.alert_type,
    alert.metadata,
    alert.score
  from vec_alerts alert
  cross join lateral (
    select lower(nullif(trim(alert.metadata->>'bssid'), '')) as bssid
    union
    select lower(nullif(trim(alert.metadata->>'destination_bssid'), '')) as bssid
    union
    select lower(nullif(trim(value), '')) as bssid
    from jsonb_array_elements_text(
      case
        when jsonb_typeof(alert.metadata->'bssids') = 'array' then alert.metadata->'bssids'
        else '[]'::jsonb
      end
    ) as bssid_values(value)
  ) alert_bssid
  where alert_bssid.bssid is not null
    and alert.created_at >= now() - interval '1 hour'
),
deauth_scores as (
  select
    bssid,
    max(score) as deauth_score
  from alert_bssid_scores
  where alert_type in ('rogue_cluster', 'deauth_flood')
  group by bssid
),
signal_anomaly_scores as (
  select
    bssid,
    max(score) as signal_anomaly_score
  from alert_bssid_scores
  where alert_type in ('signal_anomaly', 'rogue_cluster')
    and metadata->>'reason' in ('signal_jump', 'channel_band_conflict')
  group by bssid
),
typosquat_scores as (
  select
    bssid,
    max(score) as typosquat_score
  from alert_bssid_scores
  where alert_type = 'rogue_cluster'
    and metadata->>'reason' in ('ssid_typosquat', 'vendor_conflict', 'bssid_spoofing')
  group by bssid
),
vendor_mismatch_scores as (
  select
    lower(substr(regexp_replace(coalesce(nullif(bssid, ''), nullif(payload->>'bssid', ''), nullif(destination_bssid, ''), nullif(payload->>'destination_bssid', '')), '[:\-]', '', 'g'), 1, 6)) as bssid_oui,
    count(distinct lower(substr(regexp_replace(bssid, '[:\-]', '', 'g'), 1, 6)))::double precision as vendor_mismatch_score
  from sync_events_expanded
  where stream_name = 'wireless.audit'
    and observed_at >= now() - interval '1 hour'
    and nullif(coalesce(ssid, payload->>'ssid'), '') is not null
    and coalesce(nullif(bssid, ''), nullif(payload->>'bssid', ''), nullif(destination_bssid, ''), nullif(payload->>'destination_bssid', '')) is not null
    and lower(substr(regexp_replace(coalesce(nullif(bssid, ''), nullif(payload->>'bssid', ''), nullif(destination_bssid, ''), nullif(payload->>'destination_bssid', '')), '[:\-]', '', 'g'), 1, 6)) is not null
  group by bssid_oui
),
similarity_bssid_rows as (
  select
    lower(nullif(trim(coalesce(nullif(left_event.bssid, ''), nullif(left_event.payload->>'bssid', ''), nullif(left_event.destination_bssid, ''), nullif(left_event.payload->>'destination_bssid', ''))), '')) as bssid,
    p.cosine_distance
  from vec_similarity_pairs_expanded p
  join sync_events_expanded left_event
    on p.left_source_table = 'sync_events'
   and left_event.dedupe_key = p.left_source_key
  where p.computed_at >= now() - interval '1 hour'
    and p.cosine_distance > 0.15
  union all
  select
    lower(nullif(trim(coalesce(nullif(right_event.bssid, ''), nullif(right_event.payload->>'bssid', ''), nullif(right_event.destination_bssid, ''), nullif(right_event.payload->>'destination_bssid', ''))), '')) as bssid,
    p.cosine_distance
  from vec_similarity_pairs_expanded p
  join sync_events_expanded right_event
    on p.right_source_table = 'sync_events'
   and right_event.dedupe_key = p.right_source_key
  where p.computed_at >= now() - interval '1 hour'
    and p.cosine_distance > 0.15
),
embedding_outlier_scores as (
  select
    bssid,
    max(cosine_distance) as embedding_outlier_score
  from similarity_bssid_rows
  where bssid is not null
  group by bssid
),
baseline_deviation_scores as (
  select
    bssid,
    max(abs(anomaly_score)) as baseline_deviation_score
  from v_bssid_anomaly_score
  where anomaly_score is not null
    and abs(anomaly_score) > 2.0
  group by bssid
),
all_bssids as (
  select distinct bssid
  from alert_bssid_scores
  union
  select distinct bssid
  from similarity_bssid_rows
  where bssid is not null
  union
  select distinct bssid
  from baseline_deviation_scores
)
select
  a.bssid,
  coalesce(d.deauth_score, 0::double precision) as deauth_score,
  coalesce(s.signal_anomaly_score, 0::double precision) as signal_anomaly_score,
  coalesce(t.typosquat_score, 0::double precision) as typosquat_score,
  coalesce(v.vendor_mismatch_score, 0::double precision) as vendor_mismatch_score,
  coalesce(e.embedding_outlier_score, 0::double precision) as embedding_outlier_score,
  coalesce(b.baseline_deviation_score, 0::double precision) as baseline_deviation_score,
  (coalesce(d.deauth_score, 0::double precision) * 0.20
   + coalesce(s.signal_anomaly_score, 0::double precision) * 0.15
   + coalesce(t.typosquat_score, 0::double precision) * 0.15
   + coalesce(v.vendor_mismatch_score, 0::double precision) * 0.15
   + coalesce(e.embedding_outlier_score, 0::double precision) * 0.15
   + coalesce(b.baseline_deviation_score, 0::double precision) * 0.20) as composite_risk
from all_bssids a
left join deauth_scores d on d.bssid = a.bssid
left join signal_anomaly_scores s on s.bssid = a.bssid
left join typosquat_scores t on t.bssid = a.bssid
left join vendor_mismatch_scores v on v.bssid_oui = lower(substr(regexp_replace(a.bssid, '[:\-]', '', 'g'), 1, 6))
left join embedding_outlier_scores e on e.bssid = a.bssid
left join baseline_deviation_scores b on b.bssid = a.bssid;

-- object: v_vec_similarity_audit
-- folder: views
-- depends_on: vec_similarity_pairs, vec_embeddings
create or replace view v_vec_similarity_audit as
select
  pair.pair_id,
  pair.pair_kind,
  pair.embedding_model,
  pair.embedding_kind,
  pair.cosine_distance,
  pair.cosine_similarity,
  pair.rank,
  pair.evidence,
  pair.computed_at,
  pair.left_source_table,
  pair.left_source_key,
  pair.left_source_mac,
  pair.left_sensor_id,
  pair.left_location_id,
  pair.left_observed_at,
  left_event.stream_name as left_stream_name,
  left_event.ssid as left_ssid,
  left_event.bssid as left_bssid,
  left_event.destination_bssid as left_destination_bssid,
  left_device.display_name as left_device_display_name,
  left_snapshot.snapshot_id as left_snapshot_id,
  left_snapshot.window_start as left_window_start,
  left_snapshot.window_end as left_window_end,
  pair.right_source_table,
  pair.right_source_key,
  pair.right_source_mac,
  pair.right_sensor_id,
  pair.right_location_id,
  pair.right_observed_at,
  right_event.stream_name as right_stream_name,
  right_event.ssid as right_ssid,
  right_event.bssid as right_bssid,
  right_event.destination_bssid as right_destination_bssid,
  right_device.display_name as right_device_display_name,
  right_snapshot.snapshot_id as right_snapshot_id,
  right_snapshot.window_start as right_window_start,
  right_snapshot.window_end as right_window_end
from vec_similarity_pairs_expanded pair
left join sync_events_expanded left_event
  on pair.left_source_table = 'sync_events'
 and left_event.dedupe_key = pair.left_source_key
left join sync_events_expanded right_event
  on pair.right_source_table = 'sync_events'
 and right_event.dedupe_key = pair.right_source_key
left join devices left_device
  on left_device.mac_id = pair.left_source_key
  or left_device.mac_id = lower(pair.left_source_mac)
left join devices right_device
  on right_device.mac_id = pair.right_source_key
  or right_device.mac_id = lower(pair.right_source_mac)
left join vec_behaviour_snapshots_expanded left_snapshot
  on pair.left_source_table = 'vec_behaviour_snapshots'
 and left_snapshot.snapshot_id::text = pair.left_source_key
left join vec_behaviour_snapshots_expanded right_snapshot
  on pair.right_source_table = 'vec_behaviour_snapshots'
 and right_snapshot.snapshot_id::text = pair.right_source_key;

-- object: v_wireless_device_inventory override
-- folder: views
-- depends_on: v_wireless_device_inventory
create or replace view v_wireless_device_inventory as
with recent_ingest as materialized (
  select *
  from sync_events_expanded
  where stream_name = 'wireless.audit'
    and coalesce(source_mac, payload->>'source_mac') is not null
  order by observed_at desc
  limit 20000
),
base as (
  select
    dedupe_key,
    observed_at,
    lower(coalesce(source_mac, payload->>'source_mac')) as source_mac,
    coalesce(bssid, payload->>'bssid') as bssid,
    coalesce(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid') as destination_bssid,
    coalesce(ssid, payload->>'ssid') as ssid,
    coalesce(signal_dbm, coordinator.safe_int(payload->>'signal_dbm')) as signal_dbm,
    coalesce(location_id, payload->>'location_id') as location_id,
    coalesce(sensor_id, payload->>'sensor_id') as sensor_id,
    coalesce(username, payload->>'username') as username,
    coalesce(src_ip, payload->>'src_ip') as src_ip,
    coalesce(dst_ip, payload->>'dst_ip') as dst_ip,
    coalesce(dhcp_hostname, mdns_name, payload->>'dhcp_hostname', payload->>'mdns_name') as hostname,
    coalesce(app_protocol, payload->>'app_protocol') as app_protocol,
    coalesce(dns_query_name, payload->>'dns_query_name') as dns_query_name,
    coalesce(protected, false) as protected,
    wps_device_name,
    wps_manufacturer,
    wps_model_name,
    device_fingerprint
  from recent_ingest
),
latest as (
  select *
  from (
    select base.*, row_number() over (partition by source_mac order by observed_at desc, dedupe_key desc) as row_number
    from base
  ) ranked
  where row_number = 1
),
rollup as (
  select
    source_mac,
    min(observed_at) as first_occurred_at,
    max(observed_at) as last_occurred_at,
    count(*)::bigint as occurrence_count,
    string_agg(distinct src_ip, ', ') filter (where src_ip is not null) as ip_addresses,
    string_agg(distinct hostname, ', ') filter (where hostname is not null) as hostnames,
    string_agg(distinct app_protocol, ', ') filter (where app_protocol is not null) as services,
    string_agg(distinct dns_query_name, ', ') filter (where dns_query_name is not null) as dns_names,
    sum(case when protected then 1 else 0 end)::bigint as protected_frame_count,
    sum(case when not protected then 1 else 0 end)::bigint as open_frame_count
  from base
  group by source_mac
)
select
  rollup.source_mac as inventory_key,
  rollup.source_mac,
  rollup.first_occurred_at,
  rollup.last_occurred_at,
  rollup.first_occurred_at as first_seen,
  rollup.last_occurred_at as last_seen,
  rollup.last_occurred_at as observed_at,
  rollup.occurrence_count,
  rollup.occurrence_count as frame_count,
  latest.location_id,
  latest.sensor_id,
  latest.bssid,
  latest.destination_bssid,
  latest.ssid,
  latest.signal_dbm::text as signal_dbm,
  latest.username,
  rollup.ip_addresses,
  rollup.hostnames,
  rollup.services,
  rollup.dns_names,
  rollup.protected_frame_count,
  rollup.open_frame_count,
  latest.wps_device_name,
  latest.wps_manufacturer,
  latest.wps_model_name,
  latest.device_fingerprint,
  devices.mac_id as device_id,
  devices.display_name,
  devices.username as registered_username,
  devices.os_hint,
  coalesce(devices.hostname, latest.hostname) as hostname
from rollup
join latest on latest.source_mac = rollup.source_mac
left join devices on devices.mac_id = rollup.source_mac;

-- object: v_postgres_storage_health
-- folder: views
-- depends_on: sync_events, sync_event_payload_archives, sync_event_tombstones, vec_embeddings
create or replace view v_postgres_storage_health as
with relation_stats as (
  select
    relid,
    relname,
    pg_total_relation_size(relid)::bigint as total_bytes,
    pg_relation_size(relid)::bigint as table_bytes,
    (pg_total_relation_size(relid) - pg_relation_size(relid))::bigint as index_bytes,
    n_live_tup::bigint as live_tuples,
    n_dead_tup::bigint as dead_tuples,
    case
      when n_live_tup + n_dead_tup > 0
        then n_dead_tup::double precision / nullif(n_live_tup + n_dead_tup, 0)
      else 0::double precision
    end as dead_tuple_ratio,
    last_autovacuum,
    case
      when last_autovacuum is not null then extract(epoch from now() - last_autovacuum)::bigint
    end as autovacuum_age_seconds
  from pg_stat_user_tables
  where relname in (
    'sync_events',
    'wireless_frames',
    'wireless_frame_radio',
    'wireless_frame_qos',
    'wireless_frame_network',
    'wireless_frame_app_signals',
    'wireless_frame_identity',
    'wireless_frame_security',
    'sync_event_payload_archives',
    'sync_event_tombstones',
    'vec_embeddings',
    'vec_embedding_sources',
    'vec_embedding_jobs',
    'vec_embedding_job_leases',
    'vec_similarity_pairs',
    'vec_similarity_pair_meta',
    'vec_behaviour_snapshots',
    'vec_behaviour_snapshot_stats',
    'vec_frame_sequences',
    'vec_timing_profiles',
    'vec_timing_profile_stats'
  )
),
wireless_payloads as (
  select
    count(*) filter (where payload is not null)::bigint as hot_payload_count,
    coalesce(sum(pg_column_size(payload)) filter (where payload is not null), 0)::bigint as hot_payload_bytes,
    count(*) filter (
      where payload is not null
        and observed_at < now() - interval '7 days'
        and not exists (
          select 1
          from sync_event_payload_archives archive
          where archive.dedupe_key = sync_events.dedupe_key
        )
    )::bigint as unarchived_payload_count,
    min(observed_at) filter (
      where payload is not null
        and observed_at < now() - interval '7 days'
        and not exists (
          select 1
          from sync_event_payload_archives archive
          where archive.dedupe_key = sync_events.dedupe_key
        )
    ) as oldest_unarchived_payload_at
  from sync_events
  where stream_name = 'wireless.audit'
),
archive_stats as (
  select
    count(*)::bigint as archived_payload_count,
    coalesce(sum(payload_bytes), 0)::bigint as archived_payload_bytes,
    max(archived_at) as last_archived_at
  from sync_event_payload_archives
),
tombstone_stats as (
  select
    count(*)::bigint as tombstone_count,
    count(*) filter (where expires_at <= now())::bigint as expired_tombstone_count,
    min(expires_at) as next_tombstone_expiry_at
  from sync_event_tombstones
),
vector_stats as (
  select
    coalesce(jsonb_object_agg(embedding_kind, row_count order by embedding_kind), '{}'::jsonb) as vector_rows_by_kind
  from (
    select embedding_kind, count(*)::bigint as row_count
    from vec_embeddings
    group by embedding_kind
  ) grouped
)
select
  now() as measured_at,
  coalesce(
    (
      select jsonb_agg(
        jsonb_build_object(
          'relation', relname,
          'total_bytes', total_bytes,
          'table_bytes', table_bytes,
          'index_bytes', index_bytes,
          'live_tuples', live_tuples,
          'dead_tuples', dead_tuples,
          'dead_tuple_ratio', dead_tuple_ratio,
          'last_autovacuum', last_autovacuum,
          'autovacuum_age_seconds', autovacuum_age_seconds
        )
        order by total_bytes desc
      )
      from relation_stats
    ),
    '[]'::jsonb
  ) as relation_storage,
  wireless_payloads.hot_payload_count,
  wireless_payloads.hot_payload_bytes,
  wireless_payloads.unarchived_payload_count,
  wireless_payloads.oldest_unarchived_payload_at,
  case
    when wireless_payloads.oldest_unarchived_payload_at is not null
      then extract(epoch from now() - wireless_payloads.oldest_unarchived_payload_at)::bigint
    else 0::bigint
  end as archive_lag_seconds,
  archive_stats.archived_payload_count,
  archive_stats.archived_payload_bytes,
  archive_stats.last_archived_at,
  tombstone_stats.tombstone_count,
  tombstone_stats.expired_tombstone_count,
  tombstone_stats.next_tombstone_expiry_at,
  vector_stats.vector_rows_by_kind
from wireless_payloads
cross join archive_stats
cross join tombstone_stats
cross join vector_stats;

-- object: unschedule_cron_jobs
-- folder: cron
-- depends_on: pg_cron
-- Unschedules this app's pg_cron jobs left from a previous coordinator lifecycle.
-- Run this BEFORE materialized view DDL so that pg_cron does not
-- terminate the connection when a stale REFRESH job fires during DDL.
--
-- This is idempotent: unscheduling a nonexistent job is a no-op.

do $$
declare
  j record;
begin
  if to_regnamespace('cron') is not null then
    for j in
      select jobid
      from cron.job
      where jobname like 'vec-%'
         or jobname like 'search-%'
         or jobname like 'sync-%'
         or jobname = 'sync-event-retention-prune'
      order by jobid
    loop
      perform cron.unschedule(j.jobid);
    end loop;
  end if;
end $$;

-- object: mv_ap_risk_score
-- folder: materialized_views
-- depends_on: v_ap_risk_score
-- Materialized for 5-minute refresh alongside v_device_repetition_score
do $$
declare
  j record;
begin
  if to_regnamespace('cron') is not null then
    for j in select jobname from cron.job where jobname like 'vec-%' loop
      perform cron.unschedule(j.jobname);
    end loop;
  end if;
end $$;

drop materialized view if exists mv_ap_risk_score;

create materialized view mv_ap_risk_score as
select * from v_ap_risk_score;

create unique index if not exists idx_mv_ap_risk_score_bssid
  on mv_ap_risk_score (bssid);

-- object: v_device_repetition_score
-- folder: materialized_views
-- depends_on: vec_similarity_pairs
-- vec similarity foundation end
-- V019: Create v_device_repetition_score view
--
-- Provides a queryable surface for near-duplicate detection in vec_similarity_pairs.
-- Since a pair has a left and right side, we union both sides to count how many
-- times a device appears as a near-duplicate participant.

DROP MATERIALIZED VIEW IF EXISTS v_device_repetition_score;

CREATE MATERIALIZED VIEW v_device_repetition_score AS
WITH device_pairs AS (
    -- Left side: device is the left member of the pair
    SELECT
        p.left_source_mac AS source_mac,
        p.cosine_distance,
        p.left_embedding_id AS embedding_id,
        p.computed_at
    FROM vec_similarity_pairs_expanded p
    WHERE (
        (p.pair_kind = 'event_event' AND p.cosine_distance < 0.05)
        OR (p.pair_kind = 'device_device' AND p.embedding_kind = 'behaviour_window' AND p.cosine_distance < 0.12)
        OR (p.pair_kind = 'sequence_sequence' AND p.embedding_kind = 'frame_sequence' AND p.cosine_distance < 0.10)
        OR (p.pair_kind = 'timing_timing' AND p.embedding_kind = 'timing_profile' AND p.cosine_distance < 0.05)
      )
      AND p.left_source_mac IS NOT NULL

    UNION ALL

    -- Right side: device is the right member of the pair
    SELECT
        p.right_source_mac AS source_mac,
        p.cosine_distance,
        p.right_embedding_id AS embedding_id,
        p.computed_at
    FROM vec_similarity_pairs_expanded p
    WHERE (
        (p.pair_kind = 'event_event' AND p.cosine_distance < 0.05)
        OR (p.pair_kind = 'device_device' AND p.embedding_kind = 'behaviour_window' AND p.cosine_distance < 0.12)
        OR (p.pair_kind = 'sequence_sequence' AND p.embedding_kind = 'frame_sequence' AND p.cosine_distance < 0.10)
        OR (p.pair_kind = 'timing_timing' AND p.embedding_kind = 'timing_profile' AND p.cosine_distance < 0.05)
      )
      AND p.right_source_mac IS NOT NULL
)
SELECT
    source_mac,
    COUNT(*) AS near_duplicate_pairs,
    MIN(cosine_distance) AS min_distance,
    AVG(cosine_distance) AS avg_distance,
    COUNT(DISTINCT embedding_id) AS unique_events_implicated
FROM device_pairs
WHERE computed_at >= NOW() - INTERVAL '7 days'
GROUP BY source_mac
ORDER BY near_duplicate_pairs DESC;

COMMENT ON MATERIALIZED VIEW v_device_repetition_score IS
  'Daily device repetition scores from near-duplicate event, behaviour, sequence, and timing pairs in vec_similarity_pairs. Refresh with REFRESH MATERIALIZED VIEW CONCURRENTLY.';

CREATE UNIQUE INDEX IF NOT EXISTS idx_v_device_repetition_score_mac
  ON v_device_repetition_score (source_mac);

-- object: vec_dns_violation_summary
-- folder: materialized_views
-- depends_on: vec_dns_resolver_ledger

drop materialized view if exists vec_dns_violation_summary;

create materialized view vec_dns_violation_summary as
select
  wg_pubkey,
  date_trunc('day', observed_at)::date as observed_date,
  protocol,
  count(*) filter (where status <> 'observed')::bigint as violation_count,
  count(*)::bigint as observation_count,
  max(observed_at) as last_observed_at
from vec_dns_resolver_ledger
group by wg_pubkey, date_trunc('day', observed_at)::date, protocol;

comment on materialized view vec_dns_violation_summary is
  'Daily DNS resolver observations and violation counts by WireGuard public key and protocol.';

create unique index if not exists vec_dns_violation_summary_pk
  on vec_dns_violation_summary (wg_pubkey, observed_date, protocol);

-- object: vec_install_cron_jobs
-- folder: cron
-- depends_on: all vec_* objects and materialized views
create or replace function vec_refresh_device_repetition_score()
returns void
language plpgsql
as $$
begin
  if not vec_try_begin_maintenance_job('vec-refresh-device-repetition-score') then
    return;
  end if;

  refresh materialized view v_device_repetition_score;

  perform vec_finish_maintenance_job('vec-refresh-device-repetition-score');
exception when others then
  perform vec_finish_maintenance_job('vec-refresh-device-repetition-score');
  raise;
end;
$$;

create or replace function vec_refresh_ap_risk_score()
returns void
language plpgsql
as $$
begin
  if not vec_try_begin_maintenance_job('vec-refresh-ap-risk-score') then
    return;
  end if;

  refresh materialized view mv_ap_risk_score;
  perform check_high_risk_aps();

  perform vec_finish_maintenance_job('vec-refresh-ap-risk-score');
exception when others then
  perform vec_finish_maintenance_job('vec-refresh-ap-risk-score');
  raise;
end;
$$;

create or replace function vec_install_cron_jobs()
returns void
language plpgsql
as $$
declare
  j record;
begin
  if to_regnamespace('cron') is null then
    raise exception 'pg_cron schema is unavailable';
  end if;

  for j in
    select jobid
    from cron.job
    where jobname = any (array[
      'vec-build-behaviour-snapshots',
      'vec-build-frame-sequences',
      'vec-build-timing-profiles',
      'vec-build-baseline-profiles',
      'vec-build-infrastructure-graph',
      'vec-detect-rogue-clusters',
      'vec-enqueue-embedding-jobs',
      'sync-event-retention-prune',
      'vec-prune-retention',
      'vec-materialize-similarity-pairs',
      'vec-apply-similarity-flags',
      'vec-fuse-device-identities',
      'vec-refresh-device-repetition-score',
      'vec-release-expired-leases',
      'vec-reap-stale-workers',
      'vec-update-transition-model',
      'vec-update-device-centroids',
      'vec-refresh-ap-risk-score',
      'search-purge-expired-queries'
    ])
    order by jobid
  loop
    perform cron.unschedule(j.jobid);
  end loop;

  perform cron.schedule(
    'vec-build-behaviour-snapshots',
    '0,10,20,30,40,50 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-behaviour-snapshots', $stmt$select vec_build_behaviour_snapshots()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-build-frame-sequences',
    '2,12,22,32,42,52 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-frame-sequences', $stmt$select vec_build_frame_sequences()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-build-timing-profiles',
    '4,19,34,49 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-timing-profiles', $stmt$select vec_build_timing_profiles()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-build-baseline-profiles',
    '6,21,36,51 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-baseline-profiles', $stmt$select vec_build_baseline_profiles()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-build-infrastructure-graph',
    '8,23,38,53 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-infrastructure-graph', $stmt$select vec_build_infrastructure_graph()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-detect-rogue-clusters',
    '10,25,40,55 * * * *',
    $cron$select vec_run_maintenance_sql('vec-detect-rogue-clusters', $stmt$select vec_detect_rogue_clusters()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-enqueue-embedding-jobs',
    '*/5 * * * *',
    $cron$select vec_run_maintenance_sql('vec-enqueue-embedding-jobs', $stmt$select vec_enqueue_embedding_jobs('nomic-embed-text-v2-moe'::text, 'high_signal'::text)$stmt$);$cron$
  );

  perform cron.schedule(
    'sync-event-retention-prune',
    '37 * * * *',
    $cron$select coordinator.prune_sync_event_retention();$cron$
  );

  perform cron.schedule(
    'vec-prune-retention',
    '47 * * * *',
    $cron$select vec_run_maintenance_sql('vec-prune-retention', $stmt$select vec_prune_retention()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-materialize-similarity-pairs',
    '12,27,42,57 * * * *',
    $cron$select vec_run_maintenance_sql('vec-materialize-similarity-pairs', $stmt$select vec_materialize_similarity_pairs('nomic-embed-text-v2-moe'::text, 10::integer, 0.05::double precision, 0.88::double precision, 0.10::double precision, 0.05::double precision)$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-apply-similarity-flags',
    '14,29,44,59 * * * *',
    $cron$select vec_run_maintenance_sql('vec-apply-similarity-flags', $stmt$select vec_apply_similarity_flags('nomic-embed-text-v2-moe'::text, 0.05::double precision, 0.88::double precision)$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-fuse-device-identities',
    '5,20,35,50 * * * *',
    $cron$select vec_run_maintenance_sql('vec-fuse-device-identities', $stmt$select vec_fuse_device_identities()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-refresh-device-repetition-score',
    '3,18,33,48 * * * *',
    $cron$select vec_refresh_device_repetition_score();$cron$
  );

  perform cron.schedule(
    'vec-release-expired-leases',
    '* * * * *',
    $cron$select vec_release_expired_leases();$cron$
  );

  perform cron.schedule(
    'vec-reap-stale-workers',
    '*/5 * * * *',
    $cron$select vec_reap_stale_workers();$cron$
  );

  perform cron.schedule(
    'vec-update-transition-model',
    '7,22,37,52 * * * *',
    $cron$select vec_run_maintenance_sql('vec-update-transition-model', $stmt$select vec_update_transition_model()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-update-device-centroids',
    '10,25,40,55 * * * *',
    $cron$select vec_run_maintenance_sql('vec-update-device-centroids', $stmt$select vec_update_device_centroids()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-refresh-ap-risk-score',
    '9,24,39,54 * * * *',
    $cron$select vec_refresh_ap_risk_score();$cron$
  );

  perform cron.schedule(
    'search-purge-expired-queries',
    '17 3 * * *',
    $cron$select search_purge_expired_queries();$cron$
  );
end;
$$;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform vec_install_cron_jobs();
  else
    raise notice 'pg_cron extension unavailable; skipping vec cron job installation';
  end if;
end $$;

-- object: device_graph_workmap_cron_jobs
-- folder: cron
-- depends_on: pg_cron, vec_device_graph_retention, vec_job_lock_ttl_helpers, vec_dns_violation_summary

create or replace function vec_refresh_dns_violation_summary()
returns void
language plpgsql
as $$
begin
  if not vec_try_begin_maintenance_job('vec-refresh-dns-violation-summary') then
    return;
  end if;

  refresh materialized view vec_dns_violation_summary;

  perform vec_finish_maintenance_job('vec-refresh-dns-violation-summary');
exception when others then
  perform vec_finish_maintenance_job('vec-refresh-dns-violation-summary');
  raise;
end;
$$;

create or replace function vec_install_device_graph_cron_jobs()
returns void
language plpgsql
as $$
declare
  v_job text;
begin
  if to_regnamespace('cron') is null then
    raise exception 'pg_cron schema is unavailable';
  end if;

  foreach v_job in array array[
    'vec-prune-device-graph-retention',
    'vec-prune-stale-job-locks',
    'vec-refresh-dns-violation-summary'
  ] loop
    if exists (select 1 from cron.job where jobname = v_job) then
      perform cron.unschedule(v_job);
    end if;
  end loop;

  perform cron.schedule(
    'vec-prune-device-graph-retention',
    '27 2 * * *',
    $cron$select vec_run_maintenance_sql('vec-prune-device-graph-retention', $stmt$select vec_prune_device_graph_retention()$stmt$);$cron$
  );

  perform cron.schedule(
    'vec-prune-stale-job-locks',
    '*/5 * * * *',
    $cron$select vec_prune_stale_job_locks();$cron$
  );

  perform cron.schedule(
    'vec-refresh-dns-violation-summary',
    '41 2 * * *',
    $cron$select vec_refresh_dns_violation_summary();$cron$
  );
end;
$$;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform vec_install_device_graph_cron_jobs();
  else
    raise notice 'pg_cron extension unavailable; skipping device graph cron job installation';
  end if;
end $$;
