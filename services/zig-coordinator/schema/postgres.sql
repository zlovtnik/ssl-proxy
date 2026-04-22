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

create table if not exists devices (
  device_id text primary key,
  wg_pubkey text,
  claim_token_hash text,
  display_name text,
  username text,
  hostname text,
  os_hint text,
  mac_hint text,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  notes text
);

create index if not exists devices_mac_hint_idx on devices (lower(mac_hint));
create index if not exists devices_wg_pubkey_idx on devices (wg_pubkey);
create index if not exists devices_username_idx on devices (username, last_seen desc);

create or replace view v_wireless_audit_with_devices as
select
  ssi.dedupe_key,
  ssi.observed_at,
  ssi.stream_name,
  ssi.status,
  ssi.producer,
  ssi.event_kind,
  ssi.payload->>'source_mac' as source_mac,
  ssi.payload->>'bssid' as bssid,
  ssi.payload->>'ssid' as ssid,
  ssi.payload->>'frame_subtype' as frame_subtype,
  ssi.payload->>'signal_dbm' as signal_dbm,
  ssi.payload->>'location_id' as location_id,
  ssi.payload->>'sensor_id' as sensor_id,
  ssi.payload->>'identity_source' as identity_source,
  ssi.payload->>'username' as username,
  ssi.payload->'tags' as tags,
  d.device_id,
  d.display_name,
  d.username as registered_username,
  d.os_hint,
  d.hostname
from sync_scan_ingest ssi
left join devices d
  on lower(d.mac_hint) = lower(ssi.payload->>'source_mac')
  or lower(d.mac_hint) = lower(ssi.payload->>'bssid')
where ssi.stream_name = 'wireless.audit';

create index if not exists ssi_wireless_ssid_idx
  on sync_scan_ingest ((payload->>'ssid'), observed_at desc)
  where stream_name = 'wireless.audit';

do $$
begin
  if exists (
    select 1
    from pg_indexes
    where schemaname = current_schema()
      and indexname = 'ssi_wireless_source_mac_idx'
      and indexdef not ilike '%lower((payload ->> ''source_mac''::text))%'
  ) then
    drop index ssi_wireless_source_mac_idx;
  end if;
end $$;

create index if not exists ssi_wireless_source_mac_idx
  on sync_scan_ingest (lower(payload->>'source_mac'))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_bssid_idx
  on sync_scan_ingest (lower(payload->>'bssid'))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_threat_tags_idx
  on sync_scan_ingest using gin ((payload->'tags'))
  where stream_name = 'wireless.audit';

create index if not exists ssi_pending_observed_idx
  on sync_scan_ingest (observed_at asc)
  where status in ('pending', 'failed');

create or replace view v_wireless_threats as
select
  observed_at,
  payload->>'ssid' as ssid,
  payload->>'bssid' as bssid,
  payload->>'source_mac' as source_mac,
  payload->>'frame_subtype' as frame_subtype,
  payload->>'signal_dbm' as signal_dbm,
  payload->>'location_id' as location_id,
  payload->>'identity_source' as identity_source,
  payload->>'username' as username,
  payload->'tags' as tags
from sync_scan_ingest
where stream_name = 'wireless.audit'
  and (
    payload->'tags' ? 'threat:potential_evil_twin'
    or payload->'tags' ? 'threat:karma_probe_response'
    or payload->'tags' ? 'threat:deauth_flood'
    or payload->'tags' ? 'threat:deauth_frame'
  )
order by observed_at desc;
