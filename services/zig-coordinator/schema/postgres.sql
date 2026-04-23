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
  source_mac text,
  bssid text,
  destination_bssid text,
  ssid text,
  signal_dbm integer,
  raw_len integer not null default 0,
  frame_control_flags integer not null default 0,
  more_data boolean not null default false,
  retry boolean not null default false,
  power_save boolean not null default false,
  protected boolean not null default false,
  security_flags integer not null default 0,
  wps_device_name text,
  wps_manufacturer text,
  wps_model_name text,
  device_fingerprint text,
  handshake_captured boolean not null default false,
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
  cursor_end text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists sync_error (
  id bigserial primary key,
  job_id uuid,
  batch_id uuid,
  error_class text not null,
  error_text text not null,
  created_at timestamptz not null default now()
);

alter table sync_batch add column if not exists created_at timestamptz not null default now();
alter table sync_batch add column if not exists updated_at timestamptz not null default now();
alter table sync_scan_ingest add column if not exists source_mac text;
alter table sync_scan_ingest add column if not exists bssid text;
alter table sync_scan_ingest add column if not exists destination_bssid text;
alter table sync_scan_ingest add column if not exists ssid text;
alter table sync_scan_ingest add column if not exists signal_dbm integer;
alter table sync_scan_ingest add column if not exists raw_len integer not null default 0;
alter table sync_scan_ingest add column if not exists frame_control_flags integer not null default 0;
alter table sync_scan_ingest add column if not exists more_data boolean not null default false;
alter table sync_scan_ingest add column if not exists retry boolean not null default false;
alter table sync_scan_ingest add column if not exists power_save boolean not null default false;
alter table sync_scan_ingest add column if not exists protected boolean not null default false;
alter table sync_scan_ingest add column if not exists security_flags integer not null default 0;
alter table sync_scan_ingest add column if not exists wps_device_name text;
alter table sync_scan_ingest add column if not exists wps_manufacturer text;
alter table sync_scan_ingest add column if not exists wps_model_name text;
alter table sync_scan_ingest add column if not exists device_fingerprint text;
alter table sync_scan_ingest add column if not exists handshake_captured boolean not null default false;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'chk_sync_job_status') then
    alter table sync_job add constraint chk_sync_job_status check (status in ('pending','running','completed','failed'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'chk_sync_batch_status') then
    alter table sync_batch add constraint chk_sync_batch_status check (status in ('pending','processing','dispatched','completed','failed'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'fk_sync_job_stream_name') then
    alter table sync_job add constraint fk_sync_job_stream_name foreign key (stream_name) references sync_cursor(stream_name) deferrable initially deferred;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'fk_sync_batch_job_id') then
    alter table sync_batch add constraint fk_sync_batch_job_id foreign key (job_id) references sync_job(job_id);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'fk_sync_error_job_id') then
    alter table sync_error add constraint fk_sync_error_job_id foreign key (job_id) references sync_job(job_id);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'fk_sync_error_batch_id') then
    alter table sync_error add constraint fk_sync_error_batch_id foreign key (batch_id) references sync_batch(batch_id);
  end if;
end $$;

create unique index if not exists sync_batch_dedupe_idx on sync_batch (dedupe_key);
create index if not exists idx_sync_job_stream_name on sync_job (stream_name);
create index if not exists idx_sync_job_status_created_at on sync_job (status, created_at);
create index if not exists idx_sync_batch_job_batch_no on sync_batch (job_id, batch_no);
create index if not exists idx_sync_batch_status on sync_batch (status);
create index if not exists idx_sync_error_job_id on sync_error (job_id);
create index if not exists idx_sync_error_batch_id on sync_error (batch_id);
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

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'chk_audit_backlog_status') then
    alter table audit_backlog add constraint chk_audit_backlog_status check (status in ('pending','synced','sync_failed','failed'));
  end if;
end $$;

create index if not exists audit_backlog_status_idx on audit_backlog (status, updated_at);

create table if not exists authorized_wireless_networks (
  id bigserial primary key,
  ssid text,
  bssid text,
  location_id text,
  label text,
  enabled boolean not null default true,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint authorized_wireless_network_identity_chk check (
    nullif(trim(coalesce(ssid, '')), '') is not null
    or nullif(trim(coalesce(bssid, '')), '') is not null
  )
);

create unique index if not exists authorized_wireless_networks_match_idx
  on authorized_wireless_networks (
    coalesce(lower(ssid), ''),
    coalesce(lower(bssid), ''),
    coalesce(location_id, '')
  );

create index if not exists authorized_wireless_networks_enabled_idx
  on authorized_wireless_networks (enabled, location_id);

create table if not exists shadow_it_alerts (
  alert_id bigserial primary key,
  dedupe_key text not null unique,
  observed_at timestamptz not null,
  source_mac text not null,
  destination_bssid text,
  ssid text,
  sensor_id text,
  location_id text,
  signal_dbm integer,
  reason text not null,
  evidence jsonb not null default '{}'::jsonb,
  resolved_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists shadow_it_alerts_open_idx
  on shadow_it_alerts (observed_at desc)
  where resolved_at is null;

create index if not exists shadow_it_alerts_source_idx
  on shadow_it_alerts (lower(source_mac), observed_at desc);

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
  coalesce(ssi.source_mac, ssi.payload->>'source_mac') as source_mac,
  ssi.payload->>'transmitter_mac' as transmitter_mac,
  ssi.payload->>'receiver_mac' as receiver_mac,
  coalesce(ssi.bssid, ssi.payload->>'bssid') as bssid,
  coalesce(ssi.destination_bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') as destination_bssid,
  coalesce(ssi.ssid, ssi.payload->>'ssid') as ssid,
  ssi.payload->>'frame_subtype' as frame_subtype,
  coalesce(ssi.signal_dbm::text, ssi.payload->>'signal_dbm') as signal_dbm,
  ssi.payload->>'noise_dbm' as noise_dbm,
  ssi.payload->>'frequency_mhz' as frequency_mhz,
  ssi.payload->>'data_rate_kbps' as data_rate_kbps,
  coalesce(ssi.raw_len::text, ssi.payload->>'raw_len') as raw_len,
  coalesce(ssi.frame_control_flags::text, ssi.payload->>'frame_control_flags') as frame_control_flags,
  coalesce(ssi.more_data::text, ssi.payload->>'more_data') as more_data,
  coalesce(ssi.retry::text, ssi.payload->>'retry') as retry,
  coalesce(ssi.power_save::text, ssi.payload->>'power_save') as power_save,
  coalesce(ssi.protected::text, ssi.payload->>'protected') as protected,
  ssi.payload->>'location_id' as location_id,
  ssi.payload->>'sensor_id' as sensor_id,
  ssi.payload->>'identity_source' as identity_source,
  ssi.payload->>'username' as username,
  ssi.payload->'tags' as tags,
  ssi.security_flags,
  ssi.wps_device_name,
  ssi.wps_manufacturer,
  ssi.wps_model_name,
  ssi.device_fingerprint,
  ssi.handshake_captured,
  coalesce(d_src.device_id, d_bssid.device_id) as device_id,
  coalesce(d_src.display_name, d_bssid.display_name) as display_name,
  coalesce(d_src.username, d_bssid.username) as registered_username,
  coalesce(d_src.os_hint, d_bssid.os_hint) as os_hint,
  coalesce(d_src.hostname, d_bssid.hostname) as hostname
from sync_scan_ingest ssi
left join devices d_src
  on lower(d_src.mac_hint) = lower(coalesce(ssi.source_mac, ssi.payload->>'source_mac'))
left join devices d_bssid
  on lower(d_bssid.mac_hint) = lower(coalesce(ssi.bssid, ssi.payload->>'bssid'))
where ssi.stream_name = 'wireless.audit';

do $$
begin
  if exists (
    select 1
    from pg_indexes
    where schemaname = current_schema()
      and indexname = 'ssi_wireless_ssid_idx'
      and indexdef not ilike '%(ssid,%'
  ) then
    drop index ssi_wireless_ssid_idx;
  end if;
end $$;

do $$
begin
  if exists (
    select 1
    from pg_indexes
    where schemaname = current_schema()
      and indexname = 'ssi_wireless_source_mac_idx'
      and indexdef not ilike '%lower(source_mac)%'
  ) then
    drop index ssi_wireless_source_mac_idx;
  end if;
end $$;

do $$
begin
  if exists (
    select 1
    from pg_indexes
    where schemaname = current_schema()
      and indexname = 'ssi_wireless_bssid_idx'
      and indexdef not ilike '%lower(bssid)%'
  ) then
    drop index ssi_wireless_bssid_idx;
  end if;
end $$;

create index if not exists ssi_wireless_ssid_idx
  on sync_scan_ingest (ssid, observed_at desc)
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_source_mac_idx
  on sync_scan_ingest (lower(source_mac))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_bssid_idx
  on sync_scan_ingest (lower(bssid))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_destination_bssid_idx
  on sync_scan_ingest (lower(destination_bssid))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_signal_idx
  on sync_scan_ingest (signal_dbm, observed_at desc)
  where stream_name = 'wireless.audit' and signal_dbm is not null;

create index if not exists ssi_wireless_threat_tags_idx
  on sync_scan_ingest using gin ((payload->'tags'))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_device_fingerprint_idx
  on sync_scan_ingest (device_fingerprint, observed_at desc)
  where stream_name = 'wireless.audit' and device_fingerprint is not null;

create index if not exists ssi_wireless_security_flags_idx
  on sync_scan_ingest (security_flags, observed_at desc)
  where stream_name = 'wireless.audit' and security_flags <> 0;

create index if not exists ssi_wireless_handshake_captured_idx
  on sync_scan_ingest (observed_at desc)
  where stream_name = 'wireless.audit' and handshake_captured;

create index if not exists ssi_pending_observed_idx
  on sync_scan_ingest (observed_at asc)
  where status in ('pending', 'failed');

create or replace view v_wireless_threats as
select
  observed_at,
  coalesce(ssid, payload->>'ssid') as ssid,
  coalesce(bssid, payload->>'bssid') as bssid,
  coalesce(destination_bssid, payload->>'destination_bssid', payload->>'bssid') as destination_bssid,
  coalesce(source_mac, payload->>'source_mac') as source_mac,
  payload->>'transmitter_mac' as transmitter_mac,
  payload->>'receiver_mac' as receiver_mac,
  payload->>'frame_subtype' as frame_subtype,
  coalesce(signal_dbm::text, payload->>'signal_dbm') as signal_dbm,
  payload->>'noise_dbm' as noise_dbm,
  payload->>'frequency_mhz' as frequency_mhz,
  payload->>'data_rate_kbps' as data_rate_kbps,
  coalesce(raw_len::text, payload->>'raw_len') as raw_len,
  coalesce(frame_control_flags::text, payload->>'frame_control_flags') as frame_control_flags,
  coalesce(more_data::text, payload->>'more_data') as more_data,
  coalesce(retry::text, payload->>'retry') as retry,
  coalesce(power_save::text, payload->>'power_save') as power_save,
  coalesce(protected::text, payload->>'protected') as protected,
  payload->>'location_id' as location_id,
  payload->>'identity_source' as identity_source,
  payload->>'username' as username,
  payload->'tags' as tags,
  security_flags,
  wps_device_name,
  wps_manufacturer,
  wps_model_name,
  device_fingerprint,
  handshake_captured
from sync_scan_ingest
where stream_name = 'wireless.audit'
  and (
    payload->'tags' ? 'threat:potential_evil_twin'
    or payload->'tags' ? 'threat:karma_probe_response'
    or payload->'tags' ? 'threat:deauth_flood'
    or payload->'tags' ? 'threat:deauth_frame'
    or handshake_captured
  )
order by observed_at desc;

create or replace view v_shadow_it_alerts as
select
  alert_id,
  dedupe_key,
  observed_at,
  source_mac,
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
from shadow_it_alerts
order by observed_at desc;
