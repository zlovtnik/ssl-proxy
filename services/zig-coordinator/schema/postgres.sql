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
  schema_version integer not null default 1,
  frame_type text,
  source_mac text,
  bssid text,
  destination_bssid text,
  ssid text,
  signal_dbm integer,
  fragment_number integer,
  channel_number integer,
  signal_status text,
  adjacent_mac_hint text,
  qos_tid integer,
  qos_eosp boolean,
  qos_ack_policy integer,
  qos_ack_policy_label text,
  qos_amsdu boolean,
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
  app_protocol text,
  ssdp_message_type text,
  ssdp_st text,
  ssdp_mx text,
  ssdp_usn text,
  dhcp_requested_ip text,
  dhcp_hostname text,
  dhcp_vendor_class text,
  dns_query_name text,
  mdns_name text,
  session_key text,
  retransmit_key text,
  frame_fingerprint text,
  payload_visibility text,
  tsft_delta_us bigint,
  wall_clock_delta_ms bigint,
  large_frame boolean not null default false,
  mixed_encryption boolean,
  dedupe_or_replay_suspect boolean not null default false,
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
alter table sync_scan_ingest add column if not exists schema_version integer not null default 1;
alter table sync_scan_ingest add column if not exists frame_type text;
alter table sync_scan_ingest add column if not exists fragment_number integer;
alter table sync_scan_ingest add column if not exists channel_number integer;
alter table sync_scan_ingest add column if not exists signal_status text;
alter table sync_scan_ingest add column if not exists adjacent_mac_hint text;
alter table sync_scan_ingest add column if not exists qos_tid integer;
alter table sync_scan_ingest add column if not exists qos_eosp boolean;
alter table sync_scan_ingest add column if not exists qos_ack_policy integer;
alter table sync_scan_ingest add column if not exists qos_ack_policy_label text;
alter table sync_scan_ingest add column if not exists qos_amsdu boolean;
alter table sync_scan_ingest add column if not exists llc_oui text;
alter table sync_scan_ingest add column if not exists ethertype integer;
alter table sync_scan_ingest add column if not exists ethertype_name text;
alter table sync_scan_ingest add column if not exists src_ip text;
alter table sync_scan_ingest add column if not exists dst_ip text;
alter table sync_scan_ingest add column if not exists ip_ttl integer;
alter table sync_scan_ingest add column if not exists ip_protocol integer;
alter table sync_scan_ingest add column if not exists ip_protocol_name text;
alter table sync_scan_ingest add column if not exists src_port integer;
alter table sync_scan_ingest add column if not exists dst_port integer;
alter table sync_scan_ingest add column if not exists transport_protocol text;
alter table sync_scan_ingest add column if not exists transport_length integer;
alter table sync_scan_ingest add column if not exists transport_checksum integer;
alter table sync_scan_ingest add column if not exists app_protocol text;
alter table sync_scan_ingest add column if not exists ssdp_message_type text;
alter table sync_scan_ingest add column if not exists ssdp_st text;
alter table sync_scan_ingest add column if not exists ssdp_mx text;
alter table sync_scan_ingest add column if not exists ssdp_usn text;
alter table sync_scan_ingest add column if not exists dhcp_requested_ip text;
alter table sync_scan_ingest add column if not exists dhcp_hostname text;
alter table sync_scan_ingest add column if not exists dhcp_vendor_class text;
alter table sync_scan_ingest add column if not exists dns_query_name text;
alter table sync_scan_ingest add column if not exists mdns_name text;
alter table sync_scan_ingest add column if not exists session_key text;
alter table sync_scan_ingest add column if not exists retransmit_key text;
alter table sync_scan_ingest add column if not exists frame_fingerprint text;
alter table sync_scan_ingest add column if not exists payload_visibility text;
alter table sync_scan_ingest add column if not exists tsft_delta_us bigint;
alter table sync_scan_ingest add column if not exists wall_clock_delta_ms bigint;
alter table sync_scan_ingest add column if not exists large_frame boolean not null default false;
alter table sync_scan_ingest add column if not exists mixed_encryption boolean;
alter table sync_scan_ingest add column if not exists dedupe_or_replay_suspect boolean not null default false;
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
  if not exists (select 1 from pg_constraint where conname = 'chk_sync_scan_ingest_status') then
    alter table sync_scan_ingest add constraint chk_sync_scan_ingest_status check (status in ('pending','processing','batched','failed'));
  end if;
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
  coalesce(ssi.schema_version, nullif(ssi.payload->>'schema_version', '')::integer, 1) as schema_version,
  coalesce(ssi.frame_type, ssi.payload->>'frame_type') as frame_type,
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
  coalesce(ssi.channel_number::text, ssi.payload->>'channel_number') as channel_number,
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
  coalesce(d_src.hostname, d_bssid.hostname, ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') as hostname
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

create index if not exists ssi_wireless_source_mac_payload_idx
  on sync_scan_ingest (lower(coalesce(source_mac, payload->>'source_mac')))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_bssid_idx
  on sync_scan_ingest (lower(bssid))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_bssid_payload_idx
  on sync_scan_ingest (lower(coalesce(bssid, payload->>'bssid')))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_destination_bssid_idx
  on sync_scan_ingest (lower(destination_bssid))
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_schema_version_idx
  on sync_scan_ingest (schema_version, observed_at desc)
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_signal_idx
  on sync_scan_ingest (signal_dbm, observed_at desc)
  where stream_name = 'wireless.audit' and signal_dbm is not null;

create index if not exists ssi_wireless_src_ip_idx
  on sync_scan_ingest (src_ip)
  where stream_name = 'wireless.audit' and src_ip is not null;

create index if not exists ssi_wireless_dst_ip_idx
  on sync_scan_ingest (dst_ip)
  where stream_name = 'wireless.audit' and dst_ip is not null;

create index if not exists ssi_wireless_app_protocol_idx
  on sync_scan_ingest (app_protocol, observed_at desc)
  where stream_name = 'wireless.audit' and app_protocol is not null;

create index if not exists ssi_wireless_session_key_idx
  on sync_scan_ingest (session_key, observed_at desc)
  where stream_name = 'wireless.audit' and session_key is not null;

create index if not exists ssi_wireless_frame_fingerprint_idx
  on sync_scan_ingest (frame_fingerprint)
  where stream_name = 'wireless.audit' and frame_fingerprint is not null;

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
    nullif(ssi.payload->>'tsft', '')::bigint as tsft
  from sync_scan_ingest ssi
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

create or replace view v_wireless_device_inventory as
select
  md5(coalesce(lower(source_mac), '') || '|' || coalesce(location_id, '')) as inventory_key,
  lower(source_mac) as source_mac,
  max(location_id) as location_id,
  min(observed_at) as first_seen,
  max(observed_at) as last_seen,
  max(ssid) as ssid,
  max(destination_bssid) as destination_bssid,
  string_agg(distinct src_ip, ', ') filter (where src_ip is not null) as ip_addresses,
  string_agg(distinct hostname, ', ') filter (where hostname is not null) as hostnames,
  string_agg(distinct app_protocol, ', ') filter (where app_protocol is not null) as services,
  string_agg(distinct dns_query_name, ', ') filter (where dns_query_name is not null) as dns_names,
  count(*) as frame_count,
  sum(case when protected then 1 else 0 end) as protected_frame_count,
  sum(case when not protected then 1 else 0 end) as open_frame_count
from (
  select
    observed_at,
    coalesce(source_mac, payload->>'source_mac') as source_mac,
    payload->>'location_id' as location_id,
    coalesce(ssid, payload->>'ssid') as ssid,
    coalesce(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid') as destination_bssid,
    coalesce(src_ip, payload->>'src_ip') as src_ip,
    coalesce(dhcp_hostname, mdns_name, payload->>'dhcp_hostname', payload->>'mdns_name') as hostname,
    coalesce(app_protocol, payload->>'app_protocol') as app_protocol,
    coalesce(dns_query_name, payload->>'dns_query_name') as dns_query_name,
    coalesce(protected, false) as protected
  from sync_scan_ingest
  where stream_name = 'wireless.audit'
) inventory
where source_mac is not null
group by lower(source_mac), location_id;

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
