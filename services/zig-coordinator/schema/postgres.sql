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
  sensor_id text,
  location_id text,
  username text,
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

create extension if not exists pg_trgm;

alter table sync_batch add column if not exists created_at timestamptz not null default now();
alter table sync_batch add column if not exists updated_at timestamptz not null default now();
alter table sync_scan_ingest add column if not exists sensor_id text;
alter table sync_scan_ingest add column if not exists location_id text;
alter table sync_scan_ingest add column if not exists username text;
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
alter table sync_scan_ingest add column if not exists wireless_search_tsv tsvector
  generated always as (
    to_tsvector(
      'simple'::regconfig,
      lower(
        coalesce(sensor_id, '') || ' ' ||
        coalesce(source_mac, '') || ' ' ||
        coalesce(bssid, '') || ' ' ||
        coalesce(destination_bssid, '') || ' ' ||
        coalesce(ssid, '') || ' ' ||
        coalesce(wps_device_name, '') || ' ' ||
        coalesce(wps_manufacturer, '') || ' ' ||
        coalesce(wps_model_name, '') || ' ' ||
        coalesce(device_fingerprint, '') || ' ' ||
        coalesce(app_protocol, '') || ' ' ||
        coalesce(src_ip, '') || ' ' ||
        coalesce(dst_ip, '') || ' ' ||
        coalesce(username, '')
      )
    )
  ) stored;

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
end $$ ;

create unique index if not exists sync_batch_dedupe_idx on sync_batch (dedupe_key);
create index if not exists idx_sync_job_stream_name on sync_job (stream_name);
create index if not exists idx_sync_job_status_created_at on sync_job (status, created_at);
create index if not exists idx_sync_batch_job_batch_no on sync_batch (job_id, batch_no);
create index if not exists idx_sync_batch_status on sync_batch (status);
create index if not exists idx_sync_error_job_id on sync_error (job_id);
create index if not exists idx_sync_error_batch_id on sync_error (batch_id);
create index if not exists sync_scan_ingest_status_idx on sync_scan_ingest (status, observed_at);
create index if not exists sync_scan_ingest_stream_idx on sync_scan_ingest (stream_name, observed_at);
create index if not exists sync_scan_ingest_ready_idx on sync_scan_ingest (status, stream_name, observed_at)
  where status in ('pending', 'failed');
create index if not exists sync_scan_ingest_processing_idx on sync_scan_ingest (updated_at)
  where status = 'processing';
create index if not exists sync_batch_pending_idx on sync_batch (status, batch_id)
  where status = 'pending';
create index if not exists sync_batch_dispatch_lease_idx on sync_batch (status, updated_at)
  where status in ('dispatched', 'failed');

create table if not exists audit_backlog (
  dedupe_key text primary key,
  stream_name text not null,
  payload jsonb not null,
  status text not null default 'pending',
  attempt_count integer not null default 0,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

do $$
begin
  if exists (
    select 1
      from information_schema.columns
     where table_schema = 'public'
       and table_name = 'audit_backlog'
       and column_name = 'payload'
       and data_type <> 'jsonb'
  ) then
    alter table audit_backlog
      alter column payload type jsonb
      using payload::jsonb;
  end if;

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

create index if not exists authorized_wireless_networks_enabled_idx
  on authorized_wireless_networks (enabled, location_id);

create table if not exists network_clients (
  ssid text not null,
  client_mac text not null,
  known_bssid text,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  probe_count integer not null default 1,
  location_id text,
  primary key (ssid, client_mac)
);

create index if not exists idx_network_clients_client_mac
  on network_clients (client_mac);
create index if not exists idx_network_clients_last_seen
  on network_clients (last_seen desc);
create index if not exists idx_network_clients_known_bssid
  on network_clients (known_bssid)
  where known_bssid is not null;

create table if not exists shadow_it_alerts (
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
  constraint shadow_it_alerts_source_mac_format_chk check (source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
);

alter table shadow_it_alerts add column if not exists first_occurred_at timestamptz;
alter table shadow_it_alerts add column if not exists last_occurred_at timestamptz;
alter table shadow_it_alerts add column if not exists occurrence_count bigint not null default 1;
alter table shadow_it_alerts add column if not exists destination_bssid text;
alter table shadow_it_alerts add column if not exists ssid text;
alter table shadow_it_alerts add column if not exists sensor_id text;
alter table shadow_it_alerts add column if not exists location_id text;
alter table shadow_it_alerts add column if not exists signal_dbm integer;
alter table shadow_it_alerts add column if not exists reason text not null default 'strong_wireless_without_proxy_presence';
alter table shadow_it_alerts add column if not exists evidence jsonb not null default '{}'::jsonb;
alter table shadow_it_alerts add column if not exists resolved_at timestamptz;
alter table shadow_it_alerts add column if not exists created_at timestamptz not null default now();
alter table shadow_it_alerts add column if not exists updated_at timestamptz not null default now();

do $$
begin
  if exists (
    select 1
      from information_schema.columns
     where table_schema = 'public'
       and table_name = 'shadow_it_alerts'
       and column_name = 'observed_at'
  ) then
    update shadow_it_alerts
       set first_occurred_at = coalesce(first_occurred_at, observed_at, created_at, now()),
           last_occurred_at = coalesce(last_occurred_at, observed_at, updated_at, created_at, now());
    alter table shadow_it_alerts alter column observed_at drop not null;
  else
    update shadow_it_alerts
       set first_occurred_at = coalesce(first_occurred_at, created_at, now()),
           last_occurred_at = coalesce(last_occurred_at, updated_at, created_at, now());
  end if;

  if exists (
    select 1
      from information_schema.columns
     where table_schema = 'public'
       and table_name = 'shadow_it_alerts'
       and column_name = 'dedupe_key'
  ) then
    alter table shadow_it_alerts alter column dedupe_key drop not null;
  end if;
end $$;

update shadow_it_alerts
   set source_mac = lower(source_mac)
 where source_mac <> lower(source_mac);

with ranked as (
  select ctid,
         row_number() over (
           partition by source_mac
           order by last_occurred_at desc, updated_at desc, created_at desc, ctid desc
         ) as row_number
    from shadow_it_alerts
)
delete from shadow_it_alerts target
 using ranked
 where target.ctid = ranked.ctid
   and ranked.row_number > 1;

alter table shadow_it_alerts alter column first_occurred_at set not null;
alter table shadow_it_alerts alter column last_occurred_at set not null;

do $$
begin
  if not exists (
    select 1
      from pg_index idx
      join pg_class tbl on tbl.oid = idx.indrelid
      join pg_attribute attr on attr.attrelid = tbl.oid
     where tbl.relname = 'shadow_it_alerts'
       and idx.indisunique
       and attr.attnum = any(idx.indkey)
       and attr.attname = 'source_mac'
  ) then
    create unique index shadow_it_alerts_source_mac_unique_idx
      on shadow_it_alerts (source_mac);
  end if;

  if exists (
    select 1
      from pg_class idx
     where idx.relkind = 'i'
       and idx.relname = 'shadow_it_alerts_open_idx'
       and pg_get_indexdef(idx.oid) not ilike '%last_occurred_at%'
  ) then
    drop index shadow_it_alerts_open_idx;
  end if;
end $$;

create index if not exists shadow_it_alerts_open_idx
  on shadow_it_alerts (last_occurred_at desc)
  where resolved_at is null;

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

create index if not exists devices_wg_pubkey_idx on devices (wg_pubkey);
create index if not exists devices_username_idx on devices (username, last_seen desc);


drop view if exists v_wireless_audit_with_devices;

create view v_wireless_audit_with_devices as
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
  coalesce(ssi.location_id, ssi.payload->>'location_id') as location_id,
  coalesce(ssi.sensor_id, ssi.payload->>'sensor_id') as sensor_id,
  ssi.payload->>'identity_source' as identity_source,
  coalesce(ssi.username, ssi.payload->>'username') as username,
  ssi.payload->'tags' as tags,
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
from sync_scan_ingest ssi
left join devices d_src
  on lower(d_src.mac_hint) = lower(coalesce(ssi.source_mac, ssi.payload->>'source_mac'))
left join devices d_bssid
  on lower(d_bssid.mac_hint) = lower(coalesce(ssi.bssid, ssi.payload->>'bssid'))
where ssi.stream_name = 'wireless.audit';


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

create index if not exists ssi_wireless_search_tsv_idx
  on sync_scan_ingest using gin (wireless_search_tsv)
  where stream_name = 'wireless.audit';

create index if not exists ssi_wireless_common_search_idx
  on sync_scan_ingest using gin ((
    lower(coalesce(sensor_id, '')) || ' ' ||
    lower(coalesce(source_mac, '')) || ' ' ||
    lower(coalesce(ssid, ''))
  ) gin_trgm_ops)
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

drop view if exists v_wireless_threats;

create view v_wireless_threats as
select
  observed_at,
  coalesce(ssid, payload->>'ssid') as ssid,
  coalesce(bssid, payload->>'bssid') as bssid,
  coalesce(destination_bssid, payload->>'destination_bssid', payload->>'bssid') as destination_bssid,
  coalesce(source_mac, payload->>'source_mac') as source_mac,
  coalesce(sensor_id, payload->>'sensor_id') as sensor_id,
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
  coalesce(location_id, payload->>'location_id') as location_id,
  payload->>'identity_source' as identity_source,
  coalesce(username, payload->>'username') as username,
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
with recent_ingest as materialized (
  select *
  from sync_scan_ingest
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
    coalesce(signal_dbm, nullif(payload->>'signal_dbm', '')::integer) as signal_dbm,
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

create or replace view v_sync_plane_health as
with ingest_status as (
  select
    status,
    count(*)::bigint as row_count
  from sync_scan_ingest
  group by status
),
wireless_ingest_status as (
  select
    status,
    count(*)::bigint as row_count
  from sync_scan_ingest
  where stream_name = 'wireless.audit'
  group by status
),
ingest_time as (
  select
    count(*) filter (where stream_name = 'wireless.audit' and observed_at >= now() - interval '24 hours')::bigint as wireless_events_24h_count,
    max(observed_at) filter (where stream_name = 'wireless.audit') as wireless_last_observed_at
  from sync_scan_ingest
),
batch_status as (
  select
    status,
    count(*)::bigint as row_count
  from sync_batch
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
  from sync_job job
  left join sync_batch batch on batch.job_id = job.job_id
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
  from audit_backlog
  group by status
),
shadow_status as (
  select
    count(*) filter (where resolved_at is null)::bigint as open_alert_count,
    max(last_occurred_at) filter (where resolved_at is null) as last_open_alert_at
  from shadow_it_alerts
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
  (select cursor_value from sync_cursor where stream_name = 'wireless.audit') as wireless_cursor_value,
  (select updated_at from sync_cursor where stream_name = 'wireless.audit') as wireless_cursor_updated_at;

create or replace view v_shadow_it_alerts as
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
from shadow_it_alerts
order by last_occurred_at desc;

-- vec similarity foundation begin
create extension if not exists vector;
create extension if not exists pg_cron;

do $$
begin
  if not exists (select 1 from pg_am where amname = 'hnsw') then
    raise exception 'pgvector hnsw index access method is unavailable';
  end if;

  if not exists (select 1 from pg_am where amname = 'ivfflat') then
    raise exception 'pgvector ivfflat index access method is unavailable';
  end if;

  if not exists (select 1 from pg_opclass where opcname = 'vector_cosine_ops') then
    raise exception 'pgvector vector_cosine_ops operator class is unavailable';
  end if;
end $$;

create table if not exists vec_embeddings (
  embedding_id bigserial primary key,
  source_table text not null,
  source_key text not null,
  source_observed_at timestamptz,
  source_stream_name text,
  source_sensor_id text,
  source_location_id text,
  source_mac text,
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
  constraint vec_embeddings_kind_chk check (embedding_kind in ('event', 'device', 'behaviour_window')),
  constraint vec_embeddings_dimensions_chk check (embedding_dimensions > 0),
  constraint vec_embeddings_source_unique unique (source_table, source_key, embedding_model, embedding_kind)
);

create index if not exists vec_embeddings_source_idx
  on vec_embeddings (source_table, source_key);
create index if not exists vec_embeddings_kind_model_idx
  on vec_embeddings (embedding_kind, embedding_model, embedded_at desc);
create index if not exists vec_embeddings_source_mac_idx
  on vec_embeddings (lower(source_mac), source_observed_at desc)
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

create table if not exists vec_behaviour_snapshots (
  snapshot_id bigserial primary key,
  snapshot_key text not null unique,
  source_mac text not null,
  location_id text,
  sensor_id text,
  window_start timestamptz not null,
  window_end timestamptz not null,
  event_count bigint not null default 0,
  protocol_mix jsonb not null default '{}'::jsonb,
  frame_type_distribution jsonb not null default '{}'::jsonb,
  signal_min_dbm integer,
  signal_max_dbm integer,
  signal_avg_dbm numeric(8,2),
  retry_count bigint not null default 0,
  protected_count bigint not null default 0,
  unprotected_count bigint not null default 0,
  unique_bssid_count bigint not null default 0,
  mac_rotation_indicators jsonb not null default '{}'::jsonb,
  text_summary text not null,
  embedding_text text,     -- identity-stripped behavioural text for dense embedding
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_behaviour_snapshots_window_chk check (window_end > window_start)
);

create index if not exists vec_behaviour_snapshots_mac_time_idx
  on vec_behaviour_snapshots (source_mac, window_start desc);
create index if not exists vec_behaviour_snapshots_location_time_idx
  on vec_behaviour_snapshots (location_id, window_start desc);

create table if not exists vec_similarity_pairs (
  pair_id bigserial primary key,
  pair_kind text not null,
  embedding_model text not null,
  embedding_kind text not null,
  left_embedding_id bigint not null references vec_embeddings(embedding_id) on delete cascade,
  right_embedding_id bigint not null references vec_embeddings(embedding_id) on delete cascade,
  left_source_table text not null,
  left_source_key text not null,
  left_source_mac text,
  left_sensor_id text,
  left_location_id text,
  left_observed_at timestamptz,
  right_source_table text not null,
  right_source_key text not null,
  right_source_mac text,
  right_sensor_id text,
  right_location_id text,
  right_observed_at timestamptz,
  cosine_distance double precision not null,
  cosine_similarity double precision not null,
  rank integer not null default 1,
  evidence jsonb not null default '{}'::jsonb,
  computed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_similarity_pairs_kind_chk check (pair_kind in ('event_event', 'device_device', 'cross_sensor')),
  constraint vec_similarity_pairs_order_chk check (left_embedding_id < right_embedding_id),
  constraint vec_similarity_pairs_distance_chk check (cosine_distance >= 0),
  constraint vec_similarity_pairs_similarity_chk check (cosine_similarity <= 1),
  constraint vec_similarity_pairs_unique unique (pair_kind, embedding_model, embedding_kind, left_embedding_id, right_embedding_id)
);

create index if not exists vec_similarity_pairs_kind_idx
  on vec_similarity_pairs (pair_kind, embedding_model, embedding_kind, cosine_similarity desc);
create index if not exists vec_similarity_pairs_left_source_idx
  on vec_similarity_pairs (left_source_table, left_source_key);
create index if not exists vec_similarity_pairs_right_source_idx
  on vec_similarity_pairs (right_source_table, right_source_key);
create index if not exists vec_similarity_pairs_mac_idx
  on vec_similarity_pairs (left_source_mac, right_source_mac, computed_at desc);

create table if not exists vec_embedding_jobs (
  job_id bigserial primary key,
  source_table text not null,
  source_key text not null,
  embedding_model text not null,
  embedding_kind text not null,
  status text not null default 'pending',
  priority integer not null default 100,
  attempts integer not null default 0,
  max_attempts integer not null default 5,
  lease_token text,
  leased_at timestamptz,
  locked_by text,
  due_at timestamptz not null default now(),
  content_sha256 text,
  last_error text,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vec_embedding_jobs_kind_chk check (embedding_kind in ('event', 'device', 'behaviour_window')),
  constraint vec_embedding_jobs_status_chk check (status in ('pending', 'leased', 'completed', 'failed')),
  constraint vec_embedding_jobs_attempts_chk check (attempts >= 0 and max_attempts > 0),
  constraint vec_embedding_jobs_source_unique unique (source_table, source_key, embedding_model, embedding_kind)
);

create index if not exists vec_embedding_jobs_pending_idx
  on vec_embedding_jobs (priority, due_at, job_id)
  where status in ('pending', 'failed');
create index if not exists vec_embedding_jobs_lease_idx
  on vec_embedding_jobs (leased_at)
  where status = 'leased';

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
      coalesce(retry, false) as retry,
      coalesce(protected, false) as protected,
      coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid') as bssid,
      coalesce(wps_device_name, payload->>'wps_device_name') as wps_device_name,
      coalesce(wps_manufacturer, payload->>'wps_manufacturer') as wps_manufacturer,
      coalesce(wps_model_name, payload->>'wps_model_name') as wps_model_name,
      coalesce(device_fingerprint, payload->>'device_fingerprint') as device_fingerprint
    from sync_scan_ingest
    where stream_name = 'wireless.audit'
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
        'retry_ratio', case when r.event_count = 0 then 0 else round((r.retry_count::numeric / r.event_count::numeric), 4) end
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
        'unique_bssid_count: ' || r.unique_bssid_count::text
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
        'unique_bssid_count: ' || r.unique_bssid_count::text
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
  )
  insert into vec_behaviour_snapshots (
    snapshot_key, source_mac, location_id, sensor_id, window_start, window_end,
    event_count, protocol_mix, frame_type_distribution, signal_min_dbm, signal_max_dbm,
    signal_avg_dbm, retry_count, protected_count, unprotected_count, unique_bssid_count,
    mac_rotation_indicators, text_summary, embedding_text, created_at, updated_at
  )
  select
    snapshot_key, source_mac, location_id, sensor_id, window_start, window_end,
    event_count, protocol_mix, frame_type_distribution, signal_min_dbm, signal_max_dbm,
    signal_avg_dbm, retry_count, protected_count, unprotected_count, unique_bssid_count,
    mac_rotation_indicators, text_summary, embedding_text, now(), now()
  from prepared
  on conflict (snapshot_key) do update set
    sensor_id = excluded.sensor_id,
    event_count = excluded.event_count,
    protocol_mix = excluded.protocol_mix,
    frame_type_distribution = excluded.frame_type_distribution,
    signal_min_dbm = excluded.signal_min_dbm,
    signal_max_dbm = excluded.signal_max_dbm,
    signal_avg_dbm = excluded.signal_avg_dbm,
    retry_count = excluded.retry_count,
    protected_count = excluded.protected_count,
    unprotected_count = excluded.unprotected_count,
    unique_bssid_count = excluded.unique_bssid_count,
    mac_rotation_indicators = excluded.mac_rotation_indicators,
    text_summary = excluded.text_summary,
    embedding_text = excluded.embedding_text,
    updated_at = now();

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

create or replace function vec_enqueue_embedding_jobs(
  p_model text default 'nomic-embed-text-v2-moe'
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  with cursor_state as (
    select coalesce(
      (select cursor_value::timestamptz
         from sync_cursor
        where stream_name = 'vec_embeddings.sync_scan_ingest.wireless.audit'),
      timestamptz '1970-01-01 00:00:00+00'
    ) as last_cursor
  ),
  event_jobs as (
    select
      'sync_scan_ingest'::text as source_table,
      dedupe_key::text as source_key,
      p_model as embedding_model,
      'event'::text as embedding_kind,
      10 as priority
    from sync_scan_ingest source
    cross join cursor_state cursor_state
    left join vec_embeddings existing
      on existing.source_table = 'sync_scan_ingest'
     and existing.source_key = source.dedupe_key
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'event'
    where stream_name = 'wireless.audit'
      and (
        existing.embedding_id is null
        or source.updated_at > existing.embedded_at
        or (
          source.status = 'batched'
          and source.updated_at > cursor_state.last_cursor
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
    left join vec_embeddings existing
      on existing.source_table = 'devices'
     and existing.source_key = source.mac_id
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'device'
    where existing.embedding_id is null
       or source.last_seen > existing.embedded_at
  ),
  behaviour_jobs as (
    select
      'vec_behaviour_snapshots'::text as source_table,
      snapshot_id::text as source_key,
      p_model as embedding_model,
      'behaviour_window'::text as embedding_kind,
      20 as priority
    from vec_behaviour_snapshots source
    left join vec_embeddings existing
      on existing.source_table = 'vec_behaviour_snapshots'
     and existing.source_key = source.snapshot_id::text
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'behaviour_window'
    where existing.embedding_id is null
       or source.updated_at > existing.embedded_at
  ),
  inserted as (
    insert into vec_embedding_jobs (
      source_table, source_key, embedding_model, embedding_kind, priority, status, due_at, created_at, updated_at
    )
    select source_table, source_key, embedding_model, embedding_kind, priority, 'pending', now(), now(), now()
    from (
      select * from event_jobs
      union all
      select * from device_jobs
      union all
      select * from behaviour_jobs
    ) jobs
    on conflict (source_table, source_key, embedding_model, embedding_kind) do update set
      status = 'pending',
      due_at = least(vec_embedding_jobs.due_at, now()),
      priority = least(vec_embedding_jobs.priority, excluded.priority),
      completed_at = null,
      content_sha256 = null,
      updated_at = now()
    where vec_embedding_jobs.status = 'completed'
    returning 1
  )
  select count(*) into v_count from inserted;

  insert into sync_cursor (stream_name, cursor_value, updated_at)
  select
    'vec_embeddings.sync_scan_ingest.wireless.audit',
    coalesce(max(updated_at)::text, now()::text),
    now()
  from sync_scan_ingest
  where stream_name = 'wireless.audit'
  on conflict (stream_name) do update set
    cursor_value = greatest(sync_cursor.cursor_value::timestamptz, excluded.cursor_value::timestamptz)::text,
    updated_at = now();

  return v_count;
end;
$$;

create or replace function vec_lease_embedding_jobs(
  p_limit integer default 25,
  p_worker_name text default 'vector-worker',
  p_lease interval default interval '5 minutes'
)
returns setof vec_embedding_jobs
language plpgsql
as $$
begin
  return query
  with selected as (
    select job_id
    from vec_embedding_jobs
    where (
        status in ('pending', 'failed')
        or (status = 'leased' and leased_at < now() - p_lease)
      )
      and attempts < max_attempts
      and due_at <= now()
    order by priority asc, due_at asc, job_id asc
    for update skip locked
    limit greatest(p_limit, 1)
  )
  update vec_embedding_jobs job
     set status = 'leased',
         attempts = job.attempts + 1,
         lease_token = md5(random()::text || clock_timestamp()::text || job.job_id::text),
         leased_at = now(),
         locked_by = p_worker_name,
         last_error = null,
         updated_at = now()
    from selected
   where job.job_id = selected.job_id
  returning job.*;
end;
$$;

create or replace function vec_materialize_similarity_pairs(
  p_model text default 'nomic-embed-text-v2-moe',
  p_top_k integer default 10,
  p_event_dup_distance_threshold double precision default 0.05,
  p_behaviour_similarity_threshold double precision default 0.92
)
returns integer
language plpgsql
as $$
declare
  v_total integer := 0;
  v_count integer := 0;
begin
  with candidates as (
    select
      least(e1.embedding_id, neighbor.embedding_id) as left_embedding_id,
      greatest(e1.embedding_id, neighbor.embedding_id) as right_embedding_id,
      min(neighbor.cosine_distance) as cosine_distance
    from vec_embeddings e1
    join lateral (
      select
        e2.embedding_id,
        (e2.embedding::vector(768) <=> e1.embedding::vector(768)) as cosine_distance
      from vec_embeddings e2
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
      and neighbor.cosine_distance <= p_event_dup_distance_threshold
    group by least(e1.embedding_id, neighbor.embedding_id), greatest(e1.embedding_id, neighbor.embedding_id)
  )
  insert into vec_similarity_pairs (
    pair_kind, embedding_model, embedding_kind,
    left_embedding_id, right_embedding_id,
    left_source_table, left_source_key, left_source_mac, left_sensor_id, left_location_id, left_observed_at,
    right_source_table, right_source_key, right_source_mac, right_sensor_id, right_location_id, right_observed_at,
    cosine_distance, cosine_similarity, rank, evidence, computed_at, created_at, updated_at
  )
  select
    'event_event', p_model, 'event',
    candidates.left_embedding_id, candidates.right_embedding_id,
    left_e.source_table, left_e.source_key, left_e.source_mac, left_e.source_sensor_id, left_e.source_location_id, left_e.source_observed_at,
    right_e.source_table, right_e.source_key, right_e.source_mac, right_e.source_sensor_id, right_e.source_location_id, right_e.source_observed_at,
    candidates.cosine_distance,
    1 - candidates.cosine_distance,
    1,
    jsonb_build_object('threshold', p_event_dup_distance_threshold, 'detector', 'near_duplicate_event'),
    now(), now(), now()
  from candidates
  join vec_embeddings left_e on left_e.embedding_id = candidates.left_embedding_id
  join vec_embeddings right_e on right_e.embedding_id = candidates.right_embedding_id
  on conflict (pair_kind, embedding_model, embedding_kind, left_embedding_id, right_embedding_id) do update set
    cosine_distance = excluded.cosine_distance,
    cosine_similarity = excluded.cosine_similarity,
    evidence = excluded.evidence,
    computed_at = now(),
    updated_at = now();

  get diagnostics v_count = row_count;
  v_total := v_total + v_count;

  with candidates as (
    select
      least(e1.embedding_id, neighbor.embedding_id) as left_embedding_id,
      greatest(e1.embedding_id, neighbor.embedding_id) as right_embedding_id,
      min(neighbor.cosine_distance) as cosine_distance
    from vec_embeddings e1
    join lateral (
      select
        e2.embedding_id,
        (e2.embedding::vector(768) <=> e1.embedding::vector(768)) as cosine_distance
      from vec_embeddings e2
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
      and neighbor.cosine_distance <= greatest(p_event_dup_distance_threshold * 3, p_event_dup_distance_threshold)
    group by least(e1.embedding_id, neighbor.embedding_id), greatest(e1.embedding_id, neighbor.embedding_id)
  )
  insert into vec_similarity_pairs (
    pair_kind, embedding_model, embedding_kind,
    left_embedding_id, right_embedding_id,
    left_source_table, left_source_key, left_source_mac, left_sensor_id, left_location_id, left_observed_at,
    right_source_table, right_source_key, right_source_mac, right_sensor_id, right_location_id, right_observed_at,
    cosine_distance, cosine_similarity, rank, evidence, computed_at, created_at, updated_at
  )
  select
    'cross_sensor', p_model, 'event',
    candidates.left_embedding_id, candidates.right_embedding_id,
    left_e.source_table, left_e.source_key, left_e.source_mac, left_e.source_sensor_id, left_e.source_location_id, left_e.source_observed_at,
    right_e.source_table, right_e.source_key, right_e.source_mac, right_e.source_sensor_id, right_e.source_location_id, right_e.source_observed_at,
    candidates.cosine_distance,
    1 - candidates.cosine_distance,
    1,
    jsonb_build_object('detector', 'cross_sensor_event_cluster'),
    now(), now(), now()
  from candidates
  join vec_embeddings left_e on left_e.embedding_id = candidates.left_embedding_id
  join vec_embeddings right_e on right_e.embedding_id = candidates.right_embedding_id
  on conflict (pair_kind, embedding_model, embedding_kind, left_embedding_id, right_embedding_id) do update set
    cosine_distance = excluded.cosine_distance,
    cosine_similarity = excluded.cosine_similarity,
    evidence = excluded.evidence,
    computed_at = now(),
    updated_at = now();

  get diagnostics v_count = row_count;
  v_total := v_total + v_count;

  with candidates as (
    select
      least(e1.embedding_id, neighbor.embedding_id) as left_embedding_id,
      greatest(e1.embedding_id, neighbor.embedding_id) as right_embedding_id,
      min(neighbor.cosine_distance) as cosine_distance
    from vec_embeddings e1
    join vec_behaviour_snapshots s1 on s1.snapshot_id::text = e1.source_key
    join lateral (
      select
        e2.embedding_id,
        (e2.embedding::vector(768) <=> e1.embedding::vector(768)) as cosine_distance
      from vec_embeddings e2
      join vec_behaviour_snapshots s2 on s2.snapshot_id::text = e2.source_key
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
      and neighbor.cosine_distance <= (1 - p_behaviour_similarity_threshold)
    group by least(e1.embedding_id, neighbor.embedding_id), greatest(e1.embedding_id, neighbor.embedding_id)
  )
  insert into vec_similarity_pairs (
    pair_kind, embedding_model, embedding_kind,
    left_embedding_id, right_embedding_id,
    left_source_table, left_source_key, left_source_mac, left_sensor_id, left_location_id, left_observed_at,
    right_source_table, right_source_key, right_source_mac, right_sensor_id, right_location_id, right_observed_at,
    cosine_distance, cosine_similarity, rank, evidence, computed_at, created_at, updated_at
  )
  select
    'device_device', p_model, 'behaviour_window',
    candidates.left_embedding_id, candidates.right_embedding_id,
    left_e.source_table, left_e.source_key, left_e.source_mac, left_e.source_sensor_id, left_e.source_location_id, left_e.source_observed_at,
    right_e.source_table, right_e.source_key, right_e.source_mac, right_e.source_sensor_id, right_e.source_location_id, right_e.source_observed_at,
    candidates.cosine_distance,
    1 - candidates.cosine_distance,
    1,
    jsonb_build_object('threshold', p_behaviour_similarity_threshold, 'detector', 'mac_rotation_suspected'),
    now(), now(), now()
  from candidates
  join vec_embeddings left_e on left_e.embedding_id = candidates.left_embedding_id
  join vec_embeddings right_e on right_e.embedding_id = candidates.right_embedding_id
  on conflict (pair_kind, embedding_model, embedding_kind, left_embedding_id, right_embedding_id) do update set
    cosine_distance = excluded.cosine_distance,
    cosine_similarity = excluded.cosine_similarity,
    evidence = excluded.evidence,
    computed_at = now(),
    updated_at = now();

  get diagnostics v_count = row_count;
  v_total := v_total + v_count;

  update sync_scan_ingest target
     set dedupe_or_replay_suspect = true,
         updated_at = now()
   where target.dedupe_key in (
     select left_source_key
     from vec_similarity_pairs
     where pair_kind = 'event_event'
       and embedding_model = p_model
       and embedding_kind = 'event'
       and cosine_distance <= p_event_dup_distance_threshold
     union
     select right_source_key
     from vec_similarity_pairs
     where pair_kind = 'event_event'
       and embedding_model = p_model
       and embedding_kind = 'event'
       and cosine_distance <= p_event_dup_distance_threshold
   )
     and not coalesce(target.dedupe_or_replay_suspect, false);

  get diagnostics v_count = row_count;
  v_total := v_total + v_count;

  insert into shadow_it_alerts (
    source_mac, first_occurred_at, last_occurred_at, occurrence_count,
    destination_bssid, ssid, sensor_id, location_id, signal_dbm,
    reason, evidence, resolved_at, created_at, updated_at
  )
  select
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
  from vec_similarity_pairs pair
  join vec_behaviour_snapshots left_snapshot on left_snapshot.snapshot_id::text = pair.left_source_key
  join vec_behaviour_snapshots right_snapshot on right_snapshot.snapshot_id::text = pair.right_source_key
  where pair.pair_kind = 'device_device'
    and pair.embedding_model = p_model
    and pair.embedding_kind = 'behaviour_window'
    and pair.cosine_similarity >= p_behaviour_similarity_threshold
    and left_snapshot.source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
    and right_snapshot.source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
  on conflict (source_mac) do update set
    last_occurred_at = greatest(shadow_it_alerts.last_occurred_at, excluded.last_occurred_at),
    occurrence_count = coalesce(shadow_it_alerts.occurrence_count, 0) + excluded.occurrence_count,
    sensor_id = excluded.sensor_id,
    location_id = excluded.location_id,
    signal_dbm = excluded.signal_dbm,
    reason = excluded.reason,
    evidence = excluded.evidence,
    updated_at = now();

  get diagnostics v_count = row_count;
  v_total := v_total + v_count;

  return v_total;
end;
$$;

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
from vec_similarity_pairs pair
left join sync_scan_ingest left_event
  on pair.left_source_table = 'sync_scan_ingest'
 and left_event.dedupe_key = pair.left_source_key
left join sync_scan_ingest right_event
  on pair.right_source_table = 'sync_scan_ingest'
 and right_event.dedupe_key = pair.right_source_key
left join devices left_device
  on left_device.mac_id = pair.left_source_key
  or left_device.mac_id = lower(pair.left_source_mac)
left join devices right_device
  on right_device.mac_id = pair.right_source_key
  or right_device.mac_id = lower(pair.right_source_mac)
left join vec_behaviour_snapshots left_snapshot
  on pair.left_source_table = 'vec_behaviour_snapshots'
 and left_snapshot.snapshot_id::text = pair.left_source_key
left join vec_behaviour_snapshots right_snapshot
  on pair.right_source_table = 'vec_behaviour_snapshots'
 and right_snapshot.snapshot_id::text = pair.right_source_key;

create or replace function vec_install_cron_jobs()
returns void
language plpgsql
as $$
begin
  if to_regnamespace('cron') is null then
    raise exception 'pg_cron schema is unavailable';
  end if;

  perform cron.schedule(
    'vec-build-behaviour-snapshots',
    '*/5 * * * *',
    $cron$select vec_build_behaviour_snapshots();$cron$
  );

  perform cron.schedule(
    'vec-enqueue-embedding-jobs',
    '*/2 * * * *',
    $cron$select vec_enqueue_embedding_jobs();$cron$
  );

  perform cron.schedule(
    'vec-materialize-similarity-pairs',
    '*/5 * * * *',
    $cron$select vec_materialize_similarity_pairs();$cron$
  );
end;
$$;

select vec_install_cron_jobs();
-- vec similarity foundation end
