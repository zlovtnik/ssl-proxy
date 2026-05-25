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
    execute 'create extension if not exists pg_cron';
  exception when others then
    raise notice 'pg_cron extension unavailable; cron jobs will not be installed: %', sqlerrm;
  end;
end $$;

create schema if not exists coordinator;

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

create or replace function coordinator.safe_int(p_value text)
returns integer
language sql
immutable
as $$
  select case when p_value ~ '^-?[0-9]+$' then p_value::integer end
$$;

create or replace function coordinator.safe_bigint(p_value text)
returns bigint
language sql
immutable
as $$
  select case when p_value ~ '^-?[0-9]+$' then p_value::bigint end
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

create table if not exists sync_cursors (
  stream_name text primary key,
  cursor_value text not null,
  updated_at timestamptz not null default now()
);

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

create table if not exists wireless_frames (
  dedupe_key text primary key references sync_events(dedupe_key) on delete cascade,
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
  search_tsv tsvector generated always as (
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
  ) stored,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace view sync_events_expanded as
select
  e.dedupe_key,
  e.stream_name,
  e.observed_at,
  e.payload_ref,
  e.payload,
  e.payload_sha256,
  e.status,
  e.attempt_count,
  e.last_error,
  e.producer,
  e.event_kind,
  f.sensor_id,
  f.location_id,
  f.username,
  f.schema_version,
  f.frame_type,
  f.source_mac,
  f.bssid,
  f.destination_bssid,
  f.ssid,
  f.signal_dbm,
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
  f.wps_device_name,
  f.wps_manufacturer,
  f.wps_model_name,
  f.device_fingerprint,
  f.handshake_captured,
  f.search_tsv as wireless_search_tsv,
  e.created_at,
  greatest(e.updated_at, coalesce(f.updated_at, e.updated_at)) as updated_at
from sync_events e
left join wireless_frames f on f.dedupe_key = e.dedupe_key;

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

create table if not exists sync_errors (
  id bigserial primary key,
  job_id uuid references sync_jobs(job_id),
  batch_id uuid references sync_batches(batch_id),
  error_class text not null,
  error_text text not null,
  created_at timestamptz not null default now()
);

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

create index if not exists sync_events_status_idx on sync_events (status, observed_at);
create index if not exists sync_events_stream_idx on sync_events (stream_name, observed_at);
create index if not exists sync_events_ready_idx on sync_events (status, stream_name, observed_at) where status in ('pending', 'failed');
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
create index if not exists wireless_frames_ssid_idx on wireless_frames (ssid);
create index if not exists wireless_frames_source_mac_idx on wireless_frames (lower(source_mac));
create index if not exists wireless_frames_bssid_idx on wireless_frames (lower(bssid));
create index if not exists wireless_frames_destination_bssid_idx on wireless_frames (lower(destination_bssid));
create index if not exists wireless_frames_schema_version_idx on wireless_frames (schema_version);
create index if not exists wireless_frames_signal_idx on wireless_frames (signal_dbm) where signal_dbm is not null;
create index if not exists wireless_frames_src_ip_idx on wireless_frames (src_ip) where src_ip is not null;
create index if not exists wireless_frames_dst_ip_idx on wireless_frames (dst_ip) where dst_ip is not null;
create index if not exists wireless_frames_app_protocol_idx on wireless_frames (app_protocol) where app_protocol is not null;
create index if not exists wireless_frames_session_key_idx on wireless_frames (session_key) where session_key is not null;
create index if not exists wireless_frames_fingerprint_idx on wireless_frames (frame_fingerprint) where frame_fingerprint is not null;
create index if not exists wireless_frames_search_tsv_idx on wireless_frames using gin (search_tsv);
create index if not exists wireless_frames_common_search_idx on wireless_frames using gin ((
  lower(coalesce(sensor_id, '')) || ' ' || lower(coalesce(source_mac, '')) || ' ' || lower(coalesce(ssid, ''))
) gin_trgm_ops);
create index if not exists wireless_frames_device_fingerprint_idx on wireless_frames (device_fingerprint) where device_fingerprint is not null;
create index if not exists wireless_frames_security_flags_idx on wireless_frames (security_flags) where security_flags <> 0;
create index if not exists wireless_frames_handshake_captured_idx on wireless_frames (dedupe_key) where handshake_captured;

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
    dedupe_key, sensor_id, location_id, username, schema_version, frame_type,
    source_mac, bssid, destination_bssid, ssid, signal_dbm, fragment_number,
    channel_number, signal_status, adjacent_mac_hint, qos_tid, qos_eosp,
    qos_ack_policy, qos_ack_policy_label, qos_amsdu, llc_oui, ethertype,
    ethertype_name, src_ip, dst_ip, ip_ttl, ip_protocol, ip_protocol_name,
    src_port, dst_port, transport_protocol, transport_length, transport_checksum,
    app_protocol, ssdp_message_type, ssdp_st, ssdp_mx, ssdp_usn,
    dhcp_requested_ip, dhcp_hostname, dhcp_vendor_class, dns_query_name,
    mdns_name, session_key, retransmit_key, frame_fingerprint, payload_visibility,
    tsft_delta_us, wall_clock_delta_ms, large_frame, mixed_encryption,
    dedupe_or_replay_suspect, raw_len, frame_control_flags, more_data, retry,
    power_save, protected, security_flags, wps_device_name, wps_manufacturer,
    wps_model_name, device_fingerprint, handshake_captured, created_at, updated_at
  ) values (
    p_dedupe_key,
    nullif(p_payload->>'sensor_id', ''),
    nullif(p_payload->>'location_id', ''),
    nullif(p_payload->>'username', ''),
    coalesce(coordinator.safe_int(p_payload->>'schema_version'), 1),
    nullif(p_payload->>'frame_type', ''),
    lower(nullif(p_payload->>'source_mac', '')),
    lower(nullif(p_payload->>'bssid', '')),
    lower(nullif(coalesce(p_payload->>'destination_bssid', p_payload->>'destination_mac'), '')),
    nullif(p_payload->>'ssid', ''),
    coordinator.safe_int(p_payload->>'signal_dbm'),
    coordinator.safe_int(p_payload->>'fragment_number'),
    coordinator.safe_int(coalesce(p_payload->>'channel_number', p_payload->>'channel')),
    nullif(p_payload->>'signal_status', ''),
    lower(nullif(p_payload->>'adjacent_mac_hint', '')),
    coordinator.safe_int(p_payload->>'qos_tid'),
    coordinator.safe_bool(p_payload->>'qos_eosp'),
    coordinator.safe_int(p_payload->>'qos_ack_policy'),
    nullif(p_payload->>'qos_ack_policy_label', ''),
    coordinator.safe_bool(p_payload->>'qos_amsdu'),
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
    nullif(p_payload->>'app_protocol', ''),
    nullif(p_payload->>'ssdp_message_type', ''),
    nullif(p_payload->>'ssdp_st', ''),
    nullif(p_payload->>'ssdp_mx', ''),
    nullif(p_payload->>'ssdp_usn', ''),
    nullif(p_payload->>'dhcp_requested_ip', ''),
    nullif(p_payload->>'dhcp_hostname', ''),
    nullif(p_payload->>'dhcp_vendor_class', ''),
    nullif(p_payload->>'dns_query_name', ''),
    nullif(p_payload->>'mdns_name', ''),
    nullif(p_payload->>'session_key', ''),
    nullif(p_payload->>'retransmit_key', ''),
    nullif(p_payload->>'frame_fingerprint', ''),
    nullif(p_payload->>'payload_visibility', ''),
    coordinator.safe_bigint(p_payload->>'tsft_delta_us'),
    coordinator.safe_bigint(p_payload->>'wall_clock_delta_ms'),
    coalesce(coordinator.safe_bool(p_payload->>'large_frame'), false),
    coordinator.safe_bool(p_payload->>'mixed_encryption'),
    coalesce(coordinator.safe_bool(p_payload->>'dedupe_or_replay_suspect'), false),
    coalesce(coordinator.safe_int(p_payload->>'raw_len'), 0),
    coalesce(coordinator.safe_int(p_payload->>'frame_control_flags'), 0),
    coalesce(coordinator.safe_bool(p_payload->>'more_data'), false),
    coalesce(coordinator.safe_bool(p_payload->>'retry'), false),
    coalesce(coordinator.safe_bool(p_payload->>'power_save'), false),
    coalesce(coordinator.safe_bool(p_payload->>'protected'), false),
    coalesce(coordinator.safe_int(p_payload->>'security_flags'), 0),
    nullif(p_payload->>'wps_device_name', ''),
    nullif(p_payload->>'wps_manufacturer', ''),
    nullif(p_payload->>'wps_model_name', ''),
    nullif(p_payload->>'device_fingerprint', ''),
    coalesce(coordinator.safe_bool(p_payload->>'handshake_captured'), false),
    now(),
    now()
  )
  on conflict (dedupe_key) do update set
    sensor_id = excluded.sensor_id,
    location_id = excluded.location_id,
    username = excluded.username,
    schema_version = excluded.schema_version,
    frame_type = excluded.frame_type,
    source_mac = excluded.source_mac,
    bssid = excluded.bssid,
    destination_bssid = excluded.destination_bssid,
    ssid = excluded.ssid,
    signal_dbm = excluded.signal_dbm,
    fragment_number = excluded.fragment_number,
    channel_number = excluded.channel_number,
    signal_status = excluded.signal_status,
    adjacent_mac_hint = excluded.adjacent_mac_hint,
    qos_tid = excluded.qos_tid,
    qos_eosp = excluded.qos_eosp,
    qos_ack_policy = excluded.qos_ack_policy,
    qos_ack_policy_label = excluded.qos_ack_policy_label,
    qos_amsdu = excluded.qos_amsdu,
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
    app_protocol = excluded.app_protocol,
    ssdp_message_type = excluded.ssdp_message_type,
    ssdp_st = excluded.ssdp_st,
    ssdp_mx = excluded.ssdp_mx,
    ssdp_usn = excluded.ssdp_usn,
    dhcp_requested_ip = excluded.dhcp_requested_ip,
    dhcp_hostname = excluded.dhcp_hostname,
    dhcp_vendor_class = excluded.dhcp_vendor_class,
    dns_query_name = excluded.dns_query_name,
    mdns_name = excluded.mdns_name,
    session_key = excluded.session_key,
    retransmit_key = excluded.retransmit_key,
    frame_fingerprint = excluded.frame_fingerprint,
    payload_visibility = excluded.payload_visibility,
    tsft_delta_us = excluded.tsft_delta_us,
    wall_clock_delta_ms = excluded.wall_clock_delta_ms,
    large_frame = excluded.large_frame,
    mixed_encryption = excluded.mixed_encryption,
    raw_len = excluded.raw_len,
    frame_control_flags = excluded.frame_control_flags,
    more_data = excluded.more_data,
    retry = excluded.retry,
    power_save = excluded.power_save,
    protected = excluded.protected,
    security_flags = excluded.security_flags,
    wps_device_name = excluded.wps_device_name,
    wps_manufacturer = excluded.wps_manufacturer,
    wps_model_name = excluded.wps_model_name,
    device_fingerprint = excluded.device_fingerprint,
    handshake_captured = excluded.handshake_captured,
    updated_at = now();
end;
$$;
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
from sync_events_expanded ssi
left join devices d_src
  on lower(d_src.mac_hint) = lower(coalesce(ssi.source_mac, ssi.payload->>'source_mac'))
left join devices d_bssid
  on lower(d_bssid.mac_hint) = lower(coalesce(ssi.bssid, ssi.payload->>'bssid'))
where ssi.stream_name = 'wireless.audit';



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
from sync_events_expanded
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
-- vec similarity foundation begin
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
  constraint vec_embeddings_kind_chk check (embedding_kind in ('event', 'device', 'behaviour_window', 'baseline_profile', 'frame_sequence', 'infrastructure_subgraph')),
  constraint vec_embeddings_dimensions_chk check (embedding_dimensions > 0),
  constraint chk_embedding_dims_matches_embedding_dimensions check (vector_dims(embedding) = embedding_dimensions),
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

create index if not exists vec_embeddings_frame_sequence_hnsw_768_idx
  on vec_embeddings using hnsw ((embedding::vector(768)) vector_cosine_ops)
  where embedding_kind = 'frame_sequence'
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

create table if not exists vec_frame_sequences (
  session_key text primary key,
  source_mac text,
  location_id text,
  sensor_id text,
  window_start timestamptz not null,
  window_end timestamptz not null,
  sequence_tokens text not null,
  frame_count bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists vec_frame_sequences_sensor_idx
  on vec_frame_sequences (sensor_id, window_start desc);

create index if not exists vec_frame_sequences_location_idx
  on vec_frame_sequences (location_id, window_start desc);

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

create index if not exists vec_transition_model_prev_idx
  on vec_transition_model (prev_token, embedding_kind);

-- Update transition counts from ordered frame_subtype sequences in sync_events
-- over a rolling 24-hour window. Uses Laplace-smoothed bigrams.
create or replace function vec_update_transition_model()
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  with windowed as (
    select
      coalesce(frame_subtype, payload->>'frame_subtype') as frame_subtype,
      coalesce(session_key, payload->>'session_key') as session_key,
      observed_at
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= now() - interval '24 hours'
      and coalesce(session_key, payload->>'session_key') is not null
      and coalesce(frame_subtype, payload->>'frame_subtype') is not null
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
  return v_count;
end;
$$;

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

    v_log_prob := v_log_prob + log(2, v_prob);
  end loop;

  return v_log_prob;
end;
$$;

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

create index if not exists vec_infrastructure_graph_node_a_idx
  on vec_infrastructure_graph (node_a_type, node_a, edge_type, last_seen desc);

create index if not exists vec_infrastructure_graph_node_b_idx
  on vec_infrastructure_graph (node_b_type, node_b, edge_type, last_seen desc);

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
  return v_count;
end;
$$;

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

  -- Track 1: Degree spike
  with current_assoc as (
    select
      lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      observed_at
    from sync_events_expanded
    where stream_name = 'wireless.audit'
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
      lower(nullif(coalesce(ssid, payload->>'ssid'), '')) as ssid,
      array_agg(distinct lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), ''))) as bssids,
      array_agg(distinct substr(regexp_replace(lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')), '[:\-]', '', 'g'), 1, 6)) as vendor_ouis,
      count(distinct substr(regexp_replace(lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')), '[:\-]', '', 'g'), 1, 6)) as vendor_count
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(ssid, payload->>'ssid'), '') is not null
      and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
    group by lower(nullif(coalesce(ssid, payload->>'ssid'), ''))
    having count(distinct substr(regexp_replace(lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')), '[:\-]', '', 'g'), 1, 6)) >= 2
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

  -- Track 4: Sequence anomaly — flag sessions with log-prob < -15
  with session_sequences as (
    select
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      nullif(coalesce(session_key, payload->>'session_key'), '')       as session_key,
      string_agg(
        upper(regexp_replace(payload->>'frame_subtype', '-', '_', 'g')),
        ' ' order by observed_at
      ) as tokens
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(session_key, payload->>'session_key'), '') is not null
      and payload->>'frame_subtype' is not null
    group by
      nullif(coalesce(session_key, payload->>'session_key'), ''),
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), ''))
    having count(*) >= 3
  ),
  scored_sequences as (
    select
      session_key,
      source_mac,
      tokens,
      vec_score_sequence(regexp_split_to_array(tokens, E'\\s+')) as log_prob
    from session_sequences
  )
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'rogue_cluster'::text,
    ss.source_mac,
    greatest(abs(ss.log_prob)::double precision, 1.0),
    jsonb_build_object(
      'reason',      'sequence_anomaly',
      'session_key', ss.session_key,
      'log_prob',    ss.log_prob,
      'threshold',   -15
    )
  from scored_sequences ss
  where ss.log_prob < -15
    and not exists (
      select 1 from vec_alerts a
      where a.alert_type          = 'rogue_cluster'
        and a.source_mac is not distinct from ss.source_mac
        and a.created_at          > now() - interval '1 hour'
        and a.metadata->>'reason' = 'sequence_anomaly'
    );

  get diagnostics v_row_count = row_count;
  v_count := v_count + v_row_count;

  return v_count;
end;
$$;

-- Track 6.1: Composite AP risk score combining deauth, signal, typosquat,
-- vendor mismatch, and embedding outlier signals into a single score.
create or replace view v_ap_risk_score as
with deauth_scores as (
  select
    coalesce(source_mac, metadata->>'bssid') as bssid,
    score as deauth_score
  from vec_alerts
  where alert_type in ('rogue_cluster', 'deauth_flood')
    and created_at >= now() - interval '1 hour'
),
signal_anomaly_scores as (
  select
    coalesce(source_mac, metadata->>'bssid') as bssid,
    score as signal_anomaly_score
  from vec_alerts
  where alert_type in ('signal_anomaly', 'rogue_cluster')
    and metadata->>'reason' in ('signal_jump', 'channel_band_conflict')
    and created_at >= now() - interval '1 hour'
),
typosquat_scores as (
  select
    coalesce(source_mac, metadata->>'bssid') as bssid,
    score as typosquat_score
  from vec_alerts
  where alert_type = 'rogue_cluster'
    and metadata->>'reason' in ('ssid_typosquat', 'vendor_conflict', 'bssid_spoofing')
    and created_at >= now() - interval '1 hour'
),
vendor_mismatch_scores as (
  select
    lower(substr(regexp_replace(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '[:\-]', '', 'g'), 1, 6)) as bssid_oui,
    count(distinct lower(substr(regexp_replace(bssid, '[:\-]', '', 'g'), 1, 6)))::double precision as vendor_mismatch_score
  from sync_events_expanded
  where stream_name = 'wireless.audit'
    and observed_at >= now() - interval '1 hour'
    and nullif(coalesce(ssid, payload->>'ssid'), '') is not null
    and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
    and lower(substr(regexp_replace(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '[:\-]', '', 'g'), 1, 6)) is not null
  group by bssid_oui
),
embedding_outlier_scores as (
  select
    coalesce(p.left_source_mac, p.right_source_mac) as bssid,
    max(p.cosine_distance) as embedding_outlier_score
  from vec_similarity_pairs p
  where p.computed_at >= now() - interval '1 hour'
    and p.cosine_distance > 0.15
  group by coalesce(p.left_source_mac, p.right_source_mac)
),
all_bssids as (
  select distinct coalesce(source_mac, metadata->>'bssid') as bssid from vec_alerts
  union
  select distinct left_source_mac from vec_similarity_pairs where left_source_mac is not null
  union
  select distinct right_source_mac from vec_similarity_pairs where right_source_mac is not null
)
select
  a.bssid,
  coalesce(d.deauth_score, 0::double precision) as deauth_score,
  coalesce(s.signal_anomaly_score, 0::double precision) as signal_anomaly_score,
  coalesce(t.typosquat_score, 0::double precision) as typosquat_score,
  coalesce(v.vendor_mismatch_score, 0::double precision) as vendor_mismatch_score,
  coalesce(e.embedding_outlier_score, 0::double precision) as embedding_outlier_score,
  (coalesce(d.deauth_score, 0::double precision) * 0.25
   + coalesce(s.signal_anomaly_score, 0::double precision) * 0.20
   + coalesce(t.typosquat_score, 0::double precision) * 0.20
   + coalesce(v.vendor_mismatch_score, 0::double precision) * 0.15
   + coalesce(e.embedding_outlier_score, 0::double precision) * 0.20) as composite_risk
from all_bssids a
left join deauth_scores d on d.bssid = a.bssid
left join signal_anomaly_scores s on s.bssid = a.bssid
left join typosquat_scores t on t.bssid = a.bssid
left join vendor_mismatch_scores v on v.bssid_oui = lower(substr(regexp_replace(a.bssid, '[:\-]', '', 'g'), 1, 6))
left join embedding_outlier_scores e on e.bssid = a.bssid;

-- Materialized for 5-minute refresh alongside v_device_repetition_score
create materialized view if not exists mv_ap_risk_score as
select * from v_ap_risk_score;

create unique index if not exists idx_mv_ap_risk_score_bssid on mv_ap_risk_score (bssid);

-- Check for high-risk APs and insert alerts when composite_risk exceeds threshold
create or replace function check_high_risk_aps(p_threshold double precision default 0.75)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'high_risk_ap'::text,
    r.bssid,
    r.composite_risk,
    jsonb_build_object(
      'composite_risk', r.composite_risk,
      'deauth_score', r.deauth_score,
      'signal_anomaly_score', r.signal_anomaly_score,
      'typosquat_score', r.typosquat_score,
      'vendor_mismatch_score', r.vendor_mismatch_score,
      'embedding_outlier_score', r.embedding_outlier_score
    )
  from mv_ap_risk_score r
  where r.composite_risk > p_threshold
    and not exists (
      select 1 from vec_alerts a
      where a.alert_type = 'high_risk_ap'
        and a.source_mac is not distinct from r.bssid
        and a.created_at > now() - interval '1 hour'
    );

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

create or replace function vec_build_baseline_profiles(
  p_from timestamptz default now() - interval '2 hours',
  p_to timestamptz default now()
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  with prepared as (
    select
      session_key,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      nullif(coalesce(location_id, payload->>'location_id'), '') as location_id,
      nullif(coalesce(sensor_id, payload->>'sensor_id'), '') as sensor_id,
      min(observed_at) as window_start,
      max(observed_at) as window_end,
      string_agg(upper(regexp_replace(coalesce(frame_subtype, payload->>'frame_subtype'), '-', '_', 'g')), ' ' order by observed_at) as sequence_tokens,
      count(*)::bigint as frame_count
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(session_key, payload->>'session_key'), '') is not null
      and coalesce(frame_subtype, payload->>'frame_subtype') is not null
    group by nullif(coalesce(session_key, payload->>'session_key'), '')
  )
  insert into vec_frame_sequences (
    session_key,
    source_mac,
    location_id,
    sensor_id,
    window_start,
    window_end,
    sequence_tokens,
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
    frame_count = excluded.frame_count,
    updated_at = now();

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

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
  with base as (
    select
      lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
      observed_at,
      coalesce(signal_dbm,
        case when payload->>'signal_dbm' ~ '^-?[0-9]+$' then (payload->>'signal_dbm')::integer end
      ) as signal_dbm,
      coalesce(retry, false) as retry,
      coalesce(channel_number::text, payload->>'channel_number', payload->>'channel') as channel_number,
      frame_subtype,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac
    from sync_events_expanded
    where stream_name = 'wireless.audit'
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
  return v_count;
end;
$$;

create or replace view v_bssid_anomaly_score as
with current_base as (
  select
    lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
    coalesce(signal_dbm,
      case when payload->>'signal_dbm' ~ '^-?[0-9]+$' then (payload->>'signal_dbm')::integer end
    ) as signal_dbm,
    coalesce(retry, false) as retry,
    coalesce(channel_number::text, payload->>'channel_number', payload->>'channel') as channel_number,
    payload->>'frame_subtype' as frame_subtype,
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
  constraint vec_similarity_pairs_kind_chk check (pair_kind in ('event_event', 'device_device', 'cross_sensor', 'sequence_sequence')),
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
  constraint vec_embedding_jobs_kind_chk check (embedding_kind in ('event', 'device', 'behaviour_window', 'baseline_profile', 'frame_sequence', 'infrastructure_subgraph')),
  constraint vec_embedding_jobs_status_chk check (status in ('pending', 'leased', 'completed', 'failed')),
  constraint vec_embedding_jobs_attempts_chk check (attempts >= 0 and max_attempts > 0),
  constraint vec_embedding_jobs_source_unique unique (source_table, source_key, embedding_model, embedding_kind)
);

create index if not exists vec_embedding_jobs_pending_idx
  on vec_embedding_jobs (priority, due_at, job_id)
  where status in ('pending', 'failed')
    and attempts < max_attempts;
create index if not exists vec_embedding_jobs_lease_idx
  on vec_embedding_jobs (leased_at, priority, job_id)
  where status = 'leased'
    and attempts < max_attempts;
create index if not exists vec_embedding_jobs_completion_idx
  on vec_embedding_jobs (job_id, lease_token)
  where status in ('pending', 'leased', 'failed');

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
    from sync_events_expanded
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
         from sync_cursors
        where stream_name = 'vec_embeddings.sync_events.wireless.audit'),
      timestamptz '1970-01-01 00:00:00+00'
    ) as last_cursor
  ),
  event_jobs as (
    select
      'sync_events'::text as source_table,
      dedupe_key::text as source_key,
      p_model as embedding_model,
      'event'::text as embedding_kind,
      10 as priority
    from sync_events_expanded source
    cross join cursor_state cursor_state
    left join vec_embeddings existing
      on existing.source_table = 'sync_events'
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
  graph_jobs as (
    select
      'vec_infrastructure_graph'::text as source_table,
      source_key,
      p_model as embedding_model,
      'infrastructure_subgraph'::text as embedding_kind,
      15 as priority
    from (
      select distinct node_a as source_key
      from vec_infrastructure_graph
      where node_a_type = 'bssid'
      union
      select distinct node_b as source_key
      from vec_infrastructure_graph
      where node_b_type = 'bssid'
    ) keys
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
      from sync_events_expanded source
      where stream_name = 'wireless.audit'
        and lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) = bp.bssid
        and observed_at > bp.updated_at
    ) frames on true
    left join vec_embeddings existing
      on existing.source_table = 'vec_baseline_profiles'
     and existing.source_key = bp.bssid
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'baseline_profile'
    where frames.new_frame_count >= 50
      and (
        existing.embedding_id is null
        or bp.updated_at > existing.embedded_at
      )
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
      union all
      select * from baseline_jobs
      union all
      select * from graph_jobs
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

  insert into sync_cursors (stream_name, cursor_value, updated_at)
  select
    'vec_embeddings.sync_events.wireless.audit',
    coalesce(max(updated_at)::text, now()::text),
    now()
  from sync_events_expanded
  where stream_name = 'wireless.audit'
  on conflict (stream_name) do update set
    cursor_value = greatest(sync_cursors.cursor_value::timestamptz, excluded.cursor_value::timestamptz)::text,
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
declare
  v_limit integer := greatest(p_limit, 1);
  v_count integer;
  remaining_limit integer;
begin
  -- Branch A: pending & failed jobs that are due for retry.
  -- Uses pending_idx which pre-filters on status, attempts < max_attempts, due_at <= now().
  return query
  with selected as (
    select job_id
    from vec_embedding_jobs
    where status in ('pending', 'failed')
      and attempts < max_attempts
      and due_at <= now()
    order by priority asc, due_at asc, job_id asc
    for update skip locked
    limit v_limit
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

  get diagnostics v_count = row_count;
  if v_count >= v_limit then
    return;
  end if;

  remaining_limit := greatest(0, p_limit - v_count);
  if remaining_limit <= 0 then
    return;
  end if;

  -- Branch B: expired leases (worker died mid-batch).
  -- Uses lease_idx which pre-filters on status = 'leased' and attempts < max_attempts.
  return query
  with selected as (
    select job_id
    from vec_embedding_jobs
    where status = 'leased'
      and leased_at < now() - p_lease
      and attempts < max_attempts
      and due_at <= now()
    order by leased_at asc, priority asc, job_id asc
    for update skip locked
    limit remaining_limit
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

  insert into vec_embeddings (
    source_table, source_key, source_observed_at, source_stream_name,
    source_sensor_id, source_location_id, source_mac,
    embedding_model, embedding_kind, embedding_dimensions,
    content_sha256, content_text, embedding, metadata,
    embedded_at, created_at, updated_at
  )
  select
    r.source_table,
    r.source_key,
    r.source_observed_at,
    r.source_stream_name,
    r.source_sensor_id,
    r.source_location_id,
    r.source_mac,
    r.embedding_model,
    r.embedding_kind,
    r.embedding_dimensions,
    r.content_sha256,
    r.content_text,
    r.embedding::vector,
    coalesce(r.metadata, '{}'::jsonb),
    now(), now(), now()
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
  on conflict (source_table, source_key, embedding_model, embedding_kind)
  do update set
    source_observed_at = excluded.source_observed_at,
    source_stream_name = excluded.source_stream_name,
    source_sensor_id = excluded.source_sensor_id,
    source_location_id = excluded.source_location_id,
    source_mac = excluded.source_mac,
    embedding_dimensions = excluded.embedding_dimensions,
    content_sha256 = excluded.content_sha256,
    content_text = excluded.content_text,
    embedding = excluded.embedding,
    metadata = excluded.metadata,
    embedded_at = now(),
    updated_at = now();

  -- UPDATE jobs in job_id ASC order to enforce consistent lock ordering
  -- with vec_lease_embedding_jobs (which also orders by job_id ASC).
  -- This prevents deadlock cycles when both functions run concurrently.
  update vec_embedding_jobs j
     set status = 'completed',
         content_sha256 = r.content_sha256,
         completed_at = now(),
         lease_token = null,
         leased_at = null,
         locked_by = null,
         last_error = null,
         updated_at = now()
    from (
      select r.job_id, r.lease_token, r.content_sha256
        from jsonb_to_recordset(p_payload) as r(
          job_id bigint,
          lease_token text,
          content_sha256 text
        )
       order by r.job_id asc
    ) r
   where j.job_id = r.job_id
     and j.lease_token is not distinct from r.lease_token;

  get diagnostics v_count = row_count;
  return v_count;
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

  update wireless_frames target
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

  insert into wireless_shadow_alerts (
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
left join vec_behaviour_snapshots left_snapshot
  on pair.left_source_table = 'vec_behaviour_snapshots'
 and left_snapshot.snapshot_id::text = pair.left_source_key
left join vec_behaviour_snapshots right_snapshot
  on pair.right_source_table = 'vec_behaviour_snapshots'
 and right_snapshot.snapshot_id::text = pair.right_source_key;

-- Release jobs whose leases have expired (worker died mid-batch).
-- Uses a fixed default of 30 minutes matching VECTOR_EMBEDDING_LEASE_SECONDS=1800.
create or replace function vec_release_expired_leases(
  p_lease_interval interval default interval '30 minutes'
)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  update vec_embedding_jobs
     set status = 'pending',
         lease_token = null,
         leased_at = null,
         locked_by = null,
         due_at = now(),
         last_error = 'lease expired',
         updated_at = now()
   where status = 'leased'
     and leased_at < now() - p_lease_interval;

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

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
    'vec-build-baseline-profiles',
    '*/15 * * * *',
    $cron$select vec_build_baseline_profiles();$cron$
  );

  perform cron.schedule(
    'vec-build-infrastructure-graph',
    '*/5 * * * *',
    $cron$select vec_build_infrastructure_graph();$cron$
  );

  perform cron.schedule(
    'vec-detect-rogue-clusters',
    '*/5 * * * *',
    $cron$select vec_detect_rogue_clusters();$cron$
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

  perform cron.schedule(
    'vec-refresh-device-repetition-score',
    '*/5 * * * *',
    $cron$REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score;$cron$
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
    '*/15 * * * *',
    $cron$select vec_update_transition_model();$cron$
  );

  perform cron.schedule(
    'vec-refresh-ap-risk-score',
    '*/5 * * * *',
    $cron$REFRESH MATERIALIZED VIEW CONCURRENTLY mv_ap_risk_score; SELECT check_high_risk_aps();$cron$
  );
end;
$$;

-- vec similarity foundation end
-- V019: Create v_device_repetition_score view
--
-- Provides a queryable surface for near-duplicate detection in vec_similarity_pairs.
-- Since a pair has a left and right side, we union both sides to count how many
-- times a device appears as a near-duplicate participant.

CREATE MATERIALIZED VIEW IF NOT EXISTS v_device_repetition_score AS
WITH device_pairs AS (
    -- Left side: device is the left member of the pair
    SELECT
        p.left_source_mac AS source_mac,
        p.cosine_distance,
        p.left_embedding_id AS embedding_id,
        p.computed_at
    FROM vec_similarity_pairs p
    WHERE p.pair_kind = 'event_event'
      AND p.cosine_distance < 0.05
      AND p.left_source_mac IS NOT NULL

    UNION ALL

    -- Right side: device is the right member of the pair
    SELECT
        p.right_source_mac AS source_mac,
        p.cosine_distance,
        p.right_embedding_id AS embedding_id,
        p.computed_at
    FROM vec_similarity_pairs p
    WHERE p.pair_kind = 'event_event'
      AND p.cosine_distance < 0.05
      AND p.right_source_mac IS NOT NULL
)
SELECT
    source_mac,
    COUNT(*) AS near_duplicate_pairs,
    MIN(cosine_distance) AS min_distance,
    AVG(cosine_distance) AS avg_distance,
    COUNT(DISTINCT embedding_id) AS unique_events_implicated
FROM device_pairs
WHERE computed_at >= NOW() - INTERVAL '24 hours'
GROUP BY source_mac
ORDER BY near_duplicate_pairs DESC;

COMMENT ON MATERIALIZED VIEW v_device_repetition_score IS
  'Daily device repetition scores from near-duplicate event_event pairs in vec_similarity_pairs (cosine_distance < 0.05). Refresh with REFRESH MATERIALIZED VIEW CONCURRENTLY.';

CREATE UNIQUE INDEX IF NOT EXISTS idx_v_device_repetition_score_mac
  ON v_device_repetition_score (source_mac);
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
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_type_created
    ON vec_alerts (alert_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_mac
    ON vec_alerts (source_mac);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_created
    ON vec_alerts (created_at DESC);

COMMENT ON TABLE vec_alerts IS
  'Actionable alerts generated from embedding analysis (near-duplicate, behaviour anomaly, etc.).';
-- V021: Add vec_reembed_changed_jobs() function for re-queuing
--
-- After the text builder changes in Phase 3 (noise filtering, ssid reordering,
-- WPS name normalization), existing embeddings may have different content_sha256
-- values. This function identifies rows whose content_text digest no longer
-- matches the stored content_sha256 and re-queues them as pending embedding jobs.
--
-- Usage:
--   SELECT vec_reembed_changed_jobs(p_limit => 1000);
--   -- Returns number of jobs re-queued

CREATE OR REPLACE FUNCTION vec_reembed_changed_jobs(
    p_limit INTEGER DEFAULT 1000
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER := 0;
    v_job_id BIGINT;
BEGIN
    -- Insert new embedding jobs for rows where content_text would produce
    -- a different digest than the stored content_sha256.
    --
    -- We use sha256(content_text) as the expected digest. If it doesn't match
    -- the stored content_sha256, the text builder would produce different text
    -- and therefore a different embedding.
    INSERT INTO vec_embedding_jobs (
        source_table,
        source_key,
        embedding_model,
        embedding_kind,
        status,
        priority,
        max_attempts,
        due_at,
        created_at,
        updated_at
    )
    SELECT
        e.source_table,
        e.source_key,
        e.embedding_model,
        e.embedding_kind,
        'pending',
        0,   -- normal priority for re-embed
        3,   -- max 3 attempts
        NOW(),
        NOW(),
        NOW()
    FROM vec_embeddings e
    WHERE e.content_sha256 IS DISTINCT FROM encode(
        digest(e.content_text, 'sha256'), 'hex'
    )
    AND NOT EXISTS (
        -- Avoid re-queuing jobs that are already pending/leased
        SELECT 1 FROM vec_embedding_jobs j
        WHERE j.source_table = e.source_table
          AND j.source_key = e.source_key
          AND j.embedding_model = e.embedding_model
          AND j.embedding_kind = e.embedding_kind
          AND j.status IN ('pending', 'leased')
    )
    ORDER BY e.embedded_at ASC
    LIMIT p_limit;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

COMMENT ON FUNCTION vec_reembed_changed_jobs IS
  'Re-queues embedding jobs for existing rows where content_sha256 no longer matches the SHA-256 of content_text. Typically invoked after text builder changes to force re-embedding of affected rows.';
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
  valid as (
    select incoming.*
      from incoming
      join configured_streams on configured_streams.stream_name = incoming.stream_name
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
           observed_at_text::timestamptz,
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
  where raw.request->>'stream_name' = 'wireless.audit';

  return coalesce(v_recorded_count, 0);
end;
$$;

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

  insert into sync_cursors (stream_name, cursor_value, updated_at)
  select distinct on (stream_name)
         stream_name,
         extract(epoch from observed_at)::bigint::text,
         now()
    from sync_events
   where dedupe_key = any(v_processed_dedupe_keys)
   order by stream_name, observed_at desc
  on conflict (stream_name)
  do update set cursor_value = excluded.cursor_value, updated_at = now();

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

  return v_marked_count + v_recovered_count + v_batched_count;
end;
$$;

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
    select batch.batch_id
      from sync_batches batch
      join sync_jobs job on job.job_id = batch.job_id
     where batch.status = 'pending'
       and job.stream_name in (
             select btrim(configured.stream_name)
               from unnest(p_oracle_stream_names) as configured(stream_name)
              where btrim(configured.stream_name) <> ''
           )
     order by batch.batch_id
     limit 1
     for update skip locked
  ),
  updated as (
    update sync_batches batch
       set status = 'dispatched',
           attempt_count = batch.attempt_count + 1,
           last_error = null,
           updated_at = now()
      from picked
     where batch.batch_id = picked.batch_id
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

create or replace function coordinator.generate_shadow_alerts()
returns setof jsonb
language sql
as $$
  with wireless as (
    select
      observed_at,
      lower(source_mac) as source_mac,
      lower(coalesce(destination_bssid, bssid)) as destination_bssid,
      ssid,
      signal_dbm,
      payload->>'sensor_id' as sensor_id,
      payload->>'location_id' as location_id
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= now() - interval '60 seconds'
      and source_mac is not null
      and lower(source_mac) ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
      and signal_dbm >= -50
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

create or replace function coordinator.save_backlog_entry(p_payload jsonb)
returns void
language plpgsql
as $$
begin
  if nullif(p_payload->>'dedupe_key', '') is null then
    raise exception 'coordinator.save_backlog_entry requires dedupe_key';
  end if;

  insert into sync_backlog (dedupe_key, stream_name, payload, status, attempt_count, created_at, updated_at)
  values (
    p_payload->>'dedupe_key',
    p_payload->>'stream_name',
    p_payload->'payload',
    'pending',
    0,
    now(),
    now()
  )
  on conflict (dedupe_key) do update
    set payload = excluded.payload,
        status = 'pending',
        updated_at = now();
end;
$$;

create or replace function coordinator.list_pending_backlog()
returns jsonb
language sql
as $$
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'dedupe_key', dedupe_key,
      'stream_name', stream_name,
      'payload', payload,
      'attempt_count', attempt_count,
      'created_at', created_at
    )
  ), '[]'::jsonb)
  from (
    select dedupe_key, stream_name, payload, attempt_count, created_at
    from sync_backlog
    where status = 'pending'
    order by created_at asc
    limit 100
  ) pending;
$$;

create or replace function coordinator.mark_backlog_synced(p_dedupe_key text)
returns void
language sql
as $$
  update sync_backlog
  set status = 'synced', updated_at = now()
  where dedupe_key = p_dedupe_key;
$$;

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

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform vec_install_cron_jobs();
  else
    raise notice 'pg_cron extension unavailable; skipping vec cron job installation';
  end if;
end $$;