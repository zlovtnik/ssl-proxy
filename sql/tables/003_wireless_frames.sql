-- object: wireless_frames
-- folder: tables
-- depends_on: sync_events
create table if not exists wireless_frames (
  dedupe_key text primary key references sync_events(dedupe_key) on delete cascade,
  sensor_id text,
  location_id text,
  username text,
  event_type text,
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
  signal_dbm integer,
  noise_dbm integer,
  frequency_mhz integer,
  channel_flags integer,
  data_rate_kbps integer,
  antenna_id integer,
  tsft bigint,
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
  risk_score double precision,
  identity_source text,
  tags jsonb not null default '[]'::jsonb,
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

alter table wireless_frames add column if not exists frame_subtype text;

alter table wireless_frames add column if not exists event_type text;
alter table wireless_frames add column if not exists transmitter_mac text;
alter table wireless_frames add column if not exists receiver_mac text;
alter table wireless_frames add column if not exists noise_dbm integer;
alter table wireless_frames add column if not exists frequency_mhz integer;
alter table wireless_frames add column if not exists channel_flags integer;
alter table wireless_frames add column if not exists data_rate_kbps integer;
alter table wireless_frames add column if not exists antenna_id integer;
alter table wireless_frames add column if not exists tsft bigint;
alter table wireless_frames add column if not exists risk_score double precision;
alter table wireless_frames add column if not exists identity_source text;
alter table wireless_frames add column if not exists tags jsonb not null default '[]'::jsonb;

alter table wireless_frames add column if not exists bssid_oui text
  generated always as (
    nullif(lower(substr(regexp_replace(coalesce(nullif(bssid, ''), nullif(destination_bssid, ''), ''), '[:\-]', '', 'g'), 1, 6)), '')
  ) stored;

update wireless_frames wf
set frame_subtype = coalesce(wf.frame_subtype, nullif(se.payload->>'frame_subtype', '')),
    event_type = coalesce(wf.event_type, nullif(coalesce(se.payload->>'event_type', se.payload->>'type'), '')),
    transmitter_mac = coalesce(wf.transmitter_mac, lower(nullif(se.payload->>'transmitter_mac', ''))),
    receiver_mac = coalesce(wf.receiver_mac, lower(nullif(se.payload->>'receiver_mac', ''))),
    noise_dbm = coalesce(wf.noise_dbm, case when se.payload->>'noise_dbm' ~ '^-?[0-9]+$' then (se.payload->>'noise_dbm')::integer end),
    frequency_mhz = coalesce(wf.frequency_mhz, case when se.payload->>'frequency_mhz' ~ '^-?[0-9]+$' then (se.payload->>'frequency_mhz')::integer end),
    channel_flags = coalesce(wf.channel_flags, case when se.payload->>'channel_flags' ~ '^-?[0-9]+$' then (se.payload->>'channel_flags')::integer end),
    data_rate_kbps = coalesce(wf.data_rate_kbps, case when se.payload->>'data_rate_kbps' ~ '^-?[0-9]+$' then (se.payload->>'data_rate_kbps')::integer end),
    antenna_id = coalesce(wf.antenna_id, case when se.payload->>'antenna_id' ~ '^-?[0-9]+$' then (se.payload->>'antenna_id')::integer end),
    tsft = coalesce(wf.tsft, case when se.payload->>'tsft' ~ '^-?[0-9]+$' then (se.payload->>'tsft')::bigint end),
    risk_score = coalesce(
      wf.risk_score,
      case
        when se.payload->>'risk_score' ~ '^-?([0-9]+(\.[0-9]+)?|\.[0-9]+)([eE][+-]?[0-9]+)?$'
        then (se.payload->>'risk_score')::double precision
      end
    ),
    identity_source = coalesce(wf.identity_source, nullif(se.payload->>'identity_source', '')),
    tags = case
      when wf.tags <> '[]'::jsonb then wf.tags
      when jsonb_typeof(se.payload->'tags') = 'array' then se.payload->'tags'
      else wf.tags
    end
from sync_events se
where se.dedupe_key = wf.dedupe_key
  and se.payload is not null
  and (
    wf.frame_subtype is null
    or wf.event_type is null
    or wf.transmitter_mac is null
    or wf.receiver_mac is null
    or wf.noise_dbm is null
    or wf.frequency_mhz is null
    or wf.channel_flags is null
    or wf.data_rate_kbps is null
    or wf.antenna_id is null
    or wf.tsft is null
    or wf.risk_score is null
    or wf.identity_source is null
    or wf.tags = '[]'::jsonb
  );
