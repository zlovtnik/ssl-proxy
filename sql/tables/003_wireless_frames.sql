-- object: wireless_frames
-- folder: tables
-- depends_on: sync_events
create table if not exists wireless_frames (
  dedupe_key text primary key references sync_events(dedupe_key) on delete cascade,
  sensor_id text,
  location_id text,
  username text,
  schema_version integer not null default 1,
  frame_type text,
  frame_subtype text,
  source_mac text,
  bssid text,
  destination_bssid text,
  bssid_oui text generated always as (
    nullif(lower(substr(regexp_replace(coalesce(bssid, destination_bssid, ''), '[:\-]', '', 'g'), 1, 6)), '')
  ) stored,
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

alter table wireless_frames add column if not exists frame_subtype text;

alter table wireless_frames add column if not exists bssid_oui text
  generated always as (
    nullif(lower(substr(regexp_replace(coalesce(bssid, destination_bssid, ''), '[:\-]', '', 'g'), 1, 6)), '')
  ) stored;

update wireless_frames wf
set frame_subtype = nullif(se.payload->>'frame_subtype', '')
from sync_events se
where se.dedupe_key = wf.dedupe_key
  and wf.frame_subtype is null
  and nullif(se.payload->>'frame_subtype', '') is not null;
