#!/bin/bash
# Apply identities table to running PostgreSQL coordinator database
# Usage: ./apply-identities.sh

set -e

POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-sync}"
POSTGRES_USER="${POSTGRES_USER:-sync}"

echo "Applying identities table to PostgreSQL at ${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"

psql \
  -h "$POSTGRES_HOST" \
  -p "$POSTGRES_PORT" \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 << 'SQL'

-- Create identities table with source_mac as PK
create table if not exists identities (
  source_mac_lower text primary key,
  source_mac text not null,
  ssid text,
  bssid text,
  destination_bssid text,
  signal_dbm integer,
  device_id text,
  display_name text,
  username text,
  hostname text,
  device_fingerprint text,
  wps_device_name text,
  wps_manufacturer text,
  wps_model_name text,
  observed_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint fk_identities_device_id foreign key (device_id) references devices(device_id) on delete set null
);

create index if not exists identities_observed_at_idx on identities (observed_at desc);
create index if not exists identities_device_id_idx on identities (device_id);
create index if not exists identities_username_idx on identities (username);
create index if not exists identities_ssid_idx on identities (ssid) where ssid is not null;

-- Backfill identities from wireless.audit events
-- For each unique source_mac, take the latest observation
insert into identities (
  source_mac_lower,
  source_mac,
  ssid,
  bssid,
  destination_bssid,
  signal_dbm,
  device_id,
  display_name,
  username,
  hostname,
  device_fingerprint,
  wps_device_name,
  wps_manufacturer,
  wps_model_name,
  observed_at,
  created_at,
  updated_at
)
with latest_per_mac as (
  select distinct on (lower(coalesce(source_mac, payload->>'source_mac')))
    lower(coalesce(source_mac, payload->>'source_mac')) as source_mac_lower,
    coalesce(source_mac, payload->>'source_mac') as source_mac,
    coalesce(ssid, payload->>'ssid') as ssid,
    coalesce(bssid, payload->>'bssid') as bssid,
    coalesce(destination_bssid, payload->>'destination_bssid', payload->>'bssid') as destination_bssid,
    signal_dbm,
    payload->>'username' as username,
    coalesce(payload->>'dhcp_hostname', dhcp_hostname) as hostname,
    device_fingerprint,
    wps_device_name,
    wps_manufacturer,
    wps_model_name,
    observed_at
  from sync_scan_ingest
  where stream_name = 'wireless.audit'
    and coalesce(source_mac, payload->>'source_mac') is not null
  order by lower(coalesce(source_mac, payload->>'source_mac')), observed_at desc
),
with_devices as (
  select
    lpm.source_mac_lower,
    lpm.source_mac,
    lpm.ssid,
    lpm.bssid,
    lpm.destination_bssid,
    lpm.signal_dbm,
    d.device_id,
    d.display_name,
    lpm.username,
    lpm.hostname,
    lpm.device_fingerprint,
    lpm.wps_device_name,
    lpm.wps_manufacturer,
    lpm.wps_model_name,
    lpm.observed_at
  from latest_per_mac lpm
  left join devices d
    on lower(d.mac_hint) = lpm.source_mac_lower
)
select
  source_mac_lower,
  source_mac,
  ssid,
  bssid,
  destination_bssid,
  signal_dbm,
  device_id,
  display_name,
  username,
  hostname,
  device_fingerprint,
  wps_device_name,
  wps_manufacturer,
  wps_model_name,
  observed_at,
  now(),
  now()
from with_devices
on conflict (source_mac_lower) do nothing;

-- Report results
do $$
declare
  v_identity_count integer;
  v_distinct_macs integer;
begin
  select count(*) into v_identity_count from identities;
  select count(distinct lower(coalesce(source_mac, payload->>'source_mac')))
    into v_distinct_macs
    from sync_scan_ingest
   where stream_name = 'wireless.audit'
     and coalesce(source_mac, payload->>'source_mac') is not null;

  raise notice 'Identities table has % records from % distinct source_macs', v_identity_count, v_distinct_macs;
end $$;

-- Create/replace trigger function
create or replace function sync_update_identities()
returns trigger
language plpgsql
as $$
declare
  v_source_mac_lower text;
  v_device_id text;
  v_display_name text;
begin
  if new.stream_name != 'wireless.audit' then
    return new;
  end if;

  v_source_mac_lower := lower(coalesce(new.source_mac, new.payload->>'source_mac'));
  if v_source_mac_lower is null then
    return new;
  end if;

  select device_id, display_name
    into v_device_id, v_display_name
    from devices d
   where lower(d.mac_hint) = v_source_mac_lower
   limit 1;

  insert into identities (
    source_mac_lower,
    source_mac,
    ssid,
    bssid,
    destination_bssid,
    signal_dbm,
    device_id,
    display_name,
    username,
    hostname,
    device_fingerprint,
    wps_device_name,
    wps_manufacturer,
    wps_model_name,
    observed_at,
    created_at,
    updated_at
  ) values (
    v_source_mac_lower,
    coalesce(new.source_mac, new.payload->>'source_mac'),
    coalesce(new.ssid, new.payload->>'ssid'),
    coalesce(new.bssid, new.payload->>'bssid'),
    coalesce(new.destination_bssid, new.payload->>'destination_bssid', new.payload->>'bssid'),
    new.signal_dbm,
    v_device_id,
    v_display_name,
    new.payload->>'username',
    coalesce(new.payload->>'dhcp_hostname', new.dhcp_hostname),
    new.device_fingerprint,
    new.wps_device_name,
    new.wps_manufacturer,
    new.wps_model_name,
    new.observed_at,
    now(),
    now()
  )
  on conflict (source_mac_lower) do update set
    source_mac = excluded.source_mac,
    ssid = coalesce(excluded.ssid, identities.ssid),
    bssid = coalesce(excluded.bssid, identities.bssid),
    destination_bssid = coalesce(excluded.destination_bssid, identities.destination_bssid),
    signal_dbm = coalesce(excluded.signal_dbm, identities.signal_dbm),
    device_id = coalesce(excluded.device_id, identities.device_id),
    display_name = coalesce(excluded.display_name, identities.display_name),
    username = coalesce(excluded.username, identities.username),
    hostname = coalesce(excluded.hostname, identities.hostname),
    device_fingerprint = coalesce(excluded.device_fingerprint, identities.device_fingerprint),
    wps_device_name = coalesce(excluded.wps_device_name, identities.wps_device_name),
    wps_manufacturer = coalesce(excluded.wps_manufacturer, identities.wps_manufacturer),
    wps_model_name = coalesce(excluded.wps_model_name, identities.wps_model_name),
    observed_at = greatest(identities.observed_at, excluded.observed_at),
    updated_at = now();

  return new;
end;
$$;

-- Drop existing trigger if it exists
drop trigger if exists trg_sync_scan_ingest_identities on sync_scan_ingest;

-- Create trigger
create trigger trg_sync_scan_ingest_identities
  after insert on sync_scan_ingest
  for each row
  execute function sync_update_identities();

\echo 'Identities table, trigger, and backfill complete!'

SQL

echo "✅ Done!"
