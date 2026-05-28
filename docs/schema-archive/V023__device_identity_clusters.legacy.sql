-- V023: Add device_identity_clusters table and vec_assign_device_cluster() function
--
-- Track 2: MAC-rotated devices tracked as a single identity cluster.
-- Multiple devices (different mac_ids) that belong to the same physical
-- device are grouped into one cluster. The mac_ids array stores all
-- associated MACs, and size is a denormalized count for fast querying.

create table if not exists device_identity_clusters (
  cluster_id    bigserial primary key,
  cluster_name  text,                        -- optional human-readable label
  mac_ids       text[] not null default '{}', -- array of associated mac_ids
  size          integer not null default 1,   -- number of MACs in the cluster
  first_seen    timestamptz not null default now(),
  last_seen     timestamptz not null default now(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- GIN index for fast membership lookups via ANY(mac_ids)
create index if not exists idx_device_identity_clusters_mac_ids
  on device_identity_clusters using gin (mac_ids);

-- Function to assign or find a cluster for a given MAC.
-- Returns the cluster_id the MAC belongs to (creating one if needed).
-- Uses rotation indicators from vec_behaviour_snapshots to identify
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
    from vec_behaviour_snapshots lb
    where lb.source_mac = p_mac_id
      and lb.window_start > now() - interval '24 hours'
      and lb.mac_rotation_indicators is not null
      and lb.mac_rotation_indicators != '{}'::jsonb
    intersect
    select distinct rb.source_mac
    from vec_behaviour_snapshots rb
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
    set mac_ids = array_append(
          array(select distinct unnest(mac_ids || array[p_mac_id])),
          p_mac_id
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

comment on function vec_assign_device_cluster is
  'Assigns or finds a device identity cluster for a given MAC address. Uses rotation indicators from vec_behaviour_snapshots to identify related MACs belonging to the same physical device.';