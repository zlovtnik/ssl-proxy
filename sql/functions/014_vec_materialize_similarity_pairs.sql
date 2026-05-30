-- object: vec_materialize_similarity_pairs
-- folder: functions
-- depends_on: vec_similarity_pairs
drop function if exists vec_materialize_similarity_pairs(text, integer, double precision, double precision);

create or replace function vec_materialize_similarity_pairs(
  p_model text default 'nomic-embed-text-v2-moe',
  p_top_k integer default 10,
  p_event_dup_distance_threshold double precision default 0.05,
  p_behaviour_similarity_threshold double precision default 0.92,
  p_sequence_similarity_threshold double precision default 0.10
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
      and neighbor.cosine_distance <= p_sequence_similarity_threshold
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
    'sequence_sequence', p_model, 'frame_sequence',
    candidates.left_embedding_id, candidates.right_embedding_id,
    left_e.source_table, left_e.source_key, left_e.source_mac, left_e.source_sensor_id, left_e.source_location_id, left_e.source_observed_at,
    right_e.source_table, right_e.source_key, right_e.source_mac, right_e.source_sensor_id, right_e.source_location_id, right_e.source_observed_at,
    candidates.cosine_distance,
    1 - candidates.cosine_distance,
    1,
    jsonb_build_object('detector', 'similar_frame_sequence', 'threshold', p_sequence_similarity_threshold),
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
  from vec_similarity_pairs pair
  join vec_behaviour_snapshots left_snapshot on left_snapshot.snapshot_id::text = pair.left_source_key
  join vec_behaviour_snapshots right_snapshot on right_snapshot.snapshot_id::text = pair.right_source_key
  where pair.pair_kind = 'device_device'
    and pair.embedding_model = p_model
    and pair.embedding_kind = 'behaviour_window'
    and pair.cosine_similarity >= p_behaviour_similarity_threshold
    and left_snapshot.source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
    and right_snapshot.source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
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

  return v_total;
end;
$$;
