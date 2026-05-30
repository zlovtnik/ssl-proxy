-- object: vec_enqueue_embedding_jobs
-- folder: functions
-- depends_on: vec_embedding_jobs
create or replace function vec_enqueue_embedding_jobs(
  p_model text default 'nomic-embed-text-v2-moe'
)
returns integer
language plpgsql
as $$
declare
  v_count integer := 0;
begin
  if not vec_try_begin_job('vec_enqueue_embedding_jobs') then
    return 0;
  end if;

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
      and status = 'batched'
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
  frame_sequence_jobs as (
    select
      'vec_frame_sequences'::text as source_table,
      fs.session_key::text as source_key,
      p_model as embedding_model,
      'frame_sequence'::text as embedding_kind,
      18 as priority
    from vec_frame_sequences fs
    left join vec_embeddings existing
      on existing.source_table = 'vec_frame_sequences'
     and existing.source_key = fs.session_key
     and existing.embedding_model = p_model
     and existing.embedding_kind = 'frame_sequence'
    where existing.embedding_id is null
       or fs.updated_at > existing.embedded_at
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
      from (
        select source.dedupe_key
        from wireless_frames source
        join sync_events event on event.dedupe_key = source.dedupe_key
        where source.bssid is not null
          and lower(source.bssid) = bp.bssid
          and source.updated_at > bp.updated_at
          and event.status = 'batched'
        union
        select source.dedupe_key
        from wireless_frames source
        join sync_events event on event.dedupe_key = source.dedupe_key
        where source.destination_bssid is not null
          and lower(source.destination_bssid) = bp.bssid
          and source.updated_at > bp.updated_at
          and event.status = 'batched'
      ) source
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
      select * from frame_sequence_jobs
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
    and status = 'batched'
  on conflict (stream_name) do update set
    cursor_value = greatest(sync_cursors.cursor_value::timestamptz, excluded.cursor_value::timestamptz)::text,
    updated_at = now();

  perform vec_finish_job('vec_enqueue_embedding_jobs');
  return v_count;
exception when others then
  perform vec_finish_job('vec_enqueue_embedding_jobs');
  raise;
end;
$$;
