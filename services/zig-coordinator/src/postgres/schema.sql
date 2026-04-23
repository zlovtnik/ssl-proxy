\ir ../../schema/postgres.sql

create schema if not exists coordinator;

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
  insert into sync_cursor (stream_name, cursor_value, updated_at)
  values (p_stream_name, p_default_cursor, now())
  on conflict (stream_name) do nothing;

  select cursor_value
    into v_cursor
    from sync_cursor
   where stream_name = p_stream_name;

  return v_cursor;
end;
$$;

create or replace function coordinator.process_ingest_ledger(
  p_stream_names text[],
  p_max_attempts integer,
  p_backoff_secs integer
)
returns integer
language plpgsql
as $$
declare
  v_marked_count integer := 0;
  v_recovered_count integer := 0;
begin
  update sync_scan_ingest ingest
     set status = 'batched',
         updated_at = now()
   where status = 'processing'
     and exists (
       select 1
         from sync_batch batch
        where batch.dedupe_key = ingest.dedupe_key
     );
  get diagnostics v_marked_count = row_count;

  update sync_scan_ingest ingest
     set status = 'failed',
         updated_at = now(),
         last_error = coalesce(ingest.last_error, 'coordinator processing lease expired')
   where status = 'processing'
     and updated_at < now() - interval '5 minutes'
     and not exists (
       select 1
         from sync_batch batch
        where batch.dedupe_key = ingest.dedupe_key
     );
  get diagnostics v_recovered_count = row_count;

  with next_ingest as (
    update sync_scan_ingest
       set status = 'processing',
           attempt_count = attempt_count + 1,
           updated_at = now(),
           last_error = null
     where dedupe_key = (
       select dedupe_key
         from sync_scan_ingest
        where status in ('pending', 'failed')
          and stream_name = any(p_stream_names)
          and attempt_count < p_max_attempts
          and (
                status = 'pending'
                or observed_at <= now() - make_interval(secs => (greatest(attempt_count, 1) * p_backoff_secs))
              )
        order by observed_at asc
        limit 1
        for update skip locked
     )
    returning *
  ),
  job_upsert as (
    insert into sync_job (job_id, stream_name, status, attempt_count, created_at, started_at)
    select sync_stable_uuid(dedupe_key || ':job'),
           stream_name,
           'pending',
           0,
           now(),
           now()
      from next_ingest
    on conflict (job_id) do nothing
    returning job_id
  ),
  batch_upsert as (
    insert into sync_batch (
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
    select sync_stable_uuid(dedupe_key || ':batch'),
           sync_stable_uuid(dedupe_key || ':job'),
           0,
           payload_ref,
           'pending',
           1,
           payload_sha256,
           0,
           null,
           dedupe_key,
           coordinator.ensure_cursor(stream_name),
           extract(epoch from observed_at)::bigint::text
      from next_ingest
    on conflict (dedupe_key) do nothing
    returning dedupe_key
  ),
  cursor_upsert as (
    insert into sync_cursor (stream_name, cursor_value, updated_at)
    select stream_name, extract(epoch from observed_at)::bigint::text, now()
      from next_ingest
    on conflict (stream_name)
    do update set cursor_value = excluded.cursor_value, updated_at = now()
    returning stream_name
  ),
  mark_batched as (
    update sync_scan_ingest ingest
       set status = 'batched',
           updated_at = now()
      from batch_upsert
     where ingest.dedupe_key = batch_upsert.dedupe_key
    returning ingest.dedupe_key
  )
  select v_marked_count + v_recovered_count + count(*)
    into v_marked_count
    from mark_batched;

  return v_marked_count;
end;
$$;

create or replace function coordinator.get_next_batch()
returns jsonb
language plpgsql
as $$
declare
  v_payload jsonb;
begin
  with picked as (
    select batch.batch_id
      from sync_batch batch
     where batch.status = 'pending'
     order by batch.batch_id
     limit 1
     for update skip locked
  ),
  updated as (
    update sync_batch batch
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
    update sync_job job
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
    from sync_scan_ingest
    where stream_name = 'wireless.audit'
      and observed_at >= now() - interval '60 seconds'
      and source_mac is not null
      and signal_dbm >= -50
  ),
  candidates as (
    select distinct on (source_mac, destination_bssid, coalesce(location_id, ''))
      md5(
        source_mac || '|' ||
        coalesce(destination_bssid, '') || '|' ||
        coalesce(location_id, '') || '|' ||
        date_trunc('minute', observed_at)::text
      ) as dedupe_key,
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
        from authorized_wireless_networks awn
       where awn.enabled
         and (awn.location_id is null or awn.location_id = w.location_id)
         and (awn.ssid is null or (w.ssid is not null and lower(awn.ssid) = lower(w.ssid)))
         and (awn.bssid is null or (w.destination_bssid is not null and lower(awn.bssid) = w.destination_bssid))
         and (awn.ssid is not null or awn.bssid is not null)
    )
      and not exists (
        select 1
          from devices d
         where d.mac_hint is not null
           and lower(d.mac_hint) = w.source_mac
           and d.last_seen >= now() - interval '5 minutes'
      )
      and not exists (
        select 1
          from sync_scan_ingest proxy
          join devices d on d.device_id = proxy.payload->>'device_id'
         where proxy.stream_name = 'proxy.events'
           and proxy.observed_at >= now() - interval '5 minutes'
           and d.mac_hint is not null
           and lower(d.mac_hint) = w.source_mac
      )
    order by source_mac, destination_bssid, coalesce(location_id, ''), observed_at desc
  ),
  inserted as (
    insert into shadow_it_alerts (
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
      created_at,
      updated_at
    )
    select
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
      now(),
      now()
    from candidates
    on conflict (dedupe_key) do nothing
    returning *
  )
  select jsonb_build_object(
           'event_type', 'shadow_device',
           'observed_at', observed_at,
           'source_mac', source_mac,
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
    update sync_batch batch
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
    insert into sync_error (job_id, batch_id, error_class, error_text)
    select job_id,
           batch_id,
           coalesce(nullif((select payload->>'error_class' from result), ''), 'unknown'),
           coalesce(last_error, 'oracle load failed')
      from batch_update
     where status = 'failed'
    returning id
  ),
  job_done as (
    update sync_job job
       set status = case
                      when exists (
                        select 1
                          from sync_batch b
                         where b.job_id = job.job_id
                           and b.status = 'failed'
                      ) then 'failed'
                      else 'completed'
                    end,
           finished_at = now()
     where job.job_id in (select job_id from batch_update)
       and not exists (
         select 1
           from sync_batch b
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
