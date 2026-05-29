-- object: coordinator.get_next_batch
-- folder: functions
-- depends_on: sync_batches, sync_jobs
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
