-- object: vec_lease_embedding_jobs
-- folder: functions
-- depends_on: vec_embedding_jobs, vec_worker_state
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
