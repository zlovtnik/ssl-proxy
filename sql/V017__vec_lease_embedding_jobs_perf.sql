-- V017: Optimize vec_lease_embedding_jobs() performance
--
-- The slow query log showed:
--   SELECT * FROM vec_lease_embedding_jobs($1, $2, make_interval(secs => $3))
--   elapsed: 1.107s (threshold 1s), rows_returned: 100
--
-- Root cause: the function's WHERE clause used an OR between
-- "pending/failed" and "expired lease" branches, which forces PostgreSQL
-- to either BitmapOr two index scans or fall back to a seq scan.
-- Additionally, the partial indexes did not include attempts < max_attempts
-- in their predicates, causing residual filtering of exhausted jobs.
--
-- Fixes:
--   1. Rewrite vec_lease_embedding_jobs to use two independent queries
--      (pending/failed first, expired leases second) so each branch can
--      use a focused partial index without an OR.
--   2. Widen the pending_idx predicate to include attempts < max_attempts
--      and due_at <= now() so the index pre-filters completely.
--   3. Widen the lease_idx predicate to include attempts < max_attempts.

-- -------------------------------------------------------------------
-- 1. Tighten partial indexes to include attempts < max_attempts
-- -------------------------------------------------------------------

drop index if exists vec_embedding_jobs_pending_idx;

create index if not exists vec_embedding_jobs_pending_idx
  on vec_embedding_jobs (priority, due_at, job_id)
  where status in ('pending', 'failed')
    and attempts < max_attempts;

drop index if exists vec_embedding_jobs_lease_idx;

create index if not exists vec_embedding_jobs_lease_idx
  on vec_embedding_jobs (leased_at, priority, job_id)
  where status = 'leased'
    and attempts < max_attempts;

-- -------------------------------------------------------------------
-- 2. Rewrite vec_lease_embedding_jobs with a split-query approach
-- -------------------------------------------------------------------

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
begin
  -- Branch A: pending & failed jobs that are due for retry.
  -- This branch uses the pending_idx which now pre-filters on
  -- status, attempts < max_attempts, and due_at <= now().
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

  -- Branch B: expired leases (worker died mid-batch).
  -- This branch uses the lease_idx which pre-filters on
  -- status = 'leased' and attempts < max_attempts.
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
end;
$$;