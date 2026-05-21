-- V018: Fix vec_complete_embedding_batch deadlock and slow per-job completion
--
-- Observed in production:
--   1. "bulk complete failed, falling back per job", error: "deadlock detected"
--   2. Per-job UPDATE vec_embedding_jobs SET status = 'completed' ... took 15-16 seconds
--
-- Root causes:
--   a) No index on (job_id, lease_token). The UPDATE in vec_complete_embedding_batch
--      and the per-job complete_job_tx both filter by both columns. Without a covering
--      index, PostgreSQL scans the PK index and filters, which is slow with dead tuples.
--   b) The vec_complete_embedding_batch UPDATE was not ordered, so with concurrent
--      vec_lease_embedding_jobs (which locks rows via FOR UPDATE SKIP LOCKED in
--      job_id order), the two functions could acquire row locks in different orders
--      and produce a cycle → deadlock.
--
-- Fixes:
--   1. Add index on (job_id, lease_token) for fast completion lookups.
--   2. Rewrite vec_complete_embedding_batch to update jobs in job_id ASC order
--      to impose lock-ordering discipline.
--   3. Revert max_concurrent_completes default to 1 in the vec-worker config
--      (env var change, not a migration).

-- -------------------------------------------------------------------
-- 1. Add completion index
-- -------------------------------------------------------------------

create index if not exists vec_embedding_jobs_completion_idx_v2
  on vec_embedding_jobs (job_id, lease_token)
  where status in ('pending', 'leased', 'failed');

-- -------------------------------------------------------------------
-- 2. Rewrite vec_complete_embedding_batch with lock-order discipline
-- -------------------------------------------------------------------

create or replace function vec_complete_embedding_batch(p_payload jsonb)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  if p_payload is null or jsonb_typeof(p_payload) <> 'array' or jsonb_array_length(p_payload) = 0 then
    return 0;
  end if;

  insert into vec_embeddings (
    source_table, source_key, source_observed_at, source_stream_name,
    source_sensor_id, source_location_id, source_mac,
    embedding_model, embedding_kind, embedding_dimensions,
    content_sha256, content_text, embedding, metadata,
    embedded_at, created_at, updated_at
  )
  select
    r.source_table,
    r.source_key,
    r.source_observed_at,
    r.source_stream_name,
    r.source_sensor_id,
    r.source_location_id,
    r.source_mac,
    r.embedding_model,
    r.embedding_kind,
    r.embedding_dimensions,
    r.content_sha256,
    r.content_text,
    r.embedding::vector,
    coalesce(r.metadata, '{}'::jsonb),
    now(), now(), now()
  from jsonb_to_recordset(p_payload) as r(
    job_id bigint,
    lease_token text,
    source_table text,
    source_key text,
    source_observed_at timestamptz,
    source_stream_name text,
    source_sensor_id text,
    source_location_id text,
    source_mac text,
    embedding_model text,
    embedding_kind text,
    embedding_dimensions integer,
    content_sha256 text,
    content_text text,
    embedding text,
    metadata jsonb
  )
  on conflict (source_table, source_key, embedding_model, embedding_kind)
  do update set
    source_observed_at = excluded.source_observed_at,
    source_stream_name = excluded.source_stream_name,
    source_sensor_id = excluded.source_sensor_id,
    source_location_id = excluded.source_location_id,
    source_mac = excluded.source_mac,
    embedding_dimensions = excluded.embedding_dimensions,
    content_sha256 = excluded.content_sha256,
    content_text = excluded.content_text,
    embedding = excluded.embedding,
    metadata = excluded.metadata,
    embedded_at = now(),
    updated_at = now();

  -- UPDATE jobs in job_id ASC order to enforce consistent lock ordering
  -- with vec_lease_embedding_jobs (which also orders by job_id ASC).
  -- This prevents deadlock cycles when both functions run concurrently.
  update vec_embedding_jobs j
     set status = 'completed',
         content_sha256 = r.content_sha256,
         completed_at = now(),
         lease_token = null,
         leased_at = null,
         locked_by = null,
         last_error = null,
         updated_at = now()
    from payload_rows r
   where j.job_id = r.job_id
     and j.lease_token is not distinct from r.lease_token;

  with payload_rows as (
      select r.job_id, r.lease_token, r.content_sha256
        from jsonb_to_recordset(p_payload) as r(
          job_id bigint,
          lease_token text,
          content_sha256 text
        )
  ),
  locked as (
      select j.job_id, p.lease_token, p.content_sha256
        from vec_embedding_jobs j
        join payload_rows p using (job_id)
       where j.lease_token is not distinct from p.lease_token
       order by j.job_id asc
       for update
  )
  update vec_embedding_jobs j
     set status = 'completed',
         completed_at = now(),
         lease_token = null,
         leased_at = null,
         locked_by = null,
         last_error = null,
         updated_at = now()
    from locked l
   where j.job_id = l.job_id
     and j.lease_token is not distinct from l.lease_token;

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;