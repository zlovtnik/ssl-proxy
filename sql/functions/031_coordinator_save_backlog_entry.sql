-- object: coordinator.save_backlog_entry
-- folder: functions
-- depends_on: sync_backlog
create or replace function coordinator.save_backlog_entry(p_payload jsonb)
returns void
language plpgsql
as $$
begin
  if nullif(p_payload->>'dedupe_key', '') is null then
    raise exception 'coordinator.save_backlog_entry requires dedupe_key';
  end if;

  insert into sync_backlog (dedupe_key, stream_name, payload, status, attempt_count, created_at, updated_at)
  values (
    p_payload->>'dedupe_key',
    p_payload->>'stream_name',
    p_payload->'payload',
    'pending',
    0,
    now(),
    now()
  )
  on conflict (dedupe_key) do update
    set payload = excluded.payload,
        status = 'pending',
        updated_at = now();
end;
$$;
