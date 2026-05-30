-- Unschedules any pg_cron jobs left from a previous coordinator lifecycle.
-- Run this BEFORE materialized view DDL so that pg_cron does not
-- terminate the connection when a stale REFRESH job fires during DDL.
--
-- This is idempotent: unscheduling a nonexistent job is a no-op.

do $$
declare
  j record;
begin
  if to_regnamespace('cron') is not null then
    for j in select jobname from cron.job loop
      perform cron.unschedule(j.jobname);
    end loop;
  end if;
end $$;