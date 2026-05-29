-- object: coordinator.safe helpers
-- folder: functions
-- depends_on: coordinator schema
create or replace function coordinator.safe_int(p_value text)
returns integer
language sql
immutable
as $$
  select case when p_value ~ '^-?[0-9]+$' then p_value::integer end
$$;

create or replace function coordinator.safe_bigint(p_value text)
returns bigint
language sql
immutable
as $$
  select case when p_value ~ '^-?[0-9]+$' then p_value::bigint end
$$;

create or replace function coordinator.safe_bool(p_value text)
returns boolean
language sql
immutable
as $$
  select case
    when lower(p_value) in ('true', 't', '1', 'yes', 'y') then true
    when lower(p_value) in ('false', 'f', '0', 'no', 'n') then false
  end
$$;
