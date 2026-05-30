-- object: vec_detect_rogue_clusters
-- folder: functions
-- depends_on: vec_alerts
drop function if exists vec_detect_rogue_clusters(timestamp with time zone, timestamp with time zone);

create or replace function vec_detect_rogue_clusters(
  p_from timestamp with time zone DEFAULT (now() - '01:00:00'::interval),
  p_to   timestamp with time zone DEFAULT now()
)
RETURNS integer
LANGUAGE plpgsql
AS $$
declare
  v_count     integer := 0;
  v_row_count integer := 0;
begin

  -- Track 1: Degree spike
  with current_assoc as (
    select
      lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      observed_at
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
      and nullif(coalesce(source_mac, payload->>'source_mac'), '') is not null
  ),
  current_counts as (
    select bssid, count(distinct source_mac) as client_count
    from current_assoc
    group by bssid
  ),
  previous_assoc as (
    select
      lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= p_from - interval '1 hour'
      and observed_at < p_from
      and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
      and nullif(coalesce(source_mac, payload->>'source_mac'), '') is not null
  ),
  previous_counts as (
    select bssid, count(distinct source_mac) as client_count
    from previous_assoc
    group by bssid
  ),
  suspicious_bssids as (
    select
      c.bssid,
      c.client_count as current_clients,
      coalesce(p.client_count, 0) as previous_clients
    from current_counts c
    left join previous_counts p using (bssid)
    where c.client_count >= 20
      and c.client_count >= greatest(coalesce(p.client_count, 0) * 2, 10)
  )
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'rogue_cluster'::text,
    s.bssid,
    greatest(s.current_clients::double precision, 1.0),
    jsonb_build_object(
      'reason',           'degree_spike',
      'current_clients',  s.current_clients,
      'previous_clients', s.previous_clients
    )
  from suspicious_bssids s
  where not exists (
    select 1 from vec_alerts a
    where a.alert_type  = 'rogue_cluster'
      and a.source_mac is not distinct from s.bssid
      and a.created_at  > now() - interval '1 hour'
  );

  get diagnostics v_count = row_count;

  -- Track 2: Vendor conflict
  with vendor_conflicts as (
    select
      lower(nullif(coalesce(ssid, payload->>'ssid'), '')) as ssid,
      array_agg(distinct lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), ''))) as bssids,
      array_agg(distinct substr(regexp_replace(lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')), '[:\-]', '', 'g'), 1, 6)) as vendor_ouis,
      count(distinct substr(regexp_replace(lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')), '[:\-]', '', 'g'), 1, 6)) as vendor_count
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(ssid, payload->>'ssid'), '') is not null
      and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
    group by lower(nullif(coalesce(ssid, payload->>'ssid'), ''))
    having count(distinct substr(regexp_replace(lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')), '[:\-]', '', 'g'), 1, 6)) >= 2
  )
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'rogue_cluster'::text,
    null,
    greatest(vc.vendor_count::double precision, 1.0),
    jsonb_build_object(
      'reason',      'vendor_conflict',
      'ssid',        vc.ssid,
      'bssids',      vc.bssids,
      'vendor_ouis', vc.vendor_ouis
    )
  from vendor_conflicts vc
  where not exists (
    select 1 from vec_alerts a
    where a.alert_type          = 'rogue_cluster'
      and a.source_mac          is null
      and a.created_at          > now() - interval '1 hour'
      and a.metadata->>'reason' = 'vendor_conflict'
      and a.metadata->>'ssid'   = vc.ssid
  );

  get diagnostics v_row_count = row_count;
  v_count := v_count + v_row_count;

  -- Track 3: Fast roaming
  with fast_roamers as (
    select
      source_mac,
      min(observed_at)       as first_seen,
      max(observed_at)       as last_seen,
      count(distinct bssid)  as distinct_bssids
    from (
      select
        lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
        lower(nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '')) as bssid,
        observed_at
      from sync_events_expanded
      where stream_name = 'wireless.audit'
        and observed_at >= p_from
        and observed_at < p_to
        and nullif(coalesce(source_mac, payload->>'source_mac'), '') is not null
        and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
    ) t
    group by source_mac
    having count(distinct bssid) >= 3
       and max(observed_at) - min(observed_at) <= interval '60 seconds'
  )
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'rogue_cluster'::text,
    f.source_mac,
    greatest(f.distinct_bssids::double precision, 1.0),
    jsonb_build_object(
      'reason',         'fast_roaming',
      'distinct_bssids', f.distinct_bssids,
      'first_seen',      f.first_seen,
      'last_seen',       f.last_seen
    )
  from fast_roamers f
  where not exists (
    select 1 from vec_alerts a
    where a.alert_type          = 'rogue_cluster'
      and a.source_mac is not distinct from f.source_mac
      and a.created_at          > now() - interval '1 hour'
      and a.metadata->>'reason' = 'fast_roaming'
  );

  get diagnostics v_row_count = row_count;
  v_count := v_count + v_row_count;

  -- Track 4: Sequence anomaly — flag sessions with log-prob < -15
  with session_sequences as (
    select
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), '')) as source_mac,
      nullif(coalesce(session_key, payload->>'session_key'), '')       as session_key,
      string_agg(
        upper(regexp_replace(payload->>'frame_subtype', '-', '_', 'g')),
        ' ' order by observed_at
      ) as tokens
    from sync_events_expanded
    where stream_name = 'wireless.audit'
      and observed_at >= p_from
      and observed_at < p_to
      and nullif(coalesce(session_key, payload->>'session_key'), '') is not null
      and payload->>'frame_subtype' is not null
    group by
      nullif(coalesce(session_key, payload->>'session_key'), ''),
      lower(nullif(coalesce(source_mac, payload->>'source_mac'), ''))
    having count(*) >= 3
  ),
  scored_sequences as (
    select
      session_key,
      source_mac,
      tokens,
      vec_score_sequence(regexp_split_to_array(tokens, E'\\s+')) as log_prob
    from session_sequences
  )
  insert into vec_alerts (alert_type, source_mac, score, metadata)
  select
    'rogue_cluster'::text,
    ss.source_mac,
    greatest(abs(ss.log_prob)::double precision, 1.0),
    jsonb_build_object(
      'reason',      'sequence_anomaly',
      'session_key', ss.session_key,
      'log_prob',    ss.log_prob,
      'threshold',   -15
    )
  from scored_sequences ss
  where ss.log_prob < -15
    and not exists (
      select 1 from vec_alerts a
      where a.alert_type          = 'rogue_cluster'
        and a.source_mac is not distinct from ss.source_mac
        and a.created_at          > now() - interval '1 hour'
        and a.metadata->>'reason' = 'sequence_anomaly'
    );

  get diagnostics v_row_count = row_count;
  v_count := v_count + v_row_count;

  return v_count;
end;
$$;
