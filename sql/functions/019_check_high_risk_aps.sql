-- object: check_high_risk_aps
-- folder: functions
-- depends_on: mv_ap_risk_score
-- Check for high-risk APs and insert alerts when composite_risk exceeds threshold
create or replace function check_high_risk_aps(p_threshold double precision default 0.75)
returns integer
language plpgsql
as $$
declare
  v_count integer;
begin
  insert into vec_alerts (alert_type, source_mac, score, explanation_text, metadata)
  select
    'high_risk_ap'::text,
    r.bssid,
    r.composite_risk,
    concat(
      'High-risk AP ', r.bssid, ': composite_risk=',
      round(r.composite_risk::numeric, 2), ' exceeded threshold ',
      round(p_threshold::numeric, 2), '. ',
      'Contributing factors: deauth_score=',
      round(r.deauth_score::numeric, 2),
      ', signal_anomaly_score=',
      round(r.signal_anomaly_score::numeric, 2),
      ', typosquat_score=',
      round(r.typosquat_score::numeric, 2),
      ', vendor_mismatch_score=',
      round(r.vendor_mismatch_score::numeric, 2),
      ', embedding_outlier_score=',
      round(r.embedding_outlier_score::numeric, 2), '.'
    ),
    jsonb_build_object(
      'composite_risk', r.composite_risk,
      'deauth_score', r.deauth_score,
      'signal_anomaly_score', r.signal_anomaly_score,
      'typosquat_score', r.typosquat_score,
      'vendor_mismatch_score', r.vendor_mismatch_score,
      'embedding_outlier_score', r.embedding_outlier_score
    )
  from mv_ap_risk_score r
  where r.composite_risk > p_threshold
    and not exists (
      select 1 from vec_alerts a
      where a.alert_type = 'high_risk_ap'
        and a.source_mac is not distinct from r.bssid
        and a.created_at > now() - interval '1 hour'
    );

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;
