-- object: v_ap_risk_score
-- folder: views
-- depends_on: vec_alerts, vec_similarity_pairs
-- Track 6.1: Composite AP risk score combining deauth, signal, typosquat,
-- vendor mismatch, and embedding outlier signals into a single score.
create or replace view v_ap_risk_score as
with deauth_scores as (
  select
    coalesce(source_mac, metadata->>'bssid') as bssid,
    score as deauth_score
  from vec_alerts
  where alert_type in ('rogue_cluster', 'deauth_flood')
    and created_at >= now() - interval '1 hour'
),
signal_anomaly_scores as (
  select
    coalesce(source_mac, metadata->>'bssid') as bssid,
    score as signal_anomaly_score
  from vec_alerts
  where alert_type in ('signal_anomaly', 'rogue_cluster')
    and metadata->>'reason' in ('signal_jump', 'channel_band_conflict')
    and created_at >= now() - interval '1 hour'
),
typosquat_scores as (
  select
    coalesce(source_mac, metadata->>'bssid') as bssid,
    score as typosquat_score
  from vec_alerts
  where alert_type = 'rogue_cluster'
    and metadata->>'reason' in ('ssid_typosquat', 'vendor_conflict', 'bssid_spoofing')
    and created_at >= now() - interval '1 hour'
),
vendor_mismatch_scores as (
  select
    lower(substr(regexp_replace(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '[:\-]', '', 'g'), 1, 6)) as bssid_oui,
    count(distinct lower(substr(regexp_replace(bssid, '[:\-]', '', 'g'), 1, 6)))::double precision as vendor_mismatch_score
  from sync_events_expanded
  where stream_name = 'wireless.audit'
    and observed_at >= now() - interval '1 hour'
    and nullif(coalesce(ssid, payload->>'ssid'), '') is not null
    and nullif(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '') is not null
    and lower(substr(regexp_replace(coalesce(bssid, payload->>'bssid', destination_bssid, payload->>'destination_bssid'), '[:\-]', '', 'g'), 1, 6)) is not null
  group by bssid_oui
),
embedding_outlier_scores as (
  select
    coalesce(p.left_source_mac, p.right_source_mac) as bssid,
    max(p.cosine_distance) as embedding_outlier_score
  from vec_similarity_pairs p
  where p.computed_at >= now() - interval '1 hour'
    and p.cosine_distance > 0.15
  group by coalesce(p.left_source_mac, p.right_source_mac)
),
all_bssids as (
  select distinct coalesce(source_mac, metadata->>'bssid') as bssid from vec_alerts
  union
  select distinct left_source_mac from vec_similarity_pairs where left_source_mac is not null
  union
  select distinct right_source_mac from vec_similarity_pairs where right_source_mac is not null
)
select
  a.bssid,
  coalesce(d.deauth_score, 0::double precision) as deauth_score,
  coalesce(s.signal_anomaly_score, 0::double precision) as signal_anomaly_score,
  coalesce(t.typosquat_score, 0::double precision) as typosquat_score,
  coalesce(v.vendor_mismatch_score, 0::double precision) as vendor_mismatch_score,
  coalesce(e.embedding_outlier_score, 0::double precision) as embedding_outlier_score,
  (coalesce(d.deauth_score, 0::double precision) * 0.25
   + coalesce(s.signal_anomaly_score, 0::double precision) * 0.20
   + coalesce(t.typosquat_score, 0::double precision) * 0.20
   + coalesce(v.vendor_mismatch_score, 0::double precision) * 0.15
   + coalesce(e.embedding_outlier_score, 0::double precision) * 0.20) as composite_risk
from all_bssids a
left join deauth_scores d on d.bssid = a.bssid
left join signal_anomaly_scores s on s.bssid = a.bssid
left join typosquat_scores t on t.bssid = a.bssid
left join vendor_mismatch_scores v on v.bssid_oui = lower(substr(regexp_replace(a.bssid, '[:\-]', '', 'g'), 1, 6))
left join embedding_outlier_scores e on e.bssid = a.bssid;
