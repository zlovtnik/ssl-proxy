-- object: mv_ap_risk_score
-- folder: materialized_views
-- depends_on: v_ap_risk_score
-- Materialized for 5-minute refresh alongside v_device_repetition_score
create materialized view if not exists mv_ap_risk_score as
select * from v_ap_risk_score;
