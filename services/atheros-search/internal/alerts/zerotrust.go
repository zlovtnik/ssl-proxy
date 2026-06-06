package alerts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func CheckZeroTrustOverlayRisk(ctx context.Context, pool *pgxpool.Pool, cfg Config) (int, error) {
	tag, err := pool.Exec(ctx, `
WITH signals AS (
  SELECT
    d.wg_pubkey,
    d.mac_id AS source_mac,
    max(s.sensor_id) AS sensor_id,
    max(s.location_id) AS location_id,
    max(ap.composite_risk) AS high_risk_ap_score,
    0::double precision AS embedding_drift_score,
    array_remove(array_agg(DISTINCT ap.bssid), NULL) AS bssids
  FROM sync_events_expanded s
  JOIN devices d ON lower(d.mac_id) = lower(s.source_mac)
  JOIN mv_ap_risk_score ap ON ap.bssid = lower(coalesce(nullif(s.bssid, ''), nullif(s.destination_bssid, '')))
  WHERE d.wg_pubkey IS NOT NULL
    AND s.stream_name = 'wireless.audit'
    AND s.status = 'batched'
    AND s.observed_at >= now() - interval '1 hour'
    AND ap.composite_risk > $1
  GROUP BY d.wg_pubkey, d.mac_id
  UNION ALL
  SELECT
    d.wg_pubkey,
    d.mac_id AS source_mac,
    NULL::text AS sensor_id,
    NULL::text AS location_id,
    0::double precision AS high_risk_ap_score,
    max(a.score) AS embedding_drift_score,
    ARRAY[]::text[] AS bssids
  FROM vec_alerts a
  JOIN devices d ON lower(d.mac_id) = lower(a.source_mac)
  WHERE d.wg_pubkey IS NOT NULL
    AND a.alert_type = 'embedding_drift'
    AND a.created_at >= now() - interval '1 hour'
  GROUP BY d.wg_pubkey, d.mac_id
),
rolled AS (
  SELECT
    wg_pubkey,
    source_mac,
    max(sensor_id) FILTER (WHERE sensor_id IS NOT NULL) AS sensor_id,
    max(location_id) FILTER (WHERE location_id IS NOT NULL) AS location_id,
    max(high_risk_ap_score) AS high_risk_ap_score,
    max(embedding_drift_score) AS embedding_drift_score,
    array_remove(array_agg(DISTINCT bssid.value), NULL) AS bssids
  FROM signals
  LEFT JOIN LATERAL unnest(signals.bssids) AS bssid(value) ON true
  GROUP BY wg_pubkey, source_mac
)
INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
SELECT
  'zero_trust_overlay_risk',
  source_mac,
  sensor_id,
  location_id,
  greatest(coalesce(high_risk_ap_score, 0), coalesce(embedding_drift_score, 0)),
  concat('Zero-trust overlay risk for wg_pubkey ', wg_pubkey),
  jsonb_build_object(
    'wg_pubkey', wg_pubkey,
    'source_mac', source_mac,
    'bssids', bssids,
    'high_risk_ap_score', high_risk_ap_score,
    'embedding_drift_score', embedding_drift_score,
    'ap_risk_threshold', $1
  )
FROM rolled
WHERE greatest(coalesce(high_risk_ap_score, 0), coalesce(embedding_drift_score, 0)) > 0
  AND NOT EXISTS (
    SELECT 1 FROM vec_alerts a
    WHERE a.alert_type = 'zero_trust_overlay_risk'
      AND a.source_mac IS NOT DISTINCT FROM rolled.source_mac
      AND a.metadata->>'wg_pubkey' = rolled.wg_pubkey
      AND a.created_at > now() - interval '1 hour'
  )
`, cfg.APRiskThreshold)
	if err != nil {
		return 0, fmt.Errorf("zero_trust_overlay_risk query failed: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
