package alerts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func CheckNearDuplicates(ctx context.Context, pool *pgxpool.Pool, cfg Config) (int, error) {
	tag, err := pool.Exec(ctx, `
INSERT INTO vec_alerts (alert_type, source_mac, score, metadata)
SELECT
  'near_duplicate_cluster',
  source_mac,
  near_duplicate_pairs::double precision,
  jsonb_build_object(
    'near_duplicate_pairs', near_duplicate_pairs,
    'min_distance', coalesce(min_distance, 1.0),
    'avg_distance', coalesce(avg_distance, 1.0),
    'unique_events_implicated', coalesce(unique_events_implicated, 0)
  )
FROM v_device_repetition_score score
WHERE near_duplicate_pairs >= $1
  AND NOT EXISTS (
    SELECT 1 FROM vec_alerts a
    WHERE a.alert_type = 'near_duplicate_cluster'
      AND a.source_mac IS NOT DISTINCT FROM score.source_mac
      AND a.created_at > now() - interval '1 hour'
  )
  AND NOT (
    source_mac IS NOT NULL
    AND (get_byte(decode(split_part(source_mac, ':', 1), 'hex'), 0) & 2) = 2
  )
  AND NOT EXISTS (
    SELECT 1 FROM mv_ap_risk_score ap
    WHERE ap.bssid = score.source_mac
  )
`, cfg.NearDupThreshold)
	if err != nil {
		return 0, fmt.Errorf("near_duplicate query failed: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
