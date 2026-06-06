package alerts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func CheckEmbeddingDrift(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	tag, err := pool.Exec(ctx, `
INSERT INTO vec_alerts (alert_type, source_mac, score, explanation_text, metadata)
SELECT
  'embedding_drift',
  e.source_mac,
  (e.embedding::vector(768) <=> dic.embedding_centroid) AS drift_score,
  concat('Embedding drift for ', e.source_mac, ': distance=', round((e.embedding::vector(768) <=> dic.embedding_centroid)::numeric, 3)),
  jsonb_build_object(
    'drift_distance', (e.embedding::vector(768) <=> dic.embedding_centroid),
    'centroid_sample_count', dic.centroid_sample_count,
    'embedding_id', e.embedding_id,
    'cluster_id', dic.cluster_id
  )
FROM vec_embeddings e
JOIN device_identity_clusters dic
  ON EXISTS (
    SELECT 1 FROM unnest(dic.mac_ids) AS cluster_mac(mac)
    WHERE lower(cluster_mac.mac) = lower(e.source_mac)
  )
WHERE e.embedding_kind = 'event'
  AND e.embedding_dimensions = 768
  AND e.embedded_at >= now() - interval '30 minutes'
  AND e.source_mac IS NOT NULL
  AND dic.embedding_centroid IS NOT NULL
  AND dic.centroid_sample_count >= 10
  AND (e.embedding::vector(768) <=> dic.embedding_centroid) > 0.20
  AND NOT EXISTS (
    SELECT 1 FROM vec_alerts a
    WHERE a.alert_type = 'embedding_drift'
      AND a.source_mac IS NOT DISTINCT FROM e.source_mac
      AND a.created_at > now() - interval '1 hour'
  )
`)
	if err != nil {
		return 0, fmt.Errorf("embedding_drift query failed: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
