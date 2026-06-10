package search

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type boostSignals struct {
	NearDuplicate bool
	ShadowOpen    bool
	RiskScore     float64
	APRisk        float64
	ThreatTags    int
}

func rerankCandidateLimit(topK int) int {
	if topK <= 0 {
		return 0
	}
	return topK * 4
}

func ApplyThreatBoosts(ctx context.Context, pool *pgxpool.Pool, results []RawResult) ([]RawResult, error) {
	if len(results) == 0 {
		return results, nil
	}
	keys := make([]string, 0, len(results))
	for _, result := range results {
		keys = append(keys, result.SourceKey)
	}
	rows, err := pool.Query(ctx, `
WITH keys AS (
  SELECT unnest($1::text[]) AS source_key
)
SELECT
  k.source_key,
  EXISTS (
    SELECT 1 FROM vec_similarity_pairs p
    WHERE p.cosine_distance < 0.05
      AND (
        (p.left_source_table = 'sync_events' AND p.left_source_key = k.source_key)
        OR (p.right_source_table = 'sync_events' AND p.right_source_key = k.source_key)
      )
    LIMIT 1
  ) AS near_duplicate,
  EXISTS (
    SELECT 1 FROM wireless_shadow_alerts alert
    WHERE alert.resolved_at IS NULL
      AND lower(alert.source_mac) = lower(coalesce(se.source_mac, ''))
    LIMIT 1
  ) AS shadow_open,
  coalesce((se.payload->>'risk_score')::double precision, 0) AS risk_score,
  coalesce(ap.composite_risk, 0) AS ap_risk,
  coalesce((
    SELECT count(*)::integer
    FROM jsonb_array_elements_text(case when jsonb_typeof(se.payload->'tags') = 'array' then se.payload->'tags' else '[]'::jsonb end) tag(value)
    WHERE tag.value LIKE 'threat:%'
  ), 0) AS threat_tags
FROM keys k
LEFT JOIN sync_events_expanded se ON se.dedupe_key = k.source_key
LEFT JOIN mv_ap_risk_score ap ON ap.bssid = lower(coalesce(se.bssid, se.destination_bssid, ''))
`, keys)
	if err != nil {
		return results, err
	}
	defer rows.Close()

	signals := map[string]boostSignals{}
	for rows.Next() {
		var key string
		var item boostSignals
		if err := rows.Scan(&key, &item.NearDuplicate, &item.ShadowOpen, &item.RiskScore, &item.APRisk, &item.ThreatTags); err != nil {
			return results, err
		}
		signals[key] = item
	}
	if err := rows.Err(); err != nil {
		return results, err
	}

	for i := range results {
		signal := signals[results[i].SourceKey]
		var boost float32
		if signal.NearDuplicate {
			boost += 0.15
			results[i].BoostReasons = append(results[i].BoostReasons, "near_duplicate")
		}
		if signal.ShadowOpen {
			boost += 0.20
			results[i].BoostReasons = append(results[i].BoostReasons, "open_shadow_alert")
		}
		if signal.RiskScore >= 0.6 {
			boost += 0.10
			results[i].BoostReasons = append(results[i].BoostReasons, "payload_risk_score")
		}
		if signal.APRisk > 0.75 {
			boost += 0.25
			results[i].BoostReasons = append(results[i].BoostReasons, "ap_composite_risk")
		}
		if signal.ThreatTags > 0 {
			boost += float32(signal.ThreatTags) * 0.05
			results[i].BoostReasons = append(results[i].BoostReasons, "threat_tags")
		}
		if boost > 0.50 {
			boost = 0.50
		}
		results[i].ThreatBoost = boost
		results[i].Score += boost
	}
	return results, nil
}
