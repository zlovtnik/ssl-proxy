package search

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
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

func ApplyThreatBoosts(ctx context.Context, pool *sql.DB, results []RawResult) ([]RawResult, error) {
	if len(results) == 0 {
		return results, nil
	}
	placeholders := make([]string, 0, len(results))
	args := make([]any, 0, len(results))
	for _, result := range results {
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(placeholders)+1))
		args = append(args, result.SourceKey)
	}
	rows, err := pool.QueryContext(ctx, `
SELECT
  source_key,
  near_duplicate,
  shadow_open,
  risk_score,
  ap_risk,
  threat_tag_count
FROM atheros_search.threat_signals
WHERE source_key IN (`+strings.Join(placeholders, ",")+`)
`, args...)
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
		applyThreatBoost(&results[i], signals[results[i].SourceKey])
	}
	return results, nil
}

func applyThreatBoost(result *RawResult, signal boostSignals) {
	var boost float32
	if signal.NearDuplicate {
		boost += 0.15
		result.BoostReasons = append(result.BoostReasons, "near_duplicate")
	}
	if signal.ShadowOpen {
		boost += 0.20
		result.BoostReasons = append(result.BoostReasons, "open_shadow_alert")
	}
	if signal.RiskScore >= 0.6 {
		boost += 0.10
		result.BoostReasons = append(result.BoostReasons, "payload_risk_score")
	}
	if signal.APRisk > 0.75 {
		boost += 0.25
		result.BoostReasons = append(result.BoostReasons, "ap_composite_risk")
	}
	if signal.ThreatTags > 0 {
		boost += float32(signal.ThreatTags) * 0.05
		result.BoostReasons = append(result.BoostReasons, "threat_tags")
	}
	if boost > 0.50 {
		boost = 0.50
	}
	result.ThreatBoost = boost
	result.Score += boost
}
