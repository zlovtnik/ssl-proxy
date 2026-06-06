package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/seqscore"
)

type frameSequenceAlertRow struct {
	SessionKey     string
	SourceMAC      string
	SensorID       string
	LocationID     string
	WindowStart    pgtype.Timestamptz
	WindowEnd      pgtype.Timestamptz
	SequenceTokens string
	SemanticTokens string
	FrameCount     int64
}

func CheckDeauthPrecursors(ctx context.Context, pool *pgxpool.Pool, scorer *seqscore.Scorer, cfg Config) (int, error) {
	if scorer == nil {
		scorer = seqscore.Empty()
	}
	rows, err := pool.Query(ctx, `
SELECT
  session_key,
  lower(coalesce(source_mac, '')),
  coalesce(sensor_id, ''),
  coalesce(location_id, ''),
  window_start,
  window_end,
  sequence_tokens,
  coalesce(semantic_tokens, ''),
  frame_count
FROM vec_frame_sequences
WHERE window_end >= now() - interval '1 hour'
  AND frame_count >= 3
`)
	if err != nil {
		return 0, fmt.Errorf("deauth precursor query failed: %w", err)
	}
	defer rows.Close()

	inserted := 0
	for rows.Next() {
		var row frameSequenceAlertRow
		if err := rows.Scan(&row.SessionKey, &row.SourceMAC, &row.SensorID, &row.LocationID, &row.WindowStart, &row.WindowEnd, &row.SequenceTokens, &row.SemanticTokens, &row.FrameCount); err != nil {
			return inserted, fmt.Errorf("scan deauth precursor row: %w", err)
		}
		if HasTerminationToken(row.SequenceTokens, row.SemanticTokens) {
			continue
		}
		score := scorer.ScoreText(row.SequenceTokens)
		if score >= cfg.SeqThreshold {
			continue
		}
		metadata, err := json.Marshal(map[string]any{
			"reason":       "low_probability_pre_deauth_sequence",
			"session_key":  row.SessionKey,
			"log_prob":     score,
			"threshold":    cfg.SeqThreshold,
			"frame_count":  row.FrameCount,
			"window_start": alertTime(row.WindowStart),
			"window_end":   alertTime(row.WindowEnd),
		})
		if err != nil {
			return inserted, fmt.Errorf("marshal deauth precursor metadata for session %s score %v threshold %v window_start %v window_end %v: %w",
				row.SessionKey, score, cfg.SeqThreshold, alertTime(row.WindowStart), alertTime(row.WindowEnd), err)
		}
		tag, err := pool.Exec(ctx, `
INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
SELECT
  'deauth_precursor',
  nullif($1, ''),
  nullif($2, ''),
  nullif($3, ''),
  $4,
  concat('Low-probability pre-deauth sequence: log_prob=', round($4::numeric, 3), ', session=', $5),
  $6::jsonb
WHERE NOT EXISTS (
  SELECT 1 FROM vec_alerts a
  WHERE a.alert_type = 'deauth_precursor'
    AND a.metadata->>'session_key' = $5
    AND a.created_at > now() - interval '1 hour'
)
`, row.SourceMAC, row.SensorID, row.LocationID, score, row.SessionKey, string(metadata))
		if err != nil {
			return inserted, fmt.Errorf("insert deauth precursor alert: %w", err)
		}
		inserted += int(tag.RowsAffected())
	}
	if err := rows.Err(); err != nil {
		return inserted, fmt.Errorf("read deauth precursor rows: %w", err)
	}
	return inserted, nil
}

func HasTerminationToken(sequenceTokens, semanticTokens string) bool {
	for _, token := range strings.Fields(sequenceTokens) {
		switch strings.ToUpper(token) {
		case "DEAUTH", "DEAUTHENTICATION", "DISASSOC", "DISASSOCIATION":
			return true
		}
	}
	for _, token := range strings.Fields(semanticTokens) {
		if strings.EqualFold(token, "TERMINATION") {
			return true
		}
	}
	return false
}

func alertTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}
