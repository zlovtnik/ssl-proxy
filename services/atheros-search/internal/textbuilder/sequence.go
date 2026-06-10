package textbuilder

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/seqscore"
)

var sequenceScorerCache = seqscore.NewCache(60 * time.Second)

type FrameSequenceRow struct {
	QueryKey         string
	SessionKey       string
	SourceMAC        string
	SensorID         string
	LocationID       string
	WindowStart      pgtype.Timestamptz
	WindowEnd        pgtype.Timestamptz
	SequenceTokens   string
	SemanticTokens   string
	FrameCount       int64
	PrecomputedScore *float64
}

func buildFrameSequencesBatch(ctx context.Context, pool *pgxpool.Pool, jobs []db.EmbeddingJob, out map[string]db.EmbeddingInput) error {
	rows, err := pool.Query(ctx, `
SELECT
  session_key AS query_key,
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
WHERE session_key = ANY($1::text[])
`, sourceKeys(jobs))
	if err != nil {
		return fmt.Errorf("frame_sequence batch query failed: %w", err)
	}
	defer rows.Close()

	scorer, scorerErr := sequenceScorerCache.Get(ctx, pool)
	for rows.Next() {
		var row FrameSequenceRow
		if err := rows.Scan(
			&row.QueryKey,
			&row.SessionKey,
			&row.SourceMAC,
			&row.SensorID,
			&row.LocationID,
			&row.WindowStart,
			&row.WindowEnd,
			&row.SequenceTokens,
			&row.SemanticTokens,
			&row.FrameCount,
		); err != nil {
			return fmt.Errorf("scan frame_sequence row: %w", err)
		}
		if scorerErr == nil {
			score := scorer.ScoreText(row.SequenceTokens)
			row.PrecomputedScore = &score
		}
		out[row.QueryKey] = frameSequenceRowToInput(row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read frame_sequence rows: %w", err)
	}
	return nil
}

func frameSequenceRowToInput(row FrameSequenceRow) db.EmbeddingInput {
	lines := []string{"kind: frame_sequence"}
	tokenSource := strings.TrimSpace(row.SemanticTokens)
	if tokenSource == "" {
		tokenSource = row.SequenceTokens
	}
	lines = append(lines, "tokens: "+TruncateTokenSequence(tokenSource, ContentTokenBudget))
	if row.WindowStart.Valid && row.WindowEnd.Valid {
		lines = append(lines, fmt.Sprintf("window_secs: %d", int64(row.WindowEnd.Time.Sub(row.WindowStart.Time).Seconds())))
	}
	if row.PrecomputedScore != nil {
		lines = append(lines, fmt.Sprintf("log_prob: %.6f", *row.PrecomputedScore))
	}
	lines = append(lines, fmt.Sprintf("frame_count: %d", row.FrameCount))
	return db.EmbeddingInput{
		Text:             strings.Join(lines, "\n"),
		SourceObservedAt: optionalTime(row.WindowStart.Valid, row.WindowStart.Time),
		SourceSensorID:   row.SensorID,
		SourceLocationID: row.LocationID,
		SourceMAC:        row.SourceMAC,
	}
}
