package textbuilder

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

type TimingProfileRow struct {
	QueryKey               string
	SourceMAC              string
	SensorID               string
	LocationID             string
	WindowStart            pgtype.Timestamptz
	TSFTP50US              string
	TSFTP95US              string
	TSFTJitter             string
	WallP50MS              string
	WallJitterMS           string
	BeaconIntervalMedianMS string
	BeaconJitterMS         string
	EmbeddingText          string
}

func buildTimingProfilesBatch(ctx context.Context, pool *pgxpool.Pool, jobs []db.EmbeddingJob, out map[string]db.EmbeddingInput) error {
	rows, err := pool.Query(ctx, `
SELECT
  CASE WHEN profile_key = ANY($1::text[]) THEN profile_key ELSE profile_id::text END AS query_key,
  lower(coalesce(source_mac, '')),
  coalesce(sensor_id, ''),
  coalesce(location_id, ''),
  window_start,
  coalesce(tsft_p50_us::text, ''),
  coalesce(tsft_p95_us::text, ''),
  coalesce(tsft_jitter::text, ''),
  coalesce(wall_p50_ms::text, ''),
  coalesce(wall_jitter_ms::text, ''),
  coalesce(beacon_interval_median_ms::text, ''),
  coalesce(beacon_jitter_ms::text, ''),
  coalesce(embedding_text, '')
FROM vec_timing_profiles_expanded
WHERE profile_id::text = ANY($1::text[])
   OR profile_key = ANY($1::text[])
`, sourceKeys(jobs))
	if err != nil {
		return fmt.Errorf("timing_profile batch query failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var row TimingProfileRow
		if err := rows.Scan(
			&row.QueryKey,
			&row.SourceMAC,
			&row.SensorID,
			&row.LocationID,
			&row.WindowStart,
			&row.TSFTP50US,
			&row.TSFTP95US,
			&row.TSFTJitter,
			&row.WallP50MS,
			&row.WallJitterMS,
			&row.BeaconIntervalMedianMS,
			&row.BeaconJitterMS,
			&row.EmbeddingText,
		); err != nil {
			return fmt.Errorf("scan timing_profile row: %w", err)
		}
		out[row.QueryKey] = timingProfileRowToInput(row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read timing_profile rows: %w", err)
	}
	return nil
}

func timingProfileRowToInput(row TimingProfileRow) db.EmbeddingInput {
	observed := optionalTime(row.WindowStart.Valid, row.WindowStart.Time)
	text := prebuiltKindText("timing_profile", row.EmbeddingText, observed)
	if text == "" {
		lines := []string{"kind: timing_profile"}
		if row.WindowStart.Valid {
			lines = append(lines, TemporalContextLines(row.WindowStart.Time)...)
		}
		AppendValue(&lines, "tsft_p50_us", row.TSFTP50US)
		AppendValue(&lines, "tsft_p95_us", row.TSFTP95US)
		AppendValue(&lines, "tsft_jitter", row.TSFTJitter)
		AppendValue(&lines, "wall_p50_ms", row.WallP50MS)
		AppendValue(&lines, "wall_jitter_ms", row.WallJitterMS)
		AppendValue(&lines, "beacon_interval_ms", row.BeaconIntervalMedianMS)
		AppendValue(&lines, "beacon_jitter_ms", row.BeaconJitterMS)
		text = strings.Join(lines, "\n")
	}
	text = clampDefault(text)
	return db.EmbeddingInput{
		Text:             text,
		SourceObservedAt: observed,
		SourceSensorID:   row.SensorID,
		SourceLocationID: row.LocationID,
		SourceMAC:        row.SourceMAC,
	}
}
