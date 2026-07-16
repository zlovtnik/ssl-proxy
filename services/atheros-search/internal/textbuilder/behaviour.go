package textbuilder

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

type BehaviourWindowRow struct {
	QueryKey              string
	EmbeddingText         string
	TextSummary           string
	WindowStart           pgtype.Timestamptz
	WindowEnd             pgtype.Timestamptz
	SensorID              string
	LocationID            string
	SourceMAC             string
	EventCount            int64
	ProtocolMix           string
	FrameTypeDistribution string
	SignalMinDBM          string
	SignalMaxDBM          string
	SignalAvgDBM          string
	RetryCount            int64
	ProtectedCount        int64
	UnprotectedCount      int64
	UniqueBSSIDCount      int64
	MacRotationIndicators string
}

func buildBehaviourWindowsBatch(ctx context.Context, pool *pgxpool.Pool, jobs []db.EmbeddingJob, out map[string]db.EmbeddingInput) error {
	rows, err := pool.Query(ctx, `
SELECT
  CASE WHEN snapshot_key = ANY($1::text[]) THEN snapshot_key ELSE snapshot_id::text END AS query_key,
  coalesce(embedding_text, ''),
  coalesce(text_summary, ''),
  window_start,
  window_end,
  coalesce(sensor_id, ''),
  coalesce(location_id, ''),
  lower(coalesce(source_mac, '')),
  coalesce(event_count, 0),
  coalesce(protocol_mix::text, ''),
  coalesce(frame_type_distribution::text, ''),
  coalesce(signal_min_dbm::text, ''),
  coalesce(signal_max_dbm::text, ''),
  coalesce(signal_avg_dbm::text, ''),
  coalesce(retry_count, 0),
  coalesce(protected_count, 0),
  coalesce(unprotected_count, 0),
  coalesce(unique_bssid_count, 0),
  coalesce(mac_rotation_indicators::text, '')
FROM vec_behaviour_snapshots_expanded
WHERE snapshot_id::text = ANY($1::text[])
   OR snapshot_key = ANY($1::text[])
`, sourceKeys(jobs))
	if err != nil {
		return fmt.Errorf("behaviour_window batch query failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var row BehaviourWindowRow
		if err := rows.Scan(
			&row.QueryKey,
			&row.EmbeddingText,
			&row.TextSummary,
			&row.WindowStart,
			&row.WindowEnd,
			&row.SensorID,
			&row.LocationID,
			&row.SourceMAC,
			&row.EventCount,
			&row.ProtocolMix,
			&row.FrameTypeDistribution,
			&row.SignalMinDBM,
			&row.SignalMaxDBM,
			&row.SignalAvgDBM,
			&row.RetryCount,
			&row.ProtectedCount,
			&row.UnprotectedCount,
			&row.UniqueBSSIDCount,
			&row.MacRotationIndicators,
		); err != nil {
			return fmt.Errorf("scan behaviour_window row: %w", err)
		}
		out[row.QueryKey] = behaviourRowToInput(row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read behaviour_window rows: %w", err)
	}
	return nil
}

func behaviourRowToInput(row BehaviourWindowRow) db.EmbeddingInput {
	observed := optionalTime(row.WindowStart.Valid, row.WindowStart.Time)
	text := prebuiltKindText("behaviour_window", row.EmbeddingText, observed)
	if text == "" {
		text = prebuiltKindText("behaviour_window", row.TextSummary, observed)
	}
	if text == "" {
		text = buildSnapshotFallback(row)
	} else if epm := EventsPerMinute(row.EventCount, observed, optionalTime(row.WindowEnd.Valid, row.WindowEnd.Time)); epm > 0 && !strings.Contains(text, "events_per_minute:") {
		text += fmt.Sprintf("\nevents_per_minute: %.1f", epm)
		text = clampDefault(text)
	}
	return db.EmbeddingInput{
		Text:             text,
		SourceObservedAt: observed,
		SourceSensorID:   row.SensorID,
		SourceLocationID: row.LocationID,
		SourceMAC:        row.SourceMAC,
	}
}

func buildSnapshotFallback(row BehaviourWindowRow) string {
	jsonFieldBudget := wordBudget(ContentTokenBudget / 4)
	lines := []string{"kind: behaviour_window"}
	if row.WindowStart.Valid {
		lines = append(lines, TemporalContextLines(row.WindowStart.Time)...)
	}
	AppendValue(&lines, "source_mac", row.SourceMAC)
	AppendValue(&lines, "location_id", row.LocationID)
	AppendValue(&lines, "sensor_id", row.SensorID)
	if row.WindowStart.Valid {
		AppendValue(&lines, "window_start", row.WindowStart.Time.Format(timeFormatRFC3339))
	}
	if row.WindowEnd.Valid {
		AppendValue(&lines, "window_end", row.WindowEnd.Time.Format(timeFormatRFC3339))
	}
	AppendValue(&lines, "event_count", fmt.Sprint(row.EventCount))
	AppendValue(&lines, "protocol_mix", TruncateWords(NormalizeJSON(row.ProtocolMix), jsonFieldBudget))
	AppendValue(&lines, "frame_type_distribution", TruncateWords(NormalizeJSON(row.FrameTypeDistribution), jsonFieldBudget))
	AppendValue(&lines, "signal_min_dbm", row.SignalMinDBM)
	AppendValue(&lines, "signal_max_dbm", row.SignalMaxDBM)
	AppendValue(&lines, "signal_avg_dbm", row.SignalAvgDBM)
	AppendValue(&lines, "retry_count", fmt.Sprint(row.RetryCount))
	AppendValue(&lines, "protected_count", fmt.Sprint(row.ProtectedCount))
	AppendValue(&lines, "unprotected_count", fmt.Sprint(row.UnprotectedCount))
	AppendValue(&lines, "unique_bssid_count", fmt.Sprint(row.UniqueBSSIDCount))
	AppendValue(&lines, "mac_rotation_indicators", TruncateWords(NormalizeJSON(row.MacRotationIndicators), jsonFieldBudget))
	if epm := EventsPerMinute(row.EventCount, optionalTime(row.WindowStart.Valid, row.WindowStart.Time), optionalTime(row.WindowEnd.Valid, row.WindowEnd.Time)); epm > 0 {
		lines = append(lines, fmt.Sprintf("events_per_minute: %.1f", epm))
	}
	return clampDefault(strings.Join(lines, "\n"))
}
