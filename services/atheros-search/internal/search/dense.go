package search

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Dense(ctx context.Context, pool *pgxpool.Pool, qvec []float32, model string, opts Options) ([]RawResult, error) {
	out := make([]RawResult, 0, opts.TopK*len(opts.Kinds))
	for _, kind := range opts.Kinds {
		results, err := denseKind(ctx, pool, qvec, model, kind, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, results...)
	}
	return out, nil
}

func denseKind(ctx context.Context, pool *pgxpool.Pool, qvec []float32, model, kind string, opts Options) ([]RawResult, error) {
	args := []any{VectorLiteral(qvec), kind, model, opts.TopK * 4}
	embedFilter := BuildEmbeddingFilters(opts.Filters, len(args)+1)
	args = append(args, embedFilter.Args...)
	wirelessFilter := BuildWirelessFilters(opts.Filters, len(args)+1)
	args = append(args, wirelessFilter.Args...)
	baseClauses := []string{
		"e.embedding_kind = $2",
		"e.embedding_model = $3",
		"e.embedding_dimensions = 768",
	}
	if len(wirelessFilter.Clauses) > 0 {
		baseClauses = append(baseClauses, "EXISTS (SELECT 1 FROM sync_events_expanded se"+WhereSQL([]string{
			"e.source_table = 'sync_events'",
			"se.dedupe_key = e.source_key",
		}, wirelessFilter.Clauses)+")")
	}
	where := WhereSQL(baseClauses, embedFilter.Clauses)
	sql := fmt.Sprintf(`
WITH candidates AS (
  SELECT
    e.source_key,
    e.source_table,
    e.embedding_kind,
    e.source_mac,
    e.source_sensor_id,
    e.source_location_id,
    e.source_observed_at,
    (e.embedding::vector(768) <=> $1::vector(768)) AS cosine_distance
  FROM vec_embeddings e
  %s
  ORDER BY e.embedding::vector(768) <=> $1::vector(768)
  LIMIT $4
)
SELECT
  c.source_key,
  c.source_table,
  c.embedding_kind,
  coalesce(c.source_mac, se.source_mac, '') as source_mac,
  coalesce(c.source_location_id, se.location_id, '') as location_id,
  coalesce(c.source_sensor_id, se.sensor_id, '') as sensor_id,
  coalesce(c.source_observed_at, se.observed_at) as observed_at,
  coalesce(se.bssid, se.destination_bssid, '') as bssid,
  coalesce(se.ssid, '') as ssid,
  coalesce(se.frame_subtype, '') as frame_subtype,
  (1.0 - c.cosine_distance)::real as cosine_similarity,
  coalesce(jsonb_path_query_array(%s, '$[*]'), '[]'::jsonb)::text as tags_json,
  %s::text as detail_json
FROM candidates c
LEFT JOIN sync_events_expanded se
  ON c.source_table = 'sync_events'
 AND se.dedupe_key = c.source_key
`, wirelessTagsSQL, compactEventDetailSQL, where)
	sql += `
ORDER BY cosine_similarity DESC
LIMIT $4`

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := []RawResult{}
	for rows.Next() {
		result, err := scanResult(rows)
		if err != nil {
			return nil, err
		}
		if opts.MinSimilarity > 0 && result.CosineSimilarity < opts.MinSimilarity {
			continue
		}
		result.Score = result.CosineSimilarity
		results = append(results, result)
	}
	return results, rows.Err()
}

func scanResult(rows pgx.Rows) (RawResult, error) {
	var result RawResult
	var observed pgtype.Timestamptz
	var tagsJSON string
	err := rows.Scan(
		&result.SourceKey,
		&result.SourceTable,
		&result.SourceKind,
		&result.SourceMAC,
		&result.LocationID,
		&result.SensorID,
		&observed,
		&result.BSSID,
		&result.SSID,
		&result.FrameSubtype,
		&result.CosineSimilarity,
		&tagsJSON,
		&result.DetailJSON,
	)
	if err != nil {
		return result, err
	}
	if observed.Valid {
		result.ObservedAt = &observed.Time
	}
	result.Tags = parseTagsJSON(tagsJSON)
	return result, nil
}

func parseTagsJSON(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || value == "[]" {
		return nil
	}
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	parts := strings.Split(value, ",")
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(part), `"`)
		if part != "" {
			tags = append(tags, part)
		}
	}
	return TagsFromJSON(tags)
}
