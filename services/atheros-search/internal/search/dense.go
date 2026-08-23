package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

const embeddingDimensions = 768

var vectorTableByKind = map[string]string{
	"event":            "search_vectors_event",
	"device":           "search_vectors_device",
	"behaviour_window": "search_vectors_behaviour",
	"frame_sequence":   "search_vectors_sequence",
}

func Dense(ctx context.Context, pool *sql.DB, qvec []float32, model string, opts Options) ([]RawResult, error) {
	if err := validateVector(qvec); err != nil {
		return nil, err
	}
	out := make([]RawResult, 0, opts.TopK*len(opts.Kinds))
	for _, kind := range opts.Kinds {
		results, err := denseKind(ctx, pool, qvec, model, kind, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, results...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CosineSimilarity == out[j].CosineSimilarity {
			return out[i].SourceKey < out[j].SourceKey
		}
		return out[i].CosineSimilarity > out[j].CosineSimilarity
	})
	return filterResults(out, opts.Filters, opts.TopK*4), nil
}

func denseKind(ctx context.Context, pool *sql.DB, qvec []float32, model, kind string, opts Options) ([]RawResult, error) {
	table, ok := vectorTableByKind[kind]
	if !ok {
		return nil, fmt.Errorf("unsupported dense search kind %q", kind)
	}
	overfetch := opts.TopK * opts.OverfetchFactor
	if overfetch < opts.TopK {
		overfetch = opts.TopK
	}
	if overfetch > 5000 {
		overfetch = 5000
	}
	vector := VectorLiteral(qvec)
	query := denseKindQuery(table)

	rows, err := pool.QueryContext(ctx, query, vector, overfetch, model)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]RawResult, 0, overfetch)
	for rows.Next() {
		result, err := scanDenseResult(rows)
		if err != nil {
			return nil, err
		}
		if result.CosineSimilarity < opts.MinSimilarity || !resultMatchesFilters(result, opts.Filters) {
			continue
		}
		result.Score = result.CosineSimilarity
		results = append(results, result)
		if len(results) >= opts.TopK*4 {
			break
		}
	}
	return results, rows.Err()
}

func denseKindQuery(table string) string {
	return fmt.Sprintf(`
SELECT
  d.source_key,
  d.source_table,
  d.source_kind,
  COALESCE(d.source_mac, ''),
  COALESCE(d.location_id, ''),
  COALESCE(d.sensor_id, ''),
  d.observed_at,
  COALESCE(d.bssid, ''),
  COALESCE(d.ssid, ''),
  COALESCE(d.frame_subtype, ''),
  CAST(1.0 - nearest.cosine_distance AS DOUBLE PRECISION),
  COALESCE(d.tags::text, '[]'),
  COALESCE(d.detail_json::text, '{}'),
  COALESCE(d.security_flags, 0),
  COALESCE(d.handshake_captured, false)
FROM (
  SELECT
    document_id,
    embedding_model,
    embedding <=> $1::vector AS cosine_distance
  FROM atheros_search.%s
  ORDER BY embedding <=> $1::vector ASC
  LIMIT $2
) nearest
JOIN atheros_search.search_documents d ON d.document_id = nearest.document_id
WHERE nearest.embedding_model = $3 AND d.status = 'active'
ORDER BY nearest.cosine_distance ASC, d.source_key ASC`, table)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDenseResult(row scanner) (RawResult, error) {
	var result RawResult
	var observed sql.NullTime
	var tagsJSON, detailJSON string
	var securityFlags int64
	var handshake bool
	err := row.Scan(
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
		&detailJSON,
		&securityFlags,
		&handshake,
	)
	if err != nil {
		return result, err
	}
	if observed.Valid {
		value := observed.Time.UTC()
		result.ObservedAt = &value
	}
	result.Tags = parseTagsJSON(tagsJSON)
	result.DetailJSON = normalizeJSONObject(detailJSON)
	result.securityFlags = int32(securityFlags)
	result.handshakeCaptured = handshake
	return result, nil
}

func validateVector(vector []float32) error {
	if len(vector) != embeddingDimensions {
		return fmt.Errorf("embedding vector has %d dimensions, expected %d", len(vector), embeddingDimensions)
	}
	for i, value := range vector {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return fmt.Errorf("embedding vector contains a non-finite value at index %d", i)
		}
	}
	return nil
}

func parseTagsJSON(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || value == "null" || value == "[]" {
		return nil
	}
	var tags []string
	if err := json.Unmarshal([]byte(value), &tags); err != nil {
		return nil
	}
	return TagsFromJSON(tags)
}

func normalizeJSONObject(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "null" || !json.Valid([]byte(value)) {
		return "{}"
	}
	return value
}

func ensureDB(pool *sql.DB) error {
	if pool == nil {
		return errors.New("Postgres pool is not initialized")
	}
	return nil
}
