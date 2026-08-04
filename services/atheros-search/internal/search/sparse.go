package search

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

func Sparse(ctx context.Context, pool *sql.DB, query string, opts Options) ([]RawResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	if err := ensureDB(pool); err != nil {
		return nil, err
	}
	results := make([]RawResult, 0, opts.TopK*len(opts.Kinds))
	for _, kind := range opts.Kinds {
		kindResults, err := sparseKind(ctx, pool, query, kind, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, kindResults...)
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].KeywordRank == results[j].KeywordRank {
			if equalTime(results[i].ObservedAt, results[j].ObservedAt) {
				return results[i].SourceKey < results[j].SourceKey
			}
			return timeAfter(results[i].ObservedAt, results[j].ObservedAt)
		}
		return results[i].KeywordRank > results[j].KeywordRank
	})
	return filterResults(results, opts.Filters, opts.TopK*4), nil
}

func sparseKind(ctx context.Context, pool *sql.DB, query, kind string, opts Options) ([]RawResult, error) {
	if _, ok := vectorTableByKind[kind]; !ok {
		return nil, fmt.Errorf("unsupported sparse search kind %q", kind)
	}
	overfetch := opts.TopK * opts.OverfetchFactor
	if overfetch < opts.TopK*4 {
		overfetch = opts.TopK * 4
	}
	if overfetch > 5000 {
		overfetch = 5000
	}
	if isWildcardAllSearch(query) {
		return sparseWildcard(ctx, pool, kind, opts, overfetch)
	}
	patterns := sparseTokenPatterns(query)
	if len(patterns) == 0 {
		return nil, nil
	}

	clauses := make([]string, 0, len(patterns))
	args := make([]any, 0, len(patterns)+2)
	for _, pattern := range patterns {
		clauses = append(clauses, "t.token LIKE ? ESCAPE '\\\\'")
		args = append(args, pattern)
	}
	args = append(args, kind, overfetch)
	querySQL := fmt.Sprintf(`
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
  CAST(0 AS FLOAT),
  CAST(ranked.keyword_rank AS FLOAT),
  COALESCE(CAST(d.tags AS CHAR), '[]'),
  COALESCE(CAST(d.detail_json AS CHAR), '{}'),
  COALESCE(d.security_flags, 0),
  COALESCE(d.handshake_captured, 0)
FROM (
  SELECT t.document_id, SUM(t.term_frequency) AS keyword_rank
  FROM search_document_tokens t
  JOIN search_documents filter_doc ON filter_doc.document_id = t.document_id
  WHERE (%s) AND filter_doc.source_kind = ? AND filter_doc.status = 'active'
  GROUP BY t.document_id
  ORDER BY keyword_rank DESC, t.document_id ASC
  LIMIT ?
) ranked
JOIN search_documents d ON d.document_id = ranked.document_id
ORDER BY ranked.keyword_rank DESC, d.observed_at DESC, d.source_key ASC`, strings.Join(clauses, " OR "))
	return scanSparseRows(ctx, pool, querySQL, opts, args...)
}

func sparseWildcard(ctx context.Context, pool *sql.DB, kind string, opts Options, limit int) ([]RawResult, error) {
	query := `
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
  CAST(0 AS FLOAT),
  CAST(0.1 AS FLOAT),
  COALESCE(CAST(d.tags AS CHAR), '[]'),
  COALESCE(CAST(d.detail_json AS CHAR), '{}'),
  COALESCE(d.security_flags, 0),
  COALESCE(d.handshake_captured, 0)
FROM search_documents d
WHERE d.source_kind = ? AND d.status = 'active'
ORDER BY d.observed_at DESC, d.source_key ASC
LIMIT ?`
	return scanSparseRows(ctx, pool, query, opts, kind, limit)
}

func scanSparseRows(ctx context.Context, pool *sql.DB, query string, opts Options, args ...any) ([]RawResult, error) {
	rows, err := pool.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := make([]RawResult, 0)
	for rows.Next() {
		result, err := scanSparseResult(rows)
		if err != nil {
			return nil, err
		}
		if !resultMatchesFilters(result, opts.Filters) {
			continue
		}
		result.Score = result.KeywordRank
		results = append(results, result)
		if len(results) >= opts.TopK*4 {
			break
		}
	}
	return results, rows.Err()
}

func scanSparseResult(row scanner) (RawResult, error) {
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
		&result.KeywordRank,
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

func sparseTokenPatterns(query string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, raw := range strings.Fields(strings.ToLower(query)) {
		var builder strings.Builder
		for _, char := range raw {
			switch {
			case unicode.IsLetter(char), unicode.IsDigit(char), char == '_', char == '-', char == ':':
				builder.WriteRune(char)
			case char == '*', char == '%':
				builder.WriteRune('%')
			}
		}
		pattern := strings.Trim(builder.String(), "%")
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(builder.String(), "%") {
			pattern += "%"
		}
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	return out
}

func sparsePattern(query string) string {
	patterns := sparseTokenPatterns(query)
	if len(patterns) == 0 {
		return "%"
	}
	return patterns[0]
}

func equalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Equal(*right)
}

func timeAfter(left, right *time.Time) bool {
	if left == nil {
		return false
	}
	if right == nil {
		return true
	}
	return left.After(*right)
}
