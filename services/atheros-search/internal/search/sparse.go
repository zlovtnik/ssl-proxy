package search

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func Sparse(ctx context.Context, pool *pgxpool.Pool, query string, opts Options) ([]RawResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
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
			return results[i].SourceKey < results[j].SourceKey
		}
		return results[i].KeywordRank > results[j].KeywordRank
	})
	limit := opts.TopK * 4
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func sparseKind(ctx context.Context, pool *pgxpool.Pool, query, kind string, opts Options) ([]RawResult, error) {
	switch kind {
	case "event":
		return sparseEvents(ctx, pool, query, opts)
	case "device":
		return sparseDevices(ctx, pool, query, opts)
	case "behaviour_window":
		return sparseBehaviours(ctx, pool, query, opts)
	case "frame_sequence":
		return sparseSequences(ctx, pool, query, opts)
	default:
		return nil, nil
	}
}

func sparseEvents(ctx context.Context, pool *pgxpool.Pool, query string, opts Options) ([]RawResult, error) {
	args, filter, limitParam := sparseEventArgs(query, opts)
	matchClause := sparseEventMatchClause(query)
	rankExpr := sparseEventRankExpr(query)

	where := WhereSQL([]string{matchClause, "se.status = 'batched'"}, filter.Clauses)
	sql := fmt.Sprintf(`
SELECT
  wf.dedupe_key,
  'sync_events'::text as source_table,
  'event'::text as source_kind,
  coalesce(wf.source_mac, '') as source_mac,
  coalesce(wf.location_id, '') as location_id,
  coalesce(wf.sensor_id, '') as sensor_id,
  se.observed_at,
  coalesce(wf.bssid, wf.destination_bssid, '') as bssid,
  coalesce(wf.ssid, '') as ssid,
  coalesce(wf.frame_subtype, '') as frame_subtype,
  0::real as cosine_similarity,
  %s as keyword_rank,
  coalesce(jsonb_path_query_array(%s, '$[*]'), '[]'::jsonb)::text as tags_json,
  %s::text as detail_json
FROM wireless_frames_expanded wf
JOIN sync_events_expanded se ON se.dedupe_key = wf.dedupe_key
%s
ORDER BY keyword_rank DESC, se.observed_at DESC
LIMIT $%d`, rankExpr, wirelessTagsSQL, compactEventDetailSQL, where, limitParam)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []RawResult
	for rows.Next() {
		result, err := scanSparse(rows)
		if err != nil {
			return nil, err
		}
		result.Score = result.KeywordRank
		results = append(results, result)
	}
	return results, rows.Err()
}

func sparseDevices(ctx context.Context, pool *pgxpool.Pool, query string, opts Options) ([]RawResult, error) {
	searchText := "lower(concat_ws(' ', d.mac_id, d.display_name, d.username, d.hostname, d.os_hint, d.mac_hint))"
	args, filter, limitParam := sparseSourceArgs(query, opts, func(start int) SQLFilter {
		return BuildSourceFilters(opts.Filters, start, "d.mac_id", "", "", "d.last_seen")
	})
	where := WhereSQL([]string{sparseSourceMatchClause(query, searchText)}, filter.Clauses)
	rankExpr := sparseSourceRankExpr(query, searchText)
	sql := fmt.Sprintf(`
SELECT
  d.mac_id,
  'devices'::text as source_table,
  'device'::text as source_kind,
  d.mac_id as source_mac,
  ''::text as location_id,
  ''::text as sensor_id,
  d.last_seen as observed_at,
  ''::text as bssid,
  ''::text as ssid,
  ''::text as frame_subtype,
  0::real as cosine_similarity,
  %s as keyword_rank,
  '[]'::jsonb::text as tags_json,
  jsonb_build_object(
    'display_name', d.display_name,
    'username', d.username,
    'hostname', d.hostname,
    'os_hint', d.os_hint,
    'mac_hint', d.mac_hint
  )::text as detail_json
FROM devices d
%s
ORDER BY keyword_rank DESC, d.last_seen DESC
LIMIT $%d`, rankExpr, where, limitParam)
	return scanSparseRows(ctx, pool, sql, args...)
}

func sparseBehaviours(ctx context.Context, pool *pgxpool.Pool, query string, opts Options) ([]RawResult, error) {
	searchText := "lower(concat_ws(' ', b.snapshot_key, b.source_mac, b.location_id, b.sensor_id, b.embedding_text, b.text_summary, b.protocol_mix::text, b.frame_type_distribution::text, b.mac_rotation_indicators::text))"
	args, filter, limitParam := sparseSourceArgs(query, opts, func(start int) SQLFilter {
		return BuildSourceFilters(opts.Filters, start, "b.source_mac", "b.location_id", "b.sensor_id", "b.window_start")
	})
	where := WhereSQL([]string{sparseSourceMatchClause(query, searchText)}, filter.Clauses)
	rankExpr := sparseSourceRankExpr(query, searchText)
	sql := fmt.Sprintf(`
SELECT
  b.snapshot_key,
  'vec_behaviour_snapshots'::text as source_table,
  'behaviour_window'::text as source_kind,
  coalesce(b.source_mac, '') as source_mac,
  coalesce(b.location_id, '') as location_id,
  coalesce(b.sensor_id, '') as sensor_id,
  b.window_start as observed_at,
  ''::text as bssid,
  ''::text as ssid,
  ''::text as frame_subtype,
  0::real as cosine_similarity,
  %s as keyword_rank,
  '[]'::jsonb::text as tags_json,
  jsonb_build_object(
    'snapshot_key', b.snapshot_key,
    'event_count', b.event_count,
    'protocol_mix', b.protocol_mix,
    'frame_type_distribution', b.frame_type_distribution,
    'mac_rotation_indicators', b.mac_rotation_indicators
  )::text as detail_json
FROM vec_behaviour_snapshots_expanded b
%s
ORDER BY keyword_rank DESC, b.window_start DESC
LIMIT $%d`, rankExpr, where, limitParam)
	return scanSparseRows(ctx, pool, sql, args...)
}

func sparseSequences(ctx context.Context, pool *pgxpool.Pool, query string, opts Options) ([]RawResult, error) {
	searchText := "lower(concat_ws(' ', s.session_key, s.source_mac, s.location_id, s.sensor_id, s.sequence_tokens, s.semantic_tokens))"
	args, filter, limitParam := sparseSourceArgs(query, opts, func(start int) SQLFilter {
		return BuildSourceFilters(opts.Filters, start, "s.source_mac", "s.location_id", "s.sensor_id", "s.window_start")
	})
	where := WhereSQL([]string{sparseSourceMatchClause(query, searchText)}, filter.Clauses)
	rankExpr := sparseSourceRankExpr(query, searchText)
	sql := fmt.Sprintf(`
SELECT
  s.session_key,
  'vec_frame_sequences'::text as source_table,
  'frame_sequence'::text as source_kind,
  coalesce(s.source_mac, '') as source_mac,
  coalesce(s.location_id, '') as location_id,
  coalesce(s.sensor_id, '') as sensor_id,
  s.window_start as observed_at,
  ''::text as bssid,
  ''::text as ssid,
  ''::text as frame_subtype,
  0::real as cosine_similarity,
  %s as keyword_rank,
  '[]'::jsonb::text as tags_json,
  jsonb_build_object(
    'session_key', s.session_key,
    'frame_count', s.frame_count,
    'sequence_tokens', s.sequence_tokens,
    'semantic_tokens', s.semantic_tokens
  )::text as detail_json
FROM vec_frame_sequences s
%s
ORDER BY keyword_rank DESC, s.window_start DESC
LIMIT $%d`, rankExpr, where, limitParam)
	return scanSparseRows(ctx, pool, sql, args...)
}

func scanSparseRows(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) ([]RawResult, error) {
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []RawResult
	for rows.Next() {
		result, err := scanSparse(rows)
		if err != nil {
			return nil, err
		}
		result.Score = result.KeywordRank
		results = append(results, result)
	}
	return results, rows.Err()
}

func scanSparse(rows interface {
	Scan(dest ...any) error
}) (RawResult, error) {
	var result RawResult
	var observed pgxNullTime
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
		&result.KeywordRank,
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

func sparseEventArgs(query string, opts Options) ([]any, SQLFilter, int) {
	limit := opts.TopK * 4
	if isWildcardAllSearch(query) {
		args := []any{limit}
		filter := BuildWirelessFilters(opts.Filters, len(args)+1)
		args = append(args, filter.Args...)
		return args, filter, 1
	}

	args := []any{query, limit}
	filter := BuildWirelessFilters(opts.Filters, len(args)+1)
	args = append(args, filter.Args...)
	return args, filter, 2
}

func sparseSourceArgs(query string, opts Options, buildFilter func(start int) SQLFilter) ([]any, SQLFilter, int) {
	limit := opts.TopK * 4
	if isWildcardAllSearch(query) {
		args := []any{limit}
		filter := buildFilter(len(args) + 1)
		args = append(args, filter.Args...)
		return args, filter, 1
	}

	args := []any{query, sparsePattern(query), limit}
	filter := buildFilter(len(args) + 1)
	args = append(args, filter.Args...)
	return args, filter, 3
}

func sparseSourceMatchClause(query, searchText string) string {
	if isWildcardAllSearch(query) {
		return "true"
	}
	return searchText + " ILIKE $2 ESCAPE '\\'"
}

func sparseSourceRankExpr(query, searchText string) string {
	if isWildcardAllSearch(query) {
		return "0.1::real"
	}
	return fmt.Sprintf("greatest(similarity(%s, lower($1)), 0.1)::real", searchText)
}

func sparsePattern(query string) string {
	if isWildcardAllSearch(query) {
		return "%"
	}
	if strings.Contains(query, "*") {
		query = strings.ReplaceAll(query, "*", "%")
		return query
	}
	return "%" + escapeLike(query) + "%"
}

func sparseEventMatchClause(query string) string {
	if isWildcardAllSearch(query) {
		return "true"
	}
	if strings.ContainsAny(query, "*%") {
		return "lower(concat_ws(' ', wf.sensor_id, wf.source_mac, wf.bssid, wf.destination_bssid, wf.ssid, wf.wps_device_name, wf.wps_manufacturer, wf.wps_model_name, wf.device_fingerprint, wf.app_protocol, wf.src_ip, wf.dst_ip, wf.username)) like lower(replace($1, '*', '%'))"
	}
	return "wf.search_tsv @@ plainto_tsquery('simple', $1)"
}

func sparseEventRankExpr(query string) string {
	if isWildcardAllSearch(query) {
		return "0.1::real"
	}
	return `case
    when wf.search_tsv @@ plainto_tsquery('simple', $1)
    then ts_rank_cd(wf.search_tsv, plainto_tsquery('simple', $1))::real
    else 0.1::real
  end`
}

func BuildSourceFilters(filters *searchv1.SearchFilters, start int, sourceMACColumn, locationColumn, sensorColumn, observedColumn string) SQLFilter {
	if filters == nil {
		return SQLFilter{}
	}
	next := start
	out := SQLFilter{}
	add := func(clause string, value any) {
		out.Clauses = append(out.Clauses, fmt.Sprintf(clause, next))
		out.Args = append(out.Args, value)
		next++
	}
	if locationColumn != "" && len(filters.LocationIds) > 0 {
		add("coalesce("+locationColumn+", '') = any($%d::text[])", filters.LocationIds)
	}
	if sensorColumn != "" && len(filters.SensorIds) > 0 {
		add("coalesce("+sensorColumn+", '') = any($%d::text[])", filters.SensorIds)
	}
	if sourceMACColumn != "" {
		sourceMACs := filterSourceMACs(filters)
		if len(sourceMACs) > 0 {
			add("lower("+sourceMACColumn+") = any($%d::text[])", sourceMACs)
		}
	}
	if observedColumn != "" && filters.ObservedAfter != nil {
		add(observedColumn+" >= $%d", filters.ObservedAfter.AsTime())
	}
	if observedColumn != "" && filters.ObservedBefore != nil {
		add(observedColumn+" <= $%d", filters.ObservedBefore.AsTime())
	}
	return out
}
