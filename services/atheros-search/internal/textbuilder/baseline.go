package textbuilder

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

type BaselineProfileRow struct {
	QueryKey  string
	BSSID     string
	Metric    string
	P5        string
	P50       string
	P95       string
	UpdatedAt pgtype.Timestamptz
}

func buildBaselineProfilesBatch(ctx context.Context, pool *pgxpool.Pool, jobs []db.EmbeddingJob, out map[string]db.EmbeddingInput) error {
	rows, err := pool.Query(ctx, `
SELECT
  bssid AS query_key,
  bssid,
  metric,
  coalesce(p5::text, ''),
  coalesce(p50::text, ''),
  coalesce(p95::text, ''),
  updated_at
FROM vec_baseline_profiles
WHERE bssid = ANY($1::text[])
`, sourceKeys(jobs))
	if err != nil {
		return fmt.Errorf("baseline_profile batch query failed: %w", err)
	}
	defer rows.Close()

	grouped := map[string][]BaselineProfileRow{}
	for rows.Next() {
		var row BaselineProfileRow
		if err := rows.Scan(&row.QueryKey, &row.BSSID, &row.Metric, &row.P5, &row.P50, &row.P95, &row.UpdatedAt); err != nil {
			return fmt.Errorf("scan baseline_profile row: %w", err)
		}
		grouped[row.QueryKey] = append(grouped[row.QueryKey], row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read baseline_profile rows: %w", err)
	}
	for key, rows := range grouped {
		out[key] = baselineRowsToInput(rows)
	}
	return nil
}

func baselineRowsToInput(rows []BaselineProfileRow) db.EmbeddingInput {
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Metric < rows[j].Metric
	})
	lines := []string{"kind: baseline_profile"}
	if len(rows) > 0 {
		lines = append(lines, "bssid: "+rows[0].BSSID)
	}
	const maxMetricLines = (ContentTokenBudget - 4) / 8
	for i, row := range rows {
		if i >= maxMetricLines {
			lines = append(lines, fmt.Sprintf("(+%d metrics truncated)", len(rows)-maxMetricLines))
			break
		}
		parts := []string{"metric: " + row.Metric}
		if row.P5 != "" {
			parts = append(parts, "p5: "+row.P5)
		}
		if row.P50 != "" {
			parts = append(parts, "p50: "+row.P50)
		}
		if row.P95 != "" {
			parts = append(parts, "p95: "+row.P95)
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	var latest pgtype.Timestamptz
	for _, row := range rows {
		if row.UpdatedAt.Valid && (!latest.Valid || row.UpdatedAt.Time.After(latest.Time)) {
			latest = row.UpdatedAt
		}
	}
	sourceMAC := ""
	if len(rows) > 0 {
		sourceMAC = rows[0].BSSID
	}
	return db.EmbeddingInput{
		Text:             clampDefault(strings.Join(lines, "\n")),
		SourceObservedAt: optionalTime(latest.Valid, latest.Time),
		SourceMAC:        sourceMAC,
	}
}
