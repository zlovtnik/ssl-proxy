package search

import (
	"context"
	"database/sql"
	"strings"
	"time"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

type SuggestCache struct {
	ExpiresAt time.Time
	Response  *searchv1.SuggestFiltersResponse
}

const suggestSSIDSQL = `
SELECT DISTINCT ssid
FROM atheros_search.search_documents
WHERE ssid IS NOT NULL
  AND status = 'active'
  AND ($1 = '' OR LOWER(ssid) LIKE $2 ESCAPE E'\\\\')
ORDER BY ssid
LIMIT 50`

func SuggestFilters(ctx context.Context, pool *sql.DB, prefix string) (*searchv1.SuggestFiltersResponse, error) {
	resp := &searchv1.SuggestFiltersResponse{}
	normalizedPrefix := strings.ToLower(strings.TrimSpace(prefix))
	pattern := escapeLike(normalizedPrefix) + "%"
	if err := scanDistinct(ctx, pool, suggestSSIDSQL, &resp.Ssids, normalizedPrefix, pattern); err != nil {
		return nil, err
	}
	for _, item := range []struct {
		column string
		target *[]string
	}{
		{column: "location_id", target: &resp.LocationIds},
		{column: "sensor_id", target: &resp.SensorIds},
		{column: "frame_subtype", target: &resp.FrameSubtypes},
	} {
		query := `SELECT DISTINCT ` + item.column + `
FROM atheros_search.search_documents
WHERE ` + item.column + ` IS NOT NULL
  AND status = 'active'
  AND ($1 = '' OR LOWER(` + item.column + `) LIKE $2 ESCAPE E'\\\\')
ORDER BY ` + item.column + `
LIMIT 50`
		if err := scanDistinct(ctx, pool, query, item.target, normalizedPrefix, pattern); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func scanDistinct(ctx context.Context, pool *sql.DB, query string, target *[]string, args ...any) error {
	rows, err := pool.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return err
		}
		*target = append(*target, value)
	}
	return rows.Err()
}
