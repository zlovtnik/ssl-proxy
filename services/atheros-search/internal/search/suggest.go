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
SELECT DISTINCT filter_value
FROM search_filter_values
WHERE filter_kind = 'ssid'
  AND (? = '' OR normalized_value LIKE ? ESCAPE '\\')
ORDER BY normalized_value, filter_value`

func SuggestFilters(ctx context.Context, pool *sql.DB, prefix string) (*searchv1.SuggestFiltersResponse, error) {
	resp := &searchv1.SuggestFiltersResponse{}
	normalizedPrefix := strings.ToLower(strings.TrimSpace(prefix))
	pattern := escapeLike(normalizedPrefix) + "%"
	if err := scanDistinct(ctx, pool, suggestSSIDSQL, &resp.Ssids, normalizedPrefix, pattern); err != nil {
		return nil, err
	}
	for _, item := range []struct {
		kind   string
		target *[]string
	}{
		{kind: "location_id", target: &resp.LocationIds},
		{kind: "sensor_id", target: &resp.SensorIds},
		{kind: "frame_subtype", target: &resp.FrameSubtypes},
	} {
		if err := scanDistinct(ctx, pool, `
SELECT DISTINCT filter_value
FROM search_filter_values
WHERE filter_kind = ?
  AND (? = '' OR normalized_value LIKE ? ESCAPE '\\')
ORDER BY normalized_value, filter_value
		LIMIT 50`, item.target, item.kind, normalizedPrefix, pattern); err != nil {
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
