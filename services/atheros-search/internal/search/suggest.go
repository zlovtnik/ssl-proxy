package search

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

type SuggestCache struct {
	ExpiresAt time.Time
	Response  *searchv1.SuggestFiltersResponse
}

func SuggestFilters(ctx context.Context, pool *pgxpool.Pool, prefix string) (*searchv1.SuggestFiltersResponse, error) {
	resp := &searchv1.SuggestFiltersResponse{}
	escapedPrefix := escapeLike(prefix)
	if err := scanDistinct(ctx, pool, "SELECT DISTINCT ssid FROM wireless_frames WHERE ssid IS NOT NULL AND ($1 = '' OR ssid ILIKE $1 || '%' ESCAPE '\\') ORDER BY ssid LIMIT 50", escapedPrefix, &resp.Ssids); err != nil {
		return nil, err
	}
	if err := scanDistinct(ctx, pool, "SELECT DISTINCT location_id FROM wireless_frames WHERE location_id IS NOT NULL AND ($1 = '' OR location_id ILIKE $1 || '%' ESCAPE '\\') ORDER BY location_id LIMIT 50", escapedPrefix, &resp.LocationIds); err != nil {
		return nil, err
	}
	if err := scanDistinct(ctx, pool, "SELECT DISTINCT sensor_id FROM wireless_frames WHERE sensor_id IS NOT NULL AND ($1 = '' OR sensor_id ILIKE $1 || '%' ESCAPE '\\') ORDER BY sensor_id LIMIT 50", escapedPrefix, &resp.SensorIds); err != nil {
		return nil, err
	}
	if err := scanDistinct(ctx, pool, "SELECT DISTINCT frame_subtype FROM wireless_frames WHERE frame_subtype IS NOT NULL AND ($1 = '' OR frame_subtype ILIKE $1 || '%' ESCAPE '\\') ORDER BY frame_subtype LIMIT 50", escapedPrefix, &resp.FrameSubtypes); err != nil {
		return nil, err
	}
	return resp, nil
}

func scanDistinct(ctx context.Context, pool *pgxpool.Pool, sql, prefix string, target *[]string) error {
	rows, err := pool.Query(ctx, sql, prefix)
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
