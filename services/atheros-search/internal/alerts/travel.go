package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TravelObservation struct {
	ClusterID  int64
	SourceMAC  string
	SensorID   string
	LocationID string
	ObservedAt time.Time
	Latitude   float64
	Longitude  float64
}

func CheckRFImpossibleTravel(ctx context.Context, pool *pgxpool.Pool, cfg Config) (int, error) {
	rows, err := pool.Query(ctx, `
WITH cluster_macs AS (
  SELECT cluster_id, lower(mac) AS source_mac
  FROM device_identity_clusters
  CROSS JOIN LATERAL unnest(mac_ids) AS cluster_mac(mac)
),
recent AS (
  SELECT DISTINCT ON (
    cm.cluster_id,
    s.sensor_id,
    coalesce(s.location_id, ''),
    date_trunc('minute', s.observed_at)
  )
    cm.cluster_id,
    cm.source_mac,
    loc.sensor_id,
    loc.location_id,
    s.observed_at,
    loc.latitude,
    loc.longitude
  FROM cluster_macs cm
  JOIN sync_events_expanded s ON lower(s.source_mac) = cm.source_mac
  JOIN vec_rf_sensor_locations loc
    ON loc.enabled
   AND loc.sensor_id = s.sensor_id
   AND loc.location_id = coalesce(s.location_id, '')
  WHERE s.stream_name = 'wireless.audit'
    AND s.status = 'batched'
    AND s.observed_at >= now() - interval '1 hour'
  ORDER BY
    cm.cluster_id,
    s.sensor_id,
    coalesce(s.location_id, ''),
    date_trunc('minute', s.observed_at),
    s.observed_at ASC
)
SELECT cluster_id, source_mac, sensor_id, location_id, observed_at, latitude, longitude
FROM recent
ORDER BY cluster_id, observed_at ASC
LIMIT 10000
`)
	if err != nil {
		return 0, fmt.Errorf("rf impossible travel query failed: %w", err)
	}
	defer rows.Close()

	observations, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (TravelObservation, error) {
		var obs TravelObservation
		err := row.Scan(&obs.ClusterID, &obs.SourceMAC, &obs.SensorID, &obs.LocationID, &obs.ObservedAt, &obs.Latitude, &obs.Longitude)
		return obs, err
	})
	if err != nil {
		return 0, fmt.Errorf("collect rf observations: %w", err)
	}

	inserted := 0
	var previous *TravelObservation
	for i := range observations {
		current := &observations[i]
		if previous != nil && previous.ClusterID == current.ClusterID {
			if speed := ImpossibleTravelSpeedMPS(*previous, *current); speed != nil && *speed > cfg.TravelMaxSpeedMPS {
				count, err := insertRFImpossibleTravelAlert(ctx, pool, cfg, *previous, *current, *speed)
				if err != nil {
					return inserted, err
				}
				inserted += count
			}
		}
		previous = current
	}
	return inserted, nil
}

func insertRFImpossibleTravelAlert(ctx context.Context, pool *pgxpool.Pool, cfg Config, prev, current TravelObservation, speed float64) (int, error) {
	distance := HaversineMeters(prev.Latitude, prev.Longitude, current.Latitude, current.Longitude)
	elapsed := current.ObservedAt.Sub(prev.ObservedAt).Seconds()
	metadata, err := json.Marshal(map[string]any{
		"cluster_id":       current.ClusterID,
		"source_mac":       current.SourceMAC,
		"from_sensor_id":   prev.SensorID,
		"from_location_id": prev.LocationID,
		"to_sensor_id":     current.SensorID,
		"to_location_id":   current.LocationID,
		"from_observed_at": prev.ObservedAt,
		"to_observed_at":   current.ObservedAt,
		"distance_m":       distance,
		"elapsed_secs":     elapsed,
		"speed_mps":        speed,
		"max_speed_mps":    cfg.TravelMaxSpeedMPS,
	})
	if err != nil {
		return 0, fmt.Errorf("marshal rf impossible travel metadata for cluster %d source_mac %s speed %v: %w", current.ClusterID, current.SourceMAC, speed, err)
	}
	tag, err := pool.Exec(ctx, `
INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
SELECT
  'rf_impossible_travel',
  $1,
  $2,
  $3,
  $4,
  concat('RF impossible travel for cluster ', $5::text, ': speed_mps=', round($4::numeric, 2)),
  $6::jsonb
WHERE NOT EXISTS (
  SELECT 1 FROM vec_alerts a
  WHERE a.alert_type = 'rf_impossible_travel'
    AND a.metadata->>'cluster_id' = $5::text
    AND a.created_at > now() - interval '1 hour'
)
`, current.SourceMAC, current.SensorID, current.LocationID, speed, current.ClusterID, string(metadata))
	if err != nil {
		return 0, fmt.Errorf("insert rf impossible travel alert: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func HaversineMeters(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusM = 6371000.0
	phi1 := lat1 * math.Pi / 180.0
	phi2 := lat2 * math.Pi / 180.0
	dPhi := (lat2 - lat1) * math.Pi / 180.0
	dLambda := (lon2 - lon1) * math.Pi / 180.0
	a := math.Sin(dPhi/2)*math.Sin(dPhi/2) + math.Cos(phi1)*math.Cos(phi2)*math.Sin(dLambda/2)*math.Sin(dLambda/2)
	return earthRadiusM * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func ImpossibleTravelSpeedMPS(prev, current TravelObservation) *float64 {
	if prev.SensorID == current.SensorID && prev.LocationID == current.LocationID {
		return nil
	}
	elapsed := current.ObservedAt.Sub(prev.ObservedAt).Seconds()
	if elapsed <= 0 {
		return nil
	}
	distance := HaversineMeters(prev.Latitude, prev.Longitude, current.Latitude, current.Longitude)
	speed := distance / elapsed
	return &speed
}
