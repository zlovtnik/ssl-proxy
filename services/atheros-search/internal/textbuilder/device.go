package textbuilder

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

type DeviceRow struct {
	MACID       string
	DisplayName string
	Username    string
	Hostname    string
	OSHint      string
	MACHint     string
	FirstSeen   pgtype.Timestamptz
	LastSeen    pgtype.Timestamptz
	ClusterSize int32
}

func buildDevicesBatch(ctx context.Context, pool *pgxpool.Pool, jobs []db.EmbeddingJob, out map[string]db.EmbeddingInput) error {
	rows, err := pool.Query(ctx, `
SELECT
  d.mac_id,
  coalesce(d.display_name, ''),
  coalesce(d.username, ''),
  coalesce(d.hostname, ''),
  coalesce(d.os_hint, ''),
  coalesce(d.mac_hint, ''),
  d.first_seen,
  d.last_seen,
  coalesce(dic.size, 1)
FROM devices d
LEFT JOIN device_identity_clusters dic ON d.mac_id = ANY(dic.mac_ids)
WHERE d.mac_id = ANY($1::text[])
`, sourceKeys(jobs))
	if err != nil {
		return fmt.Errorf("device batch query failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var row DeviceRow
		if err := rows.Scan(
			&row.MACID,
			&row.DisplayName,
			&row.Username,
			&row.Hostname,
			&row.OSHint,
			&row.MACHint,
			&row.FirstSeen,
			&row.LastSeen,
			&row.ClusterSize,
		); err != nil {
			return fmt.Errorf("scan device row: %w", err)
		}
		out[row.MACID] = deviceRowToInput(row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read device rows: %w", err)
	}
	return nil
}

func deviceRowToInput(row DeviceRow) db.EmbeddingInput {
	lines := []string{"kind: device"}
	AppendValue(&lines, "mac_id", row.MACID)
	AppendValue(&lines, "display_name", row.DisplayName)
	AppendValue(&lines, "username", row.Username)
	AppendValue(&lines, "hostname", row.Hostname)
	AppendValue(&lines, "os_hint", row.OSHint)
	AppendValue(&lines, "mac_hint", row.MACHint)
	if row.FirstSeen.Valid {
		AppendValue(&lines, "first_seen", row.FirstSeen.Time.Format(timeFormatRFC3339))
	}
	if row.LastSeen.Valid {
		AppendValue(&lines, "last_seen", row.LastSeen.Time.Format(timeFormatRFC3339))
	}
	if row.ClusterSize > 1 {
		AppendValue(&lines, "cluster_size", fmt.Sprint(row.ClusterSize))
	}
	return db.EmbeddingInput{
		Text:             clampDefault(strings.Join(lines, "\n")),
		SourceObservedAt: optionalTime(row.LastSeen.Valid, row.LastSeen.Time),
		SourceMAC:        row.MACID,
	}
}

const timeFormatRFC3339 = "2006-01-02T15:04:05Z07:00"
