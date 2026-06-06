package alerts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func CheckDNSPrivacyLeaks(ctx context.Context, pool *pgxpool.Pool, cfg Config) (int, error) {
	tag, err := pool.Exec(ctx, `
WITH policy_devices AS (
  SELECT d.mac_id, d.wg_pubkey, p.allow_mdns
  FROM devices d
  JOIN vec_dns_policy p ON p.wg_pubkey = d.wg_pubkey
  WHERE d.wg_pubkey IS NOT NULL
    AND p.policy = 'secure_required'
),
wireless_dns AS (
  SELECT
    pd.wg_pubkey,
    pd.mac_id AS source_mac,
    s.sensor_id,
    s.location_id,
    s.observed_at,
    CASE
      WHEN nullif(s.dns_query_name, '') IS NOT NULL THEN 'plaintext_dns'
      WHEN nullif(s.mdns_name, '') IS NOT NULL AND NOT pd.allow_mdns THEN 'mdns_disallowed'
    END AS leak_reason,
    lower(coalesce(nullif(s.dns_query_name, ''), nullif(s.mdns_name, ''))) AS query_name
  FROM policy_devices pd
  JOIN sync_events_expanded s ON lower(s.source_mac) = lower(pd.mac_id)
  WHERE s.stream_name = 'wireless.audit'
    AND s.status = 'batched'
    AND s.observed_at >= now() - ($1::integer * interval '1 minute')
    AND (
      nullif(s.dns_query_name, '') IS NOT NULL
      OR (nullif(s.mdns_name, '') IS NOT NULL AND NOT pd.allow_mdns)
    )
),
candidates AS (
  SELECT DISTINCT ON (wg_pubkey, source_mac, leak_reason, query_name) *
  FROM wireless_dns
  WHERE leak_reason IS NOT NULL
  ORDER BY wg_pubkey, source_mac, leak_reason, query_name, observed_at DESC
)
INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
SELECT
  'dns_privacy_leak',
  source_mac,
  sensor_id,
  location_id,
  CASE WHEN leak_reason = 'plaintext_dns' THEN 1.0 ELSE 0.5 END,
  concat('DNS privacy leak for wg_pubkey ', wg_pubkey, ': ', leak_reason, ' query=', query_name),
  jsonb_build_object(
    'wg_pubkey', wg_pubkey,
    'source_mac', source_mac,
    'query_name', query_name,
    'reason', leak_reason,
    'lookback_minutes', $1
  )
FROM candidates
WHERE NOT EXISTS (
  SELECT 1 FROM vec_alerts a
  WHERE a.alert_type = 'dns_privacy_leak'
    AND a.source_mac IS NOT DISTINCT FROM candidates.source_mac
    AND a.metadata->>'wg_pubkey' = candidates.wg_pubkey
    AND a.metadata->>'query_name' = candidates.query_name
    AND a.metadata->>'reason' = candidates.leak_reason
    AND a.created_at > now() - interval '1 hour'
)
`, cfg.DNSLookbackMinutes)
	if err != nil {
		return 0, fmt.Errorf("dns_privacy_leak query failed: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
