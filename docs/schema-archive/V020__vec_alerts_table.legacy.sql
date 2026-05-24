-- V020: Create vec_alerts table for actionable alert feed
--
-- Stores alerts generated from embedding analysis:
-- - near_duplicate_cluster: when a device exceeds the near-duplicate threshold
-- - behaviour_anomaly: when a behaviour window deviates from baseline
-- - new_device: first-seen device with embedding profile
-- - device_fingerprint_change: WPS identity or fingerprint shift

CREATE TABLE IF NOT EXISTS vec_alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_type TEXT NOT NULL,
    source_mac TEXT,
    sensor_id TEXT,
    location_id TEXT,
    score DOUBLE PRECISION,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_type_created
    ON vec_alerts (alert_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_mac
    ON vec_alerts (source_mac);

CREATE INDEX IF NOT EXISTS idx_vec_alerts_created
    ON vec_alerts (created_at DESC);

COMMENT ON TABLE vec_alerts IS
  'Actionable alerts generated from embedding analysis (near-duplicate, behaviour anomaly, etc.).';