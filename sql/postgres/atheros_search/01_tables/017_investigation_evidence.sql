-- object: atheros_search_investigation_evidence
-- depends_on: atheros_search_guarded_identity_confirmation
--
-- Durable, bounded reporting projections.  These are written by Octopus from
-- deduplicated wireless_frames; the Search runtime only reads them, apart from
-- operator annotations and their audit trail.

CREATE TABLE IF NOT EXISTS atheros_search.ap_catalog (
  bssid              VARCHAR(17) PRIMARY KEY,
  authorized         BOOLEAN NOT NULL DEFAULT FALSE,
  authorized_label   VARCHAR(256) DEFAULT NULL,
  first_observed_at  TIMESTAMPTZ NOT NULL,
  last_observed_at   TIMESTAMPTZ NOT NULL,
  last_sensor_id     VARCHAR(128) DEFAULT NULL,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ap_catalog_bssid_ck CHECK (bssid ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'),
  CONSTRAINT ap_catalog_label_ck CHECK (authorized_label IS NULL OR length(btrim(authorized_label)) > 0)
);
CREATE INDEX IF NOT EXISTS ap_catalog_recent_idx
  ON atheros_search.ap_catalog (last_observed_at DESC, bssid);

CREATE TABLE IF NOT EXISTS atheros_search.wireless_signal_summaries (
  window_start       TIMESTAMPTZ NOT NULL,
  sensor_id          VARCHAR(128) NOT NULL,
  location_id        VARCHAR(256) DEFAULT NULL,
  bssid              VARCHAR(17) NOT NULL,
  source_mac         VARCHAR(17) NOT NULL,
  frame_count        INTEGER NOT NULL,
  rssi_sample_count  INTEGER NOT NULL DEFAULT 0,
  rssi_min_dbm       SMALLINT DEFAULT NULL,
  rssi_max_dbm       SMALLINT DEFAULT NULL,
  rssi_avg_dbm       DOUBLE PRECISION DEFAULT NULL,
  first_observed_at  TIMESTAMPTZ NOT NULL,
  last_observed_at   TIMESTAMPTZ NOT NULL,
  projected_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (window_start, sensor_id, bssid, source_mac),
  CONSTRAINT wireless_signal_summary_window_ck
    CHECK (date_trunc('minute', window_start) = window_start AND EXTRACT(MINUTE FROM window_start)::INTEGER % 5 = 0),
  CONSTRAINT wireless_signal_summary_frame_count_ck CHECK (frame_count > 0),
  CONSTRAINT wireless_signal_summary_rssi_ck CHECK (
    (rssi_sample_count = 0 AND rssi_min_dbm IS NULL AND rssi_max_dbm IS NULL AND rssi_avg_dbm IS NULL)
    OR (rssi_sample_count > 0 AND rssi_min_dbm IS NOT NULL AND rssi_max_dbm IS NOT NULL AND rssi_avg_dbm IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS wireless_signal_summaries_window_idx
  ON atheros_search.wireless_signal_summaries (window_start DESC, bssid, source_mac);
CREATE INDEX IF NOT EXISTS wireless_signal_summaries_device_idx
  ON atheros_search.wireless_signal_summaries (source_mac, window_start DESC);

CREATE TABLE IF NOT EXISTS atheros_search.investigation_watermarks (
  projection_name       VARCHAR(64) PRIMARY KEY,
  source_watermark_at   TIMESTAMPTZ DEFAULT NULL,
  projection_watermark_at TIMESTAMPTZ DEFAULT NULL,
  coverage_status       VARCHAR(32) NOT NULL DEFAULT 'unknown',
  coverage_reason       TEXT DEFAULT NULL,
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT investigation_watermarks_status_ck
    CHECK (coverage_status IN ('complete', 'partial', 'stalled', 'unknown'))
);

CREATE TABLE IF NOT EXISTS atheros_search.asset_annotations (
  asset_kind        VARCHAR(16) NOT NULL,
  asset_id          VARCHAR(255) NOT NULL,
  role              VARCHAR(32) DEFAULT NULL,
  label             VARCHAR(256) DEFAULT NULL,
  pinned            BOOLEAN NOT NULL DEFAULT FALSE,
  revision          BIGINT NOT NULL DEFAULT 1,
  updated_by        VARCHAR(255) NOT NULL,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (asset_kind, asset_id),
  CONSTRAINT asset_annotations_kind_ck CHECK (asset_kind IN ('ap', 'device')),
  CONSTRAINT asset_annotations_role_ck CHECK (role IS NULL OR role IN ('router', 'server')),
  CONSTRAINT asset_annotations_revision_ck CHECK (revision > 0),
  CONSTRAINT asset_annotations_value_ck CHECK (role IS NOT NULL OR label IS NOT NULL OR pinned)
);

CREATE TABLE IF NOT EXISTS atheros_search.asset_annotation_audit (
  audit_id           BIGSERIAL PRIMARY KEY,
  asset_kind         VARCHAR(16) NOT NULL,
  asset_id           VARCHAR(255) NOT NULL,
  revision           BIGINT NOT NULL,
  role               VARCHAR(32) DEFAULT NULL,
  label              VARCHAR(256) DEFAULT NULL,
  pinned             BOOLEAN NOT NULL,
  actor              VARCHAR(255) NOT NULL,
  changed_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT asset_annotation_audit_kind_ck CHECK (asset_kind IN ('ap', 'device')),
  CONSTRAINT asset_annotation_audit_revision_ck CHECK (revision > 0)
);
CREATE INDEX IF NOT EXISTS asset_annotation_audit_asset_idx
  ON atheros_search.asset_annotation_audit (asset_kind, asset_id, revision DESC);
