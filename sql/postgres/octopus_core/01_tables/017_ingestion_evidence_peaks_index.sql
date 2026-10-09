-- object: octopus_core_ingestion_evidence_peaks_index
-- depends_on: octopus_core_wireless_projection_receipts
-- Append-only indexes for the public operational-stats peak day/week aggregates
-- over ingestion_evidence. The expressions match IngestionSql GROUP BY keys so
-- refreshes can run as index-only scans instead of heap-wide GROUP BY.

CREATE INDEX IF NOT EXISTS ingestion_evidence_peak_day_idx
  ON octopus_core.ingestion_evidence (
    (to_char(date_trunc('day', first_seen_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD'))
  );

CREATE INDEX IF NOT EXISTS ingestion_evidence_peak_week_idx
  ON octopus_core.ingestion_evidence (
    (to_char(date_trunc('week', first_seen_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD'))
  );
