-- object: octopus_core_ingestion_evidence_peaks_index
-- depends_on: octopus_core_wireless_projection_receipts
-- Append-only index for the public operational-stats peak aggregates over
-- ingestion_evidence. A plain btree on first_seen_at is used (not an
-- expression index): date_trunc/AT TIME ZONE/to_char are STABLE, and
-- PostgreSQL rejects non-IMMUTABLE functions in index expressions.
-- Index-only scans still avoid heap fetches of wide rows during GROUP BY.

CREATE INDEX IF NOT EXISTS ingestion_evidence_first_seen_idx
  ON octopus_core.ingestion_evidence (first_seen_at);
