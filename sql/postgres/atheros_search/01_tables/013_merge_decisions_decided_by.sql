-- Append-only addition of merge_decisions.decided_by for the merge API.
ALTER TABLE atheros_search.merge_decisions
  ADD COLUMN IF NOT EXISTS decided_by text DEFAULT NULL;
