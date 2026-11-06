-- object: octopus_core_proxy_source_conflicts
-- depends_on: octopus_core_proxy_evidence
-- Private source evidence, separate from regenerated normalized evidence.
-- Map each conflicting payload's SHA-256 (PostgreSQL JSONB text) to its
-- correlation ID. Keep markers until an authoritative version is established.
DO $$
BEGIN
  PERFORM set_config('lock_timeout', '1s', true);
  ALTER TABLE octopus_core.proxy_events
    ADD COLUMN IF NOT EXISTS source_conflicts jsonb NOT NULL DEFAULT '{}'::jsonb;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
      WHERE conrelid = 'octopus_core.proxy_events'::regclass
        AND conname = 'proxy_events_source_conflicts_object_ck') THEN
    -- Existing rows receive the valid constant default without a table rewrite.
    -- NOT VALID avoids scanning retained telemetry while enforcing future writes.
    ALTER TABLE octopus_core.proxy_events
      ADD CONSTRAINT proxy_events_source_conflicts_object_ck
      CHECK (jsonb_typeof(source_conflicts) = 'object') NOT VALID;
  END IF;
END $$;
