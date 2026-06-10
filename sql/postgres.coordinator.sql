-- Coordinator schema apply wrapper.
--
-- Acquires a session-level advisory lock so that only one coordinator replica
-- applies the schema at a time.  Concurrent replicas block until the lock
-- is released (which happens automatically when psql exits, either on success
-- or on error).
--
-- Lock key = 2024061001 (arbitrary, date-stamped namespace).

BEGIN;

SELECT pg_advisory_lock(2024061001);

\ir postgres.sql

SELECT pg_advisory_unlock(2024061001);

COMMIT;