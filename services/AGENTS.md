# AGENTS.md

## Scope
This file governs `/Users/rcs/git/ssl-proxy/services` and all service
subdirectories unless a deeper `AGENTS.md` overrides it. It supplements the
repository root instructions.

## Service Boundaries
- `atheros-sensor/` is a Rust host-side Wi-Fi sensor and sync-plane producer.
- `octopus/` is the Scala 3 Cats Effect/FS2 coordinator and the sole owner of
  durable ingestion, leases, outbox, and maintained projections in PostgreSQL.
- `octopus-metrics/` materializes snapshots through a read-only PostgreSQL role;
  it reads Octopus live telemetry and publishes Redis/MinIO objects.
- `stats-reader/` is the Go always-Ready public metrics reader. It consumes
  only precomputed Redis/MinIO snapshots and must not gain a PostgreSQL client.

## Shared Guardrails
- Keep logs structured and avoid raw payloads, secrets, API tokens, full MACs,
  or user-identifying values unless an existing audited path explicitly allows
  them. Hash or summarize identifiers where the service already does so.
- Prefer existing config env var families: `ATH_SENSOR_*`, `ATHSEARCH_*`,
  `POSTGRES_*`, `SYNC_*`, `WIRELESS_*`, `MINIO_*`, and `OTEL_*`.

## Verification
- If a change touches SQL contracts used by services, also consider
  `cd apps/schema-migrator && sbt test` and the coordinator SQL contract
  tests.
