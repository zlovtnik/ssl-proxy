# AGENTS.md

## Scope
This file governs `/Users/rcs/git/ssl-proxy/services` and all service
subdirectories unless a deeper `AGENTS.md` overrides it. It supplements the
repository root instructions.

## Service Boundaries
- `atheros-sensor/` is a Rust host-side Wi-Fi sensor and sync-plane producer.
- `atheros-search/` is the Go HTTP/gRPC TiDB query facade. Octopus owns its
  former ingest, alert, repair, and embedding workflows.
- `octopus/` is the Scala 3 Cats Effect/FS2 coordinator and the sole owner of
  durable ingestion, leases, outbox, and maintained projections in TiDB.
- Keep cross-service contracts explicit: Redpanda topic names, stream names,
  schema-versioned payloads, SQL function signatures, protobuf fields, and
  HTTP routes are compatibility surfaces.

## Shared Guardrails
- Direct TiDB clients are limited to Octopus, Atheros Search, Integration
  Console, and schema-migrator, each using an isolated database and account.
- PostgreSQL is not a service runtime dependency. It is allowed only inside
  schema-migrator as an explicit external target dialect.
- Do not introduce direct database writes from `atheros-sensor/`; persistence
  stays through Redpanda and Octopus request flows.
- Keep shared schema changes in `/Users/rcs/git/ssl-proxy/sql`, not in
  service-local migration folders, unless the schema is truly service-private.
- Preserve at-least-once behavior with idempotent dedupe keys and retry-safe
  handlers.
- Keep logs structured and avoid raw payloads, secrets, API tokens, full MACs,
  or user-identifying values unless an existing audited path explicitly allows
  them. Hash or summarize identifiers where the service already does so.
- Prefer existing config env var families: `ATH_SENSOR_*`, `ATHSEARCH_*`,
  `TIDB_*`, `SYNC_*`, `WIRELESS_*`, `MINIO_*`, and `OTEL_*`.
- Do not edit runtime output directories such as `.gradle/`, `.omx/`,
  `target/`, generated logs, local outboxes, or downloaded tool caches.

## Verification
- Run the targeted service test first, then broaden only when shared contracts
  or schema behavior changed.
- Useful commands from the repository root:
  - `cargo test -p atheros-sensor`
  - `cd apps/schema-migrator && sbt test`
  - `make atheros-search-test`
  - `cd services/octopus && sbt test`
  - `make dependency-boundaries`
- If a change touches SQL contracts used by services, also consider
  `cd apps/schema-migrator && sbt test` and the coordinator SQL contract
  tests.
