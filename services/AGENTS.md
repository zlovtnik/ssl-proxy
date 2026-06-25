# AGENTS.md

## Scope
This file governs `/Users/rcs/git/ssl-proxy/services` and all service
subdirectories unless a deeper `AGENTS.md` overrides it. It supplements the
repository root instructions.

## Service Boundaries
- `atheros-sensor/` is a Rust host-side Wi-Fi sensor and sync-plane producer.
- `atheros-search/` is a Go HTTP/gRPC search, ingest, alert, and embedding
  service backed by Postgres/vector schema.
- `schema-migrator/` is a Scala Cats Effect tool that applies the ordered split
  Postgres and Oracle schema under the repository `sql/` tree.
- `zig-coordinator/` is the legacy directory name for the Java 21
  Spring Boot/Camel coordinator and Oracle sink.
- Keep cross-service contracts explicit: Redpanda topic names, stream names,
  schema-versioned payloads, SQL function signatures, protobuf fields, and
  HTTP routes are compatibility surfaces.

## Shared Guardrails
- Do not introduce direct Oracle access outside `zig-coordinator/`.
- Do not introduce direct Postgres writes from `atheros-sensor/`; persistence
  stays through Redpanda and coordinator backlog/request flows.
- Keep shared schema changes in `/Users/rcs/git/ssl-proxy/sql`, not in
  service-local migration folders, unless the schema is truly service-private.
- Preserve at-least-once behavior with idempotent dedupe keys and retry-safe
  handlers.
- Keep logs structured and avoid raw payloads, secrets, API tokens, full MACs,
  or user-identifying values unless an existing audited path explicitly allows
  them. Hash or summarize identifiers where the service already does so.
- Prefer existing config env var families: `ATH_SENSOR_*`, `ATHSEARCH_*`,
  `SYNC_*`, `WIRELESS_*`, `ORACLE_*`, `MINIO_*`, and `OTEL_*`.
- Do not edit runtime output directories such as `.gradle/`, `.omx/`,
  `target/`, generated logs, local outboxes, or downloaded tool caches.

## Verification
- Run the targeted service test first, then broaden only when shared contracts
  or schema behavior changed.
- Useful commands from the repository root:
  - `cargo test -p atheros-sensor`
  - `cd services/schema-migrator && sbt test`
  - `make atheros-search-test`
  - `cd services/zig-coordinator && ./gradlew test`
  - `make dependency-boundaries`
- If a change touches SQL contracts used by services, also consider
  `cd services/schema-migrator && sbt test` and the coordinator SQL contract
  tests.
