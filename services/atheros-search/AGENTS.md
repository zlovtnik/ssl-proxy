# AGENTS.md

## Scope
This file governs `services/atheros-search` relative to the repository root.

## Project Shape
- Go module: `github.com/zlovtnik/ssl-proxy/services/atheros-search`.
- `cmd/server/` starts the HTTP/gRPC service with optional embedding worker
  pool and ETL health monitor.
- `cmd/embedding-job-repair/` is a CLI tool for repairing stuck/failed
  embedding jobs and cleaning up the DLQ.
- `internal/api/` owns HTTP routes, CORS, auth wiring, NDJSON streaming,
  gRPC gateway behavior, and ETL health/WebSocket endpoints.
- `internal/search/` owns dense/sparse/hybrid search, graph, inventory,
  explain, and suggest logic.
- `internal/embed/` owns query embedding, caching, and backend circuit
  breaking.
- `internal/worker/` owns the embedding job worker pool with lease-based
  claiming, ETL health monitoring, and DLQ management. Workers claim
  pending jobs from `embedding_jobs`, call the embedding backend, and
  write vectors to `search_vectors_*` tables.
- `internal/health/` owns readiness checks and schema gate logic.
- Alert derivation and projection maintenance remain Octopus concerns.

## Guardrails
- Keep public API compatibility in mind for `/v1/search`, `/v1/search/stream`,
  `/v1/explain/{source_key}`, `/v1/suggest/filters`, graph, inventory,
  merge-decision, and `/v1/etl/*` endpoints.
- The stream endpoint emits one protobuf-JSON `SearchResult` per line and ends
  with a `{"type":"done"}` marker; preserve clients that parse that contract.
- The ETL stream endpoint (`/v1/etl/stream`) sends newline-delimited JSON
  snapshots; preserve this contract for Solid.js consumers.
- Keep request body limits, CORS allow-list behavior, token auth, request
  cancellation, and timeout handling intact.
- Do not log raw search queries, source keys, session IDs, API tokens, or MACs
  when existing code hashes or summarizes them.
- Keep config in `ATHSEARCH_*` env vars. The only database setting is the
  TiDB/MySQL `ATHSEARCH_TIDB_DSN`; do not add PostgreSQL URL fallbacks.
- Keep shared TiDB/vector schema changes in the repository `sql/tidb/atheros_search`
  domain.
  Service-local migrations are only for future private schema.
- Do not hand-edit generated protobuf files. Change `search.proto`, regenerate,
  and include generated outputs only when the proto contract changes.
- Worker pool configuration uses `ATHSEARCH_WORKER_*` and
  `ATHSEARCH_EMBEDDING_BATCH_SIZE`, `ATHSEARCH_LEASE_SECONDS`,
  `ATHSEARCH_POLL_INTERVAL_MS` env vars. Workers are opt-in via
  `ATHSEARCH_WORKER_ENABLED=true`.

## Commands
- Run all tests: `go test ./...`.
- Root Makefile equivalent: `make atheros-search-test`.
- Build server: `make atheros-search-build`.
- Regenerate protobufs after proto changes: `make atheros-search-proto`.
- Format Go files: `gofmt -w <files>`.
- Repair embedding jobs: `go run ./cmd/embedding-job-repair -action=status`.
- Reset stale jobs: `go run ./cmd/embedding-job-repair -action=reset-stale -stale-minutes=60`.
- Retry failed jobs: `go run ./cmd/embedding-job-repair -action=retry-failed`.
- Cleanup DLQ: `go run ./cmd/embedding-job-repair -action=cleanup-dlq -dlq-evict-hours=168`.

## Verification
- Run package-targeted `go test` for changed packages, then `go test ./...`
  when search, API, database, embedding, or shared types changed.
- If `search.proto` changes, regenerate protobufs and run `go test ./...`.
- If SQL assumptions change, run relevant service tests plus schema-migrator or
  coordinator SQL contract tests as appropriate.
