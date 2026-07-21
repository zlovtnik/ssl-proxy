# AGENTS.md

## Scope
This file governs `services/atheros-search` relative to the repository root.

## Project Shape
- Go module: `github.com/zlovtnik/ssl-proxy/services/atheros-search`.
- `cmd/server/` starts the HTTP/gRPC service. Embedding repair and other
  background database workers belong to Octopus and must not be reintroduced.
- `internal/api/` owns HTTP routes, CORS, auth wiring, NDJSON streaming, and
  gRPC gateway behavior.
- `internal/search/` owns dense/sparse/hybrid search, graph, inventory, explain,
  and suggest logic.
- `internal/embed/` owns query embedding, caching, and backend circuit breaking.
- Ingest, database workers, alert derivation, embedding completion/text
  building, and repair tooling are Octopus concerns and must not be added here.
- `proto/atheros/search/v1/search.proto` is the source of truth for protobuf
  contracts. The `.pb.go` files are generated.

## Guardrails
- Keep public API compatibility in mind for `/v1/search`, `/v1/search/stream`,
  `/v1/explain/{source_key}`, `/v1/suggest/filters`, graph, inventory, and
  merge-decision endpoints.
- The stream endpoint emits one protobuf-JSON `SearchResult` per line and ends
  with a `{"type":"done"}` marker; preserve clients that parse that contract.
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

## Commands
- Run all tests: `go test ./...`.
- Root Makefile equivalent: `make atheros-search-test`.
- Build server: `make atheros-search-build`.
- Regenerate protobufs after proto changes: `make atheros-search-proto`.
- Format Go files: `gofmt -w <files>`.

## Verification
- Run package-targeted `go test` for changed packages, then `go test ./...`
  when search, API, database, embedding, or shared types changed.
- If `search.proto` changes, regenerate protobufs and run `go test ./...`.
- If SQL assumptions change, run relevant service tests plus schema-migrator or
  coordinator SQL contract tests as appropriate.
