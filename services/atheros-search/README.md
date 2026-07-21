# Atheros Search

Atheros Search is the read/query facade for wireless audit intelligence. It
serves the existing HTTP, gRPC, protobuf, and NDJSON contracts while using the
external `atheros_search` TiDB database as its only runtime database.

Octopus owns ingestion, embedding preparation/completion, alerts, sequence and
graph projections, inventory projections, and retention. This service owns
query execution plus query logs, feedback, and merge decisions. It does not
run background database workers or consume Redpanda topics.

## Search design

- Dense search queries one fixed `VECTOR(768)` table per public search kind.
  The inner query performs an unfiltered, bounded ANN lookup ordered by
  `VEC_COSINE_DISTANCE`; model and request filters are applied afterward so
  TiFlash can use the vector index.
- Sparse search queries normalized `search_document_tokens` postings. It does
  not depend on database full-text extensions or stored routines.
- Hybrid search preserves weighted reciprocal-rank fusion, deterministic
  tie-breaking, threat boosts, and sparse fallback when query embedding fails.
- Graph and inventory endpoints read coordinator-maintained projections.
- Query text, result keys, and session IDs are hashed before persistence.
- Merge decisions are durable TiDB writes, including undo decisions.

The public protobuf schema and field numbers are unchanged. The streaming HTTP
endpoint still emits one protobuf-JSON `SearchResult` per line followed by
`{"type":"done"}`.

## Database and readiness

`ATHSEARCH_TIDB_DSN` is mandatory and must be a native MySQL driver DSN that:

- uses TCP and an external, non-loopback endpoint;
- selects exactly `atheros_search`;
- uses a dedicated non-root account.

The client always enables `parseTime`, UTC session time, strict SQL mode,
bounded pooling, and identity-verified TLS. DSN parameters cannot turn those
requirements off. Startup checks the selected database, UTC, strict mode, TiDB
v8.5 or newer, the expected schema manifest checksum, and vector readiness.

Required database settings:

| Variable | Purpose |
|---|---|
| `ATHSEARCH_TIDB_DSN` | Native DSN such as `user:password@tcp(tidb.example:4000)/atheros_search` |
| `ATHSEARCH_TIDB_TLS_CA_FILE` | PEM CA bundle used to verify the TiDB server |
| `ATHSEARCH_TIDB_TLS_SERVER_NAME` | Expected certificate DNS name |
| `ATHSEARCH_SCHEMA_MANIFEST_SHA256` | Exact 64-character canonical schema manifest checksum |

Optional client-certificate settings must be supplied as a pair:

| Variable | Purpose |
|---|---|
| `ATHSEARCH_TIDB_TLS_CERT_FILE` | PEM client certificate |
| `ATHSEARCH_TIDB_TLS_KEY_FILE` | PEM client private key |

Pool and search controls:

| Variable | Default | Purpose |
|---|---:|---|
| `ATHSEARCH_TIDB_MAX_OPEN_CONNS` | `32` | Maximum open database connections |
| `ATHSEARCH_TIDB_MAX_IDLE_CONNS` | `8` | Maximum idle database connections |
| `ATHSEARCH_TIDB_CONN_MAX_LIFETIME_MS` | `300000` | Maximum connection lifetime |
| `ATHSEARCH_TIDB_CONN_MAX_IDLE_TIME_MS` | `60000` | Maximum idle duration |
| `ATHSEARCH_DENSE_OVERFETCH_FACTOR` | `8` | ANN candidates fetched before filtering |
| `ATHSEARCH_SEARCH_TIMEOUT_MS` | `10000` | Per-search deadline |
| `ATHSEARCH_HYBRID_ALPHA` | `0.5` | Dense-versus-sparse fusion weight |
| `ATHSEARCH_SCHEMA_READY_REQUIRED` | `true` | Gate startup and readiness on schema/vector state |
| `ATHSEARCH_SCHEMA_READY_TIMEOUT_MS` | `60000` | Startup schema wait timeout |
| `ATHSEARCH_SCHEMA_READY_POLL_INTERVAL_MS` | `1000` | Schema wait poll interval |

## Embedding backend

Meaningful dense and hybrid search requires an external embedding backend that
returns 768-dimensional vectors for the same model used by Octopus. The client
accepts the existing OpenAI-compatible `/v1/embeddings` and Ollama-style
`/api/embed` response shapes.

| Variable | Default | Purpose |
|---|---:|---|
| `ATHSEARCH_EMBEDDING_BACKEND` | `VECTOR_EMBEDDING_URL` fallback | Embedding API base URL |
| `ATHSEARCH_EMBEDDING_MODEL` | `nomic-embed-text-v2-moe` | Query embedding model |
| `ATHSEARCH_EMBEDDING_DIMENSIONS` | `768` | Required dimensions; other values fail startup |

If the backend is unset, the no-op client remains available for API wiring
tests. It is not suitable for meaningful dense ranking.

## Network and API configuration

| Variable | Default | Purpose |
|---|---:|---|
| `ATHSEARCH_GRPC_PORT` | `50051` | gRPC listen port |
| `ATHSEARCH_HTTP_PORT` | `8080` | HTTP listen port |
| `ATHSEARCH_METRICS_PORT` | `9090` | Prometheus listen port |
| `ATHSEARCH_LOG_LEVEL` | `info` | Structured log level |
| `ATHSEARCH_API_TOKEN_SHA256` | empty | Optional bearer-token SHA-256 digest |
| `ATHSEARCH_CORS_ALLOWED_ORIGINS` | `http://127.0.0.1:5173` | Comma-separated origin allow-list |

HTTP request bodies remain capped at 1 MiB. Raw queries, source keys, session
IDs, tokens, and MACs are not written to logs.

## API surface

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/search` | Protobuf-JSON search |
| `POST` | `/v1/search/stream` | NDJSON result stream with final done marker |
| `GET` | `/v1/explain/{source_key}` | Explain ranking contributions |
| `GET` | `/v1/suggest/filters` | Suggest SSIDs, locations, sensors, and frame subtypes |
| `POST` | `/v1/graph` | Query the maintained graph projection |
| `POST` | `/v1/inventory` | Query registry, CMDB, or similarity inventory views |
| `POST` | `/v1/inventory/merge-candidates/{candidate_id}/decision` | Persist merge workflow decisions |
| `GET` | `/healthz` | Process liveness |
| `GET` | `/readyz` | TiDB, schema, vector, and embedding-backend readiness |

The gRPC service is defined by
`proto/atheros/search/v1/search.proto`. Regenerate generated code only when that
source contract changes:

```bash
make atheros-search-proto
```

## Layout

| Path | Purpose |
|---|---|
| `cmd/server/` | HTTP, gRPC, metrics, readiness, and graceful shutdown |
| `internal/api/` | Public routes, request bounds, auth, CORS, NDJSON, gRPC gateway |
| `internal/auth/` | Constant-time bearer-token digest verification |
| `internal/config/` | Required TiDB/TLS and search configuration validation |
| `internal/db/` | `database/sql` MySQL driver, TLS, pooling, TiDB and schema checks |
| `internal/embed/` | Query embedding client, cache, and circuit breaker |
| `internal/search/` | Dense, sparse, hybrid, filter, rerank, graph, inventory, logging, suggest |
| `internal/metrics/` | Search and embedding-query Prometheus metrics |
| `proto/` | Stable protobuf source and generated Go API |

The canonical runtime schema is under `../../sql/tidb/atheros_search/`; this
service never applies DDL.

## Development

```bash
go test ./...
go build ./cmd/server
```

For a direct process, mount real TLS files and provide the externally supplied
credential without committing it:

```bash
ATHSEARCH_TIDB_DSN='atheros_search_app:REDACTED@tcp(tidb.example.net:4000)/atheros_search' \
ATHSEARCH_TIDB_TLS_CA_FILE='/run/secrets/tidb/ca.crt' \
ATHSEARCH_TIDB_TLS_SERVER_NAME='tidb.example.net' \
ATHSEARCH_SCHEMA_MANIFEST_SHA256='REPLACE_WITH_64_HEX_CHARACTERS' \
ATHSEARCH_EMBEDDING_BACKEND='http://127.0.0.1:8083' \
go run ./cmd/server
```

The repository Helm and Compose paths provide the deployment wiring. They do
not start an application-owned TiDB instance.
