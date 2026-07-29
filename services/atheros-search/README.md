# Atheros Search

Atheros Search is the Go HTTP/gRPC search, vector and ETL control-plane service
for wireless audit data. It queries the `atheros_search` TiDB domain and owns
embedding job processing through an opt-in worker pool. Octopus owns durable
ingestion, search-document/job preparation, maintained projections and alert
derivation.

The Integration Console is the SolidJS UI in
[`apps/integration-console/atheros-search-ui`](../../apps/integration-console/atheros-search-ui/);
there is no Rails Search console.

## Runtime responsibilities

- dense `VECTOR(768)`, sparse and hybrid search
- graph, inventory, explain, filter-suggestion and merge-decision APIs
- query analytics using hashed query/session/result identifiers
- readiness and ETL health/stream APIs
- lease-based claiming of `embedding_jobs`
- batched embedding calls, `search_vectors_*` writes and job completion/failure
- worker heartbeat and DLQ inspection/repair support

The service does not apply DDL. Canonical schema lives in
[`sql/tidb/atheros_search`](../../sql/tidb/atheros_search/).

## Database and readiness

Database settings:

An explicit, valid `ATHSEARCH_*` value takes precedence over the shared
fallback shown below. `None` means that no shared-variable fallback exists.
In particular, `DATABASE_URL` and `SYNC_DATABASE_URL` are not fallbacks for
`ATHSEARCH_TIDB_DSN` and are ignored.

| Variable | Shared fallback | Purpose |
|---|---|---|
| `ATHSEARCH_TIDB_DSN` | None | Native Go MySQL DSN selecting `atheros_search`; URL-style `mysql://` values are rejected |
| `ATHSEARCH_TIDB_TLS_CA_FILE` | None | PEM CA used to verify TiDB |
| `ATHSEARCH_TIDB_TLS_CERT_FILE` | None | Optional PEM client certificate; must be supplied with the key |
| `ATHSEARCH_TIDB_TLS_KEY_FILE` | None | Optional PEM client private key; must be supplied with the certificate |
| `ATHSEARCH_TIDB_TLS_SERVER_NAME` | None | Expected certificate DNS name |
| `ATHSEARCH_SCHEMA_MANIFEST_SHA256` | None | Exact 64-character canonical manifest checksum |

Startup verifies the selected database, UTC/strict SQL session, TiDB version,
manifest checksum and vector readiness. Pool/search controls include:

| Variable | Default | Shared fallback |
|---|---:|---|
| `ATHSEARCH_TIDB_MAX_OPEN_CONNS` | `32` | None |
| `ATHSEARCH_TIDB_MAX_IDLE_CONNS` | `8` | None |
| `ATHSEARCH_TIDB_CONN_MAX_LIFETIME_MS` | `300000` | None |
| `ATHSEARCH_TIDB_CONN_MAX_IDLE_TIME_MS` | `60000` | None |
| `ATHSEARCH_SEARCH_TIMEOUT_MS` | `10000` | None |
| `ATHSEARCH_HYBRID_ALPHA` | `0.5` | None |
| `ATHSEARCH_DENSE_OVERFETCH_FACTOR` | `8` | None |
| `ATHSEARCH_SCHEMA_READY_REQUIRED` | `true` | None |
| `ATHSEARCH_SCHEMA_READY_TIMEOUT_MS` | `60000` | None |
| `ATHSEARCH_SCHEMA_READY_POLL_INTERVAL_MS` | `1000` | None |

## Embedding workers

Workers are disabled by default in the binary:

| Variable | Default | Shared fallback | Purpose |
|---|---:|---|---|
| `ATHSEARCH_WORKER_ENABLED` | `false` | None | Start the worker pool |
| `ATHSEARCH_WORKER_COUNT` | `4` | None | Concurrent claim loops |
| `ATHSEARCH_EMBEDDING_BATCH_SIZE` | `64` | None | Jobs claimed and embedded per batch |
| `ATHSEARCH_LEASE_SECONDS` | `1800` | None | Claim lease duration |
| `ATHSEARCH_POLL_INTERVAL_MS` | `1000` | None | Poll interval |
| `ATHSEARCH_WORKER_ID` | `worker-1` | None | Heartbeat/lease identity prefix |
| `ATHSEARCH_DLQ_ENABLED` | `true` | None | Expose DLQ health state |

Embedding settings use these shared fallbacks only when their corresponding
`ATHSEARCH_*` value is empty:

| Variable | Default | Shared fallback |
|---|---:|---|
| `ATHSEARCH_EMBEDDING_BACKEND` | empty | `VECTOR_EMBEDDING_URL` |
| `ATHSEARCH_EMBEDDING_MODEL` | `nomic-embed-text-v2-moe` | `VECTOR_EMBEDDING_MODEL` |
| `ATHSEARCH_EMBEDDING_DIMENSIONS` | `768` | `VECTOR_EMBEDDING_DIMENSIONS` |

Embedding dimensions must resolve to `768`. The client accepts supported
OpenAI-compatible and Ollama response shapes. With no backend configured, the
server uses a zero-vector client suitable only for wiring tests.

The umbrella Helm values declare worker settings, but its current Deployment
template does not pass them to the container. Inspect rendered environment
variables before expecting Kubernetes workers to run. The pinned Octopus
runtime also lacks the wired search-document/job producer, so an empty queue
can be a producer gap.

## Network and API

| Variable | Default | Shared fallback |
|---|---:|---|
| `ATHSEARCH_HTTP_PORT` | `8080` | None |
| `ATHSEARCH_GRPC_PORT` | `50051` | None |
| `ATHSEARCH_METRICS_PORT` | `9090` | None |
| `ATHSEARCH_LOG_LEVEL` | `info` | None |
| `ATHSEARCH_API_TOKEN_SHA256` | empty | None |
| `ATHSEARCH_CORS_ALLOWED_ORIGINS` | `http://127.0.0.1:5173` | None |
| `ATHSEARCH_WS_ENABLED` | `false` | None |

Key routes:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/search` | Protobuf-JSON search |
| `POST` | `/v1/search/stream` | NDJSON results followed by `{"type":"done"}` |
| `GET` | `/v1/explain/{source_key}` | Ranking explanation |
| `GET` | `/v1/suggest/filters` | Filter suggestions |
| `POST` | `/v1/graph` | Graph projection query |
| `POST` | `/v1/inventory` | Inventory query |
| `POST` | `/v1/inventory/merge-candidates/{candidate_id}/decision` | Persist merge workflow decisions |
| `GET` | `/v1/etl/health` | ETL summary |
| `GET` | `/v1/etl/embedding/jobs` | Embedding job state |
| `GET` | `/v1/etl/workers` | Worker heartbeat state |
| `GET` | `/v1/etl/stream` | NDJSON ETL snapshots when WebSockets are enabled |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | TiDB/schema/vector/embedding readiness |

The public protobuf contract is
[`proto/atheros/search/v1/search.proto`](proto/atheros/search/v1/search.proto).
HTTP bodies are capped at 1 MiB. Preserve CORS, token auth, deadlines and the
NDJSON completion marker.

## Observability and privacy

The service exposes Prometheus metrics on its dedicated metrics port. HTTP and
gRPC tracing hooks exist, but server startup does not currently initialize an
OTLP exporter/provider; `OTEL_EXPORTER_OTLP_ENDPOINT` alone does not export
spans.

Do not log raw queries, source keys, session IDs, tokens or full MACs. See
[Atheros Search Privacy](../../docs/atheros-search-privacy.md).

## Development

```bash
go test ./...
go build ./cmd/server
make atheros-search-proto
go run ./cmd/embedding-job-repair -action=status
```

Run protobuf generation only after changing the source `.proto`. Repair
commands and deployment cautions are documented in
[`scripts/README.md`](scripts/README.md).
