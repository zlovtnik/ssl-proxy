# Atheros Search

Atheros Search is the Go search, vector, ingest, alert, and embedding service
for wireless audit intelligence in the `ssl-proxy` platform. It exposes REST
and gRPC APIs for hybrid search over wireless telemetry, device inventory,
infrastructure graph exploration, result explanation, and merge-decision
workflows.

The service is built around PostgreSQL plus `pgvector`, Redpanda/Kafka-backed
freshness signals, protobuf API contracts, a production embedding worker, and
Prometheus/OpenTelemetry observability.

## AI Model Requirement

Atheros Search is not itself an embedding model. Meaningful dense and hybrid
search requires an external AI embedding backend.

The embedding backend must accept batched text input and return 768-dimensional
vectors for the configured model. The current client supports embedding
providers with either an OpenAI-compatible `/v1/embeddings` shape or an
Ollama-style `/api/embed` response shape. Configure it with:

```bash
ATHSEARCH_EMBEDDING_BACKEND='http://127.0.0.1:8083'
ATHSEARCH_EMBEDDING_MODEL='nomic-embed-text-v2-moe'
ATHSEARCH_EMBEDDING_DIMENSIONS=768
```

Use the same model and vector dimension for both stored document embeddings and
query embeddings. If `ATHSEARCH_EMBEDDING_BACKEND` is unset, the service falls
back to a zero-vector no-op embedder so HTTP/gRPC wiring can still run, but
dense search, hybrid search quality, and generated worker embeddings are not
meaningful.

## What It Does

- Searches wireless audit data with dense vector search, sparse keyword search,
  and hybrid result fusion.
- Builds and stores embeddings for event, device, behaviour-window,
  frame-sequence, infrastructure-subgraph, baseline-profile, and timing-profile
  records.
- Serves HTTP REST, NDJSON streaming, and gRPC search APIs from one service.
- Provides graph and inventory APIs for wireless devices, access points,
  infrastructure relationships, alerts, clusters, and merge candidates.
- Runs embedding workers with leases, batching, concurrency limits, retries,
  permanent-failure classification, queue-depth metrics, and worker state.
- Consumes Redpanda/Kafka events to refresh embedding jobs after wireless audit
  updates.
- Derives wireless security alerts from vector similarity, RF movement,
  sequence scoring, DNS behaviour, high-risk APs, rogue clusters, and duplicate
  patterns.
- Keeps query, MAC, source-key, session, and API-token data out of logs by
  hashing or summarizing sensitive fields.

## Tech Stack

| Area | Stack |
|------|-------|
| Language/runtime | Go 1.25 module, Docker builder based on Go 1.26 Bookworm |
| APIs | `net/http`, gRPC, gRPC Gateway, Protocol Buffers, protobuf JSON, NDJSON streaming |
| Search | Dense vector search, sparse text search, hybrid reciprocal-rank fusion, threat boosting, sequence scoring |
| Database | PostgreSQL, `pgx/v5`, `pgxpool`, `pgvector-go`, SQL functions, views, materialized views, HNSW vector indexes |
| Embeddings | External HTTP embedding backend, `nomic-embed-text-v2-moe`, 768-dimensional vectors, query cache, circuit breaker |
| Streaming | Redpanda/Kafka via `confluent-kafka-go/v2` |
| Workers | Leased job queue, batch preparation, concurrent embedding calls, batch completion, repair command |
| Observability | Prometheus client metrics, OpenTelemetry gRPC instrumentation, structured logging with `zerolog` |
| Configuration | `ATHSEARCH_*` environment variables, `DATABASE_URL` and `VECTOR_*` fallbacks, Viper |
| Security | Optional bearer-token auth by SHA-256 digest, CORS allow-list, request body limits, request timeouts |
| Packaging | Multi-stage Docker build, distroless Debian nonroot runtime image |
| Testing | Go unit tests with `testing` and `testify` |

## Architecture

```text
Wireless sensor / coordinator
        |
        | wireless.audit events and shared Postgres/vector schema
        v
PostgreSQL + pgvector <---- Atheros Search HTTP/gRPC APIs
        |                         |
        | vec_embedding_jobs      | /v1/search, /v1/graph, /v1/inventory
        v                         |
Embedding worker -----------------+
        |
        | HTTP /v1/embeddings or /api/embed
        v
Embedding backend

Redpanda/Kafka freshness consumer
        |
        v
vec_enqueue_embedding_jobs(...)
```

The service does not own Oracle persistence. Oracle loading, cursoring, dedupe,
and backlog control belong to `services/zig-coordinator/`. Shared
Postgres/vector schema lives under the repository-level `sql/` tree.

## Repository Layout

| Path | Purpose |
|------|---------|
| `cmd/server/` | Main service entry point, healthcheck command, HTTP/gRPC/metrics startup, graceful shutdown |
| `cmd/embedding-job-repair/` | Maintenance tool for repairing completed embedding job state |
| `internal/api/` | HTTP routes, gRPC server, auth interceptors, CORS, request limits, NDJSON streaming |
| `internal/auth/` | Bearer token verification against a configured SHA-256 digest |
| `internal/config/` | Environment-driven configuration, defaults, validation, TopK and kind normalization |
| `internal/db/` | PostgreSQL pool setup, pgvector type registration, schema readiness checks, worker SQL wrappers |
| `internal/embed/` | Embedding client, no-op embedder, query cache, circuit breaker |
| `internal/ingest/` | Redpanda freshness consumer and legacy embedded job drainer |
| `internal/worker/` | Primary embedding worker with leases, batching, retries, metrics, and alert sweep integration |
| `internal/search/` | Dense/sparse/hybrid search, graph, inventory, explain, suggest, filters, vector utilities |
| `internal/alerts/` | Alert detection sweeps for wireless/vector risk signals |
| `internal/textbuilder/` | Embedding text construction for events, devices, behaviours, infrastructure, sequences, baselines, timing |
| `internal/metrics/` | Prometheus metrics and metrics HTTP server |
| `internal/seqscore/` | Frame sequence transition scoring |
| `proto/atheros/search/v1/search.proto` | Source of truth for public gRPC/protobuf contracts |
| `migrations/` | Placeholder for future service-private migrations; shared schema is in `../../sql/` |
| `scripts/` | Placeholder for service-local helper scripts |

## API Surface

### HTTP

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/search` | Protobuf-JSON search request and response |
| `POST` | `/v1/search/stream` | NDJSON stream of protobuf-JSON `SearchResult` rows followed by `{"type":"done"}` |
| `GET` | `/v1/explain/{source_key}` | Explain dense, sparse, fused, threat-boost, and sequence contributions for one result |
| `GET` | `/v1/suggest/filters` | Suggest SSIDs, locations, sensors, and frame subtypes |
| `POST` | `/v1/graph` | Build a wireless/infrastructure/alert graph from filters |
| `POST` | `/v1/inventory` | Build inventory graph views for registry, CMDB, or similarity grouping |
| `POST` | `/v1/inventory/merge-candidates/{candidate_id}/decision` | Record merge, not-match, needs-more-data, or undo decisions |
| `GET` | `/healthz` | Liveness check |
| `GET` | `/readyz` | Readiness check for Postgres, schema control, embeddings, and optional backend health |

HTTP request bodies are capped at 1 MiB. When `ATHSEARCH_API_TOKEN_SHA256` is
set, protected routes require `Authorization: Bearer <token>`.

### gRPC

The gRPC service is defined in `proto/atheros/search/v1/search.proto`.

| RPC | Description |
|-----|-------------|
| `Search` | Unary search API |
| `SearchStream` | Server-streamed search results |
| `Explain` | Explain one source result for a query |
| `SuggestFilters` | Suggest common filter values |

Regenerate protobuf outputs only after changing `search.proto`:

```bash
make atheros-search-proto
```

## Search Model

Search requests support these kinds:

| Kind | Backing embedding kind |
|------|------------------------|
| `event` | `event` |
| `behaviour` / `behavior` | `behaviour_window` |
| `sequence` | `frame_sequence` |
| `device` | `device` |
| `cross` | event, behaviour window, frame sequence, and device |

Search modes:

- `dense`: embeds the query and runs `pgvector` cosine-distance search.
- `sparse`: runs SQL text matching/ranking over wireless and vector-backed
  source tables.
- `hybrid`: runs both paths and fuses results with weighted reciprocal-rank
  fusion controlled by `ATHSEARCH_HYBRID_ALPHA`.

The service applies threat boosts, stable result sorting, TopK clamping, query
logging, sequence log-probability scoring, and sparse fallback when hybrid query
embedding fails.

## Embedding Pipeline

The embedding pipeline is Postgres-centered:

1. SQL functions enqueue work in `vec_embedding_jobs`.
2. The worker leases pending jobs with a worker name and lease duration.
3. Text builders create deterministic embedding text for each source kind.
4. Jobs are grouped by embedding kind and sent to the external embedding
   backend.
5. Completion rows are persisted into `vec_embeddings` through batch SQL paths.
6. Failed jobs are retried or marked permanent depending on error class.
7. Worker state, queue depth, and latency metrics are published to Prometheus.

Supported text builders include:

- Wireless event frames
- Device profiles
- Behaviour windows
- Frame sequences
- Infrastructure subgraphs
- Baseline profiles
- Timing profiles

The service can also run a legacy embedded job drainer when
`ATHSEARCH_EMBEDDER_ENABLED=true`, but the configured worker path is the primary
processor.

For production-like runs, start or configure the embedding model backend before
enabling `ATHSEARCH_WORKER_ENABLED`, `ATHSEARCH_EMBEDDER_ENABLED`, or dense and
hybrid search traffic. Running those paths without a real embedding backend can
produce zero-vector embeddings that are only useful for smoke tests.

## Alerting

When worker mode and alerting are enabled, alert sweeps can refresh materialized
views and insert vector/security alerts for:

- Near-duplicate clusters
- Rogue clusters
- Deauthentication precursors
- High-risk APs
- Embedding drift
- Zero-trust overlay risk
- DNS privacy leaks
- RF impossible travel
- Rogue RF paths

Alert thresholds are controlled by `ATHSEARCH_ALERT_*` configuration.

## Configuration

Core environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ATHSEARCH_POSTGRES_DSN` | fallback to `DATABASE_URL`, then `SYNC_DATABASE_URL` | PostgreSQL connection string |
| `ATHSEARCH_REDPANDA_BOOTSTRAP` | fallback to `SYNC_REDPANDA_BOOTSTRAP_SERVERS` | Redpanda/Kafka bootstrap servers |
| `ATHSEARCH_EMBEDDING_BACKEND` | fallback to `VECTOR_EMBEDDING_URL` | Embedding backend base URL |
| `ATHSEARCH_EMBEDDING_MODEL` | `nomic-embed-text-v2-moe` | Embedding model name |
| `ATHSEARCH_EMBEDDING_DIMENSIONS` | `768` | Required vector dimension |
| `ATHSEARCH_EVENT_EMBEDDING_SCOPE` | `high_signal` | Event enqueue scope: `high_signal` or `all` |
| `ATHSEARCH_GRPC_PORT` | `50051` | gRPC listen port |
| `ATHSEARCH_HTTP_PORT` | `8080` | HTTP gateway listen port |
| `ATHSEARCH_METRICS_PORT` | `9090` | Prometheus metrics listen port |
| `ATHSEARCH_LOG_LEVEL` | `info` | Zerolog level |
| `ATHSEARCH_AUDIT_TOPIC` | `wireless.audit` | Wireless audit topic |
| `ATHSEARCH_BANDWIDTH_TOPIC` | `audit.wireless.bandwidth` | Bandwidth topic |
| `ATHSEARCH_CONSUMER_GROUP` | `atheros-search-ingest` | Redpanda consumer group |
| `ATHSEARCH_SEARCH_TIMEOUT_MS` | `10000` | Per-search timeout |
| `ATHSEARCH_HYBRID_ALPHA` | `0.5` | Dense-vs-sparse fusion weight |
| `ATHSEARCH_API_TOKEN_SHA256` | empty | Optional 64-character SHA-256 digest for bearer-token auth |
| `ATHSEARCH_CORS_ALLOWED_ORIGINS` | `http://127.0.0.1:5173` | Comma-separated allowed origins |

Worker configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `ATHSEARCH_WORKER_ENABLED` | `false` | Enable the primary embedding worker |
| `ATHSEARCH_WORKER_NAME` | hostname or `atheros-search-worker` | Worker identity for leases/state |
| `ATHSEARCH_WORKER_BATCH_SIZE` | `64` | Maximum rows leased per batch |
| `ATHSEARCH_WORKER_REQUEST_BATCH_SIZE` | min of batch size and request max | Per-request embedding group size |
| `ATHSEARCH_WORKER_REQUEST_BATCH_MAX` | `128` | Maximum request batch setting |
| `ATHSEARCH_WORKER_LEASE_SECONDS` | `1800` | Lease lifetime |
| `ATHSEARCH_WORKER_POLL_INTERVAL_MS` | `5000` | Idle polling interval |
| `ATHSEARCH_WORKER_MAX_DRAIN_BATCHES` | `0` | Drain limit per cycle; `0` means no configured limit |
| `ATHSEARCH_WORKER_MAX_INPUT_TOKENS` | `512` | Text truncation limit before embedding |
| `ATHSEARCH_WORKER_DB_CALL_TIMEOUT_MS` | `30000` | Timeout for worker DB calls |
| `ATHSEARCH_WORKER_MAX_CONCURRENT_EMBED` | `4` | Concurrent embedding requests |
| `ATHSEARCH_WORKER_MAX_CONCURRENT_COMPLETE` | `16` | Concurrent completion writes |

Optional feature flags:

| Variable | Default | Description |
|----------|---------|-------------|
| `ATHSEARCH_EMBEDDER_ENABLED` | `false` | Enable legacy embedded job drainer |
| `ATHSEARCH_INGEST_ENABLED` | `false` | Enable Kafka freshness consumer |
| `ATHSEARCH_SCHEMA_READY_REQUIRED` | `true` | Gate startup/readiness on schema control |
| `ATHSEARCH_SCHEMA_READY_TIMEOUT_MS` | `60000` | Startup schema wait timeout |
| `ATHSEARCH_SCHEMA_READY_POLL_INTERVAL_MS` | `1000` | Schema wait polling interval |
| `ATHSEARCH_READY_LAG_THRESHOLD` | `10000` | Readiness lag threshold |
| `ATHSEARCH_ALERT_ENABLED` | `false` | Enable alert sweeps from the worker |
| `ATHSEARCH_ALERT_SWEEP_INTERVAL` | `10` | Worker-iteration interval for alert sweeps |
| `ATHSEARCH_ALERT_NEAR_DUP_THRESHOLD` | `10` | Near-duplicate alert threshold |
| `ATHSEARCH_ALERT_AP_RISK_THRESHOLD` | `0.75` | AP risk alert threshold |
| `ATHSEARCH_ALERT_GRAPH_MAX_DEPTH` | `3` | Alert graph traversal depth |
| `ATHSEARCH_ALERT_SEQ_THRESHOLD` | `-15.0` | Sequence anomaly threshold |
| `ATHSEARCH_ALERT_TRAVEL_MAX_SPEED_MPS` | `50.0` | RF travel anomaly threshold |
| `ATHSEARCH_ALERT_DNS_LOOKBACK_MINUTES` | `15` | DNS alert lookback |

## Running Locally

From the repository root, run the vector profile:

```bash
REGISTRY=local IMAGE_TAG=dev \
  docker compose -f docker-compose.yaml -f docker-compose.build.yaml --profile vector up --build atheros-search
```

The compose service publishes:

| Host port | Container port | Purpose |
|-----------|----------------|---------|
| `50051` | `50051` | gRPC |
| `8080` | `8080` | HTTP |
| `19090` | `9090` | Prometheus metrics |

For a direct local process, provide at least a Postgres DSN:

```bash
cd services/atheros-search
POSTGRES_PASSWORD="$(cat ../../secrets/postgres.key)"
ATHSEARCH_POSTGRES_DSN="postgres://sync:${POSTGRES_PASSWORD}@127.0.0.1:5432/sync" \
ATHSEARCH_EMBEDDING_BACKEND='http://127.0.0.1:8083' \
go run ./cmd/server
```

If `ATHSEARCH_EMBEDDING_BACKEND` is unset, the service uses a zero-vector no-op
embedder. That is useful for wiring tests but not for meaningful vector search.
Run a compatible embedding model service and point `ATHSEARCH_EMBEDDING_BACKEND`
at it before testing dense/hybrid ranking or worker-generated embeddings.

## Example Requests

Search:

```bash
curl -sS http://127.0.0.1:8080/v1/search \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "deauth handshake high risk ap",
    "kind": "SEARCH_KIND_CROSS",
    "mode": "SEARCH_MODE_HYBRID",
    "topK": 10,
    "filters": {
      "threatOnly": true
    }
  }'
```

Stream results:

```bash
curl -N http://127.0.0.1:8080/v1/search/stream \
  -H 'Content-Type: application/json' \
  -d '{"query":"rogue ap","kind":"SEARCH_KIND_EVENT","mode":"SEARCH_MODE_HYBRID","topK":5}'
```

Readiness:

```bash
curl -i http://127.0.0.1:8080/readyz
```

Metrics:

```bash
curl -sS http://127.0.0.1:19090/metrics | grep '^athsearch_'
```

## Development

Run tests from this service directory:

```bash
go test ./...
```

Or use the repository Makefile from the root:

```bash
make atheros-search-test
make atheros-search-build
make atheros-search-proto
```

Build the server binary directly:

```bash
go build -o "${TMPDIR:-/tmp}/atheros-search" ./cmd/server
```

Format changed Go files:

```bash
gofmt -w <files>
```

## Operational Notes

- `proto/atheros/search/v1/search.proto` is the source of truth for the public
  protobuf API. Do not hand-edit generated `.pb.go` files.
- Shared PostgreSQL/vector schema belongs under `../../sql/`, not this service's
  `migrations/` directory, unless the schema is genuinely service-private.
- `/v1/search/stream` is a compatibility surface: it emits one protobuf-JSON
  `SearchResult` per line and finishes with `{"type":"done"}`.
- Logs intentionally hash or summarize search queries, source keys, session IDs,
  MAC-like identifiers, and other sensitive values.
- The Docker image builds with CGO enabled because the Kafka client depends on
  native libraries, then runs as a nonroot user on a distroless Debian image.
- Startup can fail fast if schema readiness is required and
  `schema_control.schema_ready` reports pending or failed objects.

## CV Summary

`Atheros Search` can be described as an AI-powered wireless security search
platform: a Go REST/gRPC service that combines PostgreSQL, pgvector,
Redpanda/Kafka, embedding workers, hybrid vector/keyword search, graph and
inventory APIs, Prometheus metrics, OpenTelemetry instrumentation, and
containerized production deployment.
