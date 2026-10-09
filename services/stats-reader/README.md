# stats-reader

Tiny always-Ready HTTP service that serves precomputed public stats JSON
for the product site. It is passive: the request path never computes
metrics and never touches Postgres or Kafka. Snapshots are produced by
Octopus's metric worker pool and published to Redis and MinIO.

## Endpoints

| Route | Behavior |
|---|---|
| `GET /public/stats` | Redis `GET stats:current:v2` -> MinIO `stats/latest.json` -> in-process last-good -> `503 {"error":"Metrics unavailable"}` |
| `GET /ready` | Always `200 ok` once the process is up |
| `GET /live` | Always `200 ok` once the process is up |
| `GET /health` | `200 {"redis":bool,"minio":bool}` for operators (not used by Traefik) |

`/public/stats` also answers `OPTIONS` for CORS preflight.

### Response contract

- `Content-Type: application/json`
- `Cache-Control: public, max-age=30`
- `Vary: Origin`
- CORS allowlist origins (default `https://rclabs.uk`,
  `https://www.rclabs.uk`) get `Access-Control-Allow-Origin`.
- A payload is served only when it parses and carries `asOf`. Unknown
  keys are stripped before emit. Missing fields stay missing or null -
  the service never invents zeros and never reports store hostnames.

### Snapshot v2 allowlist

Top-level: `asOf`, `peaksComputedAt`, `peakRecordsDay`,
`peakRecordsDayDate`, `peakRecordsWeek`, `peakRecordsWeekStart`,
`peakRecordsWeekEnd`, `liveStrip`, `lifetimeTotals`, `throughput24h`,
`throughput7d`.

Nested: `liveStrip` keeps `ingestProcessedRatePerSec`,
`pendingLedgerCount`, `lastIngestSuccessAt`, `backpressureActive`.
`lifetimeTotals` keeps `recordsTotal`, `daysCounted`, `computedAt`.
`throughput24h` / `throughput7d` keep `bucket` and `series` (array of
`{bucketStart, records}`).

## Configuration

| Env | Default | Notes |
|---|---|---|
| `STATS_HTTP_PORT` | `8080` | Listen port |
| `REDIS_ADDR` | `ssl-proxy-redis-runtime:6379` | Hot snapshot store |
| `REDIS_PASSWORD` | (empty) | Secret `redis-runtime`, key `password` |
| `REDIS_KEY` | `stats:current:v2` | Snapshot key |
| `MINIO_ENDPOINT` | `ssl-proxy-minio-api:9000` | host:port; optional `http(s)://` prefix is stripped |
| `MINIO_ACCESS_KEY` | (empty) | Secret `minio-credentials`, key `access-key` |
| `MINIO_SECRET_KEY` | (empty) | Secret `minio-credentials`, key `secret-key` |
| `MINIO_USE_SSL` | `false` | TLS to MinIO |
| `MINIO_STATS_BUCKET` | `ssl-proxy-stats` | Snapshot bucket |
| `MINIO_STATS_PREFIX` | `stats/` | Object prefix; key is prefix + `latest.json` |
| `STATS_ALLOWED_ORIGINS` | `https://rclabs.uk,https://www.rclabs.uk` | Comma-separated CORS allowlist |

Note the Kubernetes secret keys differ from the env var names the
process reads: `redis-runtime/password` feeds `REDIS_PASSWORD`, and
`minio-credentials/access-key` + `minio-credentials/secret-key` feed
`MINIO_ACCESS_KEY` + `MINIO_SECRET_KEY`.

## Build and test

```sh
make test
make build
```

The `Dockerfile` is multi-stage and runs as nonroot on
`gcr.io/distroless/static-debian12:nonroot`, exposing port 8080. Base
images use version tags (same pattern as
`apps/integration-console/atheros-search`). Jenkins publishes the
bootstrap image and records its digest in `artifacts/stats-reader-buildx.json`.
The gateway continues to serve `/public/stats` from Java Coordinator during
bootstrap. After reviewing the published digest, add `stats-reader` to the
deployable image contract and both app-stack Kustomizations, add the base
resource to each app-stack slice, and switch the public gateway route and
its GitOps check to `ssl-proxy-stats-reader`.
Production images are pinned by digest at the Kubernetes layer, not in
this Dockerfile.

## Layout

```
cmd/stats-reader/     process entrypoint
internal/config/      environment configuration
internal/store/       Redis + MinIO + last-good fallback
internal/http/        routes, CORS, key allowlist
```
