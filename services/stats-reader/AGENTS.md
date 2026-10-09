# AGENTS.md

## Scope
Service-specific rules for `services/stats-reader`. Repository and
`services/` parent rules still apply.

## Boundary
- Read path order is Redis hot snapshot -> MinIO fallback -> in-process
  last-good copy. No Kafka or Octopus clients live in this service.
- Never synthesize metric values. Missing fields stay missing or null;
  a measured zero is fine, an invented zero is not.
- Never emit store hostnames, credentials, or connection errors in
  response bodies or logs.

## Behavior invariants
- `/ready` and `/live` are always 200 once the process is up. Store
  health never gates readiness, so Traefik keeps routing here.
- `/public/stats` strips non-allowlisted keys (snapshot v2) before emit
  and rejects payloads without `asOf`.
- CORS allowlist comes from `STATS_ALLOWED_ORIGINS`; OPTIONS is supported
  on `/public/stats`.
- `/health` reports store reachability for operators only. Traefik does
  not use it.

## Config
- Full env table lives in [README.md](README.md).
- Kubernetes secret keys differ from env names:
  `redis-runtime` key `password` -> `REDIS_PASSWORD`;
  `minio-credentials` keys `access-key` / `secret-key` ->
  `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY`.

## Verification
- `go test ./...` must pass before any change lands.
- Prefer `make test`, `make vet`, and `make fmt-check` for local checks.
