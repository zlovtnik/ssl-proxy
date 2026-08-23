# Atheros Search Privacy

Atheros Search handles wireless metadata, normalized document text, vector
embeddings and query analytics. Treat all of them as potentially identifying
even when obvious identifiers are removed. The service boundary is described
in [System Architecture](architecture.md).

## Default analytics policy

Rows in `search_queries` expire after 30 days by default through `expires_at`
and the schema's purge operation. Runtime retention automation must be verified
in the deployed PostgreSQL topology; a schema declaration alone does not prove that a
purge scheduler is running.

Normal write paths must not store raw `query_text`, `session_id` or
`result_keys`. Store:

- `hashed_query_text`
- `session_hash`
- `result_key_hashes`

The nullable raw columns are reserved for an explicit diagnostic opt-in that
documents operator authorization, user notice or consent, access scope and a
shorter retention period.

## Logging and telemetry

- Do not log raw queries, source keys, session IDs, API tokens or full MAC
  addresses.
- Do not use those values as Prometheus labels or trace attributes.
- Hashes are still linkable identifiers; restrict access and use scoped salts
  or keyed hashing where the established contract permits it.
- Disable or redact request-body capture at proxies and observability agents.

## Documents and vectors

Normalized text and embeddings can reveal source behavior or device
characteristics. Keep them in the `atheros_search` domain, grant access only to
Octopus preparation paths and Atheros Search query/worker paths, and delete
derived vectors when the source document is lawfully removed.

## Operator checklist

1. Verify API auth and CORS for every exposed Search route.
2. Confirm analytics expiration and deletion behavior against live PostgreSQL.
3. Review diagnostic opt-ins and remove them when the incident closes.
4. Confirm Grafana, Loki, Prometheus and Jaeger are not publicly reachable.
5. Test deletion across documents, jobs, vectors, analytics, logs and exports.
