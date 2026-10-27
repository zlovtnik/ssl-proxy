# Atheros Search: source to retrieval

Atheros Search is one authenticated workbench for RAG builders and operators.
It joins evidence retrieval, indexing readiness, ingestion visibility and
configured source coverage through the existing Search API. Graphs, inventory,
explanations and DQ remain supporting tools. Retrieval returns ranked evidence;
generated answers, new connectors and new operational mutation controls are
outside this release.

## Follow the evidence

1. The [proxy](../src/) and [Atheros Sensor](../services/atheros-sensor/)
   publish observations and work discovery through Redpanda. They have no
   database credentials or direct persistence ownership.
2. [Octopus](../services/octopus/) owns durable ingestion, deduplication,
   per-topic/partition/offset evidence, document preparation, embedding-job
   creation and maintained PostgreSQL projections. Delivery can repeat;
   committed offsets and durable deduplication support replay.
3. [Search](../apps/integration-console/atheros-search/) claims embedding jobs
   with tokens and fences, calls the configured embedding backend, and
   atomically writes vectors and completes matching work. Coordinator recovery
   and embedding-worker recovery remain distinct responsibilities.
4. The [console](../apps/integration-console/atheros-search-ui/) calls the
   authenticated Search API for term, vector or hybrid retrieval, ranked
   records, evidence and operational reads. Existing HTTP and gRPC search
   contracts and fallback semantics remain in place.

An ingested event does not prove its projection is current, a document is
lexically retrievable, or its embedding exists. These are separate states.
Missing measurements remain unknown, rather than zero or ready. Operational
measurements are global unless explicitly scoped; a search filter does not
silently scope pipeline totals.

## Use the workbench

| Workspace | Entry point | Review task |
| --- | --- | --- |
| Retrieval | `/` | Query evidence and inspect ranked results and supporting records |
| Ingestion | `/ingestion` | Inspect stages, backlog, failures, workers and measurement freshness |
| Sources | `/sources` | Review configured proxy and wireless source coverage and available readiness measurements |
| Evidence | Existing graph, inventory and explanation routes | Explore relationships, observed identifiers and ranking explanations |
| Processing | Existing DQ route | Use the existing permission-controlled processing workspace |

The proxy source detail separates indexed evidence from live aggregate
telemetry. Indexed records describe observations that passed through ingestion;
live counters describe the responding proxy process. Neither establishes the
other's completeness. An observation does not establish an active connection
or physical device identity; identity suggestions remain review candidates.
Sensor placement, configured channels, observation time and address
randomization limit coverage.

The legacy proxy dashboard entry now launches the unified proxy source view
at `https://search.rclabs.uk/sources/proxy`. Internal machine APIs retain their
existing contracts; browser users authenticate through Search and do not enter
a proxy administrator key.

## Operational reads and freshness

| Search HTTP interface | Access | Meaning |
| --- | --- | --- |
| `GET /v1/operations/pipeline` | Viewer and above | Allowlisted measurements from existing ETL aggregation |
| `GET /v1/operations/sources` | Viewer and above | Available proxy/wireless indexed coverage and readiness |
| `GET /v1/operations/proxy/live` | Operator or administrator | Safe live aggregate proxy telemetry |

Search authenticates and authorizes before returning cached data. The existing
Keycloak issuer, client, audience and roles remain the login contract. The
browser receives neither proxy administrator keys nor arbitrary worker
metadata, peer addresses or raw upstream errors. Upstreams are fixed by server
configuration, with narrow Search-to-proxy access declared through
[GitOps](../cyber-stack/README.md).

Pipeline measurements reuse the 30-second ETL cache and become stale after
60 seconds. Proxy requests have a two-second timeout and share a five-second
cache; live readings become stale after 15 seconds and unavailable after
60 seconds. Rates are unavailable on the first sample, counter reset or
process change. A failed telemetry read does not make retrieval unready.

The proxy's bounded `/internal/telemetry` response uses the observability
listener and exposes cumulative counters, active tunnels, safe publisher
status, a measurement time and an opaque process identity. It has no peer or
configuration dump. Throughput and history use the existing materialized
Octopus snapshots, retaining their original timestamps: live readings have a
180-second freshness limit and peaks have a 360-second limit. Recorded history
is labelled separately and never becomes a new live observation merely
because it was fetched again.

## Public walkthrough and companion tooling

The [public site](../apps/product-site/) explains this workflow with labelled
synthetic browser samples. Those samples neither connect to the authenticated
console nor demonstrate live ingestion. The proxy and Octopus public URLs
remain technical component pages. Public Octopus measurements come from the
runtime snapshot feed, with their own coverage and freshness limits.

[Schema Migrator](../apps/schema-migrator/) remains companion tooling for
reviewing ordered SQL changes. Its SQL-file snapshots preserve source files
and checksums, not database data. Its public demonstration executes no SQL.

For implementation ownership and delivery boundaries, read the
[system architecture](architecture.md); for deployment operation, read the
[runbook](runbook.md). Image promotion uses reviewed digest changes and
rollback uses Git reverts.
