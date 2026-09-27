# Atheros reporting implementation evidence

> **Status: Implemented in the local checkout; release validation remains open.**
> Checked on 2026-09-27. The test data described below is synthetic. This note
> does not claim deployed population, sensor coverage or production capacity.

The [reporting workmap](atheros-reporting-workmap.md) and
[data contract](atheros-reporting-data-contract.md) define the intended scope.
The implementation is in
[Atheros Search](../apps/integration-console/atheros-search/) and the
[Integration Console UI](../apps/integration-console/atheros-search-ui/).

## What is available

- Search applies location, sensor, MAC, time and other supported predicates in
  candidate selection before the limit for both dense and sparse retrieval.
  Empty or excluded graph anchors return an empty focused result with a reason.
  A pending pair uses `candidate_pair`; `same_device` is reserved for confirmed
  identity. Graph nodes omit first/last ranges when only a latest projection
  timestamp exists.
- The inventory defaults to a bounded table with one row per MAC. Presets,
  identifier/name search, owner/location filtering and sorting run on the
  server before a 50-row page limit. The cursor includes the normalized filter
  and sort scope, with the MAC as the unique tie-breaker. Row and pair details
  load independently. A failed final decision keeps the pair and its evidence
  available for retry. Successful responses say that the decision was recorded;
  they do not claim that the identity projection has updated.
- The map opens on a scoped AP overview. Selecting a BSSID shows an independently
  counted, bounded roster and a map of the current page. Both use active,
  timestamped searchable wireless records. Distinct MACs count once at each
  observed AP; an identifier observed at two APs counts once in each AP roster.
  Self-observations, broadcast and unspecified MACs/BSSIDs are excluded.
  Unknown-role identifiers are included. Optional identity and RF hints come
  from the latest graph projection and are labeled as such. A missing graph AP
  edge is labeled **No AP link in this projection**, with no risk styling or
  claim about historical absence. Map distance does not represent distance in
  the physical world.
- Search, inventory and map responses disclose grain, scope, count meaning,
  response generation time, observation basis, loaded/total rows when available
  and unavailable freshness/coverage capabilities. Pipeline health is shown
  separately as a global operational status. Explain shows raw method-specific
  factors; return links validate same-origin paths and preserve the report URL.

The network endpoint is `POST /v1/network-map`. The Search filter additions
(`bssid`, `observed_ap_context_only`, `entity_query`) are additive protobuf
fields; the generated protobuf code was regenerated from `search.proto`.
These fields let an AP roster link request the same qualifying Search records.
The active document set is a searchable projection, so absent results are not
proof that a sensor saw no activity. The optional graph layer uses cumulative
edge evidence and cannot establish arbitrary historical-interval absence.
No raw MAC or query is added to telemetry labels.

## Verification and measurement

The [Testcontainers reporting harness](../scripts/tests/test_atheros_reporting.py)
applies the canonical Atheros Search manifest in a disposable PostgreSQL
database and runs Go regressions. These cover a match beyond the former global
top-N, missing/excluded graph focus, independent pair detail and finality,
inventory pages and cursor scope, and agreement among scoped AP counts, roster
and Search. `go test ./...` passes in Atheros Search. UI unit tests, typecheck,
lint, production build and Chromium reporting/accessibility tests pass. The
browser tests exercise pair retry, pagination/reload, Graph to Explain and back,
and 375, 768, 1024 and 1440 pixel layouts with reduced motion. The previous
graph interactions are reachable and tested through Advanced.

Local baseline, 25 warmed service calls per row, including JSON serialization.
Fixture: 2,000 registry MACs, 20,100 event records, 21 APs. The busy AP has
2,000 distinct MACs and 20,000 records; each of 20 sparse APs has five records.
The measurements were captured on local Docker/Testcontainers, not on the
production host or a representative retained dataset. They are diagnostic
starting points, not release targets.

| Response | p50 | p95 | JSON payload |
|---|---:|---:|---:|
| Inventory, 50 rows | 1.24 ms | 2.67 ms | 17,570 bytes |
| AP overview, up to 50 APs | 79.80 ms | 85.74 ms | 5,823 bytes |
| Busy AP roster, 50 rows | 103.53 ms | 110.45 ms | 30,292 bytes |
| Sparse AP roster, 50 rows | 46.95 ms | 49.61 ms | 3,780 bytes |

Before release, validate runtime source/projection watermarks, retention,
grants, sensor coverage and operator task outcomes against a representative
non-production environment. Repeat p50/p95 and payload measurements on that
dataset and hardware before setting a release threshold. No full-result export,
activity timeline, semantic device comparison or `embedding_similar` edge is
part of this implementation.
