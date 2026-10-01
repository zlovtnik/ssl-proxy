# Plan 003: Deliver a focused AP map with an evidence roster

> **Status: IN PROGRESS (local implementation verified; runtime validation pending).** Priority P2; effort L; change risk medium. Planned at
> `1316324e`, 2026-09-27. Depends on Plan 001 scope correctness and Plan 002
> row/detail contract. AP overview can be developed in parallel with the table.
>
> **Drift check:** `git diff --stat 1316324e..HEAD -- apps/integration-console/atheros-search apps/integration-console/atheros-search-ui services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql`
> Reconcile source/working-tree drift before changing files.

## Business outcome and current state

An operator selects an AP, sees scoped observation counts and a bounded roster,
and follows a relationship to its evidence. Missing AP context is neutral and
bounded by available coverage. Layout position never suggests physical distance.

[IdentityGraphSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IdentityGraphSql.scala)
projects `'observed_at', COUNT(*), 'frame_count'` for any frame with source MAC
and BSSID (lines 381-393). The API maps this stored kind to `association` in
[graph.go](../apps/integration-console/atheros-search/internal/reporting/graph_assembly.go).
This is evidence of observed context, not verified session association.

[useGraphAggregate.ts](../apps/integration-console/atheros-search-ui/src/hooks/useGraphAggregate.ts)
groups loaded devices by AP when over a node threshold (lines 59-66); loose
devices are a render classification, not a complete-data absence query.
[graphStore.ts](../apps/integration-console/atheros-search-ui/src/stores/graphStore.ts)
defaults to `scope: all` and all nine listed edge kinds. Existing force layout,
selection and aggregation remain useful presentation components.

## Scope and boundaries

Scope: graph query/API plus tests; additive AP overview, focus and roster
contracts; graph client/types/store/hooks/controls/panel/legend and UI tests.
Use existing parameterized queries, bounded cursors and request cancellation.
Reuse inventory detail rather than duplicate device profile loading.

Out of scope: geographic mapping, new graph engine, automatic AP authorization,
seed-device similarity, activity/anomaly alerts and schema changes in this
delivery. Any needed aggregate projection is a separately reviewed Octopus-owned
addition through canonical manifests; Search must not maintain projections.

## Steps and verification gates

1. Define an AP overview query that counts distinct qualifying observed MACs
   per BSSID within one site/sensor/retained time scope. Exclude AP self-frames
   and broadcast; document unknown roles and multiple AP contexts. Use source
   evidence for historical interval semantics: latest graph timestamps cannot
   reconstruct intervals. Return BSSID/name, latest observation, count and
   coverage/freshness metadata. Verify `go test ./internal/search ./internal/api`
   with self-frame, duplicate-frame, multi-AP and time-bound fixtures.
2. Add explicit focused AP selection by validated AP/BSSID identity. Reuse a
   scoped graph neighborhood path; add `ap_id` only if existing anchoring cannot
   express it safely. Keep one-hop default, node/edge budgets, paginated roster
   and explicit partial state. Never ignore global limits. Count the roster on
   the server independently of loaded graph edges. Verify targeted Go tests with
   a roster exceeding a page and missing/out-of-scope APs.
3. Provide a source-scoped **No AP context observed** query only if retained
   observations and coverage can establish it. Keep its anti-existence test
   independent of visible kinds and pagination. If only the current projection
   can be queried, label **No AP link in this projection** and disclose lag;
   do not offer historical/no-association claims. Use stored `observed_at` mapping
   when querying graph edges. Verify truncated pages, hidden edges, absent
   coverage, old links and partial projection fixtures.
4. Make AP overview the map entry presentation. Selection opens the focused map
   and paginated roster; Clear focus restores prior scope. Start at 200 visible
   nodes with explicit expansion; maintain selections and reduce motion during
   updates. Default to observed AP evidence, optional identity/RF layers, and
   Advanced technical controls. Show inferred evidence with method/units, never
   with connection or threat language. Verify `bun run test:unit` and lint.
5. Add a readable list/roster alternative with the same selection and evidence
   actions. Keep Search navigation scoped through Plan 001. Multiple AP links
   remain visible in detail even if layout uses one presentation group. Test
   map-to-roster-to-Search consistency and keyboard flow with
   `bun run test:e2e` and `bun run test:a11y` in the UI.
6. Capture payload/query/UI latency on representative sparse and busy AP
   fixtures. Verify `bun run build`, targeted Go tests then `go test ./...` for
   changed shared queries. If coordinator SQL changes are approved separately,
   also run the relevant `IdentityGraphSqlSuite` and projection tests from Octopus.

## Done criteria

- AP overview, roster and map use the same grain, scope and count rule.
- Missing anchors stay empty; absent coverage is unknown; graph-edge visibility
  cannot alter the absence classification.
- Busy APs use bounded pages, cancelled queries do not overwrite current focus,
  and no automatic all-scope download gates initial rendering.
- Self-frames and duplicate frames do not inflate roster counts.
- A multi-AP identifier is not presented as exclusive membership.
- Default view is readable without technical filters, with a keyboard-accessible
  equivalent. Named tests/build/lint/a11y checks pass and budgets are measured.
- Update the index after evidence-based review; do not claim production capacity
  from synthetic or cached unit tests.

## Stop conditions and maintenance

Stop if source retention/coverage cannot support time-scoped absence, if queries
need unbounded scans at representative scale, or if the work requires a new
projection/index/privilege contract. Split that prerequisite into a reviewed
change with migration/checksum/grant tests. Future association/session claims
require stronger evidence and an explicit versioned semantic contract.
