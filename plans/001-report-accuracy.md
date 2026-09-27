# Plan 001: Make report scope and evidence trustworthy

> **Status: IN PROGRESS (local implementation verified; runtime validation pending).** Priority P1; effort L across small changes; change risk
> medium. Planned at `1316324e`, 2026-09-27. No dependencies.
>
> **Drift check:** `git diff --stat 1316324e..HEAD -- apps/integration-console/atheros-search apps/integration-console/atheros-search-ui`
> Also inspect working-tree changes. If the facts below differ, reconcile the
> plan before implementing; never overwrite unrelated edits.

## Business outcome

An operator follows the same scoped evidence between Inventory, map, Search and
Explain, can review a pair without loading a whole graph, and sees whether a
final decision succeeded. Empty results must reflect the query scope rather
than an unrelated global candidate limit or a missing anchor fallback.

## Current state and boundaries

- [dense.go](../apps/integration-console/atheros-search/internal/search/dense.go)
  limits nearest candidates before `resultMatchesFilters` (lines 83, 120-138).
  [sparse.go](../apps/integration-console/atheros-search/internal/search/sparse.go)
  does the same for ranked and wildcard retrieval (lines 80-88, 117-136).
- [graph.go](../apps/integration-console/atheros-search/internal/search/graph.go)
  uses `if len(focusIDs) > 0` to add focus, while an absent anchor returns
  `nil, nil`. Both paginated and legacy paths need explicit absent-focus behavior.
- [InventoryPage.tsx](../apps/integration-console/atheros-search-ui/src/pages/InventoryPage.tsx)
  resolves selection through `inventoryNodes().find(...)` (lines 93-96).
  [MergeCandidatePanel.tsx](../apps/integration-console/atheros-search-ui/src/components/inventory/MergeCandidatePanel.tsx)
  resolves pair endpoints through graph nodes/edges (lines 48-65).
- [useInventory.ts](../apps/integration-console/atheros-search-ui/src/hooks/useInventory.ts)
  sends decision errors to `inventoryError` (line 173), which the queue view
  does not display. The independent queue already has separate data/error state.
- [service.go](../apps/integration-console/atheros-search/internal/search/service.go)
  rejects behaviour/sequence kinds (lines 342-345). The UI selector offers them.
- [fusion.go](../apps/integration-console/atheros-search/internal/search/fusion.go)
  computes `weight / (rrfK + rank)` contributions. Raw cosine, keyword rank and
  boost do not form the percentage decomposition displayed by ScoreBar.

Scope: Go search/filter/graph/inventory detail and API route handling with their
tests; UI client/types, report navigation, queue/detail/error state, kind
selector, score display and corresponding tests. Reuse parameterized SQL,
filter-bound cursors, cancellation and same-origin return validation. Preserve
public shapes with additive extensions. Keep role checks on the server.

Out of scope: new graph layouts, table redesign, semantic seed-vector APIs,
retired-kind restoration, final-decision reversibility, production changes and
new schema definitions. Pair decisions remain final and recorded by Search;
confirmation/projection remains Octopus-owned.

## Steps and verification gates

1. Build one parameterized predicate specification from the existing
   [filters.go](../apps/integration-console/atheros-search/internal/search/filters.go)
   rules. Apply supported scope predicates before limiting sparse/wildcard
   candidates and inside dense candidate selection. Keep active-version/model
   constraints and deterministic tie-breaking. Preserve hybrid fallback.
   Verify with `go test ./internal/search` from the Go service directory.
   Add a matching record beyond the old overfetch window to a representative
   ephemeral PostgreSQL fixture and assert sparse, wildcard and dense filtered
   retrieval find it. A SQL-string assertion alone is insufficient.
2. Distinguish "no focus requested" from "focus requested but missing". Return
   an empty focused graph for unknown/excluded anchors in both paths; retain
   existing in-scope neighborhood behavior. Verify the same targeted Go tests
   with missing, filtered-out and valid anchor cases, including both scopes.
3. Make selected review detail independent of graph presence. Reuse complete
   queue pair data if its contract contains endpoints/evidence; otherwise add
   an authenticated read-only candidate detail route in existing inventory API
   handling. Return both endpoints, candidate evidence and lifecycle. Do not
   introduce graph-wide loading as a workaround. Verify
   `go test ./internal/search ./internal/api` and UI unit tests for off-page pairs.
4. Display decision errors in the active review surface, keep failed candidates
   visible, disable repeated pending submissions and refresh authoritative state
   after conflicts/success. Say "Decision recorded"; do not announce completed
   identity consolidation. Verify UI tests for 403, 409 and network failure.
5. Centralize serialization of applicable investigation scope and validated
   return URLs using existing URL hooks and
   [returnPath.ts](../apps/integration-console/atheros-search-ui/src/auth/returnPath.ts).
   Preserve entity/site/sensor/time filters, query/mode/type and result settings
   through map-to-search and Search-to-Explain-to-results. Show unsupported scope
   explicitly. Verify URL round-trip and unsafe-return-path tests.
6. Remove retired choices from normal Search controls without renumbering proto
   enums. Handle legacy URLs with a clear unsupported message. Label pending
   pair relationships as possible identity matches. Present ranking factors
   individually with their units; retain cosine range and separate risk.
   Omit unsupported graph first-seen values rather than copy latest observation.
   Verify tests for legacy kinds, mixed ranking modes and unavailable timestamps.

## Commands and done criteria

From [the Go service](../apps/integration-console/atheros-search/), run
`go test ./internal/search ./internal/api`, then `go test ./...` for changed
shared query/API contracts. From [the UI](../apps/integration-console/atheros-search-ui/),
run `bun run test:unit`, `bun run lint`, `bun run build` and `bun run test:e2e`
for changed investigation flows. Successful commands exit zero. Model tests on
existing `filters_test.go`, `graph_test.go`, `inventory_test.go`, API tests and
UI client/return-path tests rather than introduce a second test framework.

Done requires all named regressions passing, API compatibility tests passing,
visible failure states, scope round trips and no production/unrelated changes.
Capture latency/plan effects of predicate pushdown on representative fixtures;
filtered ANN retrieval must be assessed for recall as well as speed. Update the
index status only after reviewer evidence is available.

## Stop conditions and maintenance

Stop and report if meaningful PostgreSQL fixture coverage is unavailable, dense
filtering loses required recall, a pair lacks independent detail data, or a
change requires a new incompatible contract/schema. Resolve that prerequisite
explicitly rather than substituting client filtering or fabricating evidence.
Future filters must enter the common predicate and navigation contracts together.
