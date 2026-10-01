# Plan 002: Deliver a bounded table-first inventory report

> **Status: IN PROGRESS (local implementation verified; runtime validation pending).** Priority P1; effort M; change risk medium. Planned at
> `1316324e`, 2026-09-27. Depends on Plan 001 query/detail/error correctness.
>
> **Drift check:** `git diff --stat 1316324e..HEAD -- apps/integration-console/atheros-search apps/integration-console/atheros-search-ui`
> Reconcile changed excerpts and working-tree edits before proceeding.

## Business outcome

An operator can find an observed identifier, inspect registration/assignment and
follow evidence without scanning a force graph. Initial rows and counts are
per MAC, not per physical device. A table page renders without loading the
entire inventory. Keep the graph and existing identity queue as secondary views.

## Current state

[inventory.go](../apps/integration-console/atheros-search/internal/reporting/inventory_assembly.go)
defines `InventoryFilters` with owner/location/active/tags and cursor controls
(lines 46-56), and `InventoryNode` with MAC and optional registry fields (lines
59-74). `first_seen` and `registered` exist in storage but are not returned as
explicit row fields. `total_registered_count` is global. Similarity grouping
synthesizes node fields from pending pairs; it is not a confirmed identity API.

[InventoryPage.tsx](../apps/integration-console/atheros-search-ui/src/pages/InventoryPage.tsx)
uses graph or dedup queue; the SVG is the graph fallback (lines 201-235).
[useInventory.ts](../apps/integration-console/atheros-search-ui/src/hooks/useInventory.ts)
already loads `scope: all` pages for graph coverage. Reuse normalization,
authenticated fetch and cancellation from
[client.ts](../apps/integration-console/atheros-search-ui/src/api/client.ts).

## Scope and constraints

Scope: inventory query/API tests, additive row/filter metadata, UI inventory
store/hook/page/controls/detail, a new `InventoryTable.tsx`, inventory styles and
unit/E2E tests. Match existing SolidJS signals/memos and styles from
[tokens.css](../apps/integration-console/atheros-search-ui/src/styles/tokens.css).
Use native table markup, ordinary pagination and existing icons. No new UI
framework, generic table DSL or new dependency is required.

Out of scope: schema changes, physical-asset consolidation, new owner/CMDB CRUD,
activity timelines, export service, restored retired types and new similarity
search. Keep existing grouping/graph responses compatible; never reinterpret
`active` as online status.

## Steps and verification gates

1. Specify an additive table response/query mode in the existing inventory
   family: one device row per MAC; explicit registered state, first/last observed
   and optional registration/owner/location/aliases; scoped result count; stable
   server sorting and a filter/sort-bound cursor. Default to last-observed
   descending plus MAC tie-break. Restrict sort columns to a server allow-list.
   Keep pending review as pair/count metadata, not one similarity cluster field.
   Verify `go test ./internal/search ./internal/api` with unique/tied ordering,
   unknown values, multi-candidate identifiers and global-versus-filtered counts.
2. Add server identifier/name search and Registered/Needs identity review
   predicates before limits. Existing inventory filters do not implement these
   presets. Reuse stored registration and pending candidate evidence; never infer
   registration from labels or reject records because they are outside a loaded
   graph. Verify the same Go tests across multiple pages and empty filters.
3. Add independent table page state and cancellation. Reset cursor on filter or
   sort change; ignore late responses. Start at 50 rows per request. Preserve
   existing graph coverage loader for graph mode only. Add a first-user default
   `table` view and migrate persisted legacy graph/queue choices safely.
   Verify `bun run test:unit` in the UI with cancellation, reload and view-mode cases.
4. Build `src/components/inventory/InventoryTable.tsx` with identifier/name,
   registration, owner, location, last observed and review state. Move tags,
   aliases and evidence to selected detail. Unknown values have explicit text.
   Use sortable headers with `aria-sort`, labelled page controls and separate
   row-action buttons. Keep search, view preset and owner/location controls
   simple; retain Advanced for uncommon filters. Verify unit tests and lint.
5. Connect row detail, scoped map and review actions to Plan 001 contracts.
   Selection/detail remains independent of the current page and graph cache.
   Show loading, empty, error and incomplete/freshness states distinctly; count
   labels state their grain. Verify `bun run test:e2e` with paginated fixtures,
   browser Back/reload, off-page detail and failed review actions.
6. Verify responsive overflow, keyboard navigation, focus return and reduced
   motion at 375/768/1024/1440 widths. Use accessible horizontal table scrolling
   or a readable narrow layout. Verify `bun run test:a11y` and `bun run build`.

## Done criteria and operational benefit

- Go query/API tests and UI unit/lint/build/E2E/a11y commands exit zero.
- A later-page record can be found by server search/sort without downloading all
  rows; counts equal the same filtered predicate over the fixture.
- Multiple pending matches appear as independent pairs, with no false physical
  asset count or client/online assumption.
- Known-identifier lookup and evidence drill-down work without Advanced controls.
- Table startup does not invoke the graph-wide page loop; stale requests cannot
  overwrite a newer filter. Record payload/latency baseline on the fixture.
- Existing graph/queue workflows remain covered; update the plan index after review.

## Stop conditions and maintenance

Stop if owner/registration semantics cannot be traced to a trusted source, a
proposed preset requires client filtering, count and row predicates diverge, or
an incompatible schema/API change becomes necessary. Report unknown provenance
instead of inventing it. Future physical-asset grouping must define its stable
identity key separately from the MAC-row report.
