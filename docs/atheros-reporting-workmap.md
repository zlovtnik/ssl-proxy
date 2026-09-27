# Atheros reporting: business review and implementation workmap

> **Status: Proposed, source-reviewed.** Reviewed on 2026-09-27 against commit
> root `1316324e` and Integration Console `18c56d1`. This replaces the assumptions in the pasted Inventory Report +
> Network Map Redesign proposal. No application changes or production data
> validation have been performed as part of this review.

## Decision

Build a table-first inventory and a focused relationship map, joined to Search
and Explain through a shared investigation scope. Correct report semantics and
query behavior before adding visual features. Keep the existing SolidJS, Go,
PostgreSQL and Octopus boundaries; a new graph engine, reporting framework,
database or generic filter builder is unnecessary for the first release.

The console serves network operators and security analysts. Its useful outcomes
are finding an observed identifier, understanding where and when it appeared,
following evidence to an AP or event, and reviewing possible identity matches.
Passive observations alone do not establish asset ownership, a physical-device
count, current connectivity, authorization or a security incident.

The [data contract](atheros-reporting-data-contract.md) defines table grains,
relationships and the claims each report can support. The executable work is
split into [three implementation plans](../plans/README.md).

## Business questions and report responsibilities

| Surface | Operator question | Primary presentation | Meaningful next action |
|---|---|---|---|
| Inventory, `/inventory` | What identifiers have we observed, and which need attention? | Paginated table; one row per observed MAC initially | Open evidence, map context or identity review |
| Network map, `/graph` | Which APs and identifiers were observed together in this scope? | AP overview, then one focused neighborhood and roster | Inspect relationship evidence or search scoped events |
| Identity review, existing inventory queue | Do these two identifiers have enough evidence for an identity decision? | Pair comparison with reasons, conflicts and provenance | Record the existing final decision |
| Search, `/` | Which wireless or proxy records support this investigation? | Ranked results with supported source type and scope | Open Explain or relevant map/inventory entity |
| Explain, `/explain/:sourceKey` | Why was this record returned and what evidence does it contain? | Source details, ranking factors and return context | Return to the same results and filters |
| ETL health APIs | Is the evidence pipeline fresh enough to trust these reports? | Compact freshness/coverage status in report chrome; operational detail separately | Diagnose delayed ingestion, projections or embeddings |

ETL is an existing backend API capability, not a separate routed UI report
today. Proxy events and blocked-host windows remain Search reports. A wireless
MAC and a proxy device ID must not be joined as the same asset without an
explicit trusted mapping. Schema Migrator and identity-provider administration
are separate products and are outside this wireless reporting redesign.

## Corrections to the original proposal

| Proposed assumption | Verified current state | Decision |
|---|---|---|
| Zero association edges means never connected to an AP | Stored `observed_at` edges map to API `association`; the projector groups any frames with source MAC and BSSID | Label this observed AP context. Do not claim connection history |
| SQL can query `edge_kind = 'association'` | The relevant stored kind is `observed_at` | Use storage/API mappings explicitly; the pasted predicate would misclassify identifiers |
| Loose graph nodes are solo devices | Missing edges can reflect paging, filters, projection lag or retained-data limits | Compute absence on the server against a defined evidence scope; show unknown when coverage is insufficient |
| Solo devices deserve a warning tint | Absence of AP context is not evidence of risk | Use a neutral label and explain the observation boundary |
| Main APs require a configurable device threshold | This adds a control without defining a decision it helps | Sort APs by distinct observed identifiers; show counts and freshness |
| AP detail should ignore global limits | A busy AP can have an arbitrarily large roster | Keep bounded requests and server pagination |
| Existing inventory fields provide a complete report | Rows are MAC records; registration and ownership may be absent; graph-generated times are unsuitable for first-observed claims | Publish field provenance and missing states before using the fields |
| Similarity cluster ID means similar devices | Inventory synthesizes this ID from a pending pair candidate; multiple pairs overwrite a node's scalar field | Use explicit pair records for review; confirmed identity membership is a separate relationship |
| Embedding preparation supports events only | Octopus preparation already includes device, behaviour and sequence source kinds | Verify deployed coverage rather than rebuild existing preparation |
| All prepared kinds should be offered in Search | Go explicitly retires behaviour and sequence search, while the UI still offers them | Align UI choices to supported API kinds; do not restore retired features in this work |
| `api.search()` can compare a selected device vector | Search embeds query text; it has no seed-device comparison contract | Treat device-to-device retrieval as a separately designed capability |
| RF edges need to be enabled by default | Existing defaults already show all nine listed edge kinds | Start with observed AP context; put inferred relationships behind an optional layer |
| Every row needs an activity sparkline | A first/last timestamp cannot reconstruct activity density | Defer until a bounded, coverage-aware activity source is proved useful |

Evidence: [graph query and mapping](../apps/integration-console/atheros-search/internal/search/graph.go),
[identity and graph projector](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IdentityGraphSql.scala),
[inventory pair construction](../apps/integration-console/atheros-search/internal/search/inventory.go),
[search preparation](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/SearchPreparationSql.scala),
[search kind handling](../apps/integration-console/atheros-search/internal/search/service.go),
[UI kind choices](../apps/integration-console/atheros-search-ui/src/components/KindSelector.tsx)
and [graph defaults](../apps/integration-console/atheros-search-ui/src/stores/graphStore.ts).

## Accuracy findings that precede redesign

These are source-confirmed findings, not claims about an observed production
incident. All have high confidence. Effort is relative: S = localized, M =
several modules, L = a cross-service contract or integration change.

| Priority | Finding and impact | Evidence at reviewed commit | Effort / change risk |
|---|---|---|---|
| P1 | Search limits global candidates before applying site/time/MAC filters; matching evidence outside that candidate window can produce misleading empty results | [dense.go](../apps/integration-console/atheros-search/internal/search/dense.go) lines 83, 120-138; [sparse.go](../apps/integration-console/atheros-search/internal/search/sparse.go) lines 80-88, 117-136 | M / medium; verify recall and latency |
| P1 | A missing or excluded MAC anchor drops the focus restriction and can return the wider graph | [graph.go](../apps/integration-console/atheros-search/internal/search/graph.go) lines 261-264, 395-396; legacy focus path also returns the unfiltered input | S / low; preserve empty focus explicitly |
| P1 | Independent review queue entries resolve their detail through the graph store, so an unloaded pair can have missing evidence | [InventoryPage.tsx](../apps/integration-console/atheros-search-ui/src/pages/InventoryPage.tsx) lines 93-96; [MergeCandidatePanel.tsx](../apps/integration-console/atheros-search-ui/src/components/inventory/MergeCandidatePanel.tsx) lines 48-65 | M / medium; separate pair detail from map loading |
| P1 | Decision errors go to an error state displayed only outside queue mode, obscuring failed final decisions | [useInventory.ts](../apps/integration-console/atheros-search-ui/src/hooks/useInventory.ts) line 173; [InventoryPage.tsx](../apps/integration-console/atheros-search-ui/src/pages/InventoryPage.tsx) lines 201-235 | S / low; keep failed pair visible and report failure |
| P1 | Pending inventory pair links use `same_device`, despite not being confirmed identity | [inventory.go](../apps/integration-console/atheros-search/internal/search/inventory.go) lines 598-621 | M / medium; preserve compatibility while fixing labels and pair data |
| P2 | Graph first-seen and last-seen both copy the single observed timestamp | [graph.go](../apps/integration-console/atheros-search/internal/search/graph.go) lines 683-687 | S / low; use real values or omit unsupported values |
| P2 | Report transitions drop location/sensor/time scope or result settings | [GraphNodePanel.tsx](../apps/integration-console/atheros-search-ui/src/components/graph/GraphNodePanel.tsx) lines 73-84; [ExplainPage.tsx](../apps/integration-console/atheros-search-ui/src/pages/ExplainPage.tsx) lines 61-64 | M / medium; test URL round trips |
| P2 | UI offers retired search kinds | [KindSelector.tsx](../apps/integration-console/atheros-search-ui/src/components/KindSelector.tsx) lines 12-19; [service.go](../apps/integration-console/atheros-search/internal/search/service.go) lines 342-345 | S / low |
| P2 | Ranking values are rendered as percentages and raw factors as additive segments; hybrid rank fusion is not that decomposition | [ScoreBar.tsx](../apps/integration-console/atheros-search-ui/src/components/ScoreBar.tsx) lines 16-28; [fusion.go](../apps/integration-console/atheros-search/internal/search/fusion.go) lines 15-24 | S / low; distinguish rank, similarity and risk |

## Simple interaction model

### Inventory

Default to a native HTML table with six visible columns: identifier/name,
registration, owner, location, last observed, and review state. Put tags,
aliases, confidence details and history inside the selected-row detail panel.
Use explicit `Unknown` or `Unassigned` states; do not fill missing values with
plausible labels. Label the initial count **Observed identifiers**. Only report
physical assets after a trusted identity contract supplies that grain.

Keep one search box, an optional owner/location filter, and one view selector:
All identifiers / Registered / Needs identity review. These are planned server
queries, not filters over the loaded page. The registration boolean exists in
storage but is not a current inventory filter/response field. Add it explicitly
before exposing this preset. Put tags and less common criteria under Advanced.
Always show applied filters and Reset. Do not introduce threshold sliders in
the main report.

Use server filtering and sorting before page limits, with a unique tie-breaker
and cursor bound to filters/sort. The table should request one page at a time;
the existing `scope: all` browser loading loop is for graph coverage and is not
a prerequisite for rendering the table. Start with ordinary pagination rather
than virtualization. Add virtualization only after measurement identifies a
need that bounded pages do not solve.

Keep the existing inventory graph as a secondary relationship view. Preserve
legacy API shapes; introduce additive row metadata and independent detail
loading where needed. A selected row, map node or review pair must remain
resolvable without loading every graph node.

### Network map

The entry view is a scoped AP overview with names, BSSIDs, distinct observed
identifier counts, last observation and evidence status. Selecting an AP opens
a bounded neighborhood and a paginated roster. Count distinct MACs in this
initial contract, exclude AP self-observations, and state how broadcast,
unknown-role and multi-AP identifiers are handled.

Use **Observed AP context** as the default relationship layer. Show identity
and RF hints only on request, with their evidence basis. Preserve the meaning
of multiple AP observations: a layout grouping is a presentation convenience,
not exclusive membership. Force-layout distance must never imply physical
distance. Avoid geographic positioning until validated coordinates exist.

Replace "Solo devices" with **No AP context observed**. This filter means no
qualifying observation in the selected retained interval and sensor/site
scope. It must query the evidence source or a projection that can prove this
meaning, independently of visible edge kinds and page contents. Today's graph
edges store a latest timestamp and cumulative evidence, so they cannot prove
arbitrary historical interval absence. A graph-only implementation must instead
say **No AP link in this projection** and disclose its narrower meaning.

Map controls: site/sensor scope, time, entity search, optional relationship
layer, and Clear focus. Keep technical node/edge-kind and hop controls in
Advanced. Show a readable roster/list alternative with the same evidence and
actions. A failed focus lookup stays an empty focused result with its reason.

### Search, Explain and review

Search defaults to ordinary evidence retrieval. Supported types are wireless
event, device, proxy event, blocked-host window and Cross. Explain displays
raw ranking factors with their method and units; a relevance rank or cosine
similarity is never a probability of identity or risk.

Preserve applicable site, sensor, time and entity filters when moving between
reports. If a destination cannot represent a filter, explicitly show that
scope change. Preserve the complete same-origin return URL for Explain using
the existing return-path validation pattern; never accept an arbitrary external
return target.

Review shows the pair, evidence age, model/method, conflicts, and decision
provenance. A score is one piece of evidence. The current decision is final,
including `needs_more_data`; do not describe it as a reversible queue pause.
Distinguish **Decision recorded** from **Identity projection updated**. Never
announce that records have been consolidated just because a decision was saved.

## Shared report contract

Every report must disclose its scope, entity grain, count meaning, observation
range and data freshness. Keep `generated_at` as response generation time;
it does not mean ingestion or projection freshness. Proposed additive metadata
should distinguish source watermark, projection watermark, loaded versus total
rows, incomplete coverage and unavailable capabilities.

Counts and rows must use the same predicates. A global registered count is not
the filtered result count. Cursor pages over a changing projection do not form
a frozen snapshot by default. Start by disclosing live results and providing
Refresh; require an explicit snapshot contract before claiming reproducible
historical reports or adding full-result exports.

Empty, unavailable, loading, partial and stale are separate states. Never infer
absence of activity from a failed query or an offline sensor. Authorization
remains enforced by the backend; final review actions retain existing roles.
Keep identifiers out of analytics/log labels and follow the
[privacy policy](atheros-search-privacy.md), including any future exports.

Use existing design tokens, restrained motion and keyboard-operable controls.
Native tables and sortable header semantics follow
[W3C's table guidance](https://www.w3.org/WAI/ARIA/apg/patterns/table/).
Provide a text/list equivalent for map evidence in accordance with
[W3C's non-text content guidance](https://www.w3.org/WAI/WCAG22/Understanding/non-text-content.html).

## Delivery order and expected benefit

| Stage | Deliverable | Business benefit | Gate |
|---|---|---|---|
| 1 | [Report accuracy](../plans/001-report-accuracy.md): scoped query correctness, focus behavior, complete pair detail/errors, supported kinds, truthful labels and navigation | Operators can trust which evidence they are seeing and whether an action succeeded | Adversarial scope/filter/pair tests pass |
| 2 | [Inventory report](../plans/002-inventory-report.md): bounded table, row grain, useful presets and detail | Faster identifier lookup and review; less visual scanning | Complete filtered results across pages; accessible row actions |
| 3 | [Focused map](../plans/003-focused-network-map.md): AP overview, paginated roster, evidence layers and honest absence state | Understand one relevant neighborhood without reconstructing a large graph | Same scoped counts/evidence in map, roster and Search |
| Later | Selected-device activity or similarity investigation | Add only if it resolves a measured operator question | Source coverage, query budget, meaningful evidence and supported API proved |

Timeline alerts such as "gone dark" need expected activity and sensor coverage;
they are not derived from two timestamps. Semantic similarity needs a defined
seed-vector API, model compatibility, exclusions and evidence labeling. Neither
feature gates the first three stages. Do not add an `embedding_similar` edge
until a real investigation requires it and its lifecycle is specified.

## Acceptance and measurement

Before implementation, capture a small baseline on representative data. Measure
task completion and errors, rather than counting new controls or charts.

- An operator finds a known identifier and opens its evidence without Advanced.
- An operator selects an AP and inspects one roster member in three actions or
  fewer; map and roster share the same scope and count definition.
- An operator sees an unknown/no-context result without interpreting it as a
  threat or proof that the identifier never connected.
- An operator reviews a pair whose endpoints are absent from the map cache,
  sees a failed decision, and can retry without losing evidence.
- Search returns an in-scope match placed beyond the former global candidate
  limit; missing focus and unsupported kind tests have explicit outcomes.
- Browser Back, reload and report links preserve the applicable investigation.
- Keyboard and assistive-technology users can reach the same evidence/actions.
  Verify 375, 768, 1024 and 1440 pixel layouts and reduced motion.

Use candidate starting budgets of 50 rows per table page and 200 visible nodes
per focused map, with explicit pagination/expansion. These are design budgets,
not performance claims. Capture response p50/p95, payload size and interaction
latency on the same representative dataset/hardware before setting release
targets. Reject unbounded AP loads and per-row activity requests.

## Review scope and validation limits

Reviewed source includes the console routes, controls, state and graph hooks;
Go search/graph/inventory/decision contracts; canonical reporting DDL; and
Octopus ingestion, preparation and identity/graph projections. Runtime
population, retention execution, production grants, sensor coverage, latency
and operator task outcomes require separate read-only deployment evidence.
This is not a whole-repository security audit or an enterprise certification.

Documentation validation: `python3 scripts/check-docs.py`. Implementation checks
and new regression cases are specified in each plan. Preserve unrelated local
changes and keep schema additions append-only through the canonical manifests.
