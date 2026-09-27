# Atheros reporting implementation plans

> **Status: Local implementation in progress; release validation pending.** Source review: commit `1316324e`,
> 2026-09-27. These plans implement the
> [business reporting workmap](../docs/atheros-reporting-workmap.md) and
> [data contract](../docs/atheros-reporting-data-contract.md).

Automated implementation evidence and synthetic measurements are recorded in
[the implementation note](../docs/atheros-reporting-implementation.md).

## Execution order

| Plan | Outcome | Priority | Effort | Dependency | Status |
|---|---|---|---|---|---|
| [001](001-report-accuracy.md) | Trustworthy scope, evidence and action results across reports | P1 | L, delivered in small changes | None | IN PROGRESS |
| [002](002-inventory-report.md) | Paginated table-first inventory with meaningful row grain | P1 | M | 001 relevant query/detail fixes | IN PROGRESS |
| [003](003-focused-network-map.md) | Bounded AP map and roster with honest observation semantics | P2 | L | 001 scope fixes; 002 row/detail contract | IN PROGRESS |

Status values: TODO, IN PROGRESS, DONE, BLOCKED (with reason), REJECTED (with
reason). Update only the plan being executed. Each executor reads the whole
plan, checks source drift and runs its verification gates.

Plan 001 should be split into reviewable changes: query scope, review detail and
errors, then navigation/kinds/labels. Inventory presentation can be designed in
parallel, but do not release it with incorrect counts or incomplete detail.
Map absence semantics require source coverage independently of table delivery.

Use `codex/` branches if creating a branch. Preserve unrelated local changes.
No plan authorizes production mutation, automatic promotion or new runtime
database ownership. No source implementation was made by this documentation
review.

## Considered and rejected approaches

- Querying stored edges as `association`: the stored kind is `observed_at`.
- Calling missing links "never connected": coverage and relationship evidence
  cannot establish that claim.
- Marking unlinked identifiers as threats: no threat evidence supports it.
- Adding an AP-count threshold slider: sorted counts answer the current task.
- Using pending-pair clusters as physical identities: candidates are review
  evidence, and an identifier can participate in multiple pairs.
- Rebuilding event-only preparation: device/behaviour/sequence preparation
  already exists; deployed readiness remains to be verified.
- Restoring retired public search kinds: outside the agreed report scope.
- Loading every identifier or an unlimited AP roster before rendering: bounded
  server pages are simpler and operationally safer.
- Per-row timelines and speculative "gone dark" alerts: no coverage-aware
  activity contract or baseline has been established.
- Replacing the graph stack or adding a generic report/filter framework: the
  existing components are sufficient for the first release.

## Verification scope

Documentation must pass `python3 scripts/check-docs.py` from the repository
root. Future application verification is specified in each plan. Passing
existing tests does not prove the new regression cases or production capacity.
