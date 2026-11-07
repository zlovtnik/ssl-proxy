# Proxy flow lifecycle v1

This contract defines how Octopus can validate a retained tunnel pair. A
validated pair contributes one flow. Individual observations remain available
under their existing source identities, including observations with no pair.

## Identity and scope

- The source is the canonical `proxy.events` stream from an attested,
  single-deployment dataset. The [scan envelope](../crates/sync-plane/src/contract.rs)
  carries no deployment ID. The caller supplies a trusted deployment scope
  from the source boundary. Mixed or unknown provenance is ineligible.
- An observation uses the canonical UUIDv4 `event_id` from the retained
  envelope. The [transform](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresTransformService.scala)
  can synthesize a legacy row ID, so a database row ID alone cannot prove
  producer identity. The flow key is the tuple of deployment scope and
  canonical UUIDv4 `correlation_id`. Keep the tuple unambiguous if it is
  encoded into a document key.
- The [tunnel emitter](../src/tunnel/audit_event.rs) creates the correlation
  UUID once per context. Its supported sequence is an unblocked
  `tunnel_open` with sequence 1 followed by an unblocked `tunnel_close`
  with sequence 2. The retained host must agree on both sides. Host
  agreement is a consistency check. It establishes neither device ownership
  nor a valid normalized endpoint. Independent HTTP observations stay
  outside this lifecycle. The frozen source fixture predates the presence
  of some additive fields, including `kind`.
- Re-delivery of the same event ID and same evidence counts once. If
  different versions of the same event ID are visible in a source snapshot,
  every affected correlation is ambiguous until the authoritative version
  is established. The [canonical sink](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/BatchSinkSql.scala)
  keeps the first payload for a repeated ID and records differing payloads in
  the separate `proxy_events.source_conflicts` column. This unresolved marker
  maps each payload's SHA-256 over PostgreSQL JSONB text to its correlation ID,
  including the original payload. Exact replays do not add a conflict. Read
  these markers as trusted ingestion metadata, separately from payload fields
  and normalized evidence. Before filtering by correlation or event time,
  include every correlation referenced by an unresolved marker in the
  attested deployment scope. Each remains ambiguous, even if its conflicting
  payload was discarded or its canonical row belongs to another correlation
  or time window. Replaying a payload or preparing evidence cannot clear the
  marker; an authoritative reconciliation must establish the accepted version
  before validation resumes. Conflicts discarded before this marker was
  deployed remain unknown; a canonical-only snapshot cannot attest their absence.
  Two distinct IDs for the same side are ambiguous even if their values agree.

## Bounded evaluation

Require a positive, versioned maximum elapsed pairing horizon. This is a
projection policy. The producer can emit longer-lived tunnels. No deployment
default is set here. For an open at time T, a compatible terminal can occur
in the closed interval from T through T + horizon. For a terminal at T, look
back through T - horizon inclusively. Equal timestamps are allowed when the
sequences are correct. The event time determines ordering independently of
ingest order and of the producer's monotonic duration measurement.

Evaluate against a consistent source snapshot. The caller must attest the
retained lower bound, the observed upper bound, any collection gaps, and the
completeness of the bounded lookup. Coverage bounds are half-open UTC
intervals. For a candidate pair, cover both sides' counterpart intervals,
from terminal time minus the horizon through open time plus the horizon.
Write that required closed interval as `[L, U]`. A half-open attested coverage
interval `[A, B)` contains it exactly when `A <= L` and `U < B`. A lookup must
include events at both `L` and `U` (for example, `time >= L AND time <= U`);
coverage ending at `B = U` is coverage limited even when a terminal at `U`
is present and satisfies the pairing horizon. Require an attested `B > U`
to establish completeness. Compare the same UTC instants at the source's
preserved precision; do not round the endpoint or invent a millisecond,
microsecond or nanosecond increment. This inclusive lookup and strict coverage
comparison require no endpoint adjustment or assumed timestamp resolution.
If storage has rounded a timestamp, retrieve a conservative candidate superset
and evaluate these bounds against retained source times; the rounded value
cannot prove an event lies inside or outside the inclusive endpoint.
Use a row limit with an overflow check before
making any positive claim. Source bounds derived only from the oldest and
newest row cannot establish coverage.

| Evidence in scope | Disposition |
| --- | --- |
| Missing source identity, invalid UUID/sequence/flags, or malformed required fields | Ineligible source evidence. An invalid tunnel row with a usable correlation prevents validation of that correlation. |
| Distinct opens or terminals, or multiple versions of one ID | Ambiguous. Keep the conflicting source references. |
| One open and terminal with a host mismatch or reversed event time | Inconsistent pair. |
| One open and terminal more than the pairing horizon apart | Outside policy horizon. |
| Candidate lookup overflows or the relevant interval is outside retained/observed coverage | Lookup incomplete or coverage limited. Include retention truncation when attested, and otherwise retain unknown coverage. |
| Exactly one side after an exhaustive lookup with full coverage | Missing open or missing terminal within policy horizon. |
| Exactly one supported pair with exhaustive lookup and covered interval | Validated. Count once under the flow key. |

Known conflicts may be reported even when coverage is incomplete. Do not
promote any incomplete or ambiguous candidate to a validated flow. Retain
the disposition and available source IDs. Recompute from current source
evidence after a late arrival, correction or deletion, including transitions
from validated to ambiguous or incomplete. A window boundary is never a
pairing boundary. Downstream counting must identify the flow by its scoped
key, including when both sides appear on different scan pages.

## Measurement handoff

Pair validation establishes a lifecycle only. Preserve terminal byte
availability, direction, source and termination separately. Confirmed byte
totals require supported measurement provenance and both nonnegative
successful-write counts. Partial counters remain partial. The frozen
lifecycle fixture declares a terminal status but lacks source, unit and
direction provenance. It tests pairing, with confirmed transfer unavailable.
Keep producer-reported connection elapsed duration separate from the wall
time between observations. The plaintext transparent socket lifecycle can
span requests and destinations. Its initial host does not establish
destination-level transfer.

The local Octopus `ProxyFlowContractSuite` checks the frozen producer pair
and boundary cases. The existing
[completeness audit](../ops/sql/proxy-tunnel-completeness.sql) measures
candidate correlations. Stage 6 runtime work depends on
[Stage 5 coverage acceptance](../advisor-plans/002-proxy-rag-ml-workmap.md#stage-5-recover-retained-eligible-data).

## Runtime preparation

B02-B04 are implemented by the existing Octopus proxy search preparer.
The additive [Search schema](../sql/postgres/atheros_search/01_tables/022_proxy_behavior.sql)
provides the singleton `proxy_behavior_policy` configuration. Provisioning
installs no row. Its reviewed configuration supplies deployment scope,
coverage bounds, coverage/conflict attestations, expiry, pairing horizon,
window size, lookback and source/output limits. Octopus has SELECT permission
on this configuration. An expired or absent policy stops publication and
retires bounded pages of previous projections.

The preparer reads a bounded event-time context and a bounded global conflict
page in one statement snapshot. The current processor lease and shared proxy
queue lock protect projection revisions, document supersession, embedding
jobs and the durable output cursor in the same transaction. Input or output
overflow records unavailable status and starts bounded retirement.
`proxy_behavior_status` exposes readiness and incomplete recomputation.

`atheros_search.proxy_flow` retains deterministic dispositions and source
references. Its Search documents use source kind `proxy_flow`, disjoint
source table/key identities and the existing `event` embedding kind.
Partial byte values stay separate from confirmed values. Unavailable totals
are null. Exact counters, identifiers and duration values stay in structured
evidence. Semantic text contains the host, disposition and transfer status.
HTTP observations retain their existing independent document identity.

`atheros_search.proxy_host_window` groups normalized host and explicitly
observed port scope into half-open UTC windows. An unknown port has its own
endpoint identity. Counts describe observations, while each validated flow
belongs to its terminal event-time window. Measured totals identify when
they cover a subset of validated flows. Empty replacement windows clear
previous counters after corrections. `proxy_host_current` advances by
window start, so a historical correction cannot replace a newer pointer.
Queries must check behavioral status before treating a recomputing projection
set as complete.

Projection fingerprints exclude calculation time. Replays retain revisions
and document identities. Evidence corrections receive a monotonic projection
revision, policy/calculation versions and source watermark. A durable output
cursor rotates flow and window work across small batches. Removed source
groups retire obsolete documents, jobs, windows and pointers.

The additive [legacy rollup migration](../sql/postgres/octopus_core/01_tables/023_proxy_rollup_event_order.sql)
adds the event-ID tie-break for latest fields. Latest metadata comes from the
maximum `(event_time,event_id)` observation, including null fields.
Cumulative counters retain their existing meanings. Existing rollups have an
empty tie-break until a newly ingested observation establishes the winner.

Production schema rollout, policy admission and Stage 5 acceptance remain
deployment gates. The legacy database inspection cannot supply absent
measurement provenance or attest source coverage.

### Populated upgrade budgets

Migration 022 installs `search_documents_kind_ck` as `NOT VALID`, enforcing new
writes without scanning retained documents under its exclusive lock. The
separate [validation migration](../sql/postgres/atheros_search/01_tables/024_proxy_document_kind_validation.sql)
runs in its own provisioning transaction. For populated Search tables, the
executor requires measured `sslproxy.proxy_kind_validation_max_rows` and an
approved `sslproxy.proxy_kind_validation_window_end` supplied through `PGOPTIONS`.
Validation uses `SHARE UPDATE EXCLUSIVE`, allowing ordinary writes, with a
one-second lock timeout and a finite `statement_timeout` greater than one second
that fits inside the approved window. It fails closed if the row budget is
exceeded or approval is missing or expired. Empty installs need no approval.

The [conflict index migration](../sql/postgres/octopus_core/01_tables/023_proxy_rollup_event_order.sql)
is transactional and therefore uses a standard index build. Before a populated
build, drain writes through reviewed GitOps changes, measure the retained row
count and build duration, and supply `sslproxy.proxy_conflicts_max_rows`,
`sslproxy.proxy_conflicts_window_end` and `sslproxy.proxy_conflicts_writes_drained=on`
through executor `PGOPTIONS`. The same finite timeout/window and one-second lock
budget apply. A table `SHARE` lock rejects an active writer before the scan and
keeps the row ceiling stable during the build. Existing indexes return before
acquiring that lock. Only the provisioning schema executor applies either DDL
step; runtimes do not create indexes or validate constraints. These controls do
not establish production row counts, duration, or permission to roll out.
