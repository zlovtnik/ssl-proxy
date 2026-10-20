# Proxy RAG evidence and preparation

> **Status: Application changes verified; production activation and recovery remain gated.**
> Verification date: 2026-10-20 UTC. Implements the stage 3 and stage 4 code in
> the [workmap](../advisor-plans/002-proxy-rag-ml-workmap.md).

## Evidence and compatibility

The proxy adds bounded endpoint provenance, attribution method and claim
validity, measurement availability, coalescing evidence and ClientHello parser
status. Routing ports remain separate from observed explicit ports. Legacy
host strings do not establish an explicitly observed port. The existing
[authority contract](proxy-authority-v1.md) supplies normalization and PSL rules.
Hostname sanitization also covers new fields and nested arrays.

CONNECT, QUIC and TCP bypass/transparent forwarding count successful writes,
retaining partial totals on failure. QUIC terminal status requires both transfer
directions and H3 finish to succeed. Transparent plaintext HTTP socket counters
remain observations with unavailable byte status/source: uploads can include
rejected pipelined requests. An open or header-only observation does not establish
a measured zero. HTTP failure durations remain unavailable rather than response
header latency. ClientHello versions and ALPN remain offers. Coalescing is
scoped to a process/event/host/peer/device/reason key, with a 500 ms window and
4096-key capacity. Capacity bypass and potentially unreported final windows are
explicit; these counters do not establish physical attempts or validated flows.
Peer references rotate on process restart or key change and expire with the
process; registration claims retain their observed validity intervals.

The [frozen synthetic envelopes](../sql/postgres/contracts/fixtures/proxy-events-v1.json)
cover seven allowlisted event types, an open/terminal pair, sanitization and
duplicate delivery. Eight distinct observations remain eight source identities.
These are fixture counts, not production measurements.

The append-only [core migration](../sql/postgres/octopus_core/01_tables/021_proxy_evidence.sql)
adds observation arrival revisions and preparation queues/progress. The
[Search migration](../sql/postgres/atheros_search/01_tables/020_proxy_preparation.sql)
adds safe published evidence, current source pointers, preparation generations,
input revisions, repair receipts/progress, queue policy and scoped similarity
state. Earlier migration bytes are unchanged. Prior manifest baselines permit
executor upgrades. Grants keep source rows and registration data private;
Search reads the published whitelist and cannot update document content.

### Populated-table maintenance gate

Adding `observation_revision` as an identity column rewrites `proxy_events` and
its indexes under an exclusive lock ([PostgreSQL ALTER TABLE](https://www.postgresql.org/docs/current/sql-altertable.html)).
The migration deliberately retains this maintenance-window approach. Production
row counts, rewrite time, WAL volume and temporary disk needs remain unmeasured;
release is blocked until a representative rehearsal establishes the budget.

Before promotion, record the measured retained row count/table and index sizes,
available disk/WAL headroom, rehearsal duration, an approved downtime interval,
and rollback criteria. Drain traffic through reviewed GitOps changes. Supply
the provisioning executor's `PGOPTIONS` through the same reviewed Git change:
`-c sslproxy.proxy_evidence_max_rows=<reviewed-row-ceiling>` and
`-c sslproxy.proxy_evidence_window_end=<UTC-timestamp-without-spaces>`, together
with `-c statement_timeout=<reviewed-duration>`. No values are enabled by default.

Populated upgrades fail closed without these settings. The timeout must exceed
one second and fit entirely before the window ends. Lock acquisition is capped
at one second. After acquiring the exclusive lock, the migration counts at most
the approved ceiling plus one row and rejects growth beyond that ceiling. The
rewrite, evidence constraint and unique index build share one timed statement
and the executor's migration transaction. Timeout/failure rolls back schema and
ledger changes; retry requires a fresh window and reviewed budget. Empty fresh
installs and already-applied replays need no maintenance approval. This gate
does not establish production performance or authorize a rollout.

Existing event document identities are retained. Blocked-window source keys
retain the legacy raw-host/device/hour formula under UTC preparation. Host
normalization is separate from that compatibility identity. The existing
`host` field preserves substring matches including ports; exact normalized
values live in structured evidence. Legacy counter aliases remain structured
with explicit availability/meaning labels. Neither transfer totals nor actual
attempts are inferred from them. New flow/window/signal kinds remain stage 6
work and are not admitted prematurely.

Reserved new-kind source-key namespaces are `proxy-flow:v1:`,
`proxy-host-window:v1:`, `proxy-device-window:v1:` and `proxy-signal:v1:`.
Each suffix is SHA-256 of an ordered JSON tuple containing the scope, kind,
normalization/policy version and validated flow or half-open window identity.
Window tuples distinguish absent from explicit ports; device tuples require
validated attribution and mapping revision. These prefixes cannot collide with
event UUID keys or legacy `proxy-window:<md5>` keys. Stage 6 must add the kinds,
source checks and partial indexes together before using these namespaces.

## Ownership and bounds

`proxy-search-preparer` is an opt-in Octopus processor with no wireless
dependency. It publishes evidence, prepares documents and jobs, reconciles
missing coverage and advances durable progress in the same fenced transaction.
The shared text builder handles wireless kinds. Proxy preparation checks the
persisted owner, token, fence and wall-clock expiry before work and before
commit. Source revisions and preparation generations prevent older work from
reactivating superseded content or replacing newer same-text evidence.

Document writers and Go completion share a source advisory lock. This avoids
granting Search document-update privileges solely to acquire PostgreSQL row
locks. Completion rechecks actual text SHA-256, stored checksum, source kind,
model/input revision and the live job lease. Unified and per-kind vector writes
and job completion remain atomic; model calls remain outside transactions.

Each preparation tick caps work items at 500. It combines historical arrival
keysets with dirty-source reconciliation, examines at most one closed UTC hour
with a 501-row overflow probe, and bounds reconciliation pages. Incomplete or
oversized windows retain a named disposition. Seven-day published-evidence
cleanup is also paged. Statement and transaction budgets are five seconds, with
a one-second lock timeout. Physical scanned rows and production throughput
still require the stage 1 measurements; LIMIT is not presented as proof of
physical scan cost.

Preparation and scoped repair serialize queue growth under a shared advisory
lock. Repair requires a fresh Octopus-published high-water policy and cannot
advance a page beyond its available headroom. Workers apply their configured
source-kind/model/input scope before claims and expired-lease recovery.
Enabling Octopus consumers still unions wireless consumers; selecting this
processor alone does not change intake configuration.

The scoped repair commands require exact kinds/model/input revision, a frozen
job-creation cutoff and a 1..1000 page limit. Mutation additionally requires
`-apply` and a campaign ID; progress rejects changed scope or cursor parameters.
Receipts preserve attempts and errors. Completed jobs missing consistent
vectors can retry within their existing attempt budget. Failed, exhausted,
cancelled, superseded and orphaned work is not globally reset or revived.
See the Search checkout's operational instructions in its `scripts` directory.

## Embedding input and release gates

The model remains `nomic-embed-text-v2-moe`, with 768 dimensions. Input identity
is `legacy_unknown` or `nomic-prefix-v1:<artifact-sha256>` and participates in
job/vector uniqueness, dense eligibility and cache namespaces. Different input
revisions coexist without overwriting wireless vectors. Queries select one
compatible input revision. Wrong-sized, nonfinite and zero-norm backend or
pooled vectors are rejected before use or persistence.

Client prefix code supplies exactly one query/document prefix on every chunk,
retokenizes effective inputs, and reserves two special tokens within 512 tokens.
That reserve is a profile contract requiring backend verification. Prefixes
remain off in the legacy profile. The current backend request cannot convey
query/document roles for server-owned prefixes, so that configuration fails
closed. Synthetic wire tests do not attest the deployed serving wrapper.

V01 remains open: production artifact/tokenizer/pooling/chunking and server
prefix behavior have not been measured. V02 activation depends on that evidence.
M07/D07 production capacity, reserve, physical plans and pause thresholds remain
open. Historical preparation timezone must be attested before recovering legacy
window keys. These gaps block activation and stage 5 recovery.

The workload checksum references and production/staging executor content hashes
are updated as desired-state files. This session did not promote images, apply
production DDL, activate the broker-drain profile, probe production models,
or mutate managed Kubernetes resources. Publish compatible pinned executor,
Octopus and Search images together under the release workmap before rollout;
the currently pinned images are not evidence of compatibility with this code.

The image-promotion review finding remains unresolved as of 2026-10-20: the
configured registry at `192.168.1.242:5000` is offline (confirmed by the operator),
and the production schema digest is absent from the local image cache. No
replacement digest was invented or promoted. Local Octopus publication preflight
also rejects the checkout because its revision differs from the parent gitlink.
Reconcile the compatible source pins, publish/verify all three candidate images,
and promote executor plus Octopus/Search digests with their checksum references
before merging deployment desired state. These manifests are not release-ready.

Old binaries using the former job/vector conflict keys are incompatible with
the extended unique keys. Do not deploy these manifests with those binaries.
Rollback uses compatible binaries with preparation/workers disabled or a
compatible input profile; retain the additive schema and evidence.

## Verification record

Measurement review follow-up on 2026-10-20 passed all 219 Rust library tests,
including clean/partial measurement status, plaintext pipelining source semantics
and HTTP failure-duration labels. Registry image verification/promotion remains
blocked as recorded above; cluster resources were not mutated.

Review follow-up on 2026-10-20 rejected userinfo in endpoint evidence, routed
CONNECT/QUIC blocked events through that helper, corrected the remaining legacy
job conflict target in `CanonicalIngestionSql`, and added the maintenance gate
above. Other Octopus and Go job/vector/similarity conflict targets already match
the extended keys and needed no changes. Manifest checksums and consumer/Job
references were refreshed together.

Follow-up checks passed: 216 Rust tests; 44 focused Scala tests, including 35
canonical persistence tests without skips; 34 Go database tests without skips;
13 audit/migration tests; six executor unit tests; 20 production manifest tests;
executor fresh/upgrade/replay/drift/ownership integration; schema, documentation,
formatting, dependency-boundary and GitOps checks.

An additional direct probe of the currently unreferenced
`CanonicalIngestionSql.applyRecord` path stops before job insertion because its
existing document INSERT omits required `source_key` (and `source_table`). That
separate issue remains outside this review fix; the passing runtime suites do
not establish end-to-end compatibility of that unused ingestion path.

| Check | Result |
| --- | --- |
| `cargo test -p ssl-proxy --lib` | 214 passed; socket tests used ephemeral loopback access |
| `cargo test -p sync-plane`; `make dependency-boundaries` | Passed |
| Octopus `OCTOPUS_REQUIRE_DOCKER=true sbt test` | 525 passed; only the explicitly opt-in live hydration probe skipped |
| Required Octopus persistence and timeout suites | 35 + 3 tests passed without skips in the full run |
| schema-migrator `sbt test` | 218 passed |
| Search `GOTOOLCHAIN=go1.26.1 make quality-go` | Passed: race suite, both lint configurations, boundaries, proto comparison and Go compatibility fixtures |
| Search `make stack-contract ATHSEARCH_STACK_ROOT=/Users/rcs/git/ssl-proxy` | Passed: shared processor/schema contracts |
| Search `make fixtures ui-check` | Passed: 7 contract checks, 165 UI tests and production UI build |
| `scripts/tests/test_atheros_reporting.py --required -v` | Passed; canonical manifests, actual grants and eight Go database consumers executed without skips |
| `scripts/tests/proxy_rag_integration.py -v` | 8 bounded audit tests passed on ephemeral canonical PostgreSQL |
| Schema contract checker and executor unit/integration checks | Passed: fresh/upgrade/replay/drift/ownership/grants |
| Documentation and production manifest checks | Passed; production manifest suite: 20 tests |
| `make gitops-check` | Passed: canonical Kustomize/Argo CD renders and schema content hashes |

Tests populated build caches and temporary artifacts; the UI build regenerated
ignored `dist/` output. No generated source,
runtime credentials or secret values were manually edited. Concurrent authority
privacy and measurement fixes were preserved and included in verification.
There are no new production before/after coverage or capacity results; the
[measurement record](../ops/sql/proxy-rag-measurements.md) retains those limits.

Implementation started from parent `d991df15`, Octopus `315954d4` and Integration
Console `349f492f`. Concurrent commits advanced the parent and Octopus during
implementation; final compatible commits/gitlinks must include their remaining
working-tree changes before promotion. No commit or push was performed by this
implementation session.
