# Proxy RAG evidence and preparation

> **Status: Application changes verified; production activation and recovery remain gated.**
> Latest verification: 2026-10-25 UTC. Implements the stage 3 and stage 4 code in
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

### SRC15-SRC21 follow-up: 2026-10-25

This batch covers the remaining seven source references. It preserves the
earlier SRC01-SRC14 changes and reuses the existing schema, lease and repair
contracts without new dependencies or deployment changes.

- SRC15: canonical retrieval tests cover both proxy kinds sharing event
  embeddings, current normalized-text checksums, input revisions and host
  substring filtering before the candidate limit. The existing dense path
  already enforces these conditions; no runtime rewrite was needed.
- SRC16: record context joins vectors by model, kind, input revision and content
  hash. Current coverage also requires completed work, active unchanged text
  and a nonzero vector. Proxy records cannot use a legacy MAC to anchor wireless
  activity. Their timeline remains explicitly unavailable. The explain panel
  preserves and displays input revision so coexisting work stays distinguishable.
  Legacy reset/retry operations now take one limited, locked page of active
  non-proxy jobs; they cannot bypass the scoped proxy campaign controls.
  Aggregate ETL gauges remain distinct from proxy source coverage.
- SRC17: the real provisioning-executor test checks coordinator write grants,
  Search read-only evidence access, denial of private sources/preparation state
  and matching ready schema proofs. Existing canonical grants needed no change.
- SRC18: audit metadata captures the actual safe worker batch, concurrency,
  source-kind and input-revision settings instead of an unused batch variable.
  Desired-file hashes include the base Search deployment. Pod specifications
  remain labelled as specifications; runtime enablement, capacity and backend
  behavior remain unattested. Credential environment values are excluded.
- SRC19: blank/whitespace correlation IDs count as missing observations rather
  than false tunnel pairs. Tests cover counterpart saturation, bounded horizon
  matching, same-time keyset pages and physical exclusion of retained history
  before aggregation. Synthetic query plans do not attest production plans.
- SRC20: the Go canonical runner pins the same pgvector image digest as the
  executor harness and uses production role search paths without public schema
  fallback. Required database tests execute actual manifests and runtime grants.
- SRC21: existing proxy lease/source-revision guards pass new regressions for
  stale replay after a legitimate text rollback and wrong owner/token/fence
  before expiry. Older work cannot reactivate an intermediate document or
  change current jobs. Generic wireless persistence remains outside this scope.

Affected runtime paths are [record context](../apps/integration-console/atheros-search/internal/search/record_context.go),
[legacy repair](../apps/integration-console/atheros-search/internal/app/repair/repair.go),
[explain UI](../apps/integration-console/atheros-search-ui/src/components/explain/EmbeddingWork.tsx),
[audit metadata](../ops/sql/proxy-rag-measure.py) and
[lifecycle measurement](../ops/sql/proxy-tunnel-completeness.sql).
Regression coverage uses the existing
[Go database runner](../scripts/tests/test_atheros_reporting.py),
[provisioner integration](../scripts/tests/test-postgres-schema-executor-integration.sh),
[audit integration](../scripts/tests/proxy_rag_integration.py) and
[Octopus canonical suite](../services/octopus/src/test/scala/com/sslproxy/coordinator/ingest/OctopusPersistenceIntegrationSuite.scala).

Verification completed for this batch:

- Octopus `OCTOPUS_REQUIRE_DOCKER=true sbt test`: 586 passed, one opt-in live
  probe skipped. Canonical Docker integration executed. Compilation retains
  `-Wunused:all -Werror`. The focused lease/revision run passed 19 tests.
- Search `PATH=/Users/rcs/go/bin:$PATH GOTOOLCHAIN=go1.26.1 make quality-go`:
  formatting, vet, race tests, both lint profiles, boundaries, protobuf and
  shared fixtures passed. The pinned lint binary is 2.13.2.
- Root `scripts/tests/test_atheros_reporting.py --required`: 35 top-level
  tests (43 including subtests), all eight consumers, zero skips/failures.
  The final run includes the exhausted/superseded repair assertion.
- Root `scripts/tests/test-postgres-schema-executor-integration.sh`: fresh
  provisioning, proxy grants/readiness, upgrade, replay, checksum drift and
  ownership checks passed. `scripts/tests/proxy_rag_integration.py`: 16 tests
  passed, zero skips. Measurement unit tests: nine passed; executor unit tests:
  six passed.
- Search `make ui-check`: 165 tests in 28 files and production build passed,
  including input-revision normalization/display. `make stack-contract` passed
  with `ATHSEARCH_STACK_ROOT=/Users/rcs/git/ssl-proxy`.
- Documentation checks and diff whitespace checks passed in the root and
  affected nested repositories. Independent scoped review found no remaining
  correctness defects.

Docker tests used `DOCKER_HOST=unix:///Users/rcs/.docker/run/docker.sock`.
The Go runner used the existing temporary test environment at
`/private/tmp/src08-src14-test-venv`, `GOTOOLCHAIN=go1.26.1`, and
`TESTCONTAINERS_HOST_OVERRIDE=172.20.10.9` for its isolated local database;
the repair CLI rejects loopback DSNs. No repository dependency was added.
Checkout HEADs remain parent `9692492026800615798bb9846341bb34d221eece`,
Octopus `9c47daffa33bf016b8a0f9fe23d5821a0c5cb65c` and Integration Console
`69db6850d8b4570987ecc3702c98db2501eb0e95`, each with the documented dirty
implementation changes. No commits were created.

Verification runs use isolated local databases. No production replay, DDL,
image promotion or configuration activation occurred. M07/D07 and V01/V02
remain open, as do the later campaign and timeline delivery gates.

### SRC08-SRC14 follow-up: 2026-10-25

This batch covers the next seven source references, preserving the earlier
SRC01-SRC07 work and all unrelated checkout changes.

- SRC08: golden tests freeze the exact proxy normalized-text checksum and
  document UUID. Metadata and preprocessing changes preserve text identity;
  endpoint normalization stays separate from compatibility prose hashing.
- SRC09: supervisor tests execute a proxy-only workload selection and observe
  no shared/wireless preparation. Consumer enablement still explicitly includes
  wireless ingestion IDs. Existing runtime paths needed no change.
- SRC10: bounded stale-signal resolution preserves history and clears signals
  whose qualifying retained observations expired or were corrected. Eligible
  observations can reopen them. Future event times do not qualify. Legacy
  score/severity behavior remains compatible for valid inputs, with additive
  uncalibrated/observation/scalar-byte provenance and confirmed_threat=false.
  Invalid negative counts and excess recency cannot inflate the calculation.
  Blocked-host rollups use event time for first/latest metadata, so late older
  observations add counters without replacing newer metadata.
- SRC11: similarity anchors and candidates require exact current-content and
  vector parity between unified/per-kind stores on both sides. Scope, model,
  normalization and input-revision checks and independent checkpoints remain.
- SRC12: canonical PostgreSQL tests admit the two implemented proxy kinds and
  four legacy kinds, retain separate preprocessing revisions in jobs and both
  vector stores, reject exact duplicates and reject unimplemented proxy_flow.
  Existing append-only schema contracts needed no DDL or manifest changes.
- SRC13: canonical worker tests retain scoped claims/recovery, checksum
  attachment, lease fencing and atomic completion. Existing code needed no change.
- SRC14: indexed backend responses are reordered by input index. Duplicate,
  out-of-range or mixed indexed/unindexed responses fail closed; legacy
  unindexed responses remain supported. Tokenizer readiness checks exact token
  identities after round-trip, including same-length corruption. The index
  association follows the [official embedding response contract](https://developers.openai.com/api/reference/resources/embeddings/methods/create).

Runtime changes are localized to
[signal reconciliation](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala),
[signal SQL](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ThreatRiskSql.scala),
[score evidence](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/IntelligencePreparation.scala),
[rollup binding](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresTransactor.scala),
[rollup SQL](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/BatchSinkSql.scala),
[similarity SQL](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IntelligenceSql.scala)
and the [embedding client](../apps/integration-console/atheros-search/internal/embed/client.go).
Acceptance coverage is in the
[canonical persistence suite](../services/octopus/src/test/scala/com/sslproxy/coordinator/ingest/OctopusPersistenceIntegrationSuite.scala),
[document suite](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/SearchDocumentPreparationSuite.scala),
[supervisor suite](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProcessorSupervisorSuite.scala),
[processor tests](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor)
(including the new `ProxyIntelligenceEvidenceSuite.scala`),
[backend response tests](../apps/integration-console/atheros-search/internal/embed/response_contract_test.go)
and [tokenizer tests](../apps/integration-console/atheros-search/internal/embed/preflight_test.go).
The [processor feature](../services/octopus/src/test/resources/features/search-projection.feature)
and [backend contract inventory](../apps/integration-console/atheros-search/docs/contracts.md)
describe the updated behavior. Existing processor, job and schema contracts are
reused; no dependency or parallel pipeline was added.

Final verification at parent `9692492026800615798bb9846341bb34d221eece`, Octopus
`9c47daffa33bf016b8a0f9fe23d5821a0c5cb65c` and Integration Console
`69db6850d8b4570987ecc3702c98db2501eb0e95`, plus uncommitted changes:

- Mandatory Docker-enabled `sbt test`: 584 passed, one opt-in live probe skipped.
  The focused canonical/intensity pass ran 52 tests without skips.
  Two similarity tests passed again after adding the anchor-store mismatch case.
- Go 1.26.1 with pinned golangci-lint 2.13.2: `make quality-go` passed race,
  vet, both lint profiles (zero issues), package boundaries, protobuf and fixtures.
  `make stack-contract ATHSEARCH_STACK_ROOT=/Users/rcs/git/ssl-proxy` passed.
- Required canonical Go database runner: 32 top-level tests, 38 including
  subtests, across all eight consumer packages passed with zero skips. The
  isolated container's non-loopback host was supplied through
  TESTCONTAINERS_HOST_OVERRIDE because the repair CLI correctly rejects loopback.
- `make ui-check`: 165 tests and the production build passed.
- Documentation cross-references and `git diff --check` passed in all affected
  repositories.
- The rollup, stale-signal, vector-parity, response-index and tokenizer corruption
  regressions were observed failing before their fixes.

Local acceptance does not authorize activation. M07/D07 capacity and physical
plans, V01 deployed backend behavior and V02 prefix activation remain open.
Legacy rollups created with ingestion-time timestamps require bounded
retained-source reconciliation before rollout; this patch does not rewrite
existing rows. Equal event timestamps retain legacy arrival-order metadata;
validated Stage 6 projections still need B04 deterministic event-ID tie-breaks.
Legacy severity bands remain uncalibrated, and retained observations cannot
establish attempts or validated transfer. No production replay, image promotion,
DDL application or managed-cluster mutation was performed.

### SRC01-SRC07 follow-up: 2026-10-24

The first seven source references in the workmap already had application code.
This follow-up closes remaining replay, measurement and correction gaps:

- SRC01: the canonical PostgreSQL integration suite now sends all frozen retained
  envelopes and their original scan identities through ingestion and the real
  transform/sink. It checks same-offset replay and later-offset duplicate delivery
  without minting replacement observations.
- SRC02-SRC03: existing endpoint, nested hostname sanitization and bounded
  coalescing contracts remain covered by the Rust regression suite.
- SRC04: transparent forwarding keeps successful-write counters outside the two
  cancellable copy futures. A partial write survives a sibling read failure in
  either direction. The shared copy loop also preserves successful forwarding,
  bounded previews and forensic observation callbacks.
- SRC05: additive TLS offer evidence comes from ClientHello legacy_version or
  the highest recognized supported_versions offer, rather than the record
  compatibility version. Unsupported or malformed version lists remain unknown.
  Legacy tls_ver and ja3_lite are preserved. Transparent blocks publish the same
  parser/status/offer evidence as tunnel lifecycle observations. The corrected
  parser is proxy-clienthello-v2; published evidence preserves supported v1/v2
  revisions and reports absent/unsupported revisions as legacy_unknown. This follows
  the compatibility distinction in [RFC 8446 section 5.1](https://www.rfc-editor.org/rfc/rfc8446#section-5.1).
- SRC06: normalized and public Search evidence retain whitelisted measurement
  source and termination fields; unsupported or unversioned provenance is
  explicitly legacy_unknown. No DDL, manifest, grant or image changes are needed.
- SRC07: source corrections retire excluded/missing observations, refresh
  published timestamps and invalidate previous blocked-window groupings. Queue
  saturation permits bounded invalidation without enqueueing new work; one-item
  batches alternate event/window validation. Event metadata retains only an
  opaque former-window key. Recovering privacy-filtered grouping scans at most
  501 private source rows; overflow leaves the old window retired with an explicit
  retired_reconciliation_required disposition.

The checks below record local code acceptance, not production coverage. Existing
prepared historical rows need bounded retained-source reconciliation to receive
new measurement provenance fields and the opaque former-window key before
rollout. Activation, image promotion and recovery
remain subject to the existing M07, D07 and release gates.

Changed runtime paths are the [TLS parser](../src/tunnel/tls.rs),
[tunnel audit context](../src/tunnel/audit_event.rs),
[transparent forwarding](../src/tunnel/transparent_sections/proxying.rs),
[blocked event builder](../src/tunnel/transparent_sections/decisions.rs),
[transparent event types](../src/tunnel/transparent_sections/listener.rs),
[evidence projection](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyEvidence.scala)
and [preparation SQL](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ProxyPreparationSql.scala).
Matching Rust and Scala regression tests and the embedding feature contract were
updated. The payload-audit integration fixture now initializes the additive
identity fields. No new dependencies or generated source files were added.

Broader checks exposed existing repository issues outside these changes:
`cargo test -p ssl-proxy` fails
`shim_unit_requires_separate_containment_without_network_admin` because the
unchanged [shim unit](../config/client/wg-obfs-shim.service) lacks the containment
dependency expected by [its test](../tests/wireguard_template.rs). The broker
payload-audit test remains explicitly ignored without Redpanda. Workspace-wide
format checking reports existing differences in unrelated files; scoped Rust
format checking passes. Clippy completes with existing warnings outside the
modified runtime paths. These checks do not establish a clean repository-wide
release gate.

| Follow-up check | Result |
| --- | --- |
| `cargo test -p ssl-proxy --lib` | 223 passed |
| `cargo test -p sync-plane` | 12 passed |
| Octopus `OCTOPUS_REQUIRE_DOCKER=true sbt test` | 573 passed; one opt-in live probe skipped |
| Focused canonical persistence, evidence and preparation SQL suites | 61 passed; zero skipped, including all 46 canonical persistence tests |
| `cargo clippy -p ssl-proxy --lib --tests` | Completed with existing warnings; none in changed runtime paths |
| Scoped `rustfmt --check`, dependency boundaries, `git diff --check`, documentation checker | Passed |

Before fixes, the TLS compatibility-record test reported TLS1.0 instead of
TLS1.2, the cancellation test lost three accepted bytes, the provenance test
dropped measurement source, and both original source-correction regressions
left stale documents active. The final suites include their passing replacements
and the subsequent queue-fairness and private-grouping regressions.

The checkout began at parent `f745f937329e17a5b21107e9cf5777f0ed6f44f9`,
Octopus `9c47daffa33bf016b8a0f9fe23d5821a0c5cb65c` and Integration Console
`69db6850d8b4570987ecc3702c98db2501eb0e95`. Existing submodule pointer differences
were preserved. The changes remain uncommitted; no images were promoted,
production data replayed or managed Kubernetes resources changed.

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
