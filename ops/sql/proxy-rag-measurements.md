# Proxy RAG measurements

Scope: stages 1 and 2 of the [workmap](../../advisor-plans/002-proxy-rag-ml-workmap.md).
The [collector](proxy-rag-measure.py), [coverage SQL](proxy-rag-coverage.sql),
[aggregate-window SQL](proxy-rag-window-coverage.sql),
[baseline SQL](proxy-rag-baseline.sql) and [lifecycle SQL](proxy-tunnel-completeness.sql)
are read-only. They never enqueue, reset, retry or repair work.

## Commands

Record local revisions, desired-file hashes and explicitly unavailable live data:

```sh
python3 ops/sql/proxy-rag-measure.py
python3 ops/sql/proxy-rag-measure.py --live --namespace prod-ssl-proxy
```

Database access uses an existing libpq service/environment and a read-only audit
account, never command-line passwords. It needs private-source SELECT privileges;
do not give those privileges to the Search runtime. Avoid logging libpq settings.

```sh
python3 ops/sql/proxy-rag-measure.py --database \
  --window-start 2026-10-18T00:00:00Z --window-end 2026-10-19T00:00:00Z \
  --page-size 500 --max-pages 10 --statement-timeout-ms 5000 --blocked-windows
```

The wrapper permits at most one day, 1000 rows per independent source/document
page, 100 pages and 30 seconds per statement. Defaults are 500 rows, one page,
five seconds; lock timeout is one second. These are audit safety ceilings, not
measured recovery budgets. Exhausting the page budget is explicitly incomplete.
Cursors are internal and stripped from exported output. Direct SQL callers must
validate parameters with equivalent limits; do not accept untrusted psql variables.
Pages use separate repeatable-read snapshots. Freeze a replica/cutoff for campaign
totals; concurrent corrections can otherwise change counts between pages.

Lifecycle candidates use the following additional bounded horizon and per-key
counterpart cap. Widening the horizon is a new measurement, not proof that an
unpaired flow is incomplete forever. Validate horizon length (at most seven days)
and counterpart limit (2..100) before direct invocation.

```sh
psql -X -w -qAt -v ON_ERROR_STOP=1 \
  -v window_start=2026-10-18T00:00:00Z -v window_end=2026-10-19T00:00:00Z \
  -v horizon_start=2026-10-17T00:00:00Z -v horizon_end=2026-10-20T00:00:00Z \
  -v after_time=2026-10-18T00:00:00Z -v after_id='' \
  -v page_size=500 -v counterpart_limit=20 -v statement_timeout_ms=5000 \
  -f ops/sql/proxy-tunnel-completeness.sql
```

## Denominators and matches

Every scanned source observation has one disposition: excluded event type,
excluded missing host, excluded control/whitespace host, eligible sanitized, or
eligible unvalidated authority. The seven event types match the
[producer allowlist](../../src/proxy_sync.rs). These are audit eligibility
dispositions; legacy preparation can still include malformed hosts. The audit
does not change that runtime behavior. Retention-truncated/unretained sources
are outside the scanned denominator and cannot be counted without a retained
ledger. Sanitized events remain observations but cannot enter exact DNS grouping.

Source matching uses `proxy_events`, source event ID, `proxy_event` and active
status; multiple active versions are a separate error count. Legacy noncompact
document identity remains Java name UUID of `source_table:source_key:text_sha256`;
source version remains the first 15 checksum hex digits interpreted as a long.
The audit does not mint identities. Expected legacy text follows the existing
template for ASCII hosts only; Unicode host text is explicitly unverifiable
because PostgreSQL and Java locale/normalization behavior need not agree.

Document pages cover active `proxy_event` and `proxy_blocked_host_window` records
whose observed time is inside the frozen interval. Source-event pages cannot
establish absent aggregate windows. `--blocked-windows` separately audits closed,
whole UTC hours with at most page-size + 1 input rows before aggregation. An
overflow sentinel suppresses the entire hour's denominator. UTC legacy keys and
text are compared; attest the preparation session timezone before trusting
historical identity matches. Null observed times are outside this
interval denominator and need a separate reviewed exception audit.

Current-content jobs match document ID, event embedding kind, model
`nomic-embed-text-v2-moe` and exact normalized-text checksum. Failed, exhausted,
cancelled, pending, leased, completed and absent are separate dispositions.
Vector presence, content checksum, actual vector equality and per-kind/unified
parity are independent. Completed jobs with missing vectors remain gaps.
Unknown preprocessing, template and normalization metadata are explicit legacy
buckets; content equality is never reported as proven preprocessing compatibility.
Exact hashes are not raw-envelope checksums. Output contains only counts,
versions, checksums and timestamps, not hosts, device keys, addresses or job IDs.

Registration-ID presence and correlation-ID presence use observation denominators
and do not validate attribution or flows. Legacy scalar zeros do not establish
measured transfer availability. Raw authority, explicit ports, suppression counts,
terminal bytes and TLS semantics stay unknown until supported evidence contracts
exist. Retained identity-method, duration and ClientHello field presence is counted
separately without validating its meaning or completeness. Lifecycle output is candidate correlations within its horizon; repeated
correlations across seed pages must not be summed as distinct validated flows.

## Capacity gate

Supply a JSON capacity sheet with `--capacity path.json`; run the collector without
it to obtain all required field names. Values must be finite, nonnegative and
measured over `measured_duration_seconds`. Record interactive p95/p99 separately
from current ingestion and backfill jobs/tokens per second, queue growth and lag.
Record backend errors, DB waits/locks/WAL and memory in the stated field units.
Operator budgets include current jobs/sec reserve, queue headroom, scan rows,
transaction milliseconds, and pause limits for p99, lag, backend errors and memory.
The collector never derives these thresholds from historical counts.

Drain seconds = pending jobs / (measured total jobs/sec - current reserve jobs/sec).
No positive reserve remainder, growing queue or exceeded pause threshold produces
a drain estimate. Even a measured candidate requires review and later recovery
prerequisites. Database cumulative counters require two timed samples. Pod env
specifications, including consumer-union intent, do not establish actual executed
processor dependency closure. Missing capacity or runtime evidence blocks recovery.

## Verification

```sh
python3 -m unittest discover -s scripts/tests -p 'test_proxy_rag_measure.py' -v
PROXY_RAG_PLAN_OUTPUT=/tmp/proxy-rag-explain.json python3 scripts/tests/proxy_rag_integration.py -v
```

The second command requires Docker and provisions disposable canonical pgvector
PostgreSQL Testcontainers using the repository-pinned image and dependencies in
[test requirements](../../scripts/requirements-test.txt). It never connects to a configured
production database. Missing Docker fails, rather than skipping the suite.
The optional EXPLAIN artifact records actual scanned/returned rows and buffers.
Database migrations remain unchanged. Test fixtures use private-source SELECT
only on an isolated audit role, not a new runtime grant.

## Implementation record: 2026-10-19

[Machine baseline](fixtures/proxy-rag-baseline-20261019.json), measured at
2026-10-19T15:35:36Z, records parent `99ed0dfbed057ac1fd2c574bcedbb338f90c85bc`,
Octopus `c8d603ed015ea71484f06ca4dcb874d23b3d5d10` and Integration Console
`6a648e8ecb6e84cb029e738b5df7409f6aee7797`. Initial drift comparisons against
the workmap bases were empty in all scoped code paths. The parent already had
documentation edits; those were preserved. All implementation changes are still
uncommitted in their owning repositories. Parent gitlinks are unchanged; commit
and record the compatible submodule pins together before promotion.

The read-only pod inspection in context `wiretrap-k3s`, namespace `prod-ssl-proxy`,
timed out after 15 seconds. Live images, worker settings, processor execution and
dependency closure remain unavailable. No production database credentials were
used; retained range, schema attestations, production vector extension and all
production counts remain unavailable. Desired file hashes are intent only.
Expected unchanged manifest identities are:

| Domain | Version | Manifest SHA-256 |
| --- | --- | --- |
| octopus_core | 2026101701 | `38f44137d93d46615bc99090dea2149637b8be5ce7c4d8dfdd0b60d9b8f170fc` |
| atheros_search | 011 | `cf93e7e611ddfa897f36e68f454160ef9dfd57686fbbb262bb030ca050ba912f` |

The synthetic database contains 20,000 older background observations. Its frozen
2026-10-19 interval has 10 observations: seven eligible (including one sanitized),
three named exclusions, five eligible absent event documents, one stale legacy
text, two stale structured details, two current-content completed jobs and two
unified vectors with both per-kind vectors missing. Eight absent documents across
all scanned rows include the three exclusions; those are not eight eligible gaps.
The independent nine-document job fixture covers absent/stale-checksum, pending,
leased, failed, cancelled, both exhausted states, completed-without-vectors and
same-checksum/different-vector parity. Unknown legacy revisions remain explicit.

The lifecycle fixture finds both cross-boundary pairs within its horizon and two
unknown missing sides when the horizon is narrowed. The blocked-window fixture
has two retained observations in one group: absent then deliberately stale
coverage is detected; an input cap of one returns an overflow sentinel and no
group denominator. These are injected synthetic gaps, not recovered production
counts. No recovery or activation was performed.

[EXPLAIN ANALYZE evidence](fixtures/proxy-rag-explain-20261019.json) records a
three-row source page and one JSON output over the representative synthetic
volume. The existing source time index scans 10 in-range rows; rows scanned are
not equated with the three-row page limit. Observed planning/execution time was
1.818/0.721 ms in the disposable database. Those timings are not production
latency or recovery budgets. Dense intervals and version history can require
more index/sort work; statement timeouts and live plans remain required.

| Command | Result |
| --- | --- |
| `python3 -m unittest discover -s scripts/tests -p 'test_proxy_rag_measure.py' -v` | PASS, 4 tests; capacity missing/finite/pause behavior and shared byte identity |
| `PROXY_RAG_PLAN_OUTPUT=/tmp/proxy-rag-explain.json /private/tmp/proxy-rag-test-venv/bin/python scripts/tests/proxy_rag_integration.py -v` | PASS, 7 tests, zero skips; canonical pgvector 0.8.6 via Testcontainers |
| In Octopus: `sbt 'testOnly com.sslproxy.coordinator.processor.ProxyAuthoritySuite com.sslproxy.coordinator.processor.SearchDocumentPreparationSuite com.sslproxy.coordinator.postgres.sql.SearchPreparationSqlSuite'` | PASS, 68 tests including 61 shared authority cases |
| In Search: `GOTOOLCHAIN=go1.26.1 go test -race ./internal/queryscope ./internal/search ./tests/architecture` | PASS; shared authority, legacy search and package boundaries |
| In Search: `PATH="/Users/rcs/go/bin:$PATH" GOTOOLCHAIN=go1.26.1 make quality-go` | PASS; vet, all race tests, both lint configurations, boundaries, proto comparison and Go fixtures |
| `GOTOOLCHAIN=go1.26.1 /private/tmp/proxy-rag-test-venv/bin/python scripts/tests/test_atheros_reporting.py --required -v` | PASS, canonical DDL, real runtime grants and executed Go database contracts; zero skips |
| `python3 scripts/check-postgres-schema-contract.py` | PASS; no migration bytes, manifests or readiness expectations changed |
| `python3 scripts/check-docs.py` and `git diff --check` in all three repositories | PASS |

The system linter was 2.14.0; the required 2.13.2 was installed and selected
explicitly for quality validation. Python test dependencies were installed into
`/private/tmp/proxy-rag-test-venv`. Build/test caches under existing generated
directories were populated by the tools; no generated source, runtime files,
production manifests or secrets were manually edited.

M01-M06 satisfy the tooling/synthetic stage gate. M07 remains open: no measured
jobs/sec, tokens/sec, latency, fresh-ingest reserve, queue headroom, DB waits/WAL,
memory, pause thresholds or drain estimate exists. Full Scala persistence,
schema-executor fresh/upgrade and producer suites were not rerun for these pure
APIs/read-only audits; later schema/producer/runtime changes require their gates.
The historical 175,519 is still unverified. Stage 2's
[IDNA/PSL and migration policy](../../docs/proxy-authority-v1.md) is implemented
as pure APIs; later activation must preserve the version and privacy boundaries.
