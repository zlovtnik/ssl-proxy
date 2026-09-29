# Atheros Search performance and code quality workmap

> **Status: Ready for execution; source changes not started.** Source reconciliation:
> 2026-09-29, repository `c6da041e`, Integration Console submodule
> `356491c`. The submodule has unrelated uncommitted record-context and explain
> edits; this workmap was reconciled against the visible source without changing
> or attributing those edits. Recheck the tree before implementing any step.

## Objective and boundaries

Turn the 21 numbered recommendations in the requested 2026 Go RAG review into
work that fits the actual Atheros Search backend. The service already owns
embedding jobs, PostgreSQL/pgvector dense search, full-text sparse search,
fusion, HTTP/gRPC search, and ETL health. It does **not** own an LLM, prompt
assembly, token-budgeted context, SSE model output, or direct document JSON
ingestion. Do not add those components to satisfy a generic RAG diagram.

The plan also covers concrete correctness, security, test, and pattern
inconsistencies found during the backend audit. It changes no source itself.
Implement it in reviewable changes, keeping the public API, protobuf, NDJSON,
privacy, schema, and GitOps contracts unless a separate contract change is
approved. Keep projection maintenance and alert derivation in Octopus.

The Integration Console submodule already has uncommitted edits in Search,
API, tests, README, and UI, including new record-context files. These belong
to another workstream. Before changing overlapping files, record their diff,
identify the owner, and isolate or integrate the work without reverting it.
Do not treat a passing test from a moving dirty tree as a fixed baseline.

## Evidence and current architecture

| Area | Present implementation | Consequence |
| --- | --- | --- |
| Retrieval | [`dense.go`](../apps/integration-console/atheros-search/internal/search/dense.go), [`sparse.go`](../apps/integration-console/atheros-search/internal/search/sparse.go), and [`service.go`](../apps/integration-console/atheros-search/internal/search/service.go) use PostgreSQL HNSW, FTS, and weighted RRF | Work reduction and recall measurement matter more than a local SIMD scan |
| Vector index | [`003_search_vectors.sql`](../sql/postgres/atheros_search/01_tables/003_search_vectors.sql) defines HNSW; SQL filters candidates by model, kind, and document scope | Filtered ANN recall and query plans need measurement |
| Embedding | [`scheduler.go`](../apps/integration-console/atheros-search/internal/embed/scheduler.go) provides process-wide interactive/worker slots; [`cache.go`](../apps/integration-console/atheros-search/internal/embed/cache.go) has bounded LRU ownership copies | Existing lane limit is useful; cache misses still duplicate work |
| Tokenization | [`tokens.go`](../apps/integration-console/atheros-search/internal/embed/tokens.go) limits active work but starts a goroutine per item | Waiting goroutines grow with admitted batch size |
| Persistence | [`worker.go`](../apps/integration-console/atheros-search/internal/worker/worker.go) batches embeddings; [`lease.go`](../apps/integration-console/atheros-search/internal/worker/lease.go) writes unified and kind-specific vectors plus completion per job | Production batch 32 entails about 96 statements plus commit |
| API | [`http.go`](../apps/integration-console/atheros-search/internal/api/http.go) caps request bodies and flushes NDJSON only after full search | The stream preserves transfer progress, not retrieval time to first result |
| Runtime | [`go.mod`](../apps/integration-console/atheros-search/go.mod) says Go 1.25, [`Dockerfile`](../apps/integration-console/atheros-search/Dockerfile) and [`Jenkinsfile`](../apps/integration-console/Jenkinsfile) use Go 1.26 | Align toolchains before depending on Go 1.27 facilities |
| Production | [`deployment.yaml`](../cyber-stack/base/atheros-search/deployment.yaml) sets a 1 GiB memory limit and no `GOMEMLIMIT` | Temporary embedding residency can approach the container ceiling |
| Diagnostics | [`metrics.go`](../apps/integration-console/atheros-search/internal/metrics/metrics.go) and [`tracing.go`](../apps/integration-console/atheros-search/internal/observability/tracing.go) expose metrics and traces | No documented secure profile/trace capture or PGO pipeline |

The unified embedding table and kind-specific vector tables are both part of
the current [reporting data contract](../docs/atheros-reporting-data-contract.md).
Treat their dual write as intentional until the contract is changed.

## Recommendation-by-recommendation audit

Status means **Present**, **Partial**, **Missing**, **Investigate**, or **Not
applicable** in this service. “Present” does not imply a measured performance
benefit. Each action points to an execution phase below.

| # | Recommendation | Status | Evidence and required action |
| --- | --- | --- | --- |
| 1 | Ownership instead of deep copying | Partial | Cache copies vectors at its ownership boundary. The dirty submodule work adds record-context fields to Search responses, but no ownership contract for query vectors, decoded responses, or chunk strings has been established. Document and test those boundaries in phase 3; clone retained substrings only if profiling shows large backing storage survives. |
| 2 | Treat `sync.Pool` as optional | Present | No application vector pool found in the recorded baseline. Keep this default; add a pool only after allocation profiles and a benchmark prove value. Recheck the dirty submodule before any adjacent edit. |
| 3 | ANN instead of full Go corpus scan | Present | Dense retrieval runs in pgvector HNSW in the recorded baseline. No retrieval/index changes are part of the current dirty submodule edits. Measure filtered recall and PostgreSQL plans in phase 6 before tuning. |
| 4 | Contiguous local vector layout | Not applicable | Dense vectors are queried through PostgreSQL/pgvector (`internal/search/dense.go`); no local corpus scan or `[][]float32` index exists. Revisit only if a justified local index is introduced. |
| 5 | Go 1.27 SIMD boundary | Not applicable | No local hot dot-product kernel; vector distance is evaluated by pgvector. Keep scalar/SIMD comparison experimental unless profiles justify local math. |
| 6 | Avoid `NumCPU` worker sizing | Present | No `runtime.NumCPU()` sizing found. Embedding slots, tokenizer concurrency, worker count, and PostgreSQL pool are explicitly configured. Benchmark CPU parallelism only if new local kernels appear. |
| 7 | Request-local plus global concurrency | Partial | `embed.Scheduler` globally bounds embedding calls and reserves a worker lane; `ChunkTexts`/`runBounded` bound each fan-out to active workers, including detokenization. Search/API requests still have no process-wide admission or bounded waiting queue, so request count can grow independently of those downstream gates. Phase 4 (previously phases 3–4). |
| 8 | Separate resource budgets | Partial | PostgreSQL pool, embedding scheduler, tokenizer concurrency, chunk cap, and worker count are separate settings. No process-wide query admission or aggregate transient-memory budget is present; no explicit provider requests-per-time quota is configured. Add query/memory budgets only from measured workload and a rate limiter only for a documented backend quota. Phase 4. |
| 9 | Degradable retrieval policy | Partial | Hybrid embedding/backend or dense-query failure has safe sparse fallback codes (`internal/search/fallback.go`, `service.go`). `Dense` and `Sparse` abort on the first per-kind query error, and `Service.Search` returns an error if its sparse leg fails, discarding results from any successful kinds/legs. Define minimum usable results and distinguish total from partial failure in phase 5. |
| 10 | Loop capture cleanup | Present | Go module language version is already 1.25; no loop-capture fix is needed. Remove redundant copies only during adjacent edits. |
| 11 | Hybrid retrieval before micro-optimization | Partial | Dense HNSW + FTS + weighted RRF exist; actual reranking and offline relevance evidence do not. Phase 6. |
| 12 | Duplicate suppression | Missing | Bounded LRU has independent concurrent misses; add interactive-only coalescing with safe cancellation in phase 4. |
| 13 | Bounded batching and bulk persistence | Partial | Embedding requests are batched by tokens; database completion is per job. Phase 7. |
| 14 | Go 1.27 JSON streaming | Investigate | Successful embedding decode already streams via `json.Decoder`; API bodies are capped; worker reads normalized SQL rows. Align Go, then benchmark JSON v2 only on measured hot paths in phase 8. |
| 15 | Avoid `unsafe` zero-copy | Present | No hand-written application `unsafe`; generated protobuf is outside manual edit scope. Keep ownership-safe conversions. |
| 16 | Use builders only where useful | Present | Vector literals use a pre-grown `strings.Builder`; no evidence supports rewriting small bounded text assembly. Profile before change. |
| 17 | Stream output and measure first result | Partial | NDJSON records flush after `svc.Search` completes. Add truthful time-to-first-write metrics and documentation; keep line/done contract. Phase 8. |
| 18 | Runtime memory limit | Missing | Pod limit 1 GiB; no `GOMEMLIMIT`. Set from measured headroom through GitOps in phase 4. |
| 19 | Weighted memory admission | Missing | Batch/chunk bounds exist but no aggregate estimated working-set limit. Phase 4. |
| 20 | Profiles and runtime diagnostics | Partial | Prometheus and OTLP exist; secure CPU/heap/block/mutex, leak, and bounded trace capture are missing. Phase 2/8. |
| 21 | Profile-guided optimization | Missing | No representative CPU profile or PGO comparison. Phase 8 after stable workload and toolchain. |

## Additional backend findings, ordered by risk

| Priority | Finding and evidence | Acceptance target |
| --- | --- | --- |
| P0 | Embedding backend error body is read without a limit in [`client.go`](../apps/integration-console/atheros-search/internal/embed/client.go); backend text reaches worker log/persist paths and viewer record context | Bound success and error response bytes; map provider failures to safe stable diagnostics; no raw provider body in logs, database, or viewer response |
| P1 | [`fusion.go`](../apps/integration-console/atheros-search/internal/search/fusion.go) deduplicates on `SourceKey` alone while CROSS mixes kinds | Prove the canonical identity and use it consistently; equal IDs in different kinds stay distinct |
| P1 | [`service.go`](../apps/integration-console/atheros-search/internal/search/service.go) accepts unknown numeric search modes as successful empty searches | Return a typed invalid argument through service, HTTP, and gRPC |
| P1 | HTTP [`StartHTTP`](../apps/integration-console/atheros-search/internal/api/http.go) starts `ListenAndServe` asynchronously and can report success after bind failure | Bind synchronously; startup fails on occupied port |
| P1 | [`health.go`](../apps/integration-console/atheros-search/internal/worker/health.go) refresh uses `context.Background()` and can remain stuck | Refresh has owned lifecycle and bounded timeout; shutdown cancels it |
| P1 | Public HTTP server has a header timeout and size cap but no body read deadline | Bound slow body reads without breaking WebSocket upgrade |
| P1 | Search/HTTP errors use string matching; JSON strictness differs across inventory, graph, network map, investigation, evidence | Central typed error mapping and one bounded decoder policy, with compatibility tests |
| P1 | Real SQL integration tests skip without DSN and the Testcontainers runner can skip without test dependencies; standard Make/CI do not require it | Mandatory canonical PostgreSQL lane that fails on missing prerequisites |
| P2 | Annotation and irreversible merge decision paths lack focused role/transaction characterization | Add conflict, rollback, audit atomicity, and role matrix tests before shared API refactors |
| P2 | Runtime config helpers silently use defaults for invalid numeric/bool/float env input in [`config.go`](../apps/integration-console/atheros-search/internal/config/config.go) | Invalid explicit values fail startup; documented bounds align with pod budget |
| P2 | Service [`AGENTS.md`](../apps/integration-console/atheros-search/AGENTS.md) documents `make atheros-search-build` and `make atheros-search-proto`, while the root [`Makefile`](../Makefile) has `build-atheros-search` and no proto target | One documented build target and pinned, reproducible protobuf generation with drift check |
| P2 | One production pod serves API and runs embedding workers under one CPU/1 GiB limit in [`deployment.yaml`](../cyber-stack/base/atheros-search/deployment.yaml) | Measure query p99 during backlog; split API/worker deployments if isolation beats shared scheduling |
| P2 | [`pg-size-report.sql`](../ops/sql/pg-size-report.sql) reports unified embeddings and only one of four kind-specific vector tables | Show table/index bytes, bloat and write cost for all vector families before deciding on storage consolidation |

## Rules for implementation and review

These rules make the quality and pattern decisions enforceable. Follow the
repository [root instructions](../AGENTS.md) and [service instructions](../apps/integration-console/atheros-search/AGENTS.md)
for all changes.

| Rule | Enforcement |
| --- | --- |
| Ownership | Publish immutable documents across goroutines. Copy slices only when crossing a mutable lifetime boundary. State who may mutate/release a vector or buffer; tests must cover aliasing where the boundary matters. |
| Bounded work | Every fan-out has both an active-work limit and a bounded queue/admission path. Do not launch one goroutine per item and block it behind a semaphore. Cancellation must release every permit. |
| Budgets by resource | Query, DB, embedding, worker, and estimated transient memory are separate budgets. A rate limiter is introduced only for a measured provider quota; concurrent slots do not substitute for a token quota. |
| Failure policy | Classify invalid input, authorization, no candidates, degraded retrieval, backend unavailable, and overload with stable typed errors/codes. Define minimum usable candidate counts before permitting partial results. |
| Retrieval identity | Fuse and deduplicate on the documented canonical document identity; preserve source kind and version semantics. Benchmark quality using exact reference queries as well as latency. |
| SQL ownership | Canonical DDL lives under `sql/postgres/atheros_search`; use append-only migrations, update manifest/checksums, and keep runtime access within grants. Only the provisioning executor applies DDL. |
| API/privacy | Preserve protobuf and NDJSON line/done contracts. Never log raw query, source key, subject, MAC, token, or backend response text. Reject malformed bodies consistently without widening filters. |
| GitOps | Change production memory, limits, and workload settings under `cyber-stack/`; render and review them. No direct managed-cluster mutation. |
| Optimization | Require representative baseline, CPU/heap/alloc evidence, and before/after outcome for pools, SIMD, unsafe, JSON v2, index changes, parallel legs, and PGO. Remove an experiment when it fails its stated threshold. |
| Test design | Use unit tests for deterministic policy, cancellation, ownership and error mapping; real PostgreSQL tests for HNSW, fencing, grants, and transaction behavior; load tests for queue, RSS, and tail latency. Do not duplicate implementation logic in tests. |
| Dependency restraint | Prefer existing standard library and module dependencies. New packages need a named use case, ownership, version/review plan, and benchmark or reliability evidence. |

## Execution map

Sequence is deliberate: stabilize the baseline and correctness, then bound
work, then tune data access, then consider runtime optimizations. Each phase
can be split into small reviewed changes. A phase is complete only after its
acceptance evidence is recorded in a short implementation note or PR.

### 0. Preserve the active work and establish a trustworthy baseline

1. Record `git status --short`, both HEADs, and the Integration Console
   submodule diff before touching code. Coordinate overlap with the active
   record-context/Search/API edits; use a separate worktree or integrate those
   changes intentionally. Never reset or overwrite them.
2. Re-run `go test ./... -count=1`, `go vet ./...`, format check, and targeted
   race tests on one fixed revision. The audit saw both a passing full run and
   an earlier `record_context_test.go` SQL-mock argument mismatch; reproduce
   and resolve that WIP mismatch before attributing later failures.
3. Record a realistic workload: query kind/mode mix, `topK`, document scope,
   candidate sizes, embedding dimensions, chunk/token distributions, worker
   batch sizes, and concurrent users. Exclude raw queries and identifiers from
   benchmark artifacts.
4. Measure p50/p95/p99, queries/s, time to first NDJSON record, provider
   calls/query, DB wait time, worker jobs/s, GC CPU, peak RSS, allocs/op,
   bytes/op, goroutines, recall@K, and nDCG on a fixed evaluation set. Record
   baseline corpus/index revisions and `EXPLAIN (ANALYZE, BUFFERS)` for dense
   filtered and sparse queries. Define target deltas from this baseline before
   any optimization; include a maximum tolerated recall regression.

**Gate:** Repeatable baseline and safe test fixture exist. Do not report an
improvement from synthetic microbenchmarks alone.

### 1. Fix correctness, privacy, and API patterns

1. In `internal/embed/client.go`, cap both successful JSON and error bodies
   using an explicit configured upper bound plus overflow detection. Return
   stable provider error codes; prevent raw backend text from flowing through
   `internal/worker/worker.go` into `last_error` or through
   `internal/search/record_context.go` to viewers. Keep enough safe structured
   detail to diagnose status, timeout, parse, and size errors. Test oversized
   and adversarial response bodies, cancellation, and redaction.
2. Define the canonical search result identity from schema and API semantics
   before editing `internal/search/fusion.go` or CROSS lookup. Include kind,
   table, source ID and version/document ID as needed; test same source ID
   across kinds and versions. Check every deduplication and explain/lookup
   path for the same identity rule.
3. Validate search mode at `internal/search/service.go` entry. Map unknown
   numeric enum to HTTP 400 and gRPC `InvalidArgument`; retain unspecified
   mode's existing default. Add service and transport contract tests.
4. Make HTTP startup bind synchronously, matching gRPC/metrics startup.
   Add a port-collision test. Bound body read time without changing WebSocket
   behavior; test a slow client and normal upgrade.
5. Give ETL health refresh a service-owned context and configurable timeout.
   Cancel on shutdown, permit retry after timeout, and make stale state
   observable without leaking high-cardinality labels. Test blocked DB calls.
6. Characterize annotation and merge decision transactions and role matrix
   before refactoring shared errors or decoders. Add a bounded strict JSON
   decoder with explicit empty/trailing-value policy. Introduce typed errors
   centrally; migrate endpoints with compatibility tests, then remove
   `strings.Contains(err.Error(), ...)` status selection.

**Gate:** No sensitive provider text reaches logs/state/viewers; invalid
input and bind failures fail explicitly; transaction and auth contracts pass.

### 2. Establish performance and database verification gates

1. Add focused benchmarks for `embed` chunk/token fan-out and decode,
   `search` fusion/vector serialization, and `worker` persistence. Include
   small/typical/pathological distributions and `-benchmem`; store commands
   and aggregate results, not sensitive fixtures.
2. Add a dedicated canonical PostgreSQL integration lane using the existing
   Testcontainers runner and `scripts/requirements-test.txt`. The lane must
   fail clearly when Docker or dependencies are absent; the fast Go unit lane
   may remain separate. Wire it into both the relevant root CI job and the
   Integration Console Jenkins job. Test actual pgvector, FTS, fences, dual
   writes, and grants. Preserve ephemeral DB isolation.
3. Add test and CI gates for `go vet`, targeted `-race`, schema contract and
   documentation checks. Add `govulncheck` after pinning its installation and
   reviewing reachable findings. Keep longer load/relevance suites scheduled
   or manually reviewed if CI time is prohibitive, but do not label skipped
   SQL tests as successful integration coverage.
4. Verify default Prometheus registry includes runtime GC/process series;
   add only missing low-cardinality counters/histograms for admission wait,
   reject, fallback, cache sharing, and first result. Protect profiling data
   and avoid labels containing query text, source IDs, tokens or MACs.
5. Reconcile documented `atheros-search-build` with the actual
   `build-atheros-search` target. Add one pinned protobuf generation command
   for both Go outputs plus a temporary-tree drift check; update the service
   instructions and scripts README in the same change. Never hand-edit
   generated protobuf files.

**Gate:** A failing real SQL assertion fails a required job; all reported
performance deltas are reproducible against the phase 0 baseline.

### 3. Reduce avoidable allocation and fan-out safely

1. Replace the goroutine-per-item pattern in `internal/embed/tokens.go`
   `runBounded` with a fixed number of workers and a bounded work channel or
   indexed loop. Preserve output order, first-error behavior, cancellation,
   and worker slot release. Test a high item count, cancellation during queue
   wait, and race detector behavior.
2. Inspect ownership in `internal/embed/cache.go` and `client.go`: ensure
   returned vectors cannot mutate cached values, batch results do not alias
   reusable decoder storage, and small retained chunk strings do not pin
   large source documents. Clone only at proven lifetime boundaries. Record
   allocs and RSS before/after.
3. Bound all in-memory batch stages (`chunks`, offsets, request inputs,
   decoded vectors) and reduce simultaneous residency if the phase 0 heap
   profile confirms the expected peak. Keep ingestion batch limits in both
   items and tokens.

**Gate:** Goroutine count remains bounded by configured workers plus a small
constant under pathological admitted input; outputs and cancellation match
the old behavior; no throughput/GC regression beyond agreed targets.

### 4. Add process admission, memory control, and duplicate suppression

1. Build one shared admission component used by HTTP and gRPC Search entry
   points. Limit in-flight and queued search work; reject excess with typed
   overload, HTTP 429 or 503 as appropriate, gRPC `ResourceExhausted` or
   `Unavailable`, and a bounded `Retry-After`. Ensure cancellation and panic
   paths release permits. Do not queue full decoded requests indefinitely.
2. Keep existing embedding lane scheduler and worker limits. Add a separate
   cancellation-aware weighted budget for estimated transient embedding
   memory, based on admitted chunk/token counts and vector dimension.
   Explicitly bound both active weight and queue length; benchmark weights
   against measured RSS. Only add external request/token rate limits when
   provider quotas are documented; the current local backend may need none.
3. Coalesce *interactive query* cache misses in `internal/embed/cache.go` or a
   narrow wrapper. Key on normalized query, kind, model/generation and
   normalization version. Let each waiter cancel independently; one canceled
   caller must not cancel work needed by remaining waiters. Bypass or segment
   worker requests so ingestion cannot evict the interactive cache. Measure
   backend calls/query and cache hit/shared-call rates.
4. Set a reviewed `GOMEMLIMIT` below the 1 GiB container limit through
   `cyber-stack/base/atheros-search/deployment.yaml` or the proper production
   overlay. Begin with 5–10% headroom as a hypothesis and account for native,
   stack, mmap and database/client buffers; choose final value from load-test
   RSS, GC CPU and p99. Validate rendered GitOps state before rollout.
5. Make explicit invalid `ATHSEARCH_*` numeric/bool/float values fail config
   validation rather than silently default. Define safe upper bounds for
   worker, embedding, tokenizer and chunk knobs; update README and production
   env sources together.
6. Measure API p99, GC CPU, RSS and DB wait during an embedding backlog. If
   shared-process pressure breaches the phase 0 targets, add explicit
   API-only and worker-only startup modes, then separate GitOps Deployments
   with independent resources, replica counts and rollout controls. Preserve
   fenced claims and service routing; first validate both roles in a staged
   rollout, then disable workers in API pods. Size each role's `GOMEMLIMIT`
   separately. Do not split on architectural preference without this evidence.

**Gate:** Bounded active and waiting work under burst; predictable overload
codes; p99 and RSS meet agreed limits; no interactive starvation or worker
throughput collapse.

### 5. Make partial retrieval behavior deliberate

1. Write a policy table for dense failure, sparse failure, one failed CROSS
   kind, no candidates, scope/auth failure, and cancellation. Keep fatal
   errors fatal; allow degraded results only when an explicit minimum count
   and source coverage rule is met. Expose stable fallback codes without raw
   query or source identifiers.
2. Refactor `internal/search/service.go` and `fallback.go` to retain successful
   dense results when sparse fails and vice versa, and to continue across an
   isolated kind failure when policy permits. Preserve ordering and search
   mode semantics. Add service, HTTP/gRPC, and metrics tests for each branch.
3. Confirm UI/explain consumers interpret fallback metadata correctly.
   Version any new public field rather than silently changing existing
   protobuf or NDJSON shapes.

**Gate:** A usable partial query returns candidates with a truthful degraded
marker; invalid scope, auth, and cancellation never degrade into success.

### 6. Validate retrieval quality before changing ranking or indexes

1. Compare HNSW results with exact search on representative model/kind/scope
   selectivity, including near-empty and highly filtered cases. Record
   recall@K, under-filled topK, latency, plans, buffers, index size and write
   cost. Tune search parameters/iterative scans only from this evidence.
2. If index or SQL changes win, add append-only migration in
   `sql/postgres/atheros_search`, update authoritative manifest/checksum and
   grants as required, and run canonical PostgreSQL tests. Do not switch
   cosine to inner product without proving that the **persisted aggregate**
   vectors are unit-normalized: a mean of normalized chunks may not be.
3. Rename `rerankCandidateLimit` to reflect its current fusion-candidate
   purpose. Define an optional reranker seam only after an offline experiment
   demonstrates recall/nDCG improvement within candidate, deadline, memory,
   and token budgets; specify bypass-on-failure. Do not add a model call merely
   to match generic RAG architecture.
4. Evaluate parallel dense/sparse legs and CROSS kinds only after phase 4
   admission exists. Compare query p95/p99 and PostgreSQL pool wait/saturation
   at the same throughput. Keep sequential execution if parallel work harms
   capacity or tail latency.

**Gate:** Quality threshold is explicit; index/ranking changes improve the
chosen objective without exceeding latency, memory, or DB load budgets.

### 7. Improve worker persistence without weakening fencing

1. Characterize current lease-token, generation, lost-lease, duplicate job,
   conflict and partial-failure behavior in real PostgreSQL tests. Confirm
   unified and kind-specific writes required by the data contract.
   Extend `ops/sql/pg-size-report.sql` to report the unified table and all
   four kind-specific vector tables and indexes. Record bytes, bloat, WAL and
   write amplification; inventory Octopus and Search consumers. Any proposal
   to consolidate storage needs a cross-service ADR and append-only migration
   with backfill, compatibility reads and rollback.
2. Benchmark the current roughly three-statements-per-job transaction against
   staged `pgx.CopyFrom`, arrays or set-based SQL using production batch sizes.
   Choose the simplest passing design. Keep one fenced transaction for vector
   writes and job completion; return individual lost-lease/failed job IDs
   when needed, with bounded isolated retry.
3. Test failover/retry at every transaction boundary and compare jobs/s,
   statements/job, pool wait, WAL, lock time, RSS, and p99 search impact.
   Keep worker concurrency independent from query admission.

**Gate:** No stale lease writes vectors or completes a job; both vector
contracts remain consistent; measured throughput gain offsets complexity.

### 8. Align runtime and add diagnostics only where evidence warrants

1. Align Go language/toolchain/runtime across `go.mod`, Docker builder,
   Jenkins and developer docs in one reviewed change. Run unit, race,
   integration and benchmark comparisons; record compiler/runtime changes.
2. Add a secured, bounded operational capture path for CPU/heap/alloc,
   block/mutex, goroutine leak and short flight-recorder snapshots when
   supported by the selected Go version. Prefer internal-only or triggered
   capture, with access, retention and privacy rules. Never expose pprof on
   the public API listener.
3. Keep `/v1/search/stream` protobuf-JSON lines and final done marker.
   Measure search-compute time, first write and full transfer separately;
   update docs to explain present semantics. Consider an additive staged
   stream only with consumer tests and a versioned protocol need.
4. Benchmark JSON v2 only for measured decode/ingestion hotspots. Keep
   `protojson` on protobuf endpoints. Profile before proposing `sync.Pool`,
   local SIMD, `unsafe`, or a new `[][]float32` replacement.
5. Collect representative CPU profiles with privacy review. Compare an
   explicit PGO build against `-pgo=off` at equal workload, noting throughput,
   p99, binary size, GC CPU and RSS. Promote `default.pgo` only if repeatable
   net benefit and profile freshness/ownership are documented.

**Gate:** Diagnostics can be captured without public exposure; profile and
PGO artifacts have provenance and retention; improvements survive load tests.

### 9. Close documentation, config, and rollout gaps

1. Reconcile Atheros Search README, architecture and degraded-search runbook
   with actual tracing startup, fallback behavior, streaming semantics,
   `ATHSEARCH_EMBEDDING_QUERY_RESERVED_SLOTS`, and every new config knob.
   Remove unconsumed `ATHSEARCH_EVENT_EMBEDDING_SCOPE` from GitOps only after
   verifying no runtime consumer or platform contract needs it.
2. Inspect suspected test-only/dead helpers before removing them; keep
   `BuildQueryText` and any exported compatibility surface that is still
   used. Pattern cleanup must follow usage evidence, not aesthetic preference.
3. Run staged canary/load comparison via reviewed GitOps changes. Watch
   overload rate, dense/sparse fallback, recall, DB pool waits, provider
   calls/query, worker backlog, GC CPU, RSS, OOM restarts, and p99. Roll back
   through Git revert if any hard gate fails; no interactive cluster patching.
4. Mark each numbered recommendation above as completed, rejected with
   evidence, or intentionally not applicable in the implementation note.
   Record source revision, commands, workload, metrics, and remaining risks.

**Gate:** Code, README/runbook, rendered manifests, and observed behavior
agree; every recommendation has a traceable disposition.

## Verification matrix

Run the smallest relevant package test during a change. The release gate is
broader because API, SQL, and capacity behavior cross package boundaries.

| Change | Required evidence |
| --- | --- |
| Go/API/embed/worker | `cd apps/integration-console/atheros-search && go test ./... -count=1`; `go vet ./...`; targeted `go test -race` for changed packages |
| Format | `gofmt -l` on changed Go files returns no paths; `git diff --check` clean |
| Real SQL | Required Testcontainers integration target against canonical manifests; verify HNSW/FTS, fencing, dual-write, grants and rollback |
| SQL migration | `python3 scripts/check-postgres-schema-contract.py` if present; relevant schema-migrator/coordinator contract tests; review manifest/checksum diff |
| GitOps | Project-native GitOps check and `kustomize build cyber-stack/matrix/prod/app-stack`; inspect effective env, limits, image digest and NetworkPolicy |
| Documentation | `python3 scripts/check-docs.py` from repository root |
| Performance | Repeat phase 0 load/relevance fixture at equal throughput and concurrency; compare p50/p95/p99, TTFR, jobs/s, calls/query, recall@K, nDCG, GC CPU, RSS, goroutines and DB waits |

At audit time `go vet ./...` and targeted embed/worker/metrics/observability
race tests passed. One full `go test ./...` attempt failed in the sandbox on
`httptest` listener binding and a dirty-tree record-context SQL-mock mismatch;
a later independent full run passed. Reconcile this on one fixed worktree before
claiming a green baseline. `python3 scripts/check-docs.py` passed before this
plan was added. Dependency update checks were blocked by sandbox network
access; `govulncheck` was not installed, so there is no dependency-audit claim.

## Stop conditions and definition of done

Stop a phase when a required change would overwrite unrelated dirty work,
broaden public contracts without consumer validation, expose sensitive data,
weaken lease fencing, bypass the provisioning schema executor, or require a
production mutation outside GitOps. Escalate that exact decision with the
measured tradeoff and a reviewable patch or experiment.

The workmap is complete when all 21 rows have evidence-backed dispositions;
the P0/P1 correctness and privacy gates pass; query, embedding, worker and
memory work remain bounded under load; SQL correctness and recall are tested
against canonical PostgreSQL; the Go and GitOps configurations match their
docs; and any optimization retained shows a repeatable quality or capacity
benefit without a tail-latency or RSS regression.
