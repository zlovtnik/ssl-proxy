# Octopus memory audit

> **Status: Audit complete; implementation and production measurements pending.**
> Reviewed 2026-10-23 against parent `f639c705`, Octopus submodule `807d639`,
> and the existing uncommitted Octopus changes. No application or deployment
> source was changed by this audit.

## Decision

- Keep Scala, Cats Effect, FS2, PostgreSQL coordination, committed-offset replay,
  transactional writes, fencing, and durable deduplication.
- Prioritize active scan-payload retention and allocation reductions.
- Measure the running container before changing heap ceilings or container limits.
- Treat derived-projection, identity, archival, and DQ changes as follow-up work:
  their workloads are disabled by the rendered production profile.
- Preserve speed and reliability as release gates; no percentage memory saving
  can be justified without a comparable workload and live measurements.

## Scope and evidence limits

| Area | Review |
| --- | --- |
| Runtime | Main, resource wiring, workload gates, scheduler, processor supervision and leases |
| Ingestion | Five locked consumer paths, hydration, dispatch, batching, payload resolution, poison handling and offsets |
| Persistence | PostgreSQL repositories, JDBC sinks, transforms, SQL catalogs and schema/hash contracts |
| Derived work | Wireless behavior/timing/sequence/baseline, similarities, identities, search preparation, risk and retention |
| Service surfaces | DQ control/apply paths, HTTP, public/live metrics, tracing and logging |
| Deployment | Docker/JDK settings, production Kustomize patch order and final rendered coordinator |
| Tests | Test inventory and relevant regression coverage; seven focused suites executed |
| Excluded | Full security/dependency advisory audit; exhaustive unrelated service review; production heap dump, allocation profile, live JVM flags and native-memory measurement |

- Build compiled 125 production Scala sources and 74 test sources successfully.
- Existing edits in the Octopus submodule and Integration Console were preserved.
- Production API reads timed out both within and outside the filesystem sandbox.
- The local `wiretrap` SSH alias did not resolve. No live production data was read.
- Configured production behavior is verified; the running image/revision and
  live environment remain unverified.

## Rendered production configuration

| Setting | Rendered desired state | Evidence |
| --- | --- | --- |
| Rollout | One replica, Recreate | [coordinator patch](../cyber-stack/matrix/prod/patches/java-coordinator.yaml) |
| Memory | Request 2 GiB; container limit 4 GiB | Same patch |
| JVM | JDK 21 generational ZGC; initial heap 40%; maximum heap 60% | Same patch |
| Processor profile | Seven sync processors; broker draining | [profile patch](../cyber-stack/matrix/prod/patches/java-coordinator-broker-drain.yaml) |
| Consumers | Enabled; adds the five Kafka consumer IDs to the enabled set | [ProcessorId.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProcessorId.scala), [consumer wiring](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/workloads/ConsumerWorkloads.scala) |
| Batch bounds | 500 records; 8 MiB encoded value bytes per partition batch | [deployment](../cyber-stack/base/java-coordinator/deployment.yaml) |
| Partition topology | Desired topic partition count 24; four concurrent scan/load/result batch handlers | Same deployment |
| DQ | Disabled; manager and workers scaled to zero | [DQ config](../cyber-stack/base/java-coordinator/dq-config.yaml), [production patch](../cyber-stack/matrix/prod/patches/dq-preparation.yaml) |

- The base deployment lists derived processors, but the production patch
  replaces that list. Base-only inspection gives the wrong diagnosis.
- Wireless audit and heartbeat consumers remain enabled through the consumer
  union. Disabling derived projections does not disable these ingestion paths.
- Desired topic partitions are not proof of the running broker topology.

### JVM sizing result

- Local Azul JDK 21.0.7, using the production collector/percentage settings and
  an explicit 4 GiB MaxRAM simulation, reports:

| Flag | Bytes | Approximate size |
| --- | ---: | ---: |
| InitialHeapSize | 1719664640 | 1.60 GiB |
| MaxHeapSize | 2577399808 | 2.40 GiB |
| MinHeapSize | 8388608 | 8 MiB |
| SoftMaxHeapSize | 2577399808 | 2.40 GiB |
| ZUncommitDelay | 300 seconds | Five minutes |

- Initial heap is not retained live data, RSS, or a permanent 1.6 GiB floor.
  This local JVM sets a much smaller minimum heap. Linux container/runtime
  behavior must be checked in the actual image before promotion.
- The 2 GiB Kubernetes request reserves scheduler capacity; it does not force
  the process to consume 2 GiB.
- A lower initial heap is a reasonable experiment, not a proven cure for
  sustained usage. Keep the existing maximum and container limit initially.
- If measurements show a small live set, compare a 256-512 MiB initial heap
  and a measured ZGC soft maximum while retaining emergency heap headroom.
  Accept only after latency, GC CPU and throughput remain within baseline.
- Keep ZGC initially. Benchmark an alternative collector only after removing
  avoidable payload/collection amplification.
- Reference: [Oracle ZGC sizing and uncommit documentation](https://docs.oracle.com/en/java/javase/21/gctuning/z-garbage-collector2.html).

## Ranked findings: active runtime

Effort: S = hours, M = roughly a day, L = multiple days, including tests.
Confidence describes the code behavior; observed production contribution is
unmeasured for every memory finding.

| Rank | Finding | Impact | Effort | Change risk | Confidence |
| --- | --- | --- | --- | --- | --- |
| 1 | Resolve and persist each scan payload together | Avoid retaining every resolved body in a 500-record batch | S | Low | High |
| 2 | Budget aggregate partition buffers | Prevent partition count from multiplying waiting batch residency | M | Medium | High |
| 3 | Remove repeated full JSON parses | Reduce payload-sized object trees and allocation/GC churn | M | Medium | High |
| 4 | Measure and tune JVM capacity | Potentially lower startup/steady capacity without removing burst headroom | S for evidence; M for controlled comparison | Medium | High for configured sizes; unproven savings |

### 1. Resolve and persist each scan payload together

- Evidence: [ScanRequestStream.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/ScanRequestStream.scala):57-75
  traverses all payload resolutions before starting persistence.
- Evidence: [PostgresPayloadResolver.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresPayloadResolver.scala):38
  reads an entire outbox file, with no configured file byte ceiling.
- Exposure: up to 500 referenced bodies per active scan batch, four active
  scan handlers. Small outbox references bypass the envelope byte budget.
  Inline payloads also coexist with their encoded request envelopes.
- Change: resolve, persist, handle poison and update metrics for one record
  before resolving the next. Keep Kafka commit after the batch completes.
- Preserve: partition ordering, dedupe on replay, permanent-error parking,
  retryable failure propagation, and no commit past unfinished work.
- Verification: fake resolver/store records operation order; second resolution
  must follow first persistence. Inject retryable failures and verify replay.
  A slow-store test with large bodies must show residency independent of
  batch record count, except Kafka envelopes and one active payload per handler.
- Compatibility note: earlier records may become durable before a later
  resolution fails; at-least-once replay and existing dedupe must cover this.

### 2. Budget aggregate partition buffers

- Evidence: [LockedTopicConsumer.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/LockedTopicConsumer.scala):65-97
  builds each partition batch before acquiring a processing permit.
- Evidence: [KafkaComponents.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/KafkaComponents.scala):153-158
  already limits prefetch to one batch and partition fetch to at most 1 MiB.
- Exposure: 24 assigned partitions with sufficiently large/backlogged data
  can hold about 192 MiB of encoded values in completed 8 MiB batches for
  one topic. This is a capacity illustration, not expected occupancy, an RSS
  estimate, or a hard whole-client bound. Count/window limits often lower it.
  Upstream chunks, fetch buffers, decoded models and other groups add memory.
- Change: design a shared admission budget with cancellation/revocation-safe
  permit release; benchmark smaller batch bytes as the simpler first option.
- Do not cap the join of long-lived partition streams: partitions beyond
  that cap could starve. Reducing handler concurrency alone leaves waiting
  batch retention intact.
- Verification: many partitions, slow database, byte/count limits, revoked
  partition, cancellation, poison record, retry, fairness and offset order.
  Kafka may exceed fetch limits for an oversized first record batch; keep
  an explicit admission policy and document that native fetches are separate.

### 3. Remove repeated full JSON parses

- Evidence: resolver streaming-validates the body at
  [PostgresPayloadResolver.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresPayloadResolver.scala):22,39,48.
- Evidence: [ScanRequestRecord.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/domain/ScanRequestRecord.scala):92
  constructs a complete Circe tree to validate and reject JSON null.
- Evidence: [PostgresRepository.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala):208,334
  parses again to extract event type and to validate hydration.
- Change: carry validated payload metadata internally; extract the two
  top-level event-type fields during streaming validation. Preserve malformed
  JSON, trailing-content, null and type-validation behavior.
- Preserve the SHA of original UTF-8 bytes and all public payload contracts.
  Do not trade repeated parses for a long-lived cached full JSON tree.
- Verification: existing domain/resolver/streaming tests plus nested arrays,
  null, invalid JSON and event_type/type precedence. Compare allocation bytes
  per event and GC CPU under identical large-array payloads.

### 4. Measure and tune JVM capacity

- Evidence: production sizing and the local flag result above.
- Required measurements: container working set/RSS; heap used and committed;
  post-GC live heap where available; metaspace/code cache; direct/mapped
  buffers; thread count; GC pause/CPU/allocation; ingest latency/throughput;
  committed-offset lag and durable backlog.
- Existing bindings: [CoordinatorMetrics.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/CoordinatorMetrics.scala):54
  exports JVM memory, buffer pools and GC. Use the existing telemetry stack.
- Distinguish reserved virtual address space, committed heap, live objects,
  native allocations and container accounting before choosing a remedy.
- Capture normal load, backlog replay, slow PostgreSQL, a large payload, and
  an idle interval longer than the uncommit delay. Do not force a production
  full GC just to get a smaller chart.
- Use Git-reviewed configuration and a comparable staging workload. Retain
  existing container/heap maximum initially; rollback by Git revert.
- Do not set an arbitrary direct-memory cap or shrink the container limit
  before identifying live/native peak requirements.

## Findings before re-enabling derived processors

| Finding | Impact | Effort | Change risk | Confidence |
| --- | --- | --- | --- | --- |
| Discarded identity lock result | Full candidate-ID list allocated even when nothing changes | S | Low | High |
| Repeated percentile sorting | Three baseline sorts; repeated timing/MAD sample sorts | S | Low | High |
| Complete projection groups | One busy window/session/BSSID can dominate peak heap | M | Medium | High |
| Complete identity graph rebuild | Several full graph representations; repeated confidence scans | L | High | High |
| Archive representation hash mismatch | Valid events can fail archival and be quarantined | M | Medium | High static evidence |
| Archive body batch retention | Up to 100 complete bodies retained through serial uploads | M | Medium | High |
| DQ report size check after parsing | Oversized report tree allocated before 64 KiB rejection | S | Low | High |

### Discarded identity lock result

- [IdentityGraphSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IdentityGraphSql.scala):107-110,170
  collects all locked candidate IDs and discards the list before the update.
- Use a cursor stream drained to completion inside the same transaction;
  preserve the separate statement and ordered locks. Streaming consumption
  does not remove the PostgreSQL lock requirement.
- Keep concurrency tests for human decisions versus automatic reconciliation.

### Repeated percentile sorting

- [ProjectionFunctions.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProjectionFunctions.scala):42-55
  sorts on every percentile call.
- [IntelligencePreparation.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/IntelligencePreparation.scala):225-229,255-259
  repeatedly sorts identical baseline and timing samples.
- Sort each sample set once, reuse its median, and sort deviations separately.
  Keep interpolation, empty input, duplicates and exact MAD semantics.

### Complete projection groups

- [PostgresRepository.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala):748-801
  fetches 128 rows at a time but `groupAdjacentBy` retains each whole group.
- [IntelligencePreparation.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/IntelligencePreparation.scala):163-259
  regroups/reorders frames and creates additional sample/token collections.
- Baseline groups contain all retained signal samples for one BSSID. Use
  integer-frequency aggregation and exact weighted percentile interpolation;
  retain authoritative sample counts. The SQL signal column is unrestricted
  INT, so a fixed 128/256-bin assumption is invalid without a contract change.
- Behavior can use counters, sums, extrema and distinct sets. Timing still
  needs exact samples or an equivalent exact distribution. Stream narrow
  row types rather than retaining complete 16-field frames.
- Sequence keys generated by the sensor have no time bucket:
  [correlation.rs](../services/atheros-sensor/src/parse/correlation.rs):54-61.
  One source/peer session can span retained history. Preserve its contract;
  reduce unused fields, duplicate lists and adjacent-token tuples first.
- Full sequence token/text output still grows with sequence length. Exact
  behavior distinct sets and exact timing distributions also need capacity;
  do not promise constant memory for every existing output.
- Do not add an outer source-row LIMIT or truncate sessions. Those changes
  corrupt complete-group counts and late-arrival/replay detection.
- Existing PostgreSQL regression:
  [OctopusPersistenceIntegrationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/ingest/OctopusPersistenceIntegrationSuite.scala):2211
  covers groups across 128-row chunks, replay and late arrivals. Add skewed
  large groups and exact randomized output equivalence before refactoring.

### Complete identity graph rebuild

- [PostgresRepository.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala):902-909
  reads all approved edges when changes require a rebuild.
- [IntelligencePreparation.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/IntelligencePreparation.scala):305-328
  creates normalized edges, pair-confidence maps and more edge vectors, then
  scans the confidence map once per component.
- [ProjectionFunctions.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProjectionFunctions.scala):69
  constructs an additional adjacency map.
- First derive confidence in one pass over edges associated with component
  IDs. Consider compact union-find and cursor input after characterization.
- Include [DqApply.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqApply.scala):193
  in any shared solution. Avoid two divergent global-identity implementations.
- Preserve deterministic cluster IDs, transitive merging, duplicate/reversed
  pair confidence, split behavior and atomic replacement. Incremental graph
  maintenance is a separate high-risk design choice.

### Archive representation hash mismatch

- Original payload bytes are hashed by
  [ScanRequestRecord.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/domain/ScanRequestRecord.scala):100
  and stored by [IngestionSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IngestionSql.scala):129.
- The payload column is JSONB in
  [006_legacy_sync_ledger.sql](../sql/postgres/octopus_core/01_tables/006_legacy_sync_ledger.sql):171.
- [MaintenanceSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/MaintenanceSql.scala):16
  reads the JSONB text representation, then
  [PayloadArchive.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/archive/PayloadArchive.scala):53
  compares its byte hash against the original payload hash.
- JSONB does not preserve whitespace or object-key order:
  [PostgreSQL JSON documentation](https://www.postgresql.org/docs/current/datatype-json.html).
  Valid compact JSON can therefore mismatch after a database round trip.
- [PayloadArchiver.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/PayloadArchiver.scala):24
  quarantines invalid archive candidates as failed. This is a reliability
  blocker before enabling archival, not a current RSS explanation.
- Preserve original event hashes. Define a separate stored/archive-byte hash
  or retain exact producer bytes; do not relabel existing evidence hashes.
  Any required schema addition must follow append-only manifest provisioning.
- Add a PostgreSQL round-trip regression using noncanonical object key order
  and compact formatting. In-memory archive candidates miss this failure.

### Archive body batch retention

- [PostgresRepository.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala):953
  materializes payload-bearing archive candidates as a list.
- [PayloadArchiver.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/PayloadArchiver.scala):15
  uploads serially while retaining that list; the default page is 100 bodies.
- Fetch candidate metadata first and one body at a time, with candidate-change
  checks. Preserve archive verification, fencing and archive-before-delete.
  Test large bodies against a slow fake object store.

### DQ report size admission

- [DqRuntime.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqRuntime.scala):335-346
  decodes and parses before applying its byte-size acceptance check.
- Check received byte length before UTF-8 decoding/JSON parsing; preserve
  receipt hashing and quarantine semantics. DQ remains disabled in production.

## Considered and rejected explanations

- Recursive supervisor growth: current supervisor uses `tailRecM`.
- Accumulating cron ticks: each workload uses sequential `awakeEvery.evalMap`.
- Unbounded public-stats cache: one constant-size snapshot and one refresh.
- Metrics label leak as primary cause: current Kafka series are removed on
  revocation/consumer stop; processor IDs and most metric dimensions are fixed.
- Legacy PayloadAuditConsumer/WirelessConsumerService default buffers: no
  production callers in current workload wiring; do not diagnose from them.
- DQ allocations as current cause: disabled by the production configuration.
- All derived processors as current cause: replaced by the broker-drain patch.
- Smaller processor group-count batch as a complete remedy: does not bound
  the largest individual group.
- Runtime database ownership changes, a language rewrite, new caching layers,
  indiscriminate dependency removal and automatic image promotion: unsupported
  by this audit and unnecessary for the demonstrated allocation problems.

## Verification performed

| Check | Result |
| --- | --- |
| Focused sbt suites, Azul JDK 21 | 53 passed; 0 failures/errors |
| Production app-stack Kustomize render | Passed using repository-documented LoadRestrictionsNone |
| Rendered coordinator inspection | Broker-drain profile, one replica, 4 GiB limit, 40/60 JVM percentages confirmed |
| Local JVM flag inspection | Initial/min/max/soft-max heap and uncommit settings recorded above |
| Documentation inventory/links/policy | Passed: python3 scripts/check-docs.py |
| Production pod metrics | Blocked: Kubernetes connection timeouts |
| Live heap/native profiles | Not collected |
| Full/Docker integration suite | Not run; no implementation change |

Executed focused command from the Octopus directory with installed JDK 21:

```sh
sbt --batch 'testOnly com.sslproxy.coordinator.processor.IntelligencePreparationSuite com.sslproxy.coordinator.processor.ProjectionFunctionsSuite com.sslproxy.coordinator.kafka.BoundedBatchingSuite com.sslproxy.coordinator.kafka.ScanRequestStreamSuite com.sslproxy.coordinator.postgres.StreamingPayloadRowsSuite com.sslproxy.coordinator.observability.CoordinatorMetricsSuite com.sslproxy.coordinator.postgres.sql.IdentityGraphSqlSuite'
```

- Test/build output wrote standard ignored `target/` artifacts, including
  coverage instrumentation. No generated artifacts were manually edited.
- Future runtime fixes need focused regressions, then coordinator-wide
  `sbt test`; PostgreSQL behavior must also run with Docker-enabled ephemeral
  integration tests. Preserve matching feature contracts when behavior changes.

## Recommended implementation selection and dependency order

1. Capture deployment/image/runtime and memory baseline; no source fix depends
   on production access, but savings claims and JVM promotion do.
2. Implement per-record scan resolution/persistence with failure/replay tests.
3. Remove redundant JSON trees with allocation comparison and strict decode tests.
4. Measure partition occupancy; implement fair, cancellation-safe byte admission
   only if observed buffers justify its additional coordination complexity.
5. Compare smaller initial heap/soft maximum with unchanged hard headroom.
6. Before restoring derived work, land discarded-lock draining and sorted-sample
   reuse; characterize large groups, then optimize baseline and projection folds.
7. Correct archive hash semantics before enabling retention; then bound archival
   body residency. Optimize global identity rebuilds only with graph-scale evidence.

- Preferred purpose: bounded in-flight coordination over durable work, with
  derivations consuming narrow streamed inputs. Keep durable state in PostgreSQL.
- Enhancement option: expose batch bytes, resolved-body bytes and largest
  projection-group counts using fixed processor/topic labels. Trade-off: small
  instrumentation cost; benefit: directly attributable memory peaks.
- Enhancement option: add a repeatable memory benchmark with ordinary load,
  skewed groups and slow dependencies. Trade-off: benchmark maintenance;
  benefit: reject memory reductions that damage throughput or reliability.
- Detailed implementation plans should be selected from this order before
  dispatch. This audit does not authorize cluster mutation or image promotion.
