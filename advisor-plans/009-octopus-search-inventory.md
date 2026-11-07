# Octopus and Atheros Search: investigation inventory

> **Status: In progress.** Source inventory, not an implementation approval or a
> complete capability audit. Runtime and business validation remain open.

## Snapshot

- Parent: `525df9f5dc0697d98c2e78a823b9910a3ccb5f68`; Search gitlink and
  checkout: `690c9143695d0c8f89fed6539b8d6bd7eaacf217`; Octopus gitlink:
  `341ffea9f33fc9251f8ddfdd325acf7865395733`; Octopus checkout:
  `8f49c5e2d974ff73c4ee0ec942da58ea164dd312`.
- Parent and both submodules contain pre-existing edits. Octopus proxy behavior,
  its SQL and tests, Search worker scope and repair code, and parent schema,
  grants and deployment files include local changes. Do not attribute their
  current contents to a commit without checking `git show`.
- The configured Kubernetes context is `wiretrap-k3s`; a read-only pod lookup
  did not return before cancellation. Running digests, flags, schema versions,
  model and workload measurements are unknown. Desired digests in
  `cyber-stack/matrix/prod/app-stack/kustomization.yaml` are not live evidence.

## Contract and process map

The catalog declares 28 IDs, 26 Octopus and two Search, with contract defaults
disabled (`services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProcessorId.scala:23`,
`:116`). Entries describe contracts, not deployment. The following groups
are the complete declared ID inventory, not a complete execution trace.

| IDs | Output and classification | Evidence still needed |
| --- | --- | --- |
| `sync-scan-ingestion`, `sync-job-planner`, `sync-backlog-recovery`, `sync-load-dispatch`, `sync-load-consumer`, `sync-result-consumer`, `sync-outbox-publisher` | Durable discovery, batching, load, results and dispatch; deterministic coordination. | Every sink's replay behavior, retention and actual consumers. |
| `wireless-heartbeat-ingestion`, `wireless-audit-projection` | Sensor heartbeat and direct wireless projection. Coverage is limited by collection. | Full producer-to-UI trace and operational coverage. |
| `wireless-frame-normalizer`, `wireless-inventory-projector`, `wireless-identity-projector` | Normalized observations, inventory and accepted identity relationships. | Source conflicts, transitive decisions and review consumers. |
| `wireless-behavior-projector`, `wireless-timing-projector`, `wireless-sequence-projector`, `wireless-baseline-projector` | Rules and descriptive statistics over observations. | Scope, late data, sample sizes and downstream decisions. |
| `wireless-similarity-projector`, `rf-alert-projector`, `threat-risk-projector` | Similarity pairs, alerts and rule-based scores; no validated probability established. | SQL eligibility, actual alert path, calibration and presentation. |
| `embedding-text-builder`, `embedding-preparer`, `proxy-search-preparer` | Documents and embedding jobs; deterministic preparation. | Privacy, versioning, corrections and all consumers. Proxy behavior has uncommitted changes. |
| `embedding-completer`, `embedding-lease-recovery` | Search-owned model execution and lease recovery. | Deployed model and input revisions, integration verification. |
| `event-retention`, `search-retention`, `stale-worker-cleanup`, `scheduled-reconciliation` | Archival/retention, cleanup and repair. | Retention race and complete rebuild coverage; reconciliation is not assumed generic. |

`ScheduledWorkloads.scala` and `RetentionWorkloads.scala` wire periodic work.
The declared continuous mode for frame normalization and its fenced periodic
runner warrant investigation before changing either contract. The enabled list
alone is insufficient: `RuntimeStreams.scala:27` adds five consumer IDs when
consumer mode is enabled. Startup separately reconciles DQ policies even when DQ
is disabled (`wiring/CoordinatorApplication.scala:50`); schema refresh and
one-shot hydration are also outside individual processor IDs
(`wiring/RuntimeStreams.scala:33`). Hydration errors are logged by that stream;
its wider recovery path has not been established.

## Ingestion and handoff

1. The sensor publishes `wireless.audit` and records companion discovery with
   backlog handling (`services/atheros-sensor/src/publish_sections/state.rs:315`).
   Proxy publishes allowed observations through discovery (`src/events.rs:270`).
2. Scan intake validates and persists evidence and eligible load work
   (`services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala:201`).
   In projection-only mode it filters companion wireless discovery
   (`services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/ScanRequestStream.scala:37`).
3. Direct wireless projection records group/topic/partition/offset receipts,
   checks coordinate hash conflicts and deduplicates payload hashes within a
   database transaction. Only observations from seven days before to 60 seconds
   after database time update projections; others receive a disposition
   (`services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessStreamSql.scala:23`).
   A retained hash means replay alone is not necessarily a reconstruction path.
   The direct and load paths must not be removed as duplicates.
4. Broker commits follow processing (`services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/LockedTopicConsumer.scala:168`).
   Load handling precedes result evidence (`services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/PostgresLoadStream.scala:49`):
   verify each sink across a crash there. Outbox publication can precede its
   acknowledgement (`services/octopus/src/main/scala/com/sslproxy/coordinator/dispatch/BatchDispatchService.scala:66`),
   so consumers must tolerate replay.
5. Octopus creates and supersedes documents and jobs; Search claims due jobs
   using model, input revision and scope, a fresh token and incremented fence
   (`apps/integration-console/atheros-search/internal/worker/lease.go:17`).
   Changed or missing input is cancelled. Claim commits before external work;
   vector insertion and completion are transactional
   (`apps/integration-console/atheros-search/internal/worker/worker.go:140`, `:296`).
   The completion guard is in locally modified `worker/scope.go`; compare its
   committed version before treating this checkout as the pinned contract.
6. Dense retrieval requires matching active documents, hashes, revisions, kind
   and model (`apps/integration-console/atheros-search/internal/search/dense.go:140`).
   Weighted reciprocal-rank fusion is a ranking, not confidence
   (`apps/integration-console/atheros-search/internal/search/fusion.go:7`).
   Filtered ANN recall, fallback coverage and ground truth are unmeasured.

## Preliminary boundary and verification gates

Keep existing Scala ingestion and current ownership. Investigate logical
grouping and independently configurable workload profiles using the existing
runners; no new service is justified by the available evidence. Existing grants
split document/job and vector responsibilities between Octopus and Search
(`sql/postgres/atheros_search/grants/least_privilege.sql.tmpl:34`); any transfer
requires deliberate ownership, grant, contract and rollback changes. No code
removal or production change is approved by this inventory.

Before implementation, complete factsheets for each capability and trace SQL,
downstream API/UI consumers, source identity, privacy, time windows, late data,
retention, monitoring and boundedness. Compare committed Octopus revisions and
dirty changes against canonical migrations. Verify duplicate and out-of-order
delivery, crash after sink write, poison handling, stale fences, corrected source,
cross-scope isolation, reviewed identity and projection rebuild. Compare old and
proposed outputs on a bounded dataset with matching source, algorithm, model and
configuration revisions; prevent duplicate side effects and define rollback.
Establish business consumers and measurements before removing work or claiming
performance or detection benefit.

## Checks and limitations

`go test ./internal/search ./internal/worker` passed in the Search working tree
on the preceding investigation. This does not prove database integration ran;
`proxy_replay_integration_test.go` requires a separate retained replay setup.
No Scala tests, live database checks, production metrics, exhaustive SQL, DQ
implementation, UI trace or model evaluation have been completed. The initial
pod query was cancelled after waiting without output. No production changes
were made.
