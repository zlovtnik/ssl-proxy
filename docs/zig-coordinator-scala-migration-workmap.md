# Zig Coordinator Java-to-Scala Migration Workmap

> **Status: Superseded / completed directionally.** The coordinator now lives
> in `services/octopus` as Scala 3/Cats Effect/FS2. This document is retained
> as migration provenance; its PostgreSQL and Oracle target state is obsolete.
> Use [System Architecture](architecture.md) for current ownership.

**Version:** 1.0  
**Date:** 2026-07-19  
**Status:** Superseded
**Scope:** Migrate `services/zig-coordinator` from Java 21, Spring Boot, and Apache Camel to Scala 3 using the architectural conventions established by `apps/schema-migrator`.

## 1. Outcome

The migration is complete when the coordinator:

- is built with sbt and packaged as a Java 21 assembly JAR;
- uses Scala 3, Cats Effect, FS2, Circe, Doobie, http4s, and log4cats;
- starts and stops through one Cats Effect `Resource` graph;
- preserves all Redpanda, PostgreSQL, Oracle, MinIO, HTTP, metrics, logging, and deployment contracts required by current callers;
- preserves at-least-once delivery and PostgreSQL-backed deduplication;
- remains the repository's only Oracle owner;
- can be cut over and rolled back without schema or message-contract changes; and
- has characterization, integration, failure-injection, and deployment tests covering the runtime state machine.

This is a runtime rewrite, not a redesign of sync-plane contracts or coordinator ownership.

## 2. Fixed Decisions

These decisions keep the migration bounded and avoid combining a language rewrite with an operational rename.

| Decision | Required approach |
|---|---|
| Source location | Keep `services/zig-coordinator` during the migration. |
| Scala project | Use a separate sbt project in `services/zig-coordinator`; do not couple its build to `apps/schema-migrator`. |
| Runtime | Scala 3 on Java 21. |
| Effect model | Use concrete `IO` for service orchestration. Keep `ConnectionIO` private to PostgreSQL persistence adapters. |
| Lifecycle | Acquire pools, Kafka clients, HTTP server, schedulers, and workers through one `Resource[IO, CoordinatorComponents]`. |
| Streaming | Replace Camel routes and timers with supervised FS2 streams. Do not start detached fibers. |
| PostgreSQL | Use Doobie for coordinator state and stored-function calls. Preserve existing SQL signatures and transaction boundaries. |
| Oracle | Keep raw Oracle JDBC behind a narrow adapter and wrap blocking operations in `IO.blocking`. |
| HTTP | Use http4s and retain compatibility endpoints on port `8081`. |
| JSON | Use Circe codecs with explicit snake_case contract fields and unknown-field tolerance. |
| Deployment identity | Initially retain image/service/chart/OTEL identity `java-coordinator` and Helm key `javaCoordinator`. Rename only in a later, separate change. |
| Topics and groups | Preserve all topic names, consumer groups, reply topics, DLQs, and stream allowlists. |
| Database schema | Do not redesign coordinator tables or stored functions as part of the language migration. |
| Delivery | Preserve at-least-once behavior; acknowledge Kafka only at the current durable boundary. |
| Cutover | Cut over by consumer role, with rollback available at each role boundary. |

## 3. Architecture Target

The target follows the schema-migrator's current source architecture rather than stale generic-effect descriptions in its README.

```text
Main (IOApp)
  -> CoordinatorConfig.load and validate
  -> CoordinatorComponents.resource
       -> Postgres transactor
       -> Kafka consumers and producer
       -> Oracle pool and preflight, when enabled
       -> MinIO client, when enabled
       -> metrics registry
       -> http4s server
       -> supervised FS2 worker streams
  -> Resource.useForever

FS2 workers
  -> decode and validate domain contracts
  -> call narrow service/store ports
  -> transact through Postgres or Oracle adapters
  -> publish results or DLQ records
  -> acknowledge only after the required durable action
```

### 3.1 Proposed Package Shape

Keep the existing package identity `com.sslproxy.coordinator` and organize Scala code by responsibility:

```text
com.sslproxy.coordinator
  Main
  config
  domain
  kafka
  ingest
  dispatch
  result
  wireless
  retention
  postgres
  oracle
  minio
  http
  observability
  error
```

### 3.2 Required Boundaries

- `domain` contains immutable case classes, enums, validation, and pure transformations.
- `kafka` owns consumer/producer construction, records, acknowledgements, retry, and DLQ policy.
- `postgres` is the only package allowed to expose Doobie `ConnectionIO` internally.
- `oracle` is the only package allowed to import Oracle JDBC and wallet-specific classes.
- `minio` owns object storage calls and deterministic archive object naming.
- orchestration packages depend on narrow `IO`-returning ports, not JDBC, Kafka, or MinIO implementation classes.
- `http` exposes compatibility health, metrics, and operational routes but does not own worker lifecycle.
- `CoordinatorComponents.resource` is the only production composition root.

### 3.3 Initial Build Baseline

Align with `apps/schema-migrator` unless a documented compatibility spike requires a different version:

- Scala `3.3.8`
- sbt `1.11.6`
- Java target `21`
- Cats Effect `3.7.0`
- FS2 `3.13.0`
- Circe `0.14.14`
- Doobie `1.0.0-RC10`
- http4s `0.23.34`
- log4cats `2.8.0`
- PostgreSQL JDBC `42.7.7`
- Oracle JDBC `23.6.0.24.10`
- MUnit `1.3.4`
- sbt-assembly, Scalafmt, Scalafix, and WartRemover

Add only the Kafka, Prometheus, tracing, Hikari, and MinIO libraries proven necessary by focused spikes. Dependency eviction remains an error, and compilation uses `-Werror`, `-Wvalue-discard`, and `-Wunused:all`.

## 4. Compatibility Contract

### 4.1 Locked Messaging Contracts

The migration must not change:

- `sync.scan.request` with consumer group `zig-coordinator-scan`;
- `sync.oracle.load` with consumer group `oracle-worker-load`;
- `sync.oracle.result` with consumer group `zig-coordinator-result`;
- `proxy.payload_audit` with consumer group `zig-coordinator-payload-audit`;
- the seven `wireless.*` operation topics, their consumer groups, reply topics, and DLQs;
- snake_case JSON fields, current null/default behavior, and tolerance of unknown fields;
- `inline://json/<base64url>` and `outbox://<safe-relative-path>` resolution;
- dynamic wireless reply-topic syntax and allowlisting; and
- configured canonical and legacy Oracle stream aliases.

Golden fixtures must cover the three core sync messages:

- scan request: `stream_name`, `dedupe_key`, `payload_ref`, `observed_at`;
- Oracle load: `job_id`, `batch_id`, `batch_no`, `stream_name`, `payload_ref`, `cursor_start`, `cursor_end`, `attempt`;
- Oracle result: `job_id`, `batch_id`, `status`, `row_count`, `checksum`, `retryable`, `error_class`, `error_text`, `finished_at`.

### 4.2 Locked Persistence Contracts

- Preserve stored-function names, parameter order, SQL array types, JSONB handling, and result columns.
- Preserve `sync_events`, `sync_jobs`, `sync_batches`, and `sync_backlog` state meanings.
- Preserve deterministic job and batch identifiers.
- Preserve `FOR UPDATE SKIP LOCKED` multi-instance behavior.
- Preserve PostgreSQL dedupe as the at-least-once replay boundary.
- Keep Kafka offsets distinct from PostgreSQL event-time cursors.
- Keep Oracle table/procedure expectations and transaction boundaries unchanged.

### 4.3 Locked Operational Contracts

- Container application port remains `8081`.
- Helm Service continues to expose `8080` and target `8081`.
- `/actuator/health` and `/actuator/prometheus` remain available, either as primary routes or compatibility aliases.
- Existing metric names and labels remain scrape-compatible.
- Existing environment variables remain accepted for the first Scala release.
- Wallet paths, password-file behavior, outbox path, and topic-manifest path remain compatible.
- Structured logs retain existing event meanings and exclude secrets and raw payloads.

## 5. Migration Rules

- Characterize current behavior before porting it.
- Port one vertical slice at a time and keep every merged slice green.
- Do not delete Java behavior until its Scala replacement has parity tests.
- Do not silently preserve known defects. Record each one in the parity-exception register and choose explicitly between exact parity and pre-cutover correction.
- Do not run Java and Scala consumers in the same production consumer group during shadow validation.
- Shadow runs must use isolated consumer groups and isolated PostgreSQL/Oracle targets to prevent duplicate side effects.
- Do not use H2 to validate PostgreSQL locking, arrays, JSONB, leases, or concurrency.
- Do not claim parity from unit tests alone; verify durable state, emitted records, acknowledgements, metrics, and failure behavior.

## 6. Work Breakdown

## Phase 0: Baseline and Decisions

**Goal:** Freeze the migration contract and establish evidence for the current Java service.

### Task 0.1: Record the production contract inventory

- [ ] Export the effective environment-variable surface from `application.yaml`, Compose, Helm, and operations tooling.
- [ ] Record topic, group, stream, reply-topic, and DLQ names.
- [ ] Record HTTP paths, ports, probes, metrics, labels, and structured-log event names.
- [ ] Record every PostgreSQL function called by `DatabaseService` and every Oracle object checked or written by the sink.
- [ ] Store sanitized representative message fixtures for every consumed and produced topic.
- [ ] Identify all external callers and dashboards that depend on `java-coordinator` naming.

**DoD:** A reviewed contract inventory exists in the coordinator test resources or documentation and every external compatibility surface has an owner.

### Task 0.2: Create the parity-exception register

Document whether the Scala implementation must preserve or intentionally correct each known behavior:

- [ ] consumers can start before `ApplicationReadyEvent` health checks complete;
- [ ] the main loop can call `get_next_batch` repeatedly after no batch is returned;
- [ ] `idleSleepBackoffMs`, `scanConsumersCount`, and `resultConsumersCount` are currently ineffective;
- [ ] dispatch publication failure can increment the attempt count twice;
- [ ] a retryable Oracle result currently becomes a terminal PostgreSQL failure;
- [ ] duplicate results can overwrite terminal results and add repeated errors;
- [ ] empty scan/result messages can remain uncommitted;
- [ ] Oracle internal retry count is hard-coded separately from route retry configuration;
- [ ] payload archive selection unlocks before MinIO upload;
- [ ] startup datasource diagnostics log failures without failing startup; and
- [ ] retention functions used by Java are not consistently represented in `sql/postgres.source.sql`.

For each entry, record owner, decision, rationale, test expectation, and release note requirement.

**DoD:** Architecture and operations owners approve every parity exception before implementation of the affected slice.

### Task 0.3: Establish repeatable Java evidence

- [ ] Run `./gradlew test` and archive the test report as the migration baseline.
- [ ] Add missing test tags or suites so contract, PostgreSQL integration, Oracle contract, Kafka integration, and deployment checks can run independently.
- [ ] Capture sanitized startup, steady-state, backpressure, retry, and shutdown logs.
- [ ] Capture Prometheus output and health JSON for enabled and disabled Oracle modes.
- [ ] Record Java image size, startup time, idle resource use, and graceful shutdown duration for regression comparison.

**DoD:** The team can rerun the Java baseline locally or in CI and compare Scala output against stable fixtures.

### Task 0.4: Resolve schema source-of-truth drift

- [ ] Reconcile coordinator function locations between root SQL, schema-migrator split SQL, and Java SQL contract tests.
- [ ] Confirm retention functions are part of the canonical ordered PostgreSQL schema.
- [ ] Update tests to read the canonical active schema rather than stale paths.
- [ ] Confirm Oracle contract tests read the canonical Oracle baseline.
- [ ] Make no function-signature changes unless handled as a separate schema contract change.

**DoD:** Java tests and schema-migrator validation agree on one PostgreSQL and one Oracle schema source of truth.

**Phase gate:** Contract inventory, parity decisions, Java baseline, and SQL source-of-truth checks are approved.

## Phase 1: Scala Build and Composition Skeleton

**Goal:** Create the production-shaped Scala service without moving business behavior.

### Task 1.1: Introduce the sbt project

- [ ] Add `build.sbt`, `project/build.properties`, and `project/plugins.sbt` using the schema-migrator baseline.
- [ ] Add matching Scalafmt and Scalafix configuration.
- [ ] Configure Java 21 output, forked tests, warnings as errors, dependency eviction errors, and assembly packaging.
- [ ] Configure `com.sslproxy.coordinator.Main` as the main class.
- [ ] Add ignores for `target/`, `project/target/`, `.bsp/`, and `.metals/` without touching generated local files.
- [ ] Add `sbt compile`, formatting, lint, test, and assembly checks to CI.

**DoD:** A clean checkout can compile, test, format-check, lint-check, and assemble the Scala skeleton on Java 21.

### Task 1.2: Implement typed configuration

- [ ] Model coordinator, PostgreSQL, Kafka, Oracle, MinIO, wireless, retention, HTTP, and observability settings as immutable case classes.
- [ ] Preserve current environment-variable names, precedence, defaults, and URL normalization.
- [ ] Fail on malformed numeric and boolean values instead of silently defaulting.
- [ ] Separate pure validation from directory creation, file reads, network access, and pool acquisition.
- [ ] Redact secrets in rendered configuration and errors.
- [ ] Add table-driven tests for enabled/disabled Oracle, MinIO archive, partial credential groups, and URL variants.

**DoD:** Configuration can be validated without opening a database or broker connection, and compatibility fixtures match current effective configuration.

### Task 1.3: Build the Resource composition root

- [ ] Implement `CoordinatorComponents.resource` with reverse-order finalization.
- [ ] Acquire PostgreSQL, Kafka, optional Oracle, optional MinIO, metrics, HTTP, and supervised workers through `Resource`.
- [ ] Define explicit startup gates before consumers begin polling.
- [ ] Define one shared graceful-shutdown deadline and cancellation finalizers.
- [ ] Add lifecycle tests proving no worker fiber survives resource release.

**DoD:** A no-op service starts, reports health, and shuts down without leaked fibers, threads, pools, or clients.

### Task 1.4: Add compatibility HTTP surfaces

- [ ] Serve on port `8081` by default.
- [ ] Add liveness, readiness, info, and Prometheus routes.
- [ ] Retain `/actuator/health` and `/actuator/prometheus` compatibility paths.
- [ ] Model readiness from initialized resources and worker state, not merely process liveness.
- [ ] Exclude high-frequency probe paths from access logs.

**DoD:** Existing Compose, Helm, operations checks, and Prometheus configuration can query the Scala skeleton without changes.

**Phase gate:** The Scala assembly starts in a container, exposes compatibility health/metrics routes, and shuts down cleanly.

## Phase 2: Domain and Wire Contracts

**Goal:** Port all pure behavior before side-effecting workers.

### Task 2.1: Port message models and codecs

- [ ] Port scan request, Oracle load, Oracle result, payload-audit, and wireless request/reply models.
- [ ] Use explicit codecs where defaults, nulls, aliases, or unknown fields matter.
- [ ] Add golden decode/encode fixtures from sanitized Java traffic.
- [ ] Verify timestamps, UUIDs, numbers, and missing optional fields.
- [ ] Prove unknown input fields remain accepted.

**DoD:** Scala reads every Java fixture and emits contract-equivalent JSON for every produced message.

### Task 2.2: Port payload references and hashing

- [ ] Port inline base64url JSON decoding.
- [ ] Port safe outbox path resolution and traversal prevention.
- [ ] Preserve the 16 MiB payload limit and JSON validation.
- [ ] Preserve SHA-256 byte semantics.
- [ ] Characterize missing or unreadable payload behavior for scan ingestion and Oracle loading separately.

**DoD:** Java and Scala produce identical resolved bytes, hashes, and error categories for the same fixture matrix.

### Task 2.3: Port Oracle target mapping and transforms

- [ ] Port canonical stream-to-target mapping and legacy aliases.
- [ ] Port envelope expansion for probe flush and client inventory.
- [ ] Port all ten target row transformations.
- [ ] Port exact Oracle result checksum construction.
- [ ] Port retryable/permanent Oracle error classification as a pure decision layer.

**DoD:** Golden row and checksum tests match Java byte-for-byte for all targets and representative invalid inputs.

### Task 2.4: Define operational error algebra

- [ ] Define validation, duplicate, transient transport, transient database, poison message, lease conflict, and ambiguous side-effect errors.
- [ ] Map each category to retry, DLQ, acknowledge, health, and log behavior.
- [ ] Preserve original exceptions as causes without exposing secrets.
- [ ] Make retry predicates explicit and bounded.

**DoD:** Every worker can make retry and acknowledgement decisions from typed error categories rather than broad exception catches.

**Phase gate:** Pure Scala contract suites pass without PostgreSQL, Kafka, Oracle, or MinIO.

## Phase 3: PostgreSQL Adapter and State-Machine Harness

**Goal:** Reproduce coordinator database behavior through narrow Doobie adapters.

### Task 3.1: Implement PostgreSQL resource and URL compatibility

- [ ] Port URL precedence and normalization for JDBC and `postgres://` forms.
- [ ] Preserve percent-decoded embedded credentials.
- [ ] Configure Hikari pool sizes and timeouts from existing environment variables.
- [ ] Keep pool metrics compatible where dashboards depend on them.
- [ ] Add connection redaction and resource-release tests.

**DoD:** All supported Java URL/config fixtures connect through the Scala transactor and no credential appears in logs or errors.

### Task 3.2: Define narrow persistence ports

- [ ] Define ports for cursor initialization, scan recording, ingest processing, pending counts, batch leasing, dispatch failure/release, lease recovery, result processing, backlog operations, payload repair, archival, and retention.
- [ ] Return domain values or typed errors from `IO` methods.
- [ ] Keep SQL fragments and `ConnectionIO` private to `postgres`.
- [ ] Add a source-boundary test that rejects Doobie imports outside the adapter package.

**DoD:** Orchestration code can be tested against in-memory ports and cannot depend directly on Doobie.

### Task 3.3: Port stored-function calls

- [ ] Preserve function names, parameter order, explicit casts, array element types, and JSONB handling.
- [ ] Preserve 500-row chunking and resource release.
- [ ] Ensure each logical function call transacts once.
- [ ] Validate returned JSON and nullable columns explicitly.
- [ ] Add contract tests against real PostgreSQL and the canonical schema.

**DoD:** Scala and Java produce equivalent database outcomes for the same function-call fixtures.

### Task 3.4: Add state-machine integration tests

- [ ] Cover pending, processing, batched, dispatched, completed, and failed transitions.
- [ ] Cover scan retry timing and maximum attempts.
- [ ] Cover deterministic IDs, cursor advancement, unsupported streams, tombstones, duplicate keys, and last-input-wins behavior.
- [ ] Cover lease recovery and exhausted attempts.
- [ ] Cover result duplicates and terminal-state behavior according to the parity register.
- [ ] Run concurrent claims to prove `SKIP LOCKED` behavior.

**DoD:** A real-PostgreSQL suite exercises the complete persisted state machine without Kafka or Oracle.

**Phase gate:** PostgreSQL adapter contract and concurrency tests pass against the canonical schema.

## Phase 4: Kafka Runtime and Ingestion

**Goal:** Establish reusable Kafka delivery semantics, then port scan and payload-audit ingestion.

### Task 4.1: Build Kafka resources and worker policy

- [ ] Acquire consumers and producer through `Resource`.
- [ ] Disable topic auto-creation and validate required topics against the manifest.
- [ ] Preserve consumer groups, offset reset behavior, poll limits, and concurrency.
- [ ] Implement bounded producer publication timeouts.
- [ ] Define retry and DLQ helpers that acknowledge only after successful DLQ publication.
- [ ] Add Kafka Testcontainers tests for replay, commit failure, producer failure, cancellation, and restart.

**DoD:** The Kafka harness proves at-least-once processing and no offset loss at durable-boundary failures.

### Task 4.2: Implement bounded batch accumulation

- [ ] Replace mutable Camel accumulators with bounded FS2 grouping or an explicitly bounded queue.
- [ ] Preserve fetch-count and backpressure-budget capacity.
- [ ] Flush on poll completion, configured batch size, or one-second partial-batch timeout as applicable.
- [ ] Define cancellation behavior so unacknowledged records replay.
- [ ] Prove no records are dropped when a database write or flush fails.

**DoD:** Deterministic tests cover size, time, poll-boundary, overflow, failure, and cancellation flush behavior.

### Task 4.3: Port `sync.scan.request`

- [ ] Decode and validate scan records with unknown-field tolerance.
- [ ] Preserve tolerant unresolved-payload recording behavior.
- [ ] Call the scan batch function before acknowledging offsets.
- [ ] Preserve retry/DLQ distinctions from the parity register.
- [ ] Add end-to-end Kafka-to-PostgreSQL replay tests.

**DoD:** Duplicate delivery, database failure, invalid records, and commit failure produce the approved Java-compatible outcomes.

### Task 4.4: Port `proxy.payload_audit`

- [ ] Preserve topic/group identity and translation behavior.
- [ ] Preserve empty-message behavior according to the parity decision.
- [ ] Commit only after the durable PostgreSQL boundary or completed DLQ publication.
- [ ] Add payload-size and no-raw-payload logging assertions.

**DoD:** Payload-audit fixtures produce equivalent database records, acknowledgements, and DLQ records.

**Phase gate:** Scala ingestion passes Kafka/PostgreSQL integration and replay tests under injected failures.

## Phase 5: Coordinator Loop, Backpressure, and Dispatch

**Goal:** Port the orchestration state machine and Oracle load publication.

### Task 5.1: Replace the Camel timer loop with an FS2 stream

- [ ] Preserve the approved phase ordering: adaptive pull, backpressure, ingest, stale lease recovery, dispatch, shadow audit, and heartbeat.
- [ ] Use `awakeEvery` or equivalent monotonic scheduling without overlapping ticks.
- [ ] Keep a failure in one tick from terminating the worker, while surfacing degraded health and metrics.
- [ ] Apply the parity decision for idle backoff and empty dispatch-loop termination.
- [ ] Add a deterministic clock-based ordering test.

**DoD:** A controlled test records the exact approved call order, cadence, error isolation, and shutdown behavior.

### Task 5.2: Port cursor initialization and ingest processing

- [ ] Initialize configured stream cursors before scan intake becomes ready.
- [ ] Invoke ingest processing with current batch, retry, and backoff settings.
- [ ] Preserve PostgreSQL transaction boundaries and cursor meanings.
- [ ] Record last-success timestamps and processed counts with compatible metrics.

**DoD:** Startup and steady-state tests prove consumers cannot be marked ready before required cursor and database initialization succeeds.

### Task 5.3: Port backpressure and adaptive pull

- [ ] Suspend scan intake at the configured budget and resume at half-budget.
- [ ] Preserve suspension state when pending-count lookup fails.
- [ ] Preserve 80 percent/20 percent adaptive thresholds, floor, change threshold, and restart interval unless superseded by a parity decision.
- [ ] Coordinate adaptive restart and suspension without races.
- [ ] Expose compatible running, suspended, and backpressure metrics.

**DoD:** Boundary and concurrency tests prove no intake resumes above the threshold and no records are lost across consumer restart.

### Task 5.4: Port batch leasing and load publication

- [ ] Lease one pending batch through the existing PostgreSQL function.
- [ ] Validate and publish the exact `sync.oracle.load` contract.
- [ ] Mark dispatch failure or release according to current durable-state rules.
- [ ] Preserve at-least-once ambiguity between PostgreSQL state and Kafka publication.
- [ ] Stop dispatch iteration when no batch is available if approved in the parity register.

**DoD:** Failure-injection tests cover crash before publish, publish failure, crash after publish, state-recording failure, replay, and exhausted attempts.

### Task 5.5: Port stale lease recovery

- [ ] Preserve lease age and maximum-attempt behavior.
- [ ] Preserve expected failure-prefix handling if retained by the parity decision.
- [ ] Prove multiple coordinator instances cannot recover the same lease concurrently.
- [ ] Emit compatible failure records, metrics, and structured logs.

**DoD:** Real-PostgreSQL concurrency tests recover or fail each stale batch exactly once per lease cycle.

**Phase gate:** The Scala coordinator can consume scans, create persisted work, dispatch loads, and recover leases with Oracle disabled.

## Phase 6: Oracle Worker and Result Publication

**Goal:** Port wallet preflight, Oracle transactions, and the `sync.oracle.load` worker.

### Task 6.1: Implement Oracle configuration and preflight

- [ ] Validate required wallet files, TNS alias, password file, and JDBC settings before the load consumer is ready.
- [ ] Preserve disabled-sink behavior and warn-only schema validation mode.
- [ ] Validate required tables and procedures.
- [ ] Avoid global JVM property mutation where the Oracle driver supports explicit connection properties; document any unavoidable mutation.
- [ ] Redact all credentials, wallet content, and connection query parameters.

**DoD:** Existing Java wallet/preflight fixtures pass equivalent Scala tests, including disabled, missing, malformed, and warn-only cases.

### Task 6.2: Implement the Oracle JDBC adapter

- [ ] Run all JDBC calls in `IO.blocking`.
- [ ] Roll back on every failed transform/write sequence.
- [ ] Preserve MERGE keys, duplicate handling, statement timeout, batch behavior, and row counts.
- [ ] Attach rollback/finalizer failures without losing the primary failure.


### Task 6.3: Port Oracle retry and result construction

- [ ] Apply the approved internal retry count and backoff.
- [ ] Map validation, payload, JDBC, timeout, and ambiguous commit outcomes to typed result fields.
- [ ] Preserve exact checksum and error-class values.
- [ ] Ensure errors do not log payload bodies or sensitive identifiers.

**DoD:** Java and Scala produce equivalent success and failure result fixtures for every classified error family.

### Task 6.4: Port `sync.oracle.load`

- [ ] Consume one load at the approved poll concurrency.
- [ ] Publish `sync.oracle.result` before acknowledging the load record.
- [ ] On route-level exhaustion, publish the original load to `sync.oracle.load.dlq` before acknowledgement


## Phase 7: Result Processing

**Goal:** Port `sync.oracle.result` and close the core sync loop.

### Task 7.1: Port result accumulation and persistence

- [ ] Decode and batch result records.
- [ ] Preserve last-result-wins behavior inside one function call unless changed by the parity register.
- [ ] Call result processing before acknowledging offsets.
- [ ] Preserve job terminal-state calculation.
- [ ] Apply the approved treatment of retryable failures and duplicate terminal results.

**DoD:** Real-PostgreSQL tests cover success, failure, retryable failure, duplicate, out-of-order, unknown batch, and partial-job results.

### Task 7.2: Port result retry and DLQ behavior

- [ ] Leave records replayable on database failure.
- [ ] Retry and DLQ malformed/nonretryable records according to the approved policy.
- [ ] Acknowledge only after durable state or completed DLQ publication.
- [ ] Add commit-failure and restart tests.

**DoD:** End-to-end Kafka/PostgreSQL tests prove no terminal result is lost and replay remains idempotent.

### Task 7.3: Add the complete sync-loop test

- [ ] Publish a scan request.
- [ ] Observe event, job, and batch creation.
- [ ] Observe load dispatch.
- [ ] Observe result publication and final PostgreSQL states.
- [ ] Repeat with injected failures at every durable boundary.

**DoD:** One automated suite covers scan-to-terminal-result success, replay, retry, DLQ, cancellation, and restart.

**Phase gate:** The complete three-topic state machine is green without the Java runtime.

## Phase 8: Wireless Operations

**Goal:** Port each wireless route as an independent FS2 worker.

### Task 8.1: Port backlog save, list, synced, and prune

- [ ] Preserve all four topic/group pairs.
- [ ] Preserve save upsert, pending ordering, oldest-100 list, mark-synced idempotency, and seven-day prune behavior.
- [ ] Preserve default and dynamic reply-topic behavior.
- [ ] Add duplicate and concurrent-request tests.

**DoD:** Java and Scala return equivalent reply payloads and PostgreSQL backlog states.

### Task 8.2: Port MAC lookup and authorized-network operations

- [ ] Preserve lookup normalization, response fields, and not-found behavior.
- [ ] Preserve authorized-network query and response behavior.
- [ ] Validate dynamic reply topics before constructing producer records.
- [ ] Avoid logging full MAC addresses or user-identifying data.

**DoD:** Golden request/reply tests and Kafka integration tests pass for default, dynamic, invalid, empty, and failing requests.

### Task 8.3: Port probe flush

- [ ] Preserve retries and `.dlq` behavior.
- [ ] Add duplicate and partial-failure tests.


### Task 8.4: Validate wireless consumer concurrency

- [ ] Honor `WIRELESS_CONSUMERS_COUNT`.
- [ ] Prove ordering assumptions for key-partitioned operations.
- [ ] Prove shutdown drains or replays unacknowledged work.
- [ ] Verify one failing wireless worker does not terminate unrelated workers.

**DoD:** Multi-consumer Kafka tests demonstrate approved ordering, isolation, retry, and replay behavior.

**Phase gate:** All seven wireless consumers pass contract and integration suites.

## Phase 9: MinIO, Retention, and Maintenance

**Goal:** Port scheduled non-Kafka maintenance behavior.

### Task 9.1: Port payload archival

- [ ] Acquire the MinIO client through `Resource` when archival is enabled.
- [ ] Preserve bucket validation/creation behavior.
- [ ] Preserve deterministic object path and `s3://` URI construction.
- [ ] Record archive metadata and clear hot payload only after successful upload and hash validation.
- [ ] Test concurrent archive attempts and idempotent overwrite behavior.
- [ ] Expose archive failures without terminating future runs.

**DoD:** MinIO integration tests cover upload, duplicate, hash mismatch, metadata failure, retry, and disabled configuration.

### Task 9.2: Port event and tombstone retention

- [ ] Preserve terminal-age selection and archive-before-delete guards.
- [ ] Preserve normalized wireless frame deletion order.
- [ ] Preserve tombstone expiry and vector retention invocation.
- [ ] Ensure maintenance runs do not overlap within one instance.
- [ ] Prove multiple instances remain safe through database locking/idempotency.

**DoD:** Real-PostgreSQL tests cover protected payloads, archived payloads, tombstones, batch limits, repeat runs, and concurrent runs.

### Task 9.3: Port maintenance scheduling

- [ ] Use monotonic FS2 schedules for archive, retention, lag refresh, shadow audit, and heartbeat work.
- [ ] Supervise every schedule under the application resource.
- [ ] Define initial delay, overlap, retry, and cancellation behavior explicitly.
- [ ] Expose last-success and failure metrics.

**DoD:** Virtual-time or short-interval tests prove cadence, non-overlap, error recovery, and cancellation.

**Phase gate:** Archive and retention behavior is green against real PostgreSQL and MinIO test infrastructure.

## Phase 10: Observability and Operational Parity

**Goal:** Make the Scala service a drop-in operational replacement.

### Task 10.1: Preserve metrics

- [ ] Retain coordinator lag, offsets, refresh failure/staleness, pending ledger, backpressure, route state, ingest, dispatch, heartbeat, and database metrics.
- [ ] Retain labels such as `role`, `route`, `topic`, and `consumer_group`.
- [ ] Preserve last-good lag values on refresh failure.
- [ ] Provide compatibility for Hikari metrics consumed by dashboards or operations tooling.
- [ ] Compare Prometheus text output with the Java baseline.

**DoD:** Existing Prometheus rules and Grafana dashboards operate without query changes.

### Task 10.2: Preserve structured logging and tracing

- [ ] Define stable JSON log events for startup, readiness, worker failure, retry, DLQ, backpressure, dispatch, Oracle load, archive, retention, and shutdown.
- [ ] Carry topic, partition, offset, batch ID, and hashed dedupe context where safe.
- [ ] Preserve OTLP endpoint, protocol, service name, resource attributes, and sampling configuration.
- [ ] Remove full dedupe keys and alert contents from logs unless an audited requirement explicitly retains them.
- [ ] Add automated secret and raw-payload log assertions.

**DoD:** Log-signature checks pass, traces export under existing service identity, and sensitive-data tests find no prohibited values.

### Task 10.3: Finalize health semantics

- [ ] Separate liveness from readiness.
- [ ] Define MinIO readiness behavior for enabled archival.
- [ ] Mark stale lag or failed maintenance as degraded without unnecessary restarts.
- [ ] Preserve compatibility JSON needed by operations tooling.

**DoD:** Compose, Helm, and operations readiness checks pass for healthy, degraded, dependency-down, and shutdown states.

### Task 10.4: Validate graceful shutdown

- [ ] Stop intake before releasing database and producer resources.
- [ ] Bound drain and finalization by the existing shutdown deadline.
- [ ] Leave unfinished records unacknowledged for replay.
- [ ] Release pools, clients, HTTP server, and worker fibers in reverse acquisition order.
- [ ] Test shutdown during every worker's durable boundary.

**DoD:** No lost records, leaked resources, or post-finalization activity occurs in shutdown failure-injection tests.

**Phase gate:** Existing dashboards, alerts, probes, operations commands, and log signatures accept the Scala service.

## Phase 11: Packaging and Repository Integration

**Goal:** Replace build and deployment internals while preserving runtime identity.

### Task 11.1: Replace the coordinator Docker build

- [ ] Build the assembly JAR in a pinned Java 21/sbt builder stage.
- [ ] Run the JAR in a minimal Java 21 JRE image as a non-root user.
- [ ] Preserve port, wallet, outbox, manifest, health-check, and filesystem paths.
- [ ] Preserve read-only-root compatibility and bounded writable temporary storage.
- [ ] Compare image size and startup time with the Java baseline.

**DoD:** `docker compose build java-coordinator` produces a runnable, non-root Scala image with passing health checks.

### Task 11.2: Update root build and CI

- [ ] Replace coordinator Gradle calls in the Makefile with explicit sbt working-directory calls.
- [ ] Add targeted coordinator compile, format, lint, test, assembly, and integration targets.
- [ ] Add Java 21 and sbt caching to root CI.
- [ ] Keep broad repository checks green.
**DoD:** Local and CI commands use the same checks and fail on formatting, lint, compile, contract, or test errors.

### Task 11.3: Validate Compose and Helm

- [ ] Keep Compose service/image name `java-coordinator` for initial cutover.
- [ ] Keep Helm alias/key `javaCoordinator` and stable Kubernetes resource names.
- [ ] Preserve environment variables, secret references, mounts, ports, probes, resources, and OTEL identity.
- [ ] Confirm `atheros-sensor` dependency/readiness behavior is unchanged.

**DoD:** Compose config, Helm lint/template, and local/Kubernetes smoke tests pass without consumer contract changes.

### Task 11.4: Update operations and documentation

- [ ] Replace Java/Spring/Camel/Gradle implementation descriptions and commands.
- [ ] Preserve operator-facing service names and endpoints through the compatibility window.
- [ ] Update wallet, Kafka lag, retry, DLQ, backpressure, archive, retention, and rollback procedures.
- [ ] Update repository and service `AGENTS.md` files after Scala becomes authoritative.
- [ ] Document deprecated framework-only environment variables without removing them prematurely.

**DoD:** A new operator can build, configure, deploy, diagnose, and roll back the Scala coordinator using repository documentation only.

**Phase gate:** Packaged Scala artifacts pass repository, Compose, Helm, and operations smoke checks.

## Phase 12: Shadow Validation, Cutover, and Cleanup

**Goal:** Prove production equivalence, switch roles safely, and remove Java only after rollback confidence.

### Task 12.1: Build an isolated shadow environment

- [ ] Mirror sanitized production-like topic inputs to shadow topics or isolated consumer groups.
- [ ] Use an isolated MinIO bucket and outbox.
- [ ] Prevent shadow outputs from entering production topics or databases.

**DoD:** Java and Scala can process identical fixtures concurrently without sharing side effects.

### Task 12.2: Run failure-injection parity

- [ ] Interrupt PostgreSQL before, during, and after each function call.
- [ ] Interrupt Kafka consume, publish, commit, and DLQ publication.
- [ ] Interrupt MinIO upload and archive metadata recording.
- [ ] Terminate the process during each durable boundary and restart it.
- [ ] Compare retries, duplicates, terminal states, offsets, and recovery time.

**DoD:** Every failure has an approved, tested outcome with no unbounded loss or duplicate side effect outside existing at-least-once guarantees.

### Task 12.3: Cut over by role

Use this order unless production evidence requires a different one:

1. HTTP health/metrics and maintenance-only duties.
2. Wireless request/reply consumers.
3. Scan and payload-audit ingestion.
4. Coordinator ingest/dispatch loop.
For each role:

- [ ] stop the Java role cleanly;
- [ ] record committed offsets and PostgreSQL state;
- [ ] start the Scala role in the original consumer group;
- [ ] verify lag, throughput, errors, duplicates, health, and downstream state;
- [ ] hold through an agreed observation window; and
- [ ] retain a tested switch-back procedure.

**DoD:** Every role completes its observation window within agreed service-level and data-integrity thresholds.

### Task 12.4: Execute rollback drills

- [ ] Stop Scala without acknowledging unfinished records.
- [ ] Restore the Java artifact with unchanged environment and schema.
- [ ] Verify Java resumes from committed offsets and persisted leases.
- [ ] Verify no message/schema translation is required.
- [ ] Record actual recovery time and operator steps.

**DoD:** Operations can restore Java within the agreed recovery objective using the documented procedure.

### Task 12.5: Remove Java and Gradle

Only after the full observation window and rollback sign-off:

- [ ] delete Java production and test sources after confirming every required behavior has Scala coverage;
- [ ] delete Gradle build files and wrapper;
- [ ] remove Spring, Camel, Actuator, Micrometer-Spring, and Logback-specific configuration;
- [ ] remove obsolete framework-only environment handling after its deprecation window;
- [ ] remove stale generated/build references from ignore and documentation files;
- [ ] keep deployment identity compatibility names until a separately approved rename project.

**DoD:** No active build, test, deployment, or documentation path depends on Java, Gradle, Spring, or Camel.

### Task 12.6: Close the migration

- [ ] Run all coordinator unit, contract, integration, failure-injection, image, Compose, and Helm checks.
- [ ] Run relevant schema-migrator tests and schema validation.
- [ ] Run repository dependency-boundary and broad test targets.
- [ ] Archive baseline-versus-final performance and correctness results.
- [ ] Mark parity exceptions as resolved, accepted, or scheduled follow-up work.
- [ ] Publish operator release notes and ownership handoff.

**DoD:** Architecture, backend, database, operations, security, and QA owners sign off the Scala coordinator as authoritative.

## 7. Required Test Matrix

| Layer | Minimum verification |
|---|---|
| Pure domain | MUnit golden codecs, transforms, hashing, validation, and error classification |
| Configuration | Table-driven environment precedence, defaults, malformed values, and secret redaction |
| PostgreSQL | Real PostgreSQL stored-function, array, JSONB, locking, lease, dedupe, cursor, backlog, archive, and retention tests |
| Kafka | Testcontainers consume, publish, commit, replay, rebalance, retry, DLQ, cancellation, and multi-consumer tests |
| MinIO | Testcontainers bucket, object, duplicate, failure, and metadata-ordering tests |
| HTTP | http4s health, readiness, metrics, compatibility-path, and shutdown tests |
| Lifecycle | Resource acquisition failure, reverse finalization, cancellation, no leaked fiber/client/pool tests |
| End to end | Scan to terminal result, wireless request/reply, archive/retention, restart, and failure-injection suites |
| Deployment | Assembly execution, non-root image, Compose config/smoke, Helm lint/template/schema, and operations checks |

H2 and mocks may support fast unit tests but cannot be the acceptance evidence for PostgreSQL concurrency or dialect behavior.

## 8. Role Ownership

| Role | Responsibilities |
|---|---|
| Scala lead | Build, Cats Effect lifecycle, FS2 workers, package boundaries, code quality |
| Coordinator domain owner | Runtime state machine, compatibility decisions, Kafka acknowledgement semantics |
| PostgreSQL owner | Stored-function contracts, dedupe, cursoring, leases, concurrency, retention |
| Platform owner | Kafka, MinIO, metrics, tracing, container, Compose, Helm, CI |
| QA owner | Characterization, golden fixtures, integration matrix, failure injection, parity reports |
| Operations owner | Cutover, observation windows, rollback drills, runbooks, service-level acceptance |
| Security owner | Secret handling, path traversal, payload limits, log redaction, container hardening |

One person may fill multiple roles, but each phase gate must have named reviewers for the affected responsibilities.

## 9. Risk Register

| Risk | Mitigation | Release gate |
|---|---|---|
| Kafka offset loss during framework replacement | Durable-boundary integration tests and process-kill replay tests | No role cutover without replay evidence |
| PostgreSQL semantic drift from JDBC to Doobie | Real PostgreSQL contract and concurrency suites | No H2-only acceptance |
| Startup races | Resource-ordered readiness and consumer startup tests | Consumers not ready before dependencies |
| Worker leaks or ungraceful cancellation | Resource/supervisor lifecycle tests | Zero surviving fibers or clients |
| Metric/dashboard breakage | Prometheus baseline comparison | Existing alerts/dashboards validated |
| Config incompatibility | Golden effective-config fixtures | Existing deployment values start Scala |
| SQL source drift | Canonical schema reconciliation in Phase 0 | No persistence port before resolution |
| Shadow duplicate side effects | Isolated groups and isolated databases/buckets | No production side effects from shadow |
| Rewrite expands into redesign | Fixed decisions and parity-exception approvals | Contract change handled separately |
| Operational rename causes avoidable churn | Retain `java-coordinator` compatibility identity | Rename deferred to separate project |

## 10. Definition of Done

The migration is complete only when all of the following are true:

- [ ] `services/zig-coordinator` is an sbt/Scala 3 project on Java 21.
- [ ] One `Resource` graph owns every long-lived resource and worker.
- [ ] No Spring Boot, Camel, or Gradle runtime/build dependency remains.
- [ ] At-least-once delivery and PostgreSQL dedupe are proven under process and dependency failures.
- [ ] Existing health, metrics, tracing, logs, Compose, Helm, operations, and dashboards work through the compatibility window.
- [ ] Java-versus-Scala shadow comparisons meet agreed correctness and performance thresholds.
- [ ] Role-by-role cutover and full Java rollback have both been rehearsed.
- [ ] Java and Gradle files are removed only after the rollback observation window.
- [ ] Documentation and local agent instructions describe the Scala implementation as authoritative.
- [ ] All phase gates have named sign-off and linked test evidence.

## 11. Suggested Delivery Milestones

| Milestone | Included phases | Exit result |
|---|---|---|
| M1: Contract baseline | Phase 0 | Current behavior and exceptions are explicit and reproducible |
| M2: Scala foundation | Phases 1-2 | Production-shaped skeleton and pure contracts are green |
| M3: Persisted ingestion | Phases 3-4 | Scan and payload-audit reach PostgreSQL safely |
| M4: Core dispatch | Phase 5 | Jobs/batches dispatch with leases and backpressure |
| M6: Full feature parity | Phases 8-10 | Wireless, maintenance, and observability are complete |
| M7: Deployable replacement | Phase 11 | Image, CI, Compose, Helm, and operations are green |
| M8: Production authority | Phase 12 | Cutover, rollback drill, Java removal, and sign-off complete |

Each milestone should be delivered as reviewable changes that leave the repository green. Avoid one final branch that combines the build replacement, behavior rewrite, deployment changes, and Java deletion.
