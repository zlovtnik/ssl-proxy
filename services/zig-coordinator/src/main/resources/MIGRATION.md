# Migration Plan: Zig Coordinator to Java/Spring Boot/Apache Camel

I've thoroughly analyzed all 9 Zig source files (1,700+ lines), the Postgres schema (4,785 lines), coordinator SQL functions (22 stored procedures), Dockerfile, docker-compose, Helm deployment, and architecture documentation.

---

## Architecture Overview (What the Zig Coordinator Does)

The coordinator is a **state-machine loop** that orchestrates the sync plane between the Rust proxy, Postgres, Redpanda, and the Oracle worker:

```text
loop {
  1. Pull scan requests from Redpanda (sync.scan.request)
  2. Record scan requests in Postgres (sync_events table)
  3. Process ingest ledger (transition events: pending->processing->batched)
  4. Recover stale dispatched batches
  5. Dispatch next batch to Oracle worker (sync.oracle.load)
  6. Handle Oracle results (sync.oracle.result -> process in Postgres)
  7. Shadow audit (generate shadow device alerts)
  8. Wireless operations (7 handlers: backlog, MAC lookup, networks, probes)
}
```

**Key technical facts:**
- All DB access is via `psql` subprocess calls (no native Postgres driver)
- All Redpanda access is via `redpanda` CLI subprocess (no native Kafka driver)
- 22 Postgres stored procedures in `coordinator` schema
- 3 Redpanda topics, 9+ streams with consumer groups
- ~40 env vars for configuration
- Backpressure via DB-driven inflight watermark
- Graceful shutdown via SIGINT/SIGTERM

---

## Proposed Java Project Structure

```text
services/zig-coordinator/
|-- build.gradle.kts
|-- settings.gradle.kts
|-- gradle/
|   `-- wrapper/
|-- Dockerfile                          # New: slim JRE-based
`-- src/
    `-- main/
        |-- java/com/sslproxy/coordinator/
        |   |-- CoordinatorApplication.java        # @SpringBootApplication
        |   |-- config/
        |   |   |-- CoordinatorProperties.java     # @ConfigurationProperties (all ~40 env vars)
        |   |   |-- RedpandaConfig.java            # Camel Kafka endpoint config
        |   |   `-- DataSourceConfig.java          # javax.sql.DataSource
        |   |-- route/
        |   |   |-- CoordinatorRoute.java          # Main Camel route (the loop)
        |   |   |-- ScanRequestRoute.java          # Pull from sync.scan.request
        |   |   |-- OracleResultRoute.java         # Handle sync.oracle.result
        |   |   |-- BatchDispatchRoute.java        # Dispatch to sync.oracle.load
        |   |   `-- WirelessRoutes.java            # All 7 wireless handlers
        |   |-- processor/
        |   |   |-- ScanRecordProcessor.java       # Record scan requests in DB
        |   |   |-- IngestProcessor.java           # process_ingest_ledger
        |   |   |-- BatchDispatchProcessor.java    # get_next_batch -> publish
        |   |   |-- ResultProcessor.java           # process_batch_results
        |   |   |-- StaleBatchRecoveryProcessor.java
        |   |   |-- ShadowAuditProcessor.java
        |   |   `-- PayloadResolver.java           # inline://json + outbox:// resolution
        |   |-- service/
        |   |   |-- DatabaseService.java           # JDBC calls to stored procedures
        |   |   |-- HealthCheckService.java        # DB + Redpanda connectivity checks
        |   |   `-- CursorService.java             # ensureCursor logic
        |   |-- model/
        |   |   |-- ScanRequest.java               # JSON DTO
        |   |   |-- DispatchPayload.java           # JSON DTO
        |   |   `-- WirelessRequest.java           # JSON DTO
        |   `-- util/
        |       |-- Sha256Utils.java
        |       `-- SqlLiteralUtils.java
        `-- resources/
            |-- application.yaml
            `-- logback.xml
```

---

## Technology Choices

| Layer | Choice | Reasoning |
|-------|--------|-----------|
| Framework | Spring Boot 3.x | DI, @ConfigurationProperties, health actuator |
| Orchestration | Apache Camel 4.x | Native routing, Kafka component, timer-based polling, error handling |
| DB Access | Spring JDBC (`JdbcTemplate`) | Direct stored procedure calls (same as Zig's psql pattern but native) |
| Redpanda | Camel Kafka component | Replaces `redpanda` CLI subprocess calls |
| Scheduling | Camel `timer:` component | Replaces the `while() { sleep }` loop with managed polling |
| Health | Spring Boot Actuator + custom | Replaces `healthcheck` subcommand |
| Build | Gradle (Kotlin DSL) | As you specified |
| Java | 21 (Azul Zulu) | LTS release, supported by Spring Boot 3.4.x |

---

## Route Design (How Camel Mirrors the Zig Loop)

The main loop becomes a Camel route with a **ScheduledPollingConsumer** pattern:

```text
timer:coordinator?period={{idleSleepMs}}
  -> choice()
    -> when(backpressure check passes)
      -> wireTap("direct:scanRequests")    // pull & record
    -> wireTap("direct:processIngest")     // process_ingest_ledger
    -> wireTap("direct:recoverStale")      // recover stale batches
    -> wireTap("direct:dispatchBatch")     // dispatch to oracle
    -> wireTap("direct:handleResults")     // pull & process results
    -> wireTap("direct:shadowAudit")       // shadow audit (rate-limited)
    -> wireTap("direct:wirelessOps")       // all 7 wireless handlers
```

Each `direct:` endpoint is a separate Camel route with:
- Error handling (redelivery, dead letter channel)
- Metrics exposure via Micrometer
- Proper backpressure via configurable thread pools

---

## DB Stored Procedure Mapping (22 functions -> JdbcTemplate)

| Zig `db_sync` call | Postgres function | Java approach |
|---|---|---|
| `pendingLedgerCount()` | `coordinator.pending_ledger_count()` | `jdbc.queryForObject("...")` |
| `recordScanRequest()` | `coordinator.record_scan_request_batch()` | Batch insert via `jdbc.batchUpdate()` |
| `processIngestLedger()` | `coordinator.process_ingest_ledger()` | `jdbc.queryForObject("...")` |
| `getNextBatch()` | `coordinator.get_next_batch()` | `jdbc.queryForObject("...")` |
| `recoverStaleDispatchedBatches()` | `coordinator.recover_stale_dispatched_batches()` | `jdbc.queryForObject("...")` |
| `markBatchDispatchFailed()` | `coordinator.mark_batch_dispatch_failed()` | `jdbc.update("...")` |
| `releaseBatchDispatch()` | `coordinator.release_batch_dispatch()` | `jdbc.update("...")` |
| `generateShadowAlerts()` | `coordinator.generate_shadow_alerts()` | `jdbc.queryForObject("...")` |
| `processBatchResults()` | `coordinator.process_batch_results()` | `jdbc.update("...")` |
| `ensureCursor()` | `coordinator.ensure_cursor()` | `jdbc.queryForObject("...")` |
| Wireless 7 calls | 7 stored procedures | `jdbc.update("...")` |

---

## Redpanda Topic Mapping

| Zig method | Topic | Consumer group | Camel approach |
|---|---|---|---|
| `pullScanBatch()` | `sync.scan.request` | `zig-coordinator-scan` | `from("kafka:sync.scan.request?groupId=...")` |
| `pullResultBatch()` | `sync.oracle.result` | `zig-coordinator-result` | `from("kafka:sync.oracle.result?groupId=...")` |
| `publish(..., sync.oracle.load, ...)` | `sync.oracle.load` | - | `to("kafka:sync.oracle.load")` |
| `publish(..., audit.threat.shadow_device, ...)` | `audit.threat.shadow_device` | - | `to("kafka:audit.threat.shadow_device")` |
| Wireless 7 consumers | 7 different streams | 7 consumer groups | 7 separate `from("kafka:...")` routes |

Key change: **Camel's Kafka consumer replaces polling CLI calls**. Instead of polling the CLI every 250ms, Camel uses Kafka's consumer group semantics with auto-commit or manual offset management. This is more efficient and reliable.

The wireless handlers currently poll one message at a time - with Camel Kafka, they can use proper consumer groups with batch consumption.

---

## Implementation Order (Phases)

### Phase 1: Foundation (project skeleton, config, DB health)
1. Create Gradle project with Spring Boot + Camel + JDBC + Kafka dependencies
2. `CoordinatorProperties.java` - all ~40 env vars as `@ConfigurationProperties`
3. `DatabaseService.java` - `JdbcTemplate` wrapper with all stored procedure calls
4. `HealthCheckService.java` - DB connectivity + Redpanda connectivity (replaces `healthcheck` mode)
5. `application.yaml` - datasource, Kafka, and coordinator settings

### Phase 2: Core Sync Loop
6. `ScanRequestRoute` + `ScanRecordProcessor` - pull from `sync.scan.request`, record in DB
7. `IngestProcessor` - call `process_ingest_ledger`
8. `StaleBatchRecoveryProcessor`
9. `BatchDispatchRoute` - `get_next_batch` -> publish to `sync.oracle.load`
10. `OracleResultRoute` - consume `sync.oracle.result`, call `process_batch_results`
11. `ShadowAuditProcessor` - rate-limited timer route

### Phase 3: Wireless Operations
12. 7 wireless handler routes (backlog save/list/synced/prune, MAC lookup, networks, probe flush)
13. Reply topic publishing where applicable

### Phase 4: Resilience + Observability
14. Graceful shutdown (Spring context close -> Camel shutdown)
15. Backpressure (same algorithm: inflight watermark based on `ingest_batch_size * 4`)
16. Adaptive pull window (shrink fetch when DB falls behind)
17. Heartbeat logging via Micrometer + actuator
18. Prometheus metrics export

### Phase 5: Deployment
19. `Dockerfile` - `azul/zulu-openjdk-alpine:21-jre`-based slim image
20. Update `docker-compose.yaml` - replace `zig-coordinator` services with `java-coordinator`
21. Update `helm/ssl-proxy/` - new deployment template
22. Update `configmap.yaml` - Java service env vars

---

## Key Differences from Zig (Improvements)

| Concern | Zig | Java/Spring/Camel |
|---|---|---|
| DB access | `psql` subprocess (stringly-typed) | Native JDBC with `JdbcTemplate` |
| Redpanda access | `redpanda` CLI subprocess per message | Native Kafka protocol with consumer groups |
| Healthcheck | CLI subcommand calling same subprocesses | Spring Actuator + custom health indicators |
| Graceful shutdown | Signal handler with 100ms polling | Spring context close + Camel lifecycle hooks |
| Config | Manual `envOrDefault()` parsing | `@ConfigurationProperties` with validation |
| Logging | Custom `logging.zig` | SLF4J + Logback (structured JSON possible) |
| Error handling | `errdefer` + manual logging | Camel error handlers, DLQ, redelivery policies |
| Metrics | None | Micrometer (Prometheus, JMX) |
| Backpressure | Manual DB query + `inflight` atomic | Camel throttler + thread pool config |
| Scalability | Multi-instance via `sync_cursors` table | Same (cursor per stream is already idempotent) |
| Testing | Zig unit tests (limited) | JUnit 5 + Spring test + Camel test support + Testcontainers |

---

## Risks and Mitigations

1. **Payload resolution**: Currently reads from outbox files on disk (`outbox://` prefix). Camel file component can handle this natively.
2. **Inline payload decoding**: base64url -> JSON validation. Straightforward Java implementation.
3. **Redpanda consumer offsets**: Need to start with manual offset management (`auto.offset.reset=earliest` or commit existing groups to avoid reprocessing).
4. **Cursor continuity**: The `sync_cursors` table is the source of truth; as long as we read from Kafka from where the cursor indicates, no messages are lost.
5. **Migration cutover**: Run Java coordinator alongside Zig on a subset of streams initially, then switch DNS/service discovery.

---

## Estimated Timeline

| Phase | Files | Effort (relative) |
|---|---|---|
| P1: Foundation | ~15 files | 2 days |
| P2: Core loop | ~10 files | 3 days |
| P3: Wireless | ~7 files | 2 days |
| P4: Resilience | ~5 files | 1 day |
| P5: Deployment | ~4 files | 1 day |
| **Total** | **~40 files** | **~9 days** |

---

## Migration Notes

The Java coordinator implementation uses the `com.sslproxy.coordinator` package
and independent Camel Kafka consumer routes for the wireless handlers. Keep
those consumer groups independent unless a future migration explicitly needs
strict serial parity with the legacy loop.
