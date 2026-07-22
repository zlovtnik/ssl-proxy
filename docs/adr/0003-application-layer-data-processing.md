# ADR-0003: Application-Layer Data Processing

## Status

Accepted

## Context

Distributing business logic between the database and the application creates
technical debt, hidden side effects, and debugging nightmares. The Scala
services (Octopus, Schema-Migrator) already use Cats Effect and FS2 for stream
processing, and all TiDB schemas are DDL-only (tables, indexes, views). This
ADR formalizes the existing practice and adds library standards for
code-review enforcement.

## Decision

### 1. The Rule

Zero business logic in the database. No custom stored procedures, functions,
or triggers in TiDB. All data processing, ETL pipelines, and complex database
operations must be engineered in the application layer.

TiDB is solely responsible for:
- Data persistence
- Distributed SQL querying
- Vector search operations

### 2. Library Standards

| Library | Version | Scope | Guidance |
|---------|---------|-------|----------|
| **Doobie** (`doobie-core`, `doobie-hikari`) | 1.0.0-RC10 | All Scala services | Mandatory for functional JDBC access. Use `sql` interpolator, `ConnectionIO`, and `Transactor`. |
| **Skunk** | n/a | n/a | Do not introduce. Doobie is established and proven in this codebase. |
| **Raw JDBC** (`java.sql.*`) | n/a | Performance-critical batch writes | Permitted only when Doobie overhead is measurable and batch throughput is a constraint. Document the exception in code comments. See `TidbTransactor` for the existing pattern. |
| **R2DBC** | 1.3.0 | Schema-migrator only | Keep scoped to migration tooling. Do not use for application-layer services. |
| **Go `database/sql`** | stdlib | Atheros Search | Go service uses standard library with `go-sql-driver/mysql`. This policy applies to Scala services; Go conventions are separate. |

### 3. Concurrency and Backpressure

FS2 paired with Cats Effect provides first-class support for stream processing
with built-in backpressure. Use these patterns:

- `parEvalMap(maxConcurrent = N)` for bounded concurrent processing
- `Semaphore[IO](poolSize)` for concurrency control on DB operations
- `Stream.awakeEvery` for periodic polling
- `Chunk` and `traverse` for batch processing
- `Resource.make(...)(...)` for lifecycle management of pools and connections

### 4. Idempotency Convention

Writes must use operation-specific idempotency keys to prevent duplicate effects
on at-least-once delivery. Where a natural unique key exists, enforce it with
explicit unique constraints or `ON DUPLICATE KEY UPDATE`. Immutable append-only
evidence (audit logs, ingestion records) should not be updated on conflict.
Durable TiDB deduplication records keyed by topic/partition/offset support
at-least-once delivery after the signed cutover offset.

### 5. Error Handling

Classify TiDB errors as retryable or permanent:

| Code | Meaning | Action |
|------|---------|--------|
| 1205 | Lock wait timeout | Retry with backoff |
| 1213 | Deadlock | Retry with backoff |
| 8028 | Metadata/schema-change transaction conflict | Retry with backoff |
| 9003 | TiKV server busy | Retry with backoff |
| 9007 | Write conflict | Retry with backoff |

Use jittered exponential backoff for retries (max 5 attempts, max 2 seconds).
See `TiDBTransactionRetry` for the implementation.

### 6. Vector Pipeline Integration

TiDB vector capabilities compose naturally with FS2 streams. The pattern:

1. Source: Stream rows from TiDB
2. Compute: Call embedding models or apply transformations
3. Sink: Stream vector inserts back to TiDB

All in a single, type-safe FS2 pipeline with backpressure.

## Consequences

- PRs introducing `CREATE PROCEDURE`, `CREATE FUNCTION`, or `CREATE TRIGGER`
  will be rejected.
- All Scala services use Doobie as the primary JDBC layer.
- Raw JDBC exceptions must be justified in code comments and code-reviewed.
- Retry logic follows the established `TidbErrorClass` and
  `TiDBTransactionRetry` patterns.
- The Go service (Atheros Search) is governed separately.

## Example

```scala
// Do not write DB triggers. Stream, process, and sink in FS2.
def processDatabaseRecords: Stream[IO, Unit] =
  dbClient.streamUnprocessedRecords()
    .parEvalMap(maxConcurrent = 10) { record =>
      transformRecord(record) // Cats Effect IO
    }
    .evalMap { transformed =>
      dbClient.updateRecord(transformed) // ON DUPLICATE KEY UPDATE
    }
```

## Follow-up

- Add lint rule or CI check to reject SQL files containing procedure/function
  definitions (outside schema-migrator external-target fixtures).
- Consider adding a `Skunk` entry to the rejected-dependency list in
  `AGENTS.md` if team consensus hardens on Doobie-only.
