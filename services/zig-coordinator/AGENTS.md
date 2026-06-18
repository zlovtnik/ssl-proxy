# AGENTS.md

## Scope
This file governs `/Users/rcs/git/ssl-proxy/services/zig-coordinator`.

## Project Shape
- The directory name is legacy. The service is Java 21 with Spring Boot 3,
  Apache Camel, JDBC, Micrometer, and Gradle Kotlin build files.
- `src/main/java/com/sslproxy/coordinator/config/` owns env-backed Spring
  properties, schema initialization, data sources, and startup checks.
- `route/` owns Camel route boundaries for scan, Oracle load/result, retention,
  and wireless request/reply flows.
- `processor/` and `service/` own batch dispatch, payload resolution, cursoring,
  backpressure, metrics, and database calls.
- `oracle/` owns Oracle wallet preflight, JDBC connection setup, transforms,
  checksums, error classification, and sink behavior.
- `src/test/java/` includes unit tests and SQL contract tests that read the root
  `sql/` files directly.

## Guardrails
- Keep this service the only Oracle owner. Oracle wallet, TNS, JDBC, and sink
  logic should not migrate into Rust proxy, sensor, search, or shared crates.
- Preserve the locked topics and consumer roles for `sync.scan.request`,
  `sync.oracle.load`, and `sync.oracle.result`.
- Keep coordinator operations retry-safe and idempotent: cursor advancement,
  batch leasing, dispatch release/failure, backlog handling, and result
  processing must tolerate duplicate delivery.
- Keep SQL function call signatures aligned with root `sql/functions/*` and
  `sql/postgres.source.sql`; update contract tests when signatures change.
- Keep record-style property accessors and Java 21 assumptions already used in
  the codebase.
- Do not commit Gradle caches, IDE state, `.omx/` output, or generated local
  runtime files.
- Do not log Oracle credentials, wallet material, MinIO secrets, raw payloads,
  or unsanitized identifiers.

## Commands
- Run tests from this directory: `./gradlew test`.
- Build: `./gradlew build`.
- Root broad test target also runs coordinator tests: `make test`.

## Verification
- Run focused Gradle tests for changed packages when practical, then
  `./gradlew test` for coordinator-wide changes.
- Run SQL contract tests when changing `DatabaseService`, processors, routes, or
  root SQL functions the coordinator calls.
- For Oracle sink changes, cover wallet/preflight failure modes, retry
  classification, transform output, and disabled-sink behavior.
