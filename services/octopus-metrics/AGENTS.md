# Octopus Metrics

## Service-specific rules
- C++23, CMake, libpq, libcurl, hiredis, and simdjson. Pure data transformations
  live in `src/domain.cpp`; all external I/O lives in `src/adapters.cpp`.
- Preserve the snapshot v2 null/zero distinction, complete UTC hour windows,
  earliest-date peak ties, and original last-good measurement timestamps.
- Queue kinds remain coalesced across queued and active work. Publishers run
  on their own thread; store failures must not consume compute workers.
- Stop tokens and deadlines accompany every I/O call. A cancelled PostgreSQL
  operation discards its connection before the next scheduled attempt.
- C-library handles have one RAII owner. Borrowed views must not escape their
  result, parser, or transfer lifetime.
- The [metrics grant fixture](../../sql/postgres/octopus_core/grants/metrics_read_only.sql.tmpl)
  defines the two relation reads available to the metrics account.
- Redis Lua and S3 conditional writes enforce monotonic publication. Retain
  both fences when changing retries, replicas, or object paths.

## Verification
- Configure/build with CMake, then run CTest. Keep build trees outside source.
- Run `tests/integration_test.py --build <build-directory>` with temporary
  PostgreSQL, Redis, and MinIO Testcontainers for adapter changes.
- Exercise memory and thread sanitizers in separate build trees.
- Follow the performance measurement procedure in [README.md](README.md).
