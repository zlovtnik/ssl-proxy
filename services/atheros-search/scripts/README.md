# Atheros Search operational commands

Repository-level build and test entry points:

```bash
make atheros-search-proto
make atheros-search-build
make atheros-search-test
```

Embedding-job repair is implemented by `cmd/embedding-job-repair`:

```bash
go run ./cmd/embedding-job-repair -action=status
go run ./cmd/embedding-job-repair -action=reset-stale -stale-minutes=60
go run ./cmd/embedding-job-repair -action=retry-failed
go run ./cmd/embedding-job-repair -action=cleanup-dlq -dlq-evict-hours=168
```

Run repair commands with the same TiDB DSN, CA and server-name verification as
the service. Start with `status`, capture evidence and confirm the exact
affected jobs before a mutation. The canonical service behavior and worker
configuration are in the [Atheros Search README](../README.md).
