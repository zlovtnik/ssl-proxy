# ADR 0001: Oracle Sink Vertical Slice

## Status
Superseded.

This ADR is retained for provenance. The current TiDB ownership and topic
semantics are defined in [System Architecture](../architecture.md). In
particular, PostgreSQL and Oracle are no longer runtime stores, and the
`sync.oracle.*` names are legacy compatibility labels for TiDB work.

## Historical decision

The following decision and consequences describe the superseded v1 design.

### Decision
- Oracle is a sink-only dependency in v1.
- The proxy does not talk to Oracle directly.
- Delivery is at-least-once with dedupe in Postgres.
- The coordinator advances a monotonic Postgres-backed work cursor.
- The proxy emits `sync.scan.request`.
- The coordinator owns `sync_jobs`, `sync_batches`, retries, and cursor advancement.
- The worker owns Oracle connectivity, per-batch commit, and `sync.oracle.result`.

### Consequences
- The Rust proxy no longer links the Oracle client or depends on wallet/TNS configuration.
- Postgres becomes the source of truth for cursors, retry state, and dedupe.
- Redpanda Redpanda is the only transport between the coordinator and worker.
- Oracle bulk-path optimizations stay out of v1 until the control-plane behavior is stable.
