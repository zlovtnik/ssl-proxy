# Redpanda daily maintenance runbook

The Job plans a per-partition target as the lesser of the oldest retained-time
cutoff and every non-ignored consumer-group commit. It plans every selected
topic before it applies any trim. Any malformed output, missing commit, failed
PostgreSQL gate, or breaker violation fails the Job and applies no trims.

> Trim is irreversible. If a consumer group is added, it must exist before its
> first run or it can lose unread data.

## Current readiness

`sync.scan.request` requires `octopus-scan-v2` in production and
`octopus-scan-v1` in the base. `wireless.audit` requires
`wireless-audit-projection-v2` in production and remains excluded from cleanup
until a projector consumes that Kafka topic, commits offsets,
and writes complete offset-linked rows to
`octopus_core.ingestion_evidence`. Aggregate row coverage is not proof that a
specific Kafka prefix was persisted.

The base ships with `DRY_RUN=true`. The production
[data-plane slice](../../cyber-stack/matrix/prod/data-plane/kustomization.yaml)
pins the maintenance image and selects only `sync.scan.request` with
`DRY_RUN=true` during broker-history recovery. Its
[topic configuration](../../cyber-stack/matrix/prod/config/redpanda-maint-topics.tsv)
requires the recovering scan group before trimming can resume. Its
[scan-only patch](../../cyber-stack/matrix/prod/patches/redpanda-maint-scan-only.yaml)
removes unused PostgreSQL credentials and TLS mounts. The daily schedule is
06:30 America/New_York.

## October 2026 broker-history recovery

The broker reused scan and load coordinates already recorded in PostgreSQL
on October 12. The [production recovery patch](../../cyber-stack/matrix/prod/patches/octopus-broker-recovery.yaml)
selects `octopus-scan-v2`, `octopus-load-v2`, and `octopus-result-v2`, plus
`wireless-sensor-heartbeat-postgres-v2` and `wireless-audit-projection-v2`.
Each new group starts at the earliest retained offset. Group-scoped evidence
is recorded separately; existing event, job, batch, and outbox deduplication
and dispatch authorization remain in effect. Keep the v2 identities after
recovery; reverting to v1 restores the conflicting evidence namespace.

The wireless recovery needs new Octopus and schema-executor images built
from the group-scoped receipt migration. Promote both reviewed digests
together; the data-plane executor applies the new schema before app-stack
starts the new coordinator. The new receipt table preserves the original
wireless receipts and continues deduplicating effects by payload hash.

After Argo CD reconciles the change, verify all five v2 groups have committed
offsets for every partition and their lag drains. Check Octopus logs for new
`changed after ingestion` errors and inspect any newly parked records. Replay
of retained source topics recovers the conflicting records already parked in
DLQs; records no longer retained in the source need a separate reviewed DLQ
replay. Preserve the old evidence and DLQs for audit.

Cleanup stays in dry-run mode during recovery. Restore `DRY_RUN=false` only
through a reviewed production change after the groups catch up and the trim
plan is verified. Do not delete evidence or reset existing group offsets to
hide coordinate conflicts.

Before enabling `wireless.audit`, remove the scan-only patch and provision the
platform Secret `redpanda-maint-pg` with `username` and `password` keys. Provision its role
outside Git with only `CONNECT`, schema `USAGE`, and `SELECT` on
`octopus_core.wireless_frames` and `octopus_core.ingestion_evidence`.

## Dry-run

After Argo CD has reconciled the reviewed desired state, create a one-off Job
from the CronJob using the normal operational access path and inspect the
`clean` container logs. The table must show partition, LSO, HWM, cutoff,
minimum commit and holder, and target. A missing or unparsable row is a failed
run, not an empty plan.

Run three days with all configured topics selected. For an isolated scan-topic
acceptance run, set `ACTIVE_TOPICS=sync.scan.request` through a reviewed prod
overlay. Do not mutate the CronJob interactively.

## No run or no success

Check the CronJob schedule, suspended state, recent Jobs, pod scheduling, and
Pushgateway reachability. `backoffLimit: 0` is intentional. Fix desired state
through Git; do not rerun a failed destructive Job without reviewing its plan.

## Blocked status

Status codes are: 0 planned/complete, 1 nothing to trim, 10 missing consumer
commit, 11 parse error, 12 stale PostgreSQL projection, 13 incomplete exact
offset evidence, 14 data older than the PostgreSQL floor, 15 trim breaker, 16
consume error, and 17 trim command failure or post-trim LSO verification
failure.

Never raise `PG_MAX_STALE_MIN` to bypass status 12. Never add a group to
`IGNORE_GROUPS` unless its owner confirms it is permanently dead. Inspect any
breaker as a possible offset or parser error before changing the threshold.

## Promotion

Promote `sync.scan.request` first by selecting only that topic and changing
`DRY_RUN=false` in the reviewed production overlay. Confirm its log-start
offsets move and shared-disk free space rises.

Promote `wireless.audit` only after its projector is current, exact ingestion
evidence is complete for every partition, and the MinIO raw archive has been
independently verified for everything before the PostgreSQL floor. Set
`ALLOW_UNPROJECTED_BEFORE_EPOCH` to that floor for one reviewed run, then remove
it. The script accepts the override only within 60 seconds of the queried
PostgreSQL floor. Keep `MAX_TRIM_FRACTION=0.90`.

## Failed Job

Open the Redpanda Cluster dashboard and the pinned Redpanda maintenance panel
in Logs Explorer. Record the status code, holder, target, and error. Because
planning is two phase, a planning failure means no topic was trimmed. A status
17 can be partial at the broker level; inspect every partition's current LSO
before retrying.
