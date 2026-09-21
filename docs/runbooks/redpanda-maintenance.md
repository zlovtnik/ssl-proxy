# Redpanda daily maintenance runbook

The Job plans a per-partition target as the lesser of the oldest retained-time
cutoff and every non-ignored consumer-group commit. It plans every selected
topic before it applies any trim. Any malformed output, missing commit, failed
PostgreSQL gate, or breaker violation fails the Job and applies no trims.

> Trim is irreversible. If a consumer group is added, it must exist before its
> first run or it can lose unread data.

## Current readiness

`sync.scan.request` requires `octopus-scan-v1`. `wireless.audit` intentionally
requires `wireless-audit-postgres-v1`, which does not exist yet. The latter must
remain blocked until a projector consumes that Kafka topic, commits offsets,
and writes complete offset-linked rows to
`octopus_core.ingestion_evidence`. Aggregate row coverage is not proof that a
specific Kafka prefix was persisted.

The base ships with `DRY_RUN=true`. The workload is not added to a production
slice until the first `redpanda-maint` image has been built by Jenkins and its
reviewed digest is pinned. The required platform Secret is
`redpanda-maint-pg` with `username` and `password` keys. Provision its role
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
