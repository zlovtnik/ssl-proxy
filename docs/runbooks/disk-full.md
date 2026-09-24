# Disk Full

Use this runbook when a storage alert fires or `df` approaches the budget.
Work read-only first, then apply one bounded change at a time and capture a
before/after snapshot with `ops/disk/audit.sh`. The phase map, targets and
gates are in the [storage workmap](../../ops/disk/README.md); PostgreSQL
volume procedures stay in
[platform storage and PostgreSQL rotation](../platform-storage-operations.md).

## First response

```bash
df -h /
bash ops/disk/audit.sh pre-incident
```

Read the snapshot top down: host filesystem, container storage, PVC usage,
Redpanda topic sizes, consumer lag and PostgreSQL relation sizes. Choose the
matching section below rather than deleting the first large thing you find.

## Host filesystem pressure

`FilesystemFreeSpaceWarning` fires at 75% usage and
`FilesystemFreeSpaceCritical` at 85% for the root filesystem and every PVC.

1. Identify the largest mount from the audit snapshot and the Infrastructure
   Capacity dashboard.
2. Reclaim from the subsystem that owns it: Redpanda topics, CI volumes,
   PostgreSQL, or Kubernetes logs.
3. Do not raise thresholds to silence the alert. Thresholds are reviewed in
   `cyber-stack/base/telemetry/config/prometheus/rules/infrastructure.rules.yml`.

## Redpanda topic oversize

`RedpandaTopicLogBytesHigh` fires above 63 GiB for `wireless.audit`;
`RedpandaTopicLogBytesCritical` fires above 90 GiB, which is the point where
the Redpanda data volume and the node fill.

```bash
bash ops/redpanda/check-topics.sh
python3 ops/redpanda/reconcile_topics.py plan
kubectl -n prod-ssl-proxy exec ssl-proxy-redpanda-0 -- rpk cluster logdirs describe --aggregate-into topic
```

Retention is declared in the tracked topics manifest and reconciled by Argo.
Change `cyber-stack/base/platform-config/configmap.yaml` and local
`docker/redpanda/topics.manifest`, then re-run `make topics-check`. Setting
`retention.ms` on `wireless.audit` below the current record age purges data on
the next reconciliation, so confirm consumer lag before merging.

The cluster defaults set by the init job bound topics that the manifest does
not manage. To inspect them:

```bash
kubectl -n prod-ssl-proxy exec ssl-proxy-redpanda-0 -- rpk cluster config list | grep -E 'retention|log_segment'
```

## CI registry volume

`RegistryVolumeHigh` fires above 15 GiB.

```bash
ops/ci/registry-gc.sh
```

The plan mode prints the volume size and the manifest retention proposal.
Manifest deletion is a reviewed manual step: the planner protects Git-pinned
and live digests, and a valid release may be referenced only by digest. After
the plan is approved, garbage collection reclaims blobs whose manifests are
already gone:

```bash
REGISTRY_GC_CONFIRM=GC-REGISTRY-BLOBS ops/ci/registry-gc.sh --apply
```

Garbage collection stops the registry for its duration, so run it in a
maintenance window. See the
[registry retention procedure](../local-registry-workflow.md#retention-and-garbage-collection).

## Jenkins Docker-in-Docker volume

`JenkinsDinDVolumeHigh` fires above 30 GiB.

```bash
ops/ci/dind-prune.sh
ops/ci/dind-prune.sh --apply
```

Pruning drops build cache older than the configured age and unused images;
containers, volumes and the Jenkins home directory are untouched. The next
build is slower, nothing else changes. The ceiling is mirrored in the
`buildx-ready` Make task, which writes the buildkit cache limit for the HTTP
builder.

## PostgreSQL growth

`PostgresDatabaseSizeHigh` fires above 150 GiB and
`PostgresRelationSizeHigh` above 50 GiB for a single relation.

```bash
ops/sql/pg-size-report.sh
```

Order of operations:

1. Confirm retention is actually running. Octopus owns row retention through
   its event-retention processor and archives raw payloads to MinIO before
   dropping rows.
2. Read the report: live rows, dead tuples and index sizes. If a large share
   is dead tuples, a plain vacuum reclaims it.
3. Only then consider a rebuild. `ops/sql/pg-repack.sh` refuses to act without
   `--apply` and `--confirm REPACK-TABLE`, needs free space larger than the
   table, and reports the blocker if `pg_repack` is not installed in the
   platform image.
4. `VACUUM FULL` is the gated fallback: it takes an exclusive lock for the
   whole rewrite. Never run it against an ingestion table inside a write
   window.

The partitioning sketch for `sync_batches` and `sync_events` is a proposal
only; it is not wired into `sql/postgres/`.

## Storage metrics are stale

`StorageTextfileStale` means the host textfile collector has not published
for over two hours, so volume and topic size alerts cannot fire.

```bash
systemctl status ssl-proxy-pv-usage-textfile.timer
journalctl -u ssl-proxy-pv-usage-textfile.service -n 50
cat /var/lib/node_exporter/textfile_collector/ssl_proxy_storage.prom
```

Reinstall the collector and timer as described in the
[host storage metrics section](../platform-storage-operations.md#host-storage-metrics).
