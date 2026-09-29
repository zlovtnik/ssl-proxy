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

## Host path volume pressure

`HostPathVolumeHigh` fires when a k3s local-path volume passes 85% of its
declared capacity. These volumes are bind mounts on the host filesystem, not
separate filesystems, so the measurement comes from the host textfile collector
rather than from kubelet. Reclaim from the subsystem that owns the volume: Loki
for the log volume, MinIO for archived payloads, Redpanda for the topic volume.
The per-volume budgets are in the [storage workmap](../../ops/disk/README.md).

```bash
kubectl -n prod-ssl-proxy get pvc
cat /var/lib/node_exporter/textfile_collector/ssl_proxy_storage.prom | grep k3s_pvc
```

## Storage metrics are missing

`StorageMetricsMissing` is critical and means at least one of
`docker_volume_used_bytes`, `ssl_proxy_storage_textfile_timestamp_seconds` or
`ssl_proxy_postgres_database_bytes` has **no series at all**. Every size alert
that reads those metrics is silently unevaluated while this is true, so treat it
as "storage is currently unmonitored" rather than as a metrics problem.

The usual cause is that the host collector was never installed. A missing
producer and a healthy reading of zero look identical to an alert rule, which is
why this check exists.

```bash
systemctl status ssl-proxy-pv-usage-textfile.timer
systemctl list-timers | grep ssl-proxy
journalctl -u ssl-proxy-pv-usage-textfile.service -n 50
ls -la /var/lib/node_exporter/textfile_collector/
```

Install it with the procedure in
[host storage metrics](../platform-storage-operations.md#host-storage-metrics).
The unit requires root because the k3s and Docker volume roots are not readable
by unprivileged processes. If `/var/lib/node_exporter/textfile_collector/` is
empty or holds no `ssl_proxy_storage.prom`, the timer is not installed.

## Node disk pressure and eviction

`NodeDiskPressure` is the condition that takes a cluster down, and
`FilesystemShrinkingFast` is its early warning. A size threshold only fires once
the disk is already full, which on this node was too late: kubelet had begun
evicting pods.

**The symptom people report is a broken Argo CD command**, not a storage error:

```
argocd --core app get ssl-proxy-prod-app-stack --show-operation
{"level":"fatal","msg":"cannot find ready pod with selector:
 [app.kubernetes.io/name=argocd-repo-server]"}
```

`--show-operation` is one of the few read commands that needs a live Ready
repo-server pod to render manifests. Under disk pressure kubelet evicts it and
the command fails even though the application is healthy. Do not debug Argo CD
first. Triage in this order:

```bash
kubectl get nodes -o wide                 # DiskPressure column
kubectl get node wiretrap -o jsonpath='{.status.conditions[?(@.type=="DiskPressure")]}{"\n"}'
kubectl get events -A --field-selector type=Warning | grep -E "Evicted|EvictionThreshold|FreeDiskSpace"
kubectl get pods -A --field-selector status.phase=Failed
```

`EvictionThresholdMet` on the node means kubelet is reclaiming ephemeral storage
by killing pods, and `FreeDiskSpaceFailed` means image garbage collection could
not free enough. Both point at the host filesystem, not at any one workload.

**Find the writer before reclaiming anything.** A size-based view hides a
sustained writer. Ask what grew:

```bash
# Which monitored host path is growing, without leaving the cluster
kubectl -n prod-ssl-proxy exec deploy/ssl-proxy-telemetry-node-exporter -- \
  sh -c 'grep host_path /var/lib/node_exporter/textfile_collector/ssl_proxy_storage.prom'

# Rate over the incident window, per host path
# ssl_proxy_host_path_used_bytes{class="host_path"}
```

`FilesystemShrinkingFast` fires at 50 GiB lost per hour. The recorded incident
lost about 374 GiB in eighty minutes and then released it, so it fired roughly
an hour before `NodeDiskPressure` would have.

Note that `du` run unprivileged under-reports this host badly: `/var/lib/docker`
and `/var/lib/rancher/k3s/agent` are root-only, so an unprivileged snapshot
reports roughly 31 GiB for a filesystem with around 493 GiB used. Attribute
sizes with the textfile collector or with `ops/disk/audit.sh` as root, not with
an unprivileged `du`.

Recovery is not self-evident. Disk pressure clears on the next kubelet disk
manager poll, which can be several minutes after the space returns, and evicted
pods are not automatically replaced in a useful timeframe. Confirm the workloads
are actually back before declaring the incident over:

```bash
kubectl get deploy -n argocd
kubectl get pods -A --field-selector status.phase!=Running | head
```

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
