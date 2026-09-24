# Wiretrap Storage Workmap

Baseline audit: 2026-09-24 on `wiretrap`, 572G of 915G used (66%). This
directory holds the read-only audit tooling, the guarded reclaim scripts and
the phase map for Redpanda, PostgreSQL, the CI registry and the Jenkins
Docker-in-Docker engine. Nothing here runs by itself: a script changes state
only with `--apply` plus its confirmation token.

## Targets

| Subsystem | Target | Owner |
| --- | --- | --- |
| Redpanda data PVC | <= 90G | topic caps in the topics manifest |
| `wireless.audit` topic | <= 63G (7 days) plus byte cap | topics manifest |
| PostgreSQL `ssl-proxy-platform-postgres-data` | retention first, then reclaim | Octopus retention plus `ops/sql` |
| Jenkins Docker-in-Docker volume | <= 30G | build cache prune |
| CI registry volume | <= 15G | retention plan, then garbage collection |
| Host filesystem | under 50%, alerts at 75% and 85% | node exporter textfile collector |

## Phases and gates

1. **Phase 0 - measure.** Run `ops/disk/audit.sh` and record a snapshot before
   and after every later phase. Confirm consumer lag, `rpk` report output and
   PostgreSQL sizes before any truncation.
2. **Phase 1 - Redpanda.** Caps live in
   `cyber-stack/base/platform-config/configmap.yaml` (production) and
   `docker/redpanda/topics.manifest` (local development). Review them with
   `bash ops/redpanda/check-topics.sh` and compare a cluster with
   `python3 ops/redpanda/reconcile_topics.py plan`.
   **Irreversible:** the `wireless.audit` cap purges records older than seven
   days on the next Argo reconciliation. Merge only after the Phase 0 lag check.
3. **Phase 2 - PostgreSQL.** Read-only first: `ops/sql/pg-size-report.sh`.
   Retention is an Octopus decision (`SYNC_EVENT_ROW_RETENTION_DAYS`,
   `WIRELESS_RAW_PAYLOAD_HOT_DAYS`); bloat reclaim is gated through
   `ops/sql/pg-repack.sh`, which refuses `--apply` without a confirm token.
   The partitioning sketch is `ops/sql/partition-sync-tables.proposed.sql`
   and is not wired into `sql/postgres/`.
4. **Phase 3 - registry.** `ops/ci/registry-gc.sh` reports sizes and the
   manifest retention plan; garbage collection needs `--apply` and
   `REGISTRY_GC_CONFIRM=GC-REGISTRY-BLOBS`. Manifest deletion stays a reviewed
   manual step.
5. **Phase 4 - Docker-in-Docker.** `ops/ci/dind-prune.sh` drops build cache and
   unused images only. Rollback: none needed, the next build repopulates the
   cache.
6. **Phase 5 - guardrails.** Alerts live in
   `cyber-stack/base/telemetry/config/prometheus/rules/storage.alerts.yml`;
   host metrics come from `scripts/pv-usage-textfile.sh`; operations are in
   the [disk full runbook](../../docs/runbooks/disk-full.md).

## Scripts

| Script | Default | Applies when |
| --- | --- | --- |
| `ops/disk/audit.sh` | read-only snapshot | never |
| `ops/redpanda/check-topics.sh` | static manifest check | never |
| `ops/redpanda/reconcile_topics.py` | `plan` | `apply --confirm APPLY-TOPIC-CONFIG` |
| `ops/sql/pg-size-report.sh` | read-only report | never |
| `ops/sql/pg-repack.sh` | plan | `--apply --confirm REPACK-TABLE` |
| `ops/ci/registry-gc.sh` | plan | `--apply` with the registry token |
| `ops/ci/dind-prune.sh` | report | `--apply` |

Snapshots and CSV evidence are written to `ops/disk/snapshots/` and are
ignored by Git; attach them to the change review instead of committing them.

The audit resolves Kubernetes access from `KUBECONFIG`, then the root-readable
`/etc/rancher/k3s/k3s.yaml`, then the ambient kubectl config, and queries the
live namespace `prod-ssl-proxy` (`REDPANDA_NAMESPACE` overrides it). `df`
omits overlay/tmpfs/shm rows and says how many it dropped. PostgreSQL sections
export the password inside the container from its own secret file, so stdin
stays reserved for the report and no credential reaches the host.

## Weekly timers

Install as root on `wiretrap` after reviewing the scripts:

```bash
install -m 0755 ops/disk/audit.sh /usr/local/sbin/ssl-proxy-disk-audit
install -m 0755 ops/ci/registry-gc.sh /usr/local/sbin/ssl-proxy-registry-gc
install -m 0755 ops/ci/dind-prune.sh /usr/local/sbin/ssl-proxy-dind-prune
install -m 0644 scripts/systemd/ssl-proxy-disk-audit.* /etc/systemd/system/
install -m 0644 scripts/systemd/ssl-proxy-registry-gc.* /etc/systemd/system/
install -m 0644 scripts/systemd/ssl-proxy-dind-prune.* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ssl-proxy-disk-audit.timer ssl-proxy-registry-gc.timer ssl-proxy-dind-prune.timer
```

The audit timer always runs read-only. The registry timer reports the plan
until `/etc/default/ssl-proxy-storage` sets `REGISTRY_GC_MODE=--apply` and
`REGISTRY_GC_CONFIRM=GC-REGISTRY-BLOBS`; the Docker-in-Docker timer prunes by
default.
