# Production prerequisites

Production uses one platform-operated PostgreSQL 16/pgvector cluster with the
`sync` database. Its exact value-free server and secret-control-plane bootstrap
requirements are pinned in the [platform input contract](../../platform-input-contract.yaml).
The repository does not deploy the database server or Vault through Kubernetes.
Its external Wiretrap host definition and operational procedure are tracked in
the [PostgreSQL host guide](../../../docs/postgres-host.md).
The PostgreSQL container must provide at least 1 GiB of shared memory so the
parallel projection queries cannot exhaust Docker's 64 MiB default `/dev/shm`.

The [bootstrap slice](bootstrap/kustomization.yaml) creates input shells and
scoped RBAC in `prod-ssl-proxy`. The host-side
[platform-sync service](../../../services/platform-sync/README.md) fills
`ssl-proxy-prod-postgres-endpoint` with these non-secret keys from Vault:

- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DATABASE`
- `POSTGRES_SSL_MODE`
- `POSTGRES_SSL_SERVER_NAME`

The values must select PostgreSQL database `sync` and verified TLS. They remain
external prerequisites and are not committed here. The synchronizer writes
`platform-ready` only after every contract input passes validation and is
written. The data-plane preflight checks readiness, the contract hash and a
numeric last-success timestamp before database-dependent startup proceeds.

The same platform workflow provides the upstream PostgreSQL CA, the distinct
`pgbouncer-listener-tls` certificate bundle (`ca.crt`, `tls.crt`, `tls.key`),
PgBouncer user list, and
separate owner, Octopus, read-only metrics, Atheros Search, schema-migrator, and Keycloak
credentials documented in the platform input contract. No operator should
patch these Kubernetes objects interactively.

The schema executor and Keycloak use the direct endpoint. Octopus, Atheros
Search, and schema-migrator use the in-cluster PgBouncer service with
`sslmode=verify-full` and only the listener CA mounted. PgBouncer requires TLS
from clients and verifies its upstream PostgreSQL certificate with
`verify-full`; only PgBouncer mounts the listener certificate and private key.
The schema
executor must complete and record matching manifest checksums before the
database-dependent workloads become ready. PgBouncer renders its upstream from
all five endpoint ConfigMap keys and refuses to start unless the TLS mode is
`verify-full` and the certificate server name equals the connection host.

NetworkPolicies remain a release gate only when the installed CNI enforces them.
Before rollout completion, capture read-only evidence that Calico, Cilium, or
kube-router is ready on every node and run an approved enforcement probe. Do not
install or modify the CNI from this repository.

The committed Octopus render uses the
[`broker-drain` processor profile](patches/java-coordinator-broker-drain.yaml):
seven sync processors remain selected and Kafka consumers remain enabled;
derived projection and maintenance processors are omitted from that selection.
The [broker recovery patch](patches/octopus-broker-recovery.yaml) selects v2
consumer groups for scan, load, result, heartbeat and audit processing. This
describes desired configuration, not evidence that backlog recovery is complete.
See the [Octopus README](../../../services/octopus/README.md) for processor
and consumer-gate behavior.

The [DQ preparation patch](patches/dq-preparation.yaml) pins the manager and
dedup worker but sets both to zero replicas pending a separate acceptance and
activation change. The production Redpanda maintenance configuration is
scan-only and dry-run; see the
[maintenance runbook](../../../docs/runbooks/redpanda-maintenance.md).

The bundled Redpanda StatefulSet is a single broker and
the topic manifest uses replication factor one. This is not a highly available
broker topology, but it is an accepted availability tradeoff for the current
Wiretrap deployment and does not disable processing. New consumer groups start
at the earliest retained record; existing groups resume from committed Kafka
offsets. Octopus uses the replication setting only when creating a missing
topic and does not alter an existing topic's replica assignment.

## Verification

Run from the repository root:

```bash
make gitops-check
make docs-check
```

The [GitOps guide](../../README.md) covers publication, reviewed digest
promotion, Git reverts and read-only health checks. Passing the static checks
does not establish live Application health or platform-input readiness.
