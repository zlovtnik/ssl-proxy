# Operator Runbook

This runbook covers the current external-TiDB runtime. Historical PostgreSQL,
MongoDB, embedded Keycloak, local mock-TiDB, and vector-worker procedures have
been retired. Use Git history if an old-release incident requires them; do not
apply them to the current runtime.

The authoritative fresh-start sequence and evidence requirements are in
[Fresh TiDB Runtime Cutover](tidb-runtime-cutover.md).

## Safety boundary

Repository checks, Helm renders, dry runs, and local tests are safe preparation.
Provisioning accounts, changing Redpanda consumer offsets, upgrading a live
release, pruning resources, and deleting the old database host path require the
approved change window and named operator approval.

The three deployment modes are:

| Mode | New clients | New consumers | Legacy compatibility |
|---|---|---|---|
| `stage` | Deployed for version/schema/TLS readiness | Disabled | Active |
| `activate` | Ready Services receive traffic | Enabled at signed offsets | Present but quiesced |
| `prune` | Active | Active | Absent |

Never jump from `stage` to `prune`.

## External prerequisites

Before rendering an activation release, supply:

- an external TiDB v8.5+ endpoint with TiFlash capacity;
- `octopus_core`, `atheros_search`, and
  `schema_migrator` databases;
- one dedicated least-privilege runtime account per database plus a separate
  DDL/provisioning account;
- TLS CA/server-name configuration and account Secrets;
- a fresh external Keycloak realm and clients (no realm/user/client import);
- the signed cutover artifact, detached signature, and pinned Ed25519 public
  key for the exact Redpanda cluster.

The database grants are documented as templates under each
`sql/tidb/<domain>/grants/` directory. Applications verify schemas; only the
schema executor applies DDL.

## Repository qualification

Run the deterministic policy and evidence checks:

```bash
make runtime-datastore-policy
make tidb-schema-contract
make cutover-evidence-test
helm lint helm/ssl-proxy
```

Then run the client suites:

```bash
cd services/octopus && sbt test
cd ../../services/atheros-search && go test ./...
cd ../../apps/schema-migrator && sbt test
```

Unit tests cannot qualify TiFlash/HNSW, TLS identity, transaction conflicts, or
consumer offsets. Record those results against the exact external environment.

## Schema provisioning

Use the repository schema executor in verify/dry-run mode first. It validates
the ordered manifests and checksums for all four domains. The Atheros Search
post-TiFlash phase is separate: it sets replicas, proves all four vector tables
report available, and only then applies the four cosine HNSW indexes.

Runtime accounts must not have DDL privileges. After apply, run executor verify
with each runtime identity and capture the manifest/version/readiness output.

## Stage

1. Render the `stage` inventory and confirm no Service selector moves.
2. Deploy new images with Octopus processors and consumers disabled.
3. Prove TiDB v8.5+, TLS identity, database/account ownership, canonical
   manifest checksums, TiFlash availability, Redis degradation behavior, and a
   token from the fresh Keycloak client.
4. Confirm legacy writers remain the only authoritative writers.

Abort if any client accepts loopback, a root account, the wrong database, an
unverified TLS connection, or a mismatched schema checksum.

## Activate

1. Quiesce legacy PostgreSQL-backed Rails/Go/coordinator writers while
   Redpanda producers continue.
2. Capture every new consumer-group/topic/partition next offset, canonicalize
   the artifact, and sign it offline.
3. Review the generated `rpk group seek` plan. Apply it only with the exact
   signed SHA-256 and confirmed cluster identity.
4. Enable Octopus processors/consumers and wait for durable readiness.
5. Switch Rails and Atheros Search Services only after their schema and smoke
   checks pass. Enable schema-migrator against its TiDB control database.

Commands and artifact shapes are in
[Signed offset artifacts](tidb-runtime-cutover.md#signed-offset-artifacts).

## Thirty-minute observation

Capture evidence for at least 30 clean minutes:

- no application PostgreSQL or MongoDB connections;
- no consumed offsets below the signed cutoff;
- no unexplained gap or duplicate in the bounded ingestion ledger;
- no `retrying` or `parked` record at audit end;
- stable/growing-free consumer lag, lease backlog, and outbox backlog;
- successful vector queries with correct cosine ordering and bounded filtering;
- Redis loss affects cache/cable delivery only and loses no durable records;
- Rails routes/channels, Atheros Search HTTP/gRPC/NDJSON, and schema-migrator
  public APIs remain compatible.

Sign the exclusive `audit_end` offsets and run the coverage command before
accepting the observation window.

## Prune and irreversible cleanup

Apply the atomic `prune` revision only after observation acceptance. Confirm
the rendered inventory has no PostgreSQL/MongoDB workload, Service, PVC,
Secret, ConfigMap, NetworkPolicy, exporter, scrape, alert, dashboard, or legacy
worker object. Delete orphaned failed-revision resources only by exact name and
release labels.

The repository intentionally does not automate the destructive host deletion.
During the approved window, an operator must:

1. Resolve the exact expected path
   `/var/lib/docker/volumes/ssl-proxy_postgres-data/_data` on the intended host.
2. Prove no process, mount, container, or Kubernetes object uses it.
3. Reconfirm the accepted audit evidence, successful `prune` revision, host,
   path, and irreversible-deletion approval.
4. Delete that exact directory with the approved host procedure and verify it
   is absent.

Do not broaden the target with variables, globs, parent directories, or a
recursive workspace/volume-root command.

## Abort and recovery

Abort activation for a signature/checksum/cluster mismatch, pre-cutoff replay,
schema drift, TLS downgrade, growing lag, stuck leases/outbox, vector failure,
public contract regression, or unexpected retired-datastore connection.

Before TiDB-only writes begin, restore the staged legacy release. After
TiDB-only writes begin, do not copy records back to PostgreSQL and do not replay
old history; stop new consumers, preserve signed evidence, and diagnose forward.

## WireGuard and proxy operations

Database migration does not change the network-path controls:

```bash
make dependency-boundaries
make diagnose PROFILE_MODE=linux-shim SERVER_IP=<server> CLIENT_IP=<client>
make k8s-status KUBE_NAMESPACE=default
```

Keep admin endpoints host-local, protect secrets with the existing rotator,
and preserve the locked Redpanda topic payload contracts.

## Single-node Kubernetes dev stack

The `helm/ssl-proxy/values-k8s.yaml` profile is the LAN development deployment
driven by `make up-ready`. It differs from the external-IdP cutover shape in
one way: the schema-migrator subchart deploys an in-cluster Keycloak (realm
`middleware`, imported from the chart ConfigMap) for the Schema Migrator UI.
This is a development convenience, not the production identity model.

Keycloak owns and migrates its own TiDB database. Provision its account the
same way as the application accounts:

```bash
k8s/tidb/bootstrap-runtime-secrets.sh  # fresh-cluster credentials only
k8s/tidb/generate-tls-secrets.sh       # TLS-only rotation; preserves credentials
kubectl apply -f k8s/tidb/init-job.yaml  # creates the keycloak database/user/grants
```

During `make up-ready` the Kubernetes flow now also:

- warns on unhealthy cluster nodes in preflight (NotReady, memory/disk/PID
  pressure, cordoned) without blocking the deploy;
- schedules the Atheros sensor DaemonSet on every eligible node without
  requiring a `wiretrap.io/sensor` label;
- reuses the existing valid TiDB CA/server certificate pair by default. It
  validates the key match, CA signature, service DNS SANs, and a 30-day
  renewal window. Set `UP_READY_ROTATE_TIDB_TLS=true` only for an intentional
  rotation; an existing deployment is restarted and verified in TiDB-first
  order, with the previous Secret pair restored if rollout fails;
- after `helm upgrade`, explicitly runs `kubectl rollout restart` and waits on
  `rollout status` for every release Deployment and DaemonSet (StatefulSets
  such as redpanda/minio are intentionally left to the rollout-revision
  annotation);
- verifies the coordinator (`/actuator/health`), schema-migrator backend
  (`/api/health`), and keycloak (`/health/ready`) endpoints before finishing.
  Override the per-workload wait with `UP_READY_ROLLOUT_STATUS_TIMEOUT`.

The split-release path never adopts resources implicitly. If the compatibility
umbrella owns the live stack, `make up-ready-stackctl` stops before TLS mutation
and prints the `ops stack cutover plan` command. Create and inspect that
UID-bound plan, drain traffic, then run guarded `cutover apply` with the plan
digest and exact context/release confirmations. Finalize only after status and
smoke checks pass; use `cutover rollback` if a gate fails. Do not uninstall the
umbrella release or delete TiDB PVCs during this migration.
