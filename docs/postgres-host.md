# Wiretrap PostgreSQL Host

This guide owns the repository-managed external PostgreSQL service on Wiretrap.
It is a platform prerequisite, not a Kubernetes workload: Argo CD continues to
manage only its clients and receives endpoint, TLS, and password projections
through `platform-sync`. Read this with the [storage runbook](platform-storage-operations.md),
[production prerequisites](../cyber-stack/matrix/prod/README.md), and the
[platform input contract](../cyber-stack/platform-input-contract.yaml).

## Host Definition

`../docker/postgres/compose.yaml` preserves project `ssl-proxy-platform`,
service `postgres`, container `ssl-proxy-platform-postgres`, endpoint
`192.168.1.242:4000/sync`, and the existing data, secret, TLS, and platform
network identities. All three volumes and the network are external, so startup
fails rather than creating a replacement prerequisite. The PostgreSQL image is
the exact digest in the platform contract.

The configuration and HBA files are mounted read-only and are authoritative.
They require TLS for every TCP client, retain SCRAM authentication and durability
defaults, preload normalized query statistics, and use the measured initial
resource profile: 10 CPUs, CPU weight 2048, 16 GiB memory limit, 8 GiB memory
reservation, disabled swap allowance, 1 GiB shared memory, a 120-second stop
grace period, and five 10 MB JSON log files.

`postgresql.conf` sets 4 GiB shared buffers, a 12 GiB cache estimate, 16 MB
per-operation work memory, 512 MB maintenance memory, 150 connections with
three administrator reservations, the requested worker limits, 15-minute
checkpoints, LZ4 WAL compression, NVMe cost/concurrency values, autovacuum
limits, and I/O/WAL/checkpoint/query-statistics diagnostics. It intentionally
does not change JIT. The cache estimate allocates no memory and `work_mem`
applies per operation, so client concurrency remains bounded below.

## Initialization And Adoption

The official PostgreSQL entrypoint runs initialization only for an empty data
volume. It reads `platform_admin.password` and the five existing isolated role
password files from the mounted secret volume without storing values in Git.
The host custodian provides the administrator file with the same restrictive
ownership and mode as the role files; `platform_postgres.py stage-secrets`
stages the five Vault-backed role files. Initialization creates only
`schema_owner`, `octopus_runtime`, `atheros_search_runtime`,
`schema_migrator_runtime`, and `keycloak_runtime`, revokes default database
access, and grants those roles access to `sync`. `schema_owner` alone receives
database `CREATE` so the canonical executor can establish its owned schemas.

The canonical extension SQL is mounted and executed during empty-volume
initialization. Application schemas, grants, manifests, and readiness evidence
remain exclusively owned by the canonical schema executor. Existing storage is
adopted unchanged: initialization does not rerun and no schema DDL is applied.

Run these read-only checks from the repository checkout on Wiretrap:

```bash
make postgres-config-check
make postgres-status
python3 scripts/platform_postgres.py check
```

The maintenance CLI now defaults to `docker/postgres/compose.yaml`; an approved
legacy or recovery definition can still be selected with `--compose-file` for
explicit Vault operations. Do not use an untracked definition for normal
recreation.

## Client Limits And Rollout

Each of the three PgBouncer role pools has eight normal and two reserve upstream
connections. `max_db_connections=30` caps each PgBouncer pod at 30 PostgreSQL
connections. PgBouncer remains at two replicas with an explicit one-pod surge
and zero unavailable pods. Four overlapping pods therefore consume at most 120
upstream connections, leaving the remaining capacity for Keycloak and
administration.

Keycloak's bootstrap and main containers each use initial/minimum pool size two
and maximum size ten. Reconcile these client limits through Argo before changing
the host. Serialize PgBouncer generations and wait for terminating pods to
disappear before proceeding to the next generation; do not scale or restart
managed resources interactively.

## Recreate And Validate

1. Validate rendering, image digest, endpoint, external volume/network contract,
   connection arithmetic, empty-volume initialization, existing-volume adoption,
   and `--compose-file` compatibility.
2. Commit and review the repository change. Reconcile the PgBouncer and Keycloak
   limits through Argo, then verify earlier PgBouncer generations have exited.
3. Before recreation, save the active configuration and take a private full
   backup. Restore it into an isolated PostgreSQL instance before proceeding.
4. Recreate only the `postgres` service from the tracked Docker Compose file.
   Preserve every external volume. Keep the legacy definition only for explicitly
   selected Vault maintenance operations.
5. Verify effective settings and sources, no pending restart, five verified-TLS
   logins, rejection of non-TLS TCP connections, and client readiness.
6. Compare equivalent intervals immediately and after 24 hours: latency,
   temporary writes, requested checkpoints, memory/cache use, OOM events, CPU
   throttling, and connection errors. Roll back configuration against the same
   data volume on readiness failure or sustained regression.

## Follow-Up Observations

Record the heavy Octopus query IDs from the pre-rollout and 24-hour samples, and
track the existing ambiguous-column errors as separate query/index work. Query
or index changes, PostgreSQL upgrades, recurring backup infrastructure, and the
separate native PostgreSQL instance are outside this host configuration change.
