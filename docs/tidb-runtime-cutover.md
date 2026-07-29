# TiDB Runtime and Cutover

This is the operational contract for application-owned durable state. The
canonical component and flow model is in [System Architecture](architecture.md).

## Policy

TiDB is the only internal application datastore. PostgreSQL is supported only
as an explicit external target of Schema Migrator. Oracle is deprecated
compatibility or historical material and is not a current runtime dependency.
Redis and MinIO may hold reconstructible cache, coordination or exported
objects, but neither replaces TiDB as authoritative application state.

## Canonical domains

Only the checksummed manifests under [`sql/tidb/`](../sql/tidb/) define runtime
DDL:

| Domain | Account | Required ownership |
|---|---|---|
| `octopus_core` | `octopus_runtime` | Octopus read/write |
| `atheros_search` | `atheros_search_runtime` and `octopus_runtime` | Search reads and worker writes; Octopus projection/document preparation |
| `integration_console` | no current runtime account | Schema reserved; no application owner today |
| `schema_migrator` | `schema_migrator_runtime` | Schema Migrator internal CRUD and execution state |
| `contracts` | schema executor | Shared manifest and contract recording |

Helm creates a separate `keycloak` database and `keycloak` account for the
in-cluster identity provider. It is deployment-owned and is not a fifth
application manifest.

## Provisioning authority

The `tidb-runtime-schema` image runs
[`k8s/tidb-schema-executor/entrypoint.sh`](../k8s/tidb-schema-executor/entrypoint.sh).
It:

1. verifies each domain's ordered file checksums;
2. applies the four application manifests over TLS as the schema owner; and
3. records the Atheros Search manifest readiness state.

Application runtimes must not apply canonical DDL. They connect with dedicated
accounts, check TiDB version/TLS/server identity and verify the expected
manifest checksum before serving traffic.

Active migrations and ordered additions are append only. Do not recreate the
retired `sql/tidb/core/` baseline or introduce PostgreSQL runtime aggregates.

## Grant matrix

The intended least-privilege matrix is:

| Account | `octopus_core` | `atheros_search` | `schema_migrator` | `keycloak` |
|---|---|---|---|---|
| `octopus_runtime` | Read/write | Read/write for owned projection preparation | None | None |
| `atheros_search_runtime` | Read-only where cross-domain queries require it | Read/write for query analytics, job leases and vectors | None | None |
| `schema_migrator_runtime` | None | None | Read/write | None |
| `keycloak` | None | None | None | Read/write |

The umbrella TiDB chart implements these Search write grants. The older
standalone [`k8s/tidb/init-job.yaml`](../k8s/tidb/init-job.yaml) still grants
`atheros_search_runtime` only `SELECT`; do not treat that manifest as a
production worker grant model.

## Locked topics and delivery

The cutover does not rename topics:

- `sync.scan.request` is producer-to-Octopus work discovery.
- `sync.oracle.load` is Octopus-owned TiDB load dispatch.
- `sync.oracle.result` is the matching TiDB load outcome.

The two `sync.oracle.*` names are legacy compatibility labels. No Oracle
connection is implied.

Delivery remains at least once after the signed cutover offset. Octopus records
topic, partition and offset evidence, uses durable dedupe keys, and advances
cursors only at the durable boundary. A cutover must never skip an unsigned
range or reuse consumer identities without proving the intended offset.

## Required connection configuration

Octopus uses the `TIDB_*` family, including host, port, database, user,
password, pool size, SSL mode, CA path and server name. Atheros Search uses a
native Go MySQL DSN in `ATHSEARCH_TIDB_DSN` plus
`ATHSEARCH_TIDB_TLS_CA_FILE`, `ATHSEARCH_TIDB_TLS_SERVER_NAME` and the expected
manifest hash. Schema Migrator uses its `BEDROCK_STATE_DB_*` settings for the
TiDB internal store.

Every connection parameter consumed by an application must have a matching
Helm value and deployment environment variable. Keep application defaults,
`global.shared.tidb` and subchart templates aligned.

## Cutover procedure

1. Back up existing evidence and record the source consumer-group offsets.
2. Provision fresh TLS identities and dedicated accounts.
3. Apply the four canonical manifests with the schema executor and retain its
   checksum evidence.
4. Verify database names, account grants, TiDB version, CA chain and server
   name from each workload network.
5. Produce and sign the cutover artifact containing cluster identity, schema
   version, required consumer groups and starting offsets.
6. Start Octopus with consumers/processors gated off; verify `/health` against
   TiDB.
7. Activate consumers at the signed boundary and confirm ingestion evidence,
   dedupe and cursor movement.
8. Enable projection/processor lanes only after their dependencies are ready.
9. Enable Atheros Search query traffic; enable workers only when document/job
   production, write grants and embedding backend readiness have been proven.
10. Retain rollback evidence until the compatibility window closes.

## Acceptance evidence

A cutover is accepted only when operators can show:

- schema-executor success and all manifest hashes;
- TLS verification from each direct client;
- exact grant output for every runtime account;
- signed topic/partition/offset boundary;
- duplicate-delivery and restart tests without duplicate effects;
- Atheros Search `/readyz` results for database, schema, vector and embedding
  dependencies;
- no application connection to an internal PostgreSQL store.

Single-node TiDB/UniStore in Compose and `values-k8s.yaml` is suitable for
development and compatibility testing. It does not prove TiFlash placement,
distributed failover or production vector-index readiness.

## Rollback

Stop new consumers before changing offsets. Preserve the signed artifact,
ingestion evidence and TiDB state. Roll back deployment code without deleting
canonical schemas or rewinding evidence tables. Any offset change requires a
new signed boundary and an explicit duplicate/replay analysis.
