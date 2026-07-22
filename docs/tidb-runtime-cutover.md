# Fresh TiDB Runtime Cutover

This runbook replaces application-owned PostgreSQL and MongoDB runtime state
with four empty databases on an externally managed TiDB 8.5 or newer cluster:

- `octopus_core`
- `atheros_search`
- `integration_console`
- `schema_migrator`

It is intentionally a fresh start. Do not copy PostgreSQL rows, configuration,
vectors, jobs, users, or consumer positions. Do not replay Redpanda records
which precede the signed cutover offsets.

## Completion states

The migration has three separate completion claims:

1. **Repository-ready** means source, schemas, manifests, tests, and guarded
   tooling are complete.
2. **Environment-qualified** means the exact external TiDB/TiFlash cluster,
   credentials, TLS identities, grants, schemas, seeds, vector indexes, and
   external identity provider passed their integration checks.
3. **Cutover-accepted** means activation, bounded offset evidence, the 30-minute
   observation, legacy resource pruning, and the separately approved host-path
   deletion completed successfully.

Never describe repository-ready work as environment-qualified or
cutover-accepted.

## Ownership and credentials

The provisioning identity is the only account allowed to create databases,
tables, indexes, migrations, or grants. The `scripts/tidb-runtime-schema`
executor allowlists the four canonical roots under `sql/tidb/`; it must reject
the retired `sql/tidb/core` baseline. HNSW DDL is a separate post-TiFlash step.

Runtime accounts have these boundaries:

| Account | Writes | Reads |
| --- | --- | --- |
| Octopus | Core, maintained Search projections, Console acknowledgements | Its processor inputs and readiness metadata |
| Rails | Console configuration, runs, windows, and command rows | Approved Core and Search projections |
| Atheros Search | Queries, results, feedback, and merge decisions | Approved Core and Search projections |
| Schema Migrator | Its control state only | Its control state only |

External migration-target credentials are separate encrypted inputs. A
PostgreSQL target credential must never be accepted as schema-migrator control
state or as a global application database URL.

Keycloak remains a supported JWT/JWKS issuer, but is external to this release.
There is no realm/user/client backfill. Qualify a fresh realm, client, roles,
admin identity, issuer/audience, discovery endpoint, JWKS endpoint, and smoke
token for a newly created test principal. (The single-node dev stack rendered
from `helm/ssl-proxy/values-k8s.yaml` is the one exception: it runs an
in-cluster Keycloak from the schema-migrator subchart with its own TiDB
account; see the runbook's single-node section.)

## Required qualification evidence

Before staging, capture all of the following in the change record:

- exact TiDB patch version and SQL mode;
- verified server name, CA chain, and optional client certificate identity for
  each of the four accounts;
- positive and negative grant results;
- four empty-domain proofs, except explicitly allowlisted system seeds;
- manifest checksums from all four `schema_migrations` tables;
- TiFlash replica availability for every vector table;
- HNSW build state and an `EXPLAIN` plan demonstrating ANN use;
- external Keycloak discovery/JWKS and smoke-token results;
- the pre-migration contract test report;
- rendered `stage`, `activate`, and `prune` Helm inventories.

Vector qualification must use the exact target cluster. TiDB vector indexing
depends on TiFlash and has version/configuration restrictions that a unit test
or mock SQL server cannot establish.

## Signed offset artifacts

The cutover artifact is canonical JSON with:

- `schema_version: 1` and `kind: cutover`;
- the Redpanda cluster identity and UTC capture time;
- the new group version;
- every consumer-group/topic/partition and its next offset.

Sign it with a detached Ed25519 signature. Keep the private key offline; mount
only the public verification key into consumers. To canonicalize, sign, and
verify an artifact:

```bash
scripts/tidb-cutover-artifact.py canonicalize cutover.json --output cutover.canonical.json
scripts/tidb-cutover-artifact.py sign cutover.json --private-key cutover-ed25519.pem --signature cutover.sig
scripts/tidb-cutover-artifact.py verify cutover.json --public-key cutover-ed25519.pub.pem --signature cutover.sig
scripts/tidb-cutover-artifact.py checksum cutover.json
```

Each partition entry carries its exact `group_id`; this prevents independent
consumers of the same topic/partition from sharing evidence accidentally. The
capture must enumerate every partition for every new group. Missing partitions,
an invalid
signature, an unexpected broker identity, or a group mismatch must fail
readiness. Group initialization is a separate mutating action: review its dry
run and require the live cutover approval before applying it. The generated
offset files use Redpanda's `<topic> <partition> <offset>` seek-file format:

```bash
scripts/tidb-cutover-artifact.py group-plan cutover.json \
  --signature cutover.sig --public-key cutover-ed25519.pub.pem \
  --output-dir evidence/group-offsets --output evidence/group-plan.json

# Mutating: run only inside the approved change window after reviewing the plan.
cutover_sha256="$(scripts/tidb-cutover-artifact.py checksum cutover.json)"
scripts/tidb-cutover-artifact.py group-apply cutover.json \
  --signature cutover.sig --public-key cutover-ed25519.pub.pem \
  --output-dir evidence/group-offsets --rpk-config production-rpk.yaml \
  --approval-sha256 "$cutover_sha256" \
  --confirm-cluster-id redpanda-production-a
```

At the end of observation, capture and sign an `audit_end` artifact with the
exclusive end offset for every partition and the canonical cutover SHA-256.
Export the durable Octopus ingestion ledger as JSON Lines with one row per
offset and these fields:

```json
{"group_id":"octopus-wireless-tidb-v1","topic":"wireless.audit","partition":0,"offset":42,"group_version":"tidb-v1","artifact_sha256":"...","status":"processed"}
```

Then prove the complete bounded interval:

```bash
scripts/tidb-cutover-artifact.py coverage \
  --cutover cutover.json \
  --cutover-signature cutover.sig \
  --audit-end audit-end.json \
  --audit-end-signature audit-end.sig \
  --public-key cutover-ed25519.pub.pem \
  --ledger ingestion-ledger.jsonl \
  --output coverage-report.json
```

The gate fails for a consumed pre-cutoff record, an unexplained offset gap, a
duplicate ledger row, a bad artifact checksum, or any `retrying`/`parked`
record. Only `processed` and durably `deduplicated` rows are clean.

## Rollout sequence

### 1. Provision and qualify

Provision the external databases, accounts, TLS, grants, canonical schemas,
system seeds, TiFlash replicas, and HNSW indexes. Provision the fresh external
identity realm/client. Do not use runtime accounts for DDL.

### 2. Stage

Render and apply the explicit `stage` profile. It retains the current legacy
resources and writers, adds new TiDB-connected images with every new consumer
disabled, and does not switch Services. Prove schema, version, TLS, grants, and
readiness. Transitional images must use the captured immutable digests.

### 3. Establish the rollback boundary

Record the last Helm revision which can restore the PostgreSQL-backed runtime.
After any TiDB-only write is externally visible there is no database rollback:
recovery becomes quiesce and forward-fix. Confirm the on-call owner and abort
criteria before continuing.

### 4. Quiesce and capture

Quiesce PostgreSQL writers and the old Rails, Go, and coordinator workers while
Redpanda producers continue. Prove the old consumers stopped advancing. Capture
and sign the exact next offset for every consumed topic/partition, then create
the new versioned groups at exactly those offsets. No `earliest` or implicit
`latest` fallback is allowed.

### 5. Activate

Apply the `activate` profile. It keeps legacy resources present but quiesced,
enables Octopus processors, starts Rails/Search/schema-migrator against TiDB,
and switches Services only after readiness and smoke tests pass.

### 6. Observe for 30 minutes

Continuously record:

- zero application PostgreSQL and MongoDB connections;
- no processing gap or pre-cutoff record;
- stable or shrinking consumer lag and outbox backlog;
- no unrecovered expired lease or transaction retry exhaustion;
- no vector-index/build/query failure;
- no Redis-authoritative dependency;
- successful Rails routes/channels, Search HTTP/gRPC, schema-migrator API, and
  locked Redpanda payload smoke tests.

Capture the signed audit-end offsets and require a clean bounded coverage
report. Any retrying or parked record blocks the next step.

### 7. Prune

Apply the atomic `prune` profile. It removes the compatibility PostgreSQL,
MongoDB, exporter, secret, policy, and legacy-worker objects. Compare the
rendered and live inventories. Delete failed-revision orphans only by exact
resource name plus release label, and only after reviewing the resolved list.

### 8. Irreversible host-path deletion

This repository does not automate this step. During the approved change window:

1. Resolve the literal path
   `/var/lib/docker/volumes/ssl-proxy_postgres-data/_data` on the intended host.
2. Prove the hostname, mount namespace, Docker volume identity, Kubernetes
   context/release, and current process/mount users.
3. Prove no snapshot, backup, PVC, or retained copy is required under the
   selected meaning of "unrecoverable."
4. Present the exact resolved deletion command and get the separate destructive
   approval.
5. Delete only that literal path, then verify it and every legacy database
   process/resource are absent.

Never use a glob, environment-variable expansion, `$HOME`, `~`, or a recursive
parent directory for this operation.

## Abort conditions

Abort activation or pruning when any required schema checksum, signature,
partition, grant, TLS identity, TiFlash replica, HNSW readiness result, smoke
test, or processor readiness result is missing. Also abort for growing lag,
unexplained offsets, retries beyond budget, parked work, lease buildup,
PostgreSQL/MongoDB connections, or failed Service switching.

Before activation, rollback may restore the captured old Helm revision. After
TiDB-only writes begin, do not write them back to PostgreSQL and do not replay
old data. Quiesce affected processors, repair forward, reconcile, and resume
from the durable TiDB/outbox state.
