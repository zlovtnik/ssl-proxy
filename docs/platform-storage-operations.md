# Platform Storage and PostgreSQL Rotation

This runbook covers the external PostgreSQL prerequisite, the private CI
registry and Kubernetes storage hygiene. Read it with the
[secret-management policy](secret-management.md), the
[production prerequisites](../cyber-stack/matrix/prod/README.md) and the
[registry workflow](local-registry-workflow.md).

## Boundaries

- Vault KV-v2 remains the production credential source of truth.
- `platform-sync` remains the only Kubernetes Secret/ConfigMap writer.
- PostgreSQL data-volume operations affect the external platform container,
  not an Argo-managed workload.
- Registry and PVC cleanup starts with a read-only inventory. A candidate is
  not proof that its data is disposable.
- Never place tokens, passwords, private keys, kubeconfigs or recovery material
  in the checkout or command arguments.

## PostgreSQL preflight and volume reset

The maintenance CLI validates the digest-pinned PostgreSQL bootstrap contract,
the exact container-to-volume attachment, Vault access and all five isolated
account inputs without printing values:

```bash
export VAULT_ADDR=https://192.168.1.242:8200
export VAULT_CACERT=/approved/path/vault-ca.crt
python3 scripts/platform_postgres.py check
```

Stage the five role files before first initialization or a volume reset. The
files are written through stdin, owned by the PostgreSQL container UID/GID and
set to mode `0400`:

```bash
python3 scripts/platform_postgres.py stage-secrets
```

A full reset is intentionally destructive. It verifies that the running
container mounts exactly `ssl-proxy-platform-postgres-data`, stages credentials,
removes and recreates only that named volume, waits for health, and runs the
canonical checksum-verifying schema executor:

```bash
python3 scripts/platform_postgres.py reset \
  --confirm RESET-ssl-proxy-platform-postgres-data
```

Run `platform-sync` after the schema executor succeeds, then let Argo reconcile
consumers. Do not roll consumers while contract validation or server-side dry
runs are failing.

## PostgreSQL password rotation

Create a separate, short-lived Vault writer token. The token can read/update
only the five PostgreSQL account paths and the PgBouncer runtime user list; it
has no Kubernetes permissions and cannot delete Vault versions:

```bash
export POSTGRES_ROTATION_TOKEN_FILE=/approved/path/postgres-rotation.token
./scripts/bootstrap-postgres-rotation-token.sh
unset VAULT_TOKEN
export VAULT_TOKEN="$(<"$POSTGRES_ROTATION_TOKEN_FILE")"
```

Rotate one role at a time in a maintenance window:

```bash
python3 scripts/platform_postgres.py rotate-password \
  --role octopus_runtime \
  --confirm ROTATE-octopus_runtime
```

The command preflights role existence and PgBouncer/Vault parity, generates a
256-bit password, updates PostgreSQL, verifies a `verify-full` login, updates
the narrow Vault paths and refreshes the host secret file. Failures trigger a
best-effort rollback to the prior database and Vault values. It never writes
Kubernetes; run the supported platform-sync service immediately, verify all
consumers, then revoke the short-lived token:

```bash
sudo systemctl start vault-k8s-sync.service
vault token revoke -self
unset VAULT_TOKEN
rm -f "$POSTGRES_ROTATION_TOKEN_FILE"
```

Treat any failed password statement that entered PostgreSQL logs as disclosure:
rotate again after correcting the failure and preserve the incident evidence.

## PostgreSQL TLS rotation

Prefer a stable offline PostgreSQL CA and rotate only the server leaf/key. The
candidate must be a regular private-key file with no group/world access, match
the certificate, chain to the approved CA, cover the exact `verify-full` server
name, and remain valid for at least seven days:

```bash
python3 scripts/platform_postgres.py validate-tls \
  --ca /approved/path/postgres-ca.crt \
  --certificate /approved/path/server.crt \
  --key /approved/path/server.key \
  --server-name 192.168.1.242
```

Do not replace a self-signed server certificate and its trust anchor in one
step. A CA rollover is a reviewed two-phase platform operation:

1. Publish an overlap bundle containing the old and new CA certificates to the
   `postgres-runtime-tls` Vault input.
2. Run platform-sync and verify direct clients and both PgBouncer pods project
   the overlap bundle.
3. Activate the new server leaf/key through the external platform workflow and
   prove `verify-full` logins for all five accounts.
4. Observe workload readiness through an Argo-managed rollout when a process
   requires reload.
5. Remove the old CA from Vault, run platform-sync again, and retain the prior
   Vault version only for the approved rollback window.

The PostgreSQL password-rotation token intentionally cannot update TLS inputs.
CA/private-key custody requires a separate break-glass-reviewed identity.

## Registry retention

Use `make registry-clean-plan` and `make registry-clean` as documented in the
[registry retention procedure](local-registry-workflow.md#retention-and-garbage-collection).
The planner protects Git pins and live pod digests before proposing deletions.
Offline garbage collection omits `--delete-untagged` because a valid release may
be referenced only by digest.

## PVC and controller hygiene

`make pvc-audit` reports only claims that simultaneously have no owner
reference, no Argo tracking annotation and no pod reference. It never deletes:

```bash
make pvc-audit KUBE_CONTEXT=wiretrap-k3s
```

Before approving a candidate, identify its application owner, reclaim policy,
backup/restore evidence and local-path directory. Namespace or PVC deletion
still requires explicit approval. Git-managed Deployments and StatefulSets keep
at most three controller revisions, and completed Jobs must declare a positive
TTL, preventing routine history from accumulating indefinitely.

## Evidence after maintenance

Capture value-free evidence:

```bash
python3 scripts/platform_postgres.py check
make stack-health KUBE_CONTEXT=wiretrap-k3s REGISTRY_PLAIN_HTTP=1
make pvc-audit KUBE_CONTEXT=wiretrap-k3s
docker system df
df -h /
```

Record Vault version numbers, certificate fingerprints, image digests, volume
names and readiness results. Never record credential values.
