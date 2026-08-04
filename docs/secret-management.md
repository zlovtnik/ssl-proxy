# Secret Management

Secrets are deployment inputs, never repository content. This policy applies
to Compose, Helm, stackctl, the operations CLI and nested repositories. Read it
with the [threat model](threat-model.md) and
[TiDB runtime contract](tidb-runtime-cutover.md).

## Secret classes

| Secret | Consumer | Preferred delivery |
|---|---|---|
| WireGuard server, peer and preshared keys | Proxy, frontdoor and rotator | Restrictive files mounted read-only |
| Admin API token | Proxy | `ADMIN_API_KEY_FILE` or Kubernetes Secret |
| TiDB account passwords and DSNs | Octopus, Search, Schema Migrator, Keycloak | Separate Kubernetes Secrets per account |
| TiDB CA and optional client keypair | Direct TiDB clients | Read-only Secret volume |
| Search API token digest | Atheros Search | Kubernetes Secret; store the digest, not a plaintext token |
| MinIO credentials | Octopus/export workflows | Kubernetes Secret or Compose required environment |
| Grafana credentials | Grafana | Secret/environment injected at deployment |
| Keycloak bootstrap/admin credentials | Keycloak | Kubernetes Secret |
| Registry credentials | Build hosts and nodes | Runtime-specific credential store |
| WAHA credentials | Optional rotator profile | Secret/environment, never Compose defaults |

Oracle wallets and passwords are deprecated compatibility material. Do not
create new wallet-based runtime guidance.

## Local generation

The repository helper can generate local secret files and a Compose
environment:

```bash
scripts/gen-secrets generate
scripts/gen-secrets env
```

Review the generated one-time token material, move recovery values to the
approved secret manager, and remove temporary copies when the handoff is
complete. Generated `secrets/`, `.env`, key material and wallet directories
must remain untracked.

## File rules

- Use regular files, not symlinks, for mounted private keys and tokens.
- Limit permissions to the owning operator/service. Containerized processes
  running as root may need to read host-owned `0600` files, but the mount must
  remain read-only.
- Mount the smallest required directory and never the repository root.
- Do not log file contents, DSNs with passwords, bearer tokens or private keys.
- Validate the exact file path before rotation or cleanup.

## Kubernetes rules

- Create one Secret per trust boundary rather than a platform-wide credential
  bundle.
- Keep the TiDB accounts for `octopus_core`, `atheros_search`,
  `schema_migrator` and Keycloak separate.
- Mount only the TiDB CA by default. Add client certificates only when the
  cluster requires mutual TLS.
- Disable service-account token automount for workloads that do not use the
  Kubernetes API.
- Render manifests and inspect `secretKeyRef`/volume wiring without printing
  Secret values.
- Treat `values.yaml` and `values-k8s.yaml` as non-secret configuration. Never
  commit credentials into them.

## Rotation

1. Identify all consumers and the overlap window.
2. Create the candidate credential in the secret manager.
3. Update the least-privileged server-side identity or grant.
4. Roll consumers and verify health/readiness and audit evidence.
5. Revoke the old credential after the overlap window.
6. Record the rotation without recording the secret.

Use the [rotator README](../apps/wg-key-rotator/README.md) for WireGuard keys.
For TiDB, rotate accounts independently and re-run the TLS/grant checks in the
[TiDB cutover guide](tidb-runtime-cutover.md).

## Incident response

If a secret may have entered logs, Git history or an artifact, revoke it first.
Removing a file from the working tree does not remove it from Git history.
Preserve incident evidence, scrub history through the approved repository
process, and rotate every derived credential.

Do not paste secrets into issue trackers, chat, command output attached to a
ticket, or `git diff`.
