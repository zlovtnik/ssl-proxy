# Secret Management

Secrets are runtime inputs, never repository content. This policy applies to
Kustomize resources, Argo CD reconciliation, local development and nested
repositories. Read it with the [threat model](threat-model.md) and
[PostgreSQL runtime manifests](../sql/postgres/).

## Secret classes

| Secret | Consumer | Preferred delivery |
|---|---|---|
| WireGuard server, peer and preshared keys | Proxy, frontdoor and rotator | Restrictive files mounted read-only |
| Admin API token | Proxy | `ADMIN_API_KEY_FILE` or Kubernetes Secret |
| PostgreSQL account passwords and DSNs | Octopus, Search, Schema Migrator, Keycloak | Separate Kubernetes Secrets per account |
| PostgreSQL CA and optional client keypair | Direct PostgreSQL clients | Read-only Secret volume |
| Search API token digest | Atheros Search | Kubernetes Secret; store the digest, not a plaintext token |
| MinIO credentials | Octopus/export workflows | Kubernetes Secret |
| Grafana credentials | Grafana | Secret/environment injected at deployment |
| Keycloak bootstrap/admin credentials | Keycloak | Kubernetes Secret |
| Registry credentials | Build hosts and nodes | Runtime-specific credential store |
| WAHA credentials | Optional rotator profile | Secret/environment, never Compose defaults |

Oracle wallets and passwords are deprecated compatibility material. Do not
create new wallet-based runtime guidance.

## Local development

The repository helper can generate local-only secret files and a Docker
Compose environment for the development harness:

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

- The platform secret control plane materializes required Secrets before Argo
  CD reconciles their consumers. The value-free
  [`cyber-stack/platform-input-contract.yaml`](../cyber-stack/platform-input-contract.yaml)
  is the authoritative production inventory of Kubernetes names, keys, types
  and Vault KV-v2 logical paths; this repository stores no values.
- Create one Secret per trust boundary rather than a platform-wide credential
  bundle.
- Keep the PostgreSQL accounts for `octopus_core`, `atheros_search`,
  `schema_migrator` and Keycloak separate.
- Mount only the PostgreSQL CA by default. Add client certificates only when the
  cluster requires mutual TLS.
- Disable service-account token automount for workloads that do not use the
  Kubernetes API.
- Render manifests and inspect `secretKeyRef`/volume wiring without printing
  Secret values.
- Keep credentials out of Kustomize bases, overlays, patches and generators.
- Do not create, edit or patch live Secrets as part of an application release.

## Production platform sync

The platform-owned Vault sync workflow must read every logical path under
`secret/ssl-proxy/prod` declared by the contract. Before writing anything, it
validates that all 17 Secrets and the PostgreSQL endpoint ConfigMap have every
declared key. It must not log values, and its Kubernetes writer identity is
external to application workloads.

The same preflight verifies that the identity certificate covers
`identity.prod.ssl-proxy.internal`, the PostgreSQL CA and server name agree, each DSN
uses the isolated account recorded in the contract, and the grant matrix in
the PostgreSQL cutover document is applied. It also verifies that `loki-htpasswd`
corresponds to the declared Loki username and password. Only after every check
passes may the platform workflow materialize all objects idempotently in
`prod-ssl-proxy`. A partial write is a failed sync.

The Jenkins file credential `ssl-proxy-prod-readonly-kubeconfig` is a separate
platform input sourced from Vault. It authenticates the
`argocd/ssl-proxy-production-gate` ServiceAccount. The platform workflow writes
it to a restrictive host file outside the checkout; the local CI Compose
harness mounts that file as a Docker secret and Jenkins Configuration as Code
imports it as a secret-file credential. It is never copied into this repository
or placed under the ignored local `secrets/` directory.

## Rotation

1. Identify all consumers and the overlap window.
2. Create the candidate credential in the secret manager.
3. Update the least-privileged server-side identity or grant.
4. Roll consumers and verify health/readiness and audit evidence.
5. Revoke the old credential after the overlap window.
6. Record the rotation without recording the secret.

Use the [rotator README](../apps/wg-key-rotator/README.md) for WireGuard keys.
For PostgreSQL, rotate accounts independently and re-run the TLS/grant checks in the
[PostgreSQL runtime manifests](../sql/postgres/).

## Incident response

If a secret may have entered logs, Git history or an artifact, revoke it first.
Removing a file from the working tree does not remove it from Git history.
Preserve incident evidence, scrub history through the approved repository
process, and rotate every derived credential.

Do not paste secrets into issue trackers, chat, command output attached to a
ticket, or `git diff`.
