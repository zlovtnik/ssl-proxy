# Staging prerequisites

This matrix defines staging render inputs for a dedicated cluster in
`staging-ssl-proxy`. The [AppProject](../../argocd/appproject-ssl-proxy.yaml)
allows the staging destination, but the committed
[ApplicationSet](../../argocd/applicationset-workloads.yaml) creates production
Applications only. These files do not establish a running staging deployment.

## Platform prerequisites

The intended isolated database is `sync_staging`, but Atheros Search currently
requires database `sync` in its
[pool validation](../../../apps/integration-console/atheros-search/internal/db/pool.go).
Resolve that runtime contract before admitting a staging deployment; rendering
the matrix alone does not validate database compatibility.

The platform must also provision TLS, least-privilege PostgreSQL accounts,
registry access, a Cloudflare tunnel, and certificates for
`staging-gateway.rclabs.uk`, `staging-migrator.rclabs.uk`, and
`staging-search.rclabs.uk`.

Prepare a reviewed staging-specific input contract and synchronization
configuration for Vault inputs under `secret/ssl-proxy/staging`. The checked-in
[platform input contract](../../platform-input-contract.yaml) targets production;
it must not be reused unchanged for staging. The bootstrap slice creates the
`ssl-proxy-staging-postgres-endpoint` shell and scoped synchronization RBAC.
Exact endpoint and tunnel values are platform supplied and intentionally not
committed.

## Render boundaries

- [Bootstrap](bootstrap/kustomization.yaml) owns namespace, shared configuration,
  input shells and synchronization RBAC.
- [Data plane](data-plane/kustomization.yaml) includes storage, PgBouncer,
  schema execution and telemetry.
- [App stack](app-stack/kustomization.yaml) includes application and public
  snapshot services; it currently has no DQ resources.

Staging reuses several production patches, including the base Octopus runtime
settings, but does not include production's broker-drain or v2 consumer-group
recovery patches. Review those shared paths before enabling the environment.
No Image Updater configuration is committed, and the production digest-bump
targets reject `ENV=staging`.

## Verification

Run from the repository root with `kustomize` installed:

```bash
kustomize build --load-restrictor LoadRestrictionsNone cyber-stack/matrix/staging/bootstrap >/dev/null
kustomize build --load-restrictor LoadRestrictionsNone cyber-stack/matrix/staging/data-plane >/dev/null
kustomize build --load-restrictor LoadRestrictionsNone cyber-stack/matrix/staging/app-stack >/dev/null
make docs-check
```

These commands render and validate documentation locally. Staging admission,
platform-input readiness and runtime acceptance require separate evidence.
See the [GitOps guide](../../README.md) for ownership and promotion rules.
