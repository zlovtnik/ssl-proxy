# GitOps Maintainability Audit

`cyber-stack/base/schema-migrator` and `cyber-stack/base/telemetry` currently
contain 2,902 YAML lines (1,229 and 1,673 respectively). This is an audit of
future extraction candidates, not a refactor plan.

## Evidence-backed candidates

1. **Third-party image catalog in the existing base Kustomizations.**
   Schema Migrator's `keycloak.yaml` repeats `quay.io/keycloak/keycloak:26.2.5`
   for four containers (lines 31, 75, 101, and 168). Telemetry similarly keeps
   its component image references in sixteen individual resource documents.
   A future reviewed change could use each directory's existing
   `kustomization.yaml` `images` field as the single version-update surface,
   while retaining the workload-local image names. This needs a render and
   policy-check update first because the current checker deliberately rejects
   mutable rendered first-party images but permits version-pinned third-party
   tags.

2. **Resource-family file boundaries.** `keycloak.yaml` is 306 lines and
   contains the Keycloak Deployment, Service and traffic-isolation resources;
   `telemetry/prometheus.yaml` (156 lines), `telemetry/jaeger.yaml` (156
   lines), `telemetry/loki.yaml` (184 lines), and `telemetry/pushgateway.yaml`
   (136 lines) use the same workload-plus-Service-plus-NetworkPolicy family.
   Splitting these families into one resource per file would make policy and
   selector changes narrower to review. Do this only when a concrete change
   benefits from it: the selectors and allowed peers differ, so they are not
   candidates for a generic NetworkPolicy template today.

3. **Label/metadata linting before templating.** Both directories repeatedly
   carry the same three ownership labels (`app.kubernetes.io/name`,
   `app.kubernetes.io/component`, and `app.kubernetes.io/managed-by`) across
   workloads, Services and policies. Add a structured lint rule if label drift
   becomes a source of defects; it is safer than introducing a broad
   `commonLabels` transformation that could alter selectors.

## Deliberate non-extraction

Do not add a Kustomize Component now. The dev/prod `identity-hostname` patches
carry different hostnames, and their `proxy-replicas` patches intentionally
set different replica counts (1 in dev and 12 in prod). Those variations are
environment policy, not reusable component defaults.
