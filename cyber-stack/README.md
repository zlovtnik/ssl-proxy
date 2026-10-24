# Kubernetes GitOps Guide

This directory is the only source of Kubernetes desired state for ssl-proxy.
Kustomize renders the production and staging slices. The committed ApplicationSet
reconciles the three production Applications from `main`; staging registration
is a separate prerequisite.
Configuration, releases, rollbacks and workload onboarding happen by reviewed
Git changes.

## Ownership boundary

The platform team provides and operates:

- Argo CD;
- registration of `cyber-stack/argocd` as this repository's control-plane path
  and of the dedicated staging cluster;
- registry access for `192.168.1.242:5000`;
- Vault values for workload Secrets and the production PostgreSQL endpoint
  ConfigMap, described by the
  [`platform-input-contract.yaml`](platform-input-contract.yaml);
- Cloudflare Tunnel credentials and an `ssl-proxy-identity-tls` certificate for
  `gateway.rclabs.uk`.

The bootstrap slice creates empty input objects and scoped synchronization RBAC.
The host-side [platform-sync service](../services/platform-sync/README.md)
validates all contract inputs before updating those objects and writes
`platform-ready` last. Argo CD ignores the synchronizer-owned data fields.
Do not create or patch inputs by hand. This repository owns the
`ssl-proxy` AppProject, one list-generated workload ApplicationSet,
and all workload desired state after registration. Local development Secrets
and DNS are outside these environment matrices and must never be
copied into the production cluster as a shortcut.

## Layout and applications

Environment-neutral resources live under `base/`. Environment configuration
lives under `matrix/prod/` and `matrix/staging/`.

| Slice | Production application | Responsibility |
|---|---|---|
| `bootstrap` | `ssl-proxy-prod-bootstrap` | Namespace, shared configuration, input shells, synchronization RBAC and Reloader |
| `data-plane` | `ssl-proxy-prod-data-plane` | PostgreSQL integration, Redpanda, MinIO, Redis, schema execution and telemetry |
| `app-stack` | `ssl-proxy-prod-app-stack` | Proxy, Octopus, Search/UI, sensor, Schema Migrator, public stats and staged DQ workloads |

The production bootstrap slice also runs a namespace-scoped Reloader controller.
It watches only `prod-ssl-proxy` and rolls opted-in Deployments when referenced
platform Secrets or ConfigMaps change. The controller-owned pod-template reload
annotation is the only Reloader field excluded from Argo CD reconciliation.

[`applicationset-workloads.yaml`](argocd/applicationset-workloads.yaml) creates
the three production slice Applications. RollingSync orders bootstrap,
data-plane, then app-stack. They track `main`, use automated sync with pruning and
self-healing, and refuse empty desired state. The data-plane entry retains the
StatefulSet PVC-template ignore rule. Namespace deletion requires explicit
confirmation. Dev Applications and dev controllers are prohibited on the
production server.

The [production prerequisites](matrix/prod/README.md) describe the active
render. The [staging prerequisites](matrix/staging/README.md) describe the
separate namespace and endpoint patches. The AppProject allows a dedicated
staging destination, but the ApplicationSet contains no staging entries or
Image Updater configuration. Registering staging requires reviewed control-plane
and platform-input changes; the production deployer RBAC stays production-only.

The single-node topology intentionally has no PodDisruptionBudgets: a PDB
cannot create redundancy on one node and can block voluntary maintenance. The
Redpanda, MinIO and Alertmanager StatefulSets remain under automated Argo CD
sync rather than a manual-sync carve-out; readiness checks, immutable images
and Git revert are the rollout controls. Revisit both decisions before adding a
second schedulable node.

The control-plane Kustomization also declares the
`ssl-proxy-production-gate` ServiceAccount and its name-scoped Role. That
identity can only get the three generated Applications. The platform team
stores its kubeconfig in Vault and provisions it in Jenkins as
`ssl-proxy-prod-readonly-kubeconfig`; the credential is not a workload Secret.

The same control-plane Kustomization owns K3s's
`kube-system/HelmChartConfig/traefik`. Traefik is an IPv4 `ClusterIP`, exposes
only HTTPS to two in-cluster `cloudflared` replicas, and watches approved CRDs
only in `prod-ssl-proxy`. The public route admits the middleware OIDC paths,
Schema Migrator `/api/` except health, Atheros Search `/v1/`, and the public
`/public/stats` snapshot endpoint; all other paths have no router. Grafana is available only at
`https://gateway.rclabs.uk:30000` from the trusted LAN through its direct TLS
NodePort; every other administrative or data-plane endpoint remains internal.
Router and host-firewall state are platform prerequisites documented in the
[operations runbook](../docs/runbook.md); they are not managed through
interactive Kubernetes changes.

`HelmChartConfig` is intentionally a K3s-only platform contract. The production
context and runbook identify the host as K3s; a migration to another Kubernetes
distribution must replace this resource with that platform's Traefik ownership
surface before the migration is accepted.

## Local development

This repository has no development Kubernetes overlay. `matrix/prod` and its
three slices are production desired state and must not be applied to a local
cluster as a development substitute. Use the repository's Docker Compose and
component test surfaces for local integration work; add a reviewed
development overlay before documenting or automating local Kubernetes use.

## Configuration rules

- Keep reusable manifests and safe defaults in `base/`; keep production
  differences in `matrix/prod/` patches.
- Put shared non-secret values in the platform ConfigMaps. Every environment
  variable consumed by a workload must have a visible base value, overlay
  patch or Secret/ConfigMap reference in the production render.
- Keep credential values out of Git. Reference the smallest platform-owned
  Secret and key required by each workload.
- PostgreSQL credentials and TLS material are platform-owned prerequisites.
  Production uses verified TLS both from PgBouncer to the direct endpoint and
  from application runtimes to PgBouncer; no root credential is consumed by
  the stack.
- Use the standard labels `app.kubernetes.io/name`,
  `app.kubernetes.io/component` and `app.kubernetes.io/managed-by`.
- The namespace default-deny baseline and component policies restrict ingress.
  Egress remains unrestricted until external endpoints and K3s CNI behavior
  have a complete allowlist. The host firewall remains authoritative for the
  host-network wireless sensor.
  NetworkPolicies are security controls only while an enforcing CNI is healthy;
  release evidence must show Calico, Cilium, or kube-router ready on every node
  and include an approved enforcement probe.
- Pin third-party images to an immutable version. First-party images in the
  canonical environment overlays must use SHA-256 digests.
- Use Argo CD sync waves and hooks for ordering. Do not encode rollout order in
  operator shell commands.
- Treat read-only `kubectl get`, `describe` and `logs` as diagnostics only.
  Desired-state changes always go through Git.

## Image release and promotion

1. Let the private Jenkins `ssl-proxy-images` pipeline publish all first-party
   images from `main` through the unchanged `make publish-all REGISTRY=...`
   interface. For an environment-aware manual publication of the twelve
   Kubernetes images, run `make publish ENV=prod`
   (`prod` is the supported deployed environment). This target derives every repository and current pin
   from its owning slice; `REGISTRY` and image tags do
   not define deployment identity.
2. Use the pushed manifest digest and exact bump command printed by
   environment-aware publication. `MATCH` means the selected Kustomization
   already pins that content; `UNPINNED` still means publication succeeded and
   requires a reviewed `make bump-digest-<service> ENV=prod
   DIGEST=sha256:<digest>` Git change. The helper keeps the owning production
   slice as the single source of truth. The bump targets require `ENV=prod`;
   staging is not supported by this publication/promotion interface.
3. CI must pass `make gitops-check`, documentation checks and component tests.
4. Complete the component acceptance checks against the published digest.
5. Open a production pull request that records the accepted digest in the
   corresponding production Kustomizations. `scripts/bump-image-digest.sh` and its generated
   `make bump-digest-<service>` targets update the owning slice. The DQ worker
   target also updates its processor manifest, checksum, and runtime digest.
6. Merge the production pull request and verify all three prod Applications.

Rollback is a Git revert of the promotion commit. Argo CD reconciles the prior
digests automatically. Do not use a controller-local rollback that leaves Git
describing a different state.

Kubernetes always deploys the committed `repository@sha256:...` references.
The commit tag and `latest` are registry lookup channels; publishing or moving
them does not deploy, promote or edit Kustomize.

The Compose-only `wg-key-rotator` image is published by the same Jenkins
pipeline but is not a Kubernetes workload: it controls the local staged-
rotation harness through the Docker API.

## Add a workload

1. Add the workload resources under `base/<component>/`. Include probes,
   requests and limits, a non-root security context, least-privilege service
   account behavior and NetworkPolicy/RBAC where the workload needs them.
2. Add the resources to the correct production slice. Use `bootstrap` for
   shared prerequisites, `data-plane` for storage/transport/telemetry, and
   `app-stack` for application workloads.
3. Add environment patches for replicas, resources, endpoints and feature
   gates. Do not put an environment address or credential in the base.
4. Add required ConfigMap and Secret names/keys to the platform input contract.
   Never commit a usable secret value.
5. Add the first-party image to its owning production slice with a digest, and
   teach `scripts/bump-image-digest.sh` which slice owns it.
6. Assign the smallest sync wave that satisfies real dependencies. Jobs must
   declare the appropriate Argo CD hook and deletion policy.
7. Update component documentation and run `make gitops-check` plus the targeted
   application tests before opening a pull request.

## Verification and diagnosis

Run from the repository root with Python, PyYAML and `kustomize` installed:

```bash
make gitops-check
make docs-check
```

Read-only cluster checks:

```bash
export KUBE_CONTEXT="$(kubectl config current-context)"
make stack-health
kustomize build --load-restrictor LoadRestrictionsNone cyber-stack/matrix/prod/bootstrap >/dev/null
kustomize build --load-restrictor LoadRestrictionsNone cyber-stack/matrix/prod/data-plane >/dev/null
kustomize build --load-restrictor LoadRestrictionsNone cyber-stack/matrix/prod/app-stack >/dev/null
```

`stack-health` defaults to production and the current Kubernetes context. It
is usually simplest to omit `KUBE_CONTEXT`; exporting the current context as
shown above freezes that selection for a sequence of commands. Context names
are local to each host, so do not copy a workstation context name onto a
server. Use `kubectl config get-contexts -o name` before exporting a different
context. If the host requires a non-default client executable, export
`KUBECTL` with its absolute path; both the Make preflight and recovery helper
honor it. The report prints the resolved context and namespace before reporting
Git/Kustomize, Argo
CD (production only), desired and live images, registry tags, runtime image
IDs, required platform object/key presence, workload and pod health, and recent
warning events. It prints the complete report before returning nonzero for
unhealthy Applications, missing required objects or keys, verified image drift,
or unhealthy workloads. A nonzero result reports detected recovery blockers; it
does not indicate that the reporting command failed. Unmanaged debug pods and
pods from superseded ReplicaSets are informational, while current managed pods
still enforce health and runtime-digest checks. The Secret query emits only type
and key names; values are suppressed. The report never changes Git, registry
state, Argo CD or Kubernetes.

`make production-gate PRODUCTION_GATE_REVISION=<full-main-sha>` is the narrower
CI check. It validates the read-only identity and waits up to 30 minutes for the
three production Applications to report that exact revision as
`Synced/Healthy`. It does not publish or promote images.

When an Application is unhealthy, inspect its conditions, the rendered Git
revision, workload events and container logs. Correct workload manifests in
the appropriate `cyber-stack/base` or environment-overlay Git source and allow
Argo CD to reconcile them. Changes to platform-owned Secrets and the production
PostgreSQL endpoint ConfigMap must instead go through the platform's declarative
control plane; they are prerequisite contracts and are not owned by an
unspecified workload repository.

If required platform input values are absent, inspect the host synchronizer's
health and contract validation before publishing images again. An existing
Secret shell does not prove that its required keys are populated, and an image
publication cannot supply missing Vault inputs.
