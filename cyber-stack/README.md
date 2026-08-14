# Kubernetes GitOps Guide

This directory is the only source of Kubernetes desired state for ssl-proxy.
Kustomize renders both environments. Argo CD on `192.168.1.221` reconciles
production from `main`; development is rendered and applied only to an
explicit local Kubernetes context. Configuration, releases, rollbacks and
workload onboarding happen by reviewed Git changes.

## Ownership boundary

The platform team provides and operates:

- Argo CD;
- registration of `cyber-stack/argocd` as this repository's production-only
  control-plane path;
- registry access for `192.168.1.221:5000`;
- workload Secrets and the production TiDB endpoint ConfigMap required by the
  rendered manifests, sourced through the value-free
  [`platform-input-contract.yaml`](platform-input-contract.yaml);
- DNS and an `ssl-proxy-identity-tls` certificate for
  `identity.prod.ssl-proxy.internal`.

Platform inputs must be delivered by the platform's declarative control plane.
Do not create or patch them by hand. This repository owns the production-only
`ssl-proxy` AppProject, one list-generated production workload ApplicationSet,
and all workload desired state after registration. Local development Secrets
and DNS are local-cluster inputs and must never be copied into the production
cluster as a shortcut.

## Layout and applications

Environment-neutral resources live under `base/`. Environment configuration
lives under `matrix/dev/` and `matrix/prod/`.

| Slice | Production application | Responsibility |
|---|---|---|
| `bootstrap` | `ssl-proxy-prod-bootstrap` | Namespace, service account and shared ConfigMaps |
| `data-plane` | `ssl-proxy-prod-data-plane` | TiDB integration, Redpanda, MinIO, Redis, schema execution and telemetry |
| `app-stack` | `ssl-proxy-prod-app-stack` | Proxy, Octopus, Search/UI, sensor and Schema Migrator |

`applicationset-workloads.yaml` creates only those three production
Applications. They track `main`, use automated sync with pruning and
self-healing, and refuse empty desired state. The data-plane entry retains the
StatefulSet PVC-template ignore rule. Namespace deletion requires explicit
confirmation. Dev Applications and dev controllers are prohibited on the
production server.

The control-plane Kustomization also declares the
`ssl-proxy-production-gate` ServiceAccount and its name-scoped Role. That
identity can only get the three generated Applications. The platform team
stores its kubeconfig in Vault and provisions it in Jenkins as
`ssl-proxy-prod-readonly-kubeconfig`; the credential is not a workload Secret.

The same control-plane Kustomization owns K3s's
`kube-system/HelmChartConfig/traefik`. During the default-deny Internet-edge
phase, Traefik exposes only IPv4 TCP 80/443 and has no routing provider,
dashboard route, redirect or certificate resolver. The workload AppProject
cannot create route kinds, and application Services remain `ClusterIP` or
headless. Router and host-firewall state are platform prerequisites documented
in the [operations runbook](../docs/runbook.md); they are not managed through
interactive Kubernetes changes.

## Local Kubernetes development

The aggregate `matrix/dev` Kustomization is the local deployment target. Use an
explicit local context on every command so the production context cannot be
selected accidentally:

```bash
kubectl config get-contexts
kustomize build --load-restrictor LoadRestrictionsNone cyber-stack/matrix/dev \
  | kubectl --context docker-desktop apply --server-side -f -
kubectl --context docker-desktop get pods -n dev-ssl-proxy -o wide
```

Materialize the dev workload Secrets in `dev-ssl-proxy` before applying the
workloads. The wireless sensor also requires a compatible monitor-mode device
and the `ssl-proxy.io/wireless-sensor=true` node label; without them its
DaemonSet intentionally remains unscheduled. Delete local dev with the same
explicit context when its PVC data is no longer needed.

## Configuration rules

- Keep reusable manifests and safe defaults in `base/`; keep environment
  differences in the matching `matrix/<environment>/` patches.
- Put shared non-secret values in the platform ConfigMaps. Every environment
  variable consumed by a workload must have a visible base value, overlay
  patch or Secret/ConfigMap reference in both environments.
- Keep credential values out of Git. Reference the smallest platform-owned
  Secret and key required by each workload.
- Use the standard labels `app.kubernetes.io/name`,
  `app.kubernetes.io/component` and `app.kubernetes.io/managed-by`.
- Pin third-party images to an immutable version. First-party images in the
  canonical environment overlays must use SHA-256 digests.
- Use Argo CD sync waves and hooks for ordering. Do not encode rollout order in
  operator shell commands.
- Treat read-only `kubectl get`, `describe` and `logs` as diagnostics only.
  Desired-state changes always go through Git.

## Image release and promotion

1. Let the private Jenkins `ssl-proxy-images` pipeline publish all first-party
   images from `main` through the unchanged `make publish-all REGISTRY=...`
   interface. For an environment-aware manual publication of the eight
   Kubernetes images, run `make publish ENV=dev` or `make publish ENV=prod`
   (`prod` is the default). This target derives every repository and current pin
   from the selected owning slice and aggregate; `REGISTRY` and image tags do
   not define deployment identity.
2. Use the pushed manifest digest and exact bump command printed by
   environment-aware publication. `MATCH` means the selected Kustomization
   already pins that content; `UNPINNED` still means publication succeeded and
   requires a reviewed `make bump-digest-<service> ENV=dev
   DIGEST=sha256:<digest>` Git change. The helper keeps the owning dev slice and
   local aggregate synchronized.
3. CI must pass `make gitops-check`, documentation checks and component tests.
4. Apply the reviewed dev render to the local cluster and complete the required
   soak and acceptance checks.
5. Open a production pull
   request that copies the exact dev digests into the corresponding prod
   Kustomizations. `scripts/bump-image-digest.sh` and its generated
   `make bump-digest-<service>` targets keep the slice and aggregate render
   aligned.
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
2. Add the resources to the correct dev and prod slice. Use `bootstrap` for
   shared prerequisites, `data-plane` for storage/transport/telemetry, and
   `app-stack` for application workloads.
3. Add environment patches for replicas, resources, endpoints and feature
   gates. Do not put an environment address or credential in the base.
4. Add required ConfigMap and Secret names/keys to the platform input contract.
   Never commit a usable secret value.
5. Add the first-party image to both environment Kustomizations with a digest
   and teach `scripts/bump-image-digest.sh` which slice owns it.
6. Assign the smallest sync wave that satisfies real dependencies. Jobs must
   declare the appropriate Argo CD hook and deletion policy.
7. Update component documentation and run `make gitops-check` plus the targeted
   application tests before opening a pull request.

## Verification and diagnosis

Render and validate every canonical source path:

```bash
make gitops-check
```

Read-only cluster checks:

```bash
export KUBE_CONTEXT="$(kubectl config current-context)"
make recover-stack ENV=prod REGISTRY_PLAIN_HTTP=1
make recover-stack ENV=dev REGISTRY_PLAIN_HTTP=1
kustomize build --load-restrictor LoadRestrictionsNone cyber-stack/matrix/dev >/dev/null
```

`recover-stack` defaults to production and the current Kubernetes context. It
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
or unhealthy workloads. The Secret query emits only type and key names; values
are suppressed. The report never changes Git, registry state, Argo CD or
Kubernetes.

`make production-gate PRODUCTION_GATE_REVISION=<full-main-sha>` is the narrower
CI check. It validates the read-only identity and waits up to 30 minutes for the
three production Applications to report that exact revision as
`Synced/Healthy`. It does not publish or promote images.

When an Application is unhealthy, inspect its conditions, the rendered Git
revision, workload events and container logs. Correct workload manifests in
the appropriate `cyber-stack/base` or environment-overlay Git source and allow
Argo CD to reconcile them. Changes to platform-owned Secrets and the production
TiDB endpoint ConfigMap must instead go through the platform's declarative
control plane; they are prerequisite contracts and are not owned by an
unspecified workload repository.

The current stack-recovery incident is blocked by missing platform-owned
Secrets, not by first-party image publication. Publishing tags again cannot
materialize those prerequisites. Recovery must proceed through the platform's
declarative control plane, after which Argo CD can reconcile the unchanged
digest-pinned workload sources.
