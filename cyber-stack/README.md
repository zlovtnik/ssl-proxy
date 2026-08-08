# Kubernetes GitOps Guide

This directory is the only source of Kubernetes desired state for ssl-proxy.
Kustomize renders the manifests and Argo CD reconciles them from the `main`
branch. Configuration, releases, rollbacks and workload onboarding happen by
reviewed Git changes. Direct mutation of managed resources is prohibited.

## Ownership boundary

The platform team provides and operates:

- Argo CD and Argo CD Image Updater 1.1 or newer;
- registration of `cyber-stack/argocd` as this repository's control-plane path;
- `ssl-proxy-image-updater-git` in the `argocd` namespace, using a GitHub App
  or scoped token that can create image-update pull requests;
- registry access for `192.168.1.221:5000`;
- workload Secrets and the production TiDB endpoint ConfigMap required by the
  rendered manifests.

Platform inputs must be delivered by the platform's declarative control plane.
Do not create or patch them by hand. This repository owns the `ssl-proxy`
AppProject, six workload Applications, the dev ImageUpdater resource, and all
workload desired state after registration.

## Layout and applications

Environment-neutral resources live under `base/`. Environment configuration
lives under `matrix/dev/` and `matrix/prod/`. Each environment has three Argo
CD source paths:

| Slice | Dev application | Prod application | Responsibility |
|---|---|---|---|
| `bootstrap` | `ssl-proxy-bootstrap` | `ssl-proxy-prod-bootstrap` | Namespace, service account and shared ConfigMaps |
| `data-plane` | `ssl-proxy-data-plane` | `ssl-proxy-prod-data-plane` | TiDB integration, Redpanda, MinIO, Redis, schema execution and telemetry |
| `app-stack` | `ssl-proxy-app-stack` | `ssl-proxy-prod-app-stack` | Proxy, Octopus, Search/UI, sensor and Schema Migrator |

All Applications track `main`, use automated sync with pruning and
self-healing, and refuse empty desired state. Namespace deletion requires
explicit prune confirmation. Sync-wave annotations order resources inside an
Application; the platform must register and verify `bootstrap` before the
other two Applications during first installation.

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

1. Publish all first-party images with `make publish-all`. The build publishes
   the immutable commit tag and updates the registry's `latest` channel.
2. Dev Image Updater observes `latest` with the `digest` strategy and opens a
   GitHub pull request that updates the relevant dev Kustomization.
3. CI must pass `make gitops-check`, documentation checks and component tests.
4. Merge the dev pull request and wait for all three dev Applications to be
   `Synced` and `Healthy`.
5. After the required dev soak and acceptance checks, open a production pull
   request that copies the exact dev digests into the corresponding prod
   Kustomizations. Image Updater never targets prod Applications.
6. Merge the production pull request and verify all three prod Applications.

Rollback is a Git revert of the promotion commit. Argo CD reconciles the prior
digests automatically. Do not use a controller-local rollback that leaves Git
describing a different state.

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
5. Add the first-party image to both environment Kustomizations with a digest.
   If it should advance automatically in dev, add it to the dev ImageUpdater
   resource with an explicit Kustomize target name and `digest` strategy.
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
kubectl get applications.argoproj.io -n argocd -o wide
kubectl get imageupdaters.argocd-image-updater.argoproj.io -n argocd
kubectl get pods -n dev-ssl-proxy -o wide
kubectl get pods -n prod-ssl-proxy -o wide
kubectl get events -A --field-selector type=Warning --sort-by=.lastTimestamp
```

When an Application is unhealthy, inspect its conditions, the rendered Git
revision, workload events and container logs. Correct the source manifest or
platform prerequisite in Git and allow reconciliation to repair the cluster.
