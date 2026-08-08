# Argo CD + Kustomize Workmap — ssl-proxy

## Architecture

Split into three Argo CD Applications for blast-radius control:

| Application | Path | Purpose |
|---|---|---|
| `bootstrap` | `cyber-stack/matrix/dev/bootstrap` | Namespace, ServiceAccount, ConfigMap (platform-config) |
| `data-plane` | `cyber-stack/matrix/dev/data-plane` | TiDB, Redpanda, MinIO, Redis, telemetry, tidb-schema-executor |
| `app-stack` | `cyber-stack/matrix/dev/app-stack` | Schema-migrator, proxy, java-coordinator, atheros-sensor, atheros-search |

The Applications deploy `cyber-stack/matrix/dev/bootstrap`, `cyber-stack/matrix/dev/data-plane`, and `cyber-stack/matrix/dev/app-stack`, respectively, with `targetRevision: dev` and `directory.recurse: false`. The `bootstrap` Application must sync and become healthy before `data-plane` and `app-stack`. Sync waves handle ordering within each Application.

## Sync Waves

### bootstrap

| Wave | Resources |
|---|---|
| `-2` | Namespace |
| `-1` | ServiceAccount, ConfigMap (platform-config) |

### data-plane

| Wave | Resources |
|---|---|
| `0` | TiDB, Redpanda, MinIO, Redis, telemetry |
| `1` | tidb-schema-executor Job |

### app-stack

| Wave | Resources |
|---|---|
| `0` | proxy, java-coordinator, atheros-sensor, atheros-search |
| `1` | schema-migrator keycloak, traefik, configmaps |
| `2` | bootstrap-job |
| `3` | schema-migrator backend, ui |
| `4` | validate-job (PostSync hook) |

## Secrets (19 total, Sealed Secrets)

| Secret | Keys | Consumers |
|---|---|---|
| tidb-root | password | TiDB init job |
| tidb-octopus | password | TiDB SS, java-coordinator |
| tidb-atheros-search | password, dsn | TiDB SS, atheros-search |
| tidb-schema-migrator | password | TiDB SS, schema-migrator backend |
| tidb-keycloak | password | TiDB SS, keycloak |
| tidb-schema-owner | dsn | tidb-schema-executor job |
| tidb-client-ca | ca.crt | 5 workloads (volume) |
| ssl-proxy-tidb-server-tls | tls.crt, tls.key | TiDB SS |
| minio-credentials | access-key, secret-key | MinIO SS, java-coordinator |
| schema-migrator-backend | encrypt-key, jwt-secret, api-bearer-token | schema-migrator backend |
| schema-migrator-keycloak | database-password, bootstrap-admin-password | keycloak, bootstrap-job |
| schema-migrator-bootstrap | application-admin-password | bootstrap-job |
| redis-runtime | password | redis deployment |
| proxy-admin-key | api-key | proxy deployment |
| proxy-runtime-secrets | wg-obfuscation-key | proxy deployment (volume) |
| ssl-proxy-identity-tls | tls.crt, tls.key | traefik (volume) |
| observability-credentials | grafana-admin-password, loki-username, loki-password, loki-htpasswd | grafana, Alloy, Loki auth proxy |
| atheros-credentials | api-token-sha256 | atheros-search |
| wireguard-config | server.conf, keys, peer configs | proxy deployment (projected volume) |

## Cutover Sequence

1. Install Argo CD on target cluster
2. Create `argocd` namespace + apply AppProject
3. Provision all 19 secrets via Sealed Secrets
4. Add sync-wave/hook annotations to base manifests (this workmap)
5. Apply bootstrap Application and confirm it is healthy
6. Apply data-plane Application (manual sync first)
7. Confirm TiDB/Redpanda/MinIO healthy + tidb-schema-executor completed
8. Apply app-stack Application (manual sync first)
9. Confirm bootstrap-job + validate-job completed, backend healthy
10. Enable automated sync on all three Applications
11. Set up notifications

## Files

```
cyber-stack/argocd/
  README.md                           # this file
  appproject-ssl-proxy.yaml           # AppProject
  application-bootstrap.yaml          # bootstrap Application
  application-data-plane.yaml         # data-plane Application
  application-app-stack.yaml          # app-stack Application
```
