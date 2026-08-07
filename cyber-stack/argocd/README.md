# Argo CD + Kustomize Workmap — ssl-proxy

## Architecture

Split into two Argo CD Applications for blast-radius control:

| Application | Path | Purpose |
|---|---|---|
| `data-plane` | `cyber-stack/matrix/prod` | Namespace, platform-config, TiDB, Redpanda, MinIO, Redis, telemetry, tidb-schema-executor |
| `app-stack` | `cyber-stack/matrix/prod` | Schema-migrator, proxy, java-coordinator, atheros-sensor, atheros-search |

Both Applications point at the same kustomize overlay (`cyber-stack/matrix/prod`) but use `directory.include` to filter which resources they manage. Sync waves handle ordering within each Application.

## Sync Waves

### data-plane

| Wave | Resources |
|---|---|
| `-2` | Namespace |
| `-1` | ServiceAccount, ConfigMap (platform-config) |
| `0` | TiDB, Redpanda, MinIO, Redis, telemetry |
| `1` | tidb-schema-executor Job (PreSync hook) |

### app-stack

| Wave | Resources |
|---|---|
| `0` | proxy, java-coordinator, atheros-sensor, atheros-search |
| `1` | schema-migrator keycloak, traefik, configmaps |
| `2` | bootstrap-job (PreSync hook) |
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
| observability-credentials | grafana-admin-password | grafana |
| atheros-credentials | api-token-sha256 | atheros-search |
| wireguard-config | server.conf, keys, peer configs | proxy deployment (projected volume) |

## Cutover Sequence

1. Install Argo CD on target cluster
2. Create `argocd` namespace + apply AppProject
3. Provision all 19 secrets via Sealed Secrets
4. Add sync-wave/hook annotations to base manifests (this workmap)
5. Apply data-plane Application (manual sync first)
6. Confirm TiDB/Redpanda/MinIO healthy + tidb-schema-executor completed
7. Apply app-stack Application (manual sync first)
8. Confirm bootstrap-job + validate-job completed, backend healthy
9. Enable automated sync on both Applications
10. Set up notifications

## Files

```
cyber-stack/argocd/
  README.md                           # this file
  appproject-ssl-proxy.yaml           # AppProject
  application-data-plane.yaml         # data-plane Application
  application-app-stack.yaml          # app-stack Application
```
