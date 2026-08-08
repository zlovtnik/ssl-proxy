# Production prerequisites

Production uses an externally operated, highly available TiDB deployment. The
prod data-plane overlay intentionally excludes the development-only UniStore
StatefulSet and initialization Jobs.

Before the prod Applications are registered, the platform control plane must
materialize `ssl-proxy-prod-tidb-endpoint` in `prod-ssl-proxy` with these
non-secret keys:

- `TIDB_HOST`
- `TIDB_PORT`
- `TIDB_TLS_SERVER_NAME`
- `SCHEMA_MIGRATOR_TIDB_JDBC_URL`

The same platform workflow must provide the existing TiDB account Secrets and
`tidb-client-ca`. Production approval also requires tested TiDB backup,
restore, failover and recovery procedures with recorded RTO and RPO. No
operator should create or patch these Kubernetes objects interactively.
