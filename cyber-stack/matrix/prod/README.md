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

For the Wiretrap address cutover, the platform-owned values must resolve the
external TiDB authority to `192.168.1.242:4000`: `TIDB_HOST` is
`192.168.1.242`, `TIDB_PORT` remains `4000`, and the JDBC URL uses the same
host and port while preserving its database, TLS and connection parameters.
The values remain external prerequisites and are not committed here.

The same platform workflow must provide the existing TiDB account Secrets and
`tidb-client-ca`. Production approval also requires tested TiDB backup,
restore, failover and recovery procedures with recorded RTO and RPO. No
operator should create or patch these Kubernetes objects interactively.

Octopus is deliberately staged with TiDB schema/readiness checks enabled while
its consumer and processor lanes and processor catalog remain disabled. The
staged configuration truthfully declares the bundled Redpanda replication
factor as one. Production validation permits that value only in this fully
disabled stage; any active production runtime still requires a replication
factor of at least three. Octopus uses the setting only when creating a missing
topic and does not alter an existing topic's replica assignment.

The bundled Redpanda StatefulSet is a single broker and its current manifest
provisions replica-one topics, so it is not a production-HA transport. Do not
enable either Octopus runtime lane or any processor until a
three-broker-capable topology, replica placement, and the signed cutover inputs
have been established and verified.
