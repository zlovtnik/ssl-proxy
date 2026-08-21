# Production prerequisites

Production uses the host-operated TiDB instance on Wiretrap. The prod
data-plane overlay excludes the development-only UniStore StatefulSet, but it
owns an idempotent bootstrap hook for the external endpoint before canonical
schema execution.

Before the prod Applications are registered, the platform control plane must
materialize `ssl-proxy-prod-tidb-endpoint` in `prod-ssl-proxy` with these
non-secret keys:

- `TIDB_HOST`
- `TIDB_PORT`
- `SCHEMA_MIGRATOR_TIDB_JDBC_URL`

For the Wiretrap address cutover, the platform-owned values must resolve the
TiDB authority to `192.168.1.242:4000`: `TIDB_HOST` is `192.168.1.242`,
`TIDB_PORT` remains `4000`, and the JDBC URL uses the same host and port with
`sslMode=DISABLED`.
The values remain external prerequisites and are not committed here.

The same platform workflow must provide `tidb-root/password` and the five
password-only account Secrets documented in the platform input contract. The
bootstrap hook tries the configured root password first and may adopt a blank
root only when the endpoint has no application databases or non-root accounts;
it rotates root immediately. No operator should patch these Kubernetes objects
interactively.

This Wiretrap deployment intentionally uses plaintext TiDB transport on a
trusted LAN. Credentials remain mandatory. The host container must use a
persistent named volume, `restart: unless-stopped`, SQL bound to
`192.168.1.242:4000`, and metrics bound to `127.0.0.1:10080`.

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
