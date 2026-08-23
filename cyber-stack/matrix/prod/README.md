# Production prerequisites

Production uses the host-operated PostgreSQL instance on Wiretrap. The prod
data-plane overlay excludes the development-only UniStore StatefulSet, but it
owns an idempotent bootstrap hook for the external endpoint before canonical
schema execution.

Before the prod Applications are registered, the platform control plane must
materialize `ssl-proxy-prod-postgres-endpoint` in `prod-ssl-proxy` with these
non-secret keys:

- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `SCHEMA_MIGRATOR_POSTGRES_JDBC_URL`

For the Wiretrap address cutover, the platform-owned values must resolve the
PostgreSQL authority to `192.168.1.242:4000`: `POSTGRES_HOST` is `192.168.1.242`,
`POSTGRES_PORT` remains `4000`, and the JDBC URL uses the same host and port with
`sslMode=DISABLED`.
The values remain external prerequisites and are not committed here.

The same platform workflow must provide `postgres-root/password` and the five
password-only account Secrets documented in the platform input contract. The
bootstrap hook tries the configured root password first and may adopt a blank
root only when the endpoint has no application databases or non-root accounts;
it rotates root immediately. No operator should patch these Kubernetes objects
interactively.

This Wiretrap deployment intentionally uses plaintext PostgreSQL transport on a
trusted LAN. Credentials remain mandatory. The host container must use a
persistent named volume, `restart: unless-stopped`, SQL bound to
`192.168.1.242:4000`, and metrics bound to `127.0.0.1:10080`.

Octopus runs with both runtime lanes, archival, and all 26 Octopus-owned
processors enabled. The bundled Redpanda StatefulSet is a single broker and
the topic manifest uses replication factor one. This is not a highly available
broker topology, but it is an accepted availability tradeoff for the current
Wiretrap deployment and does not disable processing. New consumer groups start
at the earliest retained record; existing groups resume from committed Kafka
offsets. Octopus uses the replication setting only when creating a missing
topic and does not alter an existing topic's replica assignment.
