# Production prerequisites

Production uses one platform-operated PostgreSQL 16 cluster with the `sync`
database. The repository does not deploy or bootstrap a database server.

Before the prod Applications are registered, the platform control plane must
materialize `ssl-proxy-prod-postgres-endpoint` in `prod-ssl-proxy` with these
non-secret keys:

- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DATABASE`
- `POSTGRES_SSL_MODE`
- `POSTGRES_SSL_SERVER_NAME`

The values must select PostgreSQL database `sync` and verified TLS. They remain
external prerequisites and are not committed here.

The same platform workflow provides the TLS bundle, PgBouncer user list, and
separate owner, Octopus, Atheros Search, schema-migrator, and Keycloak
credentials documented in the platform input contract. No operator should
patch these Kubernetes objects interactively.

The schema executor and Keycloak use the direct endpoint. Octopus, Atheros
Search, and schema-migrator use the in-cluster PgBouncer service. The schema
executor must complete and record matching manifest checksums before the
database-dependent workloads become ready. PgBouncer renders its upstream from
all five endpoint ConfigMap keys and refuses to start unless the TLS mode is
`verify-full` and the certificate server name equals the connection host.

Octopus runs with both runtime lanes, archival, and all 26 Octopus-owned
processors enabled. The bundled Redpanda StatefulSet is a single broker and
the topic manifest uses replication factor one. This is not a highly available
broker topology, but it is an accepted availability tradeoff for the current
Wiretrap deployment and does not disable processing. New consumer groups start
at the earliest retained record; existing groups resume from committed Kafka
offsets. Octopus uses the replication setting only when creating a missing
topic and does not alter an existing topic's replica assignment.
