# Production prerequisites

Production uses one platform-operated PostgreSQL 16/pgvector cluster with the
`sync` database. Its exact value-free server and secret-control-plane bootstrap
requirements are pinned in `../../platform-input-contract.yaml`. The repository
does not deploy the database server, run Vault or write the resulting inputs.
The PostgreSQL container must provide at least 1 GiB of shared memory so the
parallel projection queries cannot exhaust Docker's 64 MiB default `/dev/shm`.

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

The same platform workflow provides the upstream PostgreSQL CA, the distinct
`pgbouncer-listener-tls` certificate bundle (`ca.crt`, `tls.crt`, `tls.key`),
PgBouncer user list, and
separate owner, Octopus, Atheros Search, schema-migrator, and Keycloak
credentials documented in the platform input contract. No operator should
patch these Kubernetes objects interactively.

The schema executor and Keycloak use the direct endpoint. Octopus, Atheros
Search, and schema-migrator use the in-cluster PgBouncer service with
`sslmode=verify-full` and only the listener CA mounted. PgBouncer requires TLS
from clients and verifies its upstream PostgreSQL certificate with
`verify-full`; only PgBouncer mounts the listener certificate and private key.
The schema
executor must complete and record matching manifest checksums before the
database-dependent workloads become ready. PgBouncer renders its upstream from
all five endpoint ConfigMap keys and refuses to start unless the TLS mode is
`verify-full` and the certificate server name equals the connection host.

NetworkPolicies remain a release gate only when the installed CNI enforces them.
Before rollout completion, capture read-only evidence that Calico, Cilium, or
kube-router is ready on every node and run an approved enforcement probe. Do not
install or modify the CNI from this repository.

Octopus runs with both runtime lanes, archival, and all 26 Octopus-owned
processors enabled. The bundled Redpanda StatefulSet is a single broker and
the topic manifest uses replication factor one. This is not a highly available
broker topology, but it is an accepted availability tradeoff for the current
Wiretrap deployment and does not disable processing. New consumer groups start
at the earliest retained record; existing groups resume from committed Kafka
offsets. Octopus uses the replication setting only when creating a missing
topic and does not alter an existing topic's replica assignment.
