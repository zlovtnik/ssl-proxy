# ssl-proxy

![License](https://img.shields.io/badge/license-MIT-blue)

ssl-proxy is a WireGuard-first transparent proxy with wireless audit,
Redpanda-backed processing, PostgreSQL persistence and vector search. The Rust proxy
and Linux Atheros Sensor publish events; the Scala Octopus coordinator owns
durable ingestion and maintained projections; the Go Atheros Search service
owns query APIs and embedding workers; and the SolidJS Atheros Search UI is the
Integration Console.

The canonical runtime model and data ownership are documented in
[System Architecture](docs/architecture.md). Kubernetes desired state lives
only in [`cyber-stack/`](cyber-stack/). Production is reconciled by Argo CD.

## Component ownership

| Component | Responsibility | Documentation |
|---|---|---|
| `ssl-proxy` | WireGuard ingress, transparent proxying, classification and sync publishing | [Architecture](docs/architecture.md) |
| `sync-plane` | Shared Redpanda producer configuration and contracts | [`crates/sync-plane/`](crates/sync-plane/) |
| Atheros Sensor | Monitor-mode wireless capture and indirect persistence through Redpanda | [Sensor README](services/atheros-sensor/README.md) |
| Octopus | Durable ingestion, dedupe, evidence, leases, batching, outbox, PostgreSQL load/results and maintained projections | [Octopus README](services/octopus/README.md) |
| Atheros Search | HTTP/gRPC search, ETL health, embedding-job claims and vector writes | [Search README](services/atheros-search/README.md) |
| Integration Console | SolidJS UI for Search, graph, inventory and ETL health | [`atheros-search-ui`](apps/integration-console/atheros-search-ui/) |
| Schema Migrator | Migration authoring/execution and PostgreSQL-backed internal control state | [Schema Migrator README](apps/schema-migrator/README.md) |
| WireGuard key rotator | Staged WireGuard key rotation and optional notifications | [Rotator README](apps/wg-key-rotator/README.md) |

`java-coordinator` remains an image and Kubernetes resource identity for the
Octopus service. Likewise, `sync.oracle.load` and `sync.oracle.result` are
locked legacy topic names; both carry coordinator-owned PostgreSQL work and results.

## Data boundaries

Canonical DDL lives in [`sql/postgres/`](sql/postgres/) for four schemas in the
external `sync` database:

- `octopus_core`
- `atheros_search`
- `schema_migrator`
- `keycloak`

The Integration Console is database-free. Oracle remains deprecated external
target compatibility in Schema Migrator, not a stack runtime dependency.

## Get started

Initialize every nested repository first:

```bash
git submodule update --init --recursive
```

Run the targeted tests for the components you change. Validate all canonical
GitOps inputs with:

```bash
make docs-check
make gitops-check
```

Publish the eight Kubernetes images to the repositories selected by the
canonical environment (`prod` by default), then compare their pushed digests
with the committed pins:

```bash
make publish ENV=prod REGISTRY_PLAIN_HTTP=1
```

Jenkins, component publishing, and the Compose-only key rotator retain
`make publish-all REGISTRY=192.168.1.242:5000 REGISTRY_PLAIN_HTTP=1`. Publishing changes registry
tags only; it does not mutate Git or a cluster. Diagnose desired and live state
read-only with `make stack-health`; it uses the active Kubernetes
context unless `KUBE_CONTEXT` is explicitly set. Record
new dev digests with the printed `make bump-digest-<service>` commands, validate
them on the local cluster, then copy the exact tested digests in a separate
production promotion pull request. See the [GitOps guide](cyber-stack/README.md)
and [operations runbook](docs/runbook.md).

## Local development

Database integration tests use ephemeral PostgreSQL 16 Testcontainers. No
development database or database Compose stack is bundled.

```bash
(cd services/octopus && sbt test)
(cd apps/schema-migrator && sbt test)
```

Production readiness is determined from the production Argo CD Applications.

## Topic contracts

| Topic | Current meaning |
|---|---|
| `sync.scan.request` | Producer-to-Octopus work discovery |
| `sync.oracle.load` | Octopus-owned PostgreSQL load dispatch; legacy name |
| `sync.oracle.result` | Octopus-owned PostgreSQL load outcome; legacy name |
| `wireless.audit` | Sensor-published schema-versioned wireless events |

Delivery is at least once from committed Kafka consumer-group offsets, with durable PostgreSQL
dedupe and topic/partition/offset evidence.

## Common checks

```bash
cargo test -p ssl-proxy
cargo test -p sync-plane
cargo test -p atheros-sensor
(cd services/atheros-search && go test ./...)
(cd services/octopus && sbt test)
(cd apps/schema-migrator && sbt test)
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

## Operational references

- [GitOps management and onboarding](cyber-stack/README.md)
- [Jenkins image CI](docs/jenkins-ci.md)
- [System architecture](docs/architecture.md)
- [Operations runbook](docs/runbook.md)
- [Observability architecture](docs/observability-architecture-jaeger.md)
- [Secret management](docs/secret-management.md)
- [Threat model](docs/threat-model.md)
