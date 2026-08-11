# ssl-proxy

![License](https://img.shields.io/badge/license-MIT-blue)

ssl-proxy is a WireGuard-first transparent proxy with wireless audit,
Redpanda-backed processing, TiDB persistence and vector search. The Rust proxy
and Linux Atheros Sensor publish events; the Scala Octopus coordinator owns
durable ingestion and maintained projections; the Go Atheros Search service
owns query APIs and embedding workers; and the SolidJS Atheros Search UI is the
Integration Console.

The canonical runtime model and data ownership are documented in
[System Architecture](docs/architecture.md). Kubernetes desired state lives
only in [`cyber-stack/`](cyber-stack/). Production is reconciled by Argo CD;
development is rendered and applied to an explicit local Kubernetes context
with Kustomize.

## Component ownership

| Component | Responsibility | Documentation |
|---|---|---|
| `ssl-proxy` | WireGuard ingress, transparent proxying, classification and sync publishing | [Architecture](docs/architecture.md) |
| `sync-plane` | Shared Redpanda producer configuration and contracts | [`crates/sync-plane/`](crates/sync-plane/) |
| Atheros Sensor | Monitor-mode wireless capture and indirect persistence through Redpanda | [Sensor README](services/atheros-sensor/README.md) |
| Octopus | Durable ingestion, dedupe, evidence, leases, batching, outbox, TiDB load/results and maintained projections | [Octopus README](services/octopus/README.md) |
| Atheros Search | HTTP/gRPC search, ETL health, embedding-job claims and vector writes | [Search README](services/atheros-search/README.md) |
| Integration Console | SolidJS UI for Search, graph, inventory and ETL health | [`atheros-search-ui`](apps/integration-console/atheros-search-ui/) |
| Schema Migrator | Migration authoring/execution and TiDB-backed internal control state | [Schema Migrator README](apps/schema-migrator/README.md) |
| WireGuard key rotator | Staged WireGuard key rotation and optional notifications | [Rotator README](apps/wg-key-rotator/README.md) |

`java-coordinator` remains an image and Kubernetes resource identity for the
Octopus service. Likewise, `sync.oracle.load` and `sync.oracle.result` are
locked legacy topic names; both carry coordinator-owned TiDB work and results.

## Data boundaries

Canonical DDL lives in [`sql/tidb/`](sql/tidb/) for four application databases:

- `octopus_core`
- `atheros_search`
- `integration_console`
- `schema_migrator`

The in-cluster identity service uses a separate `keycloak` database.
PostgreSQL is supported only as an external Schema Migrator target. Oracle is
deprecated compatibility or historical material, not a runtime dependency.

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

Build and publish first-party images to the configured registry with:

```bash
make publish-all REGISTRY=192.168.1.221:5000
```

Publishing does not mutate a cluster. Record new dev digests with the
`make bump-digest-<service>` targets, validate them on the local cluster, then
copy the exact tested digests in a separate production promotion pull request. See the
[GitOps guide](cyber-stack/README.md) and [operations runbook](docs/runbook.md).

## Local development

Docker Compose is an optional local test harness only. It is not a Kubernetes
management, promotion or production workflow.

```bash
REGISTRY=local IMAGE_TAG=dev \
  docker compose -f docker-compose.yaml -f docker-compose.build.yaml up -d --build
```

For local Kubernetes development, render and apply
`cyber-stack/matrix/dev` only with an explicit local context as documented in
the [GitOps guide](cyber-stack/README.md). Production readiness is determined
from the prod Argo CD Applications.

## Topic contracts

| Topic | Current meaning |
|---|---|
| `sync.scan.request` | Producer-to-Octopus work discovery |
| `sync.oracle.load` | Octopus-owned TiDB load dispatch; legacy name |
| `sync.oracle.result` | Octopus-owned TiDB load outcome; legacy name |
| `wireless.audit` | Sensor-published schema-versioned wireless events |

Delivery is at least once after the signed cutover boundary, with durable TiDB
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
- [TiDB runtime and cutover](docs/tidb-runtime-cutover.md)
- [Observability architecture](docs/observability-architecture-jaeger.md)
- [Secret management](docs/secret-management.md)
- [Threat model](docs/threat-model.md)
