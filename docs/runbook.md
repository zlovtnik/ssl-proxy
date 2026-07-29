# Operations Runbook

Use this runbook with the canonical [system architecture](architecture.md).
Deployment-specific commands live in the [Helm](../helm/ssl-proxy/README.md),
[stackctl](../stackctl/README.md) and
[local registry](local-registry-workflow.md) guides.

## Before deployment

1. Initialize nested repositories with `git submodule update --init --recursive`.
2. Run `make docs-check` and the targeted tests for the images being deployed.
3. Confirm the image registry is reachable from the build host and every
   Kubernetes node.
4. Materialize secrets outside Git and verify file permissions.
5. Render the exact Helm values or run `make stackctl-render`.
6. Record the TiDB schema manifest hashes, runtime grants and signed Redpanda
   cutover offsets.
7. Confirm the selected WireGuard profile:
   - `iphone` uses the direct frontdoor path;
   - `linux-shim` uses the local obfuscation shim;
   - Compose declares public UDP `443` and `51820` concurrently.

## Deploy

The umbrella release remains the default:

```bash
make up-ready \
  PROFILE_MODE=iphone \
  SERVER_IP=192.0.2.10 \
  REGISTRY=192.0.2.10:5000
```

The split-release path is opt in:

```bash
make up-ready-stackctl \
  PROFILE_MODE=iphone \
  SERVER_IP=192.0.2.10 \
  REGISTRY=192.0.2.10:5000
```

Replace documentation addresses with real deployment values. Review generated
artifacts before applying them to a production cluster.

## Health and readiness

| Component | Check | Interpretation |
|---|---|---|
| Proxy | `GET /health` on admin port `3002` | Process and tunnel health |
| Proxy | `GET /ready` on admin port `3002` | Required runtime dependencies are ready |
| UDP frontdoor | `GET /health` on host-local `3003` | Frontdoor process and backend status |
| Octopus | `GET /health` or `/actuator/health` on `8081` | TiDB health only |
| Atheros Search | `GET /healthz` on `8080` | Process liveness |
| Atheros Search | `GET /readyz` on `8080` | TiDB, schema, vector and embedding readiness |
| Atheros Search | `GET /v1/etl/health` | Worker/job ETL snapshot |
| Prometheus | `GET /-/ready` on `9090` | Prometheus ready |
| Grafana | `GET /api/health` on `3004` | Grafana process ready |

Octopus does not currently expose `/actuator/prometheus`; its Prometheus target
will be down even when `/health` is green. Atheros Search tracing hooks also do
not currently initialize an exporter.

## Read-only diagnostics

```bash
make diagnose
make db-check-connections
make pipeline-health
make k8s-status
make stackctl-status
```

Use `KUBE_CONTEXT`, `KUBE_NAMESPACE` and `KUBE_RELEASE` when the defaults do
not select the intended cluster. Capture the output with incident timestamps;
do not paste secret values into tickets.

## Data-plane checks

1. Confirm the frontdoor sees packets and pins clients to a healthy backend.
2. Confirm the proxy publishes to Redpanda and its local outbox is not growing.
3. Confirm `sync.scan.request` consumer lag is moving.
4. Confirm Octopus writes topic/partition/offset ingestion evidence in
   `octopus_core`.
5. Confirm `sync.oracle.load` and `sync.oracle.result` progress as TiDB work and
   results; the names do not indicate Oracle.
6. For wireless audit, confirm the sensor publishes `wireless.audit` and the
   matching `sync.scan.request`. The sensor should not have database
   credentials.
7. For embeddings, confirm `search_documents` and `embedding_jobs` exist before
   enabling workers, then check leases, failures, DLQ state and vector counts.

The pinned Octopus runtime does not currently wire search-document/job
preparation, so an idle Search worker may reflect a known producer gap rather
than worker failure.

## Common incidents

### WireGuard handshake fails

- Verify the client profile matches the direct or shim endpoint.
- Check public UDP `443`/`51820`, frontdoor health and backend configuration.
- Confirm server, peer and preshared keys match the staged generation.
- Check MTU: direct defaults to `1420`; obfuscated framing requires room for
  its overhead.

### Proxy healthy but no audit data

- Check `SYNC_REDPANDA_BOOTSTRAP_SERVERS`.
- Inspect proxy outbox growth and publisher health.
- Verify Redpanda topic bootstrap and ACLs.
- Inspect Octopus consumer group offsets and signed cutover gate.

### Sensor has no events

- Confirm Linux monitor mode, interface name, regulatory domain and channel.
- Verify `ATH_SENSOR_REQUIRE_HOST_ENDPOINTS` and the host-reachable Redpanda
  bootstrap address.
- Inspect the sensor local backlog before restarting or deleting anything.

### Octopus health fails

- Verify `TIDB_HOST`, `TIDB_PORT`, `TIDB_DATABASE=octopus_core`, credentials,
  SSL mode, CA path and server name.
- Confirm the canonical manifest and signed cutover artifact.
- Do not fall back to PostgreSQL.

### Search readiness fails

- Validate the native MySQL DSN format, TLS files/server name and manifest hash.
- Confirm the Search account grants.
- Check whether the embedding backend is required for the selected mode.
- In Helm, inspect the rendered Deployment: worker values currently are not
  passed as worker environment variables.

### Missing traces

- Verify that the service actually initializes an exporter, not only that
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
- Check collector receiver/exporter health and Jaeger availability.
- Atheros Search currently has hooks but no exporter initialization.

## Rollback and recovery

Do not delete TiDB schemas, consumer evidence, outboxes or sensor backlogs
during diagnosis. Stop or scale down producers/consumers at a documented
boundary, capture offsets and leases, then roll back only the affected
deployment. Any consumer offset change requires a new signed cutover artifact
and duplicate-delivery review.

For key rotation, use the staged rotator flow in the
[WireGuard key rotator README](../apps/wg-key-rotator/README.md); do not replace
active keys without a candidate health and handshake window.
