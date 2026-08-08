# Operations Runbook

Use this runbook with the canonical [system architecture](architecture.md) and
[Kubernetes GitOps guide](../cyber-stack/README.md). Git is the source of truth;
Argo CD is the only Kubernetes reconciler for this repository.

## Before a change

1. Initialize nested repositories with `git submodule update --init --recursive`.
2. Run `make docs-check`, `make gitops-check` and targeted component tests.
3. Confirm the registry is reachable from the build host, Image Updater and
   every Kubernetes node.
4. Confirm the platform control plane has materialized the required workload
   Secrets and production endpoint ConfigMap without exposing their values.
5. Review the rendered diff for the exact environment slice being changed.
6. Record TiDB schema manifest hashes, runtime grants and signed Redpanda
   cutover offsets when those contracts change.

## Release and promotion

Publish first-party images without changing cluster state:

```bash
make publish-all REGISTRY=192.168.1.221:5000
```

Image Updater opens dev pull requests containing immutable digests. Merge only
after CI and review pass. Wait for the dev `bootstrap`, `data-plane` and
`app-stack` Applications to become `Synced` and `Healthy`.

Production promotion is a separate pull request that copies the accepted dev
digests into the matching prod Kustomizations. Image Updater does not target
prod. After merge, Argo CD reconciles the change automatically.

## Health and readiness

| Component | Check | Interpretation |
|---|---|---|
| Proxy | `GET /health` on admin port `3002` | Process and tunnel health |
| Proxy | `GET /ready` on admin port `3002` | Required runtime dependencies are ready |
| UDP frontdoor | `GET /health` on host-local `3003` | Frontdoor process and backend status |
| Octopus | `GET /live` on `8081` | HTTP process liveness |
| Octopus | `GET /ready` on `8081` | TiDB and enabled processor readiness |
| Octopus | `GET /metrics` on `8081` | Prometheus text metrics |
| Atheros Search | `GET /healthz` on `8080` | Process liveness |
| Atheros Search | `GET /readyz` on `8080` | TiDB, schema, vector and embedding readiness |
| Atheros Search | `GET /v1/etl/health` | Worker/job ETL snapshot |
| Prometheus | `GET /-/ready` on `9090` | Prometheus ready |
| Grafana | `GET /api/health` on `3004` | Grafana process ready |

Atheros Search tracing hooks do not currently initialize an exporter.

## Read-only diagnostics

```bash
kubectl get applications.argoproj.io -n argocd -o wide
kubectl get imageupdaters.argocd-image-updater.argoproj.io -n argocd
kubectl get pods -A -o wide
kubectl get events -A --field-selector type=Warning --sort-by=.lastTimestamp
```

Capture output with incident timestamps and do not paste Secret values into
tickets. Do not use interactive edits, patches, scaling or restarts to repair
drift. Correct Git or the platform prerequisite and let Argo CD reconcile it.

## Data-plane checks

1. Confirm the frontdoor sees packets and pins clients to a healthy backend.
2. Confirm the proxy publishes to Redpanda and its local outbox is not growing.
3. Confirm `sync.scan.request` consumer lag is moving.
4. Confirm Octopus writes topic/partition/offset ingestion evidence in
   `octopus_core`.
5. Confirm `sync.oracle.load` and `sync.oracle.result` progress as TiDB work and
   results; the names do not indicate Oracle.
6. Confirm the sensor publishes `wireless.audit` and the matching
   `sync.scan.request` without database credentials.
7. Confirm `search_documents` and `embedding_jobs` exist before enabling Search
   workers, then check leases, terminal failures and vector counts.

## Common incidents

### WireGuard handshake fails

- Verify the client profile matches the direct or shim endpoint.
- Check public UDP `443`/`51820`, frontdoor health and backend configuration.
- Confirm server, peer and preshared keys match the staged generation.
- Check MTU; obfuscated framing requires room for its overhead.

### Proxy healthy but no audit data

- Check `SYNC_REDPANDA_BOOTSTRAP_SERVERS` in the rendered Kustomize output.
- Inspect proxy outbox growth and publisher health.
- Verify Redpanda topic bootstrap and ACLs.
- Inspect Octopus consumer group offsets and signed cutover gate.

### Sensor has no events

- Confirm Linux monitor mode, interface name, regulatory domain and channel.
- Verify `ATH_SENSOR_REQUIRE_HOST_ENDPOINTS` and the host-reachable Redpanda
  bootstrap address.
- Inspect the sensor local backlog before restarting or deleting anything.

### Octopus health fails

- Verify the rendered TiDB host, port, database, account, SSL mode, CA path and
  server name.
- Confirm the canonical manifest and signed cutover artifact.
- Do not fall back to PostgreSQL.

### Search readiness fails

- Validate the native MySQL DSN, TLS files/server name and manifest hash.
- Confirm the Search account grants and platform-provided Secret keys.
- Check whether the embedding backend is required for the selected mode.
- Inspect the rendered app-stack Kustomization for worker configuration.

### Missing traces

- Verify that the service initializes an exporter, not only that
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
- Check collector receiver/exporter health and Jaeger availability.
- Atheros Search currently has hooks but no exporter initialization.

## Rollback and recovery

Revert the Git commit that introduced the bad desired state and let Argo CD
reconcile the previous digests/configuration. Do not perform a controller-local
rollback that leaves Git stale.

Do not delete TiDB schemas, consumer evidence, outboxes or sensor backlogs
during diagnosis. Stop producers or consumers only through an reviewed Git
change at a documented boundary. Any consumer offset change requires a new
signed cutover artifact and duplicate-delivery review.

For key rotation, use the staged rotator flow in the
[WireGuard key rotator README](../apps/wg-key-rotator/README.md); do not replace
active keys without a candidate health and handshake window.

### Locked-topic partition expansion

The locked sync topics are configured for 24 partitions. An upgrade may add
partitions, but it must not activate consumers against evidence covering only
the old partition set.

1. Stage Octopus with its consumer lane disabled through the app-stack overlay.
2. Merge the topic manifest change and verify all locked topics have 24
   partitions after Argo CD reports healthy.
3. Capture and sign a new cutover artifact covering every partition and group.
4. Enable the coordinator replicas through Git and confirm each signed
   partition is assigned and advancing.
5. Watch lag per partition with `rpk group describe`.

Do not decrease a manifest partition count; Kafka partitions cannot be removed
in place.
