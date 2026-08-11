# Operations Runbook

Use this runbook with the canonical [system architecture](architecture.md) and
[Kubernetes GitOps guide](../cyber-stack/README.md). Git is the source of truth;
Argo CD is the production reconciler and local development uses an explicit
local Kustomize context.

## Before a change

1. Initialize nested repositories with `git submodule update --init --recursive`.
2. Run `make docs-check`, `make gitops-check` and targeted component tests.
3. Confirm the registry is reachable from the build host and every Kubernetes
   node.
4. Confirm the platform control plane has materialized the required workload
   Secrets and production endpoint ConfigMap without exposing their values.
5. Review the rendered diff for the exact environment slice being changed.
6. Record TiDB schema manifest hashes, runtime grants and signed Redpanda
   cutover offsets when those contracts change.

## Release and promotion

The private Jenkins `ssl-proxy-images` pipeline publishes `main` after its
delivery checks pass through the unchanged registry-directed `publish-all`
interface. For an authorized manual rebuild of the eight Kubernetes images,
publish to the repositories selected by the canonical environment without
changing Git or cluster state:

```bash
make publish ENV=dev REGISTRY_PLAIN_HTTP=1
```

`make publish` defaults to production, derives repositories and pins from the
selected Kustomize slice and aggregate, and reports each pushed digest as
`MATCH` or `UNPINNED`. Use its exact bump command to record an immutable dev
digest. `UNPINNED` does not fail publication. Merge only after CI and review
pass, then apply the dev aggregate to an explicit local context and complete
its acceptance checks. Jenkins and the Compose-only key rotator continue to use
`make publish-all REGISTRY=192.168.1.221:5000 REGISTRY_PLAIN_HTTP=1`.

Production promotion is a separate pull request that copies the accepted dev
digests into the matching prod Kustomizations. After merge, Argo CD reconciles
the change automatically. Kubernetes uses the committed digest references, not
the mutable commit or `latest` registry tags.

## Health and readiness

| Component | Check | Interpretation |
|---|---|---|
| Proxy | `GET /health` on admin port `3002` | Process and tunnel health |
| Proxy | `GET /ready` on admin port `3002` | Required runtime dependencies are ready |
| UDP frontdoor | `GET /health` on host-local `3003` | Frontdoor process and backend status |
| Octopus | `GET /live` on `8081` | HTTP process liveness |
| Octopus | `GET /ready` on `8081` | TiDB and enabled processor readiness |
| Octopus | `GET /metrics` on `8081` | Prometheus text metrics |
| Octopus Service | `GET /live` on `ssl-proxy-java-coordinator:8080` | Service port `8080` routes to pod target port `8081` |
| Octopus Service | `GET /ready` on `ssl-proxy-java-coordinator:8080` | Service-routed dependency readiness |
| Octopus Service | `GET /metrics` on `ssl-proxy-java-coordinator:8080` | Service-routed Prometheus metrics |
| Atheros Search | `GET /healthz` on `8080` | Process liveness |
| Atheros Search | `GET /readyz` on `8080` | TiDB, schema, vector and embedding readiness |
| Atheros Search | `GET /v1/etl/health` | Worker/job ETL snapshot |
| Prometheus | `GET /-/ready` on `9090` | Prometheus ready |
| Grafana | `GET /api/health` on `3004` | Grafana process ready |

Atheros Search tracing hooks do not currently initialize an exporter.

## Read-only diagnostics

```bash
make recover-stack ENV=prod KUBE_CONTEXT=wiretrap-k3s REGISTRY_PLAIN_HTTP=1
```

The target defaults to `ENV=prod` and the current context, and prominently
prints the resolved context and namespace. It renders all canonical slices,
reports Git and production Argo revisions, inventories desired and live images
including init containers and runtime IDs, lists required Secret names and
presence only, and includes workload health and recent warnings. It prints the
whole report before returning nonzero for blockers. Registry tag lookup failure
is reported as `UNKNOWN` and does not by itself fail recovery. Dev reports skip
Argo because dev Applications are prohibited on the production controller.

Capture the report with incident timestamps and do not paste Secret values into
tickets. Do not use interactive edits, patches, scaling or restarts to repair
drift. Correct Git or the platform prerequisite and let Argo CD reconcile it.

The current recovery incident is blocked by missing platform-owned Secrets,
not by first-party publication. Republishing `$TAG` or `latest` cannot satisfy
that contract. Have the platform declarative control plane materialize the
required Secret names, then rerun `make recover-stack`; do not create or patch
the Secrets interactively.

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
during diagnosis. Stop producers or consumers only through a reviewed Git
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

### Redpanda retained chart data-path migration

New installations using
`helm/ssl-proxy/charts/redpanda/templates/statefulset.yaml` mount the data volume
at Redpanda's default `/var/lib/redpanda/data` path. An older installation may
instead have mounted its volume at `/data`, leaving live broker data in the
container filesystem. Applying the new mount to such a pod without migration
can make the replacement broker initialize from an empty volume.

Before promoting this change to an existing cluster, choose and record one of
these paths:

1. For a disposable cluster, approve a recreate through the reviewed desired
   state and explicitly accept loss of the old broker data.
2. For retained data, quiesce producers and consumers through Git, take a
   verified broker backup, and have the storage operator copy the old broker
   contents into the persistent volume so that they appear at
   `/var/lib/redpanda/data`, preserving ownership and permissions. Apply the
   reviewed path change only after the copy and backup are verified.

After reconciliation, confirm the broker recognizes the existing cluster and
topics before re-enabling producers or consumers. If the old data cannot be
copied or restored, stop the rollout; do not accept an apparently healthy but
empty broker as a successful migration.
