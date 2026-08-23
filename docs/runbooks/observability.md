# Observability runbook

The production observability stack is reconciled from `cyber-stack/`. Diagnose
with read-only queries and repair desired state through reviewed Git changes.

## Scrape target down

Open the Fleet Availability dashboard, identify the failed `job` and
`instance`, then inspect the matching workload, Service endpoints, and recent
events. A missing target generally indicates discovery or Service drift; a
present target returning errors points to the workload or its NetworkPolicy.

## Probe failed

Compare `probe_http_status_code`, `probe_duration_seconds`, and
`probe_ip_protocol` for the catalog entry. HTTP probes must use the workload's
readiness route. TCP probes only prove that the expected listener accepts a
connection.

## Telemetry pipeline

Check Prometheus, Alertmanager, the OTel collector, Jaeger, Loki, and Alloy in
that order. Collector exporter failures are visible on the Tracing & Jaeger
dashboard. Alertmanager uses the platform-owned webhook URL file; never print
that file while diagnosing delivery.

## Target absent

Render the affected environment and verify that its generated Prometheus
ConfigMap has a content hash and the expected scrape job. Confirm that the
workload references the same hash-named ConfigMap.

## Workload unavailable

Compare desired and ready replicas, pod conditions, and namespace events.
Investigate failed init containers and readiness gates before changing resource
limits.

## Restart loop

Inspect the previous container status and bounded recent logs. Preserve the
original termination reason and fix the Git-managed configuration or image.

## OOM

Use the Infrastructure Capacity dashboard to compare working set and limit.
For Jaeger, also check Badger PVC pressure and trace ingestion volume before
changing the production 512 MiB request or 2 GiB limit.

## Job failed

Inspect the failed Job's pod status and logs. Schema and initialization Jobs are
ordered by Argo CD waves and must not be rerun through interactive cluster
mutation.

## Sensor metrics stale

Confirm the sensor DaemonSet is running on the affected node and that
`/var/lib/node_exporter/textfile_collector/atheros_sensor.prom` is being
atomically refreshed. The sensor HTTP listener intentionally remains
loopback-only.

## Node saturation

Identify sustained CPU or memory pressure, then correlate it with container
usage and workload limits. Short spikes below the alert duration do not require
action.

## Storage pressure

Identify the filesystem or PVC with low free space. Do not delete archived
Jaeger v1 data: its PVC is intentionally unmounted and protected from pruning.

## Redpanda

Check broker `up`, leadership, partition, and reactor metrics. Use the Redpanda
dashboard to distinguish an unavailable admin endpoint from replication or
capacity trouble.

## Redpanda replication

Locate the under-replicated partitions and check broker readiness and disk
pressure. Preserve the repository's locked topic contracts and replication
settings.

## Redpanda errors

Correlate Kafka RPC handler errors with throughput and request latency. Inspect
producer and consumer logs using bounded time windows.

## Redpanda stalls

Reactor stalls usually accompany CPU, disk, or memory pressure. Correlate the
stall increase with node capacity before changing broker configuration.

## Redpanda latency

Use request type and broker dimensions to find the slow path. Check storage and
replication health before adjusting clients.

## Redpanda capacity

Determine whether disk or memory crossed the threshold and whether the problem
is isolated to one broker. Capacity changes remain Git-managed.

## PostgreSQL

In dev, Prometheus discovers the bundled `:10080` Service endpoint. In prod,
the host-network bridge must be scheduled on a node labelled
`ssl-proxy.io/postgres-host=true`, scrape `127.0.0.1:10080`, and remote-write to the
cluster Prometheus Service.

## PostgreSQL connections

Compare active and maximum connections with application pool use. Identify the
owning service before adjusting isolated pool settings.

## PostgreSQL latency

Correlate p95 query latency with QPS, transaction, lock, and application call
metrics. Metric labels must never contain raw SQL.

## PostgreSQL errors

Inspect bounded PostgreSQL error/deadlock metrics and correlated application logs.
Database repair and schema changes must follow the repository's provisioning
contracts.

## Trace export

Compare accepted, sent, failed, and dropped spans at each OTel pipeline stage.
Spanmetrics are produced before tail sampling, so missing RED metrics indicate
an ingest problem rather than expected sampling.

## Jaeger memory

Check working set, container limit, span ingest rate, and Badger pressure. Error
and slow traces are retained at 100 percent plus a 10 percent baseline sample.

## Traces absent

Verify the service OTLP endpoint and service name, then check collector accepted
spans and exporter failures. Expected service names are `atheros-search` and
`java-coordinator`.

## Jaeger restarts

Inspect the previous termination reason and v2 health endpoint. The v2 Badger
store is mounted at the new 10 GiB PVC; the archived v1 PVC must remain
unmounted.

## Jaeger storage

Confirm seven-day retention is active and identify unexpected ingestion growth.
Do not prune the archived v1 PVC as a capacity workaround.

## Jenkins

Confirm the private controller is reachable and `/prometheus/` authenticates
with the dedicated scrape identity. That identity has only `Overall/Read`,
`Metrics/View`, and `Job/Read` on `ssl-proxy-images`.

## Jenkins executor

Check controller and Docker-in-Docker health, executor state, and the current
pipeline before changing executor capacity.

## Jenkins queue

Inspect queue causes and executor availability. A change-driven idle pipeline is
informational; queued work older than ten minutes is actionable.

## Jenkins stuck

Compare the running build duration with recent successful duration percentiles,
then inspect the active stage. Do not trigger or cancel builds with the scrape
identity.

## Jenkins build result

Open the latest `ssl-proxy-images` build and address its first failed stage.
Production promotion remains a reviewed Git change.

## Traefik

The platform edge is route-free and should return only the configured
default-deny response. Investigate any non-404 response or sustained request
flood without enabling interactive routes.
