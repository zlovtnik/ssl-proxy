# Observability Workmap (Non-Vector Services)

> **Status: Historical workmap.** Preserve this rollout record for provenance.
> The current signal topology and known instrumentation gaps are documented in
> [Observability Architecture](observability-architecture-jaeger.md) and
> [System Architecture](architecture.md).

## Scope

This rollout adds Grafana + Loki + Jaeger + Prometheus across all non-vector services in `docker-compose.yaml`.

In scope:

- `ssl-proxy`
- `java-coordinator`, `java-coordinator-2`, `java-coordinator-3`
- `atheros-sensor`
- `redpanda`
- `minio`
- `redpanda-init`
- `minio-init`

Explicitly excluded from this rollout:

- `vec-worker`, `vec-worker-2`, `vec-worker-3`, `vec-worker-4`
- `ollama`
- any `vector.toml` pipeline changes

## Target-State Signal Path

`workers/services -> OTLP gRPC -> OTel Collector -> Jaeger -> Grafana`

`stdout JSON -> Promtail -> Loki -> Grafana`

`/metrics or exporters -> Prometheus -> Grafana (+ alert rules)`

## Wave Plan

### Wave 0 - Platform bootstrap (compose + config)

Delivered in this pass:

- `docker-compose.yaml` services: `prometheus`, `loki`, `promtail`, `jaeger`, `otel-collector`, `grafana`, `postgres-exporter`, `pushgateway`
- `docker/observability/prometheus.yml`
- `docker/observability/alerts.yml`
- `docker/observability/loki.yml`
- `docker/observability/promtail.yml`
- `docker/observability/otel-collector.yml`
- Grafana provisioning:
  - `docker/observability/grafana/provisioning/datasources/datasources.yml`
  - `docker/observability/grafana/provisioning/dashboards/dashboards.yml`
  - dashboards under `docker/observability/grafana/dashboards/`
- Prometheus scrape targets for `java-coordinator` are active and covered by critical "service down" alert rules

### Wave 1 - Telemetry contract (common schema)

Required log fields for app services:

- `timestamp`
- `level`
- `service`
- `instance`
- `trace_id`
- `span_id`
- `event`
- `error`

Required trace resource attributes:

- `service.name`
- `service.version`
- `deployment.environment`
- `compose.service`

Metrics contract:

- service-level prefixing (for example: `ssl_proxy_*`, `coordinator_*`)
- low-cardinality labels only (no request ids, no user ids, no high-cardinality path fragments)

### Wave 2 - App instrumentation status (non-vector)

| Service | Logs | Metrics | Traces | Status |
|---|---|---|---|---|
| `ssl-proxy` | JSON stdout (existing) | `/metrics` admin path (existing) | OTLP env contract wired | platform wired |
| `java-coordinator*` | JSON logback output enabled | `/actuator/prometheus` (existing) | OTLP env contract wired | platform wired |
| `redpanda-init` | structured JSON logs in `bootstrap.sh` | Pushgateway one-shot metrics (`observability_job_*`) | no long-lived traces required | platform wired |
| `minio-init` | structured JSON logs in `init.sh` | Pushgateway one-shot metrics (`observability_job_*`) | no long-lived traces required | platform wired |
| `atheros-sensor` | JSON stdout (existing) | `/metrics` enabled via `ATH_SENSOR_METRICS_PORT` | OTLP env contract wired | platform wired |

### Wave 3 - Infra coverage

Delivered in this pass:

- `redpanda` scrape target on `:9644`
- `postgres-exporter` and scrape
- `minio` scrape target on `/minio/v2/metrics/cluster`
- log collection for infra containers through Promtail

### Wave 4 - Grafana correlation + alerting

Delivered in this pass:

- Provisioned Prometheus/Loki/Jaeger datasources
- Loki derived field for `trace_id -> Jaeger trace URL`
- Dashboards:
  - stack health overview
  - per-service RED metrics
  - sync pipeline latency/failures
  - coordinator Oracle load lifecycle
  - infra saturation
- Critical alert pack in `docker/observability/alerts.yml`:
  - service down
  - scrape failures
  - error-rate spike
  - queue lag growth
  - ingestion backpressure
  - trace export failures

### Wave 5 - Rollout and cutover order

1. Platform services and config
2. App log schema normalization
3. App metrics endpoints
4. App trace instrumentation
5. Infra exporter hardening
6. Dashboard/alert tuning

## Compose Env Contract

Standard env variables now wired for non-vector app services:

- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_PROTOCOL`
- `OTEL_SERVICE_NAME`
- `OTEL_RESOURCE_ATTRIBUTES`

Additional toggles:

- `MANAGEMENT_TRACING_SAMPLING_PROBABILITY` for `java-coordinator*`
- `PUSHGATEWAY_URL` for one-shot init jobs

## Java Coordinator KEDA-Ready Metrics

The Java coordinator owns stable Redpanda lag metrics for future KEDA Prometheus scaling. KEDA manifests are intentionally not created in this rollout; Helm still keeps the future-facing coordinator max at 5 replicas.

Coordinator metrics exported at `/actuator/prometheus`:

- `coordinator_redpanda_consumer_lag_records{role,consumer_group,topic}`
- `coordinator_redpanda_topic_end_offset_records{role,consumer_group,topic}`
- `coordinator_redpanda_consumer_committed_offset_records{role,consumer_group,topic}`
- `coordinator_redpanda_lag_refresh_failures_total{role}`
- `coordinator_redpanda_lag_stale_seconds{role,consumer_group,topic}`
- `coordinator_route_running{role,route}`
- `coordinator_route_suspended{role,route}`
- `coordinator_backpressure_active`

Use `max(...)` in autoscaling queries so multiple coordinator replicas do not double count the same consumer-group lag:

```promql
max(coordinator_redpanda_consumer_lag_records{job="java-coordinator",role="scan",topic="sync.scan.request"})
max(coordinator_redpanda_consumer_lag_records{job="java-coordinator",role="result",topic="sync.oracle.result"})
```

Runtime controls:

- `SYNC_REDPANDA_LAG_METRICS_ENABLED=true`
- `SYNC_REDPANDA_LAG_METRICS_POLL_INTERVAL_MS=10000`
- `SYNC_REDPANDA_LAG_METRICS_TIMEOUT_MS=5000`
- `SYNC_HEARTBEAT_LOG_INTERVAL_MS=15000`

## Port Map (local host bindings)

- Grafana: `127.0.0.1:3004`
- Prometheus: `127.0.0.1:9090`
- Loki: `127.0.0.1:3100`
- Jaeger UI: `127.0.0.1:16686`
- OTel Collector OTLP gRPC (host): `127.0.0.1:4317`
- OTel Collector OTLP HTTP (host): `127.0.0.1:4320`
- OTel Collector self-metrics: `127.0.0.1:8888`
- Pushgateway: `127.0.0.1:9091`
- Postgres exporter: `127.0.0.1:9187`

## Verification Commands

Compose health:

```bash
docker compose up -d prometheus loki promtail jaeger otel-collector grafana postgres-exporter pushgateway
docker compose ps
```

Prometheus targets:

```bash
curl -s http://127.0.0.1:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health, instance: .labels.instance}'
```

Loki ingestion:

```bash
curl -G -s "http://127.0.0.1:3100/loki/api/v1/query" \
  --data-urlencode 'query={service=~"ssl-proxy|java-coordinator|atheros-sensor"}' \
  | jq '.status'
```

Jaeger traces:

```bash
curl -s "http://127.0.0.1:16686/api/services" | jq
```

Regression sanity:

```bash
curl -f http://127.0.0.1:3002/health
curl -f http://127.0.0.1:8081/actuator/health
```

## Troubleshooting

- No logs in Loki:
  - check `promtail` can access `/var/run/docker.sock`
  - check excluded services regex does not drop intended targets
- No traces in Jaeger:
  - confirm app OTLP endpoint points to `http://otel-collector:4317`
  - confirm `otel-collector` exporter failures are zero
- Missing Prometheus targets:
  - verify service endpoint path and port
  - for `atheros-sensor`, verify `ATH_SENSOR_METRICS_PORT` and host-gateway routing

## Exclusion Note for Existing Vector Docs

Any existing Vector-profile documentation remains unchanged. This rollout is explicitly non-vector and does not modify vector service telemetry pipelines.
