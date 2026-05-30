# Observability Architecture with Jaeger

## What changed with Jaeger

New trace path in the stack:

`workers -> OTLP gRPC -> OTel Collector -> Jaeger -> Grafana`

Rust and Zig workers now emit OTLP traces over gRPC. The OpenTelemetry Collector receives and forwards spans to Jaeger. Grafana reads Jaeger as a trace datasource and correlates traces with Loki logs and Prometheus metrics.

## Instrumentation first pass

| Signal type | Rust crate | Zig approach |
|---|---|---|
| Logs -> stdout | `tracing` + `tracing-subscriber` (JSON fmt) | custom JSON line writer or `zlog` |
| Metrics -> `/metrics` | `metrics` + `metrics-exporter-prometheus` | expose via simple HTTP handler |
| Traces -> OTLP | `opentelemetry` + `opentelemetry-otlp` | `opentelemetry-zig` or HTTP OTLP |

## Clickable architecture diagram

```mermaid
flowchart TB
    subgraph APP["Your application layer"]
        direction LR
        RW["Rust worker<br/>oracle-sync, ETL, CDC"]
        ZW["Zig worker<br/>fingerprint, embedding"]
        CJ["Cron jobs<br/>scheduled pipelines"]
    end

    subgraph COLLECT["Collection and transport layer"]
        direction LR
        GA["Grafana Alloy<br/>log collector"]
        PR["Prometheus<br/>scrapes /metrics"]
        OC["OTel Collector<br/>receives OTLP, exports to Jaeger"]
    end

    subgraph STORE["Storage backends"]
        direction LR
        LK["Grafana Loki<br/>log storage + LogQL"]
        PT["Prometheus TSDB<br/>metrics storage + PromQL"]
        JG["Jaeger<br/>trace storage + span search"]
    end

    subgraph VIZ["Visualization and correlation"]
        GF["Grafana<br/>dashboards, alerts, trace-log-metric correlation"]
    end

    RW -->|"stdout JSON"| GA
    ZW -->|"stdout JSON"| GA
    CJ -->|"stdout JSON"| GA

    RW -->|"/metrics"| PR
    ZW -->|"/metrics"| PR
    CJ -->|"/metrics"| PR

    RW -->|"OTLP gRPC"| OC
    ZW -->|"OTLP gRPC"| OC
    CJ -->|"OTLP gRPC"| OC

    GA --> LK
    PR --> PT
    OC --> JG

    LK --> GF
    PT --> GF
    JG --> GF

    click RW href "#q-rust-worker" "Follow-up question"
    click ZW href "#q-zig-worker" "Follow-up question"
    click CJ href "#q-cron-jobs" "Follow-up question"
    click GA href "#q-grafana-alloy" "Follow-up question"
    click PR href "#q-prometheus-scrape" "Follow-up question"
    click OC href "#q-otel-collector" "Follow-up question"
    click LK href "#q-loki" "Follow-up question"
    click PT href "#q-prometheus-tsdb" "Follow-up question"
    click JG href "#q-jaeger" "Follow-up question"
    click GF href "#q-grafana" "Follow-up question"
```

## Cron trace waterfall

```mermaid
flowchart LR
    R0["cron: fingerprint-pipeline<br/>trace_id=abc123<br/>27 s total"]
    S1["load_raw_events<br/>2 s"]
    S2["calculate_fingerprints<br/>3 s"]
    S3["pgvector_embedding<br/>18 s (bottleneck)"]
    S4["postgres_commit<br/>200 ms"]
    S5["oracle_sync<br/>3 s"]
    S6["publish_notification<br/>20 ms"]

    R0 --> S1 --> S2 --> S3 --> S4 --> S5 --> S6

    classDef bottleneck fill:#fde2e2,stroke:#b91c1c,stroke-width:2px,color:#7f1d1d;
    class S3 bottleneck;

    click R0 href "#q-trace-root" "Follow-up question"
    click S1 href "#q-trace-load-raw-events" "Follow-up question"
    click S2 href "#q-trace-calculate-fingerprints" "Follow-up question"
    click S3 href "#q-trace-pgvector-embedding" "Follow-up question"
    click S4 href "#q-trace-postgres-commit" "Follow-up question"
    click S5 href "#q-trace-oracle-sync" "Follow-up question"
    click S6 href "#q-trace-publish-notification" "Follow-up question"
```

`pgvector_embedding` is the visible bottleneck. Without Jaeger, you see only the 27 s total and lose phase-level latency attribution.

## Quick Grafana wiring

1. Add Jaeger as a Grafana datasource.
2. Include `trace_id` in structured JSON logs sent to Loki.
3. From a Loki log line, pivot to the matching Jaeger trace by `trace_id`.
4. Use Grafana dashboards to correlate trace spans with Prometheus metrics and Loki logs.

## Follow-up questions by node

### <a id="q-rust-worker"></a>Rust worker
What span boundaries and attributes must be emitted for Oracle sync, ETL, and CDC so failures are actionable?

### <a id="q-zig-worker"></a>Zig worker
Which fingerprint and embedding phases need child spans, and which dimensions should be tags versus logs?

### <a id="q-cron-jobs"></a>Cron jobs
Which scheduled pipelines must always create one root trace per execution, and what timeout alert should fire if the root span exceeds budget?

### <a id="q-grafana-alloy"></a>Grafana Alloy
Which JSON fields from stdout logs are mandatory for routing, parsing, and cross-linking with `trace_id`?

### <a id="q-prometheus-scrape"></a>Prometheus (scrape)
What scrape interval and timeout keep metric freshness high without overloading workers?

### <a id="q-otel-collector"></a>OTel Collector
What retry, batching, and backpressure settings prevent span loss during downstream outages?

### <a id="q-loki"></a>Loki
Which labels are required for query speed, and which fields must stay in log body to avoid cardinality explosions?

### <a id="q-prometheus-tsdb"></a>Prometheus TSDB
Which SLO and saturation metrics should be retained at high resolution for incident triage?

### <a id="q-jaeger"></a>Jaeger
What retention window and sampling policy preserve enough traces to diagnose intermittent bottlenecks?

### <a id="q-grafana"></a>Grafana
Which dashboard panels must support one-click pivot across trace, log, and metric views during incident response?

### <a id="q-trace-root"></a>Trace root (`fingerprint-pipeline`)
What run-level metadata (job id, schedule id, input size) is required on the root span for filtering and incident grouping?

### <a id="q-trace-load-raw-events"></a>`load_raw_events`
Which source latency and row-count attributes are needed to separate input slowness from compute slowness?

### <a id="q-trace-calculate-fingerprints"></a>`calculate_fingerprints`
What CPU and batch-size dimensions should be captured to detect algorithmic regression?

### <a id="q-trace-pgvector-embedding"></a>`pgvector_embedding`
What queue depth, model latency, and retry metadata must be attached to explain the 18 s bottleneck?

### <a id="q-trace-postgres-commit"></a>`postgres_commit`
Which commit latency and lock-wait fields are needed to detect transactional contention?

### <a id="q-trace-oracle-sync"></a>`oracle_sync`
What remote-call and payload attributes are needed to isolate Oracle-side latency from local pipeline latency?

### <a id="q-trace-publish-notification"></a>`publish_notification`
What broker ack and publish retry fields should be captured to detect delivery degradation early?
