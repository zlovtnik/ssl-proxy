# Product content evidence

Copy is limited to repository capabilities and explicitly sourced operational
measurements. Synthetic examples illustrate behavior without implying
performance results or customer adoption.

| Public story                                                        | Evidence                                                                                                                                                                                                                                                                                                                                                                 | Limitation                                                                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| Dense, sparse, hybrid search                                        | [Search documentation](../../integration-console/atheros-search/README.md), [fusion implementation](../../integration-console/atheros-search/internal/search/fusion.go)                                                                                                                                                                                                  | No measured relevance or speed claim                                                                               |
| Ranking explanation, context, inventory, network, processing health | [Search route and contract documentation](../../integration-console/atheros-search/README.md)                                                                                                                                                                                                                                                                            | Observations do not confirm active connections; identifiers and review candidates do not confirm physical identity |
| Passive Wi-Fi capture and site-labelled audit events                | [Sensor documentation](../../../services/atheros-sensor/README.md), [audit record](../../../services/atheros-sensor/src/model.rs)                                                                                                                                                                                                                                        | Requires monitor-mode Wi-Fi hardware; configured channels and observation time limit coverage                      |
| Wireless indicators for analyst review                              | [Sensor alert topics](../../../services/atheros-sensor/src/topics.rs), [rogue AP and signal heuristics](../../../services/atheros-sensor/src/detect_state_sections/rogue_deauth.rs), [PMF heuristics](../../../services/atheros-sensor/src/detect_state_sections/pmf.rs), [sequence heuristics](../../../services/atheros-sensor/src/detect_state_sections/sequences.rs) | Heuristics raise indicators, not confirmed incidents or complete threat coverage                                   |
| Site -> indicator -> observation public sample                      | [Synthetic fixtures](../src/data/fixtures.ts), [Search documentation](../../integration-console/atheros-search/README.md)                                                                                                                                                                                                                                                | Illustrative only; current production console does not show this full site overview end to end                     |
| Discovery, validation, ordered plans                                | [Migrator documentation](../../schema-migrator/README.md), [plan implementation](../../schema-migrator/src/main/scala/com/sslproxy/schema/engine/MigrationPlan.scala)                                                                                                                                                                                                    | Offline checks do not guarantee execution against every target                                                     |
| SQL-file snapshots and comparisons                                  | [Snapshot implementation](../../schema-migrator/src/main/scala/com/sslproxy/schema/store/SnapshotStore.scala)                                                                                                                                                                                                                                                            | Source files and checksums, not database backups                                                                   |
| Guarded runs, target credentials, audit records                     | [Migrator documentation](../../schema-migrator/README.md)                                                                                                                                                                                                                                                                                                                | No availability, compliance, or certification claim                                                                |
| Offline discovery, validation, and dry-run preview                  | [CLI commands](../../schema-migrator/src/main/scala/com/sslproxy/schema/cli/Commands.scala), [folder order](../../schema-migrator/src/main/scala/com/sslproxy/schema/discovery/FolderOrder.scala), [preview printer](../../schema-migrator/src/main/scala/com/sslproxy/schema/output/ReportPrinter.scala)                                                                | The preview prints ordered, single-line SQL cut after 120 characters; it is not an executable deployment script    |
| PostgreSQL catalog drift findings                                   | [Drift diff engine](../../schema-migrator/src/main/scala/com/sslproxy/schema/server/PostgresDriftDiffEngine.scala), [catalog reader](../../schema-migrator/src/main/scala/com/sslproxy/schema/server/PostgresCatalogReader.scala)                                                                                                                                        | Reports differences for review; it corrects nothing and reading the catalog needs a target connection              |
| WireGuard ingress, transparent proxy handling, and traffic classes | [Proxy service](../../../src/main.rs), [WireGuard configuration](../../../src/config.rs), [traffic classifier](../../../src/tunnel/classify.rs) | Classification is an operator review aid; it does not prove intent, prevent a connection, or cover traffic outside the configured path |
| Six-term technical reference on the homepage                        | The evidence rows above and [Search documentation](../../integration-console/atheros-search/README.md)                                                                                                                                                                                                                                                                   | Each entry publishes what it does not prove beside the meaning                                                     |
| Search retrieval protocol for term, vector, and hybrid modes        | [Search documentation](../../integration-console/atheros-search/README.md), [fusion implementation](../../integration-console/atheros-search/internal/search/fusion.go)                                                                                                                                                                                                  | Protocol and status only: no measurement has been run, so no relevance, latency, or storage figure is published    |

## Octopus operational evidence

| Public story | Evidence | Limitation |
| --- | --- | --- |
| Durable ingest evidence, deduplication, and original first-seen time | [Ingestion SQL](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IngestionSql.scala), [ingestion store](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresIngestionStore.scala) | Evidence keys include consumer group, topic, partition, and offset; counts include all dispositions, not unique business events |
| Leases, batches, dispatch, and outbox | [Batch dispatch](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/dispatch/BatchDispatchService.scala), [outbox store](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresOutboxStore.scala), [Octopus documentation](../../../services/octopus/README.md) | Mechanisms do not establish capacity, latency, savings, or uptime |
| Measured peak day and week | [OperationalStatsService](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/OperationalStatsService.scala), [peak queries](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IngestionSql.scala) | UTC ledger counts; 60-second aggregate cache; failures never republish expired peaks |
| Live processing, backlog, checks, and intake control | [CoordinatorMetrics](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/CoordinatorMetrics.scala), [public endpoint](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/http/PublicStatsRoutes.scala) | Process readings cover the responding coordinator's scheduled ledger processor; a full five-minute window and recent collection are required |
| Runtime-only display | [Pages proxy](../functions/api/octopus-stats.ts), [response validation](../src/data/operational-stats.ts), [browser regression tests](../tests/operational-stats.spec.ts) | No saved measurements; failed or stale readings show unavailable |

Production inspection on 2026-10-09 found a public route pointing to container
port 8081 instead of Service port 8080 and a PostgreSQL week query failing with
SQLSTATE 42883. The coordinator's internal processing-check timestamps advanced,
confirming ongoing collection independently of the broken public feed.
These findings motivate the route, query, polling, and freshness regressions.

## Evaluation boundaries

Primary-action requests use `rafael@rclabs.uk`. Email links open a request,
not an already scheduled meeting. No retired search modes or deprecated target
support appear in the main story. No automatic end-to-end outcome is promised.

The sensor's published audit record can include raw-frame data and decoded
network fields. The public copy calls this a wireless evidence trail and makes
no metadata-only, raw-capture-exclusion, fixed-retention, compliance, or
coverage-completeness claim. Verify the deployed storage path and retention
before making a more specific statement.

Homepage technical sections render from `homeSections` in
[`src/data/products.ts`](../src/data/products.ts): the migration review guide,
the six-term reference, the workflow comparison, and the Search benchmark. The
guide's command output was captured from a local sample directory with no
production target, and the comparison cites the alternative-tool documentation it
measures itself against instead of claiming compatibility or advantage.

Copy follows [the messaging framework](messaging.md). That document records the
four product stories, the audience propositions, the commercial thesis as an
evaluation hypothesis, and the rule that no numeric improvement appears here
without a documented baseline, workload, environment, and measurement method.
Appearance follows [the design system](design-system.md).

The six [technical guides](../src/pages/guides/index.astro) render the `guides`
model in [products.ts](../src/data/products.ts) through
[GuidePage](../src/components/GuidePage.astro). Their migration ordering,
validation, snapshots and drift explanations use the implementation sources
above. Wireless investigation examples use the sensor's documented heuristics,
site labels and observation caveats; hybrid search uses the search fusion and
explanation contracts. Guide tables and sample records are illustrative unless
explicitly identified as captured command output. They establish no measured
performance, confirmed attack, or complete device identity.

Visual research: [Linear](https://linear.app/), [Resend](https://resend.com/),
and [Mintlify](https://www.mintlify.com/) inform hierarchy and progressive detail;
their appearance is not accessibility evidence. The identity and SVG diagrams are
original. [Astro's official SolidJS integration](https://docs.astro.build/en/guides/integrations-guide/solid-js/)
supports the static page and small interactive-island architecture.
