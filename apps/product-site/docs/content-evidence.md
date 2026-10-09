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
| Measured peak day and week | [Committed snapshot](../src/data/octopus-stats.json), [manual refresh procedure](release-checklist.md#manual-octopus-refresh) | Highest ledger counts by first_seen_at in UTC day / Monday-Sunday week; current periods are partial and counts cover recorded ledger history |
| Manual ingest rate, pending ledger, last success, and backpressure | [Recording rules](../../../cyber-stack/base/telemetry/config/prometheus/rules/recording.rules.yml), [metric definitions](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/CoordinatorMetrics.scala) | Dated operator snapshot, not a live feed; process counters cannot establish historical peaks |

The 2026-10-08T23:54:52Z capture used a single read-only, repeatable-read
transaction: 10,077,299 ledger rows, with the earliest `first_seen_at` at
2026-10-06T15:43:50.915461Z. Peak day: 6,048,436 on 2026-10-07. Peak week:
10,077,299 for 2026-10-05 through 2026-10-11, still in progress at capture.
All four metrics were evaluated at that same capture time: ingest rate 0
records/s, pending ledger 0, backpressure 0, last-success Unix time 1791503684
(2026-10-08T23:54:44Z). Zeros are returned measurements, not missing-data defaults.
The unsuffixed last-success metric was absent; the deployed `_value` series
provided the timestamp. These counts cover the recorded ledger history only.

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
