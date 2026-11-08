# Product content evidence

Copy is limited to repository capabilities and explicitly sourced operational
measurements. Synthetic examples illustrate behavior without implying
performance results or customer adoption.

The primary product story follows Atheros Search from configured proxy and
wireless observations through ingestion, document preparation, indexing and
evidence retrieval. [Runtime ownership and readiness limits](../../../docs/atheros-search-workflow.md)
and the [architecture](../../../docs/architecture.md) ground that framing.
Proxy and Octopus remain component detail pages; Schema Migrator remains
companion tooling. The public Search sample still illustrates synthetic site,
indicator and observation review, rather than an end-to-end ingestion run.
Generated answers and new connectors are deferred. Operational measurements
remain global unless explicitly scoped; unknown coverage is not readiness.

The site is framed as Rafael Cardoso's engineering portfolio.
The owner requested the shortened public name on 2026-10-31. The
`racasantos@icloud.com` privacy contact was confirmed on 2026-10-14.
The [about page](../src/pages/about/index.astro) links the
[repository threat model](../../../docs/threat-model.md) and distinguishes
implementation evidence, synthetic demonstrations, deployment observations, and
unpublished customer or benchmark outcomes. Identity markup uses a person as
publisher and makes no registered-company claim.

The 2026-11-01 homepage summaries and contact copy follow the owner's edited
[Figma design](https://www.figma.com/design/FcboDrnxKQP4TFhsq7O8ib?node-id=2-12).
The owner subsequently requested a general `Contact` action across all routes,
using the subject `General inquiry` and a general email body. Shared contact
copy stays in the product model. The concise Search caveat keeps
the observation/identity boundary and labels identity suggestions as candidates.
The Migrator summary preserves the drift-scope, shortened-preview and backup
limitations. Proxy classification remains an operator review aid. Full project
failure cases and regression coverage remain on About, with existing links to
source and tests. Homepage production readings are linked through Octopus and
are never replaced by sample values.

The homepage, About page, and printable [resume](../src/pages/resume/index.astro)
use the November 8, 2026 career facts and portfolio draft from the owner's CV
workspace. The public headline targets Senior Software Engineer roles in backend
systems and enterprise integration. About and the resume show the individual
Synchro titles and dates. Career evidence includes 15+ years in software and
enterprise integrations, architecture and code reviews for teams of 3 to 8, and
approximately 20 million weekly fiscal transactions in the Synchro integration
between Oracle ERP Cloud, invoicing, and tax systems. The resume retains the
1-2 GB source XML document size, U.S. work authorization without sponsorship,
and remote/hybrid availability. The 2024 Synchro customer project covered invoice
recognition and fiscal data preparation using Go retrieval-augmented generation,
Python machine learning, Oracle Integration Cloud, and OCI AI capabilities.
The workload figure supersedes the older
[August resume](https://docs.google.com/document/d/1eRrKPRxudXWgvVlowoMQ5De4Khgj-ynJy7FWw8UbEZ4/edit),
which used 2 million. The phone, personal email, profile links, and location on
the public resume are the details supplied by the owner in that current text.
Employer code and operational monitoring are not public. These are historical
employer-system claims, not Octopus throughput or an independent benchmark.
The older Drive document remains private; no Drive sharing was changed.

The shared [case studies](../src/components/ProjectStudies.astro) link to concrete
implementation and regression files for each independent project. Octopus uses
the [persistence suite](../../../services/octopus/src/test/scala/com/sslproxy/coordinator/ingest/OctopusPersistenceIntegrationSuite.scala),
[partial-failure suite](../../../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/PostgresLoadStreamSuite.scala),
and [processor-state suite](../../../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProcessorSupervisorSuite.scala).
Those sources cover duplicate replay, identity/payload invariants, concurrent
claims, partial results, completion guards, and persisted processor status.
Database integration tests can skip without Docker; current backend pass status,
recovery times, and a complete process/broker/database crash campaign are not
claimed. Source links use `main` and can change with later revisions.

Column definitions and nullability are outside the Migrator comparison scope;
this limitation now appears in the opening product and drift-guide copy.
The [CLI](../../schema-migrator/src/main/scala/com/sslproxy/schema/cli/Commands.scala)
compacts and shortens SQL before passing it to the report printer. The dry-run
guide requires reviewing the original files alongside that incomplete preview.

| Public story                                                        | Evidence                                                                                                                                                                                                                                                                                                                                                                 | Limitation                                                                                                                             |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Dense, sparse, hybrid search                                        | [Search documentation](../../integration-console/atheros-search/README.md), [fusion implementation](../../integration-console/atheros-search/internal/search/fusion.go)                                                                                                                                                                                                  | No measured relevance or speed claim                                                                                                   |
| Ranking explanation, context, inventory, network, processing health | [Search route and contract documentation](../../integration-console/atheros-search/README.md)                                                                                                                                                                                                                                                                            | Observations do not confirm active connections; identifiers and review candidates do not confirm physical identity                     |
| Passive Wi-Fi capture and site-labelled audit events                | [Sensor documentation](../../../services/atheros-sensor/README.md), [audit record](../../../services/atheros-sensor/src/model.rs)                                                                                                                                                                                                                                        | Requires monitor-mode Wi-Fi hardware; configured channels and observation time limit coverage                                          |
| Wireless indicators for analyst review                              | [Sensor alert topics](../../../services/atheros-sensor/src/topics.rs), [rogue AP and signal heuristics](../../../services/atheros-sensor/src/detect_state_sections/rogue_deauth.rs), [PMF heuristics](../../../services/atheros-sensor/src/detect_state_sections/pmf.rs), [sequence heuristics](../../../services/atheros-sensor/src/detect_state_sections/sequences.rs) | Heuristics raise indicators, not confirmed incidents or complete threat coverage                                                       |
| Site -> indicator -> observation public sample                      | [Synthetic fixtures](../src/data/fixtures.ts), [Search documentation](../../integration-console/atheros-search/README.md)                                                                                                                                                                                                                                                | Illustrative only; current production console does not show this full site overview end to end                                         |
| Discovery, validation, ordered plans                                | [Migrator documentation](../../schema-migrator/README.md), [plan implementation](../../schema-migrator/src/main/scala/com/sslproxy/schema/engine/MigrationPlan.scala)                                                                                                                                                                                                    | Offline checks do not guarantee execution against every target                                                                         |
| SQL-file snapshots and comparisons                                  | [Snapshot implementation](../../schema-migrator/src/main/scala/com/sslproxy/schema/store/SnapshotStore.scala)                                                                                                                                                                                                                                                            | Source files and checksums, not database backups                                                                                       |
| Guarded runs, target credentials, audit records                     | [Migrator documentation](../../schema-migrator/README.md)                                                                                                                                                                                                                                                                                                                | No availability, compliance, or certification claim                                                                                    |
| Offline discovery, validation, and dry-run preview                  | [CLI commands](../../schema-migrator/src/main/scala/com/sslproxy/schema/cli/Commands.scala), [folder order](../../schema-migrator/src/main/scala/com/sslproxy/schema/discovery/FolderOrder.scala), [preview printer](../../schema-migrator/src/main/scala/com/sslproxy/schema/output/ReportPrinter.scala)                                                                | The preview prints ordered, single-line SQL cut after 120 characters; it is not an executable deployment script                        |
| PostgreSQL catalog drift findings                                   | [Drift diff engine](../../schema-migrator/src/main/scala/com/sslproxy/schema/server/PostgresDriftDiffEngine.scala), [catalog reader](../../schema-migrator/src/main/scala/com/sslproxy/schema/server/PostgresCatalogReader.scala)                                                                                                                                        | Reports differences for review; it corrects nothing and reading the catalog needs a target connection                                  |
| WireGuard ingress, transparent proxy handling, and traffic classes  | [Proxy service](../../../src/main.rs), [WireGuard configuration](../../../src/config.rs), [traffic classifier](../../../src/tunnel/classify.rs)                                                                                                                                                                                                                          | Classification is an operator review aid; it does not prove intent, prevent a connection, or cover traffic outside the configured path |
| Search retrieval protocol for term, vector, and hybrid modes        | [Search documentation](../../integration-console/atheros-search/README.md), [fusion implementation](../../integration-console/atheros-search/internal/search/fusion.go)                                                                                                                                                                                                  | Synthetic ranks explain the method; no measured relevance, latency, or storage result is published                                     |

## Octopus operational evidence

| Public story                                                         | Evidence                                                                                                                                                                                                                                                                                                    | Limitation                                                                                                                      |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Durable ingest evidence, deduplication, and original first-seen time | [Ingestion SQL](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IngestionSql.scala), [ingestion store](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresIngestionStore.scala)                                                              | Evidence keys include consumer group, topic, partition, and offset; counts include all dispositions, not unique business events |
| Leases, batches, dispatch, and outbox                                | [Batch dispatch](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/dispatch/BatchDispatchService.scala), [outbox store](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresOutboxStore.scala), [Octopus documentation](../../../services/octopus/README.md) | Mechanisms do not establish capacity, latency, savings, or uptime                                                               |
| Measured peak day and week                                           | [C++ repository](../../../services/octopus-metrics/src/adapters.cpp), [snapshot serialization](../../../services/octopus-metrics/src/domain.cpp)                                                                                                                                                            | UTC evidence counts; 300-second refresh; failures retain measured history and original timestamps                               |
| Live processing, backlog, checks, and intake control                 | [CoordinatorMetrics](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/CoordinatorMetrics.scala), [internal live bridge](../../../services/octopus/src/main/scala/com/sslproxy/coordinator/http/LiveMetricsRoutes.scala)                                                      | Committed broker deliveries over five minutes; pending ledger rows and broker lag are separate gauges                           |
| Lifetime ledger totals and hourly throughput windows                 | [C++ repository](../../../services/octopus-metrics/src/adapters.cpp), [response validation](../src/data/operational-stats.ts)                                                                                                                                                                               | 24 and 168 complete UTC hour buckets; retained windows keep their original bucket times during refresh failures                 |
| Runtime-only display                                                 | [Pages proxy](../functions/api/octopus-stats.ts), [response validation](../src/data/operational-stats.ts), [browser regression tests](../tests/operational-stats.spec.ts)                                                                                                                                   | Durable Cloudflare and browser copies retain recorded history through outages; never invent values or rewrite measurement times |

Octopus copy connects source offsets to incident triage, committed offsets and
deduplication to restart recovery, and work claims to inspection of stalled
loads. These are uses of the mechanisms above, not measured time savings,
zero-loss guarantees, or prevention of every duplicate. The Engineering and
Operations views separate record-level investigation from backlog and throughput
review. Contact remains an email discussion with an engineer.

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

The homepage links to the six dedicated guides instead of repeating their
technical chapters. Legacy topic fragments still reach the guide index.
`migrationExamples` in [the content model](../src/data/products.ts) holds the
SQL inputs and captured CLI output used by the dry-run guide. Those examples,
guide bodies, caveats and source links were preserved during the editorial
cleanup. Product cards use one factual summary; implementation detail lives on
the product and guide routes.

Copy follows [the messaging framework](messaging.md). That document records the
component stories, the audience propositions, the portfolio scope, and the rule
that no numeric improvement appears here
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
