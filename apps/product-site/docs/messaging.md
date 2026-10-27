# Messaging framework

RCLabs is Rafael Cardoso dos Santos's independently maintained backend and
data-platform engineering portfolio. Atheros Search is the first walkthrough:
the proxy and sensor publish observations, Octopus coordinates ingestion, and
Search provides retrieval, evidence, fenced embedding workers and authenticated
operational reads through one pipeline workbench. The main audience is RAG
builders and operators tracing ingestion to available evidence. Schema Migrator
is companion tooling for SQL change review. Proxy and Octopus retain technical
detail pages and their existing URLs as component capabilities. Generated
answers and new connectors remain future work. Each component keeps its caveat.
The public site describes mechanisms, review workflows,
and measured operational evidence; it does not make savings, latency, market,
capacity, coverage, or outcome claims.

Copy lives in [`src/data/products.ts`](../src/data/products.ts). Route files
and components render that model instead of restating product copy, audience
statements, workflow steps, caveats, or contact labels.

## Product stories

| Product            | Public story                                                                            | Primary action                        |
| ------------------ | --------------------------------------------------------------------------------------- | ------------------------------------- |
| Atheros Search     | Trace configured source observations through ingestion, indexing and evidence retrieval. | Explore the synthetic site review.    |
| Schema Migrator    | Inspect ordered SQL changes, validation, and run records before execution.              | Explore the synthetic change review.  |
| RCLabs VPN / Proxy | Inspect WireGuard ingress, transparent-proxy classification, and audit publishing.      | Explore the synthetic traffic review. |
| Octopus            | Follow incoming events through jobs and loads, with live readings and recorded history. | View live metrics.                    |

The project catalogue retains the `/products/` URL and compares all four
components and companion tools within the Atheros Search workflow. Do not present the page count as evidence of four commercial
products, customer adoption, or a particular career level. The `/about/` page
identifies the author, links source, and summarizes security boundaries and
remaining evidence gaps. The homepage playground runs
one of three synthetic samples at a time. Octopus has no synthetic demo.
Its production activity section follows the hero, with current readings before
historical peaks and a disclosure for measurement definitions.
The same-origin runtime feed refreshes every 30 seconds. Never embed measurements
in the build. Loading, unavailable, stale, and live states must be distinct;
failed requests retain the last fresh reading with a delayed label until it
expires. Missing or expired snapshots show one explanation and a workflow link
instead of a grid of unavailable values. Partial snapshots explain warmup and
missing history without inventing counts. No-JavaScript rendering shows the
workflow link and an instruction to enable JavaScript. Pipeline and audience controls progressively enhance
static product copy.

The six technical guides under `/guides/` explain separate investigation and
migration questions with repository-backed mechanisms and labelled examples.
They link to the relevant product and sibling guides. Keep each guide distinct;
the homepage introduces the topics and links to the complete guides.

## Evidence and language

Use `interactive sample`, never `live sample`, for the synthetic demos.
Those demos run only in the browser. Octopus separately reads public production
metrics without credentials or personal data.

Historical peaks count rows in `octopus_core.ingestion_evidence` by
`first_seen_at`, across all ingest paths and dispositions. They are not unique
business events or a capacity benchmark. UTC days and Monday-Sunday weeks include
the current period so far. Show their own computation time, separately from the
live response time. The processing rate describes the responding coordinator's
scheduled ledger processor, not every stream; a successful check can find no work.
Require fresh observations before displaying zero or inactive. Never link internal
dashboards or publish credentials, topology, or extra upstream JSON fields.

Describe Search heuristics as indicators for analyst review. Atheros Sensor
uses monitor-mode capture on configured Wi-Fi channels; say `monitored site`,
not every site or every device. Describe the VPN / Proxy story as ingress,
proxy handling, classification, and audit publishing. Do not infer blocking,
privacy, or complete traffic coverage from the sample.

## Required caveats

Keep these statements in the model, product page, and relevant sample:

- **Search:** An observation does not confirm a current connection or device
  identity. Identity suggestions are review candidates.
- **Migrator:** SQL-file snapshots preserve source files and checksums. They do
  not back up database data. The public demonstration executes no SQL. State in
  the opening product and guide copy that column definitions and nullability
  are outside drift comparison scope, and dry-run output is shortened.
- **VPN / Proxy:** Classification is an operator review aid. It does not prove
  intent, prevent a connection, or cover traffic outside the configured path.
- **Octopus:** Delivery may repeat; saved progress and deduplication support replay.
  Coverage is limited to configured streams. Keep measurement definitions beside
  the production activity section in a disclosure.

## Contact

General calls to action use `mailto:` links for `rafael@rclabs.uk`. The privacy
notice identifies Rafael Cardoso dos Santos as the individual controller and
uses his confirmed privacy contact, `racasantos@icloud.com`. Subjects are
`Use-case discussion: [product]`. The contact page keeps the address visible
with a copy fallback. Email begins a discussion; it does not schedule a meeting.
The Octopus contact invites a pipeline setup discussion with an engineer about
stream topology, state bottlenecks, and recovery. Do not promise instant booking,
zero-loss recovery, or an uptime guarantee. Engineering copy focuses on source
lineage, replay, and persistent job state; Operations copy focuses on processing,
backlog, intake control, throughput, and measurement freshness.

## Adding or changing copy

1. Change the product model in `src/data/products.ts`.
2. Keep the synthetic label visible wherever a reader could mistake a sample
   for production data.
3. Update [content evidence](content-evidence.md) and the relevant browser
   tests when product copy, a caveat, or a destination changes.
4. Run `npm run build` and `npm test`.
