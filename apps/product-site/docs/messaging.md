# Messaging framework

RCLabs presents four separate product stories: Atheros Search, Schema
Migrator, RCLabs VPN / Proxy, and Octopus. Each story has its own audience,
workflow, and caveat. The public site describes mechanisms, review workflows,
and measured operational evidence; it does not make savings, latency, market,
capacity, coverage, or outcome claims.

Copy lives in [`src/data/products.ts`](../src/data/products.ts). Route files
and components render that model instead of restating product copy, audience
statements, workflow steps, caveats, or contact labels.

## Product stories

| Product | Public story | Primary action |
| --- | --- | --- |
| Atheros Search | Review wireless indicators with monitored-site context and supporting observations. | Explore the synthetic site review. |
| Schema Migrator | Inspect ordered SQL changes, validation, and run records before execution. | Explore the synthetic change review. |
| RCLabs VPN / Proxy | Inspect WireGuard ingress, transparent-proxy classification, and audit publishing. | Explore the synthetic traffic review. |
| Octopus | Coordinate durable ingestion and inspect historical ledger counts with provenance. | Review measured throughput. |

The catalogue at `/products/` compares all four. The homepage playground runs
one of three synthetic samples at a time. Their product pages place the full
sample below the introductory hero. Octopus has no demo island. Its page uses
UX islands only for stage emphasis, audience framing, optional count-up
presentation, and the operational-evidence widget. That widget polls live
production metrics when `PUBLIC_OCTOPUS_STATS_URL` is set at build time;
otherwise it shows the dated `octopus-stats.json` snapshot and must label it as
the build-time fallback, never as live.
The operator snapshot section follows capability evidence and precedes the
glossary. Pipeline short labels (`Discovery`, `Dispatch`, `Evidence`) are
model-owned `stageLabel` values. Toggle labels (`I am an Engineer`,
`I am an Operator`) are UI chrome; the card audience statements stay in the model.

The six technical guides under `/guides/` explain separate investigation and
migration questions with repository-backed mechanisms and labelled examples.
They link to the relevant product and sibling guides. Keep each guide distinct;
the homepage introduces the topics and links to the complete guides.

## Evidence and language

Use `interactive sample`, never `live sample`. Every demonstration uses
synthetic fixtures in the browser. There is no production connection, account,
or credential on this site.

Measured operational evidence needs a documented source, definition, UTC
boundaries, and visible as-of time. Octopus peaks count rows in
`octopus_core.ingestion_evidence` by `first_seen_at`, across all ingest paths
and dispositions. They are ledger counts, not unique business events or a
throughput benchmark. A current day or week is counted only so far. Describe
the metrics strip as live production data when the feed is configured;
otherwise label it as a dated published snapshot. Never present the snapshot
as live when the feed is not updating.
Never link internal dashboards or publish their addresses or topology in
page content, rendered JSON fields, or bundled assets. Never fabricate numbers;
null peaks show a pending-refresh note and a null strip is omitted.

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
  not back up database data. The public demonstration executes no SQL.
- **VPN / Proxy:** Classification is an operator review aid. It does not prove
  intent, prevent a connection, or cover traffic outside the configured path.
- **Octopus:** Peaks are historical ledger counts, not a throughput limit,
  capacity forecast, savings, or latency claim. The metrics strip reflects live
  production data when the feed is configured. Keep this caveat beside the
  measured evidence.

## Contact

Calls to action use `mailto:` links for `rafael@rclabs.uk`. Subjects are
`Use-case discussion: [product]`. The contact page keeps the address visible
with a copy fallback. Email begins a discussion; it does not schedule a meeting.

## Adding or changing copy

1. Change the product model in `src/data/products.ts`.
2. Keep the synthetic label visible wherever a reader could mistake a sample
   for production data.
3. Update [content evidence](content-evidence.md) and the relevant browser
   tests when product copy, a caveat, or a destination changes.
4. Run `npm run build` and `npm test`.
