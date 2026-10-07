# Messaging framework

RCLabs presents three separate product stories: Atheros Search, Schema
Migrator, and RCLabs VPN / Proxy. Each story has its own audience, workflow,
sample, and caveat. The public site describes mechanisms and review workflows;
it does not make savings, latency, market, coverage, or outcome claims.

Copy lives in [`src/data/products.ts`](../src/data/products.ts). Route files
and components render that model instead of restating product copy, audience
statements, workflow steps, caveats, or contact labels.

## Product stories

| Product | Public story | Primary action |
| --- | --- | --- |
| Atheros Search | Review wireless indicators with monitored-site context and supporting observations. | Explore the synthetic site review. |
| Schema Migrator | Inspect ordered SQL changes, validation, and run records before execution. | Explore the synthetic change review. |
| RCLabs VPN / Proxy | Inspect WireGuard ingress, transparent-proxy classification, and audit publishing. | Explore the synthetic traffic review. |

The catalogue at `/products/` compares all three. The homepage playground runs
one synthetic sample at a time. Product pages place the full sample below the
introductory hero so expanding a detail changes the page height naturally.

## Evidence and language

Use `interactive sample`, never `live sample`. Every demonstration uses
synthetic fixtures in the browser. There is no production connection, account,
or credential on this site.

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
