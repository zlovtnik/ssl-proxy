# Messaging framework

RCLabs is Rafael Cardoso's independently maintained backend and
data-platform engineering portfolio. Recruiters, engineering managers, and
technical interviewers are the primary portfolio audience. The professional
headline is Senior Software Engineer | Backend Systems & Enterprise Integration.
The homepage introduces ingestion, recovery, and search, followed by Synchro
experience, independent projects, and source and test links. Atheros
Search documentation explains the technical workflow:
the proxy and sensor publish observations, Octopus coordinates ingestion, and
Search provides retrieval, evidence, fenced embedding workers and authenticated
operational reads through one pipeline workbench. Schema Migrator
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

| Product            | Public story                                                                             | Primary action                        |
| ------------------ | ---------------------------------------------------------------------------------------- | ------------------------------------- |
| Atheros Search     | Trace configured source observations through ingestion, indexing and evidence retrieval. | Explore the synthetic site review.    |
| Schema Migrator    | Inspect ordered SQL changes, validation, and run records before execution.               | Explore the synthetic change review.  |
| RCLabs VPN / Proxy | Inspect WireGuard ingress, transparent-proxy classification, and audit publishing.       | Explore the synthetic traffic review. |
| Octopus            | Follow incoming events through jobs and loads, with live readings and recorded history.  | View live metrics.                    |

The project catalogue retains the `/products/` URL and compares all four
components and companion tools within the Atheros Search workflow. Do not present the page count as evidence of four commercial
products, customer adoption, or a particular career level. The `/about/` page
identifies the author, links source, and summarizes security boundaries and
remaining evidence gaps. The homepage links to the project documentation.
Search, Migrator, and VPN / Proxy samples belong on their respective project
pages. Do not duplicate them in a combined homepage playground. Octopus has no synthetic demo.
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

Homepage and About case studies share the same contribution model: what Rafael
built, the hardest failure mode, the response, repository regression coverage,
and remaining verification gaps. Octopus leads with persisted state, committed
offset replay, durable deduplication, fenced leases, and partial-failure recovery.
Source links establish that implementation and tests exist, not that a current
backend suite passed or a production crash campaign was performed.

Keep Synchro employment, independent projects, and synthetic examples explicitly
attributed. Show individual role dates on About and the resume. The owner's
current supplied resume reports approximately
20 million weekly fiscal transactions for a Synchro invoicing integration.
It supersedes the older August resume's 2 million figure. It is historical employer-system
workload, not Octopus activity, unique ledger events, or measured capacity.

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

The shared navigation links to `/contact/` on every route. `/demo/` redirects
permanently to that page, preserving existing section fragments. Hiring is the
primary call to action. Project email links invite questions about the published
engineering work. The `discussionLink` helper uses subjects in the format
`Engineering discussion: [project]`. Resume links retain the static, printable
`/resume/` page.
Use `rafael@rclabs.uk` consistently, including the privacy notice. Keep the email
visible with a copy fallback, and omit phone details from the public resume.
Email begins a discussion and does not schedule a meeting. Do not promise
instant booking, zero-loss recovery, or an uptime guarantee.

## Adding or changing copy

1. Change the product model in `src/data/products.ts`.
2. Keep the synthetic label visible wherever a reader could mistake a sample
   for production data.
3. Update [content evidence](content-evidence.md) and the relevant browser
   tests when product copy, a caveat, or a destination changes.
4. Run `npm run build` and `npm test`.

## Editorial style

Never use semicolons in public prose, including contact copy, labels, caveats,
metadata, and example explanations. Split sentences or use commas and
conjunctions. Keep punctuation required by code and SQL examples intact.
Use Rafael Cardoso as the public name everywhere, including the resume,
privacy notice, metadata, and structured data.

Write as Rafael, the individual author. Use concrete project names, inputs,
failures and implementation choices. A heading should name its subject rather
than tell the reader to explore, inspect or assess it. Avoid repeating the same
claim as a category label, slogan, summary and feature list. Project cards have
one factual description and their existing destinations. The homepage introduces
the work and links to guides; full technical chapters belong on guide routes.
Preserve caveats beside the examples they qualify, employment attribution, and
measurement definitions. The resume and privacy notice retain their factual
structure.

## Portfolio review rules

The [portfolio review article](https://labs.codersarts.com/blog/build-in-public/portfolio-projects-get-developers-hired-2026)
is editorial inspiration. Apply these checks to the existing projects:

- Verify every sample destination works today, with clear synthetic labels.
- Link readable source and tests alongside the implementation they support.
- Explain the problem, intended audience, technical decisions, failure handling,
  accepted tradeoffs and known limits using repository evidence.
- Keep the backend and data-platform work easy for employers to review.
- Distinguish historical employer workload, current runtime readings and
  synthetic examples. Never infer users, adoption or performance from them.

Do not add projects, user counts, popularity targets or hiring promises merely
to match the article. A working browser sample demonstrates that sample only.
