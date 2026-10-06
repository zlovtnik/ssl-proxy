# Messaging framework

One visual system, two product stories. RCLabs presents Atheros Search and
Schema Migrator as two independent tools. Each tool has its own audience,
workflow, and caveats. Nothing on the public site implies a shared connection
between them.

Copy lives in [`src/data/products.ts`](../src/data/products.ts). Route files
render that model; they do not restate headlines, summaries, calls to action,
audience propositions, or workflow steps. Edit the model, not the pages.

## Positioning

- Investigate wireless indicators in monitored-site context.
- Review database changes.
- Convert technically with a working synthetic sample.
- Convert commercially with "Discuss your use case" over email.

Atheros Search's public story is **site -> wireless indicator -> supporting
observation**. Atheros Sensor uses monitor-mode capture on configured Wi-Fi
channels, then publishes audit records to the configured backend. Search helps
review those records with location and sensor context. The sensor requires
monitor-mode Wi-Fi hardware; say "monitored site," not "every site" or "every
device."

Describe rogue-access-point heuristics, deauthentication floods, signal
anomalies, attack sequences, and PMF-related patterns as **indicators for
analyst review**. Do not call them confirmed incidents, complete threat
coverage, noise reduction, automated resolution, or definitive proof. Keep
judgment with the operator.

The site-to-indicator sample is synthetic and illustrates a workflow that the
current production console does not show end to end. Do not imply otherwise.
Call its historical data a wireless evidence trail; do not promise metadata-only
records, a raw-capture exclusion, or a retention duration. The sensor audit
schema can include raw-frame data and decoded network fields, and actual
retention depends on deployment.

Use "interactive sample", not "live sample". Every demonstration runs on
synthetic fixtures in the browser. There is no production connection, account,
or credential anywhere on this site.

## Route stories

| Route               | Story                                            | Primary action                              | Commercial action                        |
| ------------------- | ------------------------------------------------ | ------------------------------------------- | ---------------------------------------- |
| `/`                 | Two independent tools, one attention to evidence | Explore the samples, in the hero playground | Discuss your use case, `/demo/`          |
| `/atheros-search/`  | Review wireless indicators in site context       | Explore a sample site review, `#demo`       | Discuss your use case, `/demo/#search`   |
| `/schema-migrator/` | Review SQL changes before you run them           | Explore a sample migration review, `#demo`  | Discuss your use case, `/demo/#migrator` |
| `/demo/`            | Choose a product, then write                     | Product-specific email links                | Visible address with copy fallback       |
| `/accessibility/`   | Read the site in the way that works for you      | Reading and display settings                | Barrier report address                   |

Product pages follow one order: hero with sample, three-step workflow, technical
and buyer value, supporting capability evidence, glossary, contact. The homepage
carries the shared FAQ.

## Homepage order

The homepage runs hero, products, then four technical sections in this order,
followed by the shared principles, FAQ, and contact:

| Anchor                       | Section                                             | Model key                 |
| ---------------------------- | --------------------------------------------------- | ------------------------- |
| `#postgres-migration-review` | Review PostgreSQL migrations before execution       | `homeSections.guide`      |
| `#technical-reference`       | Six technical terms and what they do not prove      | `homeSections.reference`  |
| `#workflow-comparison`       | Schema Migrator review and site-aware Search sample | `homeSections.comparison` |
| `#search-benchmark`          | Term, vector and hybrid search protocol             | `homeSections.benchmark`  |

The homepage title and H1 lead with site-aware wireless security while keeping
PostgreSQL migration review visible as the separate Schema Migrator story. Both
ship from `home`. Each product card heading starts with the product name, so the
two tools stay distinguishable in the outline.

Each technical section keeps its summary short and puts commands, protocols, and
references inside a native `details` disclosure. The guide separates the offline
file checks from the target-connected catalog check, and repeats the two
load-bearing caveats beside the reference entries they qualify.

## Audience propositions

Both audience readings appear openly on each product page. They are not hidden
behind tabs or filters, so a reader can disagree with one and keep reading.

- Search technical users receive mechanisms: monitor-mode capture, configured
  wireless indicators, site/sensor context, and supporting observations.
- Migrator technical users receive mechanisms: ordering, validation,
  explanations, checksums, catalog drift, and run records.
- Buyers and operators receive each product's actual operating shape, without
  implied incident-response savings, compliance readiness, or zero-footprint
  deployment.

Each product also carries one `problem` statement naming its audience, used above
the audience pair and in the homepage question about who the tools are for.

## Evidence rules

Publish mechanisms and demonstrable capabilities. Do not publish savings,
latency, market size, or defensibility claims. Architecture alone does not
establish a moat.

Numeric improvement requires a documented baseline, workload, environment, and
measurement method. Until those exist, no figure appears on the public site.
Supporting evidence is traced in [content evidence](content-evidence.md).

The Search benchmark section follows that rule directly: it publishes the
dataset, labelled query set, retrieval modes, and metrics to be computed, plus a
status statement that measurement has not run. Synthetic examples are never
reported as performance evidence, and no drop-in compatibility or performance
advantage is claimed against another tool.

## Preserved caveats

These two statements are load-bearing. Keep them beside the content they
qualify, and keep them in the synthetic fixtures as well as the pages.

- **Search:** An observation does not confirm a current connection or device
  identity. Identity suggestions are review candidates.
- **Migrator:** SQL-file snapshots preserve source files and checksums. They do
  not back up database data. The public demonstration executes no SQL.

## Commercial thesis and evaluation hypothesis

The thesis is reduced investigation and change-review effort through reusable
workflows and inspectable evidence. Treat it as an evaluation hypothesis, not a
measured result.

Use these measures in buyer conversations. They are prompts for the buyer's own
numbers, not claims about ours.

| Product  | Measures                                                                                     |
| -------- | -------------------------------------------------------------------------------------------- |
| Search   | Investigation time, processing throughput, embedding cost per 1,000 records                  |
| Migrator | Review time per change, time spent reconstructing run history, maintenance effort per target |

## Strategic input provenance

The Atheros Search positioning also uses the user-provided strategic note
`Pasted text.txt` (Codex attachment
`d73fdc42-eb33-49e9-9b27-1bdb3a7a9686`, received 2026-10-06): emphasize
practical workflows, inspectable evidence, and human judgment. The excerpt
supplies no source URLs, sample, or research method. Treat it as directional
input, not representative community research, customer validation, or permission
to publish its claims. Do not reuse its unsupported speed, risk-reduction,
dispatch, "zero friction," or "zero infrastructure footprint" claims.

## Contact route

Every call to action opens `mailto:` at `rafael@rclabs.uk` through
`demoLink()`. Subjects are `Use-case discussion: [product]`. The email address
stays visible on `/demo/` with a copy button and a manual-copy fallback. The
copy states that a meeting is scheduled only after a time is agreed.

`contact.headline` is the section heading on the contact route, the product
contact banners, and the homepage. `contact.cta` labels the navigation and hero
actions. `contact.link` is the shorter label for a mailto link that already sits
under that heading, so one block never repeats the same words.

## Adding copy

1. Add or change the entry in `src/data/products.ts`. Homepage sections live in
   `homeSections`; route copy lives on `home`, `products`, `contact`, and the
   section objects.
2. Keep the synthetic label visible on anything the reader could mistake for
   real data.
3. Add or update the corresponding capability row in
   [content evidence](content-evidence.md).
4. If the change touches a CTA destination, email subject, or link, extend
   [tests/site.spec.ts](../tests/site.spec.ts) and rerun `npm run build` and
   `npm test`.
