# Messaging framework

One visual system, two product stories. RCLabs presents Atheros Search and
Schema Migrator as two independent tools. Each tool has its own audience,
workflow, and caveats. Nothing on the public site implies a shared connection
between them.

Copy lives in [`src/data/products.ts`](../src/data/products.ts). Route files
render that model; they do not restate headlines, summaries, calls to action,
audience propositions, or workflow steps. Edit the model, not the pages.

## Positioning

- Investigate network evidence.
- Review database changes.
- Convert technically with a working synthetic sample.
- Convert commercially with "Discuss your use case" over email.

Use "interactive sample", not "live sample". Every demonstration runs on
synthetic fixtures in the browser. There is no production connection, account,
or credential anywhere on this site.

## Route stories

| Route               | Story                                            | Primary action                              | Commercial action                        |
| ------------------- | ------------------------------------------------ | ------------------------------------------- | ---------------------------------------- |
| `/`                 | Two independent tools, one attention to evidence | Explore the samples, in the hero playground | Discuss your use case, `/demo/`          |
| `/atheros-search/`  | Search network records, inspect why they match   | Explore a sample investigation, `#demo`     | Discuss your use case, `/demo/#search`   |
| `/schema-migrator/` | Review SQL changes before you run them           | Explore a sample migration review, `#demo`  | Discuss your use case, `/demo/#migrator` |
| `/demo/`            | Choose a product, then write                     | Product-specific email links                | Visible address with copy fallback       |
| `/accessibility/`   | Read the site in the way that works for you      | Reading and display settings                | Barrier report address                   |

Product pages follow one order: hero with sample, three-step workflow, technical
and buyer value, supporting capability evidence, glossary, contact. The homepage
carries the shared FAQ.

## Audience propositions

Both audience readings appear openly on each product page. They are not hidden
behind tabs or filters, so a reader can disagree with one and keep reading.

- Technical users receive mechanisms: interfaces, ordering, validation,
  explanations, checksums, catalog drift, run records.
- Buyers and investors receive operating shape: storage location, worker pools,
  guarded execution, credential handling, audit records.

Each product also carries one `problem` statement naming its audience, used above
the audience pair and in the homepage question about who the tools are for.

## Evidence rules

Publish mechanisms and demonstrable capabilities. Do not publish savings,
latency, market size, or defensibility claims. Architecture alone does not
establish a moat.

Numeric improvement requires a documented baseline, workload, environment, and
measurement method. Until those exist, no figure appears on the public site.
Supporting evidence is traced in [content evidence](content-evidence.md).

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

1. Add or change the entry in `src/data/products.ts`.
2. Keep the synthetic label visible on anything the reader could mistake for
   real data.
3. Add or update the corresponding capability row in
   [content evidence](content-evidence.md).
4. If the change touches a CTA destination, email subject, or link, extend
   [tests/site.spec.ts](../tests/site.spec.ts) and rerun `npm run build` and
   `npm test`.
