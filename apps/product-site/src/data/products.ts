export const email = 'rafael@rclabs.uk';

// The two load-bearing caveats, defined once so the product pages and the
// homepage reference entries can never drift apart.
export const searchCaveat =
  'Sensor placement, configured channel coverage, observation time, and MAC randomization limit what can be seen. An observed Wi-Fi identifier does not confirm a current connection or physical device identity.';
export const migratorCaveat =
  'SQL-file snapshots preserve source files and checksums. They do not back up database data.';
export const vpnCaveat =
  'Traffic categories are heuristics. Routing, inspection, and policy outcomes depend on deployment configuration. This synthetic sample establishes no VPN connection and sends no traffic.';
export const octopusCaveat =
  'Peaks are historical ingest-ledger counts, not a throughput limit, capacity forecast, savings, or latency claim. The metrics strip reflects live production data when the feed is configured.';

export const home = {
  // Google rewrites and truncates titles; this is an editorial target, not a
  // ranking rule. The homepage shares one title and description with Layout.
  title: 'Wi-Fi Investigation & PostgreSQL Migration Software',
  description:
    'Explore four RCLabs products for Wi-Fi investigation, PostgreSQL change review, WireGuard traffic handling, and durable sync coordination with Octopus.',
  headline: ['Understand the evidence.', 'Control the next step.'],
  subheadline:
    'Investigate wireless indicators, review database changes, follow network traffic, and coordinate durable ingestion. Four focused products, with workflows you can inspect.',
  primaryCta: { label: 'Explore the samples', href: '#playground' },
  secondaryCta: { label: 'Discuss your use case', href: '/demo/' },
  supporting:
    'Four products. Product samples and operational evidence. No account required.',
  eyebrow: 'RCLABS / INFRASTRUCTURE TOOLS',
  productsEyebrow: 'FOUR PRODUCTS / FOUR WORKFLOWS',
  playground: {
    eyebrow: 'THE PLAYGROUND',
    title: 'Take a closer look.',
    summary:
      'Explore Search, Migrator, and VPN / Proxy product samples. Every interaction stays in your browser. Octopus has a separate operational evidence page.',
  },
  relationship:
    'Search can review proxy observations through the configured backend. Schema Migrator has its own change-review workflow. The public samples run independently in your browser.',
  approach:
    'Each product makes a different part of your infrastructure inspectable.',
  explore:
    'Try product samples with synthetic records in your browser, or review Octopus operational evidence. No account or production connection required.',
} as const;

export const catalogue = {
  title: 'Products',
  description:
    'Compare Atheros Search, Schema Migrator, RCLabs VPN / Proxy, and Octopus by audience, inputs, workflow, and output.',
  headline: ['Find the tool', 'for the work ahead.'],
  summary:
    'Start with the question you need to answer. Four products offer focused workflows and clear operating boundaries, with browser samples or measured operational evidence to review.',
  comparisonTitle: 'A different job for each tool.',
  comparisonSummary:
    'Compare what goes in, what happens, and what you can review afterward.',
} as const;

// Homepage technical sections. Reference entries, capability tables and the
// benchmark protocol are rendered from this reviewed structure at build time.
// Only distinct information is published: no generated keyword variants. The
// benchmark publishes protocol until results are measured; synthetic examples
// are never reported as performance evidence.
export const homeSections = {
  guide: {
    id: 'postgres-migration-review',
    eyebrow: 'INTEGRATION GUIDE / POSTGRESQL',
    title: 'Review PostgreSQL migrations before execution.',
    summary:
      'Reviewers need to inspect the SQL and the execution order before anything is applied. This guide runs a two-file sample directory through the offline commands, then separates what those commands establish from what they cannot.',
    checks: {
      title: 'What an offline dry run checks',
      summary:
        'File validation and planning read a directory. They do not connect to PostgreSQL.',
      points: [
        [
          'Files only',
          'list, validate, and --dry-run apply read SQL files: discovery order, required headers, declared dependencies, and SQL parsing.',
        ],
        [
          'Target inspection',
          'drift-check and apply open a PostgreSQL connection to read a live catalog or change it. They are separate steps with separate evidence.',
        ],
        [
          'Boundary',
          'Offline validation does not guarantee successful execution. Permissions, locks, and data-dependent failures only appear when SQL runs.',
        ],
      ],
      note: 'Prerequisites: a JDK, sbt, and a directory of SQL files. The offline commands need no credentials, and every command below ran against a local sample with no production target.',
    },
    ordering: {
      title: 'Define the SQL files and execution order',
      summary:
        'Order comes from the supported folder sequence and the dependencies each file declares, not from an arbitrary filename.',
      detailLabel:
        'Show the directory, the SQL files, and how order is decided',
      tree: `sql/
  extensions/
  schemas/
  types/
  tables/001_observations.sql
  indexes/002_observed_at.sql
  functions/
  views/
  cron/
  materialized_views/`,
      files: [
        {
          path: 'tables/001_observations.sql',
          sql: `-- object: observations
-- folder: tables
-- depends_on: -
create table if not exists observations (
  id bigint primary key,
  source text not null,
  observed_at timestamptz not null
);`,
        },
        {
          path: 'indexes/002_observed_at.sql',
          sql: `-- object: observations observed_at index
-- folder: indexes
-- depends_on: observations
create index if not exists observations_observed_at_idx
  on observations (observed_at desc);`,
        },
      ],
      notes: [
        'For PostgreSQL the folder sequence is extensions, schemas, types, tables, indexes, functions, views, cron, then materialized_views. Files sort by name inside a folder, so the table file runs before its index file. A filename alone never moves a file in front of an earlier folder.',
        'Every file carries -- object, -- folder, and -- depends_on headers. A missing or ambiguous dependency is reported as a validation error, so an ordering mistake surfaces before execution.',
        'A directory that holds a manifest (core/manifest.yaml) uses its apply_order list instead of folder sorting, and SQL files not listed there are reported as ignored.',
        'Folders in the sequence that hold no files still need to exist; otherwise discovery reports each missing folder as a warning.',
      ],
    },
    preview: {
      title: 'Validate the files and inspect the dry-run preview',
      summary:
        'Three commands cover discovery, validation, and the preview. Each output below was captured from the sample directory.',
      detailLabel: 'Show the commands and their captured output',
      runs: [
        {
          command: 'sbt "run --db-kind postgres --sql-dir ./sql list"',
          output: `tables/001_observations.sql
indexes/002_observed_at.sql`,
          note: 'Discovery prints files in apply order. No database is contacted.',
        },
        {
          command: 'sbt "run --db-kind postgres --sql-dir ./sql validate"',
          output: `warning: tables/001_observations.sql: expected 'CREATE TABLE IF NOT EXISTS' for idempotency`,
          note: 'Findings are reported per file with the path that produced them. A clean directory prints nothing and exits 0, and warnings do not fail the run.',
        },
        {
          command: 'sbt "run --db-kind postgres --sql-dir ./sql validate"',
          output: `error: tables/002_broken.sql: SQL parsing check failed (unterminated single-quoted string)`,
          note: 'An invalid file is reported with its path and the run exits non-zero, so a pipeline can stop before any execution is attempted.',
        },
        {
          command:
            'sbt "run --db-kind postgres --sql-dir ./sql --dry-run apply"',
          output: `tables/001_observations.sql                      -- object: observations -- folder: tables -- depends_on: - create table if not exists observations ( id bigint primary ...
indexes/002_observed_at.sql                      -- object: observations observed_at index -- folder: indexes -- depends_on: observations create index if not exists obs...`,
          note: 'The preview prints each path with its SQL compacted to one line and cut after 120 characters. The current CLI shows ordered, shortened previews, not a complete executable deployment script.',
        },
      ],
    },
    separation: {
      title: 'Separate file changes, catalog drift and execution risk',
      summary:
        'Three different questions use three different inputs. Keeping them apart is what makes a review readable.',
      caption:
        'Four checks, what each one reads, and what each one establishes.',
      tableHead: ['Check', 'Reads', 'Needs a target', 'Establishes'],
      tableRows: [
        [
          'File discovery and validation',
          'SQL directory and ordering configuration',
          'No',
          'Files parse, headers and dependencies resolve, and the apply order is deterministic.',
        ],
        [
          'Dry-run preview',
          'Validated files',
          'No',
          'The ordered, shortened SQL that would be submitted for review.',
        ],
        [
          'PostgreSQL catalog drift',
          'Live catalog and expected definitions',
          'Yes',
          'Expected versus observed structure, reported as differences for review.',
        ],
        [
          'Execution',
          'Target connection and credentials',
          'Yes',
          'What actually ran. Permissions, locks, and data-dependent failures appear here.',
        ],
      ],
      risk: 'Drift inspection reports differences; it corrects nothing on its own. A migration-file checksum establishes that a file changed, not what the database looks like now. Only a rehearsal against a non-production target covers permission, lock, and data-dependent failures.',
    },
    sample: {
      title: 'Inspect a sample migration review',
      summary:
        'The browser demonstration runs on synthetic records. It shows the shape of a review, executes no SQL, and connects to no database.',
      primary: {
        label: 'Explore a sample migration review.',
        href: '/schema-migrator/#demo',
      },
      secondary: {
        label: 'Discuss your PostgreSQL review workflow.',
        href: '/demo/#migrator',
      },
    },
  },
  reference: {
    id: 'technical-reference',
    eyebrow: 'TECHNICAL REFERENCE',
    title: 'Six technical terms and what they do not prove.',
    summary:
      'Security and migration decisions depend on what evidence can establish. Each entry gives the meaning, an example, and its limits.',
    entries: [
      {
        term: 'Migration checksum mismatch',
        meaning:
          'A SHA-256 calculated from a SQL file no longer matches the value stored with it, so the file changed after it was recorded in a snapshot or run.',
        example:
          'A snapshot comparison reports the path as changed with the checksum before and after. Added and removed files use the same comparison.',
        limit:
          'It says nothing about the structure of a live database. A checksum is calculated over files, not over catalog objects.',
        link: {
          label: 'Inspect SQL-file snapshots in the sample',
          href: '/schema-migrator/#demo',
        },
      },
      {
        term: 'PostgreSQL catalog drift',
        meaning:
          'A difference between the structure your files and control records expect and the structure the live PostgreSQL catalog reports. Findings are typed as missing, untracked, definition changed, or pending control state.',
        example:
          'An index listed in the manifest but absent from the catalog is reported as missing. A tracked index with a different definition is reported as changed.',
        limit:
          'It corrects nothing. Drift inspection reports differences for a reviewed correction, and reading the catalog requires a target connection.',
        link: {
          label: 'See how file checks and drift are separated',
          href: '/#postgres-migration-review',
        },
      },
      {
        term: 'Dry-run preview',
        meaning:
          'The output of --dry-run apply: every discovered file path followed by a shortened preview of its SQL, printed in apply order without contacting a target.',
        example:
          'Whitespace is collapsed to one line and the text stops after 120 characters with an ellipsis, so long statements are visible but not complete.',
        limit:
          'It is not a complete executable deployment script, and it proves nothing about how the same SQL behaves against a real database.',
        link: {
          label: 'Read the captured preview',
          href: '/#postgres-migration-review',
        },
      },
      {
        term: 'Configured wireless indicator',
        meaning:
          'A sensor heuristic that flags a wireless pattern for an analyst to review, such as a suspected rogue access point, deauthentication flood, signal anomaly, attack sequence, or PMF-related pattern.',
        example:
          'A sample access point advertises an SSID that resembles a configured network name, so the sensor raises an indicator for review.',
        limit:
          'The configured heuristic raises a lead; it does not prove a successful attack, establish complete threat coverage, or replace analyst judgment.',
        link: {
          label: 'Review a synthetic wireless indicator',
          href: '/atheros-search/#demo',
        },
      },
      {
        term: 'Observed relationship',
        meaning:
          'A link between records that observations support: a device seen with an access point, or two events sharing a recorded identifier.',
        example:
          'Observed Wi-Fi identifier 07 appeared in a synthetic beacon observation associated with a sample site.',
        limit: searchCaveat,
        link: {
          label: 'Follow a relationship in the sample',
          href: '/atheros-search/#demo',
        },
      },
      {
        term: 'SQL-file snapshot',
        meaning:
          'A saved set of SQL source files with their SHA-256 checksums, kept so a later reviewer can compare what changed between two points in time.',
        example:
          'Two snapshots compare per path as added, removed, or changed, with the checksum recorded on each side.',
        limit: migratorCaveat,
        link: {
          label: 'Compare files in the sample',
          href: '/schema-migrator/#demo',
        },
      },
    ],
  },
  comparison: {
    id: 'workflow-comparison',
    eyebrow: 'ARCHITECTURE COMPARISON',
    title: 'Schema Migrator versus manually reviewed SQL.',
    summary:
      'Both paths can review a change. This comparison lists what each one assembles, and where the manual workflow is already sufficient.',
    caption:
      'How Schema Migrator and a manually reviewed SQL workflow handle each stage.',
    tableHead: ['Stage', 'Schema Migrator', 'Manually reviewed SQL'],
    tableRows: [
      [
        'File discovery',
        'Reads a fixed folder sequence or a manifest and lists the files it found.',
        'A reviewer lists the files and keeps the order in conventions or notes.',
      ],
      [
        'Ordering',
        'Folder sequence plus declared dependencies; a missing or ambiguous dependency is an error.',
        'Convention and reviewer memory; an ordering mistake surfaces in review or during execution.',
      ],
      [
        'Validation',
        'Offline parse, header, and idempotency checks reported per file as warnings or errors.',
        'Each file is read by a reviewer, so coverage depends on attention and time.',
      ],
      [
        'Target-state checks',
        'PostgreSQL catalog drift check compares expected definitions with the live catalog.',
        'Scripts are compared with the database by hand, or the comparison is skipped.',
      ],
      [
        'Execution',
        'Connection checks, guarded apply, and a dry run that prints before anything runs.',
        'SQL runs through psql or another migration tool chosen outside this service.',
      ],
      [
        'Retained evidence',
        'Run records, audit rows, and SQL-file snapshots with checksums for later comparison.',
        'Review history and comments; execution history is partial or reconstructed.',
      ],
    ],
    adequacy: {
      title: 'Where a manual review is enough',
      summary:
        'Adoption is not the point of this section. Keep the workflow you have when it already covers the case.',
      points: [
        'A small number of infrequent changes where one reviewer already reads every file end to end.',
        'A pipeline whose run history, rollback story, and audit trail already satisfy your change-review process.',
        'A review that must stay inside existing tooling. The file checks above need no target connection to evaluate.',
      ],
    },
    atheros: {
      title: 'Atheros Search / wireless indicators in site context',
      summary:
        'A synthetic review path shows how a monitored site, a configured wireless indicator, and its supporting observations fit together.',
      caption:
        'Illustrative path from a monitored site to an indicator and supporting wireless observation.',
      tableHead: [
        'Stage',
        'What the sample shows',
        'What it does not establish',
      ],
      tableRows: [
        [
          'Site scope',
          'A sensor location label and the wireless records associated with it.',
          'Complete coverage of the physical site or every device there.',
        ],
        [
          'Indicator',
          'A configured sensor heuristic, such as a suspected rogue access point or deauthentication pattern.',
          'Proof of a successful attack or a confirmed threat.',
        ],
        [
          'Observation',
          'Supporting wireless audit records with their observed time and channel.',
          'A current connection or a known physical device identity.',
        ],
        [
          'Analyst review',
          'An inspectable example that keeps the indicator beside its evidence.',
          'An end-to-end site dashboard in the current production console.',
        ],
      ],
    },
    notes: {
      title: 'Evaluation notes',
      detailLabel: 'Show the references this page relies on',
      summary:
        'Alternative-tool questions are evaluation questions, so this page answers them plainly.',
      items: [
        {
          label: 'Flyway documents migration dry runs',
          href: 'https://documentation.red-gate.com/fd/migration-command-dry-runs-275218517.html',
        },
        {
          label:
            'Elasticsearch documents explanations for reciprocal rank fusion',
          href: 'https://www.elastic.co/docs/reference/elasticsearch/rest-apis/reciprocal-rank-fusion#explain-in-rrf',
        },
        {
          label:
            'Google identifies scaled low-value content and doorway pages as spam',
          href: 'https://developers.google.com/search/docs/essentials/spam-policies',
        },
      ],
      close:
        'We claim no drop-in compatibility, no performance advantage, and no unique dry-run feature. The last reference is why this page publishes four distinct sections instead of generated keyword variants.',
    },
    cta: { label: 'Discuss your review workflow.', href: '/demo/' },
  },
  benchmark: {
    id: 'search-benchmark',
    eyebrow: 'BENCHMARK REPORT / STATUS',
    title: 'Term, vector and hybrid search on network observations.',
    summary:
      'One dataset, one labelled query set, three retrieval modes. The protocol is published now; numbers follow only once they are measured.',
    modes: {
      title: 'What is compared',
      summary:
        'All three modes read the same records, so a difference in results comes from retrieval rather than from different data.',
      caption: 'The three retrieval modes read the same records.',
      tableHead: ['Mode', 'How it retrieves', 'Queries in the labelled set'],
      tableRows: [
        [
          'Term (sparse)',
          'Matches terms present in the record text.',
          'Exact identifiers such as a device or access-point name.',
        ],
        [
          'Vector (dense)',
          'Matches meaning with 768-dimension embeddings.',
          'Paraphrases that share no terms with the record.',
        ],
        [
          'Hybrid',
          'Blends term and vector results; ATHSEARCH_HYBRID_ALPHA defaults to 0.5.',
          'Filtered investigations and questions mixing identifiers with description.',
        ],
      ],
    },
    protocol: {
      title: 'Methodology',
      summary:
        'Everything needed to reproduce a run, published together with the results.',
      detailLabel: 'Show the measurement protocol',
      points: [
        'One versioned dataset, frozen before measurement, covering wireless, device, and proxy observations.',
        'A labelled query set with exact identifiers, paraphrases, filtered investigations, and no-match cases.',
        'Relevance metrics computed against the labels, plus p50 and p95 latency, storage footprint, hardware, embedding model, and the full test configuration.',
        'Raw results and the reproducible method published side by side, with limitations stated next to the figures.',
      ],
    },
    status: {
      title: 'Status and limitations',
      points: [
        'No relevance, latency, or storage figures appear here yet, because measurement has not been run.',
        'The interactive samples on this site are synthetic demonstrations. Synthetic examples are not performance evidence.',
        'Atheros Search investigates wireless, device, and proxy observations; generic hybrid retrieval and explanations are not claimed as unique.',
      ],
      sample: {
        label: 'Open the Search sample',
        href: '/atheros-search/#demo',
      },
    },
  },
} as const;

// Shared section structure, with each product's story kept in its own model.
const workflowSection = { label: 'HOW IT WORKS' } as const;
const audienceSection = {
  label: 'AUDIENCE VALUE',
  note: 'Both readings are published openly. Choose the one that matches your question.',
} as const;
const evidenceSection = {
  label: 'SUPPORTING CAPABILITY EVIDENCE',
  title: 'Mechanisms you can inspect.',
  note: 'These are working behaviours of the product, not projected savings, latency, or market claims.',
} as const;
const glossarySection = {
  label: 'GLOSSARY',
  title: 'A few terms, made clear.',
} as const;

export const products = [
  {
    id: 'search',
    name: 'Atheros Search',
    path: '/atheros-search/',
    label: 'SITE-AWARE WIRELESS SECURITY',
    homeTitle: 'Atheros Search',
    headline: ['Review wireless indicators.', 'See their site context.'],
    summary:
      'Atheros Sensor passively listens on configured Wi-Fi channels and publishes audit records to the backend. Atheros Search helps teams review wireless indicators with monitored-site context and supporting observations.',
    problem:
      'Security teams responsible for monitored sites who need to assess wireless indicators alongside the observations that triggered them.',
    promise: 'An indicator points to evidence for review.',
    primaryCta: { label: 'Explore a sample site review', href: '#demo' },
    secondaryCta: { label: 'Discuss your use case', href: '/demo/#search' },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'From a monitored site to observations for review.',
        note: 'The synthetic sample illustrates a site-to-indicator-to-observation workflow. The current production console does not yet show this complete site overview end to end.',
      },
      value: {
        ...audienceSection,
        title: 'Two ways to assess Atheros Search.',
      },
      evidence: {
        ...evidenceSection,
        caveatLabel: 'COVERAGE AND IDENTITY / READ WITH CARE',
        footnote:
          'The sensor listens on configured channels and publishes audit records to the configured backend. Deployment requires monitor-mode Wi-Fi hardware. Audit fields and retention depend on deployment; no retention duration is promised here.',
      },
      glossary: glossarySection,
    },
    audiences: [
      {
        id: 'technical',
        title: 'For technical users',
        proposition:
          'Review a wireless indicator alongside its supporting observations.',
        points: [
          'Search dense, sparse, or hybrid records through HTTP and gRPC interfaces, with site and sensor scope where supported.',
          'Review configured rogue-access-point, deauthentication, signal, sequence, and PMF-related indicators as leads, not proof of compromise.',
        ],
      },
      {
        id: 'buyers',
        title: 'For buyers and operators',
        proposition: 'Keep the operating picture inspectable.',
        points: [
          'Keep search and vector storage in PostgreSQL, with embedding work handled by a configurable worker pool.',
          'Inspect embedding jobs, worker heartbeats, and processing failures when evaluating the search service and its operations.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Scope a site',
        input: 'A monitored location and available sensor observations',
        processing: 'Use recorded location and sensor context',
        output: 'Wireless records within the sample scope',
      },
      {
        step: 'Review an indicator',
        input: 'A configured wireless detection pattern',
        processing: 'Inspect the heuristic reason and related records',
        output: 'An indicator for analyst review',
      },
      {
        step: 'Inspect observations',
        input: 'Supporting wireless audit records',
        processing: 'Review observed identifiers, time, channel, and evidence',
        output: 'Context for a human assessment',
      },
    ],
    caveat: searchCaveat,
    highlights: [
      ['Scope the evidence', 'Review observations from a monitored site.'],
      [
        'Review wireless indicators',
        'See configured patterns beside supporting observations.',
      ],
      [
        'Keep judgment with the analyst',
        'Treat an indicator as a lead to investigate, not a verdict.',
      ],
    ],
    features: [
      [
        'Listen on configured Wi-Fi channels',
        'Atheros Sensor uses monitor-mode capture. It listens on configured channels rather than joining access points, then publishes audit records to the configured backend.',
      ],
      [
        'Review configured wireless indicators',
        'Sensor heuristics can flag suspected rogue access points, deauthentication floods, signal anomalies, attack sequences, and PMF-related patterns for analyst review.',
      ],
      [
        'Inspect supporting observations',
        'Review wireless audit records with site, sensor, channel, and observed-time context. Retention details depend on deployment.',
      ],
      [
        'Treat identifiers carefully',
        'Inventory shows observed Wi-Fi identifiers. MAC randomization and incomplete sensor coverage mean identifiers are not a count of confirmed physical devices.',
      ],
      [
        'See processing progress',
        'Inspect embedding jobs, worker heartbeats, and extract, transform, load (ETL) health to understand how records become searchable.',
      ],
    ],
    glossary: [
      [
        'Dense search',
        'Finds records with similar meaning using numerical representations called embeddings.',
      ],
      ['Sparse search', 'Finds records by matching terms.'],
      ['Hybrid search', 'Combines meaning and term matches to rank results.'],
      [
        'Wireless indicator',
        'A configured sensor heuristic that points to a wireless pattern for an analyst to review. It does not prove a threat.',
      ],
      [
        'Observed Wi-Fi identifier',
        'An identifier seen in captured wireless traffic. It may not map one-to-one to a physical device.',
      ],
      [
        'Observed relationship',
        'A link supported by recorded observations. It does not prove a current connection or confirmed identity.',
      ],
      [
        'ETL',
        'Extract, transform, load: the processing steps that prepare data for use.',
      ],
    ],
  },
  {
    id: 'migrator',
    name: 'Schema Migrator',
    path: '/schema-migrator/',
    homeTitle: 'Schema Migrator',
    label: 'DATABASE CHANGE REVIEW',
    headline: ['Review SQL changes', 'before you run them.'],
    summary:
      'Discover SQL files in a fixed order, validate them offline, and inspect a dry-run plan. Keep execution records and file checksums for subsequent review.',
    problem:
      'Platform and database engineers reviewing SQL execution order, target drift, and evidence of previous changes.',
    promise: 'Read the plan before the run.',
    primaryCta: { label: 'Explore a sample migration review', href: '#demo' },
    secondaryCta: { label: 'Discuss your use case', href: '/demo/#migrator' },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'From source files to a reviewable record.',
        note: 'Each step takes a defined input and produces something you can read. The public demonstration executes no SQL.',
      },
      value: {
        ...audienceSection,
        title: 'Two ways to assess Schema Migrator.',
      },
      evidence: {
        ...evidenceSection,
        caveatLabel: 'SQL-FILE SNAPSHOTS / READ WITH CARE',
        footnote:
          'The sample review records are synthetic. It connects to no target and executes no SQL.',
      },
      glossary: glossarySection,
    },
    audiences: [
      {
        id: 'technical',
        title: 'For technical users',
        proposition: 'Review the order, the target, and the evidence.',
        points: [
          'Discover ordered SQL and run offline validation before reviewing a dry-run plan.',
          'Inspect PostgreSQL catalog drift, SQL-file checksums, and recorded runs through the CLI and operator interfaces.',
        ],
      },
      {
        id: 'buyers',
        title: 'For buyers and investors',
        proposition: 'Make change review a repeatable handoff.',
        points: [
          'Use stored run and audit records to support change reviews and operational handoffs.',
          'Keep target configuration and encrypted credentials in one service, with connection checks and guarded execution.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Validate',
        input: 'SQL files and ordering configuration',
        processing: 'Discover files and validate inputs offline',
        output: 'Ordered files and validation findings',
      },
      {
        step: 'Plan',
        input: 'Validated files and target configuration',
        processing: 'Generate a dry-run plan',
        output: 'Proposed execution order for review',
      },
      {
        step: 'Review the record',
        input: 'A completed run and saved SQL files',
        processing: 'Retrieve execution evidence and compare checksums',
        output: 'Run history and file changes',
      },
    ],
    caveat: migratorCaveat,
    highlights: [
      [
        'Read the source',
        'Inspect SQL files and their explicit execution order.',
      ],
      ['Review the plan', 'Check inputs offline and examine the dry-run plan.'],
      [
        'Keep the evidence',
        'Inspect audit records and compare SQL-file snapshots.',
      ],
    ],
    features: [
      [
        'Spot schema drift',
        'Compare PostgreSQL catalog structure with expected definitions. Drift is a difference between the expected schema and the target database.',
      ],
      [
        'Compare SQL files',
        'Capture SQL-file snapshots and compare their checksums. These snapshots preserve source files; they are not database backups.',
      ],
      [
        'Manage your targets',
        'Keep target configuration in one place, check connections, and store target credentials encrypted. PostgreSQL is the primary target story.',
      ],
      [
        'Keep changes accountable',
        'Discover files in order, validate offline, review dry-run plans, and inspect guarded migration runs and audit records. Review before applying to a real target.',
      ],
    ],
    glossary: [
      [
        'SQL',
        'Structured Query Language: the language used to define and query database structures.',
      ],
      [
        'Schema',
        'The structure of a database, including tables, columns, and related objects.',
      ],
      ['Dry-run', 'A plan of proposed work without applying the changes.'],
      [
        'Drift',
        'A difference between expected definitions and the database structure.',
      ],
      [
        'SQL-file snapshot',
        'A saved set of SQL source files and checksums. It does not back up database data.',
      ],
      [
        'Checksum',
        'A value calculated from a file to detect changes to its contents.',
      ],
    ],
  },
  {
    id: 'vpn',
    name: 'RCLabs VPN / Proxy',
    path: '/vpn-proxy/',
    homeTitle: 'RCLabs VPN / Proxy',
    label: 'WIREGUARD / TRANSPARENT PROXY',
    headline: ['Follow the traffic.', 'Inspect the decision.'],
    summary:
      'Bring traffic through WireGuard ingress, handle connections with a transparent proxy, and inspect classification and policy decisions through audit records.',
    problem:
      'Network and platform teams operating WireGuard ingress, transparent proxy policies, and traffic audit pipelines.',
    promise: 'An inspectable path through your network.',
    primaryCta: { label: 'Explore a sample traffic flow', href: '#demo' },
    secondaryCta: { label: 'Discuss your use case', href: '/demo/#vpn' },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'From ingress to an inspectable decision.',
        note: 'Follow a configured traffic path, its classification, and the evidence it produces. The sample does not establish a tunnel.',
      },
      value: {
        ...audienceSection,
        title: 'Two ways to assess RCLabs VPN / Proxy.',
      },
      evidence: {
        ...evidenceSection,
        caveatLabel: 'CONFIGURATION / COVERAGE',
        footnote:
          'Sample flows and decisions are illustrative fixtures. No credentials, network connection, or live policy changes are involved.',
      },
      glossary: glossarySection,
    },
    audiences: [
      {
        id: 'technical',
        title: 'For technical users',
        proposition: 'Trace ingress, handling, and evidence.',
        points: [
          'Review WireGuard ingress and transparent proxy handling as distinct stages of the traffic path.',
          'Inspect coarse traffic categories and the configured reasons behind connection handling.',
        ],
      },
      {
        id: 'buyers',
        title: 'For buyers and operators',
        proposition: 'Understand the operating boundary.',
        points: [
          'Evaluate the proxy, administrative readiness surfaces, and the separate staged WireGuard key rotator.',
          'Plan for audit publishing through Redpanda and backend processing through Octopus; persistence is owned by the backend.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Enter',
        input: 'A configured WireGuard peer and traffic',
        processing: 'Receive traffic through WireGuard ingress',
        output: 'Traffic available to the configured proxy path',
      },
      {
        step: 'Handle',
        input: 'Destination and available connection metadata',
        processing: 'Classify the flow and apply configured handling',
        output: 'A connection decision with a recorded reason',
      },
      {
        step: 'Inspect',
        input: 'Proxy observations and audit events',
        processing: 'Publish evidence to the configured backend',
        output: 'Records for operational review',
      },
    ],
    caveat: vpnCaveat,
    highlights: [
      ['WireGuard ingress', 'Receive traffic from configured peers.'],
      ['Transparent handling', 'Inspect categories and configured decisions.'],
      ['Audit publishing', 'Follow observations into the backend pipeline.'],
    ],
    features: [
      [
        'Receive WireGuard traffic',
        'The Rust proxy owns WireGuard ingress and tunnel transport. Peer setup and network routing are deployment prerequisites.',
      ],
      [
        'Classify destinations',
        'Hostname and port heuristics group traffic as advertising/tracking, analytics, CDN, essential API, authentication, or unknown. A category is not a security verdict.',
      ],
      [
        'Inspect configured handling',
        'The transparent proxy supports policy-driven connection handling, including blocking and bypass paths. The active configuration determines the outcome.',
      ],
      [
        'Publish audit evidence',
        'The proxy publishes observations to the configured Redpanda pipeline. Octopus owns durable ingestion and maintained PostgreSQL projections.',
      ],
      [
        'Operate peer keys separately',
        'The WireGuard key rotator supports staged server and peer key rotation as a separate operational component.',
      ],
    ],
    glossary: [
      [
        'WireGuard',
        'A VPN protocol used here as a traffic ingress path for configured peers.',
      ],
      [
        'Transparent proxy',
        'A proxy that receives traffic through configured network routing rather than an application-specific proxy setting.',
      ],
      [
        'Traffic category',
        'A coarse label inferred from destination metadata. It does not prove whether traffic is safe or malicious.',
      ],
      [
        'Policy decision',
        'The connection handling selected by the configured rules, with its recorded reason.',
      ],
      [
        'Audit publishing',
        'Sending observations to a backend pipeline for processing and later review.',
      ],
    ],
  },
  {
    id: 'octopus',
    name: 'Octopus',
    path: '/octopus/',
    homeTitle: 'Octopus',
    label: 'DURABLE SYNC COORDINATOR',
    headline: ['Coordinate the work.', 'Count the evidence.'],
    summary:
      'Octopus is a Scala coordinator on the JVM for durable ingestion and sync work. It discovers records, leases and dispatches work, and records ingestion evidence in PostgreSQL.',
    problem:
      'Platform and data teams who need to follow work from incoming streams through durable job state to recorded ingestion evidence.',
    promise: 'Every processed record leaves a ledger row you can count.',
    primaryCta: {
      label: 'Review measured throughput',
      href: '#operational-evidence',
    },
    secondaryCta: { label: 'Discuss your use case', href: '/demo/#octopus' },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'From incoming streams to durable evidence.',
        note: 'Follow discovery, coordinated work, and the ledger that records ingestion across paths.',
      },
      value: {
        ...audienceSection,
        title: 'Two ways to assess Octopus.',
      },
      evidence: {
        ...evidenceSection,
        caveatLabel: 'MEASUREMENT / OPERATING BOUNDARY',
        footnote:
          'Published measurements come from the production ingest ledger and coordinator pipeline metrics. They describe recorded activity under that deployment configuration.',
      },
      glossary: glossarySection,
    },
    audiences: [
      {
        id: 'technical',
        title: 'For technical users',
        proposition: 'Trace ingestion through durable state.',
        points: [
          'Inspect committed consumer offsets and ingestion evidence by consumer group, topic, partition, and offset.',
          'Coordinate deduplication, leases, batching, and load outcomes through PostgreSQL-backed state.',
        ],
      },
      {
        id: 'buyers',
        title: 'For buyers and operators',
        proposition: 'Evaluate operations with a defined count.',
        points: [
          'Review historical peak day and week counts with their source and UTC boundaries.',
          'Read the pending ledger, ingest rate, and last ingest success from live production metrics.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Discover work',
        stageLabel: 'Discovery',
        input: 'Incoming records and sync discovery requests',
        processing:
          'Consume streams with committed group offsets and durable deduplication',
        output: 'Recorded work available for coordination',
      },
      {
        step: 'Lease and dispatch',
        stageLabel: 'Dispatch',
        input: 'Durable jobs and pending work',
        processing:
          'Acquire leases, form batches, and dispatch configured loads',
        output: 'Tracked jobs and load outcomes',
      },
      {
        step: 'Record evidence',
        stageLabel: 'Evidence',
        input: 'Consumed records and their broker coordinates',
        processing:
          'Persist ingestion evidence and maintain configured projections',
        output: 'Durable ledger rows for operational review and counting',
      },
    ],
    caveat: octopusCaveat,
    highlights: [
      ['Discover work', 'Bring incoming streams into durable coordination.'],
      ['Coordinate dispatch', 'Track leases, batches, and load outcomes.'],
      ['Count evidence', 'Review historical ledger counts with provenance.'],
    ],
    features: [
      [
        'Durable ingestion',
        'PostgreSQL stores ingestion evidence keyed by consumer group, topic, partition, and offset. Repeated delivery preserves the original first-seen time.',
      ],
      [
        'At-least-once delivery',
        'Consumers resume from committed group offsets. Durable deduplication accounts for repeated delivery; new groups start from the earliest retained records.',
      ],
      [
        'Leases and dispatch',
        'Coordinator-owned job state, leases, batches, and outbox records track work and its load outcomes.',
      ],
      [
        'Maintained projections',
        'Octopus maintains PostgreSQL projections and derives alerts. Atheros Search owns embedding job processing through its worker pool.',
      ],
      [
        'Measured ledger history',
        'Peak day and week counts use durable ingestion evidence across ingest paths. Process restarts do not reset these ledger rows.',
      ],
    ],
    glossary: [
      [
        'Ingest ledger',
        'Durable evidence of consumed records, identified by consumer group, topic, partition, and offset. Counts include all recorded dispositions and are not a count of unique business events.',
      ],
      ['Lease', 'A time-bounded claim on work used to coordinate processing.'],
      ['Outbox', 'Durable records of messages waiting for dispatch.'],
      [
        'At-least-once',
        'A delivery model in which records may be delivered again. Durable deduplication handles repeated work.',
      ],
      [
        'Peak day / week',
        'The highest historical ledger-row count in a UTC calendar day or Monday-to-Sunday ISO week, including the current period so far.',
      ],
    ],
  },
] as const;

export type Product = (typeof products)[number];
export type ProductId = Product['id'];
export function getProduct(id: ProductId): Product {
  return products.find((product) => product.id === id)!;
}

// Octopus publishes measured evidence; it has no synthetic demo.
export const sampleProducts = products.filter(
  (product) => product.id !== 'octopus',
);

export const contact = {
  headline: ['Discuss your', 'use case.'],
  supporting:
    "Tell us what you need to investigate, change, route, or ingest, your environment, and the constraints that matter. We'll agree on the next step by email.",
  cta: 'Discuss your use case',
  // Short form for a mailto link that already sits under the headline, so the
  // same words never appear twice in one block.
  link: 'Write to us',
} as const;

export const allProducts = products.map((product) => product.name).join(', ');

export const contactOptions = [
  {
    id: 'search',
    label: 'Atheros Search',
    subject: 'Atheros Search',
    text: 'Review site-scoped wireless indicators and supporting observations.',
  },
  {
    id: 'migrator',
    label: 'Schema Migrator',
    subject: 'Schema Migrator',
    text: 'Review SQL files, dry-run plans, and run records.',
  },
  {
    id: 'vpn',
    label: 'RCLabs VPN / Proxy',
    subject: 'RCLabs VPN / Proxy',
    text: 'Review WireGuard ingress, transparent proxy handling, and audit evidence.',
  },
  {
    id: 'octopus',
    label: 'Octopus',
    subject: 'Octopus',
    text: 'Review durable ingestion, work leases, and measured ledger evidence.',
  },
  {
    id: 'all',
    label: 'All products',
    subject: allProducts,
    text: 'Discuss all four products in one conversation.',
  },
] as const;

export function demoLink(product: string) {
  const subject = `Use-case discussion: ${product}`;
  const body = `Hello Rafael,\n\nI'd like to discuss our use case for ${product}.\n\nMy use case:\n\nEnvironment and constraints:\n\nPreferred times and time zone:\n\nThank you.`;
  return `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

export const notFound = {
  title: 'Page not found',
  description:
    'This page is no longer available. Explore RCLabs products and technical guides.',
  eyebrow: '404 / PAGE NOT FOUND',
  heading: 'This page is not available.',
  summary: 'The address may have changed, or the page may have been retired.',
  productsLabel: 'Explore the products',
  guidesLabel: 'Read the technical guides',
} as const;

export interface GuideSection {
  id: string;
  title: string;
  paragraphs: readonly string[];
  points?: readonly string[];
  examples?: readonly { label: string; code: string; note: string }[];
  table?: {
    caption: string;
    headers: readonly string[];
    rows: readonly (readonly string[])[];
  };
}

export interface Guide {
  slug: string;
  title: string;
  description: string;
  productId: ProductId;
  eyebrow: string;
  introduction: string;
  caveat: string;
  sections: readonly GuideSection[];
  sources: readonly { label: string; href: string; note: string }[];
  related: readonly string[];
}

export const guideIndex = {
  title: 'PostgreSQL migration and wireless investigation guides',
  description:
    'Practical guides to PostgreSQL migration dry runs, schema drift, file checksums, wireless indicators, and hybrid search, with worked examples and limits.',
  summary:
    'Review migration files, compare PostgreSQL catalogs, and investigate wireless observations with distinct worked examples and explicit evidence boundaries.',
  eyebrow: 'TECHNICAL GUIDES',
  introduction:
    'Follow a specific review task from its inputs to the evidence it produces. These guides explain the mechanisms behind Schema Migrator and Atheros Search software with local or clearly labelled synthetic examples.',
  contentsLabel: 'In this guide',
  sourcesTitle: 'Implementation evidence',
  sourcesNote:
    'The linked repository files describe the implementation behind these examples. Examples are educational inputs, not production records or measured results.',
  limitsLabel: 'Operating boundary',
  relatedTitle: 'Continue the review',
  productLinkLabel: 'Explore the product and its synthetic sample',
  indexLinkLabel: 'Browse all technical guides',
  readLabel: 'Read guide',
} as const;

const repositorySource = (path: string) => {
  const repositories = [
    ['apps/schema-migrator/', 'schema-migrator'],
    ['apps/integration-console/', 'integration-console'],
  ] as const;
  for (const [prefix, repository] of repositories) {
    if (path.startsWith(prefix)) {
      return `https://github.com/zlovtnik/${repository}/blob/main/${path.slice(prefix.length)}`;
    }
  }
  return `https://github.com/zlovtnik/ssl-proxy/blob/main/${path}`;
};

export const guides: readonly Guide[] = [
  {
    slug: 'postgresql-migration-dry-run',
    title: 'Review a PostgreSQL migration dry run before execution',
    description:
      'Run a two-file PostgreSQL migration example through discovery, validation, and an offline dry-run preview. Learn what the checks establish and what needs a target.',
    productId: 'migrator',
    eyebrow: 'POSTGRESQL / FILE REVIEW',
    introduction:
      'A useful migration dry run begins with inspectable SQL and an explicit order. Schema Migrator can discover and validate files and print their ordered preview without opening a database connection. This local example creates a table before its index.',
    caveat: `${migratorCaveat} The public demonstration executes no SQL. An offline preview does not establish whether a target can execute the statements.`,
    sections: [
      {
        id: 'inputs',
        title: 'Prepare the complete two-file input',
        paragraphs: [
          'Use a local checkout of Schema Migrator, a JDK and sbt. Run the commands from apps/schema-migrator. Create a new empty directory named review-example and save only the two files below in its tables and indexes folders. Keep this disposable input separate from the repository SQL tree. No target credentials are needed for these offline commands.',
        ],
        examples: [
          {
            label: 'Local example directory; all listed folders exist',
            code: homeSections.guide.ordering.tree.replace(
              /^sql\//,
              'review-example/',
            ),
            note: 'Empty folders avoid missing-folder discovery warnings. This example uses folder ordering, not a manifest.',
          },
          ...homeSections.guide.ordering.files.map((file) => ({
            label: file.path,
            code: file.sql,
            note: 'Illustrative source SQL for the local example; it is not a production migration.',
          })),
        ],
        points: [
          'PostgreSQL discovery orders extensions, schemas, types, tables, indexes, functions, views, cron, then materialized_views. Filenames sort inside each folder.',
          'The object, folder, and depends_on headers declare the object and its dependency. The index names observations as its prerequisite.',
          'For a directory using core/manifest.yaml, apply_order determines the sequence instead; unlisted SQL is reported as ignored.',
        ],
      },
      {
        id: 'discover-validate',
        title: 'Discover files, then review validation findings',
        paragraphs: [
          'The application output below was captured for the local example and excludes sbt startup messages. list reports order. validate reports file-specific findings; warnings do not fail the command, while validation errors do.',
        ],
        examples: homeSections.guide.preview.runs.slice(0, 2).map((run) => ({
          label: run.command.replace('./sql', './review-example'),
          code: run.output,
          note: run.note,
        })),
        points: [
          'The lowercase CREATE TABLE in this fixture still produces the shown idempotency warning. Read findings alongside the complete SQL rather than treating a zero exit status as proof of execution safety.',
          'As a separate negative test, an unterminated single-quoted SQL string produces a parsing error with the file path and a non-zero exit. Keep invalid test files out of the two-file preview input.',
        ],
      },
      {
        id: 'preview',
        title: 'Read the ordered preview beside the full files',
        paragraphs: [
          '--dry-run apply prints file paths and compacted SQL in apply order. It does not execute the table or index statement.',
        ],
        examples: homeSections.guide.preview.runs.slice(3).map((run) => ({
          label: run.command.replace('./sql', './review-example'),
          code: run.output,
          note: run.note,
        })),
        points: [
          'The printer collapses whitespace and shortens SQL after 120 characters. Retain the full files as the review artifact; the displayed preview cannot be used as a complete deployment script.',
          'Check that each referenced table, type and extension precedes its dependent objects. Review destructive operations and transaction requirements in the full statements.',
        ],
      },
      {
        id: 'next-check',
        title: 'Choose the next check for the unresolved question',
        paragraphs: [
          'A file review answers what would be submitted, not what already exists or what a target will permit. Select the next step according to the evidence you still need.',
        ],
        table: {
          caption: 'Separate offline review from target-dependent checks',
          headers: ['Question', 'Check', 'Boundary'],
          rows: [
            [
              'Do files parse and dependencies resolve?',
              'Offline validation',
              'No target execution evidence',
            ],
            [
              'What structure exists now?',
              'Connected catalog drift inspection',
              'Findings require review; no automatic correction',
            ],
            [
              'Will these statements work with these data and permissions?',
              'Rehearsal on a non-production target',
              'Production locks, data, and concurrent activity can still differ',
            ],
          ],
        },
      },
    ],
    sources: [
      {
        label: 'CLI validation and offline command paths',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/cli/Commands.scala',
        ),
        note: 'list, validate and dry-run apply use SQL-only configuration validation.',
      },
      {
        label: 'PostgreSQL folder order',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/discovery/FolderOrder.scala',
        ),
        note: 'The supported folder sequence for this example.',
      },
      {
        label: 'Preview output formatting',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/output/ReportPrinter.scala',
        ),
        note: 'File paths, warnings, errors and dry-run previews are printed as review output.',
      },
    ],
    related: ['postgresql-schema-drift', 'migration-checksum-mismatch'],
  },
  {
    slug: 'postgresql-schema-drift',
    title:
      'Investigate PostgreSQL schema drift with expected and observed definitions',
    description:
      'Compare expected PostgreSQL definitions, live catalog objects, and migration control state in a worked schema drift example. Separate detection from remediation.',
    productId: 'migrator',
    eyebrow: 'POSTGRESQL / CATALOG REVIEW',
    introduction:
      'Schema drift asks whether a live PostgreSQL catalog matches the expected structure. It is a different question from whether SQL files have changed. Schema Migrator compares expected definitions and control records with catalog objects, then reports differences for review.',
    caveat: `${migratorCaveat} Catalog inspection needs a target connection. Drift findings do not correct the database, and a finding is not a safe migration plan by itself.`,
    sections: [
      {
        id: 'scope',
        title: 'Establish the expected state and target scope',
        paragraphs: [
          'Start with the reviewed SQL manifest and its control state, then identify the target database and schemas being inspected. A catalog read needs access to that target. Record when it was read so findings are not mistaken for a timeless view.',
        ],
        points: [
          'Keep manifest definitions, migration apply statuses, source paths and recorded checksums with the report.',
          'Check whether control state was available. A warning about unavailable control state leaves part of the comparison unresolved.',
          'A pending or failed apply status is a control-state issue, not proof that someone edited a catalog object manually.',
        ],
      },
      {
        id: 'example',
        title: 'Compare a synthetic expected catalog with an observed catalog',
        paragraphs: [
          'The following teaching example is constructed, not captured from a database. Assume tracked objects without a pending status have an applied control status; the final object is pending.',
        ],
        table: {
          caption:
            'Synthetic schema drift inputs and expected finding categories',
          headers: ['Object', 'Expected', 'Observed', 'Finding'],
          rows: [
            [
              'public.observations_source_idx',
              'Index on source',
              'Same index name, indexed column is observed_at',
              'definition_changed',
            ],
            [
              'public.observations_observed_at_idx',
              'Tracked index on observed_at',
              'Index absent',
              'missing_actual',
            ],
            [
              'public.review_notes',
              'Absent from manifest and control records',
              'Table present',
              'untracked_actual',
            ],
            [
              'public.observations_source_order_idx',
              'Tracked index; apply_status=pending',
              'Index absent',
              'pending_or_failed_control',
            ],
          ],
        },
        points: [
          'A missing object can result from incomplete application or later removal. The category alone does not establish the cause.',
          'An untracked object may be an intended addition that has not been recorded. Compare ownership and change history before proposing removal.',
          'The pending index is reported through its control status rather than counted again as an ordinary missing object.',
        ],
      },
      {
        id: 'definitions',
        title: 'Read the definition behind a changed-index finding',
        paragraphs: [
          'Names are insufficient: the expected and observed object must also agree on the compared definition. This synthetic index comparison changes the indexed column while retaining the same index name.',
        ],
        examples: [
          {
            label: 'Synthetic expected and observed definitions',
            code: 'Expected: CREATE INDEX observations_source_idx\n          ON public.observations (source);\nObserved: CREATE INDEX observations_source_idx\n          ON public.observations (observed_at);\nFinding:  definition_changed',
            note: 'A condensed teaching view, not a literal API response. Retain the complete reported DDL for an actual review.',
          },
        ],
        points: [
          'Definition comparisons cover functions, procedures, triggers, views, materialized views and indexes. The reader checks table presence, but does not compare column definitions or nullability; those need a separate check.',
          'An index definition finding describes structure, not how a proposed replacement will behave under load. Review data size, permissions and locking conditions before execution.',
        ],
      },
      {
        id: 'remediation',
        title: 'Turn a finding into a reviewed change',
        paragraphs: [
          'Preserve the observed definitions and check the source history. Decide whether the manifest or the live object reflects the intended design. Write a new ordered migration when a correction is needed, rehearse it against non-production data, and inspect the catalog again afterward.',
        ],
        points: [
          'Keep active ordered migrations append-only; do not conceal drift by rewriting an already recorded file.',
          'Handle target credentials and DDL through the deployment workflow. Catalog inspection may create and drop temporary session views to normalize view definitions; it applies no permanent correction.',
          'A clean report establishes agreement within the inspected scope and comparison logic, not complete database health.',
        ],
      },
    ],
    sources: [
      {
        label: 'PostgreSQL drift diff engine',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/server/PostgresDriftDiffEngine.scala',
        ),
        note: 'Finding types, control-state handling and expected-versus-observed comparisons.',
      },
      {
        label: 'PostgreSQL catalog reader',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/server/PostgresCatalogReader.scala',
        ),
        note: 'The live catalog scope that supports drift inspection.',
      },
    ],
    related: ['migration-checksum-mismatch', 'postgresql-migration-dry-run'],
  },
  {
    slug: 'migration-checksum-mismatch',
    title: 'Understand a migration checksum mismatch before changing history',
    description:
      'Reproduce a SQL-file checksum mismatch locally, interpret added, removed, and changed snapshot paths, and distinguish file integrity from PostgreSQL schema drift.',
    productId: 'migrator',
    eyebrow: 'POSTGRESQL / SOURCE INTEGRITY',
    introduction:
      'A migration checksum mismatch means the recorded file bytes and the current file bytes differ. It does not tell you whether a live table or index changed. Schema Migrator snapshots compare SQL files by path and SHA-256, keeping this question separate from catalog drift.',
    caveat: `${migratorCaveat} Equal checksums establish equal file content for the comparison; they do not prove successful execution or agreement with a live database.`,
    sections: [
      {
        id: 'reproduce',
        title: 'Reproduce a changed-file comparison without a database',
        paragraphs: [
          'Run this standard-library Python example in a temporary directory. It keeps the original SQL unchanged and adds a comment to a separate copy, so it demonstrates a mismatch without modifying an active migration.',
        ],
        examples: [
          {
            label: 'Local synthetic SQL-file comparison',
            code: String.raw`python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

original = b"create table observations (id bigint primary key);\n"
with TemporaryDirectory() as directory:
    before = Path(directory) / "before.sql"
    after = Path(directory) / "after.sql"
    before.write_bytes(original)
    after.write_bytes(original + b"-- review note\n")
    base_hash = sha256(before.read_bytes()).hexdigest()
    compare_hash = sha256(after.read_bytes()).hexdigest()
    print("base_sha256:", base_hash)
    print("compare_sha256:", compare_hash)
    print("changed:", base_hash != compare_hash)
PY`,
            note: 'Both files are disposable inputs. The comment changes bytes even though it does not change the table definition.',
          },
          {
            label: 'Captured output from the disposable-file example',
            code: 'base_sha256: 750a67cd5c8cfcb2214b3ab0e3e68c7fd579221b005c70b9ca76597188db5b53\ncompare_sha256: 056db53ecbcb355def021845147df816ff383ace88b5664099dfaf06fd7e22bf\nchanged: True',
            note: 'These are actual SHA-256 values for the synthetic inputs above, not values from a migration run or database.',
          },
        ],
      },
      {
        id: 'interpret',
        title: 'Read the path and both checksums',
        paragraphs: [
          'Snapshot comparison matches files by path. A path present only in the newer snapshot is added; one present only in the base is removed. A path present in both is changed when its SHA-256 differs. Unchanged paths do not produce diff items.',
        ],
        table: {
          caption: 'Synthetic snapshot path comparison',
          headers: [
            'Path',
            'Base snapshot',
            'Comparison snapshot',
            'Diff category',
          ],
          rows: [
            [
              'tables/001_observations.sql',
              'Original bytes',
              'Same bytes plus a comment',
              'changed',
            ],
            ['indexes/002_observed_at.sql', 'Absent', 'New file', 'added'],
            ['views/003_review.sql', 'File present', 'Absent', 'removed'],
          ],
        },
        points: [
          'Keep the full before and after checksums and the original source available to the reviewer.',
          'A rename can appear as one removed path and one added path. The diff categorizes paths; it does not infer a semantic rename.',
          'Whitespace, line endings and comments can change a file checksum without changing database semantics. Inspect the actual diff before deciding on a correction.',
        ],
      },
      {
        id: 'decision',
        title: 'Resolve the discrepancy without erasing evidence',
        paragraphs: [
          'First check which source version was reviewed and recorded. If a recorded migration was accidentally edited, restore the reviewed bytes from version control. If the intended schema needs to change, add a new ordered migration rather than rewriting the old record.',
        ],
        points: [
          'For a file that has not been applied, follow the project review process and record the new reviewed version before execution.',
          'Do not replace a recorded checksum solely to make the mismatch disappear. That removes the evidence you need to understand the discrepancy.',
          'If the concern is the live database, perform catalog drift inspection separately. A file can change while the database stays the same, or the database can change while files stay identical.',
        ],
      },
    ],
    sources: [
      {
        label: 'SQL-file snapshot comparison',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/store/SnapshotStore.scala',
        ),
        note: 'Diff items are added, removed or changed, with before and after SHA-256 values.',
      },
      {
        label: 'Migration planning',
        href: repositorySource(
          'apps/schema-migrator/src/main/scala/com/sslproxy/schema/engine/MigrationPlan.scala',
        ),
        note: 'Ordered SQL inputs remain separate from snapshot comparison.',
      },
    ],
    related: ['postgresql-schema-drift', 'postgresql-migration-dry-run'],
  },
  {
    slug: 'rogue-access-point-investigation',
    title: 'Investigate a suspected rogue access point with site context',
    description:
      'Work through synthetic rogue access point observations using SSID, BSSID, channel, time, and authorized-network context. Separate wireless indicators from confirmed incidents.',
    productId: 'search',
    eyebrow: 'WIRELESS / ACCESS POINT REVIEW',
    introduction:
      'A suspicious SSID or BSSID is a lead to investigate. Start with the monitored site and the observation time, then compare the advertised network with the site inventory. Atheros Sensor raises configured indicators; Atheros Search helps review the observations behind them.',
    caveat: `${searchCaveat} A rogue access point indicator does not prove an attack or an unauthorized physical device.`,
    sections: [
      {
        id: 'prerequisites',
        title: 'Record what the sensor could observe',
        paragraphs: [
          'Passive capture requires Linux, monitor-mode Wi-Fi hardware, and configured channels. Establish the sensor location, interface, time range and channel coverage before comparing access points. Use an up-to-date authorized-network list for that site.',
        ],
        points: [
          'A sensor observing channel 6 cannot establish that nothing happened on unmonitored channels.',
          'The detector reviews beacon and probe-response observations. An advertised network name alone does not establish a client connection.',
          'Record maintenance windows, managed AP changes and the age of the authorized inventory alongside the observation.',
        ],
      },
      {
        id: 'records',
        title: 'Follow a synthetic SSID discrepancy',
        paragraphs: [
          'In this constructed example, the site inventory lists LabNet as an authorized network. The two rows are educational observation summaries, not sensor payloads or production records.',
        ],
        table: {
          caption: 'Synthetic observations at lab-west, sensor-lab-01',
          headers: [
            'Time (UTC)',
            'SSID',
            'BSSID',
            'Channel',
            'Observed security',
          ],
          rows: [
            [
              '2026-10-08 10:00:00',
              'LabNet',
              '02:00:00:00:00:10',
              '6',
              'Encryption advertised',
            ],
            [
              '2026-10-08 10:00:05',
              'LabNet',
              '02:00:00:00:00:20',
              '6',
              'No encryption advertised',
            ],
          ],
        },
        examples: [
          {
            label: 'Synthetic detector inputs and review reason',
            code: 'Configured known SSID: LabNet\nObserved SSID: LabNet\nObserved security_flags: 0\nReview reason: open_authorized_ssid',
            note: 'This matches the implementation condition: a known SSID with security_flags equal to zero. It is a reason to inspect the evidence, not an incident verdict.',
          },
        ],
      },
      {
        id: 'investigate',
        title: 'Review the indicator against the supporting observations',
        paragraphs: [
          'Scope the review to lab-west and the observation interval. Inspect the beacon or probe-response fields and related records for each BSSID. Preserve the source keys, timestamps and detector reasons so another analyst can follow the same evidence.',
        ],
        points: [
          'Check the configured network list: was an open guest network, temporary AP or recent controller change omitted?',
          'Compare the AP inventory and maintenance history. An SSID shared by multiple BSSIDs can be expected in a managed deployment.',
          'Review related observations before deciding whether the pattern persists. The detector also has reasons for similar SSIDs, changed BSSID-to-SSID mappings, and channel or vendor conflicts; each reason needs its own context.',
          'Use location or device identity suggestions as review candidates. Do not turn an observed address into a confirmed owner or physical asset.',
        ],
      },
      {
        id: 'outcome',
        title: 'Document uncertainty as part of the finding',
        paragraphs: [
          'A useful investigation note states the site, time window, observed fields, triggered reason, inventory comparison and unresolved questions. A possible explanation such as maintenance must be corroborated rather than assumed.',
        ],
        examples: [
          {
            label: 'Synthetic analyst note',
            code: 'Site: lab-west\nWindow: 10:00:00-10:00:05 UTC\nLead: known SSID LabNet observed without advertised encryption\nEvidence: BSSID 02:00:00:00:00:20, channel 6\nInventory check: unresolved; ask the site owner to confirm AP changes\nConclusion: review candidate; no connection or device identity confirmed',
            note: 'An example of recording the evidence boundary; no message is sent by this guide.',
          },
        ],
        points: [
          'Capture placement, missed frames and incomplete channel coverage can leave gaps.',
          'A stale authorized list or a legitimate configuration change can explain a lead. Close the finding only after recording the supporting check.',
        ],
      },
    ],
    sources: [
      {
        label: 'Rogue access point detection conditions',
        href: repositorySource(
          'services/atheros-sensor/src/detect_state_sections/rogue_deauth.rs',
        ),
        note: 'Known open SSIDs, similar names, mapping changes and conflict reasons are heuristic leads.',
      },
      {
        label: 'Sensor capture and configuration',
        href: repositorySource('services/atheros-sensor/README.md'),
        note: 'Monitor-mode prerequisites and configured capture scope.',
      },
      {
        label: 'Search review surfaces',
        href: repositorySource(
          'apps/integration-console/atheros-search/README.md',
        ),
        note: 'Search, inventory and record explanation capabilities.',
      },
    ],
    related: [
      'wifi-deauthentication-investigation',
      'hybrid-search-network-observations',
    ],
  },
  {
    slug: 'wifi-deauthentication-investigation',
    title:
      'Investigate Wi-Fi deauthentication observations without overclaiming',
    description:
      'Use a synthetic time-window example to review Wi-Fi deauthentication and disassociation indicators, capture scope, detector thresholds, and corroborating evidence.',
    productId: 'search',
    eyebrow: 'WIRELESS / TIME-WINDOW REVIEW',
    introduction:
      'A burst of observed deauthentication frames needs a scoped investigation. The sensor counts deauthentication and disassociation observations in a configured window and raises an indicator when the threshold is reached. The count establishes observed frames, not confirmed disruption or attacker identity.',
    caveat: `${searchCaveat} Observed management frames and a threshold crossing do not prove that a client disconnected, that an attack succeeded, or who transmitted the frames.`,
    sections: [
      {
        id: 'scope',
        title: 'Keep capture scope and detector settings together',
        paragraphs: [
          'Use monitor-mode hardware on the channels under review and record the sensor, site, interval and configuration. Atheros Sensor groups valid BSSIDs separately; when a BSSID cannot be parsed, it uses a fallback source identity. Both deauthentication and disassociation frames count.',
        ],
        points: [
          'A zero threshold or zero window disables this detector path.',
          'A cooldown can suppress repeated alerts even when frames continue to be observed. Alert totals are not raw frame totals.',
          'Missing frames, unmonitored channels and capture placement limit the interpretation of both positive and absent findings.',
        ],
      },
      {
        id: 'window',
        title: 'Reproduce the reasoning with a small synthetic window',
        paragraphs: [
          'For this teaching example, choose a threshold of 3 frames and a 10-second window. These are example settings, not production defaults or recommended thresholds. All four observations have BSSID 02:00:00:00:00:30 at lab-west on channel 6.',
        ],
        table: {
          caption: 'Synthetic frame sequence for one BSSID',
          headers: [
            'Time (UTC)',
            'Frame subtype',
            'Count at this observation',
            'Interpretation',
          ],
          rows: [
            ['10:00:00', 'deauthentication', '1', 'Below example threshold'],
            [
              '10:00:01',
              'disassociation',
              '2',
              'Also counted by this detector',
            ],
            [
              '10:00:02',
              'deauthentication',
              '3',
              'Threshold reached; eligible to alert',
            ],
            [
              '10:00:03',
              'deauthentication',
              '4',
              'Still observed; cooldown may suppress another alert',
            ],
          ],
        },
        examples: [
          {
            label: 'Reproducible teaching count; not the sensor implementation',
            code: `python3 - <<'PY'
times = [0, 1, 2, 3]
window_seconds = 10
threshold = 3
for index, now in enumerate(times):
    count = sum(now - time < window_seconds for time in times[:index + 1])
    print(now, count, count >= threshold)
PY`,
            note: 'The four timestamps stay inside one window. The actual detector uses per-second buckets and a frame-time cooldown; this small example illustrates the threshold only.',
          },
          {
            label: 'Captured output from the teaching count',
            code: '0 1 False\n1 2 False\n2 3 True\n3 4 True',
            note: 'Each row shows elapsed seconds, observed count and whether the example threshold is reached. It is not sensor alert output.',
          },
        ],
      },
      {
        id: 'corroborate',
        title: 'Check the lead against nearby records',
        paragraphs: [
          'Review the source and receiver addresses, reason fields where decoded, BSSID, channel and timestamps in the original audit observations. Compare records before and after the burst, then check AP or client operational logs when available.',
        ],
        points: [
          'Look for related association and authentication observations, but do not infer a complete session from a partial passive capture.',
          'Compare the interval with maintenance, AP restarts and client behavior. A frame subtype by itself does not reveal why the frame was transmitted.',
          'Inspect PMF-related context when available; a PMF indicator remains a separate heuristic and does not prove a client accepted or rejected the frame.',
          'Retain the configured threshold and cooldown with the investigation so a later analyst can explain why one alert represents several observations.',
        ],
      },
      {
        id: 'report',
        title: 'Report the observation and the unresolved impact separately',
        paragraphs: [
          'A defensible note can say that three matching frames were observed in the example window and that the configured condition was reached. It should state separately whether client impact was corroborated, which channels were monitored, and what identity remains unknown.',
        ],
        examples: [
          {
            label: 'Synthetic investigation conclusion',
            code: 'Observed: 3 deauthentication/disassociation frames in the example window\nScope: lab-west, sensor-lab-01, channel 6, BSSID 02:00:00:00:00:30\nDetector condition: example threshold reached\nClient impact: not established by passive observations\nTransmitter identity: not confirmed',
            note: 'This records a lead without claiming a successful attack or a current connection.',
          },
        ],
      },
    ],
    sources: [
      {
        label: 'Deauthentication counter and cooldown',
        href: repositorySource(
          'services/atheros-sensor/src/detect_state_sections/rogue_deauth.rs',
        ),
        note: 'Accepted subtypes, threshold comparison, grouping and cooldown behavior.',
      },
      {
        label: 'Wireless audit model',
        href: repositorySource('services/atheros-sensor/src/model.rs'),
        note: 'Published observations retain sensor, site, time and decoded frame context.',
      },
      {
        label: 'PMF review heuristics',
        href: repositorySource(
          'services/atheros-sensor/src/detect_state_sections/pmf.rs',
        ),
        note: 'PMF-related patterns are additional indicators, not proof of client behavior.',
      },
    ],
    related: [
      'rogue-access-point-investigation',
      'hybrid-search-network-observations',
    ],
  },
  {
    slug: 'hybrid-search-network-observations',
    title: 'Understand hybrid search for network and wireless observations',
    description:
      'Compare term, vector, and hybrid retrieval on the same synthetic observations. Work through weighted reciprocal-rank fusion and interpret explain data and sparse fallback.',
    productId: 'search',
    eyebrow: 'SEARCH / RETRIEVAL REVIEW',
    introduction:
      'Term search and vector search offer different ways to retrieve a record. Atheros Search combines their ranked candidates with weighted reciprocal-rank fusion. A same-data example makes that mechanism inspectable without claiming that one mode is more accurate or faster.',
    caveat: `${searchCaveat} Ranking is a retrieval signal, not a probability of an incident. This guide publishes no measured relevance, latency or storage result.`,
    sections: [
      {
        id: 'data',
        title: 'Fix the query and scope before comparing modes',
        paragraphs: [
          'Use the same dataset, source kinds, site filter, observation interval and result budget for each mode. This synthetic text collection illustrates candidate ranking; it is not an ingested sensor payload or an actual embedding run.',
        ],
        table: {
          caption: 'Synthetic observations, all scoped to lab-west',
          headers: ['Record', 'Observation summary'],
          rows: [
            ['A', 'Deauthentication frames observed on channel 6'],
            [
              'B',
              'Management frames coincide with a reported wireless interruption',
            ],
            [
              'C',
              'AP maintenance note mentions deauthentication during review',
            ],
          ],
        },
        examples: [
          {
            label: 'Fixed teaching query and scope',
            code: 'Query: wireless deauthentication\nSite: lab-west\nObservation interval: 2026-10-08 10:00-10:10 UTC\nResult budget: 3\nCompare: sparse, dense, hybrid',
            note: 'Conceptual inputs, not a literal request body. A real comparison must preserve the same service filters and record collection.',
          },
        ],
      },
      {
        id: 'modes',
        title: 'Keep term and vector evidence separate',
        paragraphs: [
          'Sparse retrieval uses PostgreSQL full-text term matching. Dense retrieval compares query embeddings with stored embeddings for the configured model. Hybrid retrieval merges their candidate lists by source key rather than adding incomparable raw keyword and cosine scores.',
        ],
        table: {
          caption:
            'Assigned teaching ranks on the same data; not measured retrieval results',
          headers: [
            'Record',
            'Sparse rank',
            'Dense rank',
            'Review interpretation',
          ],
          rows: [
            ['A', '1', '2', 'Appears in both candidate lists'],
            [
              'B',
              'Not returned',
              '1',
              'Semantic candidate in the assigned example',
            ],
            [
              'C',
              '2',
              'Not returned',
              'Term candidate in the assigned example',
            ],
          ],
        },
        points: [
          'Missing from a returned candidate list does not mean the record is absent from the dataset.',
          'Dense retrieval depends on embedding availability and model coverage. Keep processing health and coverage with a real evaluation.',
          'Do not label these assigned ranks as a benchmark. Measured relevance needs independently judged queries and captured results.',
        ],
      },
      {
        id: 'fusion',
        title: 'Calculate an explainable fusion stage',
        paragraphs: [
          'The implementation uses k = 60. A dense candidate contributes alpha / (60 + rank); a sparse candidate contributes (1 - alpha) / (60 + rank). For the example alpha = 0.5, the record appearing in both lists accumulates both contributions. These values are arithmetic outputs for the assigned ranks, not service measurements.',
        ],
        examples: [
          {
            label: 'Synthetic weighted RRF calculation; alpha = 0.5',
            code: 'A = 0.5 / (60 + 2) + 0.5 / (60 + 1) = 0.016261\nB = 0.5 / (60 + 1)                      = 0.008197\nC = 0.5 / (60 + 2)                      = 0.008065\nFusion order: A, B, C',
            note: 'Values are rounded to six decimals. This illustrates the fusion stage, not an incident confidence score.',
          },
        ],
        points: [
          'Candidates are deduplicated by source key. Equal final scores use source-key ordering as the tie-break.',
          'Changing alpha changes the relative weight of the two ranked lists; it does not calibrate the result into a probability.',
          'Retain the selected record and the original result envelope when explaining a real result. A later search can observe a changed collection or embedding state.',
        ],
      },
      {
        id: 'explain',
        title: 'Read the available explanation and actual mode used',
        paragraphs: [
          'A scoped explanation resolves the selected record within the supplied scope and computes its sparse score directly. It does not invent dense or fusion ranks that are unavailable. Preserve dense and fusion information from the original response when it exists.',
        ],
        points: [
          'Check mode_used, fallback_code and the returned candidate counts. A request for hybrid search can return sparse results when the embedding leg is unavailable or lacks coverage.',
          'A fallback reason explains retrieval availability, not the truth of an observation. Do not describe a sparse fallback result as successful semantic retrieval.',
          'Open the source record to review time, site, identifiers and decoded evidence. Relevance alone does not establish a current connection or physical device identity.',
          'For a real evaluation, record dataset version, model, filters, queries, judgments, returned ranks and fallback state before discussing measured quality.',
        ],
      },
    ],
    sources: [
      {
        label: 'Weighted reciprocal-rank fusion',
        href: repositorySource(
          'apps/integration-console/atheros-search/internal/search/fusion.go',
        ),
        note: 'Rank weighting, source-key deduplication and deterministic tie-breaking.',
      },
      {
        label: 'Fusion constant and raw result fields',
        href: repositorySource(
          'apps/integration-console/atheros-search/internal/search/types.go',
        ),
        note: 'The implementation sets rrfK to 60.',
      },
      {
        label: 'Search orchestration and fallback',
        href: repositorySource(
          'apps/integration-console/atheros-search/internal/search/service.go',
        ),
        note: 'Requested and actual modes, candidate counts and semantic fallback behavior.',
      },
      {
        label: 'Scoped record explanation',
        href: repositorySource(
          'apps/integration-console/atheros-search/internal/search/scoped_explain.go',
        ),
        note: 'Direct sparse-score explanation preserves the selected record and scope.',
      },
    ],
    related: [
      'rogue-access-point-investigation',
      'wifi-deauthentication-investigation',
    ],
  },
];

export const guidePath = (slug: string) => `/guides/${slug}/`;

export function getGuide(slug: string): Guide {
  const guide = guides.find((item) => item.slug === slug);
  if (!guide) throw new Error(`Unknown guide: ${slug}`);
  return guide;
}
