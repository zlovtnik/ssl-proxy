export const email = 'rafael@rclabs.uk';

// The two load-bearing caveats, defined once so the product pages and the
// homepage reference entries can never drift apart.
export const searchCaveat =
  'An observation does not confirm a current connection or device identity.';
export const migratorCaveat =
  'SQL-file snapshots preserve source files and checksums. They do not back up database data.';

export const home = {
  // Google rewrites and truncates titles; this is an editorial target, not a
  // ranking rule. The homepage shares one title and description with Layout.
  title: 'Network Evidence Search & PostgreSQL Migrations',
  description:
    'Explore Atheros Search for network evidence and Schema Migrator for ordered SQL validation, PostgreSQL drift checks, and migration dry-run plans.',
  headline: ['Network evidence search', 'and PostgreSQL migration review'],
  subheadline:
    'Atheros Search and Schema Migrator are two independent products from RCLabs. Each one is shown here with a synthetic sample you can run in your browser.',
  primaryCta: { label: 'Explore the samples', href: '#playground' },
  secondaryCta: { label: 'Discuss your use case', href: '/demo/' },
  supporting:
    'Two independent tools. Browser-based samples. No account required.',
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
        'For PostgreSQL the folder sequence is extensions, schemas, types, tables, indexes, functions, views, cron hooks, materialized views, then cron jobs. Files sort by name inside a folder, so the table file runs before its index file. A filename alone never moves a file in front of an earlier folder.',
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
    title: 'Six technical terms and what they prove.',
    summary:
      'Evaluation questions come down to what a signal can establish. Each entry gives the operational meaning, a concrete example, and the limit.',
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
          'An index listed in the manifest but absent from the catalog is reported as missing. A column edited by hand is reported as a changed definition.',
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
        term: 'Hybrid ranking',
        meaning:
          'Sparse term matching and dense vector similarity are combined into one ranked list. ATHSEARCH_HYBRID_ALPHA controls the blend and defaults to 0.5.',
        example:
          'An exact device identifier and a paraphrase of the same question are ranked together, with each contribution visible in the explanation.',
        limit:
          'An explanation shows why one record sits above another in a result set; it is not a relevance score you can cite. Hybrid retrieval and explanations are general capabilities that Elasticsearch also documents.',
        link: {
          label: 'Open the ranking explanation',
          href: '/atheros-search/#demo',
        },
      },
      {
        term: 'Observed relationship',
        meaning:
          'A link between records that observations support: a device seen with an access point, or two events sharing a recorded identifier.',
        example:
          'Guest device 07 was observed with Lobby access point in one sample record.',
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
      title: 'Atheros Search versus keyword-only search',
      summary:
        'The smaller comparison on the evidence side: what changes when retrieval and correlation are part of the product.',
      caption:
        'How Atheros Search and keyword-only search with manual correlation handle each stage.',
      tableHead: [
        'Stage',
        'Atheros Search',
        'Keyword-only search and manual correlation',
      ],
      tableRows: [
        [
          'Query',
          'Term, vector, or hybrid retrieval over wireless, device, and proxy observations.',
          'Exact keywords, one tool and one query language at a time.',
        ],
        [
          'Ranking',
          'Per-result ranking explanations you open next to the record.',
          'Relevance is inferred from whatever order the tool returns.',
        ],
        [
          'Relationships',
          'Recorded relationships retrieved with the result as investigation context.',
          'Correlated by hand across tabs, exports, and dashboards.',
        ],
        [
          'Identity',
          'Suggestions are review candidates; an observation never confirms identity.',
          'The same limits apply, without the recorded evidence laid out for review.',
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

// Section headings shared by both product pages. The product-specific parts of
// each section sit on the product itself, so the two routes cannot drift apart.
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
    label: 'NETWORK EVIDENCE',
    homeTitle: 'Atheros Search: investigate network observations',
    headline: ['Search network records.', 'Inspect why they match.'],
    summary:
      'Combine term and vector search across wireless, device, and proxy observations. Inspect ranking explanations and related records to assess a result with its context.',
    problem:
      'Network and security engineers investigating records whose relevance, relationships, and identity implications need verification.',
    promise: 'A match is a starting point.',
    primaryCta: { label: 'Explore a sample investigation', href: '#demo' },
    secondaryCta: { label: 'Discuss your use case', href: '/demo/#search' },
    sections: {
      workflow: {
        ...workflowSection,
        title: 'From a question to leads you can review.',
        note: 'Each step takes a defined input and produces something you can read. Every record in the sample is synthetic.',
      },
      value: {
        ...audienceSection,
        title: 'Two ways to assess Atheros Search.',
      },
      evidence: {
        ...evidenceSection,
        caveatLabel: 'RELATIONSHIP VIEWS / READ WITH CARE',
        footnote:
          'The sample shows recorded observations only. It connects to no production system and makes no identity determination.',
      },
      glossary: glossarySection,
    },
    audiences: [
      {
        id: 'technical',
        title: 'For technical users',
        proposition:
          'Query, inspect, and review without leaving the investigation.',
        points: [
          'Query dense, sparse, or hybrid search through HTTP and gRPC interfaces.',
          'Inspect ranking explanations and related observations alongside each investigation; treat identity suggestions as candidates for review.',
        ],
      },
      {
        id: 'buyers',
        title: 'For buyers and investors',
        proposition: 'Keep the operating picture inspectable.',
        points: [
          'Keep search and vector storage in PostgreSQL, with embedding work handled by a configurable worker pool.',
          'Inspect embedding jobs, worker heartbeats, and processing failures when evaluating capacity and operating cost.',
        ],
      },
    ],
    workflow: [
      {
        step: 'Search',
        input: 'A question or exact terms, with filters',
        processing: 'Term matching, vector similarity, or hybrid ranking',
        output: 'Ranked observation records',
      },
      {
        step: 'Inspect',
        input: 'A selected result',
        processing: 'Retrieve ranking explanations and record context',
        output: 'Evidence explaining the match',
      },
      {
        step: 'Investigate',
        input: 'A device, access point, or related observation',
        processing: 'Retrieve recorded relationships and inventory context',
        output: 'Leads for further investigation',
      },
    ],
    caveat: searchCaveat,
    highlights: [
      ['Find the signal', 'Search by meaning, exact terms, or both.'],
      [
        'Understand the match',
        'Inspect ranking explanations and related observations.',
      ],
      [
        'Investigate the context',
        'Review relationships and possible identity matches.',
      ],
    ],
    features: [
      [
        'Search beyond exact words',
        'Use dense search for meaning, sparse search for terms, or hybrid search to combine both. Inspect wireless, device, and proxy records.',
      ],
      [
        'Follow the evidence',
        'Open ranking explanations and related observations. Network views help you explore relationships without treating an observation as a confirmed connection.',
      ],
      [
        'Review your inventory',
        'Explore observed device identifiers and review possible identity matches. A suggested match is a review candidate, not a confirmed device identity.',
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
    homeTitle: 'Schema Migrator: review PostgreSQL changes before execution',
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
] as const;

export const contact = {
  headline: ['Discuss your', 'use case.'],
  supporting:
    "Tell us what you need to investigate or change, your environment, and the constraints that matter. We'll agree on the next step by email.",
  cta: 'Discuss your use case',
  // Short form for a mailto link that already sits under the headline, so the
  // same words never appear twice in one block.
  link: 'Write to us',
} as const;

export const bothProducts = 'Atheros Search and Schema Migrator';

export const contactOptions = [
  {
    id: 'search',
    label: 'Atheros Search',
    subject: 'Atheros Search',
    text: 'Explore network evidence and investigation context.',
  },
  {
    id: 'migrator',
    label: 'Schema Migrator',
    subject: 'Schema Migrator',
    text: 'Review SQL files, dry-run plans, and run records.',
  },
  {
    id: 'both',
    label: 'Both products',
    subject: bothProducts,
    text: 'Discuss the two separate tools in one conversation.',
  },
] as const;

export function demoLink(product: string) {
  const subject = `Use-case discussion: ${product}`;
  const body = `Hello Rafael,\n\nI'd like to discuss our use case for ${product}.\n\nMy use case:\n\nEnvironment and constraints:\n\nPreferred times and time zone:\n\nThank you.`;
  return `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
