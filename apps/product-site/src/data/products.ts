export const email = 'rafael@rclabs.uk';

export const home = {
  headline: ['Investigate network evidence.', 'Review database changes.'],
  subheadline:
    'Atheros Search combines search results, ranking explanations, and recorded relationships. Schema Migrator validates ordered SQL and produces plans before execution. Explore both workflows with synthetic data.',
  primaryCta: { label: 'Explore the samples', href: '#playground' },
  secondaryCta: { label: 'Discuss your use case', href: '/demo/' },
  supporting:
    'Two independent tools. Browser-based samples. No account required.',
} as const;

export const products = [
  {
    id: 'search',
    name: 'Atheros Search',
    path: '/atheros-search/',
    label: 'NETWORK EVIDENCE',
    headline: ['Search network records.', 'Inspect why they match.'],
    summary:
      'Combine term and vector search across wireless, device, and proxy observations. Inspect ranking explanations and related records to assess a result with its context.',
    primaryCta: { label: 'Explore a sample investigation', href: '#demo' },
    secondaryCta: { label: 'Discuss your use case', href: '/demo/#search' },
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
    caveat:
      'An observation does not confirm a current connection or device identity.',
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
    label: 'DATABASE CHANGE REVIEW',
    headline: ['Review SQL changes', 'before you run them.'],
    summary:
      'Discover SQL files in a fixed order, validate them offline, and inspect a dry-run plan. Keep execution records and file checksums for subsequent review.',
    primaryCta: { label: 'Explore a sample migration review', href: '#demo' },
    secondaryCta: { label: 'Discuss your use case', href: '/demo/#migrator' },
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
    caveat:
      'SQL-file snapshots preserve source files and checksums. They do not back up database data.',
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
} as const;

export function demoLink(product: string) {
  const subject = `Use-case discussion: ${product}`;
  const body = `Hello Rafael,\n\nI'd like to discuss our use case for ${product}.\n\nMy use case:\n\nEnvironment and constraints:\n\nPreferred times and time zone:\n\nThank you.`;
  return `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
