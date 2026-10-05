export const email = 'rafael@rclabs.uk';
export const products = [
  {
    id: 'search',
    name: 'Atheros Search',
    path: '/atheros-search/',
    label: 'NETWORK EVIDENCE',
    headline: 'Find the evidence in your network data.',
    summary:
      'Search network observations, inspect why records match, and put the evidence in context.',
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
  },
  {
    id: 'migrator',
    name: 'Schema Migrator',
    path: '/schema-migrator/',
    label: 'DATABASE CHANGE REVIEW',
    headline: 'Know what changes before you apply them.',
    summary:
      'Review ordered SQL, validate a plan, and keep a record of your database schema changes.',
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
  },
] as const;

export function demoLink(product: string) {
  const subject = `Guided demo request: ${product}`;
  const body = `Hello Rafael,\n\nI'd like a guided demo of ${product}.\n\nMy use case:\n\nPreferred times and time zone:\n\nThank you.`;
  return `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
