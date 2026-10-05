// Entirely synthetic examples. No customer records, credentials, or API calls.
export const investigations = [
  {
    query: 'Guest network observations',
    record: 'Guest device 07',
    source: 'Wireless observation',
    explanation:
      'The record includes the term "guest" and a description of a guest network. Hybrid search combines term matches and similarity of meaning.',
    relation:
      'Guest device 07 was observed with Lobby access point. This observation does not prove an active connection or confirmed device identity.',
  },
  {
    query: 'Proxy requests to an API',
    record: 'Proxy event 12',
    source: 'Proxy observation',
    explanation:
      'The record mentions an API request. The term match and similarity of meaning contribute to its position in the sample results.',
    relation:
      'Proxy event 12 and Device identifier 03 share a recorded identifier. A shared identifier alone does not confirm a physical device identity.',
  },
];
export const migrationSteps = [
  {
    name: 'Inspect SQL',
    title: '01 / Review the source',
    text: 'An ordered file adds a table for observations. Read the SQL before planning a change.',
    code: '001_observations.sql\n\nCREATE TABLE observations (\n  id bigint PRIMARY KEY,\n  observed_at timestamptz NOT NULL\n);',
  },
  {
    name: 'Review validation',
    title: '02 / Check the files',
    text: 'Sample offline validation: the file is readable and the ordered input is consistent. Offline validation does not prove that SQL will succeed against every target.',
    code: 'File: 001_observations.sql\nOffline checks: passed (sample)\nTarget connection: not attempted',
  },
  {
    name: 'Examine plan',
    title: '03 / See the proposed order',
    text: 'A sample dry-run plan places the table before its index. Nothing in this demonstration is applied to a database.',
    code: '1. tables/001_observations.sql\n2. indexes/002_observed_at.sql\n\nMode: dry-run\nDatabase changes: none',
  },
  {
    name: 'Inspect run record',
    title: '04 / Read the evidence',
    text: 'A fictional completed run records the target, outcome, and ordered files. This is an example audit record, not a live execution.',
    code: 'Run: sample-run-004\nTarget: example-postgres\nOutcome: completed (synthetic)\nFiles: 2\nSQL-file snapshot: sample-snapshot-004',
  },
];
