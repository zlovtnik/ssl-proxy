// Entirely synthetic examples. No customer records, credentials, or API calls.
export const investigations = [
  {
    query: 'North Campus / suspected rogue access point',
    site: 'North Campus / sample',
    sensor: 'Sensor 02 / sample',
    indicator: 'Suspected rogue access point',
    reason: 'SSID lookalike heuristic / sample',
    record: 'Observed access point 07',
    identifier: 'Observed Wi-Fi identifier 07',
    source: 'Beacon observation / sample',
    channel: 'Channel 6 / 09:42 UTC / sample time',
    explanation:
      'A sample beacon advertises an SSID that resembles a configured network name. The sensor can raise this configured heuristic as an indicator for analyst review; the match alone does not prove a rogue access point.',
    relation:
      'Sensor 02 recorded a beacon from observed access point 07 on channel 6 at the sample time. This synthetic relationship does not prove an active connection or physical device identity.',
  },
  {
    query: 'West Distribution / PMF-related reconnect pattern',
    site: 'West Distribution / sample',
    sensor: 'Sensor 01 / sample',
    indicator: 'PMF-related reconnect pattern',
    reason: 'Deauthentication followed by reassociation / sample',
    record: 'Observed Wi-Fi identifier 12',
    identifier: 'Observed Wi-Fi identifier 12',
    source: 'Wireless observation / sample',
    channel: 'Channel 11 / 10:08 UTC / sample time',
    explanation:
      'The sample sequence contains wireless observations associated with a PMF-related detector pattern. It is presented as an indicator for a person to assess, not a confirmed attack.',
    relation:
      'The sample records a deauthentication observation followed by a reassociation observation on the monitored channel. Channel hopping, sensor placement, and the observation window affect what may be captured.',
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
