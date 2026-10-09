# Release checklist

This checklist covers the public products, technical guides, and search routing. Prior release
evidence is retained in [validation results](validation-results.md). Copy and
appearance follow [messaging](messaging.md) and [the design system](design-system.md).

## Local verification

- [ ] Record the final build, type check, and browser-suite results for this revision.
- [ ] Check all public routes in the shared dark theme, including guides, navigation and contact.
- [ ] Confirm saved light/system themes and system colour preferences cannot change the theme.
- [ ] Check every sample, expanded disclosure, and card at 320-1440px.
- [ ] Confirm the removed display-settings dock stays absent and browser zoom
      and system motion preferences work.
- [ ] Check enlarged text, spacing overrides, focus, contrast, and hidden panels.
- [ ] Inspect dark screenshots of the homepage, catalogue, and every demo state.
- [ ] Confirm static stories, contact, and sample explanations without JavaScript.
- [ ] Record browser coverage explicitly; previous browser runs are not evidence for this revision.

## Human evaluation

- [ ] Inspect true 400% browser zoom; viewport simulation is a reflow proxy.
- [ ] Inspect forced-colours rendering and system reduced-motion settings on supported devices.
- [ ] Complete keyboard walkthroughs across all routes and demo states.
- [ ] Evaluate VoiceOver/Safari and NVDA/Firefox, including live announcements,
      disclosure reading order, and diagrams.
- [ ] Conduct usability sessions with disabled participants.
- [ ] Review reading level, specialist terms, and all applicable criteria in the
      [accessibility matrix](accessibility-matrix.md).
- [ ] Review all four product stories and their caveats against repository evidence.
- [ ] Verify the live feed is configured (`PUBLIC_OCTOPUS_STATS_URL`) in production
      and the metrics strip shows live data (not the build-time fallback label).
- [ ] Verify CORS from the live origin; confirm foreign origins get no CORS headers.
- [ ] Confirm rendered pages and shipped assets contain no internal dashboard
      links, addresses, credentials, or topology.
- [ ] Update public accessibility claims only to the level demonstrated.

## Reviewed publication

- [ ] Build with `PUBLIC_SITE_URL=https://rclabs.uk`; verify all public sitemap URLs,
      canonical URLs, robots response, and updated social preview.
- [ ] Push reviewed Git changes and inspect the automatic Cloudflare Pages preview.
- [ ] Merge reviewed changes to main, then verify the served revision and routes.
- [ ] Verify image responses for the PNG/ICO favicons, real 404 responses for
      unmatched addresses, and the contact permanent redirects.
- [ ] Verify a preview branch remains `noindex` even when it inherits production variables.
- [ ] Inspect the sitemap and indexing status in Search Console manually after publication.
- [ ] Verify plain email contact without JavaScript on the live origin.
- [ ] Verify the no-JS page still shows the build-time snapshot values.
- [ ] Verify `/metrics` and `/actuator/prometheus` are not publicly routed.
- [ ] Check social preview compatibility on the sharing platforms in use.
- [ ] Recheck analytics consent, rejection, and withdrawal on the production build.
- [ ] Measure field performance with the existing consent requirements.

The Git-connected Pages configuration is recorded in [README](../README.md)
and [wrangler.jsonc](../wrangler.jsonc). This frontend does not provision
hosting or change Kubernetes resources.

## Live feed configuration

The Octopus product page fetches live metrics from the coordinator's
`GET /public/stats` endpoint when `PUBLIC_OCTOPUS_STATS_URL` is set at build
time. The committed [`octopus-stats.json`](../src/data/octopus-stats.json)
serves as the no-JS / fetch-failure fallback.

- Set `PUBLIC_OCTOPUS_STATS_URL` only in the production Pages environment.
  Preview builds leave it unset so previews never fetch production stats.
- The Octopus service exposes `/public/stats` via `OCTOPUS_PUBLIC_STATS_ENABLED=true`
  and `OCTOPUS_PUBLIC_STATS_ALLOWED_ORIGINS` (CORS allowlist).
- The Kubernetes ingress path-allowlists `/public/stats` only; `/metrics` and
  `/actuator/prometheus` stay internal.

## Fallback snapshot hygiene

When the live feed is unavailable or for initial population, refresh the
committed snapshot manually. Use the authorized operator environment and its
existing database credentials. Do not copy credentials, internal addresses, or
dashboard links into the site.

Run both peak queries in one read-only, repeatable-read transaction:

```sql
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '60s';
SELECT to_char(transaction_timestamp() AT TIME ZONE 'UTC',
               'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS as_of;

SELECT date_trunc('day', first_seen_at AT TIME ZONE 'UTC')::date AS day,
       count(*) AS records
FROM octopus_core.ingestion_evidence
GROUP BY 1
ORDER BY records DESC, day ASC
LIMIT 1;

SELECT date_trunc('week', first_seen_at AT TIME ZONE 'UTC')::date AS week_start,
       date_trunc('week', first_seen_at AT TIME ZONE 'UTC')::date + 6 AS week_end,
       count(*) AS records
FROM octopus_core.ingestion_evidence
GROUP BY 1, 2
ORDER BY records DESC, week_start ASC
LIMIT 1;
COMMIT;
```

The source is always `octopus_core.ingestion_evidence` / `first_seen_at`, with
no operation, disposition, or path filter. Do not substitute a process counter.

Read these operator metrics at the same `asOf` evaluation time:

| JSON field | Prometheus expression | Conversion |
| --- | --- | --- |
| `ingestProcessedRatePerSec` | `octopus:ingest_processed:rate5m` | Finite nonnegative number; records per second averaged over five minutes |
| `pendingLedgerCount` | `octopus:pending_ledger:current` | Nonnegative integer |
| `backpressureActive` | `max(coordinator_backpressure_active_value)` | 1 is true; 0 is false; missing is not false |
| `lastIngestSuccessAt` | `max(coordinator_ingest_ledger_last_success_timestamp_seconds_value)` | Positive Unix seconds to ISO UTC; missing or zero becomes null |

Never infer zero from missing data. If rate, pending count, or
backpressure is unavailable, leave `liveStrip` null. If only last success is
unavailable, use null for that field; the page labels it unavailable.

Paste measured values and UTC dates into
[`octopus-stats.json`](../src/data/octopus-stats.json). Keep numbers numeric,
use null for unmeasured peaks and their dates, and leave `asOf` null before the
first capture. Build, run the browser tests, and commit the snapshot.

Screen-reader, participant, and field evaluation remain separate from automated
tests. See [WCAG 2.2](https://www.w3.org/TR/WCAG22/) for the evaluation criteria.
