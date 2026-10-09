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
- [ ] Verify the production runtime feed returns fresh measurements and errors
      cannot leave old values labelled live.
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
- [ ] Verify the no-JS page shows unavailable readings and the JavaScript explanation.
- [ ] Verify `/metrics` and `/actuator/prometheus` are not publicly routed.
- [ ] Check social preview compatibility on the sharing platforms in use.
- [ ] Recheck analytics consent, rejection, and withdrawal on the production build.
- [ ] Measure field performance with the existing consent requirements.

The Git-connected Pages configuration is recorded in [README](../README.md)
and [wrangler.jsonc](../wrangler.jsonc). This frontend does not provision
hosting or change Kubernetes resources.

## Runtime metrics release checks

The [Pages Function](../functions/api/octopus-stats.ts) serves
`/api/octopus-stats` and forwards only validated public fields from the
coordinator. Production hosts are enabled in code; preview hosts return 503.
There is no build-time metrics configuration or saved measurement fallback.

- Verify two real responses at least 30 seconds apart have advancing `asOf`
  values. Counts can legitimately remain unchanged.
- Check `peaksComputedAt` advances after the 300-second cache period.
- Verify the public gateway targets Service port 8080, which forwards to
  container port 8081. NetworkPolicy still allows Traefik to container port 8081.
- Confirm `OCTOPUS_PUBLIC_STATS_ENABLED` and the allowed origins in the rendered
  deployment. Internal metrics endpoints remain private.
- The production allowlist includes the exact published Figma reference origin,
  `https://palm-beauty-99316208.figma.site`, so its direct public-feed request works
  after promotion. Unpublished Make preview origins are not allowlisted.
- Compare displayed readings to the coordinator's collected observations.
  Zero is valid only after successful collection. A fresh HTTP timestamp alone
  does not prove the underlying process gauges were sampled.
- After a restart, the live strip stays unavailable during the five-minute rate
  window. It also becomes unavailable if required collection is over 60 seconds old.
- Test a failed request, invalid JSON, missing fields, and stale source timestamps.
  The page must remove the old readings and stop saying live.
- Verify no-JavaScript output contains no measurements, and preview builds do not
  fetch production.
- Publish through reviewed Git changes and immutable coordinator image promotion,
  then repeat these checks against the deployed revision.

The source of historical peaks is `octopus_core.ingestion_evidence.first_seen_at`
across all paths and dispositions. The processing rate sums successful scheduled
ledger processing counts across a full five-minute window. The last successful
check may have processed no records; it is not evidence of fresh traffic.

Screen-reader and participant evaluation remain separate from automated tests.
See [WCAG 2.2](https://www.w3.org/TR/WCAG22/) for evaluation criteria.
