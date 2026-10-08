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
- [ ] Review all three product stories and their caveats against repository evidence.
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
- [ ] Check social preview compatibility on the sharing platforms in use.
- [ ] Recheck analytics consent, rejection, and withdrawal on the production build.
- [ ] Measure field performance with the existing consent requirements.

The Git-connected Pages configuration is recorded in [README](../README.md)
and [wrangler.jsonc](../wrangler.jsonc). This frontend does not provision
hosting or change Kubernetes resources.

Screen-reader, participant, and field evaluation remain separate from automated
tests. See [WCAG 2.2](https://www.w3.org/TR/WCAG22/) for the evaluation criteria.
