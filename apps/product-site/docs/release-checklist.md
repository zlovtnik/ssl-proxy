# Evaluation and release checklist

The implemented site is a local review artifact. This checklist records work
that needs human participants, assistive technology, a public hostname, or a
reviewed infrastructure change. No conformance or field-performance claim is made.

Automated coverage does not replace the manual items below. Current results and
the reason each check passes are in
[validation results](validation-results.md); tokens and pattern rules are in
[the design system](design-system.md).

## Automated and local evaluation

- [x] Run build/type checks and Playwright on all five routes in Chromium,
      Firefox, and WebKit: 84 checks passed on October 5, 2026.
- [x] Complete the configured Firefox suite. Ran on this host with
      `CFFIXED_USER_HOME` pointing at a fresh directory, because macOS 27
      denies this terminal access to the shared Firefox app-data directory;
      28 of 28 checks passed.
- [x] Run axe against dark/light pages with details open and every demo state.
- [x] Inspect rendered pages at 320, 375, 768, and 1440 CSS pixels. Automated
      reflow checks cover these widths for overflow, and full-page screenshots at
      320, 768, 1440 desktop and 375 mobile were reviewed in both themes.
- [ ] Inspect 200% text size and true 400% browser zoom; a 320px viewport is
      a reflow proxy, not evidence for browser zoom itself.
- [x] Inspect text-spacing overrides, forced colors, and reduced movement.
- [x] Verify core content/contact and text demo alternatives without JavaScript.
- [x] Check every rendered contrast pairing and keyboard focus/target geometry.
      Automated checks now measure rendered text, control boundaries, and focus
      rings on every tabbable control in both themes; forced-colors rendering and
      focus appearance still need a person.
- [x] Evaluate light and dark screenshots for clipping and legibility.
- [x] Measure cold-cache mobile/desktop lab LCP and CLS, and user-triggered
      interaction latency. Targets: LCP <= 2.5 seconds, INP <= 200 milliseconds,
      CLS <= 0.1. A lab interaction proxy is not post-launch field INP.

## Manual scoped evaluation

- [ ] Keyboard walkthrough: all routes, expanded/collapsed details, every query
      and migration step, display settings, email copy success/failure.
      Automated coverage now confirms tab order reaches every control and each
      ring is visible; the operator walkthrough is still outstanding.
- [ ] VoiceOver/Safari: headings, landmarks, reading order, diagram descriptions,
      live updates, details, selections, and email actions.
- [ ] NVDA/Firefox: repeat the complete screen-reader walkthrough.
- [ ] Usability sessions with disabled participants, including low vision,
      motor access, and cognitive/reading needs; record consented findings and fixes.
- [ ] Specialist review of reading level, abbreviations, visual presentation,
      unusual words, and pronunciation where meaning would otherwise be ambiguous.
- [ ] Complete and independently review every applicable criterion in the
      [accessibility matrix](accessibility-matrix.md), justifying non-applicability.
- [ ] Review the two product stories and audience propositions against the
      [messaging framework](messaging.md) and confirm no unsupported numeric
      claim appears.
- [ ] Update the public statement only to the level established by evidence.

## Reviewed delivery and field evaluation

- [x] Select the public hostname; set `PUBLIC_SITE_URL` and verify canonical,
      sitemap, social preview, robots, and page metadata in the resulting build.
      Verified on `https://rclabs.uk` on October 5, 2026: canonical URLs on all
      five routes, `www` canonicalising to the apex, `og:`/`twitter:` tags,
      five-URL sitemap, allowing `robots.txt`, and no `noindex`.
- [x] Publish the reviewed source and confirm the served revision matches it.
      Preview `894a0139-6b6b-4695-887f-0e488cece27e` was inspected before
      production deployment `f5ca6be9-6681-4228-b296-8417402392b1`, both from
      source `4a9b38e`; the marker publication
      `a016abbb-cdf6-4be6-89f2-1e6fc5307ad8` superseded it, and the served
      routes matched the published build at each step. The homepage update
      shipped as production deployment
      `28901202-7e1e-4e99-b370-541aa9f26987` from source `2ea9f34` under
      explicit approval as a direct upload without preview inspection; the
      five routes, canonical URL, five-URL sitemap, allowing `robots.txt`,
      homepage structured data, and unobfuscated email contact were verified
      on `https://rclabs.uk` afterwards.
- [ ] Recheck email contact without JavaScript on the live origin. One response
      served seconds after the marker-less publication was Cloudflare
      email-obfuscated; later fetches were clean, the markers are now published
      and consumed by Cloudflare, and the zone-level Email Obfuscation setting
      lives outside this repository.
- [ ] Confirm social preview compatibility on the selected sharing platforms.
- [ ] Add reviewed desired state under repository [cyber-stack](../../../cyber-stack),
      following its [instructions](../../../AGENTS.md), for the selected hosting
      path. The selected path is Cloudflare Pages, which cyber-stack does not
      currently describe.
- [ ] Keep first-party production images pinned by digest and promotion reviewed.
- [ ] Publish only through the reviewed Git/Argo CD path. The October 5, 2026
      publications were approved direct uploads, recorded as an exception in
      the [README](../README.md); moving Pages publication onto the reviewed
      path is outstanding.
- [ ] Measure post-launch field LCP, INP, and CLS with a consent/privacy-reviewed
      measurement approach; no third-party tracking is included in this release.

Evaluation references: [W3C evaluation guidance](https://www.w3.org/WAI/test-evaluate/tools/selecting/),
[Core Web Vitals](https://web.dev/articles/vitals), and
[WCAG 2.2](https://www.w3.org/TR/WCAG22/).
