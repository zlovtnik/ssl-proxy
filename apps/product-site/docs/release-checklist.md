# Evaluation and release checklist

The implemented site is a local review artifact. This checklist records work
that needs human participants, assistive technology, a public hostname, or a
reviewed infrastructure change. No conformance or field-performance claim is made.

Automated coverage does not replace the manual items below. Current results and
the reason each check passes are in
[validation results](validation-results.md); tokens and pattern rules are in
[the design system](design-system.md).

## Automated and local evaluation

- [x] Run build/type checks and Playwright on all five routes in Chromium/WebKit.
- [ ] Complete the configured Firefox suite on a compatible host.
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

- [ ] Select the public hostname; set `PUBLIC_SITE_URL` and verify canonical,
      sitemap, social preview, robots, and page metadata in the resulting build.
- [ ] Confirm social preview compatibility on the selected sharing platforms.
- [ ] Add reviewed desired state under repository [cyber-stack](../../../cyber-stack),
      following its [instructions](../../../AGENTS.md), for the selected hosting path.
- [ ] Keep first-party production images pinned by digest and promotion reviewed.
- [ ] Publish only through the reviewed Git/Argo CD path.
- [ ] Measure post-launch field LCP, INP, and CLS with a consent/privacy-reviewed
      measurement approach; no third-party tracking is included in this release.

Evaluation references: [W3C evaluation guidance](https://www.w3.org/WAI/test-evaluate/tools/selecting/),
[Core Web Vitals](https://web.dev/articles/vitals), and
[WCAG 2.2](https://www.w3.org/TR/WCAG22/).
