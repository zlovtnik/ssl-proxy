# Local validation results

This record covers the three-product site and technical guides: the shared
RCLabs dark/green visual system, product catalogue, natural-height demos and
disclosures, and search routing. No accessibility conformance claim is made.

## Automated checks

Last run: 2026-10-08. Re-run these after every theme or layout change and replace
the dated entries with new evidence:

- `PUBLIC_SITE_URL=https://rclabs.uk npm run build`: passed; 16 HTML pages
  (15 indexable pages and an excluded 404), zero errors, warnings, or hints.
- `npm test -- --config=/tmp/rclabs-seo-playwright.config.ts`: passed; 50
  Chromium tests, with two analytics tests skipped because no measurement ID
  is configured. Temporary test settings reused the existing site preview on
  port 4323 instead of stopping it. The repository test configuration is unchanged.
- A Pages preview build with `CF_PAGES=1`, `CF_PAGES_BRANCH=seo-preview`, and an
  inherited production `PUBLIC_SITE_URL` passed. Homepage and guide artifacts
  retained `noindex`; robots excluded crawling. Final output was rebuilt with
  the production origin afterward.
- PNG and ICO response bytes, 15 unique sitemap URLs, production canonicals,
  and the excluded 404 artifact passed dedicated checks.
- Local Pages routing checks confirmed retired paths return 404, both old
  contact forms redirect with 301 to `/demo/`, and favicons return image content.
  The installed emulator used its supported compatibility date, `2026-06-24`,
  for these local static-routing checks; production configuration was unchanged.
- Desktop and mobile guide screenshots were inspected. Prior `npm run review`
  captures cover the original eight routes, not the added guides. These are
  local observations, not field performance data.
- `python3 scripts/check-docs.py`: passed Markdown references and repository
  documentation checks.
- Targeted formatting checks passed for the new SEO tests, guide components,
  guide routes/styles, 404, favicon generator, shared layout and configuration.
  A repository-wide formatting cleanup was not performed.

The browser suite covers the shared dark theme (including saved light/system
values and system colour preferences being ignored), product switching, all
three synthetic samples, focus, contrast, responsive reflow, and link
destinations across all 15 public content routes. It confirms the display-settings
dock is absent while previously
saved display choices still apply.

- [Layout regressions](../tests/layout.spec.ts) expand each disclosure and card
  individually and together at 320, 375, 768, 1024, and 1440px, with enlarged
  text and spacing overrides. They verify containment, no page overflow, and
  that following sections remain below expanded content.
- `python3 scripts/check-docs.py` validates Markdown cross-references from the
  repository root after documentation changes.

## Visual inspection

The shared dark theme should be checked on the homepage, catalogue, and each
product sample. The expected layout is a short intro beside a workflow outline,
followed by a full-width demo in normal document flow. The homepage playground
shows one selected product at a time; inactive panels are hidden and inert.

## Manual work still required

- Test VoiceOver/Safari and NVDA/Firefox.
- Inspect true 400% browser zoom and forced-colours mode.
- Run usability sessions with disabled participants.
- Build with `PUBLIC_SITE_URL=https://rclabs.uk` and inspect the deployment
  preview before publication.

The detailed evaluation scope remains in the
[accessibility matrix](accessibility-matrix.md) and
[release checklist](release-checklist.md).
