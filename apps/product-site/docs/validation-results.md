# Local validation results

This record covers the four-product site and technical guides: the shared
RCLabs dark/green visual system, product catalogue, natural-height demos and
disclosures, and search routing. No accessibility conformance claim is made.

## 2026-10-09: runtime metrics and Octopus copy

- `npm run build`: passed with no type errors, warnings, or hints; 17 pages built.
- Runtime response validation and Pages proxy tests: two passed. These execute
  without a browser and verify malformed, missing, stale, and private fields.
- Octopus backend: 27 focused tests passed. A separate PostgreSQL Testcontainers
  test passed, executing the real day/week queries across UTC boundaries.
- GitOps and manifest regression checks: 67 tests passed; `make gitops-check`
  rendered and validated the canonical Kustomize/Argo CD surfaces.
- `python3 scripts/check-docs.py`: passed after documentation changes.
- Full `npm test` and local visual review remain pending: the sandbox prevented
  the preview server from listening, and automatic approval review could not
  complete because of an account usage limit. Existing browser tests are not
  evidence for the revised local page until rerun.
- The updated Figma Make reference was visually inspected. Its failed-feed state
  displays unavailable values without the previous saved numbers. This does not
  substitute for local Astro/Solid browser verification.
- Wiretrap's public stats route returned 404; the direct service returned 500
  with PostgreSQL SQLSTATE 42883 on the week query. Processing-check timestamps
  advanced. A later readiness check reported PostgreSQL UP and processors DOWN,
  so production rollout also needs processor-health verification.

Build and test commands regenerated ignored local build outputs. No runtime
measurements are committed. These changes are not yet promoted to production.

## Prior automated checks

Prior run: 2026-10-08 (Octopus landing redesign). These results describe that
earlier revision and do not verify the 2026-10-09 changes:

- `npm run build`: passed; `astro check` clean and 17 pages built, including the
  dedicated `OctopusPage` composition at `/octopus/`.
- `npm test`: passed; 55 Chromium tests green (2 analytics tests skipped with no
  measurement ID). Coverage includes no-JS Octopus evidence, UX-island allowlist
  (`data-ux=pipeline|audience-toggle|count-up`), pipeline/toggle layout at
  320–1440 and 200% text, forced colours, reduced motion, contrast, and the three
  synthetic demos still intact. Solid hydration keys are stripped before the
  privacy raw-HTML scan so island ids cannot match internal-port patterns.
- `PUBLIC_SITE_URL=https://rclabs.uk npm run build` and the prior SEO/Pages
  evidence below remain from the previous run and should be re-checked before
  publication.
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
