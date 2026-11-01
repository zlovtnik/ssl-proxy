# Local validation results

This record covers the four-project site and technical guides: the shared
RCLabs dark/green visual system, product catalogue, natural-height demos and
disclosures, and search routing. No accessibility conformance claim is made.

## 2026-10-31: direct project samples and editorial rules

- Removed the combined homepage playground and its exclusive styles. Project
  links now navigate directly to dedicated samples without click interception.
  Existing project demos and Octopus runtime metrics remain on their routes.
- Public pages, metadata, structured data, resume and privacy copy now use
  Rafael Cardoso. Site-wide rules prohibit semicolons in public prose while
  preserving code and SQL syntax. Browser coverage checks all 19 pages.
- `npm run build` passed with zero Astro/TypeScript diagnostics and 19 pages.
- `npm test`: 89 passed, two production-only analytics tests skipped because
  no measurement ID is configured. Both JavaScript and no-JavaScript sample
  navigation pass, alongside the existing project interaction checks.
- `npm run review` completed 38 desktop/mobile route runs with zero page errors.
  Homepage desktop/mobile screenshots and the mobile Search interaction were
  inspected. The visual verdict is 94/100 for the requested simplification.
  These local lab runs are not field performance or accessibility-conformance
  evidence.
- Touched-file formatting, `git diff --check`, and the repository documentation
  checker pass. The full formatting command reports six pre-existing warnings
  in untouched Contact, MigratorDemo, SearchDemo and the Search, Migrator and
  VPN route files. The same warnings reproduce from their HEAD versions.
- Generated build, test and screenshot outputs were refreshed locally. Visual
  verdict state is stored under ignored `.omx/`. No publication was performed.
  Assistive-technology and participant evaluation remain pending.

## 2026-10-31: site-wide editorial cleanup

- Baseline and final `npm run build` passed. The final build reports zero
  Astro/TypeScript errors, warnings or hints and produces all 19 pages.
- Baseline and final `npm test`: 88 passed; two production analytics tests
  skipped because no measurement ID is configured. Existing metrics, samples,
  keyboard, contrast, forced-colours, reflow, print and no-JavaScript coverage
  remain intact. The portfolio test now follows every guide link without JS.
- The first post-edit run found a duplicate guide landmark name and three
  assertions tied to old copy. The landmark names are now distinct; assertions
  retain the Search production-scope and contact limitations in the final copy.
- `npm run review` completed 38 desktop/mobile runs across all 19 routes,
  including the guide index, six guides and 404 page, with zero page errors.
  Desktop/mobile route overviews and the full homepage, catalogue and Octopus
  composition were inspected. The final visual verdict is 92/100.
- The initial screenshot attempt used the changing development server and
  timed out waiting for hydration. The complete successful run used the stable
  built-site preview. The lab measurements are not field performance evidence.
- Guide section bodies, SQL examples, caveats and source links were compared
  before and after removing the unused homepage model and remained identical.
- Touched-file Prettier checks, `git diff --check`, and the repository
  `python3 scripts/check-docs.py` pass. There is no separate lint script in this
  app; Astro diagnostics provide static/type checking.
- Generated build, browser-report, screenshot and visual-verdict artifacts were
  regenerated locally. No dependencies, runtime metrics code, resume facts,
  hosting or deployment configuration changed.
- VoiceOver/Safari, NVDA/Firefox and participant evaluation remain pending.
  Backend integration suites were not run for this frontend-only cleanup.

## 2026-10-27: hiring portfolio and current resume

- `npm run build`: passed; Astro/TypeScript reported zero errors, warnings, or
  hints and built 19 pages, including the new static resume.
- Final full Chromium run: 88 passed and two analytics tests skipped because no
  measurement ID was configured. Coverage includes the corrected repository
  destinations for evidence links and a privacy check that distinguishes public
  tool names in the resume from internal dashboard URLs.
- Portfolio regressions cover no-JavaScript hierarchy and disclosures, Synchro
  attribution, separate employment/project emails, current resume facts and
  contact links, responsive reflow, and automated accessibility.
- The print regression passed with a visible production-style consent banner:
  print hides consent, navigation, and print controls while retaining content
  on a white background. Final desktop and print-media screenshots were inspected.
- `npm run review`: captured 11 routes at desktop/mobile sizes with no page
  errors. These local lab samples do not establish field performance or
  accessibility conformance. The final resume text also passed responsive tests.
- Targeted Prettier checks, `git diff --check`, and
  `python3 scripts/check-docs.py` passed.
- Backend services and database integration suites were not executed for this
  frontend change. Case-study links describe existing regression coverage and
  explicitly leave current backend pass status and complete crash testing open.
- Local checks regenerated ignored build, test, screenshot, and visual-verdict
  state artifacts. No hosting, deployment, or runtime infrastructure was changed.

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
values and system colour preferences being ignored), all
three synthetic samples, focus, contrast, responsive reflow, and link
destinations across all 19 public pages. It confirms the display-settings
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
followed by a full-width demo in normal document flow. The homepage links
directly to dedicated project samples and does not embed a combined playground.

## Manual work still required

- Test VoiceOver/Safari and NVDA/Firefox.
- Inspect true 400% browser zoom and forced-colours mode.
- Run usability sessions with disabled participants.
- Build with `PUBLIC_SITE_URL=https://rclabs.uk` and inspect the deployment
  preview before publication.

The detailed evaluation scope remains in the
[accessibility matrix](accessibility-matrix.md) and
[release checklist](release-checklist.md).
