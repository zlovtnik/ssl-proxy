# Local validation results

Local evaluation on October 5, 2026. See the
[criterion matrix](accessibility-matrix.md) and
[release checklist](release-checklist.md). No AAA conformance claim is made.

## Completed checks

### Latest reference layout correction

- The header remains visible while scrolling. Navigation links target landing
  sections, and product sample links switch the local playground in place.
- Desktop uses paired product cards; mobile uses a native navigation disclosure.
  Both preview panels share a grid area to keep their height stable; inactive
  controls are inert. Without JavaScript, sample links open the text walkthroughs.
- Added a regression check for header position, route preservation, preview
  height, and mobile navigation. Target-size checks evaluate visible controls.
- Build and 20 Chromium checks passed. Desktop and mobile were inspected visually.
  Build and test output directories were regenerated. WebKit, Firefox, screen
  readers, and the performance samples below were not reevaluated in this revision.

### Landing-page redesign follow-up

- `npm run build`: five static pages, zero errors, warnings, or hints.
- `npm test`: 19 Chromium checks passed, including the new landing playground.
- Verified observation filtering, empty results, initial pressed states, keyboard
  selection, and all four migration preview steps in both themes.
- Automated reflow checks cover 320, 375, 768, 1024, and 1440 CSS pixels in the
  migration preview. Existing all-route reading, contrast, and no-JavaScript
  checks passed. Desktop and mobile layouts were also inspected visually.
- Theme changes apply immediately to avoid intermediate low-contrast text.
  Decorative movement respects system and saved reduced-motion preferences.
- This follow-up has not rerun WebKit or Firefox. The performance samples below
  predate the redesign and do not measure the new landing page.

### Initial site evaluation

- `npm run build`: five static pages, zero errors, warnings, or hints.
- `npm run test:all-browsers -- --project=chromium --project=webkit`:
  36 checks passed across Chromium and WebKit.
- Axe checks passed on all five routes in both themes with details expanded,
  both Search samples, and all four migration steps.
- Verified keyboard-controlled sample switching, migration steps, and skip link;
  no-JavaScript story/contact/text alternatives; preference persistence/reset;
  reduced motion, forced colors, copy success/failure, and email subjects.
- Verified no horizontal overflow at 1440, 768, 375, and 320 CSS pixels,
  text-spacing overrides, and 200% root text resizing. This does not replace
  true browser zoom evaluation.
- Tested normal-text token pairs at >= 7:1 and control-boundary pairs at >= 3:1
  on both backgrounds/themes. Tested navigation, buttons, selects, and summary
  targets at >= 44 by 44 CSS pixels at each tested viewport.
- Verified canonical/social metadata, sitemap, local noindex/robots guard,
  internal page links, and no external network requests during route loading.
- `npm install` audit: zero known dependency vulnerabilities. Versions and
  transitive dependencies are recorded in the npm lockfile.
- `python3 scripts/check-docs.py`: documentation inventory, cross-references,
  and repository delivery policy passed. `git diff --check` passed.
- Captured all routes in both themes at desktop/mobile sizes, plus interaction
  states. Inspected the hub and product-page screenshots for layout and legibility.
  Fonts are self-hosted; their original licenses are included with the static assets.

## Local performance samples

`npm run review` captured one cold-cache run per route/profile in Chromium.
Desktop viewport: 1440 by 1000. Mobile viewport: 375 by 812 with 4x CPU slowdown,
150ms network latency, and 1.6Mbps download.

| Metric                             | Worst observed sample | Target                      |
| ---------------------------------- | --------------------- | --------------------------- |
| Largest Contentful Paint           | 516ms                 | <= 2500ms                   |
| Cumulative Layout Shift            | 0.00144 (rounded up)  | <= 0.1                      |
| Observed event duration, lab proxy | 48ms                  | <= 200ms interaction target |

No browser script errors were recorded. Event duration is not field Interaction
to Next Paint (INP). These single local samples are not production field evidence
or a performance guarantee. JSON and PNG outputs are in the ignored
`review-artifacts/` directory; Playwright reports/traces, dependencies, and static
build outputs are also generated locally and ignored.

## Remaining evaluation and delivery

- Firefox's current downloaded test build failed at launch with "Could not find
  profile folder". An older local build also failed to establish a usable browser
  session, reporting sandbox/framebuffer errors. Firefox checks remain unverified;
  rerun the configured Firefox project on a compatible host.
- VoiceOver/Safari and NVDA/Firefox walkthroughs, disabled-participant usability
  sessions, true 400% browser zoom, reading-level review, and complete manual
  criterion evaluation remain pending. WebKit automation is not VoiceOver/Safari.
- A public hostname and reviewed Git/Kustomize/Argo CD hosting change have not
  been selected or applied. The default local build disables indexing. Public
  origin configuration was checked using a test-only hostname without publication.
- No production APIs, databases, authentication, or migration execution changed.
