# Local validation results

Local evaluation on October 5, 2026, with the reading-controls revision of
October 6, 2026. See the
[criterion matrix](accessibility-matrix.md) and
[release checklist](release-checklist.md). No AAA conformance claim is made.

## Completed checks

### Reading controls docked to the page bottom

- The reading and display controls moved out of the band above `main` into a
  compact card docked to the bottom right of the viewport: one 44px row when
  closed, opening upward into a two-column panel. `body` padding and root
  `scroll-padding-bottom` reserve 96px above the footer. Escape or a press
  outside closes the card, and Escape returns focus to its toggle.
- `npm run build`: five static pages, zero errors, warnings, or hints.
- `npm test`: 30 Chromium checks passed on October 6, 2026, including new dock
  checks for viewport containment when open, footer clearance when collapsed at
  standard and enlarged text, and Escape with focus return. The rendered-text
  and control walk opens the dock after the in-page interactions, because the
  open card covers the page content underneath it.
- `npm run review`: no browser script errors on any route; worst samples 592ms
  largest contentful paint, 0.011 cumulative layout shift, and 176ms observed
  event duration (opening the dock on the homepage, desktop profile).
- `/accessibility/` now points readers to the controls at the bottom of the
  page. WebKit and Firefox were not rerun in this revision.

### Homepage technical sections

- `npm run build`: five static pages, zero errors, warnings, or hints, with the
  four new homepage sections rendered from `homeSections`.
- `npm run test:all-browsers`: 87 checks passed, 29 each in Chromium, Firefox,
  and WebKit. `npm test` alone passes the same 29 in Chromium, including a new
  homepage check that
  asserts the modelled title, description, single H1, one heading per section,
  both product capability headings, the four call-to-action destinations, the
  benchmark status statement, and the absence of structured data on the other
  four routes.
- Identity markup is limited to `Organization` and `WebSite`, derived from
  `Astro.site`: a production build names `https://rclabs.uk/` and the default
  build keeps localhost. No logo, `sameAs`, `SoftwareApplication`, FAQ, or HowTo
  markup is published, because none of it is verified here.
- The rendered-text walk, axe, target-size, and tab-traversal checks cover the
  new sections with every reference disclosure open, in both themes. The
  homepage stays inside the 60-press tab-traversal budget.
- Reflow defect found and fixed in that run: at 320px with 200% root text, WCAG
  text-spacing overrides, and the reader's enlarged size, the fifth FAQ question
  pushed the page one pixel past the viewport because the rotated disclosure
  marker painted outside its row. Disclosure summaries now reserve 1rem on the
  right.
- Reflow defect found and fixed in a follow-up pass: `overflow-wrap: anywhere`
  on table cells let the auto table layout shrink columns below word width, so
  labels broke mid-word at 375px (`Stag e`, `Valid ation`, `Executio n`). Tables
  now wrap whole words inside `.landing-table-wrap`, a caption-named and
  Tab-reachable scroll region. Measured at 1440, 768, 375, and 320 CSS pixels:
  no cell needs a mid-word break, only hyphenated compounds break at their
  hyphen, the document never scrolls horizontally, and the widest table scrolls
  110px inside its own region at 320px.
- `PUBLIC_SITE_URL=https://rclabs.uk npm run build` confirmed canonical,
  `og:url`, sitemap, and JSON-LD URLs on the public origin, with no `noindex`.
  The default local build keeps localhost metadata and `noindex`.
- `npm run review`: no browser script errors on any route; worst sample 656ms
  largest contentful paint, 0.009 cumulative layout shift, and 64ms observed
  event duration against the local targets below.

### Content model, composition, and rendered evidence

- `npm run build`: five static pages, zero errors, warnings, or hints.
- `CFFIXED_USER_HOME=<fresh directory> npm run test:all-browsers`: 87 checks
  passed on October 5, 2026, 29 each in Chromium, Firefox, and WebKit. Earlier
  rounds recorded 84 checks (28 each), 26 Chromium checks, and 52
  Chromium/WebKit checks.
- Firefox needs `CFFIXED_USER_HOME` on this host: macOS 27 denies terminal-launched
  processes access to `~/Library/Application Support/Firefox`, so Playwright's
  bundled Firefox 155.0 exits at launch with "Could not find profile folder"
  before any profile is written. The variable redirects that app-data lookup and
  leaves the suite unchanged. Tracked upstream as microsoft/playwright#42768.
- One stylesheet owns colours, header geometry, typography, spacing, controls,
  and display-settings placement. Automated checks compare tokens, header
  geometry, reading-bar position, heading type, and control styling across all
  five routes in dark and light themes, so a route that drifts fails the suite.
- Headlines, summaries, audience propositions, workflow steps, both caveats,
  contact labels, email subjects, and the product page titles now ship from
  `src/data/products.ts`. Routes render that model instead of restating it, and a
  check fails if a caveat appears only once on its page or only in one of the two
  demonstrations.
- Both product pages keep a split hero with the demonstration in the proof
  column, exactly once per route, under the retained `#demo` anchor. The homepage
  playground keeps product switching, filtering, stable panel sizing, and
  no-JavaScript links to the product walkthroughs.
- Verified both themes at 320, 375, 768, 1024, and 1440px with no page-level
  horizontal scrolling, including enlarged text and WCAG text-spacing overrides.
  Full-page screenshots at 320, 768, and 1440 desktop and 375 mobile were
  reviewed in both themes for composition, clipping, and legibility.
- Composition defects found and fixed in that review: the contact heading and its
  button repeated the same words, the product name appeared twice in the hero,
  the four migration controls wrapped 3+1, and the header wrapped to two rows at
  768px.

### Contrast, focus, and target evidence

- Token pairs measured above 7:1 for core text and accents, and above 3:1 for
  control boundaries, on both page and panel backgrounds in both themes.
- A rendered walk now composites ancestor backgrounds, including alpha and colour
  mixes, and measures every text node and control boundary on all five routes in
  both themes against 7:1 normal text, 4.5:1 large text, and 3:1 non-text. It
  found secondary text at 6.88:1 on a selected playground row in the light theme;
  the accent tint was reduced from 10% to 6% and the state is still carried by the
  rule and `aria-pressed`.
- Every tabbable control on every route is focused and checked for a visible
  outline of at least 2px at 3:1 against the surface behind it, in both themes.
  Real key presses additionally confirm document-order traversal with no skipped
  control.
- axe passes on all five routes in both themes with every disclosure open and
  every demo state active.
- Verified hero CTA destinations, product-specific email subjects, the visible
  address with copy fallback, canonical and social metadata, sitemap, internal
  links, and no external network requests.
- `python3 scripts/check-docs.py`: documentation inventory, cross-references,
  and repository delivery policy passed.
- Chromium, Firefox, and WebKit run the same 29 checks, so the run above is the
  current cross-engine evidence. Screen readers, disabled-participant
  sessions, true browser zoom, forced-colors rendering, and complete manual
  criterion evaluation remain pending.

### Publication verification

- `PUBLIC_SITE_URL=https://rclabs.uk npm run build` produced the public output;
  the default local build keeps localhost metadata and `noindex`.
- Before this run the live origin still served source `1c542c4`, five commits
  behind the reviewed source at `4a9b38e`, so the pre-redesign headlines, the
  `live sample` wording, and the older email subjects were public.
- The reviewed output was published to the `codex-product-site-preview` branch
  as preview `894a0139-6b6b-4695-887f-0e488cece27e`, inspected there, and then
  published to `main` as production deployment
  `f5ca6be9-6681-4228-b296-8417402392b1` from source `4a9b38e`. The `email_off`
  markers added to the contact, demo, and accessibility pages followed as
  preview `f6d6d81c-7f15-47d4-97ed-ed234e8f6777` and production deployment
  `a016abbb-cdf6-4be6-89f2-1e6fc5307ad8`. The homepage structured data and
  sections then shipped as production deployment
  `28901202-7e1e-4e99-b370-541aa9f26987` from source `2ea9f34`, under explicit
  approval as a direct upload without preview inspection; it is the current
  deployment, and the prior one remains available for rollback.
- All five routes, `sitemap.xml`, `robots.txt`, `social-preview.png`,
  `favicon.svg`, and the hashed `_astro` assets return 200 at
  `https://rclabs.uk`. Each route's served HTML is byte-identical to the current
  published build once the `email_off` markers that Cloudflare consumes and the
  two elements it injects at the edge (a hidden `/cdn-cgi/content` anchor and
  the challenge-platform script) are removed.
- Live metadata is correct for the served origin: canonical URLs on all five
  routes, `www` canonicalising to the apex, `og:` and `twitter:` tags pointing
  at `social-preview.png` (200, `image/png`), a five-URL sitemap, `robots.txt`
  allowing crawling with a sitemap link, and no `noindex` on any public route.
- One response captured seconds after the marker-less publication served
  Cloudflare email-obfuscated HTML, where the address reads
  `[email protected]` and the `mailto:` links do not resolve without
  JavaScript. Thirteen later fetches, including ten probes of the same URL,
  served unobfuscated HTML with both `mailto:` links and their product subjects
  intact; the zone-level setting was not readable with the available API scope,
  so that flip is unexplained. After the markers were published the served HTML
  is unobfuscated with the markers consumed, which is the intended behaviour.
  No-JS email contact on the live origin still needs a manual recheck.

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

`npm run review` captured one cold-cache run per route/profile in Chromium after
the font preload was added. Desktop viewport: 1440 by 1000. Mobile viewport: 375
by 812 with 4x CPU slowdown, 150ms network latency, and 1.6Mbps download.

| Metric                             | Worst observed sample | Target                      |
| ---------------------------------- | --------------------- | --------------------------- |
| Largest Contentful Paint           | 656ms                 | <= 2500ms                   |
| Cumulative Layout Shift            | 0.009 (rounded up)    | <= 0.1                      |
| Observed event duration, lab proxy | 64ms                  | <= 200ms interaction target |

The same run measured 0.157 to 0.189 cumulative layout shift on `/` and
`/schema-migrator/` before the fix: the two Latin variable faces arrived after
first paint, and the swap reflowed the hero and header. `Layout.astro` now
preloads them through build-time asset URLs. The current run measures 0.000
cumulative layout shift on nine of the ten route/profile samples, with
`/schema-migrator/` mobile at 0.008. No browser script errors were recorded. Event duration
is not field Interaction to Next Paint (INP). These single local samples are not
production field evidence or a performance guarantee. JSON and PNG outputs are in
the ignored `review-artifacts/` directory; Playwright reports/traces, dependencies,
and static build outputs are also generated locally and ignored.

## Remaining evaluation and delivery

- WebKit is automated but cannot enumerate a full traversal: Tab can move focus
  into browser chrome part-way through, so focus-ring coverage there is per
  control rather than per traversal.
- VoiceOver/Safari and NVDA/Firefox walkthroughs, disabled-participant usability
  sessions, true 400% browser zoom, forced-colors rendering, reading-level review,
  and complete manual criterion evaluation remain pending. WebKit automation is not
  VoiceOver/Safari.
- No-JS email contact has not been rechecked on the live origin by a person:
  one post-publication response was Cloudflare email-obfuscated, later fetches
  were clean, and the zone-level Email Obfuscation setting is outside this
  repository and was not readable with the available API scope.
- The `email_off` markers in `Contact.astro`, `demo/index.astro`, and
  `accessibility/index.astro` are committed (`df030a08`) and included in the
  current production deployment, so the served build and the reviewed source
  agree.
- Social preview rendering on the selected sharing platforms is unconfirmed; the
  image, `og:` tags, and `twitter:card` were checked only by inspecting the
  served HTML and asset responses.
- Publication on October 5, 2026 used approved direct uploads to Cloudflare
  Pages, not the reviewed Git/Argo CD path, and Kubernetes desired state under
  [cyber-stack](../../../cyber-stack) does not cover this site's hosting.
- No production APIs, databases, authentication, or migration execution changed.
