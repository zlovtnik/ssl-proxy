# RCLabs Search Console, Search Appearance, and Growth Plan

## Requirements

Connect `rclabs.uk` to the user's chosen Google Search Console account and
make the public Atheros Search and Schema Migrator pages eligible for Google
Search. The user selected Search Console and indexing only. This plan does
not require visitor analytics, a Google tracking tag, or application OAuth.
The follow-up request expands this to missing search icons, outdated results,
and broader search positioning. Account setup, DNS writes, code changes, and
publication remain separate work. The code implementation and local validation
record below track completion without changing the user's Google account.

## Work ownership

- **User, manual Google tasks:** open the intended Search Console account,
  confirm domain access/ownership, submit the sitemap, inspect indexed/live URLs,
  request indexing after publication, and review queries and indexing reports.
- **Code changes:** favicon assets, missing-page handling, supported contact
  redirects, preview indexing protection, console exclusions, shared metadata,
  technical guide pages, internal links, sitemap, and regression coverage.
- **Publication:** follow the existing reviewed Git delivery path. No remote
  settings, commits, pushes, or deployments are part of this implementation run.

## Verified baseline

Read-only public HTTPS and DNS checks on October 8, 2026 found:

| Surface | Observed configuration | Intended treatment |
| --- | --- | --- |
| `https://rclabs.uk/` | HTTP 200; canonical points to the apex domain; no meta `noindex` or `X-Robots-Tag` | Public search result |
| `https://rclabs.uk/atheros-search/` | HTTP 200; self-canonical; no indexing exclusion | Public Search product result |
| `https://rclabs.uk/schema-migrator/` | HTTP 200; self-canonical; no indexing exclusion | Public Migrator product result |
| `https://rclabs.uk/robots.txt` | HTTP 200; allows crawling and declares the sitemap | Keep |
| `https://rclabs.uk/sitemap.xml` | HTTP 200; eight apex-domain URLs, including both product pages | Submit to Google |
| `https://www.rclabs.uk/` | HTTP 200; canonical points to the apex homepage; no redirect | Keep apex as the preferred hostname |
| `https://search.rclabs.uk/` | Public HTTP 200 application shell; no meta or header indexing exclusion | Recommend `noindex` |
| `https://migrator.rclabs.uk/` | Public HTTP 200 application shell; no meta or header indexing exclusion | Recommend `noindex` |
| Domain DNS | Cloudflare nameservers; an existing `google-site-verification` TXT record | Check account access before adding a record |

The existing TXT record does not reveal the owning Google account or prove
that verification is still valid in Search Console. The user has not checked
the target account yet. Indexing status and sitemap submission status are
also unknown until that account is inspected.

Repository evidence:

- [Publication configuration](../../../apps/product-site/README.md), lines
  67-89, describes the `rclabs` Cloudflare Pages project, production
  `PUBLIC_SITE_URL=https://rclabs.uk`, and reviewed Git publication.
- [Astro configuration](../../../apps/product-site/astro.config.mjs), lines
  5-24, sets the site origin and trailing slashes.
- [Shared page layout](../../../apps/product-site/src/layouts/Layout.astro),
  lines 21-23 and 66-73, emits canonical metadata and excludes localhost builds.
- [Robots route](../../../apps/product-site/src/pages/robots.txt.ts), lines
  3-6, allows public crawling; [sitemap route](../../../apps/product-site/src/pages/sitemap.xml.ts),
  lines 3-15, lists eight public routes.
- [Search HTML](../../../apps/integration-console/atheros-search-ui/index.html)
  and [Migrator HTML](../../../apps/schema-migrator/schema-migrator-ui/index.html)
  contain product/social metadata but no robots meta exclusion.

## Setup and implementation steps

1. Sign in to [Search Console](https://search.google.com/search-console/)
   using the intended Google account. Check the property selector for
   `rclabs.uk`, then Settings > Ownership verification and Users and permissions.
   If access already exists, record its permission level and verification
   method. Do not assume that a URL-prefix property covers all subdomains.
2. If access is absent, add a **Domain** property named `rclabs.uk`, without
   `https://` or a path. Either have an existing verified owner grant access,
   or verify independently using the exact DNS record issued to the intended
   account. For a TXT verification, add the issued value at the domain root
   in Cloudflare DNS and retain existing verification and mail records.
   Confirm the new value is publicly resolvable, then click Verify. Keep the
   verification record after success. No website tag is needed for this method.
3. In the domain property, submit `https://rclabs.uk/sitemap.xml`. Inspect the
   homepage and the two public product URLs with URL Inspection > Test live URL.
   Resolve any crawl/indexing restriction shown there, then request indexing.
   Use Performance page filters for each product URL. Separate URL-prefix
   properties for the two product paths are optional reporting conveniences.
4. In a reviewed follow-up change, add `<meta name="robots" content="noindex">`
   to both console HTML heads identified above. Inspect other publicly
   reachable console entry points and deployment response headers for the same
   policy. Keep application authentication and API authorization intact;
   `noindex` does not protect data. Do not add a robots disallow that prevents
   Google from seeing the exclusion. Keep consoles out of the public sitemap.
   Publish each UI through its documented reviewed Git path, then verify live
   responses. No interactive Kubernetes changes are required.

Google documents [Domain property coverage and DNS verification](https://support.google.com/webmasters/answer/34592?hl=en),
[ownership verification and token retention](https://support.google.com/webmasters/answer/9008080?hl=en),
[sitemap submission](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap),
[indexing requests](https://developers.google.com/search/docs/crawling-indexing/ask-google-to-recrawl),
and [crawlable noindex exclusions](https://developers.google.com/search/docs/crawling-indexing/block-indexing).

## Acceptance criteria and verification

- The intended Google account can open the `rclabs.uk` Domain property;
  owner/full-user permissions support sitemap submission and indexing requests.
- Search Console shows the submitted sitemap as successfully read, with both
  public product URLs present. The current live sitemap contains eight URLs.
- All three inspected public pages pass the live indexing eligibility check;
  record Google-selected canonical URLs when indexed inspection data is available.
- Both console shells expose `noindex` in fetched HTML or an effective response
  header; protected data still requires existing authentication.
- Local and Pages preview builds remain excluded from indexing. Verify the
  actual preview output: the source guard relies on the configured hostname,
  so inherited production environment values must not be assumed safe.
- After future source edits, run the owning UI's build and applicable checks.
  For public-site edits, run `npm run build` and `npm test` per its
  [local instructions](../../../apps/product-site/AGENTS.md). Existing metadata
  coverage is in [site tests](../../../apps/product-site/tests/site.spec.ts),
  lines 508-551. Run `python3 scripts/check-docs.py` after documentation edits.
- Record later Page Indexing and Performance results. A successfully submitted
  request is the setup completion criterion; indexing, ranking, and Google
  sitelinks remain Google's decisions and are not guaranteed by verification.

## Risks and mitigations

- **Existing ownership may belong to another account:** check the target account
  first; add its issued token or request access without removing other tokens.
- **Console shells can appear in search:** publish explicit `noindex` while
  retaining authentication, and inspect resulting exclusions in Search Console.
- **Production origin inherited by a preview:** inspect rendered preview
  metadata and headers before accepting a deployment as safely excluded.
- **Duplicate hostname responses:** current canonical tags prefer the apex;
  an optional permanent `www` redirect is a separate hosting improvement.
- **Discovery is mistaken for guaranteed listing:** use Search Console reports
  to diagnose actual indexing outcomes; do not promise a ranking or timeline.

## Planning validation

The live public routes, sitemap, robots rules, console HTML, and DNS were read
successfully. No Search Console account was inspected and no remote settings
were changed. The original planning pass added only this plan. The implementation
evidence below records the subsequently authorized code changes.

## Expanded search appearance audit

The user supplied a Google result titled "RCLabs: Site-aware Wi-Fi Security &
PostgreSQL Migration ...", describing the two-product site. The live homepage
now uses "Wireless Evidence, SQL Review & WireGuard VPN / Proxy | RCLabs".
Older crawl information or Google's title rewriting could explain the mismatch;
the exact cause requires URL Inspection's indexed HTML and last-crawl evidence.
The "Missing: software" message is a query-matching annotation, not proof of
an indexing configuration failure. One result for a query does not establish
that only one URL is indexed.

Additional public checks on October 8, 2026 found:

| Finding | Evidence | Priority |
| --- | --- | --- |
| Only an SVG favicon is declared | Live homepage links `/favicon.svg`; it returns SVG with HTTP 200. [Layout source](../../../apps/product-site/src/layouts/Layout.astro), line 68; [icon source](../../../apps/product-site/public/favicon.svg), line 1 | P0 |
| There is no usable conventional ICO response | `/favicon.ico` returns HTTP 200 and homepage HTML, not an icon | P0 |
| Retired URLs return the homepage as successful pages | `/service-areas`, `/services`, `/about`, `/blog`, `/contact`, `/faq`, and `/terms` return HTTP 200 with the homepage title and apex canonical | P0 |
| Historical service-area content remains discoverable through a search provider | A search result for `/service-areas` still describes the former London agency site; its live URL now serves the homepage. This is not a complete Google index inventory | P0 |
| Useful technical material has no separate landing URLs | [Content model](../../../apps/product-site/src/data/products.ts), lines 53-454, holds a migration guide, technical definitions, comparison, and benchmark protocol; [homepage rendering](../../../apps/product-site/src/pages/index.astro), lines 111 onward, renders these as sections | P1 |
| Search Console evidence is unavailable | Ownership, actual indexed URL count, selected canonicals, queries, impressions, and clicks have not been inspected | Required baseline |

Cloudflare documents that a Pages site without a top-level `404.html` uses
[single-page application fallback](https://developers.cloudflare.com/pages/configuration/serving-pages/).
There is no custom 404 page in the current source. This is a likely explanation
for the observed fallback; verify the built artifact and Pages routing before
finalizing the repair. Canonical tags alone do not make these responses actual
redirects or errors.

## P0: Correct search presentation and retired routes

1. Derive a 96x96 PNG and conventional ICO from the existing RCLabs icon;
   preserve the current design. Place the assets in the site's existing public
   assets directory and declare a stable PNG icon URL in the shared layout.
   Keep the SVG available for browser use. Validate actual image dimensions,
   MIME types, successful responses, and accessibility to Googlebot-Image.
   Google's [current favicon format guidance](https://developers.google.com/search/docs/appearance/favicon-in-search)
   lists PNG and ICO among its supported formats and recommends a square icon
   larger than 48x48. This is a concrete eligibility improvement, not proof of
   the sole cause of the missing icon. Request a homepage recrawl after release.
2. Add an Astro 404 route that emits a top-level `404.html` in the build output.
   Verify unknown URLs return an actual HTTP 404 after Pages publication.
   Inventory retired URLs using Search Console and the former site navigation.
   Use permanent redirects only where a genuinely equivalent current page
   exists; for example, evaluate former contact content against the current
   contact section. Do not blanket-redirect unrelated old service/location
   pages to the homepage. Keep unmatched retired URLs as 404 or deliberately
   configured 410 responses. Google documents [redirect behavior](https://developers.google.com/search/docs/crawling-indexing/301-redirects)
   and [HTTP status effects](https://developers.google.com/crawling/docs/troubleshooting/http-status-codes).
3. Finalize one homepage title, description, main heading, and WebSite identity
   that accurately describe the three-product software business. Use the word
   "software" naturally when it clarifies the offering; do not repeat variants
   to satisfy one query annotation. Preserve the existing WebSite/Organization
   identity graph in [homepage source](../../../apps/product-site/src/pages/index.astro),
   lines 19-39. Add an Organization logo only using a real crawlable brand asset;
   it does not replace the favicon. Inspect existing indexed HTML before
   attributing stale display entirely to metadata.
4. Complete the console exclusions and account/sitemap steps above. Inspect
   retired URLs after Google recrawls them. Use Search Console's removal tools
   only if urgent hiding is needed; permanent behavior must be supplied by the
   site. Do not remove the valid homepage because its displayed title is old.

## P1: Build distinct search entry points

Target specific technical jobs with useful standalone pages. The following
queries are hypotheses grounded in product capabilities, not measured search
volume or validated competitive opportunities. Use Search Console and live
result analysis to refine their language and order before drafting each page.
Existing product routes remain the commercial destinations.

| Proposed page, not yet created | Search intent to evaluate | Required original material |
| --- | --- | --- |
| `/guides/postgresql-migration-dry-run/` | PostgreSQL migration dry run; validate SQL before execution | Expand the existing tested two-file guide, with complete inputs, captured output, prerequisites, and limits |
| `/guides/postgresql-schema-drift/` | PostgreSQL schema drift detection | Worked expected-versus-observed catalog example; distinguish checking from remediation |
| `/guides/migration-checksum-mismatch/` | Migration checksum mismatch; changed migration files | Reproducible changed-file example; explain file integrity versus live schema drift |
| `/guides/rogue-access-point-investigation/` | Investigate suspected rogue access points | Labelled synthetic records, channel/time/site context, analyst steps, and false-positive discussion |
| `/guides/wifi-deauthentication-investigation/` | Investigate Wi-Fi deauthentication events | Reproducible observation example, evidence interpretation, monitor-mode prerequisites, and limitations |
| `/guides/hybrid-search-network-observations/` | Hybrid search for network logs and wireless observations | Same-data term/vector/hybrid walkthrough and explainable result example; no unmeasured benchmark claims |

Ship the first three pages as one reviewed content batch, then the next three
after checking their evidence and early search data. Each page needs its own
title, H1, description, canonical URL, complete static body, relevant diagram
or sample, sources, and a link to its product and a relevant sibling guide.
Add a guides index and navigation links so no page depends on sitemap discovery
alone. Condense the corresponding homepage section into a useful summary that
links to the detailed guide; preserve existing anchor destinations where used.
Do not publish identical copies under multiple keyword URLs.

Use the [content evidence map](../../../apps/product-site/docs/content-evidence.md)
and [messaging rules](../../../apps/product-site/docs/messaging.md) for every
capability claim. Keep copy in the existing content model, or a focused guide
content model when the added material warrants it. Extend the existing shared
layout and styles rather than redesigning the site as part of SEO work.
Add visible breadcrumbs and matching BreadcrumbList data to the guide and
product hierarchy where applicable. Markup must describe visible content.
Do not add fabricated reviews, customer outcomes, prices, or benchmark numbers.

Google documents [descriptive internal linking](https://developers.google.com/search/docs/crawling-indexing/links-crawlable),
[breadcrumb markup](https://developers.google.com/search/docs/appearance/structured-data/breadcrumb),
and [useful original content](https://developers.google.com/search/docs/fundamentals/creating-helpful-content).

## P2: Earn visibility and measure outcomes

- Record a Search Console baseline before release: indexed intended URLs,
  exclusion reasons, Google-selected canonicals, branded and non-branded
  impressions/clicks, CTR, and average position by query and page. Preserve
  date range, country, and device filters for comparable measurements.
- Review at 14, 30, and 60 days after release. Compare non-branded query coverage
  and clicks as well as indexed intended pages; a single brand search is not
  the success metric. Low traffic may make CTR and position comparisons noisy.
- Improve titles and explanations using actual queries and result-page intent.
  Group close query variants onto the same useful page. Record actionable
  findings instead of scheduling automatic changes.
- Prepare useful public examples, release notes, and reproducible technical
  reports for relevant developer and wireless communities. Add product links
  to public repository documentation where relevant in a separately reviewed
  change. Outreach or messages to other people require explicit authorization.
- Publish measured comparison or benchmark reports only after the documented
  protocol has actually been run. Current [benchmark material](../../../apps/product-site/src/data/products.ts),
  lines 398-454, explicitly contains no measured results.
- Improve navigation for possible brand-result sitelinks, while recognizing
  that [Google selects sitelinks automatically](https://developers.google.com/search/docs/appearance/sitelinks).
  Do not promise multiple results for every query or a top position.

## Expanded acceptance criteria

- A 96x96 PNG favicon and valid ICO return image content, and the homepage
  declares the intended stable icon. Neither icon path serves fallback HTML.
- A random unknown path and each unmatched retired route return HTTP 404/410;
  approved equivalent redirects return 301/308 with the intended Location.
  All eight existing public content routes remain reachable with their current
  canonical targets. The error page is excluded from the sitemap and indexing.
- The six new guides are published only after their distinct examples and
  claims pass evidence review. All are reachable from static internal links
  and included in the sitemap, with self-canonicals and unique metadata.
- Breadcrumb markup matches rendered navigation and passes applicable
  structured-data validation. Organization markup and favicon are checked
  separately; neither is treated as a guaranteed ranking improvement.
- Extend existing browser route coverage to the guides and error page; check
  navigation, keyboard access, static content, canonicals, and metadata.
  Run the site's required build/browser checks and the documentation checker.
  Verify live status codes separately because local preview does not prove
  Cloudflare's deployed routing behavior.
- Establish the Search Console baseline and review records. Set numerical
  traffic goals only after baseline volume is known; setup completion and
  publication do not constitute proof of ranking gains.

## Implementation evidence, October 8, 2026

All code tasks are implemented locally. Six guides are statically generated by
the model-driven [guide route](../../../apps/product-site/src/pages/guides/%5Bslug%5D.astro),
with an index, homepage/product/navigation links, and 15 sitemap URLs. PNG/ICO
assets, preview indexing guards, breadcrumb markup, missing-page handling,
contact redirects, and both console exclusions are complete. No new
dependencies, account changes, commits, pushes, or deployments were made.

Production and inherited-variable preview builds passed. After cleanup, the
production build generated 16 HTML pages with no diagnostics; the full Chromium
suite passed 50 tests, with two analytics tests skipped because no measurement
ID is configured. The final artifact has 15 unique apex-domain sitemap URLs,
self-canonicals, no public indexing exclusions, and an excluded 404.
Both console UI builds passed, with one effective `noindex` meta in each output.
Local Pages checks confirmed 404 responses, contact 301 redirects, and image
responses for both favicons. Independent review approved the implementation and
cleanup. See the [validation record](../../../apps/product-site/docs/validation-results.md).

Generated build and test outputs were refreshed solely for verification. The
manual Google tasks listed under Work ownership remain with the user; remote
publication still follows the existing reviewed Git workflow. Optional
hostname redirects and later measured benchmark reports were not added.
