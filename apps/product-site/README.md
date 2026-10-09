# RCLabs public product site

A standalone Astro + TypeScript frontend with SolidJS synthetic demonstrations
for Atheros Search, Schema Migrator, and RCLabs VPN / Proxy, plus a static Octopus
product page with manually captured operational evidence. The existing Search
and Migrator operator consoles are separate applications.
No application API, authentication, database, or migration execution is used here.

## Local development

Use Node.js 22.12 or newer and npm:

```sh
cd apps/product-site
npm ci
npm run dev
```

Open `http://localhost:4321`. Routes are `/`, `/products/`,
`/atheros-search/`, `/schema-migrator/`, `/vpn-proxy/`, `/octopus/`, `/demo/`,
`/accessibility/`, and `/privacy/`.

```sh
npm run build
npx playwright install chromium
npm test
npm run preview
```

To run the same checks in Chromium, Firefox, and WebKit:

```sh
npx playwright install chromium firefox webkit
npm run test:all-browsers
```

Generated dependency, build, and test outputs are ignored. The npm lockfile is
committed. Fonts are bundled locally from Fontsource packages; no font CDN is
used. The two Latin variable faces are preloaded from build-time asset URLs so
the first paint already uses them. Previously saved display preferences may
still be applied from browser local storage. Google Analytics 4 is loaded only
on the production host, after analytics consent, and only when
PUBLIC_GA4_MEASUREMENT_ID contains the GA4 web stream ID. Local and Pages
preview builds do not include the analytics ID.
Original font licenses are shipped in `public/font-licenses/`.

Use `npm run format:check` to check source formatting and `npm run format`
to apply the pinned Astro-aware formatter.

With the preview running, `npm run review` captures screenshots of all routes
in the shared dark theme at desktop/mobile sizes and writes single-run local performance
measurements to the ignored `review-artifacts/` directory. The mobile profile
uses 4x CPU slowdown, 150ms latency, and 1.6Mbps download. These measurements
are lab evidence, not field Core Web Vitals. The committed PNG social preview
is a raster export of the original SVG in `public/`.

## Content and evidence

- [Atheros Search documentation](../integration-console/atheros-search/README.md)
- [Schema Migrator documentation](../schema-migrator/README.md)
- [Content source map](docs/content-evidence.md)
- [Messaging framework](docs/messaging.md)
- [Design system](docs/design-system.md)
- [Accessibility matrix](docs/accessibility-matrix.md)
- [Evaluation and release checklist](docs/release-checklist.md)
- [Local validation results](docs/validation-results.md)

## Publication

The public site uses the Cloudflare Pages project `rclabs`, connected to
`https://rclabs.uk` and `https://www.rclabs.uk`. Like the separate Search and
Migrator Pages projects, it is connected to `zlovtnik/ssl-proxy` and deploys
automatically from `main`. Cloudflare watches `apps/product-site/*`, runs
`npm run build` in `apps/product-site`, and uses the `dist` output declared in
[`wrangler.jsonc`](wrangler.jsonc). Other repository changes do not trigger a
public-site build.

The default local metadata origin is localhost and indexing is disabled.
Cloudflare sets the production build's `PUBLIC_SITE_URL` to
`https://rclabs.uk`; Pages branches other than `main` force the localhost
metadata origin and remain `noindex`, even if they inherit `PUBLIC_SITE_URL`.
The configuration validates that the value is an HTTP(S) origin.
Set PUBLIC_GA4_MEASUREMENT_ID in the production Pages build environment after
creating the GA4 web stream. It is a public measurement ID, not a credential.
Leave it unset in local and preview builds.
Octopus fetches `/api/octopus-stats` every 30 seconds. The
[Pages Function](functions/api/octopus-stats.ts) requests the coordinator's public
stats endpoint at runtime, with no build-time measurements or URL setup.
Only the production hostnames can use this proxy; local and Pages preview
hosts return unavailable and never fetch production. Browser tests intercept
this route with isolated responses. No-JavaScript visitors see unavailable
readings and an explanation. Upstream failures, invalid responses and stale
timestamps cannot fall back to saved values.
The sitemap, canonical URLs, social URLs, and robots response use that origin.
Do not ship localhost metadata.

## Search visibility

The public product pages and six technical guides are indexable in production.
The guide index, navigation, product links, and sitemap expose the guide routes
without JavaScript. Visible product and guide breadcrumbs have matching
BreadcrumbList markup. The separate authenticated Search and Migrator console
shells use `noindex`; public product pages are the search destinations.

The [404 route](src/pages/404.astro) creates the top-level `404.html` that
disables Pages' default single-page application fallback. Unmatched retired
addresses return a missing-page response instead of a successful homepage copy.
The [redirect rules](public/_redirects) move the old contact address to the
current contact page. Canonical metadata prefers the apex hostname over `www`.

The existing SVG brand icon has PNG and ICO equivalents for search and browser
compatibility. Recreate them after an intentional icon change with
`node scripts/generate-favicons.mjs`; this uses the installed local Playwright
browser and changes only those two public assets.

Google Search Console remains manual: verify account access, submit the sitemap,
inspect the homepage and product/guide URLs, and request indexing after reviewed
publication. Check indexed HTML and crawl dates before treating old snippets as
current site content. See the [search implementation plan](../../docs/compose/plans/2026-10-08-google-search-console.md).

## Reviewed publication

After reviewing the Git source and running local tests, push a branch touching
`apps/product-site/` and inspect its automatic Pages preview. Merge the
reviewed change to `main` to publish automatically, then verify the live site.
To reproduce the production build locally:

```sh
PUBLIC_SITE_URL=https://rclabs.uk npm run build
```

Do not use a direct Wrangler upload for routine publication. The October 5,
2026 direct uploads were approved exceptions before Git deployment was
connected. Their production deployments
`28901202-7e1e-4e99-b370-541aa9f26987` and
`a016abbb-cdf6-4be6-89f2-1e6fc5307ad8` remain in Pages history for rollback.

Every page that shows or links the address wraps it in `<!--email_off-->`
markers so Cloudflare Email Obfuscation cannot replace the visible address or
the `mailto:` links, which must work without JavaScript.

Root-site publication does not require Wiretrap or tunnel changes. Kubernetes
changes still follow the Kustomize/Argo CD delivery path under
[cyber-stack](../../cyber-stack). The build and test scripts perform no cluster
or hosting mutation.
An AAA conformance claim requires the complete scoped evaluation to pass first.
