# RCLabs public product site

A standalone Astro + TypeScript frontend with SolidJS synthetic demonstrations.
The existing Search and Migrator operator consoles are separate applications.
No application API, authentication, database, or migration execution is used here.

## Local development

Use Node.js 22.12 or newer and npm:

```sh
cd apps/product-site
npm ci
npm run dev
```

Open `http://localhost:4321`. Routes are `/`, `/atheros-search/`,
`/schema-migrator/`, `/demo/`, and `/accessibility/`.

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
committed. Fonts are bundled locally from Fontsource packages; no font CDN or
third-party analytics is used. The two Latin variable faces are preloaded from
build-time asset URLs so the first paint already uses them. Display preferences
are stored only in browser local storage, with a fallback when storage is
unavailable.
Original font licenses are shipped in `public/font-licenses/`.

Use `npm run format:check` to check source formatting and `npm run format`
to apply the pinned Astro-aware formatter.

With the preview running, `npm run review` captures screenshots of all routes
in both themes at desktop/mobile sizes and writes single-run local performance
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
`https://rclabs.uk`; preview builds use the localhost default and remain
`noindex`. The configuration validates that the value is an HTTP(S) origin.
The sitemap, canonical URLs, social URLs, and robots response use that origin.
Do not ship localhost metadata.

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
