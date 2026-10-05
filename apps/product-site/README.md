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
third-party analytics is used. Display preferences are stored only in browser
local storage, with a fallback when storage is unavailable.
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
- [Accessibility matrix](docs/accessibility-matrix.md)
- [Evaluation and release checklist](docs/release-checklist.md)

## Publication

This is a reviewable local build. The default metadata origin is localhost and
indexing is disabled. A selected public origin is passed as `PUBLIC_SITE_URL`
at build time. The configuration validates that it is an HTTP(S) origin.
The sitemap, canonical URLs, social URLs, and robots response use that origin.
Do not ship localhost metadata.

Publication requires a reviewed Git change defining hosting, the chosen hostname,
and the repository's Kustomize/Argo CD delivery path under [cyber-stack](../../cyber-stack).
No cluster or hosting mutation is performed by the build or test scripts.
An AAA conformance claim requires the complete scoped evaluation to pass first.
