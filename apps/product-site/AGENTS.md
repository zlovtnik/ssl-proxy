# Product site

- This is a static public marketing frontend, separate from the operator consoles.
- Use Astro pages and SolidJS islands with synthetic fixtures in `src/data/`.
- Keep core navigation, product copy, and email contact available without JavaScript.
- Do not add production API calls, credentials, tracking, or migration execution.
- Preserve the Search observation/identity caveat and SQL-file snapshot/backup caveat.
- Run `npm run build` and `npm test` for site changes.
- Keep accessibility evidence in `docs/accessibility-matrix.md`; distinguish automated
  evidence from pending assistive-technology and participant evaluation.
- Shared branding, type, spacing, and controls live in `src/styles/site.css`.
  Route stylesheets compose those patterns and must not redefine them.
- Copy lives in `src/data/products.ts`. Follow `docs/messaging.md` and
  `docs/design-system.md` when adding copy or patterns; publish mechanisms, not
  savings, latency, or market claims.
- A public build needs `PUBLIC_SITE_URL`. Publication follows the reviewed Git
  deployment path; the local site does not provision hosting.
