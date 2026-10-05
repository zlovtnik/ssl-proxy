# Product site

- This is a static public marketing frontend, separate from the operator consoles.
- Use Astro pages and SolidJS islands with synthetic fixtures in `src/data/`.
- Keep core navigation, product copy, and email contact available without JavaScript.
- Do not add production API calls, credentials, tracking, or migration execution.
- Preserve the Search observation/identity caveat and SQL-file snapshot/backup caveat.
- Run `npm run build` and `npm test` for site changes.
- Keep accessibility evidence in `docs/accessibility-matrix.md`; distinguish automated
  evidence from pending assistive-technology and participant evaluation.
- A public build needs `PUBLIC_SITE_URL`. Publication follows the reviewed Git
  deployment path; the local site does not provision hosting.
