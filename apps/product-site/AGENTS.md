# Product site

- This is a static public marketing frontend, separate from the operator consoles.
- Use Astro pages and SolidJS islands with synthetic fixtures in `src/data/`.
- Keep core navigation, product copy, and email contact available without JavaScript.
- Analytics may be added only with explicit consent, minimal event data, no PII,
  and production-only configuration. Never add advertising or identity tracking.
- Preserve the Search observation/identity caveat and SQL-file snapshot/backup caveat.
- Run `npm run build` and `npm test` for site changes.
- Keep accessibility evidence in `docs/accessibility-matrix.md`; distinguish automated
  evidence from pending assistive-technology and participant evaluation.
- Shared branding, type, spacing, and controls live in `src/styles/site.css`.
  Route stylesheets compose those patterns and must not redefine them.
- Copy lives in `src/data/products.ts`. Follow `docs/messaging.md` and
  `docs/design-system.md` when adding copy or patterns; publish mechanisms, not
  savings, latency, or market claims. The two caveats, the contact labels, and
  the audience statements belong to that model, not to a route or a component.
- `npm test` measures rendered text, control boundaries, and focus rings on every
  route in the shared dark theme. Keep new colours and controls inside those targets.
- Dark is the only theme; ignore saved theme values and system colour preferences.
  Preserve the other reading preferences and forced-colours support.
- A public build needs `PUBLIC_SITE_URL`. Publication follows the reviewed Git
  deployment path; the local site does not provision hosting.
