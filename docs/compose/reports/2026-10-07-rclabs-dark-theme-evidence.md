# RCLabs dark theme — verification evidence

Date: 2026-10-07
Spec: [design](../specs/2026-10-07-rclabs-dark-theme-design.md)
Plan: [plan](../plans/2026-10-07-rclabs-dark-theme.md)

## Command results

| Surface | Command | Result |
| --- | --- | --- |
| Docs (pre) | `python3 scripts/check-docs.py` | PASS |
| Product site build | `cd apps/product-site && npm run build` | PASS — 8 routes, 0 diagnostics |
| Product site browser tests | `cd apps/product-site && npm test` | PASS — 40 passed, 2 skipped (GA4 without measurement ID) |
| Product site visual review | `cd apps/product-site && npm run review` | PASS — 8 routes × desktop/mobile, 0 errors, CLS ≤ 0.013 |
| Atheros Search | `make atheros-search-ui-check` | pending |
| Atheros Search e2e | `cd apps/integration-console/atheros-search-ui && npm run test:e2e` | pending |
| Schema Migrator build | `cd apps/schema-migrator/schema-migrator-ui && npm run build` | pending |
| Schema Migrator tests | `cd apps/schema-migrator/schema-migrator-ui && npm test` | pending |
| Schema Migrator Electron | `cd apps/schema-migrator/schema-migrator-ui && npm run electron:build-main` | pending |
| Keycloak login suite | `cd scripts/tests/keycloak-theme && npm test` | pending |
| Docs (final) | `python3 scripts/check-docs.py` | pending |

## Fixes made during gap-close

- `apps/product-site/docs/validation-results.md`: removed light-theme guidance and stale dated pass claims; describes shared dark theme only.
- `apps/schema-migrator/codex/skills/schema-migrator-ui-quality/references/wcag-22-aa-codex.md`: contrast rule now names the shared dark-only theme.

## Fixes made during verification

(none yet)

## Manual evaluation still pending

All entries below remain **pending**. No WCAG conformance claim is made from
the automated evidence above.

- Public routes and every demo state: keyboard and screen-reader walkthrough,
  reading preferences, true zoom and forced colours.
- Search routes, populated/empty/error results, graph/detail/drawer and report
  states: keyboard equivalents, reading order, announcements, zoom and forced
  colours.
- Migrator routes, forms, validation errors, dialogs and run states in web and
  packaged desktop clients: keyboard, screen reader, zoom and forced colours.
- Live Keycloak normal/error login, password-manager use and recovery: keyboard,
  screen reader, zoom and Windows High Contrast.
- Touch, switch, voice and reduced-motion evaluation on supported devices.
- Complete applicability review of every WCAG 2.2 criterion before making any
  conformance statement.
