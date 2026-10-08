# RCLabs dark/green theme across all UIs — design

## [S1] Problem

Four UI surfaces (public product site, Atheros Search, Schema Migrator web and desktop, custom Keycloak login) must share one dark RCLabs palette and stop offering light or system themes. Layouts, copy, data meanings and authentication behaviour stay as they are. The public site keeps its other reading preferences.

## [S2] Solution overview

Align each app's existing design tokens to the documented six-colour RCLabs palette, force dark as the only theme, keep semantic warning/error/info colours distinct and legible, and update theme guidance, accessibility documentation and tests. Target WCAG 2.2 AAA contrast (7:1 normal text, 4.5:1 large text, 3:1 applicable control boundaries and focus indicators) plus the listed non-contrast checks. No conformance claim beyond collected evidence.

## [S3] Palette contract

| Role | Colour | Use |
| --- | --- | --- |
| Page | `#090909` | Main background and desktop startup background |
| Surface | `#141414` | Panels, navigation and form surfaces |
| Raised surface | `#1C1C1C` | Raised panels and hover surfaces |
| Primary text | `#F5F5F2` | Headings, labels and content |
| Secondary text | `#BEC2B9` | Supporting text and metadata |
| Brand accent | `#A3E6A3` | Primary actions, selection and brand focus |

Supporting tokens (boundaries, dividers, action-on-green text, semantic status colours) sit outside the six core colours and are intentional. The public design system is the palette reference; each app keeps its own token names and component structure.

## [S4] Surface coverage

| Surface | Token home | Dark lock | Theme UI |
| --- | --- | --- | --- |
| Public site | `apps/product-site/src/styles/site.css` | `data-theme="dark"` in `Layout.astro` | Theme select removed; size/width/spacing/motion prefs kept |
| Atheros Search | `apps/integration-console/atheros-search-ui/src/styles/tokens.css` | `data-theme="dark"` in `index.html`, `color-scheme: dark` | `ThemeToggle.tsx` deleted |
| Schema Migrator web | `apps/schema-migrator/schema-migrator-ui/src/design/tokens.ts` | `installDesignTokens()` forces `dataset.theme = "dark"` | Theme select removed from Settings |
| Schema Migrator desktop | `electron/main.ts` | `nativeTheme.themeSource = "dark"`, window `backgroundColor: "#090909"` | Same web bundle |
| Keycloak login | `cyber-stack/base/schema-migrator/configmaps/keycloak-theme/login/` | `color-scheme: dark` CSS + meta, `darkMode=true` | No theme choice (login page) |

## [S5] Behaviour rules

- Dark is applied regardless of `prefers-color-scheme` or a previously saved theme.
- Public site reading preferences other than theme remain available and persist under the existing opt-in.
- Green is used for primary actions, selection and brand focus. Warning, error and informational colours stay distinct and keep text or icon cues.
- Dark text on filled green actions retains at least 7:1 contrast. Focus remains visible on green actions and dark surfaces.
- Forced colours may replace author colours; boundaries, focus, selection and readable state labels are preserved.
- Keycloak authentication behaviour and error states are unchanged.

## [S6] Accessibility targets

All applicable WCAG 2.2 A, AA and AAA criteria are the target. Automated checks cover token and rendered contrast, focus indicators, target size, reflow/text-spacing, reduced-motion, forced-colours, keyboard order and axe rules. Manual keyboard, screen-reader, zoom, touch/switch/voice and Windows High Contrast evaluation remain pending and are recorded in `docs/rclabs-theme.md`. No conformance claim is made from automation alone.

## [S7] Verification

| Surface | Commands |
| --- | --- |
| Public site | `cd apps/product-site && npm run build && npm test && npm run review` |
| Atheros Search | `make atheros-search-ui-check` and `cd apps/integration-console/atheros-search-ui && npm run test:e2e` |
| Schema Migrator | `cd apps/schema-migrator/schema-migrator-ui && npm run build && npm test && npm run electron:build-main` |
| Keycloak | `cd scripts/tests/keycloak-theme && npm test` |
| Documentation | `python3 scripts/check-docs.py` |

## [S8] Current state and remaining work

Theme implementation is present as uncommitted changes across the four surfaces. Remaining gaps before verification:

1. Stale light-theme wording in `apps/product-site/docs/validation-results.md` (lines 14, 27).
2. Stale "light and dark themes" wording in `apps/schema-migrator/schema-migrator-ui` skill reference `codex/skills/schema-migrator-ui-quality/references/wcag-22-aa-codex.md:87`.
3. Untracked files that belong to this change: `docs/rclabs-theme.md`, `schema-migrator-ui/src/design/sqlHighlightTheme.ts`, `atheros-search-ui/tests/e2e/theme.spec.ts`.
4. Verification suite has not been run against the working tree.

## [S9] Out of scope

App layouts, copy, data meanings and API contracts. Cluster or GitOps mutation beyond the already-modified Keycloak theme ConfigMap sources. Committing or opening a PR unless requested. Making a WCAG conformance claim.
