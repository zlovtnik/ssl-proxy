# Shared RCLabs theme and accessibility evidence

The public site, Atheros Search, Schema Migrator web and desktop clients, and
the custom Keycloak login use one dark theme. System colour preference and
previously stored light or system selections do not select another palette.
The public site's other reading preferences remain available. Forced colours
may replace author colours with the user's system colours.

## Palette contract

The [public design system](../apps/product-site/docs/design-system.md) is the
palette reference. Each app keeps its existing token names and component
structure.

| Role | Colour | Use |
| --- | --- | --- |
| Page | `#090909` | Main background and desktop startup background |
| Surface | `#141414` | Panels, navigation and form surfaces |
| Raised surface | `#1C1C1C` | Raised panels and hover surfaces |
| Primary text | `#F5F5F2` | Headings, labels and content |
| Secondary text | `#BEC2B9` | Supporting text and metadata |
| Brand accent | `#A3E6A3` | Primary actions, selection and brand focus |

Dark text on filled green actions must retain at least 7:1 contrast. Warnings,
errors and information retain distinct semantic colours and text or icons;
green must not replace their meanings. Decorative dividers may be subdued,
but boundaries needed to identify controls must reach 3:1 against adjacent
surfaces. Focus must remain visible on green actions as well as dark surfaces.

Calculated solid-colour contrast against the raised surface is 15.60:1 for
primary text, 9.42:1 for secondary text, and 11.69:1 for the accent. These token
calculations do not cover opacity, gradients, overlays, images or all rendered
states; browser checks must cover those combinations separately.

## Accessibility targets

The target is all applicable [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
A, AA and AAA criteria. This theme change and its automated checks do not
establish conformance. Layouts, copy, data meanings and authentication workflows
retain their existing purposes.

| Area | Acceptance target | Evaluation still required |
| --- | --- | --- |
| Text and non-text contrast | Normal text 7:1; large text 4.5:1; applicable control boundaries and state indicators 3:1. Large means at least 24 CSS px, or about 18.67 CSS px bold. | Inspect composited states, diagrams, SVGs, disabled exceptions and platform rendering. |
| Keyboard and focus | Keyboard access without traps; logical focus order; focus fully visible; indicator area at least a 2 CSS px perimeter equivalent with a 3:1 change. | Complete workflows with keyboard, including dialogs, menus, graph alternatives and authentication. |
| Target size | 44 by 44 CSS px targets, with documented inline, equivalent, user-agent or essential exceptions. | Touch, switch and voice control evaluation; graph targets and equivalent controls. |
| Reflow and text | 320 CSS px wide layouts; 200% text; 1.5 line height, 2em paragraph spacing, 0.12em letter spacing and 0.16em word spacing without lost content or controls. | True 400% browser zoom, desktop OS scaling, text presentation and essential two-dimensional regions. |
| Motion and appearance | Honour reduced motion and forced colours; preserve boundaries, focus, selection and readable state labels. | Windows High Contrast and device motion preferences, including Electron native chrome. |
| Structure and status | Names, roles, values, relationships, headings and status announcements remain available. | VoiceOver/Safari and NVDA/Firefox, tables, graph/report equivalents and error announcement timing. |
| Authentication and input | Preserve password-manager and paste support, labels, error associations and existing confirmation mechanisms. | Complete login, error recovery, re-authentication and error-prevention processes with assistive technology. |
| Other applicable criteria | Review language, abbreviations, reading level, help, timing, interruptions, navigation and media criteria. | Criterion-by-criterion applicability review with content and product owners; no blanket exemption based on this visual scope. |

Focus and target-size interpretations follow W3C's
[focus appearance guidance](https://www.w3.org/WAI/WCAG22/Understanding/focus-appearance.html)
and [enhanced target-size guidance](https://www.w3.org/WAI/WCAG22/Understanding/target-size-enhanced.html).

## Repeatable checks

| Surface | Commands and evidence |
| --- | --- |
| Public site | In `apps/product-site`, run `npm run build`, `npm test`, and `npm run review` against a local preview. See the [accessibility matrix](../apps/product-site/docs/accessibility-matrix.md), [browser tests](../apps/product-site/tests/site.spec.ts), [layout tests](../apps/product-site/tests/layout.spec.ts), and [validation results](../apps/product-site/docs/validation-results.md). |
| Atheros Search | Run `make atheros-search-ui-check` from the repository root and the UI's `npm run test:e2e`. The [browser suite](../apps/integration-console/atheros-search-ui/tests/e2e/) covers Search, inventory, graph and reports with synthetic responses. |
| Schema Migrator | In `apps/schema-migrator/schema-migrator-ui`, run `npm run build`, `npm test`, and `npm run electron:build-main`. See [design checks](../apps/schema-migrator/schema-migrator-ui/src/design/) and [UI quality guidance](../apps/schema-migrator/codex/skills/schema-migrator-ui-quality/SKILL.md). |
| Keycloak | In `scripts/tests/keycloak-theme`, run `npm test`. The [login suite](../scripts/tests/keycloak-theme/login.spec.cjs) loads the actual theme CSS into representative normal and error fixtures; it does not run a Keycloak server. |
| Documentation | Run `python3 scripts/check-docs.py` from the repository root. |

Builds and browser checks generate local output such as `dist`, test reports
and screenshots. These are verification artifacts, not deployment changes.

## Manual evaluation record

All entries below remain **pending** until a person records the browser or
desktop version, platform, routes/states, result and any issue. Automated
keyboard input, viewport resizing and forced-colours emulation are supporting
evidence only.

- [ ] Public routes and every demo state: complete keyboard and screen-reader
  walkthrough, reading preferences, true zoom and forced colours.
- [ ] Search routes, populated/empty/error results, graph/detail/drawer and
  report states: keyboard equivalents, reading order, announcements, zoom and
  forced colours.
- [ ] Migrator routes, forms, validation errors, dialogs and run states in web
  and packaged desktop clients: keyboard, screen reader, zoom and forced colours.
- [ ] Live Keycloak normal/error login, password-manager use and recovery:
  keyboard, screen reader, zoom and Windows High Contrast.
- [ ] Touch, switch, voice and reduced-motion evaluation on supported devices.
- [ ] Complete applicability review of every WCAG 2.2 criterion before making
  any conformance statement.
