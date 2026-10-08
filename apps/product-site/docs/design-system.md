# Design system

All eight public routes share [site.css](../src/styles/site.css). It owns
colours, typography, spacing, surfaces, controls, product cards, and demo layouts.
[landing.css](../src/styles/landing.css) composes homepage-specific patterns
without redefining the shared system.

The machine-readable palette source is
[`theme/rclabs.tokens.json`](../../../theme/rclabs.tokens.json) at the repository
root. Surface token values are generated from it (`make theme-sync`) and checked
with `make theme-check`. Do not hand-edit colour hexes in `site.css`.

## Palette

| Role | Shared dark theme |
| --- | --- |
| Page | `#090909` |
| Panel | `#141414` |
| Raised surface | `#1C1C1C` |
| Inset surface | `#0E0E0E` |
| Main text | `#F5F5F2` |
| Secondary text | `#BEC2B9` |
| Action / product accent / focus | `#A3E6A3` |
| Action text | `#102010` |
| Control boundary | `#7D8278` |
| Decorative divider | `#343632` |

Dark is the only theme. The public site, Search, Migrator web and desktop, and
custom Keycloak login share the six core RCLabs colours. The site renders dark
before JavaScript and ignores saved theme values and system colour preferences.
Forced colours may override the palette for accessibility.
Green identifies actions, selected states, and focus; labels,
icons, and pressed attributes identify the products and their state independently
of colour. Depth comes from distinct surfaces, fine borders, and restrained
shadows.

The [browser suite](../tests/site.spec.ts) checks 7:1 normal text, 4.5:1 large
text, and 3:1 control boundaries and focus rings. Token checks cover all four
surfaces; rendered checks composite ancestor backgrounds. Decorative dividers
are not control boundaries.

## Typography and geometry

- Self-hosted Inter Variable for prose and controls; JetBrains Mono Variable
  for code, metadata, indices, and diagrams. Latin faces remain preloaded.
- Hero headings: 40-72px; section headings: 28-40px; body: 16px; supporting
  technical detail: 14px. Product category captions may use 12px with full
  normal-text contrast.
- Shell: 1280px maximum. Gutters: 24px mobile, 32px tablet, 48px desktop.
- Reading width: 64ch by default.
- Section spacing: 96px desktop, 56px mobile. Controls: 6px radius; panels: 12px.
- Product cards: three columns at desktop, two below 1024px, one below 768px.
- Heroes place introductory copy beside a short workflow outline and stack
  below 1024px. Demos always occupy a separate full-width section below.
- Demo inputs and results use two columns at desktop and stack below 768px.
  Controls wrap; content determines height.

## Expansion and interaction

The playground keeps each product's state mounted. Inactive panels use
`hidden`, `inert`, and `aria-hidden`; they occupy no layout space. Visible
panels grow naturally. No overlapping grid placement or fixed preview height
is used.

Native disclosures stay in document flow. Long SQL, identifiers, and explanations
wrap within their panel. [Layout regressions](../tests/layout.spec.ts) open
disclosures separately and together, cycle every sample, and check containment,
card collisions, subsequent section positions, and overflow from 320 to 1440px.
The same checks cover 200% text with expanded spacing.

Keyboard focus stays visible; interactive controls target at least 44px.
Animations only clarify state changes. Reduced motion and forced colours remain
supported. Static navigation, product copy, contact, and text explanations work
without JavaScript.

## Shared patterns

[ProductPage](../src/components/ProductPage.astro) renders the common product
page structure. [ProductCards](../src/components/ProductCards.astro) serves the
homepage and catalogue. [Layout](../src/layouts/Layout.astro) owns navigation,
footer, and consent.

The homepage technical sections retain captioned tables, scoped headers, native
disclosures, and labelled diagrams. Wide tables scroll inside named,
keyboard-accessible regions. Product comparisons use responsive definition lists.

Browser zoom, custom styles, forced colours, and system reduced-motion settings
remain supported. Previously saved text size, line width, spacing, and movement
choices are still applied when present in browser storage; the site no longer
provides controls to change them.

## Verification and maintenance

Run `npm run build`, `npm test`, and `npm run review` after visual changes.
Update [validation results](validation-results.md), the
[accessibility matrix](accessibility-matrix.md), and
[messaging guidance](messaging.md). Automated checks do not establish
screen-reader usability or accessibility conformance; those evaluations remain
tracked in the [release checklist](release-checklist.md).
