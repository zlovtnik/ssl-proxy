# Design system

One system across all five public routes. [`src/styles/site.css`](../src/styles/site.css)
owns the tokens, type, geometry, and cross-route patterns.
[`src/styles/landing.css`](../src/styles/landing.css) may arrange homepage
composition but must not redefine branding: no raw colours, no shadowing of
shared type or control rules outside its own section classes.

`tests/site.spec.ts` asserts this boundary by snapshotting tokens, header
geometry, reading-settings placement, heading type, and control styling across
all five routes in both themes. A route that drifts fails the suite.

## Palette

| Role                   | Dark theme | Light theme |
| ---------------------- | ---------- | ----------- |
| Page background        | `#090D1A`  | `#F7F8FF`   |
| Panel background       | `#121A2B`  | `#EDF0FA`   |
| Main text              | `#F4F6FF`  | `#10182B`   |
| Secondary text         | `#B8C4DD`  | `#394865`   |
| Violet accent / action | `#C4B5FD`  | `#5B21B6`   |
| Cyan evidence accent   | `#67E8F9`  | `#164E63`   |
| Control boundary       | `#687999`  | `#667085`   |
| Decorative divider     | `#26324A`  | `#D7DEEB`   |
| Primary-button text    | `#160E2B`  | `#FFFFFF`   |

Colour carries meaning, and only that meaning:

- Violet is the primary action colour on both products.
- Cyan marks Search evidence. Violet marks Migrator plans.
- Green is reserved for labelled success states such as the copy confirmation.
- Accent colour never replaces text. Pressed, current, and success states are
  also carried by text, weight, or an `aria-*` attribute.

Core text and accent pairs are calculated above 7:1 against both page and panel
backgrounds; control boundaries meet 3:1. Verify rendered states, not just
token values. The automated check covers token pairs; rendered combinations
remain part of the manual evaluation in
[the accessibility matrix](accessibility-matrix.md).

## Typography

Both families are self-hosted Fontsource variable fonts. There are no external
font requests.

- Inter Variable: headings, body copy, controls.
- JetBrains Mono Variable: SQL, identifiers, metadata, diagram labels, indices.

| Role                | Size                                   | Weight |
| ------------------- | -------------------------------------- | ------ |
| Shared hero heading | 40px to 72px, fluid                    | 550    |
| Section heading     | 28px to 40px, fluid                    | 550    |
| Lead paragraph      | 18px to 20px, fluid                    | 400    |
| Body                | 16px minimum                           | 400    |
| Technical detail    | 14px minimum, monospace where relevant | 550    |

Headings use balanced wrapping, tightened tracking, and no fixed widths beyond
the prose measure.

## Geometry

- Shell: 1280px maximum, centred.
- Gutters: 24px at mobile, 32px at tablet, 48px at desktop.
- Prose measure: approximately 64 characters, adjustable by reader preference.
- Section spacing: 96px desktop, 56px mobile.
- Control radius: 6px. Demo panel radius: 12px.
- Hero: five columns of copy, seven of proof at desktop. Stacks below 1024px.
- Depth comes from differentiated surfaces, restrained shadows, and a faint
  violet glow behind the hero proof panel.

Verified at 320, 375, 768, 1024, and 1440px in both themes with no
page-level horizontal scrolling, including enlarged text.

## Shared patterns

`Layout.astro` owns the header, footer, navigation, display settings, and
theme tokens. Route files compose these patterns and add nothing of their own
structure where a shared one exists.

| Pattern         | Classes                                             |
| --------------- | --------------------------------------------------- |
| Hero            | `.hero`, `.hero-split`, `.hero-copy`, `.hero-proof` |
| Section heading | `.section`, `.section-heading`, `.eyebrow`          |
| Workflow        | `.workflow-steps`, `.workflow-step`                 |
| Audience value  | `.audience-grid`, `.audience-card`, `.checklist`    |
| Evidence        | `.evidence-panel`, `.caveat`, `.feature-grid`       |
| Demo panel      | `.demo-panel`, `.demo-top`, `.demo-content`         |
| Contact         | `.contact-banner`, `.email-row`                     |
| Actions         | `.actions`, `.button`, `.text-link`                 |
| Location        | `.breadcrumb`                                       |

## Visuals and interaction

- Use selectable SQL, real synthetic result records, ranking explanations, and
  labelled input/process/output diagrams. Every synthetic dataset is visibly
  labelled.
- Do not add decorative 3D objects, stock photography, generic feature icons, or
  invented charts.
- Keep headings descriptive, paragraphs short, and technical evidence adjacent to
  the claim it supports.
- Put extended definitions in native `details` disclosures.
- Use brief state transitions, visible focus, and labelled status indicators.
  Remove continuous decorative pulsing and unnecessary entrance movement.
- Honour forced colors with system colors for borders, diagram strokes, and
  focus outlines.

## Display preferences

Theme, text size, line width, text spacing, and movement are reader settings
that persist in local storage with a working fallback. Theme changes apply
immediately so text never crosses an intermediate contrast state. All settings
are offered in the same position on every route. Settings are progressive
enhancement: browser zoom, text sizing, and custom styles keep working without
JavaScript.

## Changing the system

1. Change the token or pattern in `site.css`. Do not patch a route to work
   around a token.
2. If a new token is introduced, add it to the contrast test's token list.
3. Run `npm run build`, `npm test`, and `npm run review`, then record the
   outcome in [validation results](validation-results.md).
4. Update this file and [the messaging framework](messaging.md) when the change
   affects the palette, type scale, geometry, or pattern inventory.
