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
| Labelled success text  | `#6EE7B7`  | `#064E3B`   |
| Focus outline          | `#F4F6FF`  | `#10182B`   |

Colour carries meaning, and only that meaning:

- Violet is the primary action colour on both products.
- Cyan marks Search evidence. Violet marks Migrator plans.
- Green is reserved for labelled success states such as the copy confirmation.
- Accent colour never replaces text. Pressed, current, and success states are
  also carried by text, weight, or an `aria-*` attribute.

Token pairs are calculated above 7:1 against both page and panel backgrounds;
control boundaries meet 3:1. Rendered combinations are measured separately,
because alpha, colour mixes, and inherited surfaces are invisible to a token
check: the browser walk in `tests/site.spec.ts` composites each layer and
asserts 7:1 for normal text, 4.5:1 for large text, and 3:1 for control
boundaries and focus rings, on every route in both themes. Two results from
that walk shaped the system: secondary text on a selected playground row needed
the accent tint reduced from 10% to 6%, and a filled control is identified by its
own surface rather than its border. Decorative dividers are excluded by design.
Forced-colors rendering still needs a human check; automation cannot select that
rendering mode for a reader.

## Typography

Both families are self-hosted Fontsource variable fonts. There are no external
font requests. `Layout.astro` preloads the two Latin variable faces through
build-time asset URLs, because a late swap reflowed the hero and header on a
cold cache; measured cold-load layout shift is now zero on all five routes.

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
- The reading controls dock to the bottom right inside a reserved 96px strip,
  so the collapsed dock never covers the footer or a control scrolled into view.
- The header stays on one row at every width: the wordmark descriptor is dropped
  below 1024px before the navigation would wrap.

Verified at 320, 375, 768, 1024, and 1440px in both themes with no
page-level horizontal scrolling, including enlarged text.

## Shared patterns

`Layout.astro` owns the header, footer, navigation, display settings, consent
panel, privacy links, and theme tokens. Route files compose these patterns and
add nothing of their own structure where a shared one exists.

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
| Privacy choice  | `.privacy-consent`, `.privacy-consent-actions`      |

A pattern never repeats its own words next to itself: the contact banner pairs
the "Discuss your use case." heading with the shorter `contact.link` label, and
the product breadcrumb carries the product name so the hero eyebrow carries only
the story label.

Homepage technical sections compose those shared patterns with
composition-only classes in `landing.css`: `.landing-block`, `.landing-points`,
`.landing-list`, `.landing-details`, `.landing-reference-list`,
`.landing-table-wrap`, and `.landing-table`. Prose keeps the 64-character
measure; tables and diagrams take the full shell width. Tables use a
`<caption>`, `scope` on every header cell, and whole-word wrapping, and each one
sits inside `.landing-table-wrap`: a `role="region"` scroll area named by its
caption and reachable with Tab. A narrow viewport therefore scrolls the table
inside that wrapper instead of breaking words mid-word or scrolling the page.
Disclosure rows reserve 1rem on the right because the open marker
rotates 45 degrees, and that painted box would otherwise reach past the row at
narrow widths with enlarged text.

## Visuals and interaction

- Use selectable SQL, synthetic wireless indicators and supporting
  observations, ranking explanations, and labelled workflow diagrams. Every
  synthetic dataset is visibly labelled, and illustrative paths are not shown
  as production interfaces.
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

Theme, text size, line width, text spacing, and movement are reader settings.
They persist in local storage only while “Save these settings in this browser”
is enabled; disabling it clears saved values and keeps current choices in
memory. Theme changes apply immediately so text never crosses an intermediate
contrast state. All settings
are offered in the same position on every route: one compact row docked to the
bottom right of the viewport, opening upward into a two-column card that stays
inside the viewport at every reader text size. Escape or a press outside closes
the card and Escape returns focus to its toggle. Settings are progressive
enhancement: browser zoom, text sizing, and custom styles keep working without
JavaScript.

## Privacy controls

When a production GA4 measurement ID is configured, the consent panel appears
until the reader accepts or rejects analytics. Acceptance and rejection have
equal button styling. The footer keeps a permanent privacy notice link and a
control to reopen the choice. Analytics remains off until affirmative consent.

## Changing the system

1. Change the token or pattern in `site.css`. Do not patch a route to work
   around a token.
2. If a new token is introduced, add it to the contrast test's token list.
3. Run `npm run build`, `npm test`, and `npm run review`, then record the
   outcome in [validation results](validation-results.md).
4. Update this file and [the messaging framework](messaging.md) when the change
   affects the palette, type scale, geometry, or pattern inventory.
