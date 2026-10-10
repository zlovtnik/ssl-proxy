# WCAG 2.2 evidence matrix

Scope: the four public product stories and guide routes, the shared dark theme, product catalogue, and all three
synthetic samples. The site targets
applicable WCAG 2.2 A, AA, and AAA criteria. It makes no conformance claim.

**AUTO** is covered by the browser suite. **CODE** is implementation evidence.
**MANUAL** still needs human evaluation. Automated and code evidence are not a
substitute for assistive-technology or participant testing.

| Area | Evidence | Remaining evaluation |
| --- | --- | --- |
| Structure and language | AUTO: one H1 per route, landmarks, labels, and rendered text checks. CODE: semantic headings, native controls, lists, tables, and `lang=en`. | MANUAL: screen-reader heading, table, and diagram review. |
| Keyboard and focus | AUTO: interactive controls receive a green focus ring at least 2px wide and 3:1 against its surrounding surface; demo, disclosure, mobile navigation, and copy controls are exercised. CODE: native buttons, links, selects, and details stay in document order. | MANUAL: complete keyboard walkthrough at browser zoom, including focus visibility and obstruction. |
| Reflow and text spacing | AUTO: 320-1440px layouts, 200% text, spacing overrides, expansion, and panel containment. CODE: visible panels use normal document flow and inactive panels are hidden and inert. | MANUAL: true 400% zoom and platform text scaling. |
| Colour and appearance | AUTO: 7:1 normal text, 4.5:1 large text, and 3:1 applicable boundary and focus checks in the shared dark theme; saved light/system values and both system colour preferences preserve dark. CODE: labels, icons, and pressed state identify selections beyond colour. | MANUAL: forced-colours rendering and visual review on target displays. |
| Controls and motion | AUTO: target-size and state checks for visible controls. CODE: 44px controls, reduced-motion support, no time limits, no drag or path gestures. | MANUAL: touch, switch, voice, and motion-preference evaluation. |
| Content and status | CODE: synthetic labels, visible caveats, glossary definitions, and polite status messages. | MANUAL: clarity and announcement timing with VoiceOver/Safari and NVDA/Firefox. |
| Non-text content | CODE: labelled diagrams and decorative SVGs hidden from the accessibility tree. | MANUAL: equivalent-text usefulness. |
| Operational evidence | CODE: semantic metric definitions, distinct feed status text, a polite status announcement, separate UTC reading/history timestamps, and a native methodology disclosure. Missing or expired snapshots show a compact explanation and workflow link. No-JavaScript output has no measurements and retains that link. Regression tests cover refresh, stale data, failure, and recovery. | MANUAL: screen-reader interpretation of periods, partial weeks, and update announcements. |
| Octopus UX islands | CODE: labelled pipeline and audience controls; inactive audience content uses `hidden`, `inert`, and `aria-hidden`; decorative motif and status dot stay hidden from assistive technology. Metrics have no count-up animation. Layout tests cover 320-1440px and 200% text. | MANUAL: keyboard order, forced-colours, switch access, and announcement timing. |

## Current automated coverage

The browser suite covers all routes in the shared dark theme, all three sample workflows,
expanded disclosures, catalogue cards, and responsive widths. Layout regression
tests specifically confirm that expanding cards and details preserves
containment and keeps subsequent sections below the expanded content. It also
confirms the display-settings dock is absent and previously saved display choices
remain supported. See
[browser tests](../tests/site.spec.ts) and
[layout regressions](../tests/layout.spec.ts).

## Pending evaluation

- VoiceOver with Safari and NVDA with Firefox.
- Keyboard, zoom, forced-colours, and touch walkthroughs on supported devices.
- Usability sessions with disabled participants.
- A full criterion-by-criterion applicability review before any conformance
  statement.

Release conditions are tracked in the [release checklist](release-checklist.md).
Design and implementation patterns are documented in the
[design system](design-system.md).
