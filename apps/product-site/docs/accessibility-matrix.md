# WCAG 2.2 evidence matrix

Scope: all five public routes and every synthetic demo/display setting state.
Target: all applicable A, AA, and AAA criteria. No conformance claim is made.
This includes all 86 current success criteria; 4.1.1 Parsing was removed in 2.2.

Scope also includes the shared visual system recorded in
[the design system](design-system.md). Contrast evidence below separates token
calculation from rendered combinations.

Evidence keys: **AUTO** refers to assertions in [browser tests](../tests/site.spec.ts);
**CODE** refers to implemented semantics/content/styles; **MANUAL** means a human
evaluation is still pending, even where automated evidence exists. **N/A** is a
reasoned proposal to be confirmed in the final scoped review. Implementation
evidence alone is never a passed conformance result.

| Criterion                                       | Level | Evidence and remaining evaluation                                                                                                                                                           |
| ----------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.1.1 Non-text Content                          | A     | CODE: SVG titles, descriptions, visible captions; MANUAL: screen reader alternatives                                                                                                        |
| 1.2.1 Audio-only and Video-only                 | A     | N/A: no audio/video media                                                                                                                                                                   |
| 1.2.2 Captions (Prerecorded)                    | A     | N/A: no prerecorded media                                                                                                                                                                   |
| 1.2.3 Audio Description or Media Alternative    | A     | N/A: no prerecorded video                                                                                                                                                                   |
| 1.2.4 Captions (Live)                           | AA    | N/A: no live media                                                                                                                                                                          |
| 1.2.5 Audio Description (Prerecorded)           | AA    | N/A: no video                                                                                                                                                                               |
| 1.2.6 Sign Language (Prerecorded)               | AAA   | N/A: no audio media                                                                                                                                                                         |
| 1.2.7 Extended Audio Description                | AAA   | N/A: no video                                                                                                                                                                               |
| 1.2.8 Media Alternative (Prerecorded)           | AAA   | N/A: no time-based media                                                                                                                                                                    |
| 1.2.9 Audio-only (Live)                         | AAA   | N/A: no live audio                                                                                                                                                                          |
| 1.3.1 Info and Relationships                    | A     | AUTO: axe; CODE: headings, labels, lists, definitions, table captions and scope, groups; MANUAL: assistive-technology structure                                                             |
| 1.3.2 Meaningful Sequence                       | A     | CODE: document order matches reading order; MANUAL: CSS-off and screen reader                                                                                                               |
| 1.3.3 Sensory Characteristics                   | A     | CODE: named steps, labels, text captions; MANUAL: instructions review                                                                                                                       |
| 1.3.4 Orientation                               | AA    | CODE: no orientation lock; MANUAL: portrait/landscape devices                                                                                                                               |
| 1.3.5 Identify Input Purpose                    | AA    | N/A: no collection of user personal data; display/query controls are not personal fields                                                                                                    |
| 1.3.6 Identify Purpose                          | AAA   | CODE: semantic landmarks, native controls, product labels; MANUAL: purpose/personalization review                                                                                           |
| 1.4.1 Use of Color                              | A     | CODE: product names and pressed/text states accompany color; MANUAL: monochrome review                                                                                                      |
| 1.4.2 Audio Control                             | A     | N/A: no audio                                                                                                                                                                               |
| 1.4.3 Contrast (Minimum)                        | AA    | AUTO: axe, token pairs, and a rendered walk of every text node with composited backgrounds in both themes; MANUAL: forced-colors rendering and reader review                                |
| 1.4.4 Resize Text                               | AA    | AUTO: 200% root text resizing; MANUAL: browser text-only resize                                                                                                                             |
| 1.4.5 Images of Text                            | AA    | CODE: core story and diagrams use readable HTML/SVG text; MANUAL: image use review                                                                                                          |
| 1.4.6 Contrast (Enhanced)                       | AAA   | AUTO: token pairs >= 7:1 and rendered text >= 7:1 normal / 4.5:1 large on every route and theme; MANUAL: review of the rendered result and forced colors                                    |
| 1.4.7 Low or No Background Audio                | AAA   | N/A: no audio                                                                                                                                                                               |
| 1.4.8 Visual Presentation                       | AAA   | CODE: theme, width <= 80ch, size/spacing controls, left-aligned prose; AUTO: settings persist/reflow; MANUAL: full presentation requirements and user styling                               |
| 1.4.9 Images of Text (No Exception)             | AAA   | CODE: HTML text; social card is supplementary with matching text alternative; MANUAL: logo/social exemption review                                                                          |
| 1.4.10 Reflow                                   | AA    | AUTO: 320px width on all routes; MANUAL: true 400% browser zoom                                                                                                                             |
| 1.4.11 Non-text Contrast                        | AA    | AUTO: rendered control boundaries and focus rings >= 3:1 in both themes; CODE: rule/focus tokens, forced colors; MANUAL: decorative rules, diagrams, and forced colors                      |
| 1.4.12 Text Spacing                             | AA    | AUTO: WCAG spacing overrides with no horizontal overflow; MANUAL: no loss or clipped content                                                                                                |
| 1.4.13 Content on Hover or Focus                | AA    | N/A: no custom tooltips or hover/focus popovers                                                                                                                                             |
| 2.1.1 Keyboard                                  | A     | AUTO: every tabbable control focusable and ringed, document-order traversal with no skipped control, sample-site selector, indicator details, migration buttons, skip link; MANUAL: complete route/control walkthrough |
| 2.1.2 No Keyboard Trap                          | A     | CODE: native controls, no focus trap; MANUAL: traverse all controls                                                                                                                         |
| 2.1.3 Keyboard (No Exception)                   | AAA   | CODE: no path-dependent interaction; MANUAL: all functionality                                                                                                                              |
| 2.1.4 Character Key Shortcuts                   | A     | N/A: no custom character shortcuts                                                                                                                                                          |
| 2.2.1 Timing Adjustable                         | A     | N/A: no site time limits                                                                                                                                                                    |
| 2.2.2 Pause, Stop, Hide                         | A     | N/A: no automatic moving/updating content                                                                                                                                                   |
| 2.2.3 No Timing                                 | AAA   | CODE: all demos advance only on user input; MANUAL: no time-dependent actions                                                                                                               |
| 2.2.4 Interruptions                             | AAA   | N/A: no unsolicited interruptions                                                                                                                                                           |
| 2.2.5 Re-authenticating                         | AAA   | N/A: no authentication/session                                                                                                                                                              |
| 2.2.6 Timeouts                                  | AAA   | N/A: no inactivity timeout or user-entered data loss                                                                                                                                        |
| 2.3.1 Three Flashes or Below Threshold          | A     | N/A: no flashing content                                                                                                                                                                    |
| 2.3.2 Three Flashes                             | AAA   | N/A: no flashing content                                                                                                                                                                    |
| 2.3.3 Animation from Interactions               | AAA   | CODE: brief color transitions; system and user reduced-motion support; AUTO: reduced-motion state; MANUAL: motion inspection                                                                |
| 2.4.1 Bypass Blocks                             | A     | AUTO: skip link focuses main; CODE: landmarks                                                                                                                                               |
| 2.4.2 Page Titled                               | A     | CODE: route-specific titles; AUTO: metadata; MANUAL: title usefulness                                                                                                                       |
| 2.4.3 Focus Order                               | A     | CODE: source order, no positive tabindex; MANUAL: whole-site focus order                                                                                                                    |
| 2.4.4 Link Purpose (In Context)                 | A     | AUTO: axe; CODE: descriptive links; MANUAL: purpose review                                                                                                                                  |
| 2.4.5 Multiple Ways                             | AA    | CODE: navigation/footer and hub product links; MANUAL: route discoverability                                                                                                                |
| 2.4.6 Headings and Labels                       | AA    | AUTO: one h1, axe; CODE: modelled section titles and capability-led product headings; MANUAL: heading/label clarity                                                                         |
| 2.4.7 Focus Visible                             | AA    | AUTO: every tabbable control on every route shows a >= 2px outline at >= 3:1 in both themes; MANUAL: reading the ring while navigating                                                      |
| 2.4.8 Location                                  | AAA   | CODE: product breadcrumbs, current navigation, route headings; MANUAL: location clarity                                                                                                     |
| 2.4.9 Link Purpose (Link Only)                  | AAA   | CODE: named product/action links; MANUAL: isolated link list                                                                                                                                |
| 2.4.10 Section Headings                         | AAA   | CODE: content sections have headings; MANUAL: coverage review                                                                                                                               |
| 2.4.11 Focus Not Obscured (Minimum)             | AA    | CODE: sticky header; landing sections and playground use scroll margins; MANUAL: focus scrolling at zoom under the header                                                                   |
| 2.4.12 Focus Not Obscured (Enhanced)            | AAA   | CODE: scroll margins; MANUAL: complete control visibility                                                                                                                                   |
| 2.4.13 Focus Appearance                         | AAA   | AUTO: outline geometry, offset, and 3:1 contrast on every tabbable control in both themes; MANUAL: geometry judgement and forced colors                                                     |
| 2.5.1 Pointer Gestures                          | A     | N/A: no multipoint or path gestures                                                                                                                                                         |
| 2.5.2 Pointer Cancellation                      | A     | CODE: native click activation, no down-event handlers; MANUAL: cancel pointer actions                                                                                                       |
| 2.5.3 Label in Name                             | A     | AUTO: axe; CODE: visible native labels; MANUAL: speech control                                                                                                                              |
| 2.5.4 Motion Actuation                          | A     | N/A: no device-motion actions                                                                                                                                                               |
| 2.5.5 Target Size (Enhanced)                    | AAA   | CODE: controls and navigation aim for 44x44 CSS px; MANUAL: all controls including details and text-link exceptions                                                                         |
| 2.5.6 Concurrent Input Mechanisms               | AAA   | CODE: no device restriction; MANUAL: touch/keyboard/pointer switching                                                                                                                       |
| 2.5.7 Dragging Movements                        | AA    | N/A: no drag interactions                                                                                                                                                                   |
| 2.5.8 Target Size (Minimum)                     | AA    | CODE: enhanced target sizing; MANUAL: geometry and permitted inline exceptions                                                                                                              |
| 3.1.1 Language of Page                          | A     | AUTO: axe; CODE: html lang=en                                                                                                                                                               |
| 3.1.2 Language of Parts                         | AA    | N/A: no natural-language passages in another language; proper names/code excluded                                                                                                           |
| 3.1.3 Unusual Words                             | AAA   | CODE: product glossaries and plain summaries; MANUAL: participant comprehension review                                                                                                      |
| 3.1.4 Abbreviations                             | AAA   | CODE: SQL, ETL expanded; SVG access-point abbreviation described; MANUAL: all rendered content audit                                                                                        |
| 3.1.5 Reading Level                             | AAA   | CODE: plain summaries supplement technical details; MANUAL: reading-level and participant evaluation                                                                                        |
| 3.1.6 Pronunciation                             | AAA   | N/A proposed: no pronunciation-dependent meaning; MANUAL: specialist vocabulary review                                                                                                      |
| 3.2.1 On Focus                                  | A     | CODE: no focus-driven changes; MANUAL: focus traversal                                                                                                                                      |
| 3.2.2 On Input                                  | A     | CODE: sample changes only nearby results, never navigates; AUTO: query/step changes                                                                                                         |
| 3.2.3 Consistent Navigation                     | AA    | CODE: shared layout; AUTO: navigation available all routes                                                                                                                                  |
| 3.2.4 Consistent Identification                 | AA    | CODE: shared names and controls; MANUAL: consistency review                                                                                                                                 |
| 3.2.5 Change on Request                         | AAA   | CODE: demos, settings, navigation only by user action; MANUAL: context behavior                                                                                                             |
| 3.2.6 Consistent Help                           | A     | CODE: footer contact and email address on all routes; MANUAL: help placement                                                                                                                |
| 3.3.1 Error Identification                      | A     | CODE: clipboard failure status; AUTO: failure path; N/A: no submission/validation form                                                                                                      |
| 3.3.2 Labels or Instructions                    | A     | CODE: labeled controls and demo steps; AUTO: axe; MANUAL: instructions clarity                                                                                                              |
| 3.3.3 Error Suggestion                          | AA    | CODE: manual-copy suggestion on failure; AUTO: failure path                                                                                                                                 |
| 3.3.4 Error Prevention (Legal, Financial, Data) | AA    | N/A: site submits no data and executes no production operations                                                                                                                             |
| 3.3.5 Help                                      | AAA   | CODE: step explanations, glossary, contact; MANUAL: contextual help usefulness                                                                                                              |
| 3.3.6 Error Prevention (All)                    | AAA   | N/A: no on-site information submission; mailto is a disclosed external handoff                                                                                                              |
| 3.3.7 Redundant Entry                           | A     | N/A: no multistep user information entry                                                                                                                                                    |
| 3.3.8 Accessible Authentication (Minimum)       | AA    | N/A: no authentication                                                                                                                                                                      |
| 3.3.9 Accessible Authentication (Enhanced)      | AAA   | N/A: no authentication                                                                                                                                                                      |
| 4.1.2 Name, Role, Value                         | A     | AUTO: axe, pressed states; CODE: native controls; MANUAL: both screen-reader combinations                                                                                                   |
| 4.1.3 Status Messages                           | AA    | CODE: polite sample/run updates and copy status; AUTO: status content; MANUAL: announcement timing and usefulness                                                                           |

## Evidence record

The shared-system revision consolidates colour, header, typography, spacing, and
control rules into one stylesheet that all five routes use. Automated checks
compare tokens, header geometry, reading-settings placement, heading type, and
control styling across every route in both themes, and confirm each product demo
appears once in its hero proof column. Both product pages use a split hero, an
openly presented pair of audience propositions, a labelled input/process/output
diagram, and a caveat panel beside the qualified content.

Contrast evidence is now split into three layers rather than two. Token pairs are
calculated; a rendered walk composites every ancestor background, including alpha
and colour mixes, and asserts 7:1 for normal text, 4.5:1 for large text, and 3:1
for control boundaries; axe covers the same routes in both themes with every
disclosure open and every demo state active. Both caveats, the contact labels, and
the audience statements ship from the content model, so a copy edit cannot drop or
duplicate a statement that a criterion depends on. Forced-colors rendering,
screen readers, and participant sessions remain manual.

The landing-page redesign adds a labeled observation filter, pressed-state product
selectors, a result-count status, and four user-controlled migration steps in
[LandingPlayground](../src/components/LandingPlayground.tsx). The
[browser tests](../tests/site.spec.ts) cover initial selection, filtering, empty
results, keyboard selection, and both themes at 320 through 1440 CSS pixels.
Screen-reader and participant evaluation remain pending.

The homepage technical sections add four model-driven sections built from
`homeSections`: a migration review guide, a six-term reference, two workflow
comparisons, and a Search benchmark. They introduce data tables with captions
and scoped headers, native disclosures, and an SVG review-path diagram with a
title, description, and visible caption. Each data table sits inside a
`role="region"` scroll wrapper named by its caption and reachable with Tab, so
at 320px the table scrolls inside its own region with whole words instead of
scrolling the page. The browser tests assert the homepage
title, description, single H1, `Organization`/`WebSite` identity markup, one
heading per section, and the four calls to action, alongside the existing axe,
contrast, reflow, and tab-traversal checks in both themes. Walkthroughs of the
tables and disclosures with a screen reader remain pending.

The latest layout revision adds persistent navigation, a native mobile menu,
in-page product sample links, and equal-height preview panels. Inactive panels
are inert and hidden from assistive technology. Automated checks cover header
position after scrolling, product switching without route or height changes,
and mobile menu dismissal. Scroll and reveal movement respect reduced-motion
settings; content remains visible without JavaScript.

Build/test outcomes and local screenshots are recorded in
[validation results](validation-results.md). Pending manual tasks and release
conditions are in the [release checklist](release-checklist.md). Any new feature,
route, content format, or external service requires re-evaluating applicability.

Standard: [WCAG 2.2](https://www.w3.org/TR/WCAG22/).
