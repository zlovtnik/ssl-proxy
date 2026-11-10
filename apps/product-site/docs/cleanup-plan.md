# Product site editorial cleanup

The site has accumulated repeated explanations and presentation patterns. This
pass keeps the existing engineering portfolio, routes and technical claims while
making the pages shorter and more direct.

## Behavior to preserve

- Static navigation, contact, resume and product copy without JavaScript.
- Synthetic Search, Migrator and VPN examples, including their caveats.
- Runtime-only Octopus readings, freshness, polling and stored-history handling.
- Keyboard operation, focus contrast, forced colours and reading preferences.
- Source links, employment attribution, guide examples and measurement limits.

The baseline is the [browser suite](../tests/site.spec.ts), including
[layout checks](../tests/layout.spec.ts), [portfolio checks](../tests/portfolio.spec.ts)
and [runtime-metrics checks](../tests/operational-stats.spec.ts).

## Ordered passes

1. Remove dead styles and ornamental numbering, duplicate headings and Octopus
   hero decoration. Keep numbering that conveys an actual ordered process.
2. Replace the homepage's repeated technical chapters with links to the existing
   guides. Retain old section fragments as concise topic links. Keep projects,
   career information, interactive examples and contact paths easy to find.
3. Edit shared copy in [the content model](../src/data/products.ts): use specific
   nouns and verbs, shorten generic invitations, and speak as the named author.
   Review every route, including guides, About, contact and policy pages.
4. Simplify repeated card presentation using the existing shared styles. Do not
   add dependencies, a new design system or backend behavior.
5. Update assertions for deliberately removed presentation while retaining
   interaction, caveat, routing and accessibility coverage. Record browser and
   visual evidence in the existing validation documents.

## Verification

Run the build and complete browser suite before and after edits, check formatting
on touched files, inspect desktop/mobile screenshots across all route types, and
run the repository documentation checker. Review the diff for accidental claim,
metric, contact or behavior changes. No publishing or hosting changes are part
of this pass.

## Completion report

All four cleanup passes are complete. The homepage now introduces the projects
and links to the six technical guides. Product and guide headings name their
subjects; contact copy speaks as Rafael. Project cards have one description.
Decorative numbering, the Octopus hero motif, an unused homepage diagram and
their exclusive styles were deleted. The resume and privacy notice retain their
existing factual content.

Changed files:

- [Content model](../src/data/products.ts): shorter copy, factual card summaries,
  FAQ/contact copy, and removal of unused homepage chapter data.
- [Homepage](../src/pages/index.astro), [About](../src/pages/about/index.astro),
  [contact](../src/pages/contact/index.astro), [accessibility](../src/pages/accessibility/index.astro),
  and [guide index](../src/pages/guides/index.astro): reduced repetition and
  retained navigation, including legacy homepage fragments.
- [ProductCards](../src/components/ProductCards.astro),
  [ProductPage](../src/components/ProductPage.astro),
  [OctopusPage](../src/components/OctopusPage.astro), and
  [ProjectStudies](../src/components/ProjectStudies.astro): simpler presentation.
- [Shared styles](../src/styles/site.css), [homepage styles](../src/styles/landing.css)
  and [Octopus styles](../src/styles/octopus.css): removed unused decoration and
  layouts; preserved shared controls and accessibility preferences.
- [Site tests](../tests/site.spec.ts), [portfolio tests](../tests/portfolio.spec.ts)
  and [review script](../scripts/review.mjs): retained behavior checks, added
  no-JavaScript guide navigation, and extended screenshots to all 19 pages.
- [Messaging](messaging.md), [design system](design-system.md),
  [content evidence](content-evidence.md), [accessibility matrix](accessibility-matrix.md)
  and [validation results](validation-results.md): updated guidance and evidence.

The build, static/type checks, formatting and documentation checks pass.
Browser results: 88 passed, two production-only analytics tests skipped.
The 38 desktop/mobile review runs have no page errors. Remaining limits are
assistive-technology/participant evaluation and backend suites, as recorded in
the validation results. Changes remain local and unpublished.
