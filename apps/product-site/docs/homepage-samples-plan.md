# Homepage samples and editorial rules

The homepage combines three synthetic demos behind a product switcher and
intercepts project links to scroll back into that widget. The owner reports
that this presentation is confusing and does not work for their visitors.

## Changes

1. Remove the combined homepage playground and its exclusive styles. Keep the
   project catalogue and direct links to each dedicated sample. Delete link
   interception so destinations work with and without JavaScript.
2. Keep the existing project-page demos, their synthetic labels, caveats,
   keyboard controls and static explanations. Keep Octopus metrics on its page.
3. Use Rafael Cardoso throughout public pages and metadata. Prohibit semicolons
   in public prose through site guidance and a rendered-page regression check.
   Preserve punctuation required by code and SQL examples.
4. Keep employment attribution, implementation decisions, source links,
   regression coverage and verification limits ahead of project samples.
   External portfolio advice cannot establish claims about these projects.

## Verification

The preceding browser run passed 88 tests with two production-only skips.
Update [site tests](../tests/site.spec.ts), [layout tests](../tests/layout.spec.ts)
and [portfolio tests](../tests/portfolio.spec.ts) for direct navigation while
retaining product interactions and accessibility coverage. Run the build,
complete browser suite, formatting and documentation checks. Inspect desktop
and mobile screenshots using the [review script](../scripts/review.mjs).

The work stays local and follows the existing reviewed Git publication path.
