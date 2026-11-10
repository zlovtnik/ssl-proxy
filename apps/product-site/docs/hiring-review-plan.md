# Hiring portfolio review

## Scope and order

1. Use the existing browser suite to lock navigation, synthetic demo caveats,
   contact access without JavaScript, and runtime-only operational readings.
2. Remove customer acquisition copy, repeated audience instructions, unsupported
   resume claims and public phone details in the shared content model.
3. Make contact canonical, preserve legacy demo links with permanent redirects,
   and use the same navigation on every page.
4. Correct evidence links, skill mappings and social metadata. Keep the Search
   and Migrator console URLs with a temporary availability notice.
5. Run the build, browser suite, formatting and repository documentation checks.

No benchmark results or personal history will be invented. Backend code,
account billing and repository protection settings are outside this site pass.

## Verification sources

- [Browser coverage](../tests/portfolio.spec.ts)
- [Runtime metrics coverage](../tests/operational-stats.spec.ts)
- [Shared content](../src/data/products.ts)
- [Existing editorial plan](cleanup-plan.md)

## Results, November 10, 2026

The shared copy now addresses hiring and technical review. Contact is canonical
at `/contact/`, with permanent legacy redirects configured for `/demo/`. Existing
contact section IDs remain available. Resume claims use narrower archive, risk
scoring and rollback wording, and link to implementation evidence. The public
phone and unsupported MCP claim were removed. All contact emails use one address.

Octopus and Search expose shared decision notes. The homepage links documented
GitOps delivery and rollback procedures. Octopus debugging topics render without
an audience toggle, and its unused toggle code and CSS were deleted. The social
preview SVG and generated PNG were updated. Hosted Search and Migrator URLs are
retained and labelled temporarily unavailable.

Verification: baseline build and 91 browser tests passed, with two analytics
tests skipped. Final build and static diagnostics passed with zero errors or
warnings. Final Chromium run passed 92 tests, with two production-only analytics
tests skipped. Touched-file formatting, diff whitespace and the repository
documentation checker passed. Desktop/mobile screenshots were captured for home,
contact, Octopus and Search and reviewed for clipping and overflow.

No deployment was performed. Cloudflare HTTP redirect status and legacy fragment
preservation need verification after deployment. Account billing, effective
GitHub merge protection, backend benchmarks, personal career history and a
dedicated PDF resume remain outside this change. Runtime readings remain
runtime-only, with no invented static fallback.
