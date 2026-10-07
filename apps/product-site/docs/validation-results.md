# Local validation results

This record covers the three-product redesign: a black and green visual system,
the `/products/` catalogue, RCLabs VPN / Proxy, and natural-height demos and
disclosures. It replaces earlier two-product layout notes. No accessibility
conformance claim is made.

## Automated checks

- `npm run build` passed on October 7, 2026: eight static routes and zero
  diagnostics.
- `npm test` passed on October 7, 2026: 50 Chromium checks passed and 2
  analytics tests were skipped because no production measurement ID is
  configured. Coverage includes rendered content, both themes, product
  switching, all three synthetic samples, focus, contrast, responsive reflow,
  and link destinations.
- [Layout regressions](../tests/layout.spec.ts) expand each disclosure and card
  individually and together at 320, 375, 768, 1024, and 1440px, with enlarged
  text and spacing overrides. They verify containment, no page overflow, and
  that following sections remain below expanded content.
- `python3 scripts/check-docs.py` passed on October 7, 2026, validating
  Markdown cross-references from the repository root after documentation
  changes.

## Visual inspection

Dark and light themes should be checked on the homepage, catalogue, and each
product sample. The expected layout is a short intro beside a workflow outline,
followed by a full-width demo in normal document flow. The homepage playground
shows one selected product at a time; inactive panels are hidden and inert.

## Manual work still required

- Test VoiceOver/Safari and NVDA/Firefox.
- Inspect true 400% browser zoom and forced-colours mode.
- Run usability sessions with disabled participants.
- Build with `PUBLIC_SITE_URL=https://rclabs.uk` and inspect the deployment
  preview before publication.

The detailed evaluation scope remains in the
[accessibility matrix](accessibility-matrix.md) and
[release checklist](release-checklist.md).
