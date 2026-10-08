# Local validation results

This record covers the three-product redesign: the shared RCLabs dark/green
visual system, the `/products/` catalogue, RCLabs VPN / Proxy, and natural-height
demos and disclosures. It replaces earlier two-product layout notes. No
accessibility conformance claim is made.

## Automated checks

Last run: 2026-10-08. Re-run these after every theme or layout change and replace
the dated entries with new evidence:

- `npm run build`: passed; eight static routes, zero errors, warnings, or hints.
- `npm test`: passed; 39 Chromium tests, with two production analytics tests
  skipped because no production measurement ID is configured.
- `npm run review`: completed all 16 desktop/mobile route captures with no page
  errors. These are local single-run measurements, not field performance data.
- `python3 scripts/check-docs.py`: passed Markdown references and repository
  documentation checks.
- `npm run format:check`: reports formatting warnings in 21 files, including
  existing formatting in files touched for this update; no broad reformatting
  was applied.

The browser suite covers the shared dark theme (including saved light/system
values and system colour preferences being ignored), product switching, all
three synthetic samples, focus, contrast, responsive reflow, and link
destinations. It confirms the display-settings dock is absent while previously
saved display choices still apply.

- [Layout regressions](../tests/layout.spec.ts) expand each disclosure and card
  individually and together at 320, 375, 768, 1024, and 1440px, with enlarged
  text and spacing overrides. They verify containment, no page overflow, and
  that following sections remain below expanded content.
- `python3 scripts/check-docs.py` validates Markdown cross-references from the
  repository root after documentation changes.

## Visual inspection

The shared dark theme should be checked on the homepage, catalogue, and each
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
