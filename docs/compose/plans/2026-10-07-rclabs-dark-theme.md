# RCLabs Dark Theme Gap-Close and Verification Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining dark-only documentation gaps and produce verified accessibility evidence for the already-applied RCLabs dark/green theme across all four UIs.

**Architecture:** Theme tokens, dark locks, and UI removals are already present as uncommitted changes in the working tree. This plan only (1) fixes two stale light-theme documentation references, (2) confirms the three untracked theme files are wired into their consumers, and (3) runs every verification command in the brief, fixing real failures if they appear.

**Tech Stack:** Astro/SolidJS (product-site), SolidJS/Vite (atheros-search-ui), React/Vite/Electron (schema-migrator-ui), Keycloak FreeMarker theme + Playwright fixtures, Playwright/Vitest, Python docs checker.

## Global Constraints

- Palette is exactly: page `#090909`, surface `#141414`, raised `#1C1C1C`, primary text `#F5F5F2`, secondary text `#BEC2B9`, brand accent `#A3E6A3`.
- Dark is the only theme. No light or system theme choices, no `prefers-color-scheme` palette switches, no saved-theme restore paths.
- Public site reading preferences other than theme (text size, line width, text spacing, movement, opt-in persistence) stay available.
- Warning, error and informational colours stay distinct and legible; green must not replace their meanings.
- Contrast targets: normal text 7:1, large text 4.5:1, applicable control boundaries and focus indicators 3:1.
- Layouts, copy, data meanings and API contracts are unchanged.
- No WCAG conformance claim beyond collected evidence. Manual AT/zoom/forced-colors entries stay pending in `docs/rclabs-theme.md`.
- Do not commit or open a PR unless the user explicitly asks. Do not mutate Kubernetes or GitOps state interactively.
- Prefer `rg` for search. Keep changes ASCII. Do not edit generated output (`dist/`, `target/`, `node_modules/`).
- Root `AGENTS.md` and `apps/product-site/AGENTS.md` already encode product-site and theme rules; do not duplicate them.

## File Structure

| Path | Responsibility |
| --- | --- |
| `docs/compose/specs/2026-10-07-rclabs-dark-theme-design.md` | Spec for this change set |
| `docs/rclabs-theme.md` | Shared theme contract and evidence log (already written, untracked) |
| `apps/product-site/docs/validation-results.md` | Product-site local validation record (stale light wording) |
| `apps/schema-migrator/codex/skills/schema-migrator-ui-quality/references/wcag-22-aa-codex.md` | Migrator UI quality rules (stale light wording) |
| `apps/product-site/src/styles/site.css` | Public-site tokens (already aligned) |
| `apps/integration-console/atheros-search-ui/src/styles/tokens.css` | Search UI tokens (already aligned) |
| `apps/schema-migrator/schema-migrator-ui/src/design/tokens.ts` | Migrator tokens (already aligned) |
| `cyber-stack/base/schema-migrator/configmaps/keycloak-theme/login/resources/css/custom-login.css` | Keycloak theme (already aligned) |

---

### Task 1: Fix stale light-theme documentation

**Covers:** [S5], [S8]

**Files:**
- Modify: `apps/product-site/docs/validation-results.md:3-4`, `:10-16`, `:25-30`
- Modify: `apps/schema-migrator/codex/skills/schema-migrator-ui-quality/references/wcag-22-aa-codex.md:81-87`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: documentation that describes dark-only theme; later docs-check task validates these files.

- [ ] **Step 1: Update product-site validation results**

Replace the light-theme language and the stale "passed on October 7" claims with dark-only wording and pending status (verification runs in later tasks). The file must end up describing the shared dark theme only.

Apply this exact content to `apps/product-site/docs/validation-results.md`:

```markdown
# Local validation results

This record covers the three-product redesign: the shared RCLabs dark/green
visual system, the `/products/` catalogue, RCLabs VPN / Proxy, and natural-height
demos and disclosures. It replaces earlier two-product layout notes. No
accessibility conformance claim is made.

## Automated checks

Re-run these after every theme or layout change and replace the dated entries
with new evidence:

- `npm run build`: eight static routes and zero diagnostics.
- `npm test`: Chromium checks covering rendered content, the shared dark theme
  (including saved light/system values and system colour preferences being
  ignored), product switching, all three synthetic samples, focus, contrast,
  responsive reflow, and link destinations.
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
```

- [ ] **Step 2: Update Migrator WCAG rule wording**

In `apps/schema-migrator/codex/skills/schema-migrator-ui-quality/references/wcag-22-aa-codex.md`, replace the CONTRAST_AA_01 validation line:

From:
```
Keep token contrast tests current for light and dark themes.
```

To:
```
Keep token contrast tests current for the shared dark-only theme.
```

- [ ] **Step 3: Confirm no remaining light-theme guidance**

Run:
```bash
rg -n -i 'both themes|light and dark|light theme|dark and light' \
  apps/product-site apps/schema-migrator apps/integration-console/atheros-search-ui \
  cyber-stack/base/schema-migrator/configmaps/keycloak-theme docs
```

Expected: only negative assertions (tests that saved light/system values are ignored) and intentional phrases such as product-site `landing.css` "tint stays light". No instructional "check both themes" wording.

- [ ] **Step 4: Stage nothing; leave the working tree dirty for verification**

Do not commit. Later verification tasks need the same tree.

---

### Task 2: Verify untracked theme files are wired

**Covers:** [S3], [S4], [S8]

**Files:**
- Confirm: `docs/rclabs-theme.md`
- Confirm: `apps/schema-migrator/schema-migrator-ui/src/design/sqlHighlightTheme.ts`
- Confirm: `apps/integration-console/atheros-search-ui/tests/e2e/theme.spec.ts`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: confidence that later build/test commands actually exercise these files.

- [ ] **Step 1: Confirm `sqlHighlightTheme.ts` is imported**

Run:
```bash
rg -n 'sqlHighlightTheme|rclabs-dark' apps/schema-migrator/schema-migrator-ui/src
```

Expected: `SqlPreviewPane.tsx` (or similar) imports `sqlHighlightTheme.ts` and registers the `rclabs-dark` shiki theme. If not imported, the file is dead code — wire it into the SQL preview theme selection the same way the previous stock theme was chosen.

- [ ] **Step 2: Confirm `theme.spec.ts` is in the Playwright suite**

Run:
```bash
rg -n 'testDir|testMatch|theme' apps/integration-console/atheros-search-ui/playwright.config.ts apps/integration-console/atheros-search-ui/package.json
```

Expected: `playwright.config.ts` uses `tests/e2e` (or equivalent) so `theme.spec.ts` is collected by `npm run test:e2e`. If the config lists files explicitly, add `theme.spec.ts`.

- [ ] **Step 3: Confirm `docs/rclabs-theme.md` cross-references resolve**

Run:
```bash
python3 scripts/check-docs.py
```

Expected: PASS, including the untracked `docs/rclabs-theme.md`. If check-docs only scans tracked files, `git add docs/rclabs-theme.md` (intent-to-add is fine) and re-run.

---

### Task 3: Verify product-site build, browser tests, and visual review

**Covers:** [S2], [S3], [S5], [S6], [S7]

**Files:**
- Observe only: `apps/product-site/**` (already themed)

**Interfaces:**
- Consumes: themed working tree.
- Produces: build/test/review evidence for the evidence report.

- [ ] **Step 1: Build the product site**

Run:
```bash
cd apps/product-site && npm run build
```

Expected: success, eight routes, zero diagnostics.

- [ ] **Step 2: Run browser tests**

Run:
```bash
cd apps/product-site && npm test
```

Expected: all Playwright checks pass. Failures about contrast, theme switching, or missing `data-theme="dark"` are real bugs — fix the token or markup, not the assertion, unless the assertion contradicts the brief.

- [ ] **Step 3: Run visual review**

Run:
```bash
cd apps/product-site && npm run review
```

Expected: completes and writes local screenshots under the script's output directory. Inspect at least the homepage, `/products/`, and one product demo for dark-only rendering, green primary actions, and legible error/warning/info states.

- [ ] **Step 4: Record evidence**

Append a short dated entry to `docs/compose/reports/2026-10-07-rclabs-dark-theme-evidence.md` with the three command results and any fixes made.

---

### Task 4: Verify Atheros Search UI

**Covers:** [S2], [S3], [S5], [S6], [S7]

**Files:**
- Observe/fix only as needed: `apps/integration-console/atheros-search-ui/**`

**Interfaces:**
- Consumes: themed working tree.
- Produces: `make atheros-search-ui-check` and e2e evidence.

- [ ] **Step 1: Run the make check**

Run:
```bash
make atheros-search-ui-check
```

Expected: vitest unit + `tsc --noEmit` + `vite build` all pass.

- [ ] **Step 2: Run e2e theme and a11y suites**

Run:
```bash
cd apps/integration-console/atheros-search-ui && npm run test:e2e
```

Expected: `theme.spec.ts`, `a11y.spec.ts`, and `graph-presentation.spec.ts` pass. Dark must hold under saved `theme=light` and system light. Graph/report states must stay legible.

If e2e is too heavy or blocked (no browsers), run the theme spec alone and record the blocker:
```bash
cd apps/integration-console/atheros-search-ui && npx playwright test tests/e2e/theme.spec.ts
```

- [ ] **Step 3: Record evidence**

Append results to `docs/compose/reports/2026-10-07-rclabs-dark-theme-evidence.md`.

---

### Task 5: Verify Schema Migrator web and desktop

**Covers:** [S2], [S3], [S4], [S5], [S6], [S7]

**Files:**
- Observe/fix only as needed: `apps/schema-migrator/schema-migrator-ui/**`

**Interfaces:**
- Consumes: themed working tree including `sqlHighlightTheme.ts`.
- Produces: build/test/electron evidence.

- [ ] **Step 1: Build the Migrator UI**

Run:
```bash
cd apps/schema-migrator/schema-migrator-ui && npm run build
```

Expected: Vite build succeeds.

- [ ] **Step 2: Run unit tests**

Run:
```bash
cd apps/schema-migrator/schema-migrator-ui && npm test
```

Expected: `tokens.test.ts`, `accessibilityCodex.test.ts`, and `SettingsPage.test.tsx` pass. Failures about palette values or dark-lock assertions are real bugs.

- [ ] **Step 3: Build Electron main**

Run:
```bash
cd apps/schema-migrator/schema-migrator-ui && npm run electron:build-main
```

Expected: compiles; `nativeTheme.themeSource = "dark"` and window `backgroundColor: "#090909"` remain in `electron/main.ts`.

- [ ] **Step 4: Record evidence**

Append results to `docs/compose/reports/2026-10-07-rclabs-dark-theme-evidence.md`.

---

### Task 6: Verify Keycloak theme and documentation

**Covers:** [S3], [S5], [S6], [S7], [S8]

**Files:**
- Observe/fix only as needed: `scripts/tests/keycloak-theme/**`, `cyber-stack/base/schema-migrator/configmaps/keycloak-theme/**`

**Interfaces:**
- Consumes: themed Keycloak CSS and fixtures.
- Produces: login-suite and docs-check evidence; closes Task 1/2 validation.

- [ ] **Step 1: Run the Keycloak Playwright suite**

Run:
```bash
cd scripts/tests/keycloak-theme && npm test
```

Expected: normal and error fixtures pass at all listed widths; contrast, target size, keyboard, reduced-motion, and forced-colours assertions pass; alert colours stay distinct.

- [ ] **Step 2: Run the repository docs check**

Run:
```bash
python3 scripts/check-docs.py
```

Expected: PASS. Fix any broken cross-reference introduced by Task 1.

- [ ] **Step 3: Re-run the light-theme wording sweep**

Run:
```bash
rg -n -i 'both themes|light and dark|light theme|dark and light' \
  apps docs cyber-stack scripts
```

Expected: no instructional light-theme guidance remains.

- [ ] **Step 4: Finalize the evidence report**

Write `docs/compose/reports/2026-10-07-rclabs-dark-theme-evidence.md` with:
- One table row per surface: command, result (pass/fail), timestamp.
- List of code/doc fixes made during verification.
- Explicit statement that manual keyboard, screen-reader, zoom, touch/switch/voice and Windows High Contrast evaluation remain **pending**.
- Explicit statement: no WCAG conformance claim.

---

## Self-Review Notes

- Spec coverage: S1 problem is background; S2–S7 covered by Tasks 3–6 verification; S5 behaviour rules asserted by those suites; S8 gaps covered by Tasks 1–2; S9 out of scope holds (no commits, no cluster mutation).
- Placeholders: none; each step has exact paths, commands, and expected outcomes.
- Type consistency: no new code interfaces; tasks are documentation edits plus verification.
