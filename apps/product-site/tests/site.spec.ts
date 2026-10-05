import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const routes = [
  '/',
  '/atheros-search/',
  '/schema-migrator/',
  '/demo/',
  '/accessibility/',
];
const tags = [
  'wcag2a',
  'wcag2aa',
  'wcag2aaa',
  'wcag21a',
  'wcag21aa',
  'wcag22aa',
  'best-practice',
];

test('header stays visible and product samples preserve the landing layout', async ({
  page,
}) => {
  await page.goto('/');
  const preview = page.locator('.landing-playground');
  await expect(
    preview.getByRole('button', { name: 'Schema Migrator', exact: true }),
  ).toBeEnabled();
  const initial = await preview.boundingBox();
  for (const product of ['Schema Migrator', 'Atheros Search']) {
    await page.getByRole('link', { name: `Try the ${product} sample` }).click();
    await expect(
      preview.getByRole('button', { name: product, exact: true }),
    ).toHaveAttribute('aria-pressed', 'true');
    expect(new URL(page.url()).pathname).toBe('/');
    expect((await preview.boundingBox())!.height).toBeCloseTo(
      initial!.height,
      0,
    );
  }
  await page
    .getByRole('navigation', { name: 'Main navigation', exact: true })
    .getByRole('link', { name: 'FAQ', exact: true })
    .click();
  await expect
    .poll(async () => (await page.locator('.site-top').boundingBox())!.y)
    .toBe(0);
  await expect(page.locator('#faq')).toBeInViewport();
  await page.setViewportSize({ width: 375, height: 900 });
  await page.getByLabel('Toggle navigation').click();
  await page
    .getByRole('navigation', { name: 'Mobile navigation', exact: true })
    .getByRole('link', { name: 'Products', exact: true })
    .click();
  await expect(page.locator('.mobile-menu')).not.toHaveAttribute('open');
  await expect(page.locator('#products')).toBeInViewport();
});

test('landing preview filters observations and reviews every migration step', async ({
  page,
}) => {
  await page.goto('/');
  const preview = page.locator('.landing-playground');
  await expect(
    preview.getByRole('button', { name: 'Schema Migrator', exact: true }),
  ).toBeEnabled();
  await expect(
    preview.getByRole('button', { name: /Guest device 07/ }),
  ).toHaveAttribute('aria-pressed', 'true');
  await expect(
    preview.getByRole('button', { name: /Proxy event 12/ }),
  ).toHaveAttribute('aria-pressed', 'false');
  await preview.getByLabel('Filter sample observations').fill('proxy');
  await expect(preview.getByRole('status')).toContainText(
    '1 sample observations',
  );
  await preview.getByRole('button', { name: /Proxy event 12/ }).press('Space');
  await expect(preview.locator('.preview-evidence')).toContainText(
    'A shared identifier alone',
  );
  await preview
    .getByLabel('Filter sample observations')
    .fill('no-matching-record');
  await expect(preview.getByRole('status')).toContainText(
    '0 sample observations',
  );
  await expect(preview.locator('.preview-evidence')).toHaveCount(0);
  await preview.getByLabel('Filter sample observations').fill('');
  for (const theme of ['dark', 'light']) {
    await page.evaluate(
      (value) => (document.documentElement.dataset.theme = value),
      theme,
    );
    await preview
      .getByRole('button', { name: 'Atheros Search', exact: true })
      .click();
    expect(
      (await new AxeBuilder({ page }).withTags(tags).analyze()).violations,
    ).toEqual([]);
    await preview
      .getByRole('button', { name: 'Schema Migrator', exact: true })
      .press('Space');
    for (const name of [
      'Inspect SQL',
      'Review validation',
      'Examine plan',
      'Inspect run record',
    ]) {
      const button = preview.getByRole('button', { name, exact: true });
      await button.click();
      await expect(button).toHaveAttribute('aria-pressed', 'true');
      expect(
        (await new AxeBuilder({ page }).withTags(tags).analyze()).violations,
      ).toEqual([]);
      for (const width of [1440, 1024, 768, 375, 320]) {
        await page.setViewportSize({ width, height: 900 });
        expect(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= innerWidth,
          ),
        ).toBe(true);
      }
    }
  }
});

for (const route of routes) {
  for (const theme of ['dark', 'light']) {
    test(`${route}: ${theme} accessibility, reflow, and links`, async ({
      page,
    }) => {
      await page.goto(route);
      await page.locator('#reading-controls > summary').click();
      await page.locator('#setting-theme').selectOption(theme);
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      // Include every expandable explanation in the evaluation.
      await page
        .locator('details')
        .evaluateAll((elements) =>
          elements.forEach(
            (element) => ((element as HTMLDetailsElement).open = true),
          ),
        );
      await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
      const results = await new AxeBuilder({ page }).withTags(tags).analyze();
      expect(results.violations).toEqual([]);
      for (const width of [1440, 768, 375, 320]) {
        await page.setViewportSize({ width, height: 900 });
        expect(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= window.innerWidth,
          ),
        ).toBe(true);
        const targets = await page
          .locator(
            'button, select, summary, header a, footer a, .button, .text-link',
          )
          .evaluateAll((elements) =>
            // Responsive menus and inactive previews are not interactive targets.
            elements
              .filter(
                (element) =>
                  element.checkVisibility() && !element.closest('[inert]'),
              )
              .map((element) => {
                const bounds = element.getBoundingClientRect();
                return {
                  label: element.textContent?.trim(),
                  width: bounds.width,
                  height: bounds.height,
                };
              }),
          );
        for (const target of targets) {
          expect(target.width, target.label).toBeGreaterThanOrEqual(44);
          expect(target.height, target.label).toBeGreaterThanOrEqual(44);
        }
      }
      await page.addStyleTag({
        content:
          '* { line-height: 1.5 !important; letter-spacing: .12em !important; word-spacing: .16em !important; } p { margin-bottom: 2em !important; }',
      });
      await page.locator('#setting-size').selectOption('extra');
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      ).toBe(true);
      const links = await page
        .locator('a[href^="/"]')
        .evaluateAll((elements) => [
          ...new Set(
            elements.map(
              (element) =>
                (element as HTMLAnchorElement)
                  .getAttribute('href')!
                  .split('#')[0],
            ),
          ),
        ]);
      for (const link of links)
        expect((await page.request.get(link)).ok()).toBe(true);
    });
  }
}

test('Search changes sample records and explains both states using a keyboard', async ({
  page,
}) => {
  await page.goto('/atheros-search/');
  const nextQuery = page.getByRole('button', {
    name: 'Try the next sample query',
  });
  await expect(nextQuery).toBeEnabled();
  await nextQuery.focus();
  await page.keyboard.press('Space');
  await expect(
    page.getByRole('heading', { name: 'Proxy event 12' }),
  ).toBeVisible();
  const explanation = page.getByText('3. Open the ranking explanation', {
    exact: true,
  });
  await explanation.focus();
  await page.keyboard.press('Enter');
  await expect(
    page.getByText('The record mentions an API request.', { exact: false }),
  ).toBeVisible();
  await page
    .getByText('4. Inspect observed relationships', { exact: true })
    .click();
  await expect(
    page.getByText('A shared identifier alone', { exact: false }),
  ).toBeVisible();
  await page.getByLabel('1. Choose a sample query').selectOption('0');
  await expect(
    page.getByRole('heading', { name: 'Guest device 07' }),
  ).toBeVisible();
  for (const theme of ['dark', 'light']) {
    await page.evaluate(
      (value) => (document.documentElement.dataset.theme = value),
      theme,
    );
    for (const sample of ['0', '1']) {
      await page.getByLabel('1. Choose a sample query').selectOption(sample);
      expect(
        (await new AxeBuilder({ page }).withTags(tags).analyze()).violations,
      ).toEqual([]);
    }
  }
});

test('Migrator steps are user controlled and accessible in both themes', async ({
  page,
}) => {
  await page.goto('/schema-migrator/');
  const buttons = page
    .getByRole('group', { name: 'Migration review steps' })
    .getByRole('button');
  for (const theme of ['dark', 'light']) {
    await page.evaluate(
      (value) => (document.documentElement.dataset.theme = value),
      theme,
    );
    for (let index = 0; index < 4; index++) {
      await buttons.nth(index).focus();
      await expect(buttons.nth(index)).toBeEnabled();
      await page.keyboard.press('Space');
      await expect(buttons.nth(index)).toHaveAttribute('aria-pressed', 'true');
      expect(
        (await new AxeBuilder({ page }).withTags(tags).analyze()).violations,
      ).toEqual([]);
    }
  }
  await expect(
    page.getByText('Run: sample-run-004', { exact: false }).first(),
  ).toBeVisible();
});

test('email requests have the recipient, product subjects, and honest scheduling copy', async ({
  page,
  context,
  browserName,
}) => {
  if (browserName === 'chromium')
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/demo/');
  // Verify the success handler on engines without automatable clipboard permission.
  if (browserName !== 'chromium')
    await page.evaluate(() =>
      Object.defineProperty(navigator, 'clipboard', {
        value: {
          writeText: async (text: string) => {
            document.body.dataset.copied = text;
          },
        },
      }),
    );
  for (const [id, subject] of [
    ['search', 'Atheros Search'],
    ['migrator', 'Schema Migrator'],
    ['both', 'Atheros Search and Schema Migrator'],
  ]) {
    const href = await page.locator(`#${id} a`).getAttribute('href');
    const url = new URL(href!);
    expect(url.pathname).toBe('rafael@rclabs.uk');
    expect(url.searchParams.get('subject')).toBe(
      `Guided demo request: ${subject}`,
    );
    expect(url.searchParams.get('body')).toContain(
      'Preferred times and time zone:',
    );
  }
  await page.getByRole('button', { name: 'Copy email address' }).click();
  await expect(page.getByRole('status')).toHaveText('Email address copied.');
  expect(
    await page.evaluate(
      (realClipboard) =>
        realClipboard
          ? navigator.clipboard.readText()
          : document.body.dataset.copied,
      browserName === 'chromium',
    ),
  ).toBe('rafael@rclabs.uk');
  await expect(
    page.getByText('We will agree on the details', { exact: false }),
  ).toBeVisible();
});

test('clipboard failure gives a usable fallback', async ({ page }) => {
  await page.goto('/demo/');
  await page.evaluate(() =>
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: () => Promise.reject(new Error('Unavailable')) },
    }),
  );
  await page.getByRole('button', { name: 'Copy email address' }).click();
  await expect(page.getByRole('status')).toContainText(
    'Select the visible address',
  );
});

test('core story, navigation, contact and text demos work without JavaScript', async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  for (const route of routes) {
    await page.goto(`http://127.0.0.1:4323${route}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(
      page.getByRole('navigation', { name: 'Main navigation' }),
    ).toBeVisible();
    expect(await page.locator('a[href^="mailto:"]').count()).toBeGreaterThan(0);
  }
  await page.goto('http://127.0.0.1:4323/schema-migrator/');
  await page.getByText('Read all steps as text', { exact: true }).click();
  await expect(
    page.getByText('Run: sample-run-004', { exact: false }).last(),
  ).toBeVisible();
  await page.goto('http://127.0.0.1:4323/atheros-search/');
  await page
    .getByText('3. Open the ranking explanation', { exact: true })
    .click();
  await expect(
    page.getByText('No measured relevance score', { exact: false }),
  ).toBeVisible();
  await context.close();
});

test('skip link, reading persistence, reduced motion, forced colors, and 200% text', async ({
  page,
  browserName,
}) => {
  await page.goto('/');
  await page.keyboard.press(browserName === 'webkit' ? 'Alt+Tab' : 'Tab');
  await expect(
    page.getByRole('link', { name: 'Skip to content' }),
  ).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('main')).toBeFocused();
  await page.locator('#reading-controls > summary').click();
  await page.locator('#setting-theme').selectOption('light');
  await page.locator('#setting-width').selectOption('narrow');
  await page.locator('#setting-spacing').selectOption('comfortable');
  await page.locator('#setting-motion').selectOption('reduced');
  await page.goto('/schema-migrator/');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('html')).toHaveAttribute('data-width', 'narrow');
  await expect(page.locator('html')).toHaveAttribute(
    'data-spacing',
    'comfortable',
  );
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced');
  await page.setViewportSize({ width: 320, height: 900 });
  await page.addStyleTag({ content: ':root { font-size: 200% !important; }' });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
  await page.getByRole('button', { name: '4. Inspect run record' }).click();
  await expect(
    page.getByRole('button', { name: '4. Inspect run record' }),
  ).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#reading-controls > summary').click();
  await page.getByRole('button', { name: 'Reset settings' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});

test('metadata, sitemap, local indexing guard, self-hosted assets and no external requests', async ({
  page,
}) => {
  const external: string[] = [];
  page.on('request', (request) => {
    if (!request.url().startsWith('http://127.0.0.1:4323'))
      external.push(request.url());
  });
  for (const route of routes) {
    await page.goto(route);
    await expect(page.locator('meta[name="description"]')).toHaveAttribute(
      'content',
      /.+/,
    );
    await expect(page.locator('meta[property="og:image"]')).toHaveAttribute(
      'content',
      /social-preview/,
    );
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
      'href',
      `http://localhost:4321${route}`,
    );
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute(
      'content',
      'noindex, nofollow',
    );
  }
  expect(external).toEqual([]);
  const sitemap = await (await page.request.get('/sitemap.xml')).text();
  for (const route of routes)
    expect(sitemap).toContain(`http://localhost:4321${route}`);
  expect(await (await page.request.get('/robots.txt')).text()).toContain(
    'Disallow: /',
  );
});

test('enhanced text contrast and control boundaries meet thresholds in both themes', async ({
  page,
}) => {
  await page.goto('/');
  for (const theme of ['dark', 'light']) {
    await page.evaluate(
      (value) => (document.documentElement.dataset.theme = value),
      theme,
    );
    const ratios = await page.evaluate(() => {
      const style = getComputedStyle(document.documentElement);
      function luminance(token: string) {
        const hex = style.getPropertyValue(token).trim().slice(1);
        const rgb = [0, 2, 4]
          .map((offset) => parseInt(hex.slice(offset, offset + 2), 16) / 255)
          .map((value) =>
            value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4,
          );
        return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
      }
      return ['--text', '--muted', '--search', '--migrator', '--rule'].flatMap(
        (foreground) =>
          ['--bg', '--surface'].map((background) => {
            const values = [luminance(foreground), luminance(background)].sort(
              (a, b) => b - a,
            );
            return {
              foreground,
              background,
              ratio: (values[0] + 0.05) / (values[1] + 0.05),
            };
          }),
      );
    });
    for (const pair of ratios)
      expect(
        pair.ratio,
        `${theme} ${pair.foreground}/${pair.background}`,
      ).toBeGreaterThanOrEqual(pair.foreground === '--rule' ? 3 : 7);
  }
});
