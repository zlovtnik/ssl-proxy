import { test, expect, type Page } from '@playwright/test';
import { products, sampleProducts } from '../src/data/products';
import { trafficFlows } from '../src/data/fixtures';

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      'rclabs-analytics-consent',
      JSON.stringify({ version: 1, analytics: false, savedAt: Date.now() }),
    );
  });
});

async function expectContainedLayout(page: Page) {
  const failures = await page.evaluate(() => {
    const failures: string[] = [];
    if (document.documentElement.scrollWidth > innerWidth)
      failures.push('Page scrolls horizontally');
    const visible = (element: Element) =>
      element.checkVisibility() && element.getBoundingClientRect().height > 0;
    for (const panel of document.querySelectorAll(
      '.landing-playground, .demo-panel, .product-card',
    )) {
      if (!visible(panel)) continue;
      const bounds = panel.getBoundingClientRect();
      for (const child of panel.querySelectorAll(
        'h2, h3, h4, p, pre, button, select, summary, details[open]',
      )) {
        if (!visible(child)) continue;
        const rect = child.getBoundingClientRect();
        if (
          rect.bottom > bounds.bottom + 1 ||
          rect.top < bounds.top - 1 ||
          rect.right > bounds.right + 1 ||
          rect.left < bounds.left - 1
        ) {
          failures.push(
            `${panel.className}: ${child.tagName} ${child.textContent?.trim().slice(0, 60)} escapes its panel`,
          );
        }
      }
    }
    const sections = Array.from(
      document.querySelectorAll('main > section'),
    ).filter(visible);
    for (let i = 1; i < sections.length; i++) {
      if (
        sections[i].getBoundingClientRect().top <
        sections[i - 1].getBoundingClientRect().bottom - 1
      )
        failures.push(`Main section ${i} overlaps its predecessor`);
    }
    const cards = Array.from(
      document.querySelectorAll(
        '.product-card, .workflow-step, .audience-card',
      ),
    ).filter(visible);
    for (let i = 0; i < cards.length; i++) {
      const a = cards[i].getBoundingClientRect();
      for (let j = i + 1; j < cards.length; j++) {
        const b = cards[j].getBoundingClientRect();
        if (
          Math.min(a.right, b.right) - Math.max(a.left, b.left) > 1 &&
          Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 1
        )
          failures.push(`Cards ${i} and ${j} overlap`);
      }
    }
    return failures;
  });
  expect(failures).toEqual([]);
}

for (const route of [
  '/',
  '/products/',
  ...products.map((product) => product.path),
]) {
  for (const theme of ['dark']) {
    test(`${route} ${theme}: expansions and every sample stay in document flow`, async ({
      page,
    }) => {
      test.setTimeout(90_000);
      await page.goto(route);
      await page.evaluate((value) => {
        document.documentElement.dataset.theme = value;
      }, theme);
      const intro = page.locator('.hero');
      const introHeight = (await intro.boundingBox())!.height;
      // Check each disclosure on its own, then retain every one open.
      for (const summary of await page
        .locator('main details > summary:visible')
        .all()) {
        await summary.click();
        await expectContainedLayout(page);
        await summary.click();
      }
      await page.locator('main details').evaluateAll((elements) =>
        elements.forEach((element) => {
          (element as HTMLDetailsElement).open = true;
        }),
      );
      expect((await intro.boundingBox())!.height).toBeCloseTo(introHeight, 0);
      for (const width of [1440, 1024, 768, 375, 320]) {
        await page.setViewportSize({ width, height: 1000 });
        await expectContainedLayout(page);
        const choices =
          route === '/'
            ? sampleProducts
            : sampleProducts.filter((product) => product.path === route);
        for (const product of choices) {
          if (route === '/') {
            await page
              .locator('.preview-switch')
              .getByRole('button', { name: product.name, exact: true })
              .click();
            await expect(page.locator('.preview-panel:visible')).toHaveCount(1);
            expect(
              await page
                .locator('.preview-panel[hidden]')
                .evaluateAll((panels) =>
                  panels.every(
                    (panel) =>
                      panel.getBoundingClientRect().height === 0 &&
                      panel.hasAttribute('inert'),
                  ),
                ),
            ).toBe(true);
          }
          if (product.id === 'migrator') {
            for (const step of await page
              .locator(
                route === '/'
                  ? '.preview-steps button'
                  : '.step-controls button',
              )
              .all()) {
              await step.click();
              await expectContainedLayout(page);
            }
          } else if (product.id === 'vpn') {
            for (let i = 0; i < trafficFlows.length; i++) {
              await page
                .getByLabel('Sample traffic flow', { exact: true })
                .selectOption(String(i));
              await expectContainedLayout(page);
            }
          } else if (route === '/') {
            const filter = page.getByLabel(
              'Filter sample sites, indicators, and observations',
            );
            await filter.fill('no-results');
            await expectContainedLayout(page);
            await filter.fill('');
            for (const record of await page.locator('.preview-record').all()) {
              await record.click();
              await expectContainedLayout(page);
            }
          } else {
            for (const option of ['0', '1']) {
              await page
                .getByLabel('1. Choose a monitored sample site')
                .selectOption(option);
              await expectContainedLayout(page);
            }
          }
        }
      }
      await page.addStyleTag({
        content:
          ':root { font-size: 200% !important; } * { line-height: 1.5 !important; letter-spacing: .12em !important; word-spacing: .16em !important; } p { margin-bottom: 2em !important; }',
      });
      await expectContainedLayout(page);
    });
  }
}

test('Octopus pipeline and audience toggle stay contained at every width', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.goto('/octopus/');
  await expect(page.locator('.workflow-step')).toHaveCount(3);
  await expect(page.locator('.audience-card')).toHaveCount(2);
  for (const width of [1440, 1024, 768, 375, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    await expectContainedLayout(page);
    const pipelineButtons = page.locator(
      '[data-ux="pipeline"] .pipeline-selector button',
    );
    await expect(pipelineButtons).toHaveCount(3);
    for (const button of await pipelineButtons.all()) {
      await button.click();
      await expectContainedLayout(page);
      await expect(page.locator('.workflow-step')).toHaveCount(3);
    }
    const toggleButtons = page.locator(
      '[data-ux="audience-toggle"] .audience-toggle button',
    );
    await expect(toggleButtons).toHaveCount(2);
    for (const button of await toggleButtons.all()) {
      await button.click();
      await expectContainedLayout(page);
      await expect(page.locator('.audience-card')).toHaveCount(2);
      const hidden = await page
        .locator('.audience-card[hidden]')
        .evaluateAll((cards) =>
          cards.every(
            (card) =>
              card.getBoundingClientRect().height === 0 &&
              card.hasAttribute('inert'),
          ),
        );
      expect(hidden).toBe(true);
    }
  }
  await page.addStyleTag({
    content:
      ':root { font-size: 200% !important; } * { line-height: 1.5 !important; letter-spacing: .12em !important; word-spacing: .16em !important; } p { margin-bottom: 2em !important; }',
  });
  await expectContainedLayout(page);
  for (const button of await page
    .locator('[data-ux="pipeline"] .pipeline-selector button')
    .all()) {
    await button.click();
    await expectContainedLayout(page);
  }
  for (const button of await page
    .locator('[data-ux="audience-toggle"] .audience-toggle button')
    .all()) {
    await button.click();
    await expectContainedLayout(page);
  }
});

test('VPN samples update their evidence and retain state through product switching', async ({
  page,
}) => {
  await page.goto('/');
  await page
    .getByRole('button', { name: 'RCLabs VPN / Proxy', exact: true })
    .press('Space');
  await page
    .getByText('Inspect the sample audit record', { exact: true })
    .click();
  for (let i = 0; i < trafficFlows.length; i++) {
    await page
      .getByLabel('Sample traffic flow', { exact: true })
      .selectOption(String(i));
    await expect(page.locator('.flow-result')).toContainText(
      trafficFlows[i].category,
    );
    await expect(page.locator('.flow-result')).toContainText(
      trafficFlows[i].decision,
    );
    await expect(page.locator('.panel-vpn pre')).toContainText(
      `Destination: ${trafficFlows[i].destination}`,
    );
  }
  await page
    .getByRole('button', { name: 'Atheros Search', exact: true })
    .click();
  await expect(
    page.getByLabel('Sample traffic flow', { exact: true }),
  ).toBeHidden();
  await page
    .getByRole('button', { name: 'RCLabs VPN / Proxy', exact: true })
    .click();
  await expect(
    page.getByLabel('Sample traffic flow', { exact: true }),
  ).toHaveValue('5');
  await expect(page.locator('.panel-vpn details').first()).toHaveAttribute(
    'open',
  );
  await page
    .getByRole('link', { name: 'Open the traffic walkthrough' })
    .click();
  await expect(page).toHaveURL(/\/vpn-proxy\/#demo$/);
});

test('VPN categories and catalogue links remain available without JavaScript', async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:4323/products/');
  for (const product of products) {
    await expect(
      page.getByRole('link', {
        name: `${product.name} product details`,
        exact: true,
      }),
    ).toHaveAttribute('href', product.path);
  }
  await page.goto('http://127.0.0.1:4323/vpn-proxy/');
  await expect(
    page.getByLabel('Sample traffic flow', { exact: true }),
  ).toBeDisabled();
  await page
    .getByText('Read all traffic categories as text', { exact: true })
    .click();
  for (const flow of trafficFlows)
    await expect(
      page.getByRole('heading', {
        name: `${flow.label} / ${flow.category}`,
        exact: true,
      }),
    ).toBeVisible();
  await context.close();
});
