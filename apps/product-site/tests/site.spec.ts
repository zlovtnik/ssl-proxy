import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  allProducts,
  contactOptions,
  contact,
  email,
  home,
  homeSections,
  products,
} from '../src/data/products';

const routes = [
  '/',
  '/products/',
  '/vpn-proxy/',
  '/atheros-search/',
  '/schema-migrator/',
  '/demo/',
  '/accessibility/',
  '/privacy/',
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

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      'rclabs-analytics-consent',
      JSON.stringify({
        version: 1,
        analytics: false,
        savedAt: Date.now(),
      }),
    );
  });
});

test('header stays visible and product samples preserve the landing layout', async ({
  page,
}) => {
  await page.goto('/');
  const preview = page.locator('.landing-playground');
  await expect(
    preview.getByRole('button', { name: 'Schema Migrator', exact: true }),
  ).toBeEnabled();
  for (const product of products) {
    await page.getByRole('link', { name: `Try the ${product.name} sample` }).click();
    await expect(
      preview.getByRole('button', { name: product.name, exact: true }),
    ).toHaveAttribute('aria-pressed', 'true');
    expect(new URL(page.url()).pathname).toBe('/');
    await expect(preview.locator('.preview-panel:visible')).toHaveCount(1);
    const panel = (await preview.boundingBox())!;
    const next = (await page.locator('#products').boundingBox())!;
    expect(next.y).toBeGreaterThanOrEqual(panel.y + panel.height);
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
  await expect(page).toHaveURL(/\/products\/$/);
  await expect(page.locator('.mobile-menu')).not.toHaveAttribute('open');
  await expect(page.locator('.product-card')).toHaveCount(3);
});

test('landing preview filters site-scoped wireless samples and reviews migration steps', async ({
  page,
}) => {
  await page.goto('/');
  const preview = page.locator('.landing-playground');
  await expect(
    preview.getByRole('button', { name: 'Schema Migrator', exact: true }),
  ).toBeEnabled();
  await expect(
    preview.getByRole('button', { name: /North Campus/ }),
  ).toHaveAttribute('aria-pressed', 'true');
  await expect(
    preview.getByRole('button', { name: /West Distribution/ }),
  ).toHaveAttribute('aria-pressed', 'false');
  await preview
    .getByLabel('Filter sample sites, indicators, and observations')
    .fill('West Distribution');
  await expect(preview.getByRole('status')).toContainText('1 wireless samples');
  await preview
    .getByRole('button', { name: /West Distribution/ })
    .press('Space');
  await expect(preview.locator('.preview-evidence')).toContainText(
    'deauthentication observation followed by a reassociation observation',
  );
  await preview
    .getByLabel('Filter sample sites, indicators, and observations')
    .fill('no-matching-record');
  await expect(preview.getByRole('status')).toContainText('0 wireless samples');
  await expect(preview.locator('.preview-evidence')).toHaveCount(0);
  await preview
    .getByLabel('Filter sample sites, indicators, and observations')
    .fill('');
  for (const theme of ['dark']) {
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
  for (const theme of ['dark']) {
    test(`${route}: ${theme} accessibility, reflow, and links`, async ({
      page,
    }) => {
      await page.goto(route);
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
      for (const width of [1440, 1024, 768, 375, 320]) {
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
      await page.addStyleTag({
        content: ':root { font-size: 150% !important; }',
      });
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

test('Search reviews sample sites and indicators with a keyboard', async ({
  page,
}) => {
  await page.goto('/atheros-search/');
  await expect(
    page.getByText(
      'The current production console does not yet show this complete site overview end to end.',
      { exact: false },
    ),
  ).toBeVisible();
  const nextSite = page.getByRole('button', {
    name: 'Try the next sample site',
  });
  await expect(nextSite).toBeEnabled();
  await nextSite.focus();
  await page.keyboard.press('Space');
  await expect(
    page.getByRole('heading', { name: 'PMF-related reconnect pattern' }),
  ).toBeVisible();
  const explanation = page.getByText('3. Review why the indicator was raised', {
    exact: true,
  });
  await explanation.focus();
  await page.keyboard.press('Enter');
  await expect(
    page.getByText('not a confirmed attack', { exact: false }),
  ).toBeVisible();
  await page
    .getByText('4. Inspect the supporting observation', { exact: true })
    .click();
  await expect(
    page.getByText(
      'deauthentication observation followed by a reassociation observation',
      { exact: false },
    ),
  ).toBeVisible();
  await page.getByLabel('1. Choose a monitored sample site').selectOption('0');
  await expect(
    page.getByRole('heading', { name: 'Suspected rogue access point' }),
  ).toBeVisible();
  for (const theme of ['dark']) {
    await page.evaluate(
      (value) => (document.documentElement.dataset.theme = value),
      theme,
    );
    for (const sample of ['0', '1']) {
      await page
        .getByLabel('1. Choose a monitored sample site')
        .selectOption(sample);
      expect(
        (await new AxeBuilder({ page }).withTags(tags).analyze()).violations,
      ).toEqual([]);
    }
  }
});

test('Migrator steps are user controlled and accessible in the dark theme', async ({
  page,
}) => {
  await page.goto('/schema-migrator/');
  const buttons = page
    .getByRole('group', { name: 'Migration review steps' })
    .getByRole('button');
  for (const theme of ['dark']) {
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
  for (const { id, subject } of contactOptions) {
    const href = await page.locator(`#${id} a`).getAttribute('href');
    const url = new URL(href!);
    expect(url.pathname).toBe('rafael@rclabs.uk');
    expect(url.searchParams.get('subject')).toBe(
      `Use-case discussion: ${subject}`,
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
    page.getByText("We'll agree on the next step by email", { exact: false }),
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
    .getByText('3. Review why the indicator was raised', { exact: true })
    .click();
  await expect(
    page.getByText('does not prove a rogue access point', { exact: false }),
  ).toBeVisible();
  await context.close();
});

test('skip link, saved display choices, reduced motion, forced colors, and 200% text', async ({
  page,
  browserName,
}) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      'rclabs-reading',
      JSON.stringify({
        width: 'narrow',
        spacing: 'comfortable',
        motion: 'reduced',
      }),
    );
  });
  await page.goto('/');
  await page.keyboard.press(browserName === 'webkit' ? 'Alt+Tab' : 'Tab');
  await expect(
    page.getByRole('link', { name: 'Skip to content' }),
  ).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('main')).toBeFocused();
  await page.goto('/schema-migrator/');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
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
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});

test('display settings controls are absent and previously saved choices still apply', async ({
  page,
}) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      'rclabs-reading',
      JSON.stringify({
        size: 'large',
        width: 'narrow',
        spacing: 'comfortable',
        motion: 'reduced',
      }),
    );
  });
  for (const route of routes) {
    await page.goto(route);
    await expect(page.locator('.reading-bar')).toHaveCount(0);
    await expect(page.locator('#setting-size')).toHaveCount(0);
    await expect(page.locator('html')).toHaveAttribute('data-size', 'large');
    await expect(page.locator('html')).toHaveAttribute('data-width', 'narrow');
    await expect(page.locator('html')).toHaveAttribute(
      'data-spacing',
      'comfortable',
    );
    await expect(page.locator('html')).toHaveAttribute(
      'data-motion',
      'reduced',
    );
  }
});

for (const colorScheme of ['light', 'dark'] as const) {
  test(`dark theme ignores ${colorScheme} system preference and saved themes on every route`, async ({ page }) => {
    await page.emulateMedia({ colorScheme });
    await page.goto('/');
    for (const theme of ['light', 'system', 'dark']) {
      await page.evaluate((savedTheme) => {
        localStorage.setItem('rclabs-reading', JSON.stringify({
          theme: savedTheme,
          size: 'large',
          width: 'narrow',
          spacing: 'comfortable',
          motion: 'reduced',
        }));
      }, theme);
      for (const route of routes) {
        await page.goto(route);
        await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
        await expect(page.locator('html')).toHaveCSS('color-scheme', 'dark');
        await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(9, 9, 9)');
        await expect(page.locator('#setting-theme')).toHaveCount(0);
        await expect(page.locator('html')).toHaveAttribute('data-size', 'large');
        await expect(page.locator('html')).toHaveAttribute('data-width', 'narrow');
        await expect(page.locator('html')).toHaveAttribute('data-spacing', 'comfortable');
        await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced');
      }
    }
  });
}

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
    const isPreview = await page.locator('meta[name="robots"]').count();
    const expectedOrigin = isPreview
      ? 'http://localhost:4321'
      : 'https://rclabs.uk';
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
      'href',
      expectedOrigin + route,
    );
    if (isPreview)
      await expect(page.locator('meta[name="robots"]')).toHaveAttribute(
        'content',
        'noindex, nofollow',
      );
    else await expect(page.locator('meta[name="robots"]')).toHaveCount(0);
  }
  expect(external).toEqual([]);
  const sitemap = await (await page.request.get('/sitemap.xml')).text();
  const sitemapOrigin =
    (await page.locator('meta[name="robots"]').count()) > 0
      ? 'http://localhost:4321'
      : 'https://rclabs.uk';
  for (const route of routes) expect(sitemap).toContain(sitemapOrigin + route);
  const robots = await (await page.request.get('/robots.txt')).text();
  expect(robots).toContain(
    sitemapOrigin === 'http://localhost:4321' ? 'Disallow: /' : 'Allow: /',
  );
});

test('enhanced text contrast and control boundaries meet thresholds in the dark theme', async ({
  page,
}) => {
  await page.goto('/');
  for (const theme of ['dark']) {
    await page.evaluate(
      (value) => (document.documentElement.dataset.theme = value),
      theme,
    );
    const ratios = await page.evaluate(() => {
      const style = getComputedStyle(document.documentElement);
      function luminance(token: string) {
        const value = style.getPropertyValue(token).trim().slice(1);
        const hex = value.length === 3 ? [...value].map((digit) => digit + digit).join('') : value;
        const rgb = [0, 2, 4]
          .map((offset) => parseInt(hex.slice(offset, offset + 2), 16) / 255)
          .map((value) =>
            value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4,
          );
        return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
      }
      return [
        '--text',
        '--muted',
        '--search',
        '--migrator',
        '--vpn',
        '--action',
        '--success',
        '--rule',
      ].flatMap((foreground) =>
        ['--bg', '--surface', '--raised', '--inset'].map((background) => {
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

type RenderedPair = {
  kind: string;
  label: string;
  ratio: number;
  target: number;
  width?: number;
  outline?: string;
  order?: number;
  count?: number;
  visible?: boolean;
};

// Token pairs cannot see alpha, colour mixes, inherited surfaces, or a focus
// outline painted outside a control, so this resolves rendered combinations.
// Decorative gradient glows sit behind the hero proof panel and are not part of
// the composited chain.
async function renderedPairs(
  page: Page,
  mode: 'text' | 'control' | 'focus' | 'focusable' | 'rings',
) {
  return page.evaluate((audit): RenderedPair[] => {
    const parse = (value: string) => {
      const [red, green, blue, alpha = '1'] = value.match(/[\d.]+/g)!;
      // Colour mixes serialise as color(srgb 0-1); rgb() uses 0-255.
      const scale = value.startsWith('color(') ? 255 : 1;
      return {
        r: Number(red) * scale,
        g: Number(green) * scale,
        b: Number(blue) * scale,
        a: Number(alpha),
      };
    };
    const over = (top: string, bottom: string) => {
      const a = parse(top);
      const b = parse(bottom);
      const alpha = a.a + b.a * (1 - a.a);
      const mix = (x: number, y: number) =>
        alpha === 0 ? 0 : (x * a.a + y * b.a * (1 - a.a)) / alpha;
      return `rgb(${mix(a.r, b.r)} ${mix(a.g, b.g)} ${mix(a.b, b.b)})`;
    };
    const luminance = (value: string) => {
      const channels = parse(value);
      const [r, g, b] = [channels.r, channels.g, channels.b].map((channel) => {
        const part = channel / 255;
        return part <= 0.04045 ? part / 12.92 : ((part + 0.055) / 1.055) ** 2.4;
      });
      return r * 0.2126 + g * 0.7152 + b * 0.0722;
    };
    const ratio = (foreground: string, background: string) => {
      const values = [luminance(foreground), luminance(background)].sort(
        (a, b) => b - a,
      );
      return (values[0] + 0.05) / (values[1] + 0.05);
    };
    const shown = (element: Element) => {
      if (!element.getClientRects().length || element.closest('[inert]'))
        return false;
      for (let node: Element | null = element; node; node = node.parentElement)
        if (getComputedStyle(node).visibility !== 'visible') return false;
      return true;
    };
    const background = (element: Element) => {
      const layers: string[] = [];
      for (
        let node: Element | null = element;
        node;
        node = node.parentElement
      ) {
        const colour = getComputedStyle(node).backgroundColor;
        if (parse(colour).a === 0) continue;
        layers.push(colour);
        if (parse(colour).a === 1) break;
      }
      // The nearest layer is painted on top of everything behind it.
      let result = getComputedStyle(document.documentElement).backgroundColor;
      for (const layer of layers.reverse()) result = over(layer, result);
      return result;
    };
    const label = (element: Element, text: string) =>
      `${element.tagName.toLowerCase()}.${element.className} "${text.slice(0, 24)}"`;
    const focusable = [
      ...document.querySelectorAll<HTMLElement>(
        'a[href], button, select, input, summary, [tabindex]',
      ),
    ].filter(
      (element) =>
        element.tabIndex >= 0 &&
        shown(element) &&
        // Controls inside a collapsed disclosure are not tabbable.
        !(
          element.closest('details:not([open])') &&
          element.tagName !== 'SUMMARY'
        ),
    );
    if (audit === 'rings') {
      // Focus each tabbable control in turn. Every control in this site accepts
      // programmatic focus as :focus-visible once the document has keyboard
      // focus, which keeps the check identical across engines.
      return focusable.map((element) => {
        element.focus();
        const style = getComputedStyle(element);
        return {
          kind: 'ring',
          label: label(element, element.textContent?.trim() ?? ''),
          // The outline is painted outside the border box, so it is compared
          // with the surface immediately behind the control.
          ratio: ratio(
            style.outlineColor,
            background(element.parentElement ?? document.body),
          ),
          target: 3,
          width: parseFloat(style.outlineWidth),
          outline: style.outlineStyle,
          visible: element.matches(':focus-visible'),
        };
      });
    }
    if (audit === 'focusable')
      return [
        {
          kind: 'focusable',
          label: 'tabbable controls',
          ratio: 0,
          target: 0,
          count: focusable.length,
        },
      ];
    if (audit === 'focus') {
      const active = document.activeElement as HTMLElement | null;
      if (!active || active === document.body) return [];
      const style = getComputedStyle(active);
      // Position in tab order, so traversal can be checked without labels.
      const order = focusable.indexOf(active);
      // The outline is painted outside the border box, so it is compared with
      // the surface immediately behind the control.
      return [
        {
          kind: 'focus',
          label: label(active, active.textContent?.trim() ?? ''),
          ratio: ratio(
            style.outlineColor,
            background(active.parentElement ?? document.body),
          ),
          target: 3,
          width: parseFloat(style.outlineWidth),
          outline: style.outlineStyle,
          order,
        },
      ];
    }
    const results: RenderedPair[] = [];
    if (audit === 'text') {
      for (const element of document.body.querySelectorAll<HTMLElement>('*')) {
        const text = [...element.childNodes]
          .filter((node) => node.nodeType === 3)
          .map((node) => node.textContent ?? '')
          .join('')
          .trim();
        if (!text || !shown(element)) continue;
        const style = getComputedStyle(element);
        const size = parseFloat(style.fontSize);
        const large =
          size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700);
        results.push({
          kind: 'text',
          label: label(element, text),
          ratio: ratio(style.color, background(element)),
          target: large ? 4.5 : 7,
        });
      }
      return results;
    }
    for (const element of document.body.querySelectorAll<HTMLElement>(
      'button, select, input, a.button, summary, .button',
    )) {
      if (!shown(element)) continue;
      const style = getComputedStyle(element);
      const around = background(element.parentElement!);
      const name = label(element, element.textContent?.trim() ?? '');
      // A filled control is identified by its own surface against the page.
      const fill = ratio(background(element), around);
      if (fill >= 3) {
        results.push({ kind: 'fill', label: name, ratio: fill, target: 3 });
        continue;
      }
      const widths = [
        style.borderTopWidth,
        style.borderRightWidth,
        style.borderBottomWidth,
        style.borderLeftWidth,
      ].map(parseFloat);
      // Decorative rules and hairline separators are not control boundaries.
      if (widths.some((width) => width === 0)) continue;
      if (style.borderTopStyle === 'none') continue;
      results.push({
        kind: 'boundary',
        label: name,
        ratio: ratio(style.borderTopColor, around),
        target: 3,
      });
    }
    return results;
  }, mode);
}

test('rendered text and control boundaries meet the documented targets in every demo state', async ({
  page,
}) => {
  test.setTimeout(120_000);
  const audit = async (state: string) => {
    const audited = [
      ...(await renderedPairs(page, 'text')),
      ...(await renderedPairs(page, 'control')),
    ];
    expect(audited.length, `${state} audited pairs`).toBeGreaterThan(30);
    for (const result of audited)
      expect(result.ratio, `${state} ${result.kind} ${result.label}`).toBeGreaterThanOrEqual(result.target);
  };
  for (const route of routes) {
    await page.goto(route);
    // Read settled states; the 150ms border transition would otherwise be
    // sampled mid-interpolation.
    await page.addStyleTag({
      content: '* { transition: none !important; animation: none !important; }',
    });
    await page
      .locator('details')
      .evaluateAll((elements) =>
        elements.forEach(
          (element) => ((element as HTMLDetailsElement).open = true),
        ),
      );
    for (const width of [1440, 768, 320]) {
      await page.setViewportSize({ width, height: 1000 });
      const state = `${route} ${width}px`;
      await audit(`${state} page`);
      const choices = route === '/' ? products : products.filter((product) => product.path === route);
      for (const product of choices) {
        if (route === '/')
          await page.locator('.preview-switch').getByRole('button', { name: product.name, exact: true }).click();
        if (product.id === 'migrator') {
          for (const step of await page.locator(route === '/' ? '.preview-steps button' : '.step-controls button').all()) {
            await step.click();
            await audit(`${state} ${await step.textContent()}`);
          }
        } else if (product.id === 'vpn') {
          const flow = page.getByLabel('Sample traffic flow', { exact: true });
          for (const option of await flow.locator('option').all()) {
            await flow.selectOption((await option.getAttribute('value'))!);
            await audit(`${state} ${await option.textContent()}`);
          }
        } else if (route === '/') {
          const filter = page.getByLabel('Filter sample sites, indicators, and observations');
          await filter.fill('no-results');
          await audit(`${state} empty search`);
          await filter.fill('');
          for (const record of await page.locator('.preview-record').all()) {
            await record.click();
            await audit(`${state} ${await record.textContent()}`);
          }
        } else {
          for (const sample of ['0', '1']) {
            await page.getByLabel('1. Choose a monitored sample site').selectOption(sample);
            await audit(`${state} search ${sample}`);
          }
        }
      }
    }
  }
});

test('every route supports forced colours and reduced motion', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
  for (const route of routes) {
    await page.goto(route);
    for (const width of [1440, 320]) {
      await page.setViewportSize({ width, height: 1000 });
      const skipLink = page.getByRole('link', { name: 'Skip to content' });
      await skipLink.focus();
      await expect(skipLink).toBeFocused();
      await expect(skipLink).toHaveCSS('outline-style', 'solid');
      await expect(skipLink).toHaveCSS('outline-width', '3px');
      await expect(page.locator('html')).toHaveCSS('scroll-behavior', 'auto');
      await expect(page.locator('.reading-bar')).toHaveCount(0);
      const transitions = await page.locator('a, button, select').evaluateAll((elements) =>
        elements.filter((element) => element.checkVisibility()).map((element) => getComputedStyle(element).transitionDuration));
      expect(transitions.every((duration) => duration === '0s')).toBe(true);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
  }
});

test('both caveats ship from the content model beside the content they qualify', async ({
  page,
}) => {
  for (const product of products) {
    await page.goto(product.path);
    const html = await page.content();
    // The page copy and the demonstration both carry the same statement.
    expect(html.split(product.caveat).length - 1, product.name).toBeGreaterThan(
      1,
    );
    await page.locator('#demo').scrollIntoViewIfNeeded();
  }
  await page.goto('/');
  const home = await page.content();
  for (const product of products)
    expect(
      home.includes(product.caveat),
      `${product.name} caveat in the playground`,
    ).toBe(true);
  await page
    .getByRole('button', { name: 'Atheros Search', exact: true })
    .click();
  await expect(
    page.getByRole('link', { name: 'Open the Search sample workflow' }),
  ).toHaveAttribute('href', `${products[0].path}#demo`);
  await page
    .getByRole('button', { name: 'Schema Migrator', exact: true })
    .click();
  await expect(
    page.getByRole('link', { name: 'Open the migration walkthrough' }),
  ).toHaveAttribute('href', `${products[1].path}#demo`);
});

test('every tabbable control shows a compliant focus ring and keeps tab order', async ({
  page,
  browserName,
}) => {
  for (const route of routes) {
    for (const theme of ['dark']) {
      await page.goto(route);
      await page.evaluate(
        (value) => (document.documentElement.dataset.theme = value),
        theme,
      );
      const rings = await renderedPairs(page, 'rings');
      const [counted] = await renderedPairs(page, 'focusable');
      expect(rings.length, `${route} ${theme} focusable controls`).toBe(
        counted!.count,
      );
      for (const ring of rings) {
        const where = `${route} ${theme} ${ring.label}`;
        expect(ring.visible, `${where} focus-visible`).toBe(true);
        expect(ring.outline, where).not.toBe('none');
        expect(ring.width!, where).toBeGreaterThanOrEqual(2);
        expect(ring.ratio, where).toBeGreaterThanOrEqual(ring.target);
      }
      if (browserName !== 'chromium') continue;
      // Real key presses confirm the document order traversal. Chromium is the
      // engine used here because WebKit can move focus into browser chrome
      // part-way through a traversal.
      let previous = -1;
      let stops = 0;
      for (let step = 0; step < 60; step++) {
        await page.keyboard.press('Tab');
        const [focused] = await renderedPairs(page, 'focus');
        if (!focused) continue;
        if (focused.order! <= previous) break;
        previous = focused.order!;
        stops++;
      }
      expect(stops, `${route} ${theme} skipped controls`).toBe(counted!.count);
    }
  }
});

test('all eight routes share one system of colours, header geometry, type and controls', async ({
  page,
}) => {
  const snapshot = async (route: string, theme: string) => {
    await page.goto(route);
    await page.evaluate(
      (value) => (document.documentElement.dataset.theme = value),
      theme,
    );
    return page.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const header = document
        .querySelector('.site-header')!
        .getBoundingClientRect();
      const h1 = getComputedStyle(document.querySelector('h1')!);
      const control = getComputedStyle(
        document.querySelector('.site-header .button')!,
      );
      return {
        tokens: [
          '--bg',
          '--surface',
          '--raised',
          '--inset',
          '--text',
          '--muted',
          '--action',
          '--action-text',
          '--rule',
          '--divider',
          '--search',
          '--migrator',
          '--vpn',
        ].map((name) => `${name}:${root.getPropertyValue(name).trim()}`),
        header: `${Math.round(header.width)}x${Math.round(header.height)}`,
        h1: `${h1.fontSize}/${h1.fontWeight}/${h1.fontFamily}`,
        body: getComputedStyle(document.body).fontFamily,
        controlRadius: control.borderRadius,
        controlMinHeight: control.minHeight,
        controlBackground: control.backgroundColor,
      };
    });
  };
  for (const theme of ['dark']) {
    const reference = await snapshot(routes[0], theme);
    for (const route of routes.slice(1))
      expect(await snapshot(route, theme), `${route} ${theme}`).toEqual(
        reference,
      );
  }
});

test('hero calls to action keep their documented destinations', async ({
  page,
}) => {
  await page.goto('/');
  const home = page.locator('#top');
  await expect(
    home.getByRole('link', { name: 'Explore the samples' }),
  ).toHaveAttribute('href', '#playground');
  await expect(
    home.getByRole('link', { name: 'Discuss your use case' }),
  ).toHaveAttribute('href', '/demo/');
  await page.goto('/atheros-search/');
  const search = page.locator('.product-hero');
  await expect(
    search.getByRole('link', { name: 'Explore a sample site review' }),
  ).toHaveAttribute('href', '#demo');
  await expect(
    search.getByRole('link', { name: 'Discuss your use case' }),
  ).toHaveAttribute('href', '/demo/#search');
  await page.goto('/schema-migrator/');
  const migrator = page.locator('.product-hero');
  await expect(
    migrator.getByRole('link', { name: 'Explore a sample migration review' }),
  ).toHaveAttribute('href', '#demo');
  await expect(
    migrator.getByRole('link', { name: 'Discuss your use case' }),
  ).toHaveAttribute('href', '/demo/#migrator');
});

test('every route that offers a commercial action uses the shared contact pattern', async ({
  page,
}) => {
  for (const product of [null, ...products]) {
    const route = product ? product.path : '/';
    await page.goto(route);
    const banner = page.locator('.contact-banner');
    await expect(banner, route).toHaveCount(1);
    // One pattern, one set of words: the heading, the shorter link label, and the
    // visible address all ship from the content model.
    await expect(banner.getByRole('heading', { level: 2 })).toHaveText(
      contact.headline.join(' '),
    );
    const href = await banner
      .getByRole('link', { name: contact.link })
      .getAttribute('href');
    const request = new URL(href!, 'https://example.invalid');
    expect(request.pathname, route).toBe(email);
    expect(request.searchParams.get('subject'), route).toBe(
      `Use-case discussion: ${product ? product.name : allProducts}`,
    );
    expect(request.searchParams.get('body'), route).toContain(
      'Preferred times and time zone:',
    );
    await expect(banner.getByRole('link', { name: email })).toHaveAttribute(
      'href',
      `mailto:${email}`,
    );
    await expect(banner).toContainText('after we agree on a time');
  }
});

test('the three product routes share the same section structure from the model', async ({
  page,
}) => {
  const labels: string[][] = [];
  for (const product of products) {
    await page.goto(product.path);
    labels.push(
      await page.locator('.section-heading .eyebrow').allTextContents(),
    );
    for (const section of [
      'workflow',
      'value',
      'evidence',
      'glossary',
    ] as const)
      await expect(
        page.getByRole('heading', {
          level: 2,
          name: product.sections[section].title,
        }),
        `${product.name} ${section}`,
      ).toHaveCount(1);
    await expect(page.locator('.workflow-step')).toHaveCount(3);
    await expect(page.locator('.audience-card')).toHaveCount(2);
    await expect(page.locator('.evidence-panel')).toHaveCount(1);
    await expect(page.locator('.contact-banner')).toHaveCount(1);
  }
  for (const label of labels.slice(1)) expect(label).toEqual(labels[0]);
});

test('each product demo appears once below its introduction', async ({
  page,
}) => {
  for (const [route, panel] of [
    ['/atheros-search/', '.search-demo'],
    ['/schema-migrator/', '.migrator-demo'],
    ['/vpn-proxy/', '.vpn-demo'],
  ] as const) {
    await page.goto(route);
    await expect(page.locator('#demo')).toHaveCount(1);
    await expect(page.locator('.product-demo ' + panel)).toHaveCount(1);
    await expect(page.locator(panel)).toHaveCount(1);
    expect(
      await page.evaluate(() => {
        const intro = document
          .querySelector('.product-hero')!
          .getBoundingClientRect();
        const demo = document
          .querySelector('.product-demo')!
          .getBoundingClientRect();
        return demo.top >= intro.bottom && demo.width === intro.width;
      }),
    ).toBe(true);
  }
});

test('homepage metadata, identity markup and technical sections ship from the model', async ({
  page,
}) => {
  await page.goto('/');
  await expect(page).toHaveTitle(`${home.title} | RCLabs`);
  await expect(page.locator('meta[name="description"]')).toHaveAttribute(
    'content',
    home.description,
  );
  // One H1, built from the two halves of the modelled headline.
  const headings = page.getByRole('heading', { level: 1 });
  await expect(headings).toHaveCount(1);
  await expect(headings).toHaveText(home.headline.join(' '));

  // Identity markup only on the homepage, and only what this site can verify.
  await expect(page.locator('script[type="application/ld+json"]')).toHaveCount(
    1,
  );
  const graph = JSON.parse(
    (await page.locator('script[type="application/ld+json"]').textContent())!,
  );
  expect(graph['@context']).toBe('https://schema.org');
  const nodes = graph['@graph'] as Record<string, any>[];
  expect(nodes.map((node) => node['@type'])).toEqual([
    'Organization',
    'WebSite',
  ]);
  expect(nodes[0].name).toBe('RCLabs');
  const siteOrigin = new URL(
    (await page.locator('link[rel="canonical"]').getAttribute('href'))!,
  ).origin;
  expect(nodes[0].url).toBe(siteOrigin + '/');
  expect(nodes[0].email).toBe(email);
  expect(nodes[0].logo).toBeUndefined();
  expect(nodes[0].sameAs).toBeUndefined();
  expect(nodes[1].publisher['@id']).toBe(nodes[0]['@id']);
  expect(nodes[0]['@id']).toBe(siteOrigin + '/#organization');

  // Every modelled section is published once, with its own heading.
  for (const section of Object.values(homeSections)) {
    await expect(page.locator(`#${section.id}`), section.id).toHaveCount(1);
    await expect(
      page.getByRole('heading', { level: 2, name: section.title }),
      section.id,
    ).toHaveCount(1);
  }
  await expect(page.locator('#products .product-card h2')).toHaveText(
    products.map((product) => product.homeTitle),
  );

  // The four new calls to action keep their documented destinations.
  await expect(
    page.getByRole('link', { name: homeSections.guide.sample.primary.label }),
  ).toHaveAttribute('href', homeSections.guide.sample.primary.href);
  await expect(
    page.getByRole('link', { name: homeSections.guide.sample.secondary.label }),
  ).toHaveAttribute('href', homeSections.guide.sample.secondary.href);
  await expect(
    page.getByRole('link', { name: homeSections.comparison.cta.label }),
  ).toHaveAttribute('href', homeSections.comparison.cta.href);
  await expect(
    page.getByRole('link', {
      name: homeSections.benchmark.status.sample.label,
      exact: true,
    }),
  ).toHaveAttribute('href', homeSections.benchmark.status.sample.href);
  // The benchmark stays a protocol until results are measured.
  await expect(page.locator('#search-benchmark')).toContainText(
    'No relevance, latency, or storage figures appear here yet',
  );
  // The other four routes carry no structured data of their own.
  for (const route of routes.slice(1)) {
    await page.goto(route);
    await expect(
      page.locator('script[type="application/ld+json"]'),
      route,
    ).toHaveCount(0);
  }
});

test('analytics markup matches the public-build measurement configuration', async ({
  page,
}) => {
  await page.goto('/');
  const measurementId = await page.locator('html').getAttribute('data-ga4-id');
  if (measurementId) {
    expect(measurementId).toMatch(/^G-[A-Z0-9]{5,}$/);
    await expect(page.locator('#privacy-consent')).toHaveCount(1);
    await expect(page.locator('#privacy-consent')).toBeHidden();
  } else {
    await expect(page.locator('#privacy-consent')).toHaveCount(0);
  }
});

test('GA4 waits for consent, tracks safe events, and stops on withdrawal', async ({
  browser,
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.route('https://www.googletagmanager.com/**', (route) =>
    route.fulfill({ contentType: 'application/javascript', body: '' }),
  );
  const analyticsRequests: string[] = [];
  page.on('request', (request) => {
    if (/googletagmanager|google-analytics/.test(request.url()))
      analyticsRequests.push(request.url());
  });
  await page.goto(
    'http://127.0.0.1:4323/?person=visitor%40example.com&search=confidential&utm_source=linkedin&utm_campaign=fall-2026',
  );
  const panel = page.locator('#privacy-consent');
  if (!(await panel.count())) test.skip();
  await expect(panel).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute(
    'data-ga4-id',
    /^G-[A-Z0-9]{5,}$/,
  );
  expect(analyticsRequests).toEqual([]);
  expect(
    (await new AxeBuilder({ page }).withTags(tags).analyze()).violations,
  ).toEqual([]);
  for (const width of [375, 320]) {
    await page.setViewportSize({ width, height: 900 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    for (const button of await panel
      .locator('button[data-consent]:visible')
      .all()) {
      const bounds = await button.boundingBox();
      expect(bounds!.width).toBeGreaterThanOrEqual(44);
      expect(bounds!.height).toBeGreaterThanOrEqual(44);
    }
    await panel.getByRole('button', { name: 'Settings' }).click();
    const saveChoice = panel.getByRole('button', { name: 'Save choice' });
    const saveBounds = await saveChoice.boundingBox();
    expect(saveBounds!.width).toBeGreaterThanOrEqual(44);
    expect(saveBounds!.height).toBeGreaterThanOrEqual(44);
    await panel.getByRole('button', { name: 'Settings' }).click();
  }
  await page.setViewportSize({ width: 1280, height: 900 });

  await page.getByRole('button', { name: 'Accept analytics' }).click();
  await expect.poll(() => analyticsRequests.length).toBe(1);
  const measurementId = await page.locator('html').getAttribute('data-ga4-id');
  await expect
    .poll(() =>
      page.evaluate(
        (id) =>
          Boolean(
            (window as unknown as Record<string, boolean | undefined>)[
              'ga-disable-' + id
            ] === false,
          ),
        measurementId,
      ),
    )
    .toBe(true);
  await page
    .getByLabel('Filter sample sites, indicators, and observations')
    .fill('visitor@example.com');
  await page
    .locator('#playground')
    .getByRole('button', { name: 'Schema Migrator', exact: true })
    .click();
  const inspectDataLayer = async () => {
    const snapshot = await page.evaluate(() => {
      const entries =
        (window as unknown as { dataLayer?: IArguments[] }).dataLayer || [];
      return {
        entriesAreArguments: entries.every(
          (entry) =>
            Object.prototype.toString.call(entry) === '[object Arguments]',
        ),
        entries: entries.map((entry) => Array.from(entry)),
      };
    });
    expect(snapshot.entriesAreArguments).toBe(true);
    return snapshot.entries.map((entry) => JSON.stringify(entry)).join('\n');
  };
  const queued = await inspectDataLayer();
  expect(queued).toContain('page_view');
  expect(queued).toContain('sample_interaction');
  expect(queued).toContain('linkedin');
  expect(queued).toContain('fall-2026');
  expect(queued).not.toContain('visitor@example.com');
  expect(queued).not.toContain('person=');
  expect(queued).not.toContain('search=');
  expect(queued).not.toContain('mailto:');

  await page.goto('http://127.0.0.1:4323/demo/');
  await page.locator('a[href^="mailto:"]').first().click();
  const mailtoEvent = await inspectDataLayer();
  expect(mailtoEvent).toContain('mailto_click');
  expect(mailtoEvent).not.toContain('rafael@rclabs.uk');
  expect(mailtoEvent).not.toContain('subject=');

  await context.addCookies([
    {
      name: '_ga',
      value: 'test-browser-id',
      url: 'http://127.0.0.1:4323',
    },
  ]);
  await page.getByRole('button', { name: 'Cookie preferences' }).click();
  await expect(panel).toBeVisible();
  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(
    panel.getByLabel('Allow Google Analytics to measure site use'),
  ).toBeChecked();
  await panel
    .getByLabel('Allow Google Analytics to measure site use')
    .uncheck();
  await panel.getByRole('button', { name: 'Save choice' }).click();
  await expect(panel).toBeHidden();
  await expect
    .poll(() =>
      page.evaluate(
        (id) =>
          Boolean(
            (window as unknown as Record<string, boolean | undefined>)[
              'ga-disable-' + id
            ],
          ),
        measurementId,
      ),
    )
    .toBe(true);
  expect(
    await context
      .cookies()
      .then((cookies) => cookies.some((cookie) => cookie.name === '_ga')),
  ).toBe(false);
  await context.close();
});

test('rejecting optional analytics keeps the tag and identifiers off', async ({
  browser,
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.route('https://www.googletagmanager.com/**', (route) =>
    route.fulfill({ contentType: 'application/javascript', body: '' }),
  );
  const analyticsRequests: string[] = [];
  page.on('request', (request) => {
    if (/googletagmanager|google-analytics/.test(request.url()))
      analyticsRequests.push(request.url());
  });
  await page.goto('http://127.0.0.1:4323/');
  const measurementId = await page.locator('html').getAttribute('data-ga4-id');
  if (!measurementId) test.skip();
  await page.getByRole('button', { name: 'Reject optional' }).click();
  await expect(page.locator('#privacy-consent')).toBeHidden();
  await expect
    .poll(() =>
      page.evaluate(
        (id) =>
          Boolean(
            (window as unknown as Record<string, boolean | undefined>)[
              'ga-disable-' + id
            ],
          ),
        measurementId,
      ),
    )
    .toBe(true);
  expect(analyticsRequests).toEqual([]);
  expect(
    await context
      .cookies()
      .then((cookies) =>
        cookies.some((cookie) => /^_(ga|gid)/.test(cookie.name)),
      ),
  ).toBe(false);
  await page.reload();
  await expect(page.locator('#privacy-consent')).toBeHidden();
  expect(analyticsRequests).toEqual([]);
  await context.close();
});
