import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { guides, guidePath } from '../src/data/products';

test('Pages previews ignore an inherited production site origin', () => {
  const siteFor = (branch: string) =>
    JSON.parse(
      execFileSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          "import config from './astro.config.mjs'; console.log(JSON.stringify(config.site));",
        ],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            CF_PAGES: '1',
            CF_PAGES_BRANCH: branch,
            PUBLIC_SITE_URL: 'https://rclabs.uk',
          },
          encoding: 'utf8',
        },
      ),
    );
  expect(siteFor('main')).toBe('https://rclabs.uk');
  expect(siteFor('seo-preview')).toBe('http://localhost:4321');
  expect(siteFor('')).toBe('http://localhost:4321');
});

test('favicons return image bytes, including a square PNG and ICO resolutions', async ({
  request,
  page,
}) => {
  await page.goto('/');
  await expect(
    page.locator('link[rel="icon"][type="image/png"]'),
  ).toHaveAttribute('href', '/favicon.png');
  const png = await request.get('/favicon.png');
  expect(png.status()).toBe(200);
  expect(png.headers()['content-type']).toContain('image/png');
  const bytes = await png.body();
  expect(bytes.subarray(0, 8).toString('hex')).toBe('89504e470d0a1a0a');
  expect(bytes.readUInt32BE(16)).toBe(96);
  expect(bytes.readUInt32BE(20)).toBe(96);
  const ico = await request.get('/favicon.ico');
  expect(ico.status()).toBe(200);
  const iconBytes = await ico.body();
  expect(iconBytes.readUInt16LE(2)).toBe(1);
  expect(iconBytes.readUInt16LE(4)).toBe(3);
  expect([0, 1, 2].map((index) => iconBytes[6 + index * 16])).toEqual([
    16, 32, 48,
  ]);
});

test('unmatched retired paths are errors rather than successful homepage copies', async ({
  request,
}) => {
  const errorPage = readFileSync('dist/404.html', 'utf8');
  expect(errorPage).toContain('noindex');
  expect(errorPage).not.toContain('rel="canonical"');
  for (const path of [
    '/service-areas',
    '/services',
    '/about',
    '/blog',
    '/faq',
    '/terms',
    '/unrecognised-seo-check',
  ]) {
    const response = await request.get(path);
    expect(response.status(), path).toBe(404);
  }
  const sitemap = await (await request.get('/sitemap.xml')).text();
  expect(sitemap).not.toContain('/404');
});

test('each guide has distinct crawlable content and matching breadcrumb markup', async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    const titles = new Set<string>();
    await page.goto('http://127.0.0.1:4323/guides/');
    for (const guide of guides)
      expect(
        await page.locator(`main a[href="${guidePath(guide.slug)}"]`).count(),
      ).toBeGreaterThan(0);
    for (const guide of guides) {
      await page.goto(`http://127.0.0.1:4323${guidePath(guide.slug)}`);
      const title = await page.title();
      expect(titles.has(title)).toBe(false);
      titles.add(title);
      await expect(page.getByRole('heading', { level: 1 })).toHaveText(
        guide.title,
      );
      await expect(page.locator('meta[name="description"]')).toHaveAttribute(
        'content',
        guide.description,
      );
      const canonical = (await page
        .locator('link[rel="canonical"]')
        .getAttribute('href'))!;
      expect(new URL(canonical).pathname).toBe(guidePath(guide.slug));
      const breadcrumb = JSON.parse(
        (await page
          .locator('script[type="application/ld+json"]')
          .textContent())!,
      );
      expect(breadcrumb['@type']).toBe('BreadcrumbList');
      const visibleNames = await page
        .getByRole('navigation', { name: 'Breadcrumb', exact: true })
        .locator('a, [aria-current="page"]')
        .allTextContents();
      expect(
        breadcrumb.itemListElement.map((item: { name: string }) => item.name),
      ).toEqual(visibleNames.map((name) => name.trim()));
      expect(breadcrumb.itemListElement.at(-1).item).toBe(canonical);
      expect((await page.locator('main').innerText()).length).toBeGreaterThan(
        1800,
      );
      const links = await page
        .locator('main a[href^="/"]')
        .evaluateAll((elements) =>
          elements.map((element) => element.getAttribute('href')!),
        );
      for (const link of links)
        expect((await page.request.get(link)).ok(), link).toBe(true);
    }
  } finally {
    await context.close();
  }
});
