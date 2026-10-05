import { chromium } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// Run against a separately started local preview. This never publishes the site.
const origin = process.env.REVIEW_ORIGIN || 'http://127.0.0.1:4321';
const url = new URL(origin);
if (!['localhost', '127.0.0.1'].includes(url.hostname))
  throw new Error('Review is local only.');
const output = new URL('../review-artifacts/', import.meta.url);
await mkdir(output, { recursive: true });
const browser = await chromium.launch();
const routes = [
  '/',
  '/atheros-search/',
  '/schema-migrator/',
  '/demo/',
  '/accessibility/',
];
const results = [];
try {
  for (const profile of ['desktop', 'mobile']) {
    for (const route of routes) {
      const context = await browser.newContext({
        viewport:
          profile === 'mobile'
            ? { width: 375, height: 812 }
            : { width: 1440, height: 1000 },
        reducedMotion: 'reduce',
      });
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', (error) => errors.push(error.message));
      const cdp = await context.newCDPSession(page);
      await cdp.send('Network.enable');
      await cdp.send('Network.setCacheDisabled', { cacheDisabled: true });
      if (profile === 'mobile') {
        await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
        await cdp.send('Network.emulateNetworkConditions', {
          offline: false,
          latency: 150,
          downloadThroughput: 200000,
          uploadThroughput: 93750,
        });
      }
      await page.addInitScript(() => {
        window.reviewMetrics = { lcp: null, cls: 0, interactions: [] };
        let start = 0,
          last = 0,
          sum = 0;
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries())
            window.reviewMetrics.lcp = entry.startTime;
        }).observe({ type: 'largest-contentful-paint', buffered: true });
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (entry.hadRecentInput) continue;
            if (
              entry.startTime - last > 1000 ||
              entry.startTime - start > 5000
            ) {
              start = entry.startTime;
              sum = 0;
            }
            sum += entry.value;
            last = entry.startTime;
            window.reviewMetrics.cls = Math.max(window.reviewMetrics.cls, sum);
          }
        }).observe({ type: 'layout-shift', buffered: true });
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries())
            if (entry.interactionId)
              window.reviewMetrics.interactions.push(entry.duration);
        }).observe({ type: 'event', buffered: true, durationThreshold: 16 });
      });
      await page.goto(new URL(route, origin).href);
      await page.evaluate(() => document.fonts.ready);
      if (route === '/atheros-search/')
        await page
          .getByLabel('1. Choose a sample query')
          .waitFor({ state: 'visible' });
      const name = route === '/' ? 'hub' : route.replaceAll('/', '');
      for (const theme of ['dark', 'light']) {
        await page.evaluate(
          (value) => (document.documentElement.dataset.theme = value),
          theme,
        );
        await page.screenshot({
          path: fileURLToPath(
            new URL(`${name}-${profile}-${theme}.png`, output),
          ),
          fullPage: true,
        });
      }
      if (route === '/schema-migrator/') {
        await page
          .getByRole('button', { name: '4. Inspect run record' })
          .click();
        await page.getByText('Read all steps as text', { exact: true }).click();
      } else if (route === '/atheros-search/') {
        await page.getByLabel('1. Choose a sample query').selectOption('1');
        await page
          .getByText('3. Open the ranking explanation', { exact: true })
          .click();
      } else {
        await page.locator('#reading-controls > summary').click();
      }
      await page.screenshot({
        path: fileURLToPath(
          new URL(`${name}-${profile}-interaction.png`, output),
        ),
        fullPage: true,
      });
      const metrics = await page.evaluate(() => window.reviewMetrics);
      results.push({
        route,
        profile,
        lcpMs: metrics.lcp,
        cls: metrics.cls,
        maxObservedEventMs: metrics.interactions.length
          ? Math.max(...metrics.interactions)
          : null,
        errors,
      });
      await context.close();
    }
  }
  await writeFile(
    new URL('lab-results.json', output),
    JSON.stringify(
      {
        note: 'Single local cold-cache runs. Mobile: 4x CPU, 150ms latency, 1.6Mbps download. Event durations are a lab proxy, not field INP; null means no event above the 16ms observer floor. LCP and CLS are observed only through these sample interactions.',
        results,
      },
      null,
      2,
    ),
  );
  console.log(JSON.stringify(results, null, 2));
} finally {
  await browser.close();
}
