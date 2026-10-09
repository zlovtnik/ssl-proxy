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
  '/products/',
  '/vpn-proxy/',
  '/atheros-search/',
  '/schema-migrator/',
  '/octopus/',
  '/demo/',
  '/accessibility/',
  '/privacy/',
];
const results = [];
async function reviewPage(profile, route) {
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
        if (entry.startTime - last > 1000 || entry.startTime - start > 5000) {
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
      .getByLabel('1. Choose a monitored sample site')
      .waitFor({ state: 'visible' });
  const name = route === '/' ? 'hub' : route.replaceAll('/', '');
  async function captureState(state) {
    await page.screenshot({
      path: fileURLToPath(new URL(`${name}-${profile}-${state}.png`, output)),
      fullPage: true,
    });
  }
  await captureState('dark');
  if (route === '/schema-migrator/') {
    await page.getByRole('button', { name: '4. Inspect run record' }).click();
    await page.getByText('Read all steps as text', { exact: true }).click();
  } else if (route === '/atheros-search/') {
    await page
      .getByLabel('1. Choose a monitored sample site')
      .selectOption('1');
    await page
      .getByText('3. Review why the indicator was raised', { exact: true })
      .click();
  } else {
    const disclosure = page.locator('main details:visible').first();
    if (await disclosure.count()) {
      await disclosure.locator('summary').click();
    } else {
      await page.getByRole('link', { name: 'Skip to content' }).focus();
    }
  }
  await page.screenshot({
    path: fileURLToPath(new URL(`${name}-${profile}-interaction.png`, output)),
    fullPage: true,
  });
  const metrics = await page.evaluate(() => window.reviewMetrics);
  // Capture each synthetic state after collecting the initial lab sample.
  // These screenshots are visual evidence, not additional performance runs.
  if (route === '/' || route === '/atheros-search/') {
    if (route === '/') {
      const filter = page.getByLabel('Filter sample sites, indicators, and observations');
      for (const [index, record] of (await page.locator('.preview-record').all()).entries()) {
        await record.click();
        await captureState(`search-${index}`);
      }
      await filter.fill('no-matching-record');
      await captureState('search-empty');
      await filter.fill('');
    } else {
      for (const sample of ['0', '1']) {
        await page.getByLabel('1. Choose a monitored sample site').selectOption(sample);
        await captureState(`search-${sample}`);
      }
    }
  }
  if (route === '/' || route === '/schema-migrator/') {
    if (route === '/')
      await page.getByRole('button', { name: 'Schema Migrator', exact: true }).click();
    const steps = await page.locator(route === '/' ? '.preview-steps button' : '.step-controls button').all();
    for (const [index, step] of steps.entries()) {
      await step.click();
      await captureState(`migrator-${index}`);
    }
  }
  if (route === '/' || route === '/vpn-proxy/') {
    if (route === '/')
      await page.getByRole('button', { name: 'RCLabs VPN / Proxy', exact: true }).click();
    const flow = page.getByLabel('Sample traffic flow', { exact: true });
    for (const option of await flow.locator('option').all()) {
      const value = await option.getAttribute('value');
      await flow.selectOption(value);
      await captureState(`vpn-${value}`);
    }
  }
  const result = {
    route,
    profile,
    lcpMs: metrics.lcp,
    cls: metrics.cls,
    maxObservedEventMs: metrics.interactions.length
      ? Math.max(...metrics.interactions)
      : null,
    errors,
  };
  await context.close();
  return result;
}

// Yield lazily: only one measured page may use the browser/CPU at a time.
// Parallel page loads would contaminate the cold-cache performance samples.
function* reviewRuns() {
  for (const profile of ['desktop', 'mobile']) {
    for (const route of routes) {
      yield reviewPage(profile, route);
    }
  }
}

try {
  for await (const result of reviewRuns()) results.push(result);
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
