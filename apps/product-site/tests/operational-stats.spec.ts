import { test, expect } from '@playwright/test';
import { parseStats } from '../src/data/operational-stats';
import { onRequestGet } from '../functions/api/octopus-stats';

const captured = new Date('2026-10-09T12:00:00Z');
// These are isolated test responses, never imported by the site or its API.
const reading = (offset = 0, count = 123) => ({
  asOf: new Date(captured.getTime() + offset).toISOString(),
  peaksComputedAt: new Date(captured.getTime() + offset).toISOString(),
  peakRecordsDay: count,
  peakRecordsDayDate: '2026-10-08',
  peakRecordsWeek: count * 2,
  peakRecordsWeekStart: '2026-10-05',
  peakRecordsWeekEnd: '2026-10-11',
  liveStrip: {
    ingestProcessedRatePerSec: count / 10,
    pendingLedgerCount: count,
    lastIngestSuccessAt: captured.toISOString(),
    backpressureActive: count > 200,
  },
});

test('new responses update every displayed metric; a failed poll keeps the last reading then recovers', async ({
  page,
}) => {
  await page.clock.install({ time: captured });
  let calls = 0;
  // Route handlers run in Node; keep a mock-clock offset for asOf stamps.
  let offset = 0;
  await page.route('**/api/octopus-stats', (route) => {
    calls++;
    return calls === 3
      ? route.fulfill({ status: 503, json: { error: 'unavailable' } })
      : route.fulfill({ json: reading(offset, calls * 123) });
  });
  await page.goto('/octopus/');
  const widget = page.locator('[data-ux="ops-stats"]');
  await expect(widget).toHaveAttribute('data-live', 'true');
  await expect(widget).toHaveAttribute('data-mode', 'live');
  await expect(page.locator('[data-metric="day"]')).toHaveText('123 records');
  await expect(page.locator('[data-metric="backpressure"]')).toHaveText(
    'Accepting work',
  );
  offset = 30_000;
  await page.clock.runFor(30_000);
  await expect(page.locator('[data-metric="day"]')).toHaveText('246 records');
  await expect(page.locator('[data-metric="week"]')).toHaveText('492 records');
  await expect(page.locator('[data-metric="rate"]')).toHaveText(
    '24.6 records/s',
  );
  await expect(page.locator('[data-metric="pending"]')).toHaveText('246');
  await expect(page.locator('[data-metric="backpressure"]')).toHaveText(
    'Paused to drain backlog',
  );
  // Failed poll: retain the last fresh reading, clearly not live.
  offset = 65_000;
  await page.clock.runFor(30_000);
  await expect(widget).toHaveAttribute('data-live', 'false');
  await expect(widget).toHaveAttribute('data-mode', 'delayed');
  await expect(page.locator('[data-metric="day"]')).toHaveText('246 records');
  await expect(page.locator('[data-metric="rate"]')).toHaveText(
    '24.6 records/s',
  );
  await expect(page.getByRole('status')).toHaveText('Live metrics delayed');
  // Faster retry recovers onto the next successful payload.
  await page.clock.runFor(30_000);
  await expect(widget).toHaveAttribute('data-live', 'true');
  await expect(page.locator('[data-metric="day"]')).toHaveText('492 records');
});

test('old peaks expire independently and missing readings never become zero', async ({
  page,
}) => {
  await page.clock.install({ time: captured });
  await page.route('**/api/octopus-stats', (route) =>
    route.fulfill({
      json: {
        ...reading(),
        peaksComputedAt: new Date(captured.getTime() - 361_000).toISOString(),
        liveStrip: null,
      },
    }),
  );
  await page.goto('/octopus/');
  await expect(page.getByRole('status')).toHaveText(
    'Production connected · warming up',
  );
  await expect(page.locator('[data-metric="day"]')).toHaveText('Unavailable');
  await expect(page.locator('[data-metric="week"]')).toHaveText('Unavailable');
  await expect(page.locator('[data-metric="rate"]')).toHaveText('Warming up');
  await expect(page.locator('[data-metric="pending"]')).toHaveText('Warming up');
});

test('repeated cached responses lose live status when the source timestamp expires', async ({
  page,
}) => {
  await page.clock.install({ time: captured });
  await page.route('**/api/octopus-stats', (route) =>
    route.fulfill({ json: reading() }),
  );
  await page.goto('/octopus/');
  await expect(page.locator('[data-ux="ops-stats"]')).toHaveAttribute(
    'data-live',
    'true',
  );
  await page.clock.runFor(92_000);
  await expect(page.locator('[data-ux="ops-stats"]')).toHaveAttribute(
    'data-live',
    'false',
  );
  await expect(page.locator('[data-ux="ops-stats"]')).toHaveAttribute(
    'data-mode',
    'unavailable',
  );
  await expect(page.locator('[data-metric="pending"]')).toHaveText(
    'Unavailable',
  );
});

test('response validation rejects missing fields, invalid numbers, dates and timestamps', () => {
  const valid = reading();
  expect(parseStats(valid, captured.getTime()).peakRecordsDay).toBe(123);
  for (const invalid of [
    {},
    { ...valid, asOf: '2020-01-01T00:00:00Z' },
    { ...valid, asOf: '2030-01-01T00:00:00Z' },
    { ...valid, peakRecordsDay: -1 },
    { ...valid, peakRecordsDayDate: '2026-02-30' },
    { ...valid, peakRecordsWeekEnd: '2026-10-12' },
    { ...valid, liveStrip: {} },
    {
      ...valid,
      liveStrip: { ...valid.liveStrip, ingestProcessedRatePerSec: NaN },
    },
    {
      ...valid,
      liveStrip: { ...valid.liveStrip, backpressureActive: 'false' },
    },
  ])
    expect(() => parseStats(invalid, captured.getTime())).toThrow();
});

test('Pages proxy passes only measured public fields and fails closed', async () => {
  const original = globalThis.fetch;
  const request = new Request('https://rclabs.uk/api/octopus-stats');
  const measured = {
    ...reading(),
    asOf: new Date().toISOString(),
    peaksComputedAt: new Date().toISOString(),
    internalHost: 'private.example',
  };
  try {
    let calls = 0;
    globalThis.fetch = async () => {
      calls++;
      return Response.json(measured);
    };
    const response = await onRequestGet({ request });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).not.toHaveProperty('internalHost');
    expect(
      (
        await onRequestGet({
          request: new Request('https://branch.pages.dev/api/octopus-stats'),
        })
      ).status,
    ).toBe(503);
    expect(calls).toBe(1);
    globalThis.fetch = async () =>
      new Response('upstream failed', { status: 500 });
    expect((await onRequestGet({ request })).status).toBe(503);
    globalThis.fetch = async () =>
      Response.json({ ...measured, asOf: '2020-01-01T00:00:00Z' });
    expect((await onRequestGet({ request })).status).toBe(503);
  } finally {
    globalThis.fetch = original;
  }
});
