import { test, expect } from '@playwright/test';
import { parseStats } from '../src/data/operational-stats';
import { onRequestGet } from '../functions/api/octopus-stats';
import { octopusMetrics } from '../src/data/products';

const captured = new Date('2026-10-09T12:00:00Z');
const hourMs = 3_600_000;
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
// Contiguous hourly buckets ending at `end`. `gapAt` breaks one step on purpose.
const hourlySeries = (
  end: Date,
  length: number,
  recordsAt: (i: number) => number,
  gapAt?: number,
) => ({
  bucket: 'hour' as const,
  series: Array.from({ length }, (_, i) => ({
    bucketStart: new Date(
      end.getTime() - (length - 1 - i) * hourMs + (gapAt === i ? hourMs : 0),
    ).toISOString(),
    records: recordsAt(i),
  })),
});
const withThroughput = (offset = 0, count = 123) => ({
  ...reading(offset, count),
  lifetimeTotals: {
    recordsTotal: 45_678,
    daysCounted: 90,
    computedAt: new Date(captured.getTime() + offset).toISOString(),
  },
  throughput24h: hourlySeries(captured, 24, (i) => (i % 5) * 3),
  throughput7d: hourlySeries(captured, 168, (i) => i % 24),
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
      : route.fulfill({ json: withThroughput(offset, calls * 123) });
  });
  await page.goto('/octopus/');
  const widget = page.locator('[data-ux="ops-stats"]');
  await expect(widget).toHaveAttribute('data-live', 'true');
  await expect(widget).toHaveAttribute('data-mode', 'live');
  await expect(page.locator('[data-metric="day"]')).toHaveText('123 records');
  await expect(page.locator('[data-metric="backpressure"]')).toHaveText(
    'Accepting work',
  );
  await expect(page.locator('[data-metric="lifetime-records"]')).toHaveText(
    '45,678',
  );
  await expect(page.locator('[data-metric="lifetime-days"]')).toHaveText('90');
  await expect(page.locator('.ops-bars .ops-bar-row')).toHaveCount(24);
  await expect(page.locator('.ops-spark-bar')).toHaveCount(168);
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

test('partial readings explain warmup and missing history without displaying invented metrics', async ({
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
  await expect(
    page.getByText(octopusMetrics.warmup, { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(octopusMetrics.missingHistory, { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(octopusMetrics.missingThroughput, { exact: true }),
  ).toBeVisible();
  await expect(page.locator('[data-metric]')).toHaveCount(0);
  await expect(page.locator('.ops-bars')).toHaveCount(0);
  await expect(page.locator('.ops-spark')).toHaveCount(0);
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
  // maxStatsAgeMs is 180 seconds; readings expire after that window.
  await page.clock.runFor(182_000);
  await expect(page.locator('[data-ux="ops-stats"]')).toHaveAttribute(
    'data-live',
    'false',
  );
  await expect(page.locator('[data-ux="ops-stats"]')).toHaveAttribute(
    'data-mode',
    'unavailable',
  );
  await expect(page.locator('[data-metric]')).toHaveCount(0);
  await expect(page.locator('.ops-empty')).toContainText(
    octopusMetrics.empty.description,
  );
  await expect(page.locator('[data-ux="ops-stats"] time')).toHaveCount(0);
});

test('a failed feed shows a workflow path and automatically recovers to measured data', async ({
  page,
}) => {
  await page.clock.install({ time: captured });
  let calls = 0;
  await page.route('**/api/octopus-stats', (route) => {
    calls++;
    return calls === 1
      ? route.fulfill({ status: 503, json: { error: 'unavailable' } })
      : route.fulfill({ json: withThroughput(5_000) });
  });
  await page.goto('/octopus/');
  const widget = page.locator('[data-ux="ops-stats"]');
  await expect(widget).toHaveAttribute('data-mode', 'unavailable');
  await expect(widget.locator('[data-metric], time')).toHaveCount(0);
  await expect(widget).toContainText(octopusMetrics.empty.retry);
  await widget.getByRole('link', { name: octopusMetrics.empty.link }).click();
  await expect(page.locator('#workflow-title')).toBeInViewport();
  await page.clock.runFor(5_000);
  await expect(widget).toHaveAttribute('data-mode', 'live');
  await expect(widget.locator('.ops-empty')).toHaveCount(0);
  await expect(widget.locator('[data-metric="day"]')).toHaveText('123 records');
  await expect(widget.locator('.ops-bar-row')).toHaveCount(24);
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

test('lifetime totals and hourly throughput series parse when measured', () => {
  const parsed = parseStats(withThroughput(), captured.getTime());
  expect(parsed.lifetimeTotals).toEqual({
    recordsTotal: 45_678,
    daysCounted: 90,
    computedAt: captured.toISOString(),
  });
  expect(parsed.throughput24h!.bucket).toBe('hour');
  expect(parsed.throughput24h!.series).toHaveLength(24);
  expect(parsed.throughput7d!.series).toHaveLength(168);
  // A measured bucket may honestly be zero.
  expect(parsed.throughput24h!.series[0].records).toBe(0);
  expect(parsed.throughput24h!.series[0].bucketStart).toBe(
    new Date(captured.getTime() - 23 * hourMs).toISOString(),
  );
});

test('null or absent totals and series stay missing rather than zero', () => {
  for (const payload of [
    reading(),
    {
      ...reading(),
      lifetimeTotals: null,
      throughput24h: null,
      throughput7d: null,
    },
  ]) {
    const parsed = parseStats(payload, captured.getTime());
    expect(parsed.lifetimeTotals).toBeNull();
    expect(parsed.throughput24h).toBeNull();
    expect(parsed.throughput7d).toBeNull();
  }
});

test('response validation rejects wrong series lengths and broken hours', () => {
  const valid = withThroughput();
  for (const invalid of [
    {
      ...valid,
      throughput24h: hourlySeries(captured, 23, () => 1),
    },
    {
      ...valid,
      throughput24h: hourlySeries(captured, 25, () => 1),
    },
    {
      ...valid,
      throughput7d: hourlySeries(captured, 167, () => 1),
    },
    {
      ...valid,
      throughput7d: hourlySeries(captured, 169, () => 1),
    },
    // Non-contiguous: one bucket is two hours after its predecessor.
    {
      ...valid,
      throughput24h: hourlySeries(captured, 24, () => 1, 10),
    },
    {
      ...valid,
      throughput7d: hourlySeries(captured, 168, () => 1, 80),
    },
    {
      ...valid,
      throughput24h: { ...valid.throughput24h, bucket: 'day' },
    },
    {
      ...valid,
      throughput24h: {
        bucket: 'hour',
        series: valid.throughput24h.series.map((point, i) =>
          i === 3 ? { ...point, records: -1 } : point,
        ),
      },
    },
    {
      ...valid,
      throughput24h: {
        bucket: 'hour',
        series: valid.throughput24h.series.map((point, i) =>
          i === 3 ? { ...point, records: 1.5 } : point,
        ),
      },
    },
    {
      ...valid,
      throughput24h: {
        bucket: 'hour',
        series: valid.throughput24h.series.map((point, i) =>
          i === 3 ? { ...point, bucketStart: 'not-a-timestamp' } : point,
        ),
      },
    },
    {
      ...valid,
      lifetimeTotals: { ...valid.lifetimeTotals, recordsTotal: -1 },
    },
    {
      ...valid,
      lifetimeTotals: { ...valid.lifetimeTotals, computedAt: 'yesterday' },
    },
  ])
    expect(() => parseStats(invalid, captured.getTime())).toThrow();
});

test('response validation rejects stale asOf and strips unknown keys', () => {
  // Fresh inside the 180-second window, stale beyond it.
  expect(() =>
    parseStats(reading(0), captured.getTime() + 180_000),
  ).not.toThrow();
  expect(() => parseStats(reading(0), captured.getTime() + 181_000)).toThrow();
  const parsed = parseStats(
    {
      ...withThroughput(),
      internalHost: 'private.example',
      lifetimeTotals: {
        recordsTotal: 1,
        daysCounted: 1,
        computedAt: captured.toISOString(),
        sourceQuery: 'select secret',
      },
      throughput24h: {
        bucket: 'hour',
        series: withThroughput().throughput24h.series.map((point) => ({
          ...point,
          debugNote: 'internal',
        })),
        watermark: 'internal',
      },
    },
    captured.getTime(),
  );
  expect(parsed).not.toHaveProperty('internalHost');
  expect(parsed.lifetimeTotals).not.toHaveProperty('sourceQuery');
  expect(parsed.throughput24h).not.toHaveProperty('watermark');
  expect(parsed.throughput24h!.series[0]).toEqual({
    bucketStart: parsed.throughput24h!.series[0].bucketStart,
    records: parsed.throughput24h!.series[0].records,
  });
  expect(Object.keys(parsed).sort()).toEqual(
    [
      'asOf',
      'lifetimeTotals',
      'liveStrip',
      'peakRecordsDay',
      'peakRecordsDayDate',
      'peakRecordsWeek',
      'peakRecordsWeekEnd',
      'peakRecordsWeekStart',
      'peaksComputedAt',
      'throughput24h',
      'throughput7d',
    ].sort(),
  );
});

test('Pages proxy passes only measured public fields and fails closed', async () => {
  const original = globalThis.fetch;
  const request = new Request('https://rclabs.uk/api/octopus-stats');
  const measured = {
    ...withThroughput(),
    asOf: new Date().toISOString(),
    peaksComputedAt: new Date().toISOString(),
    lifetimeTotals: {
      ...withThroughput().lifetimeTotals,
      computedAt: new Date().toISOString(),
    },
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

test('Pages proxy accepts a full-size snapshot inside the raised body cap', async () => {
  const original = globalThis.fetch;
  const request = new Request('https://rclabs.uk/api/octopus-stats');
  const full = {
    ...withThroughput(),
    asOf: new Date().toISOString(),
    peaksComputedAt: new Date().toISOString(),
    lifetimeTotals: {
      ...withThroughput().lifetimeTotals,
      computedAt: new Date().toISOString(),
    },
  };
  const text = JSON.stringify(full);
  // 168 buckets must fit; the previous 8192 cap rejected this payload.
  expect(text.length).toBeGreaterThan(8192);
  expect(text.length).toBeLessThanOrEqual(16384);
  try {
    globalThis.fetch = async () =>
      new Response(text, {
        headers: { 'content-type': 'application/json' },
      });
    const response = await onRequestGet({ request });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.throughput7d.series).toHaveLength(168);
    globalThis.fetch = async () =>
      new Response(`${text}${'x'.repeat(16385 - text.length + 1)}`, {
        headers: { 'content-type': 'application/json' },
      });
    expect((await onRequestGet({ request })).status).toBe(503);
  } finally {
    globalThis.fetch = original;
  }
});
