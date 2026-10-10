export interface ThroughputPoint {
  bucketStart: string;
  records: number;
}

export interface ThroughputSeries {
  bucket: 'hour';
  series: ThroughputPoint[];
}

export interface LifetimeTotals {
  recordsTotal: number;
  daysCounted: number;
  computedAt: string;
}

export interface Stats {
  asOf: string;
  peaksComputedAt: string | null;
  peakRecordsDay: number | null;
  peakRecordsDayDate: string | null;
  peakRecordsWeek: number | null;
  peakRecordsWeekStart: string | null;
  peakRecordsWeekEnd: string | null;
  liveStrip: {
    ingestProcessedRatePerSec: number;
    pendingLedgerCount: number;
    brokerLagCount: number | null;
    lastIngestSuccessAt: string | null;
    backpressureActive: boolean;
  } | null;
  lifetimeTotals: LifetimeTotals | null;
  throughput24h: ThroughputSeries | null;
  throughput7d: ThroughputSeries | null;
}

// Must cover the 30-second store publish cadence plus the reader fallback hop
// and clock slack.
export const maxStatsAgeMs = 180_000;
// Must cover Octopus peaks-refresh-seconds (300) plus fetch and clock slack.
export const maxPeaksAgeMs = 360_000;
export const throughput24hBuckets = 24;
export const throughput7dBuckets = 168;
const hourMs = 3_600_000;
const object = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null;
const count = (v: unknown): v is number =>
  typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const instant = (v: unknown): v is string =>
  typeof v === 'string' && /T.*Z$/.test(v) && Number.isFinite(Date.parse(v));
const day = (v: unknown): v is string =>
  typeof v === 'string' &&
  /^\d{4}-\d{2}-\d{2}$/.test(v) &&
  Number.isFinite(Date.parse(v)) &&
  new Date(v).toISOString().slice(0, 10) === v;

export function isFresh(value: string, now: number, maxAge: number) {
  const age = now - Date.parse(value);
  return age >= -5_000 && age <= maxAge;
}

// A partial refresh cannot erase already measured historical sections. Keep
// each section intact, including its original computation/bucket timestamps.
// Live gauges always come from the new response, never from an older part.
export function retainHistory(current: Stats, previous?: Stats): Stats {
  if (!previous) return current;
  const measuredEmpty = current.lifetimeTotals?.recordsTotal === 0;
  const lostPeak =
    (previous.peakRecordsDay !== null && current.peakRecordsDay === null) ||
    (previous.peakRecordsWeek !== null && current.peakRecordsWeek === null);
  const keepPeaks =
    previous.peaksComputedAt !== null &&
    (current.peaksComputedAt === null || (lostPeak && !measuredEmpty));
  return {
    ...current,
    ...(keepPeaks
      ? {
          peaksComputedAt: previous.peaksComputedAt,
          peakRecordsDay: previous.peakRecordsDay,
          peakRecordsDayDate: previous.peakRecordsDayDate,
          peakRecordsWeek: previous.peakRecordsWeek,
          peakRecordsWeekStart: previous.peakRecordsWeekStart,
          peakRecordsWeekEnd: previous.peakRecordsWeekEnd,
        }
      : {}),
    lifetimeTotals: current.lifetimeTotals ?? previous.lifetimeTotals,
    throughput24h: current.throughput24h ?? previous.throughput24h,
    throughput7d: current.throughput7d ?? previous.throughput7d,
  };
}

// A measured series object is full length and contiguous; a measured bucket may
// honestly be 0. Absent or null means never computed, never an empty zero chart.
const throughputSeries = (
  v: unknown,
  length: number,
): v is ThroughputSeries => {
  if (
    !object(v) ||
    v.bucket !== 'hour' ||
    !Array.isArray(v.series) ||
    v.series.length !== length
  )
    return false;
  let previous = Number.NaN;
  for (const raw of v.series) {
    if (!object(raw) || !instant(raw.bucketStart) || !count(raw.records))
      return false;
    const start = Date.parse(raw.bucketStart);
    if (Number.isFinite(previous) && start - previous !== hourMs) return false;
    previous = start;
  }
  return true;
};

// Validate at both the server and browser boundary; missing data is never zero.
export function parseStats(value: unknown, now = Date.now()): Stats {
  if (
    !object(value) ||
    !instant(value.asOf) ||
    Date.parse(value.asOf) > now + 5_000
  )
    throw new Error('Invalid snapshot timestamp');
  const v = value;
  if (
    !(v.peaksComputedAt === null || instant(v.peaksComputedAt)) ||
    !(
      (v.peakRecordsDay === null && v.peakRecordsDayDate === null) ||
      (count(v.peakRecordsDay) && day(v.peakRecordsDayDate))
    ) ||
    !(
      (v.peakRecordsWeek === null &&
        v.peakRecordsWeekStart === null &&
        v.peakRecordsWeekEnd === null) ||
      (count(v.peakRecordsWeek) &&
        day(v.peakRecordsWeekStart) &&
        day(v.peakRecordsWeekEnd) &&
        new Date(v.peakRecordsWeekStart).getUTCDay() === 1 &&
        Date.parse(v.peakRecordsWeekEnd) -
          Date.parse(v.peakRecordsWeekStart) ===
          6 * 86400_000)
    )
  )
    throw new Error('Invalid peaks');
  const live = v.liveStrip;
  if (
    live !== null &&
    (!object(live) ||
      typeof live.ingestProcessedRatePerSec !== 'number' ||
      !Number.isFinite(live.ingestProcessedRatePerSec) ||
      live.ingestProcessedRatePerSec < 0 ||
      !count(live.pendingLedgerCount) ||
      !(
        live.brokerLagCount === undefined ||
        live.brokerLagCount === null ||
        count(live.brokerLagCount)
      ) ||
      typeof live.backpressureActive !== 'boolean' ||
      !(
        live.lastIngestSuccessAt === null ||
        (instant(live.lastIngestSuccessAt) &&
          Date.parse(live.lastIngestSuccessAt) <= Date.parse(value.asOf))
      ))
  )
    throw new Error('Invalid pipeline metrics');
  // Absent is missing, not zero; present values must be fully valid.
  const lifetime = v.lifetimeTotals;
  if (
    lifetime !== null &&
    lifetime !== undefined &&
    (!object(lifetime) ||
      !count(lifetime.recordsTotal) ||
      !count(lifetime.daysCounted) ||
      !instant(lifetime.computedAt))
  )
    throw new Error('Invalid lifetime totals');
  const t24 = v.throughput24h;
  if (
    t24 !== null &&
    t24 !== undefined &&
    !throughputSeries(t24, throughput24hBuckets)
  )
    throw new Error('Invalid 24h throughput');
  const t7d = v.throughput7d;
  if (
    t7d !== null &&
    t7d !== undefined &&
    !throughputSeries(t7d, throughput7dBuckets)
  )
    throw new Error('Invalid 7d throughput');
  const strip = live as Stats['liveStrip'];
  // Allowlist fields so an upstream change cannot expose internal metadata.
  return {
    asOf: v.asOf as string,
    peaksComputedAt: v.peaksComputedAt as string | null,
    peakRecordsDay: v.peakRecordsDay as number | null,
    peakRecordsDayDate: v.peakRecordsDayDate as string | null,
    peakRecordsWeek: v.peakRecordsWeek as number | null,
    peakRecordsWeekStart: v.peakRecordsWeekStart as string | null,
    peakRecordsWeekEnd: v.peakRecordsWeekEnd as string | null,
    liveStrip:
      strip === null
        ? null
        : {
            ingestProcessedRatePerSec: strip.ingestProcessedRatePerSec,
            pendingLedgerCount: strip.pendingLedgerCount,
            brokerLagCount: strip.brokerLagCount ?? null,
            lastIngestSuccessAt: strip.lastIngestSuccessAt,
            backpressureActive: strip.backpressureActive,
          },
    lifetimeTotals:
      lifetime === null || lifetime === undefined
        ? null
        : {
            recordsTotal: lifetime.recordsTotal as number,
            daysCounted: lifetime.daysCounted as number,
            computedAt: lifetime.computedAt as string,
          },
    throughput24h:
      t24 === null || t24 === undefined
        ? null
        : {
            bucket: 'hour',
            series: (t24.series as ThroughputPoint[]).map((point) => ({
              bucketStart: point.bucketStart,
              records: point.records,
            })),
          },
    throughput7d:
      t7d === null || t7d === undefined
        ? null
        : {
            bucket: 'hour',
            series: (t7d.series as ThroughputPoint[]).map((point) => ({
              bucketStart: point.bucketStart,
              records: point.records,
            })),
          },
  };
}
