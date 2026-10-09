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
    lastIngestSuccessAt: string | null;
    backpressureActive: boolean;
  } | null;
}

export const maxStatsAgeMs = 90_000;
export const maxPeaksAgeMs = 120_000;
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

// Validate at both the server and browser boundary; missing data is never zero.
export function parseStats(value: unknown, now = Date.now()): Stats {
  if (
    !object(value) ||
    !instant(value.asOf) ||
    !isFresh(value.asOf, now, maxStatsAgeMs)
  )
    throw new Error('Stale metrics');
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
      typeof live.backpressureActive !== 'boolean' ||
      !(
        live.lastIngestSuccessAt === null ||
        (instant(live.lastIngestSuccessAt) &&
          Date.parse(live.lastIngestSuccessAt) <= Date.parse(value.asOf))
      ))
  )
    throw new Error('Invalid pipeline metrics');
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
            lastIngestSuccessAt: strip.lastIngestSuccessAt,
            backpressureActive: strip.backpressureActive,
          },
  };
}
