import { createSignal, onMount, onCleanup, Show } from 'solid-js';
import {
  isFresh,
  maxPeaksAgeMs,
  maxStatsAgeMs,
  parseStats,
  type Stats,
} from '../data/operational-stats';

const number = new Intl.NumberFormat('en-GB', { maximumFractionDigits: 2 });
const rate = new Intl.NumberFormat('en-GB', { maximumFractionDigits: 3 });
const dayFmt = new Intl.DateTimeFormat('en-GB', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  timeZone: 'UTC',
});
const timeFmt = new Intl.DateTimeFormat('en-GB', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  timeZone: 'UTC',
});
const date = (v: string) => dayFmt.format(new Date(v));
const timestamp = (v: string) =>
  `${date(v)}, ${timeFmt.format(new Date(v))} UTC`;

type Mode = 'ssr' | 'loading' | 'live' | 'warmup' | 'delayed' | 'unavailable';

const statusText: Record<Mode, string> = {
  ssr: 'Live metrics unavailable',
  loading: 'Connecting to production',
  live: 'Live production data',
  warmup: 'Production connected · warming up',
  delayed: 'Live metrics delayed',
  unavailable: 'Live metrics unavailable',
};

export default function OctopusOperationalStats() {
  const [stats, setStats] = createSignal<Stats | null>(null);
  const [fetchState, setFetchState] = createSignal<
    'idle' | 'loading' | 'ok' | 'failed'
  >('idle');
  const [now, setNow] = createSignal(Date.now());

  const asOfFresh = () =>
    stats() !== null && isFresh(stats()!.asOf, now(), maxStatsAgeMs);
  const peaksReady = () =>
    asOfFresh() &&
    stats()!.peaksComputedAt !== null &&
    isFresh(stats()!.peaksComputedAt!, now(), maxPeaksAgeMs);
  const liveStrip = () =>
    asOfFresh() && stats()!.liveStrip !== null ? stats()!.liveStrip : null;
  const weekInProgress = () =>
    peaksReady() &&
    stats()!.peakRecordsWeekStart !== null &&
    stats()!.asOf.slice(0, 10) >= stats()!.peakRecordsWeekStart! &&
    stats()!.asOf.slice(0, 10) <= stats()!.peakRecordsWeekEnd!;

  const mode = (): Mode => {
    if (fetchState() === 'idle') return 'ssr';
    if (fetchState() === 'loading' && stats() === null) return 'loading';
    if (!asOfFresh()) return 'unavailable';
    if (liveStrip() === null) return 'warmup';
    return fetchState() === 'failed' ? 'delayed' : 'live';
  };

  // Live pipeline cells: never invent zeros; warm-up is not an error.
  // Values are thunks so missing readings cannot throw while formatting.
  const liveCell = (value: () => string) => {
    const m = mode();
    if (m === 'ssr') return 'Unavailable';
    if (m === 'loading') return '—';
    if (m === 'unavailable') return 'Unavailable';
    if (m === 'warmup') return 'Warming up';
    return value();
  };
  // Historical peaks have their own freshness; missing stays unavailable.
  const peakCell = (value: () => string) => {
    const m = mode();
    if (m === 'ssr') return 'Unavailable';
    if (m === 'loading') return '—';
    return peaksReady() && stats() !== null ? value() : 'Unavailable';
  };

  onMount(() => {
    let disposed = false;
    let controller: AbortController | undefined;
    let failStreak = 0;
    const refresh = async () => {
      if (controller) return;
      controller = new AbortController();
      setFetchState((s) => (s === 'idle' ? 'loading' : s));
      const timeout = setTimeout(() => controller?.abort(), 10_000);
      try {
        const response = await fetch('/api/octopus-stats', {
          signal: controller.signal,
          cache: 'no-store',
          headers: { Accept: 'application/json' },
        });
        if (!response.ok) throw new Error('Metrics unavailable');
        const data = parseStats(await response.json());
        if (!disposed) {
          failStreak = 0;
          setNow(Date.now());
          setStats(data);
          setFetchState('ok');
        }
      } catch {
        if (!disposed) {
          failStreak = Math.min(failStreak + 1, 3);
          setNow(Date.now());
          // Retain the last good reading until its freshness window expires.
          setFetchState('failed');
        }
      } finally {
        clearTimeout(timeout);
        controller = undefined;
      }
    };
    let lastAttempt = 0;
    const gapMs = () =>
      failStreak === 0 ? 30_000 : failStreak === 1 ? 5_000 : 10_000;
    const tick = () => {
      if (document.hidden || controller) return;
      if (Date.now() - lastAttempt < gapMs()) return;
      lastAttempt = Date.now();
      void refresh();
    };
    const poll = setInterval(tick, 1_000);
    const age = setInterval(() => setNow(Date.now()), 1_000);
    const visible = () => {
      setNow(Date.now());
      if (!document.hidden && !controller) {
        lastAttempt = Date.now();
        void refresh();
      }
    };
    document.addEventListener('visibilitychange', visible);
    lastAttempt = Date.now();
    void refresh();
    onCleanup(() => {
      disposed = true;
      controller?.abort();
      clearInterval(poll);
      clearInterval(age);
      document.removeEventListener('visibilitychange', visible);
    });
  });

  return (
    <div
      class="ops-widget"
      data-ux="ops-stats"
      data-live={mode() === 'live' ? 'true' : 'false'}
      data-mode={mode()}
    >
      <div class="ops-feed-header">
        <p class="ops-status" role="status" data-active={mode() === 'live'}>
          <span
            class="ops-status-dot"
            data-live={mode() === 'live' ? 'true' : 'false'}
            aria-hidden="true"
          />
          {statusText[mode()]}
        </p>
        <p class="fine-print">Refreshes every 30 seconds</p>
      </div>
      <div class="ops-snapshot">
        <h3>Pipeline now</h3>
        <dl class="ops-metrics">
          <div>
            <dt>
              Ledger processing / second
              <span class="fine-print">Average over the last 5 minutes</span>
            </dt>
            <dd data-metric="rate">
              {liveCell(
                () =>
                  `${rate.format(liveStrip()!.ingestProcessedRatePerSec)} records/s`,
              )}
            </dd>
          </div>
          <div>
            <dt>
              Records waiting
              <span class="fine-print">Pending or being processed</span>
            </dt>
            <dd data-metric="pending">
              {liveCell(() => number.format(liveStrip()!.pendingLedgerCount))}
            </dd>
          </div>
          <div>
            <dt>Last successful processing check</dt>
            <dd data-metric="success">
              <Show
                when={
                  (mode() === 'live' || mode() === 'delayed') &&
                  liveStrip()?.lastIngestSuccessAt
                }
                fallback={liveCell(() => 'Unavailable')}
              >
                <time datetime={liveStrip()!.lastIngestSuccessAt!}>
                  {timestamp(liveStrip()!.lastIngestSuccessAt!)}
                </time>
              </Show>
            </dd>
          </div>
          <div>
            <dt>Intake control</dt>
            <dd data-metric="backpressure">
              {liveCell(() =>
                liveStrip()!.backpressureActive
                  ? 'Paused to drain backlog'
                  : 'Accepting work',
              )}
            </dd>
          </div>
        </dl>
        <Show when={asOfFresh() && mode() !== 'ssr' && mode() !== 'loading'}>
          <p class="fine-print">
            Measured{' '}
            <time datetime={stats()!.asOf}>{timestamp(stats()!.asOf)}</time>
            <Show when={mode() === 'delayed'}>
              {' '}
              · last successful reading, not live
            </Show>
          </p>
        </Show>
      </div>
      <div class="ops-history">
        <h3>Busiest recorded periods</h3>
        <div class="ops-peaks">
          <article class="ops-card" aria-labelledby="ops-day-title">
            <h4 id="ops-day-title">Peak day</h4>
            <p class="ops-count" data-metric="day">
              {peakCell(
                () => `${number.format(stats()!.peakRecordsDay!)} records`,
              )}
            </p>
            <Show when={peaksReady() && stats()!.peakRecordsDayDate}>
              {(value) => (
                <p>
                  <time datetime={value()}>{date(value())}</time> UTC
                </p>
              )}
            </Show>
          </article>
          <article class="ops-card" aria-labelledby="ops-week-title">
            <h4 id="ops-week-title">Peak week</h4>
            <p class="ops-count" data-metric="week">
              {peakCell(
                () => `${number.format(stats()!.peakRecordsWeek!)} records`,
              )}
            </p>
            <Show when={peaksReady() && stats()!.peakRecordsWeekStart}>
              {(value) => (
                <p>
                  <time datetime={value()}>{date(value())}</time> to{' '}
                  <time datetime={stats()!.peakRecordsWeekEnd!}>
                    {date(stats()!.peakRecordsWeekEnd!)}
                  </time>{' '}
                  UTC
                </p>
              )}
            </Show>
            <Show when={weekInProgress()}>
              <p class="fine-print">This week, so far</p>
            </Show>
          </article>
        </div>
        <Show when={peaksReady()}>
          <p class="fine-print">
            History checked{' '}
            <time datetime={stats()!.peaksComputedAt!}>
              {timestamp(stats()!.peaksComputedAt!)}
            </time>
          </p>
        </Show>
      </div>
    </div>
  );
}
