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

export default function OctopusOperationalStats() {
  const [stats, setStats] = createSignal<Stats | null>(null);
  const [state, setState] = createSignal<'loading' | 'ready' | 'unavailable'>(
    'loading',
  );
  const [now, setNow] = createSignal(Date.now());
  const fresh = () =>
    state() === 'ready' &&
    stats() !== null &&
    isFresh(stats()!.asOf, now(), maxStatsAgeMs);
  const live = () => (fresh() ? stats()!.liveStrip : null);
  const peaks = () =>
    fresh() &&
    stats()!.peaksComputedAt !== null &&
    isFresh(stats()!.peaksComputedAt!, now(), maxPeaksAgeMs);
  const weekInProgress = () =>
    peaks() &&
    stats()!.peakRecordsWeekStart !== null &&
    stats()!.asOf.slice(0, 10) >= stats()!.peakRecordsWeekStart! &&
    stats()!.asOf.slice(0, 10) <= stats()!.peakRecordsWeekEnd!;

  onMount(() => {
    let disposed = false;
    let controller: AbortController | undefined;
    const refresh = async () => {
      if (controller) return;
      controller = new AbortController();
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
          setNow(Date.now());
          setStats(data);
          setState('ready');
        }
      } catch {
        if (!disposed) {
          setStats(null);
          setState('unavailable');
        }
      } finally {
        clearTimeout(timeout);
        controller = undefined;
      }
    };
    void refresh();
    const poll = setInterval(() => {
      if (!document.hidden) void refresh();
    }, 30_000);
    const age = setInterval(() => setNow(Date.now()), 1_000);
    const visible = () => {
      setNow(Date.now());
      if (!document.hidden) void refresh();
    };
    document.addEventListener('visibilitychange', visible);
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
      data-live={live() ? 'true' : 'false'}
    >
      <div class="ops-feed-header">
        <p class="ops-status" role="status">
          <span
            class="ops-status-dot"
            data-live={live() ? 'true' : 'false'}
            aria-hidden="true"
          />
          {state() === 'loading'
            ? 'Connecting to production'
            : live()
              ? 'Live production data'
              : 'Live metrics unavailable'}
        </p>
        <p class="fine-print">Refreshes every 30 seconds</p>
      </div>
      <div class="ops-snapshot">
        <h3>Pipeline now</h3>
        <dl class="ops-metrics">
          <div>
            <dt>Ledger processing / second</dt>
            <dd data-metric="rate">
              {live()
                ? `${rate.format(live()!.ingestProcessedRatePerSec)} records/s`
                : 'Unavailable'}
            </dd>
            <p class="fine-print">Average over the last 5 minutes</p>
          </div>
          <div>
            <dt>Records waiting</dt>
            <dd data-metric="pending">
              {live()
                ? number.format(live()!.pendingLedgerCount)
                : 'Unavailable'}
            </dd>
            <p class="fine-print">Pending or being processed</p>
          </div>
          <div>
            <dt>Last successful processing check</dt>
            <dd data-metric="success">
              <Show when={live()?.lastIngestSuccessAt} fallback="Unavailable">
                {(value) => (
                  <time datetime={value()}>{timestamp(value())}</time>
                )}
              </Show>
            </dd>
          </div>
          <div>
            <dt>Intake control</dt>
            <dd data-metric="backpressure">
              {live()
                ? live()!.backpressureActive
                  ? 'Paused to drain backlog'
                  : 'Accepting work'
                : 'Unavailable'}
            </dd>
          </div>
        </dl>
        <Show when={live()}>
          <p class="fine-print">
            Measured{' '}
            <time datetime={stats()!.asOf}>{timestamp(stats()!.asOf)}</time>
          </p>
        </Show>
      </div>
      <div class="ops-history">
        <h3>Busiest recorded periods</h3>
        <div class="ops-peaks">
          <article class="ops-card" aria-labelledby="ops-day-title">
            <h4 id="ops-day-title">Peak day</h4>
            <p class="ops-count" data-metric="day">
              {peaks() && stats()!.peakRecordsDay !== null
                ? `${number.format(stats()!.peakRecordsDay!)} records`
                : 'Unavailable'}
            </p>
            <Show when={peaks() && stats()!.peakRecordsDayDate}>
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
              {peaks() && stats()!.peakRecordsWeek !== null
                ? `${number.format(stats()!.peakRecordsWeek!)} records`
                : 'Unavailable'}
            </p>
            <Show when={peaks() && stats()!.peakRecordsWeekStart}>
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
        <Show when={peaks()}>
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
