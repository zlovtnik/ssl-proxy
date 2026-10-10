import { createSignal, onMount, onCleanup, Show, For } from 'solid-js';
import { octopusMetrics } from '../data/products';
import {
  isFresh,
  maxStatsAgeMs,
  parseStats,
  type Stats,
  type ThroughputSeries,
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
const hourFmt = new Intl.DateTimeFormat('en-GB', {
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'UTC',
});
const date = (v: string) => dayFmt.format(new Date(v));
const timestamp = (v: string) =>
  `${date(v)}, ${timeFmt.format(new Date(v))} UTC`;
const hourLabel = (v: string) => hourFmt.format(new Date(v));
const seriesMax = (series: ThroughputSeries) =>
  series.series.reduce((m, p) => Math.max(m, p.records), 0);
const fill = (records: number, max: number) =>
  max > 0 ? `${Math.round((records / max) * 100)}%` : '0%';

type Mode =
  | 'ssr'
  | 'loading'
  | 'live'
  | 'warmup'
  | 'delayed'
  | 'historical'
  | 'unavailable';

const statusText: Record<Mode, string> = {
  ssr: 'Production metrics',
  loading: 'Connecting to production',
  live: 'Live production data',
  warmup: 'Production connected · warming up',
  delayed: 'Live metrics delayed',
  historical: 'Latest recorded production data',
  unavailable: 'Waiting for production data',
};

export default function OctopusOperationalStats() {
  const [stats, setStats] = createSignal<Stats | null>(null);
  const [fetchState, setFetchState] = createSignal<
    'idle' | 'loading' | 'ok' | 'failed' | 'historical'
  >('idle');
  const [now, setNow] = createSignal(Date.now());

  const asOfFresh = () =>
    stats() !== null && isFresh(stats()!.asOf, now(), maxStatsAgeMs);
  const peaksReady = () =>
    stats() !== null && stats()!.peaksComputedAt !== null;
  const liveStrip = () =>
    asOfFresh() && fetchState() !== 'historical' && stats()!.liveStrip !== null
      ? stats()!.liveStrip
      : null;
  const weekInProgress = () =>
    peaksReady() &&
    stats()!.peakRecordsWeekStart !== null &&
    stats()!.asOf.slice(0, 10) >= stats()!.peakRecordsWeekStart! &&
    stats()!.asOf.slice(0, 10) <= stats()!.peakRecordsWeekEnd!;

  const mode = (): Mode => {
    if (fetchState() === 'idle') return 'ssr';
    if (fetchState() === 'loading' && stats() === null) return 'loading';
    if (stats() === null) return 'unavailable';
    if (!asOfFresh() || fetchState() === 'historical') return 'historical';
    if (liveStrip() === null)
      return peaksReady() || lifetimeReady() ? 'historical' : 'warmup';
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
  // Historical measurements remain useful after live collection stops.
  const peakCell = (measured: boolean, value: () => string) => {
    const m = mode();
    if (m === 'ssr') return 'Unavailable';
    if (m === 'loading') return '—';
    return peaksReady() && stats() !== null && measured
      ? value()
      : 'Unavailable';
  };
  // Keep the measured history and its timestamps; null stays unavailable.
  const snapshotCell = (ready: boolean, value: () => string) => {
    const m = mode();
    if (m === 'ssr') return 'Unavailable';
    if (m === 'loading') return '—';
    return ready && stats() !== null ? value() : 'Unavailable';
  };
  const lifetimeReady = () =>
    stats() !== null && stats()!.lifetimeTotals !== null;
  const windowReady = (key: 'throughput24h' | 'throughput7d') =>
    stats() !== null &&
    stats()![key] !== null &&
    mode() !== 'ssr' &&
    mode() !== 'loading';
  const windowSeries = (key: 'throughput24h' | 'throughput7d') =>
    windowReady(key) ? stats()![key]! : null;

  onMount(() => {
    const savedKey = 'octopus-stats:v2';
    try {
      const saved = localStorage.getItem(savedKey);
      if (saved) {
        setStats(parseStats(JSON.parse(saved)));
        setFetchState('failed');
      }
    } catch {
      // Storage can be disabled or contain an invalid previous response.
    }
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
          if (!stats() || Date.parse(data.asOf) >= Date.parse(stats()!.asOf)) {
            setStats(data);
            try {
              localStorage.setItem(savedKey, JSON.stringify(data));
            } catch {
              // Persistence failure must not discard a measured response.
            }
          }
          setFetchState(
            response.headers.get('X-Metrics-State') === 'historical'
              ? 'historical'
              : 'ok',
          );
        }
      } catch {
        if (!disposed) {
          failStreak = Math.min(failStreak + 1, 3);
          setNow(Date.now());
          // Keep measured history through failures, including after expiry.
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
      <Show
        when={stats() !== null}
        fallback={
          <div class="ops-empty">
            <h3>
              {mode() === 'loading'
                ? octopusMetrics.empty.loadingTitle
                : octopusMetrics.empty.title}
            </h3>
            <p>
              {mode() === 'loading'
                ? octopusMetrics.empty.loadingDescription
                : octopusMetrics.empty.description}
            </p>
            <Show when={mode() !== 'ssr'}>
              <p class="fine-print">{octopusMetrics.empty.retry}</p>
            </Show>
            <a class="text-link" href={octopusMetrics.empty.href}>
              {octopusMetrics.empty.link}
            </a>
          </div>
        }
      >
        <div class="ops-snapshot">
          <h3>{liveStrip() ? 'Pipeline now' : 'Latest snapshot'}</h3>
          <Show
            when={liveStrip() !== null}
            fallback={
              <p>
                {mode() === 'warmup'
                  ? octopusMetrics.warmup
                  : 'Live collection is delayed. Recorded totals and hourly history remain available below.'}
              </p>
            }
          >
            <dl class="ops-metrics">
              <div>
                <dt>
                  Broker records processed / second
                  <span class="fine-print">
                    Average over the last 5 minutes
                  </span>
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
                  Ledger records waiting
                  <span class="fine-print">Pending or being processed</span>
                </dt>
                <dd data-metric="pending">
                  {liveCell(() =>
                    number.format(liveStrip()!.pendingLedgerCount),
                  )}
                </dd>
              </div>
              <div>
                <dt>
                  Broker records waiting
                  <span class="fine-print">
                    Waiting to be fetched by this coordinator
                  </span>
                </dt>
                <dd data-metric="broker-pending">
                  {liveCell(() =>
                    liveStrip()!.brokerLagCount === null
                      ? 'Unavailable'
                      : number.format(liveStrip()!.brokerLagCount!),
                  )}
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
                    fallback={liveCell(() => octopusMetrics.missingCheck)}
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
          </Show>
          <Show
            when={stats() !== null && mode() !== 'ssr' && mode() !== 'loading'}
          >
            <p class="fine-print">
              Measured{' '}
              <time datetime={stats()!.asOf}>{timestamp(stats()!.asOf)}</time>
              <Show when={mode() === 'delayed' || mode() === 'historical'}>
                {' '}
                · last successful reading, not live
              </Show>
            </p>
          </Show>
        </div>
        <div class="ops-history">
          <h3>Busiest recorded periods</h3>
          <Show
            when={peaksReady()}
            fallback={<p>{octopusMetrics.missingHistory}</p>}
          >
            <div class="ops-peaks">
              <article class="ops-card" aria-labelledby="ops-day-title">
                <h4 id="ops-day-title">Peak day</h4>
                <p class="ops-count" data-metric="day">
                  {peakCell(
                    stats()!.peakRecordsDay !== null,
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
                    stats()!.peakRecordsWeek !== null,
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
          </Show>
        </div>
        <Show
          when={
            lifetimeReady() ||
            windowReady('throughput24h') ||
            windowReady('throughput7d')
          }
          fallback={
            <p class="fine-print">{octopusMetrics.missingThroughput}</p>
          }
        >
          <div class="ops-throughput">
            <h3>Throughput</h3>
            <dl class="ops-metrics">
              <div>
                <dt>
                  Records recorded
                  <span class="fine-print">
                    Lifetime ingestion ledger total
                  </span>
                </dt>
                <dd data-metric="lifetime-records">
                  {snapshotCell(lifetimeReady(), () =>
                    number.format(stats()!.lifetimeTotals!.recordsTotal),
                  )}
                </dd>
              </div>
              <div>
                <dt>
                  Days counted
                  <span class="fine-print">
                    Distinct UTC days with ledger rows
                  </span>
                </dt>
                <dd data-metric="lifetime-days">
                  {snapshotCell(lifetimeReady(), () =>
                    number.format(stats()!.lifetimeTotals!.daysCounted),
                  )}
                </dd>
              </div>
            </dl>
            <Show when={lifetimeReady()}>
              <p class="fine-print">
                Totals computed{' '}
                <time datetime={stats()!.lifetimeTotals!.computedAt}>
                  {timestamp(stats()!.lifetimeTotals!.computedAt)}
                </time>
              </p>
            </Show>
            <div class="ops-window">
              <h4 id="ops-24h-title">
                {mode() === 'historical'
                  ? 'Recorded 24-hour window'
                  : 'Last 24 hours'}
              </h4>
              <Show
                when={windowSeries('throughput24h')}
                fallback={
                  <p class="ops-count" data-metric="throughput-24h">
                    {snapshotCell(false, () => 'Unavailable')}
                  </p>
                }
              >
                {(series) => {
                  const data = series();
                  const max = seriesMax(data);
                  const first = data.series[0].bucketStart;
                  const last = data.series[data.series.length - 1].bucketStart;
                  return (
                    <div class="ops-chart">
                      <ul
                        class="ops-bars"
                        aria-label="Hourly ledger-row totals for the last 24 hours"
                      >
                        <For each={data.series}>
                          {(point) => (
                            <li class="ops-bar-row">
                              <span class="ops-bar-label">
                                <time datetime={point.bucketStart}>
                                  {hourLabel(point.bucketStart)}
                                </time>
                              </span>
                              <span class="ops-bar-track" aria-hidden="true">
                                <span
                                  class="ops-bar-fill"
                                  style={{ width: fill(point.records, max) }}
                                />
                              </span>
                              <span class="ops-bar-count">
                                {number.format(point.records)}
                              </span>
                            </li>
                          )}
                        </For>
                      </ul>
                      <p class="fine-print">
                        <time datetime={first}>{timestamp(first)}</time> to{' '}
                        <time datetime={last}>{timestamp(last)}</time> UTC ·
                        peak {number.format(max)} records in one hour
                      </p>
                    </div>
                  );
                }}
              </Show>
            </div>
            <div class="ops-window">
              <h4 id="ops-7d-title">
                {mode() === 'historical'
                  ? 'Recorded 7-day window'
                  : 'Last 7 days'}
              </h4>
              <Show
                when={windowSeries('throughput7d')}
                fallback={
                  <p class="ops-count" data-metric="throughput-7d">
                    {snapshotCell(false, () => 'Unavailable')}
                  </p>
                }
              >
                {(series) => {
                  const data = series();
                  const max = seriesMax(data);
                  const first = data.series[0].bucketStart;
                  const last = data.series[data.series.length - 1].bucketStart;
                  const label = `Hourly ledger-row totals for the last 7 days: ${data.series.length} buckets from ${timestamp(first)} to ${timestamp(last)}. Peak ${number.format(max)} records in one hour.`;
                  return (
                    <div class="ops-chart">
                      <div class="ops-spark" role="img" aria-label={label}>
                        <For each={data.series}>
                          {(point) => (
                            <span
                              class="ops-spark-bar"
                              style={{ height: fill(point.records, max) }}
                            />
                          )}
                        </For>
                      </div>
                      <p class="fine-print">
                        <time datetime={first}>{timestamp(first)}</time> to{' '}
                        <time datetime={last}>{timestamp(last)}</time> UTC ·
                        peak {number.format(max)} records in one hour
                      </p>
                    </div>
                  );
                }}
              </Show>
            </div>
          </div>
        </Show>
      </Show>
    </div>
  );
}
