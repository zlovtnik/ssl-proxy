/**
 * Live operational stats island. Fetches from PUBLIC_OCTOPUS_STATS_URL every
 * 30s and updates peak cards + live strip in place. Falls back to SSR values
 * when the URL is unset, fetch fails, or JS is disabled.
 */
import { createSignal, onMount, onCleanup, For, Show } from 'solid-js';

interface LiveStrip {
  ingestProcessedRatePerSec: number;
  pendingLedgerCount: number;
  lastIngestSuccessAt: string | null;
  backpressureActive: boolean;
}

interface Stats {
  asOf: string;
  peaksComputedAt?: string | null;
  peakRecordsDay: number | null;
  peakRecordsDayDate: string | null;
  peakRecordsWeek: number | null;
  peakRecordsWeekStart: string | null;
  peakRecordsWeekEnd: string | null;
  liveStrip: LiveStrip | null;
}

const number = new Intl.NumberFormat('en-GB', { maximumFractionDigits: 2 });
const dayFmt = new Intl.DateTimeFormat('en-GB', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  timeZone: 'UTC',
});

const date = (v: string) => dayFmt.format(new Date(v));
const timestamp = (v: string) => `${v.replace('T', ' ').replace('Z', '')} UTC`;

function motionReduced() {
  return (
    typeof window !== 'undefined' &&
    (window.matchMedia('(prefers-reduced-motion: reduce)').matches ||
      document.documentElement.dataset.motion === 'reduced')
  );
}

export default function OctopusOperationalStats(props: {
  initial: Stats;
  statsUrl?: string;
  pollMs?: number;
}) {
  const [stats, setStats] = createSignal<Stats>(props.initial);
  const [live, setLive] = createSignal(false);

  onMount(() => {
    if (!props.statsUrl) return;
    let aborted = false;
    let timer: ReturnType<typeof setInterval> | undefined;

    const fetchStats = async () => {
      try {
        const res = await fetch(props.statsUrl!, {
          signal: AbortSignal.timeout(10_000),
        });
        if (!res.ok || aborted) return;
        const data: Stats = await res.json();
        if (!aborted) {
          setStats(data);
          setLive(true);
        }
      } catch {
        // keep SSR values on failure
      }
    };

    fetchStats();
    timer = setInterval(() => {
      if (!document.hidden) fetchStats();
    }, props.pollMs ?? 30_000);

    const onVisibility = () => {
      if (!document.hidden) fetchStats();
    };
    document.addEventListener('visibilitychange', onVisibility);

    onCleanup(() => {
      aborted = true;
      if (timer) clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    });
  });

  const s = stats();
  const weekInProgress =
    s.asOf.slice(0, 10) >= s.peakRecordsWeekStart! &&
    s.asOf.slice(0, 10) <= s.peakRecordsWeekEnd!;

  return (
    <div class="ops-widget" data-ux="ops-stats" data-live={live() ? 'true' : 'false'}>
      <div class="ops-peaks">
        <article class="ops-card" aria-labelledby="ops-day-title">
          <h3 id="ops-day-title">Peak day</h3>
          <Show
            when={s.peakRecordsDay !== null && s.peakRecordsDayDate !== null}
            fallback={<p>Pending first measured refresh</p>}
          >
            <p class="ops-count">
              <span data-ux="count-up">{number.format(s.peakRecordsDay!)} records</span>
            </p>
            <p>
              <time datetime={s.peakRecordsDayDate!}>{date(s.peakRecordsDayDate!)}</time>{' '}
              (UTC)
            </p>
          </Show>
        </article>
        <article class="ops-card" aria-labelledby="ops-week-title">
          <h3 id="ops-week-title">Peak week</h3>
          <Show
            when={
              s.peakRecordsWeek !== null &&
              s.peakRecordsWeekStart !== null &&
              s.peakRecordsWeekEnd !== null
            }
            fallback={<p>Pending first measured refresh</p>}
          >
            <p class="ops-count">
              <span data-ux="count-up">{number.format(s.peakRecordsWeek!)} records</span>
            </p>
            <p>
              <time datetime={s.peakRecordsWeekStart!}>{date(s.peakRecordsWeekStart!)}</time> to{' '}
              <time datetime={s.peakRecordsWeekEnd!}>{date(s.peakRecordsWeekEnd!)}</time> (UTC)
            </p>
            <Show when={weekInProgress}>
              <p class="fine-print">Week in progress at capture; counted so far.</p>
            </Show>
          </Show>
        </article>
      </div>
      <Show when={s.liveStrip}>
        <div class="ops-snapshot">
          <h3>Pipeline metrics</h3>
          <dl class="ops-metrics">
            <div>
              <dt>Ingest rate (5-minute average)</dt>
              <dd>{number.format(s.liveStrip!.ingestProcessedRatePerSec)} records/s</dd>
            </div>
            <div>
              <dt>Pending ledger</dt>
              <dd>{number.format(s.liveStrip!.pendingLedgerCount)} records</dd>
            </div>
            <div>
              <dt>Last ingest success</dt>
              <dd>
                <Show
                  when={s.liveStrip!.lastIngestSuccessAt}
                  fallback={<span>Unavailable in this snapshot</span>}
                >
                  <time datetime={s.liveStrip!.lastIngestSuccessAt!}>
                    {timestamp(s.liveStrip!.lastIngestSuccessAt!)}
                  </time>
                </Show>
              </dd>
            </div>
            <div>
              <dt>Backpressure</dt>
              <dd>
                <span
                  class="ops-status"
                  data-active={s.liveStrip!.backpressureActive ? 'true' : 'false'}
                >
                  <span class="ops-status-dot" aria-hidden="true"></span>
                  {s.liveStrip!.backpressureActive ? 'Active' : 'Inactive'}
                </span>
              </dd>
            </div>
          </dl>
          <p class="fine-print">
            {live()
              ? 'Live production metrics. Refreshes every 30 seconds.'
              : 'Build-time snapshot fallback.'}
          </p>
        </div>
      </Show>
    </div>
  );
}
