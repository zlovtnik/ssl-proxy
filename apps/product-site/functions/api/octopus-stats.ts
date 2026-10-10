import {
  isFresh,
  maxStatsAgeMs,
  parseStats,
  retainHistory,
  type Stats,
} from '../../src/data/operational-stats';

const bodyLimit = 16_384;
// Newest versions sort first. Separate immutable keys prevent an older request
// from overwriting a newer snapshot; include sub-millisecond source precision.
export function snapshotKey(asOf: string) {
  const fraction = (asOf.match(/\.(\d+)Z$/)?.[1] ?? '').padEnd(9, '0');
  const nanos =
    BigInt(Date.parse(asOf)) * 1_000_000n + BigInt(fraction.slice(3, 9));
  return `v2/${(8_640_000_000_000_000_000_000n - nanos).toString().padStart(23, '0')}`;
}

// The generated binding supplies the native namespace type. This read/write
// subset also allows isolated tests without a remote Cloudflare account.
type HistoryStore = Pick<Env['METRICS_HISTORY'], 'list'> & {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
};

async function recorded(history: HistoryStore): Promise<Stats | undefined> {
  let keys = ['bootstrap'];
  try {
    const entries = await history.list({ prefix: 'v2/', limit: 3 });
    keys = [...entries.keys.map((entry) => entry.name), ...keys];
  } catch {
    // The permanent initial reading also covers listing outages/quotas.
  }
  let selected: Stats | undefined;
  for (const key of keys) {
    try {
      const text = await history.get(key);
      if (text && new TextEncoder().encode(text).byteLength <= bodyLimit) {
        const measured = parseStats(JSON.parse(text));
        selected = selected ? retainHistory(selected, measured) : measured;
        if (
          selected.peaksComputedAt &&
          selected.lifetimeTotals &&
          selected.throughput24h &&
          selected.throughput7d
        )
          return selected;
      }
    } catch {
      // Try an earlier real measurement if a saved object cannot be read.
    }
  }
  return selected;
}

// Bound the response while reading it, including a stalled or oversized body.
async function readSnapshot(response: Response): Promise<Stats> {
  if (!response.ok || !response.body) throw new Error('Invalid response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > bodyLimit) throw new Error('Oversized snapshot');
      chunks.push(value);
    }
  } finally {
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return parseStats(JSON.parse(new TextDecoder().decode(bytes)));
}

// Only the C++ publisher produces measurements. This route retains validated
// public snapshots in durable backup storage; timestamps are never rewritten.
export async function onRequestGet(context: {
  request: Request;
  env?: { METRICS_HISTORY?: HistoryStore };
  waitUntil?: (promise: Promise<unknown>) => void;
}) {
  const headers = { 'Cache-Control': 'no-store' };
  const unavailable = () =>
    Response.json(
      { error: 'No recorded snapshot yet' },
      { status: 503, headers },
    );
  if (
    !['rclabs.uk', 'www.rclabs.uk'].includes(
      new URL(context.request.url).hostname,
    )
  )
    return unavailable();

  const history = context.env?.METRICS_HISTORY;
  let saved: Stats | undefined;
  let backupTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    if (history)
      saved = await Promise.race([
        recorded(history),
        new Promise<undefined>((resolve) => {
          backupTimer = setTimeout(() => resolve(undefined), 1_000);
        }),
      ]);
  } catch {
    // Backup failure cannot prevent a gateway read.
  } finally {
    clearTimeout(backupTimer);
  }

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let selected = saved;
  let received: Stats | undefined;
  try {
    const upstream = fetch('https://gateway.rclabs.uk/public/stats', {
      headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
      cache: 'no-store',
      signal: controller.signal,
    }).then(readSnapshot);
    const measured = await Promise.race([
      upstream,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error('Snapshot timeout'));
        }, 7_000);
      }),
    ]);
    received = measured;
    if (!selected || snapshotKey(measured.asOf) <= snapshotKey(selected.asOf)) {
      selected = retainHistory(measured, saved);
      // A durable historical copy every five minutes bounds backup writes;
      // the current gateway reading still supplies every successful response.
      if (
        history &&
        (!saved ||
          Date.parse(measured.asOf) - Date.parse(saved.asOf) >= 300_000)
      ) {
        const persist = history
          .put(snapshotKey(selected.asOf), JSON.stringify(selected))
          .catch(() => {});
        if (context.waitUntil) context.waitUntil(persist);
        else await persist;
      }
    }
  } catch {
    // Dependency/validation failures retain the recorded snapshot.
  } finally {
    clearTimeout(timer);
  }
  if (!selected) return unavailable();
  return Response.json(selected, {
    headers: {
      ...headers,
      'X-Metrics-As-Of': selected.asOf,
      'X-Metrics-State':
        received?.asOf === selected.asOf &&
        isFresh(selected.asOf, Date.now(), maxStatsAgeMs) &&
        selected.liveStrip
          ? 'live'
          : 'historical',
    },
  });
}
