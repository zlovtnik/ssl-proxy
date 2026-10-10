import {
  isFresh,
  maxStatsAgeMs,
  parseStats,
  type Stats,
} from '../../src/data/operational-stats';

const bodyLimit = 16_384;
const cacheKey = 'https://rclabs.uk/api/octopus-stats';

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
// public snapshots at the edge; publication timestamps are never rewritten.
export async function onRequestGet(context: {
  request: Request;
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

  let cache: Cache | undefined;
  let saved: Stats | undefined;
  try {
    cache = await caches.open('octopus-stats-v2');
    const response = await cache.match(cacheKey);
    if (response) saved = await readSnapshot(response);
  } catch {
    // Edge cache absence/failure cannot prevent a gateway read.
  }

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let selected = saved;
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
        }, 8_000);
      }),
    ]);
    if (!selected || Date.parse(measured.asOf) >= Date.parse(selected.asOf)) {
      selected = measured;
      if (cache) {
        // Keep a separate, long-lived last-good entry. Browser responses still
        // use no-store so every poll attempts to obtain a newer measurement.
        const persist = cache
          .put(
            cacheKey,
            Response.json(measured, {
              headers: { 'Cache-Control': 'public, max-age=31536000' },
            }),
          )
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
        isFresh(selected.asOf, Date.now(), maxStatsAgeMs) && selected.liveStrip
          ? 'live'
          : 'historical',
    },
  });
}
