import { parseStats } from '../../src/data/operational-stats';

// Pages serves this route at runtime; no production values enter the build.
export async function onRequestGet({ request }: { request: Request }) {
  const headers = { 'Cache-Control': 'no-store' };
  const unavailable = () =>
    Response.json({ error: 'Metrics unavailable' }, { status: 503, headers });
  if (!['rclabs.uk', 'www.rclabs.uk'].includes(new URL(request.url).hostname))
    return unavailable();
  try {
    const response = await fetch('https://gateway.rclabs.uk/public/stats', {
      headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
      signal: AbortSignal.timeout(12_000),
      redirect: 'error',
    });
    if (
      !response.ok ||
      !response.headers.get('content-type')?.includes('application/json')
    ) {
      await response.body?.cancel();
      return unavailable();
    }
    const reader = response.body?.getReader();
    if (!reader) return unavailable();
    const decoder = new TextDecoder();
    let body = '';
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 8192) return unavailable();
        body += decoder.decode(value, { stream: true });
      }
      body += decoder.decode();
    } finally {
      await reader.cancel();
    }
    return Response.json(parseStats(JSON.parse(body)), { headers });
  } catch {
    return unavailable();
  }
}
