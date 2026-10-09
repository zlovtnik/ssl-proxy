import { parseStats } from '../../src/data/operational-stats';

// Pages serves this route at runtime; no production values enter the build.
// Note: AbortSignal.timeout and redirect:'error' raise TypeError in the Pages
// runtime on this gateway fetch, so the wait is raced and redirects are not
// rejected at the fetch layer (the body still has to parse as allowlisted JSON).
export async function onRequestGet({ request }: { request: Request }) {
  const headers = { 'Cache-Control': 'no-store' };
  const unavailable = () =>
    Response.json({ error: 'Metrics unavailable' }, { status: 503, headers });
  if (!['rclabs.uk', 'www.rclabs.uk'].includes(new URL(request.url).hostname))
    return unavailable();
  try {
    const upstream = fetch('https://gateway.rclabs.uk/public/stats', {
      headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
      cache: 'no-store',
    });
    const response = await Promise.race([
      upstream,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 12_000)),
    ]);
    if (!response) {
      void upstream.then((r) => r.body?.cancel()).catch(() => {});
      return unavailable();
    }
    const type = response.headers.get('content-type');
    const text = await response.text();
    const looksJson =
      type?.includes('application/json') || text.trimStart().startsWith('{');
    if (!response.ok || !looksJson || text.length > 8192) return unavailable();
    return Response.json(parseStats(JSON.parse(text)), { headers });
  } catch {
    return unavailable();
  }
}
