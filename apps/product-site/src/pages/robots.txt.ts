import type { APIRoute } from 'astro';
export const GET: APIRoute = ({ site }) => {
  const local = !site || ['localhost', '127.0.0.1'].includes(site.hostname);
  return new Response(
    `User-agent: *\n${local ? 'Disallow: /' : `Allow: /\nSitemap: ${new URL('/sitemap.xml', site).href}`}\n`,
    { headers: { 'Content-Type': 'text/plain' } },
  );
};
