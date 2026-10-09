import type { APIRoute } from 'astro';
import { guides, guidePath } from '../data/products';
export const GET: APIRoute = ({ site }) => {
  const paths = [
    '/',
    '/products/',
    '/vpn-proxy/',
    '/atheros-search/',
    '/schema-migrator/',
    '/octopus/',
    '/demo/',
    '/accessibility/',
    '/privacy/',
    '/guides/',
    ...guides.map((guide) => guidePath(guide.slug)),
  ];
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${paths.map((path) => `<url><loc>${new URL(path, site).href}</loc></url>`).join('')}</urlset>`,
    { headers: { 'Content-Type': 'application/xml' } },
  );
};
