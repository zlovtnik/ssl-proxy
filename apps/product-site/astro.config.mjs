import { defineConfig } from 'astro/config';
import solid from '@astrojs/solid-js';

// Local metadata uses the review origin until a public hostname is chosen.
const site = process.env.PUBLIC_SITE_URL || 'http://localhost:4321';
const origin = new URL(site);
if (
  !['http:', 'https:'].includes(origin.protocol) ||
  origin.pathname !== '/' ||
  origin.search ||
  origin.hash ||
  origin.username ||
  origin.password
) {
  throw new Error(
    'PUBLIC_SITE_URL must be an HTTP(S) origin without a path or credentials.',
  );
}
export default defineConfig({
  site: origin.origin,
  output: 'static',
  trailingSlash: 'always',
  integrations: [solid()],
  devToolbar: { enabled: false },
});
