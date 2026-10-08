import { defineConfig } from 'astro/config';
import solid from '@astrojs/solid-js';

// Preview branches must stay excluded even if they inherit production variables.
const pagesPreview =
  process.env.CF_PAGES === '1' && process.env.CF_PAGES_BRANCH !== 'main';
const site = pagesPreview
  ? 'http://localhost:4321'
  : process.env.PUBLIC_SITE_URL || 'http://localhost:4321';
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
