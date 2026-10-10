import type { KVNamespace as CloudflareKVNamespace } from '@cloudflare/workers-types';

declare global {
  interface KVNamespace extends CloudflareKVNamespace {}
}
