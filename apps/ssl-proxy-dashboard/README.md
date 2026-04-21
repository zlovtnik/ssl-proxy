# ssl-proxy Dashboard Frontend (SvelteKit)

Standalone SvelteKit dashboard for ssl-proxy admin APIs.

## Requirements

- Bun 1.2+

## Development

```bash
cd apps/ssl-proxy-dashboard
bun install
bun run dev
```

Default dev URL: `http://127.0.0.1:5173`

The Vite dev proxy forwards `/hosts`, `/stats`, `/devices`, `/health`, and `/ready` to `http://127.0.0.1:3002` and injects `x-api-key: test` for protected HTTP routes.

## Environment

- `VITE_ADMIN_BASE_URL`
  - Used by production builds for API requests.
  - Default: `http://127.0.0.1:3002`
- `VITE_ADMIN_API_KEY`
  - API key included by the frontend request client and inlined into the client bundle because it uses the `VITE_*` prefix.
  - Do not place a real admin credential here; every browser downloads it.
  - Safer options: terminate auth at a reverse proxy that injects `x-api-key` server-side, or exchange a user session for a scoped token before calling the admin API.

## Checks

```bash
bun run check
bun run test
```
